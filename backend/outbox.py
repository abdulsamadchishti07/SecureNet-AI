"""Durable FIFO HTTP outbox. Credentials are never stored in its database."""

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import sqlite3
from threading import Event, Thread
import time
import urllib.error
import urllib.parse
import urllib.request


class DeliveryError(Exception):
    def __init__(self, message, retryable=True):
        super().__init__(message)
        self.retryable = retryable


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ApiTransport:
    def __init__(self, base_url, token, sensor_id):
        parsed = urllib.parse.urlsplit(base_url)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("API URL must be HTTP(S), without embedded credentials/query/fragment")
        if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError("Use HTTPS for sensors connecting beyond loopback")
        if not token or len(token.encode()) < 32 or not sensor_id:
            raise ValueError("API forwarding requires SENSOR_API_TOKEN (32+ bytes) and SENSOR_ID")
        self.base_url, self.token, self.sensor_id = base_url.rstrip("/"), token, sensor_id
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, path, payload=None):
        body = None if payload is None else json.dumps(payload, allow_nan=False).encode()
        request = urllib.request.Request(self.base_url + path, data=body,
            headers={"Content-Type": "application/json", "X-Sensor-Token": self.token,
                     "X-Sensor-ID": self.sensor_id}, method="GET" if body is None else "POST")
        try:
            with self.opener.open(request, timeout=2) as response:
                data = response.read(1_048_577)
                if len(data) > 1_048_576:
                    raise DeliveryError("Oversized API response", retryable=False)
                return json.loads(data) if data else {}
        except urllib.error.HTTPError as exc:
            raise DeliveryError(f"HTTP {exc.code}", exc.code in (408, 429) or exc.code >= 500) from exc
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise DeliveryError(type(exc).__name__) from exc


class Outbox:
    def __init__(self, path, namespace, capacity=100000, clock=time.time):
        self.path, self.capacity, self.clock = Path(path), capacity, clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = open(str(self.path) + ".lock", "a")
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._lock.close()
            raise RuntimeError("Another sensor process owns this outbox")
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY, namespace TEXT NOT NULL)")
            existing = db.execute("SELECT namespace FROM metadata WHERE id=1").fetchone()
            if existing and existing[0] != namespace:
                self.close()
                raise ValueError("An outbox cannot be reused for a different API or sensor")
            db.execute("INSERT OR IGNORE INTO metadata VALUES (1, ?)", (namespace,))
            db.execute("""CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY, path TEXT NOT NULL, payload TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'PENDING', attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt REAL NOT NULL DEFAULT 0, last_error TEXT, created_at REAL NOT NULL)""")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=2)
        try:
            with db:
                yield db
        finally:
            db.close()

    def contains(self, message_id):
        with self.connect() as db:
            return db.execute("SELECT 1 FROM messages WHERE id=?", (message_id,)).fetchone() is not None

    def enqueue(self, message_id, path, payload):
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self.connect() as db:
            existing = db.execute("SELECT path,payload FROM messages WHERE id=?", (message_id,)).fetchone()
            if existing:
                if existing != (path, serialized):
                    raise ValueError("Outbox message identity reused with a different payload")
                return
            if db.execute("SELECT count(*) FROM messages").fetchone()[0] >= self.capacity:
                raise RuntimeError("Durable outbox capacity reached; accepted event was retained in JSONL")
            db.execute("INSERT INTO messages(id,path,payload,created_at) VALUES(?,?,?,?)",
                       (message_id, path, serialized, self.clock()))

    def next_message(self):
        with self.connect() as db:
            row = db.execute("SELECT id,path,payload,attempts,next_attempt FROM messages WHERE state='PENDING' ORDER BY created_at,rowid LIMIT 1").fetchone()
        return row if row and row[4] <= self.clock() else None

    def delivered(self, message_id):
        with self.connect() as db:
            db.execute("DELETE FROM messages WHERE id=?", (message_id,))

    def failed(self, message_id, error):
        with self.connect() as db:
            attempts = db.execute("SELECT attempts FROM messages WHERE id=?", (message_id,)).fetchone()[0] + 1
            state = "FAILED" if attempts >= 8 or not error.retryable else "PENDING"
            db.execute("UPDATE messages SET attempts=?,state=?,next_attempt=?,last_error=? WHERE id=?",
                       (attempts, state, self.clock() + min(60, 2 ** attempts), str(error), message_id))

    def retry_failed(self):
        with self.connect() as db:
            db.execute("UPDATE messages SET state='PENDING',attempts=0,next_attempt=0 WHERE state='FAILED'")

    def stats(self):
        with self.connect() as db:
            counts = dict(db.execute("SELECT state,count(*) FROM messages GROUP BY state"))
        return {"pending": counts.get("PENDING", 0), "failed": counts.get("FAILED", 0)}

    def close(self):
        self._lock.close()


class ApiSender:
    def __init__(self, outbox, transport, on_commands):
        self.outbox, self.transport, self.on_commands = outbox, transport, on_commands
        self.stop = Event()
        self.forwarded = self.failed = self.poll_failed = 0
        self._error = None
        self.thread = Thread(target=self._run, name="securenet-api-sender", daemon=True)

    def start(self):
        self.thread.start()

    def _run(self):
        next_poll = 0
        try:
            while not self.stop.is_set():
                message = self.outbox.next_message()
                if message:
                    message_id, path, body, *_ = message
                    try:
                        payload = json.loads(body)
                        acknowledgement = self.transport.request(path, payload)
                        self._validate_ack(path, payload, acknowledgement)
                    except DeliveryError as exc:
                        self.outbox.failed(message_id, exc)
                        self.failed += 1
                    else:
                        self.outbox.delivered(message_id)
                        self.forwarded += 1
                if time.monotonic() >= next_poll:
                    try:
                        commands = self.transport.request("/api/sensor/commands")
                        self.on_commands(commands)
                    except (DeliveryError, ValueError, TypeError):
                        self.poll_failed += 1
                    next_poll = time.monotonic() + 1
                self.stop.wait(0.05)
        except Exception as exc:
            self._error = exc

    @staticmethod
    def _validate_ack(path, payload, response):
        if not isinstance(response, dict):
            raise DeliveryError("Invalid acknowledgement", retryable=False)
        if path == "/api/alerts/ingest":
            valid = (response.get("event_id") == payload["event"]["event_id"]
                     and response.get("status") in ("ingested", "already_ingested"))
        elif path == "/api/sensor/firewall-events":
            valid = response.get("action_id") == payload["action_id"] and response.get("status") == "recorded"
        else:
            valid = (response.get("command_id") == path.split("/")[-2]
                     and response.get("status") == "ACKNOWLEDGED")
        if not valid:
            raise DeliveryError("Acknowledgement identity/status mismatch", retryable=False)

    def close(self):
        deadline = time.monotonic() + 2.5
        while self.outbox.stats()["pending"] and time.monotonic() < deadline and self.thread.is_alive():
            self.stop.wait(0.05)
        self.stop.set()
        self.thread.join(timeout=2.5)
        if self.thread.is_alive():
            raise RuntimeError("API sender did not stop; messages remain in the durable outbox")
        if self._error:
            raise RuntimeError("API sender failed; messages remain in the durable outbox") from self._error


def main():
    parser = argparse.ArgumentParser(description="Inspect or retry retained outbox messages while the sensor is stopped")
    parser.add_argument("operation", choices=("status", "retry"))
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    if not args.path.is_file():
        parser.error("Outbox does not exist")
    with sqlite3.connect(args.path) as db:
        namespace = db.execute("SELECT namespace FROM metadata WHERE id=1").fetchone()[0]
    outbox = Outbox(args.path, namespace)
    try:
        if args.operation == "retry":
            outbox.retry_failed()
        print(json.dumps(outbox.stats()))
    finally:
        outbox.close()


if __name__ == "__main__":
    main()
