"""Bounded live socket scenarios in two namespaces, with honest detection outcomes.

Run through scripts/netns_multi_attack_lab.sh. No host routes/firewall, configured
DB, external services, replayed predictions or model overrides are used.
"""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import hashlib
from datetime import datetime, timezone
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
from threading import Event, Thread
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(__file__).resolve()
TARGET = "10.210.0.1"
VECTORS = (("PORTSCAN", "10.210.0.2"), ("BRUTE_FORCE", "10.210.0.3"), ("DOS", "10.210.0.4"))


def command(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10, **kwargs)


def wait_until(predicate, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise RuntimeError("Lab readiness/acknowledgement deadline exceeded")


def traffic(vector, source, count=None):
    """Called only inside the private attacker namespace. Every destination is fixed."""
    count = count or {"PORTSCAN": 11, "BRUTE_FORCE": 30, "DOS": 200}[vector]
    print(json.dumps({"onset_monotonic": time.monotonic()}), flush=True)

    def send_one(index):
        port = 8080 + index % 11 if vector == "PORTSCAN" else 21 if vector == "BRUTE_FORCE" else 80
        with socket.socket() as connection:
            connection.settimeout(0.15)
            connection.bind((source, 0))
            try:
                connection.connect((TARGET, port))
                if vector == "BRUTE_FORCE":
                    connection.recv(1024)
                    connection.sendall(b"USER lab\r\nPASS synthetic-guess\r\n")
                elif vector == "DOS":
                    connection.sendall(b"GET /?lab=" + b"x" * 512 + b" HTTP/1.0\r\n\r\n")
                connection.recv(1024)
            except OSError:
                return
    # Fixed flow counts, four flood workers, fixed target, no internet route.
    if vector == "DOS":
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(send_one, range(count)))
    else:
        for index in range(count):
            send_one(index)
            time.sleep(0.02 if vector == "PORTSCAN" else 0.03)


class Lab:
    def __init__(self, work):
        self.work = work
        self.processes, self.files, self.servers = [], [], []
        self.stop = Event()
        self.api_base = "http://127.0.0.1:18010"
        self.admin_token = None
        # All services get ephemeral configuration, including explicit notification disable.
        self.env = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(work), "TMPDIR": str(work),
                    "DATABASE_URL": "sqlite:///" + str(work / "lab.sqlite3"),
                    "SECRET_KEY": "multi-vector-private-jwt-key-00000000000000",
                    "SENSOR_API_TOKEN": "multi-vector-private-sensor-key-00000000000",
                    "SENSOR_ID": "sensor-multi-lab", "CORS_ORIGINS": "",
                    "ALERT_NOTIFICATIONS_ENABLED": "false", "ALERT_INCLUDE_DRY_RUN": "false",
                    "SMTP_HOST": "", "SMTP_PORT": "587", "SMTP_SECURITY": "starttls",
                    "SMTP_USER": "", "SMTP_PASSWORD": "", "SMTP_SENDER": "",
                    "ALERT_EMAIL_RECIPIENT": "", "ALERT_WEBHOOK_URL": "", "ALERT_WEBHOOK_FORMAT": "generic",
                    "ALERT_COOLDOWN_SECONDS": "600", "ALERT_MAX_PER_HOUR": "30", "ALERT_QUEUE_SIZE": "64"}

    def launch(self, args, name):
        output = open(self.work / (name + ".log"), "w")
        self.files.append(output)
        process = subprocess.Popen(args, env=self.env, stdout=output, stderr=subprocess.STDOUT, cwd=ROOT)
        self.processes.append(process)
        return process

    def api(self, path, form=None, payload=None):
        headers = {"Authorization": "Bearer " + self.admin_token} if self.admin_token else {}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.api_base + path, data=body, headers=headers)
        with urllib.request.urlopen(request, timeout=2) as response:
            return json.load(response)

    def attacker(self, args):
        return ["nsenter", f"--net=/proc/{self.peer.pid}/ns/net", sys.executable, str(SCRIPT), *args]

    def reachable(self, ip):
        result = subprocess.run(self.attacker(["--probe", ip]), capture_output=True, timeout=3)
        return result.returncode == 0

    def ping(self, ip):
        result = subprocess.run(["nsenter", f"--net=/proc/{self.peer.pid}/ns/net", "ping",
                                 "-I", ip, "-c1", "-W1", TARGET], capture_output=True, timeout=3)
        return result.returncode == 0

    def records(self, ip):
        path = self.work / "alerts.jsonl"
        records = []
        for line in path.read_text().splitlines() if path.exists() else []:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue  # A concurrent append may not have completed the last record yet.
            if record.get("event", {}).get("src_ip") == ip:
                records.append(record)
        return records

    def blocked_record(self, ip):
        return next((r for r in self.records(ip) if (r.get("firewall") or {}).get("status") == "blocked"), None)

    def serve(self, port):
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((TARGET, port))
        listener.listen(256)
        listener.settimeout(0.1)
        self.servers.append(listener)

        def loop():
            while not self.stop.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                with connection:
                    connection.settimeout(0.2)
                    try:
                        if port == 21:
                            connection.sendall(b"220 SecureNet isolated lab FTP simulation\r\n")
                            connection.recv(1024)
                            connection.sendall(b"530 Login incorrect\r\n")
                        elif port == 80:
                            connection.recv(4096)
                            connection.sendall(b"HTTP/1.0 503 Lab\r\nContent-Length: 0\r\n\r\n")
                        else:
                            connection.sendall(b"OK\n")
                    except OSError:
                        pass
        Thread(target=loop, daemon=True).start()

    def sensor_start(self, name="sensor"):
        self.sensor = self.launch([sys.executable, "-m", "sniffer.main", "-i", "veth-sensor",
            "-f", "tcp and (portrange 8080-8090 or port 21 or port 80)",
            "--termination-grace", "0.1", "--predict", "--respond", "--enforce",
            "--helper-socket", str(self.work / "helper.sock"), "--protect", TARGET + "/32",
            "--response-confidence", "0.5", "--response-min-flows", "2", "--response-window", "10",
            "--block-seconds", "120", "--alert-log", str(self.work / "alerts.jsonl"),
            "--outbox", str(self.work / "outbox.sqlite3"), "--api-url", self.api_base], name)

    def setup(self):
        command(["ip", "link", "set", "lo", "up"])
        self.peer = self.launch(["unshare", "--net", "sleep", "240"], "peer")
        wait_until(lambda: os.readlink(f"/proc/{self.peer.pid}/ns/net") != os.readlink("/proc/self/ns/net"))
        command(["ip", "link", "add", "veth-sensor", "type", "veth", "peer", "name", "veth-peer"])
        command(["ip", "addr", "add", TARGET + "/24", "dev", "veth-sensor"])
        command(["ip", "link", "set", "veth-sensor", "up"])
        command(["ip", "link", "set", "veth-peer", "netns", str(self.peer.pid)])
        peer_ip = ["nsenter", f"--net=/proc/{self.peer.pid}/ns/net", "ip"]
        command([*peer_ip, "link", "set", "lo", "up"])
        command([*peer_ip, "link", "set", "veth-peer", "up"])
        for ip in [ip for _, ip in VECTORS] + ["10.210.0.5"]:
            command([*peer_ip, "addr", "add", ip + "/24", "dev", "veth-peer"])
        self.launch(["/usr/bin/python3", "-I", str(ROOT / "backend/fw_helper.py"),
            "--socket", str(self.work / "helper.sock"), "--protect", TARGET + "/32",
            "--lease-seconds", "5", "--allowed-uid", str(os.getuid())], "helper")
        wait_until(lambda: (self.work / "helper.sock").exists())
        command([sys.executable, "-c",
            "import os; from backend.database import create_database_engine, init_db; "
            "from backend.manage import bootstrap_admin; e=create_database_engine(os.environ['DATABASE_URL']); "
            "init_db(e); bootstrap_admin(e,'lab_admin','lab@example.com','LabPrivatePass123!'); e.dispose()"], env=self.env)
        self.launch([sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1",
                     "--port", "18010", "--no-access-log", "--log-level", "warning"], "api")
        def healthy():
            try:
                return self.api("/api/health").get("status") == "ok"
            except OSError:
                return False
        wait_until(healthy)
        self.admin_token = self.api("/api/auth/login", form={"username": "lab_admin", "password": "LabPrivatePass123!"})["access_token"]
        for port in (18080, 21, 80):
            self.serve(port)
        self.sensor_start()
        wait_until(lambda: (self.work / "outbox.sqlite3.lock").exists(), 20)
        time.sleep(0.8)
        command(self.attacker(["--traffic", "PORTSCAN", "--source", "10.210.0.5", "--count", "1"]))
        wait_until(lambda: self.records("10.210.0.5"), 10)  # Proves live capture, extraction and inference readiness.

    def scenario(self, vector, ip, seconds):
        if not self.reachable(ip) or not self.ping(ip):
            raise RuntimeError(f"{vector}: baseline connectivity failed")
        process = subprocess.Popen(self.attacker(["--traffic", vector, "--source", ip]),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.processes.append(process)
        onset = json.loads(process.stdout.readline())["onset_monotonic"]
        deadline, first_drop, record = onset + seconds, None, None
        while time.monotonic() < deadline:
            if self.sensor.poll() is not None:
                raise RuntimeError("Live sensor exited unexpectedly")
            record = self.blocked_record(ip)
            if record and not self.reachable(ip):
                first_drop = time.monotonic()
                break
            time.sleep(0.05)
        process.communicate(timeout=12)
        if process.returncode:
            raise RuntimeError("Traffic generator failed")
        # Include delayed flow emissions up to the scenario deadline; never flush via EOF.
        records = self.records(ip)
        labels = dict(Counter(r["event"]["label"] for r in records))
        result = {"vector": vector, "source_ip": ip, "baseline_reachable": True,
                  "predicted_labels": labels, "emitted_flows": len(records),
                  "observation_seconds": seconds, "mitigation_latency_seconds": None,
                  "packet_drop_verified": False, "manual_unblock_recovered": None,
                  "classification_match": False, "status": "missed"}
        if not record:
            if not self.reachable(ip):
                raise RuntimeError("Connectivity failed without an audited enforcement action")
            return result
        # Both kernel membership and actual TCP/ICMP drops must agree with the audit.
        elements = json.loads(command(["nft", "-j", "list", "set", "ip", "securenet", "blocked_ips"]).stdout)
        if ip not in json.dumps(elements) or first_drop is None or self.ping(ip):
            raise RuntimeError("Audited block was not confirmed by nftables and packet probes")
        action = record["firewall"]
        block_id = action["block"]["block_id"]
        wait_until(lambda: any(b["block_id"] == block_id for b in self.api("/api/firewall/blocked")))
        self.api("/api/firewall/unblock/" + ip + "?block_id=" + block_id, payload={})
        wait_until(lambda: any(b["block_id"] == block_id for b in self.api("/api/firewall/blocked?status=UNBLOCKED")))
        if not self.reachable(ip) or not self.ping(ip):
            raise RuntimeError("Manual unblock did not restore traffic")
        result.update(status="mitigated" if record["event"]["label"] == vector else "misclassified_block",
                      classification_match=record["event"]["label"] == vector,
                      enforced_label=record["event"]["label"], packet_drop_verified=True,
                      mitigation_latency_seconds=round(first_drop - onset, 6), manual_unblock_recovered=True)
        return result

    def watchdog(self):
        # Independent safety check, explicitly a scan; no replacement for missed scenario results.
        ip = "10.210.0.2"
        command(self.attacker(["--traffic", "PORTSCAN", "--source", ip]))
        def active():
            blocks = self.api("/api/firewall/blocked")
            return next((b for b in blocks if b["ip"] == ip and b["status"] == "ACTIVE"), None)
        block = wait_until(active)
        if self.reachable(ip):
            raise RuntimeError("Watchdog precondition: scan was not blocked")
        self.sensor.kill()
        self.sensor.wait(timeout=5)
        def removed():
            return subprocess.run(["nft", "list", "table", "ip", "securenet"], capture_output=True, timeout=2).returncode != 0
        wait_until(removed, 9)
        if not self.reachable(ip):
            raise RuntimeError("Watchdog did not restore traffic")
        self.sensor_start("restarted-sensor")
        wait_until(lambda: any(b["block_id"] == block["block_id"] for b in self.api("/api/firewall/blocked?status=ROLLED_BACK")))
        self.sensor.terminate()
        self.sensor.wait(timeout=10)
        if self.sensor.returncode != 0 or not removed():
            raise RuntimeError("SIGTERM did not cleanly remove enforcement")
        return {"sigkill_rollback_recovered": True, "startup_db_reconciled": True, "sigterm_exit_code": 0}

    def close(self):
        self.stop.set()
        for listener in self.servers:
            listener.close()
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        for output in self.files:
            output.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "reports/sprint7/multi_attack_lab.json")
    parser.add_argument("--scenario-seconds", type=float, default=8)
    parser.add_argument("--require-all-detected", action="store_true", help="Exit 2 when any vector is missed or misclassified")
    parser.add_argument("--parent-netns", help=argparse.SUPPRESS)
    parser.add_argument("--traffic", choices=[v for v, _ in VECTORS], help=argparse.SUPPRESS)
    parser.add_argument("--source", choices=[ip for _, ip in VECTORS] + ["10.210.0.5"], help=argparse.SUPPRESS)
    parser.add_argument("--probe", choices=[ip for _, ip in VECTORS], help=argparse.SUPPRESS)
    parser.add_argument("--count", type=int, choices=[1], help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.probe or args.traffic:
        links = json.loads(command(["ip", "-j", "link", "show"]).stdout)
        if {link["ifname"] for link in links} != {"lo", "veth-peer"}:
            parser.error("Internal traffic commands require the private attacker namespace")
    if args.probe:
        try:
            with socket.socket() as connection:
                connection.settimeout(0.15)
                connection.bind((args.probe, 0))
                connection.connect((TARGET, 18080))
                if connection.recv(8) != b"OK\n":
                    raise OSError("Unexpected probe reply")
        except OSError:
            raise SystemExit(1)
        return
    if args.traffic:
        if not args.source:
            parser.error("--source is required for private lab traffic")
        traffic(args.traffic, args.source, args.count)
        return
    if not 3 <= args.scenario_seconds <= 30:
        parser.error("--scenario-seconds must be between 3 and 30")
    interfaces = json.loads(command(["ip", "-j", "link", "show"]).stdout)
    if (not args.parent_netns or os.readlink("/proc/self/ns/net") == args.parent_netns
            or {link["ifname"] for link in interfaces} != {"lo"}):
        parser.error("Run the shell launcher: a fresh private network namespace is required")
    os.chdir(ROOT)
    (ROOT / "runtime").mkdir(exist_ok=True)
    def stop_lab(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, stop_lab)
    report = {"schema_version": 1, "status": "error", "scenarios": [],
              "recorded_at": datetime.now(timezone.utc).isoformat(),
              "source_hashes": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in (SCRIPT, ROOT / "scripts/netns_multi_attack_lab.sh",
                                             ROOT / "ml_engine/models/unified_v1/inference_bundle.pkl")},
              "scope": "live synthetic socket traffic; isolated netns; unchanged unified model",
              "policy": {"confidence": 0.5, "min_flows": 2, "window_seconds": 10, "termination_grace": 0.1},
              "latency_basis": "attacker monotonic timestamp immediately before socket traffic to first confirmed failed TCP probe; includes flow finalization, queueing and probe timeout; upper bound, not exact kernel drop time"}
    with tempfile.TemporaryDirectory(prefix="securenet-multi-", dir=ROOT / "runtime") as directory:
        lab = Lab(Path(directory))
        try:
            lab.setup()
            for vector, ip in VECTORS:
                result = lab.scenario(vector, ip, args.scenario_seconds)
                report["scenarios"].append(result)
                print(json.dumps(result), flush=True)
            report["recovery"] = lab.watchdog()
            report["status"] = "ok" if all(s["status"] == "mitigated" for s in report["scenarios"]) else "completed_with_detection_gaps"
        except (Exception, KeyboardInterrupt) as exc:
            report["error"] = f"{type(exc).__name__}: {exc}"
            for name in ("sensor", "restarted-sensor", "helper", "api"):
                path = lab.work / (name + ".log")
                if path.exists():
                    print(f"{name}: {path.read_text()[-2000:]}", file=sys.stderr)
        finally:
            lab.close()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "report": str(args.output)}))
    if report["status"] == "error":
        raise SystemExit(1)
    if args.require_all_detected and report["status"] != "ok":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
