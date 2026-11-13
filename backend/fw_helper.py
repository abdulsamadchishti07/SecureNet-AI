"""Privileged host-local nftables helper daemon (pure Python stdlib; run with python3 -I)."""

import argparse
from collections import OrderedDict
from ipaddress import IPv4Address, IPv4Network
import json
import math
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
from threading import Event, Lock, Thread
import time
from uuid import UUID, uuid4

DEFAULT_PROTECTED = ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4")


def _nft_block_cmd(ip, ttl):
    return ["nft", "add", "element", "ip", "securenet", "blocked_ips", "{", f"{ip} timeout {int(ttl)}s", "}"]


def _nft_unblock_cmd(ip):
    return ["nft", "delete", "element", "ip", "securenet", "blocked_ips", "{", str(ip), "}"]


def _nft_rollback_cmd():
    return ["nft", "delete", "table", "ip", "securenet"]


def _peer_uid(conn):
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


class FwHelperServer:
    """Isolated nftables 'ip securenet' controller with SO_PEERCRED and lease watchdog."""

    def __init__(self, socket_path="runtime/fw_helper.sock", protected=(), max_blocks=256,
                 lease_seconds=15.0, allowed_uids=None, nft_bin="nft", runner=None, clock=time.monotonic):
        self.socket_path = Path(socket_path)
        self.protected = tuple(IPv4Network(cidr, strict=False) for cidr in (*DEFAULT_PROTECTED, *protected))
        if isinstance(max_blocks, bool) or not isinstance(max_blocks, int) or not 1 <= max_blocks <= 4096:
            raise ValueError("max_blocks must be an integer in 1..4096")
        if isinstance(lease_seconds, bool) or not math.isfinite(lease_seconds) or not 0.1 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be in 0.1..3600")
        self.max_blocks, self.lease_seconds, self.nft_bin, self.clock = max_blocks, float(lease_seconds), nft_bin, clock
        default_uids = {os.geteuid()}
        if os.environ.get("SUDO_UID", "").isdigit():
            default_uids.add(int(os.environ["SUDO_UID"]))
        self.allowed_uids = set(default_uids if allowed_uids is None else allowed_uids)
        self._runner = runner or self._default_runner
        self._lock = Lock()
        self._active = {}
        self._ops = OrderedDict()
        self._lease_id = None
        self._lease_deadline = None
        self._rolled_back = []
        self._table_active = False
        self._stop = Event()
        self._sock = self._thread = None

    def _default_runner(self, args, stdin_text=None):
        completed = subprocess.run(
            [self.nft_bin, *args[1:]],
            input=stdin_text,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        return completed.returncode, completed.stderr or ""

    def is_whitelisted(self, ip):
        address = IPv4Address(ip)
        return any(address in network for network in self.protected)

    def _init_table_locked(self):
        ruleset = (
            "table ip securenet\n"
            "delete table ip securenet\n"
            "table ip securenet {\n"
            "    set blocked_ips {\n"
            "        type ipv4_addr\n"
            "        flags timeout\n"
            f"        size {self.max_blocks}\n"
            "    }\n"
            "    chain input {\n"
            "        type filter hook input priority filter; policy accept;\n"
            "        ip saddr @blocked_ips drop\n"
            "    }\n"
            "}\n"
        )
        code, err = self._runner(["nft", "-f", "-"], stdin_text=ruleset)
        if code != 0:
            raise RuntimeError(f"nft table initialization failed: {err.strip()}")
        self._table_active = True

    def _rollback_locked(self, reason="rollback"):
        cleared = [entry["block_id"] for entry in self._active.values()]
        self._active.clear()
        self._lease_id = None
        self._lease_deadline = None
        if self._table_active or cleared:
            code, err = self._runner(_nft_rollback_cmd())
            if code != 0 and "No such file" not in err and "does not exist" not in err:
                raise RuntimeError(f"nft table rollback failed: {err.strip()}")
        self._table_active = False
        if cleared:
            self._rolled_back.extend(v for v in cleared if v not in self._rolled_back)
        return cleared

    def _prune_expired_locked(self, now):
        for ip, entry in list(self._active.items()):
            if now >= entry["expires_at"]:
                del self._active[ip]

    def _remember_op_locked(self, op_id, response):
        self._ops[op_id] = response
        self._ops.move_to_end(op_id)
        while len(self._ops) > 4096:
            self._ops.popitem(last=False)
        return response

    def check_lease(self):
        with self._lock:
            if self._lease_id is not None and self.clock() >= self._lease_deadline:
                return self._rollback_locked("lease_expired")
            return []

    def handle_request(self, req):
        if not isinstance(req, dict) or not isinstance(req.get("op"), str):
            return {"ok": False, "error": "invalid_request"}
        op = req["op"]
        with self._lock:
            now = self.clock()
            if self._lease_id is not None and now >= self._lease_deadline and op != "hello":
                self._rollback_locked("lease_expired")
                if op != "status":
                    return {"ok": False, "error": "lease_expired"}
            try:
                if op == "hello":
                    self._rollback_locked("startup_cleanup")
                    self._init_table_locked()
                    self._lease_id = str(uuid4())
                    self._lease_deadline = self.clock() + self.lease_seconds
                    rolled_back = list(self._rolled_back)
                    self._rolled_back.clear()
                    return {
                        "ok": True,
                        "lease_id": self._lease_id,
                        "lease_seconds": self.lease_seconds,
                        "max_blocks": self.max_blocks,
                        "protected_cidrs": [str(net) for net in self.protected],
                        "rolled_back_block_ids": rolled_back,
                    }
                if op == "status":
                    self._prune_expired_locked(now)
                    return {
                        "ok": True,
                        "table_active": self._table_active,
                        "lease_active": self._lease_id is not None,
                        "active_block_ids": [v["block_id"] for v in self._active.values()],
                        "rolled_back_block_ids": list(self._rolled_back),
                    }
                if op == "rollback":
                    cleared = self._rollback_locked(str(req.get("reason", "rollback")))
                    self._rolled_back.clear()
                    return {
                        "ok": True,
                        "status": "rolled_back",
                        "cleared_block_ids": cleared,
                        "command": _nft_rollback_cmd(),
                    }
                if not self._lease_id or req.get("lease_id") != self._lease_id:
                    return {"ok": False, "error": "invalid_or_expired_lease"}
                if op == "heartbeat":
                    self._prune_expired_locked(now)
                    self._lease_deadline = now + self.lease_seconds
                    return {"ok": True, "active_blocks": len(self._active)}
                op_id = str(UUID(str(req["op_id"])))
                if op_id in self._ops:
                    self._lease_deadline = now + self.lease_seconds
                    return self._ops[op_id]
                ip = str(IPv4Address(str(req["ip"])))
                if op == "block":
                    block_id = str(UUID(str(req["block_id"])))
                    ttl = req.get("ttl")
                    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= 86400:
                        return {"ok": False, "error": "invalid_ttl"}
                    self._prune_expired_locked(now)
                    self._lease_deadline = now + self.lease_seconds
                    if self.is_whitelisted(ip):
                        return self._remember_op_locked(op_id, {"ok": True, "status": "protected", "command": None})
                    if ip in self._active:
                        return self._remember_op_locked(op_id, {
                            "ok": True,
                            "status": "already_blocked",
                            "block_id": self._active[ip]["block_id"],
                            "command": None,
                        })
                    if len(self._active) >= self.max_blocks:
                        return self._remember_op_locked(op_id, {"ok": True, "status": "capacity_reached", "command": None})
                    cmd = _nft_block_cmd(ip, ttl)
                    code, err = self._runner(cmd)
                    if code != 0:
                        return {"ok": False, "error": f"nft_add_failed: {err.strip()}"}
                    self._active[ip] = {"block_id": block_id, "expires_at": now + ttl, "ttl": ttl}
                    return self._remember_op_locked(op_id, {"ok": True, "status": "blocked", "command": cmd})
                if op == "unblock":
                    block_id = str(UUID(str(req["block_id"]))) if req.get("block_id") is not None else None
                    self._lease_deadline = now + self.lease_seconds
                    current = self._active.get(ip)
                    if current and block_id is not None and current["block_id"] != block_id:
                        return self._remember_op_locked(op_id, {
                            "ok": True,
                            "status": "stale_block",
                            "block_id": block_id,
                            "command": None,
                        })
                    if current is None:
                        return self._remember_op_locked(op_id, {
                            "ok": True,
                            "status": "already_unblocked",
                            "block_id": block_id,
                            "command": None,
                        })
                    del self._active[ip]
                    cmd = _nft_unblock_cmd(ip)
                    code, err = self._runner(cmd)
                    if code != 0 and "No such file" not in err and "does not exist" not in err:
                        return {"ok": False, "error": f"nft_delete_failed: {err.strip()}"}
                    return self._remember_op_locked(op_id, {
                        "ok": True,
                        "status": "unblocked",
                        "block_id": current["block_id"],
                        "command": cmd,
                    })
                return {"ok": False, "error": "unsupported_operation"}
            except (KeyError, ValueError, TypeError) as exc:
                return {"ok": False, "error": f"validation_error: {exc}"}
            except RuntimeError as exc:
                return {"ok": False, "error": str(exc)}

    def _serve_client(self, conn):
        with conn:
            conn.settimeout(2.0)
            try:
                uid = _peer_uid(conn)
            except OSError:
                return
            if uid not in self.allowed_uids:
                conn.sendall(b'{"ok":false,"error":"unauthorized_peer_uid"}\n')
                return
            chunks, total = [], 0
            while True:
                try:
                    data = conn.recv(4096)
                except OSError:
                    return
                if not data:
                    break
                chunks.append(data)
                total += len(data)
                if total > 4096:
                    conn.sendall(b'{"ok":false,"error":"request_too_large"}\n')
                    return
                if b"\n" in data:
                    break
            raw = b"".join(chunks).split(b"\n", 1)[0]
            if not raw:
                return
            try:
                req = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                reply = {"ok": False, "error": "invalid_json"}
            else:
                reply = self.handle_request(req)
            try:
                conn.sendall(json.dumps(reply, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n")
            except OSError:
                pass

    def start(self):
        if self._sock is not None:
            raise RuntimeError("Helper server already started")
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.is_socket():
            self.socket_path.unlink()
        elif self.socket_path.exists():
            raise FileExistsError(f"Refusing to overwrite non-socket file: {self.socket_path}")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o660)
        sock.listen(16)
        sock.settimeout(0.2)
        self._sock = sock
        self._stop.clear()
        self._thread = Thread(target=self._loop, name="securenet-fw-helper", daemon=True)
        self._thread.start()
        return self

    def _loop(self):
        while not self._stop.is_set():
            self.check_lease()
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            self._serve_client(conn)

    def close(self):
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            self._thread = None
        with self._lock:
            try:
                self._rollback_locked("helper_shutdown")
            except RuntimeError:
                pass
        if self.socket_path.is_socket():
            try:
                self.socket_path.unlink()
            except OSError:
                pass

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, tb):
        self.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, default=Path("runtime/fw_helper.sock"))
    parser.add_argument("--protect", action="append", default=[], metavar="IPv4/CIDR")
    parser.add_argument("--max-blocks", type=int, default=256)
    parser.add_argument("--lease-seconds", type=float, default=15.0)
    parser.add_argument("--allowed-uid", action="append", type=int, dest="allowed_uids")
    parser.add_argument("--nft-bin", default="nft")
    args = parser.parse_args(argv)
    try:
        server = FwHelperServer(
            socket_path=args.socket,
            protected=args.protect,
            max_blocks=args.max_blocks,
            lease_seconds=args.lease_seconds,
            allowed_uids=args.allowed_uids,
            nft_bin=args.nft_bin,
        )
    except ValueError as exc:
        parser.error(str(exc))
    stop = Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_args: stop.set())
    with server:
        print(f"Firewall helper ready on {args.socket} (max_blocks={args.max_blocks}, lease={args.lease_seconds:g}s)", flush=True)
        while not stop.is_set():
            stop.wait(0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

