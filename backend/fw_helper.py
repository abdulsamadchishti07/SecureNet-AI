"""Privileged host-local nftables helper daemon (pure Python stdlib; run with python3 -I)."""

import argparse
from collections import OrderedDict
from ipaddress import IPv4Address, IPv4Network
import json
import math
import os
from pathlib import Path
import pwd
import signal
import socket
import stat
import struct
import subprocess
import sys
from threading import Event, Lock, Thread
import time
from uuid import UUID, uuid4

DEFAULT_PROTECTED = ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4")
_SHARED_DIRS = frozenset({
    ".", "/", "/bin", "/boot", "/dev", "/dev/shm", "/etc", "/home", "/lib", "/lib64",
    "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/run/lock", "/sbin", "/srv",
    "/sys", "/tmp", "/usr", "/var", "/var/lock", "/var/log", "/var/run", "/var/tmp",
})
_DEDICATED_DIR_NAMES = frozenset({"runtime", "securenet", "securenet-ai", "fw_helper", "fw-helper"})


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
                 lease_seconds=15.0, allowed_uids=None, nft_bin="nft", runner=None, clock=time.monotonic,
                 socket_uid=None, socket_gid=None, socket_mode=0o660, dir_mode=0o750):
        self.socket_path = Path(socket_path)
        self.protected = tuple(IPv4Network(cidr, strict=False) for cidr in (*DEFAULT_PROTECTED, *protected))
        if isinstance(max_blocks, bool) or not isinstance(max_blocks, int) or not 1 <= max_blocks <= 4096:
            raise ValueError("max_blocks must be an integer in 1..4096")
        if isinstance(lease_seconds, bool) or not math.isfinite(lease_seconds) or not 0.1 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be in 0.1..3600")
        for label, value in (("socket_uid", socket_uid), ("socket_gid", socket_gid)):
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise ValueError(f"{label} must be a non-negative integer")
        for label, value in (("socket_mode", socket_mode), ("dir_mode", dir_mode)):
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0o777):
                raise ValueError(f"{label} must be an integer mode in 0..0777")
        self.max_blocks, self.lease_seconds, self.nft_bin, self.clock = max_blocks, float(lease_seconds), nft_bin, clock
        self.socket_uid, self.socket_gid = socket_uid, socket_gid
        self.socket_mode = socket_mode if socket_mode is not None else 0o660
        self.dir_mode = dir_mode
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
        try:
            completed = subprocess.run(
                [self.nft_bin, *args[1:]],
                input=stdin_text,
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            return 1, f"{type(exc).__name__}: {exc}"
        return completed.returncode, completed.stderr or ""

    def _run_nft(self, args, stdin_text=None):
        try:
            if stdin_text is None:
                return self._runner(args)
            return self._runner(args, stdin_text=stdin_text)
        except (subprocess.SubprocessError, OSError) as exc:
            return 1, f"{type(exc).__name__}: {exc}"

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
        code, err = self._run_nft(["nft", "-f", "-"], stdin_text=ruleset)
        if code != 0:
            raise RuntimeError(f"nft table initialization failed: {err.strip()}")
        self._table_active = True

    def _rollback_locked(self, reason="rollback"):
        cleared = [entry["block_id"] for entry in self._active.values()]
        if self._table_active or cleared:
            code, err = self._run_nft(_nft_rollback_cmd())
            if code != 0 and "No such file" not in err and "does not exist" not in err:
                raise RuntimeError(f"nft table rollback failed: {err.strip()}")
        self._active.clear()
        self._lease_id = None
        self._lease_deadline = None
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
            try:
                if op == "hello":
                    if self._lease_id is not None and now < self._lease_deadline:
                        return {"ok": False, "error": "active_lease_exists"}
                    self._rollback_locked("startup_cleanup" if self._lease_id is None else "lease_expired")
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
                    rollback_error = None
                    if self._lease_id is not None and now >= self._lease_deadline:
                        try:
                            self._rollback_locked("lease_expired")
                        except (RuntimeError, subprocess.SubprocessError, OSError) as exc:
                            rollback_error = str(exc)
                    if rollback_error is None:
                        self._prune_expired_locked(now)
                    reply = {
                        "ok": True,
                        "table_active": self._table_active,
                        "lease_active": self._lease_id is not None,
                        "active_block_ids": [v["block_id"] for v in self._active.values()],
                        "rolled_back_block_ids": list(self._rolled_back),
                    }
                    if rollback_error is not None:
                        reply["rollback_error"] = rollback_error
                    return reply
                if not self._lease_id or req.get("lease_id") != self._lease_id:
                    return {"ok": False, "error": "invalid_or_expired_lease"}
                if op == "rollback":
                    try:
                        cleared = self._rollback_locked(str(req.get("reason", "rollback")))
                    except (RuntimeError, subprocess.SubprocessError, OSError):
                        # Mark the lease expired so the watchdog keeps retrying deletion.
                        self._lease_deadline = now
                        raise
                    self._rolled_back.clear()
                    return {
                        "ok": True,
                        "status": "rolled_back",
                        "cleared_block_ids": cleared,
                        "command": _nft_rollback_cmd(),
                    }
                if now >= self._lease_deadline:
                    self._rollback_locked("lease_expired")
                    return {"ok": False, "error": "lease_expired"}
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
                    code, err = self._run_nft(cmd)
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
                    cmd = _nft_unblock_cmd(ip)
                    code, err = self._run_nft(cmd)
                    if code != 0 and "No such file" not in err and "does not exist" not in err:
                        return {"ok": False, "error": f"nft_delete_failed: {err.strip()}"}
                    del self._active[ip]
                    return self._remember_op_locked(op_id, {
                        "ok": True,
                        "status": "unblocked",
                        "block_id": current["block_id"],
                        "command": cmd,
                    })
                return {"ok": False, "error": "unsupported_operation"}
            except (KeyError, ValueError, TypeError) as exc:
                return {"ok": False, "error": f"validation_error: {exc}"}
            except (RuntimeError, subprocess.SubprocessError, OSError) as exc:
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

    def _resolve_socket_ownership(self):
        uid = self.socket_uid
        if uid is None and os.geteuid() == 0:
            non_root = [candidate for candidate in self.allowed_uids if candidate != 0]
            if len(non_root) == 1:
                uid = non_root[0]
            elif os.environ.get("SUDO_UID", "").isdigit():
                uid = int(os.environ["SUDO_UID"])
        gid = self.socket_gid
        if gid is None and os.geteuid() == 0 and uid is not None:
            if os.environ.get("SUDO_GID", "").isdigit() and str(uid) == os.environ.get("SUDO_UID"):
                gid = int(os.environ["SUDO_GID"])
            else:
                try:
                    gid = pwd.getpwuid(uid).pw_gid
                except KeyError:
                    gid = None
        return uid, gid

    def start(self):
        if self._sock is not None:
            raise RuntimeError("Helper server already started")
        parent = self.socket_path.parent
        norm_parent = os.path.normpath(str(parent))
        created_parent = not parent.exists()
        parent.mkdir(parents=True, exist_ok=True)
        uid, gid = self._resolve_socket_ownership()
        if self.dir_mode is not None and norm_parent not in _SHARED_DIRS and not parent.is_symlink():
            st = parent.stat()
            is_sticky_public = bool(st.st_mode & stat.S_ISVTX)
            is_dedicated = created_parent or parent.name in _DEDICATED_DIR_NAMES
            if not is_sticky_public and is_dedicated and (created_parent or (os.geteuid() == 0 and st.st_uid == 0)):
                if os.geteuid() == 0 and gid is not None:
                    os.chown(parent, 0, gid)
                os.chmod(parent, self.dir_mode)
        if self.socket_path.is_symlink():
            raise FileExistsError(f"Refusing to bind over symlink: {self.socket_path}")
        if self.socket_path.is_socket():
            self.socket_path.unlink()
        elif self.socket_path.exists():
            raise FileExistsError(f"Refusing to overwrite non-socket file: {self.socket_path}")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(self.socket_path))
        if uid is not None or gid is not None:
            os.chown(self.socket_path, -1 if uid is None else uid, -1 if gid is None else gid)
        os.chmod(self.socket_path, self.socket_mode)
        sock.listen(16)
        sock.settimeout(0.2)
        self._sock = sock
        self._stop.clear()
        self._thread = Thread(target=self._loop, name="securenet-fw-helper", daemon=True)
        self._thread.start()
        return self

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.check_lease()
            except (RuntimeError, subprocess.SubprocessError, OSError) as exc:
                print(f"Firewall helper lease rollback failed (will retry): {exc}", file=sys.stderr, flush=True)
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
            except (RuntimeError, subprocess.SubprocessError, OSError):
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
    parser.add_argument("--socket-uid", type=int, default=None)
    parser.add_argument("--socket-gid", type=int, default=None)
    parser.add_argument("--socket-mode", type=lambda v: int(v, 8), default=0o660)
    parser.add_argument("--dir-mode", type=lambda v: int(v, 8), default=0o750)
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
            socket_uid=args.socket_uid,
            socket_gid=args.socket_gid,
            socket_mode=args.socket_mode,
            dir_mode=args.dir_mode,
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

