"""Unprivileged Unix-socket client and canonical command builders for fw_helper."""

import json
from pathlib import Path
import socket
from uuid import uuid4


class EnforcementError(RuntimeError):
    """Raised when the privileged firewall helper fails, disconnects, or rejects enforcement."""


def nft_block_command(ip, ttl):
    return ["nft", "add", "element", "ip", "securenet", "blocked_ips", "{", f"{ip} timeout {int(ttl)}s", "}"]


def nft_unblock_command(ip):
    return ["nft", "delete", "element", "ip", "securenet", "blocked_ips", "{", str(ip), "}"]


def nft_rollback_command():
    return ["nft", "delete", "table", "ip", "securenet"]


class FwHelperClient:
    """Synchronous length-bounded JSON-RPC client over AF_UNIX stream socket."""

    def __init__(self, socket_path="runtime/fw_helper.sock", timeout=2.0):
        self.socket_path = Path(socket_path)
        self.timeout = float(timeout)
        self.lease_id = None
        self.startup_rolled_back = ()

    def _call(self, payload):
        raw = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
        if len(raw) > 4096:
            raise EnforcementError("Helper request exceeds 4096 bytes")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(self.timeout)
                client.connect(str(self.socket_path))
                client.sendall(raw)
                chunks, size = [], 0
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > 65536:
                        raise EnforcementError("Oversized response from firewall helper")
                    if b"\n" in chunk:
                        break
        except OSError as exc:
            raise EnforcementError(f"Firewall helper communication failed: {exc}") from exc
        line = b"".join(chunks).split(b"\n", 1)[0]
        if not line:
            raise EnforcementError("Empty response from firewall helper")
        try:
            response = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise EnforcementError("Malformed JSON from firewall helper") from exc
        if not isinstance(response, dict) or not response.get("ok"):
            error = response.get("error", "unknown_helper_error") if isinstance(response, dict) else "invalid_response"
            raise EnforcementError(f"Firewall helper rejected operation: {error}")
        return response

    def start(self):
        response = self._call({"op": "hello"})
        self.lease_id = response["lease_id"]
        self.startup_rolled_back = tuple(response.get("rolled_back_block_ids", ()))
        return response

    def heartbeat(self):
        if not self.lease_id:
            raise EnforcementError("Firewall helper lease is not initialized")
        return self._call({"op": "heartbeat", "lease_id": self.lease_id})

    def block(self, ip, ttl, block_id, op_id=None):
        if not self.lease_id:
            raise EnforcementError("Firewall helper lease is not initialized")
        return self._call({
            "op": "block",
            "lease_id": self.lease_id,
            "op_id": str(op_id or uuid4()),
            "block_id": str(block_id),
            "ip": str(ip),
            "ttl": int(ttl),
        })

    def unblock(self, ip, block_id=None, op_id=None):
        if not self.lease_id:
            raise EnforcementError("Firewall helper lease is not initialized")
        return self._call({
            "op": "unblock",
            "lease_id": self.lease_id,
            "op_id": str(op_id or uuid4()),
            "block_id": str(block_id) if block_id is not None else None,
            "ip": str(ip),
        })

    def rollback(self, reason="shutdown"):
        try:
            response = self._call({"op": "rollback", "lease_id": self.lease_id, "reason": str(reason)})
        finally:
            self.lease_id = None
        return response

    def status(self):
        return self._call({"op": "status"})

