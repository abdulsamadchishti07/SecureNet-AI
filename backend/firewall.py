
"""Firewall controller supporting default dry-run simulation and helper-mediated enforcement."""

from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv4Network
import time
from uuid import uuid4

from backend.fw_client import nft_unblock_command
from sniffer.events import finite_number

DEFAULT_PROTECTED = ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4")
PROTECTED_CIDRS = DEFAULT_PROTECTED


class FirewallController:
    mode = "dry_run"

    def __init__(self, protected=(), duration_seconds=900, max_blocks=None,
                 clock=time.monotonic, mode="dry_run", helper_client=None,
                 allow_unprotected=False):
        if mode not in ("dry_run", "enforced"):
            raise ValueError("mode must be 'dry_run' or 'enforced'")
        self.mode = mode
        self.helper_client = helper_client
        self.allow_unprotected = bool(allow_unprotected)
        user_protected = tuple(IPv4Network(cidr, strict=False) for cidr in protected)
        if mode == "enforced":
            if helper_client is None:
                raise ValueError("Enforced mode requires a helper_client")
            if not user_protected and not self.allow_unprotected:
                raise ValueError("Enforced mode requires at least one protected CIDR or allow_unprotected=True")
        if max_blocks is None:
            max_blocks = 256 if mode == "enforced" else 4096
        self.protected = tuple(IPv4Network(cidr, strict=False) for cidr in (*DEFAULT_PROTECTED, *user_protected))
        self.duration = finite_number(duration_seconds, "block duration", minimum=0.001, maximum=86400)
        if isinstance(max_blocks, bool) or not isinstance(max_blocks, int) or max_blocks < 1:
            raise ValueError("max_blocks must be a positive integer")
        self.max_blocks, self.clock, self._blocks = max_blocks, clock, {}

    def start(self):
        if self.mode == "enforced":
            return self.helper_client.start()
        return None

    def heartbeat(self):
        if self.mode == "enforced":
            return self.helper_client.heartbeat()
        return None

    def rollback(self, reason="shutdown"):
        self._blocks.clear()
        if self.mode == "enforced":
            return self.helper_client.rollback(reason)
        return None

    def is_whitelisted(self, ip):
        address = IPv4Address(ip)
        return any(address in network for network in self.protected)

    @staticmethod
    def _command(ip, operation):
        return ["iptables", "-w", "2", operation, "INPUT", "-s", ip,
                "-m", "comment", "--comment", "securenet-ai", "-j", "DROP"]

    def block_ip(self, ip, threat):
        if not isinstance(ip, str):
            raise ValueError("IP address must be an IPv4 string")
        ip = str(IPv4Address(ip))
        if not isinstance(threat, str) or not threat or threat == "BENIGN":
            raise ValueError("A non-benign threat label is required")
        action = {"mode": self.mode, "ip": ip, "threat": threat}
        if self.is_whitelisted(ip):
            return {**action, "status": "protected"}
        if ip in self._blocks:
            status = "already_blocked" if self.mode == "enforced" else "already_simulated"
            return {**action, "status": status, "block": dict(self._blocks[ip][0])}
        if len(self._blocks) >= self.max_blocks:
            return {**action, "status": "capacity_reached"}
        created = datetime.now(timezone.utc)
        block = {"block_id": str(uuid4()), "ip": ip, "threat": threat, "mode": self.mode,
                 "blocked_at": created.isoformat(),
                 "unblock_at": (created + timedelta(seconds=self.duration)).isoformat()}
        if self.mode == "enforced":
            ttl = max(1, min(86400, round(self.duration)))
            reply = self.helper_client.block(ip, ttl, block_id=block["block_id"])
            if reply["status"] in ("protected", "capacity_reached"):
                return {**action, "status": reply["status"]}
            if reply["status"] == "already_blocked":
                return {**action, "status": "already_blocked", "block": dict(block)}
            self._blocks[ip] = (block, self.clock() + self.duration)
            return {**action, "status": "blocked", "block": dict(block), "command": reply["command"]}
        self._blocks[ip] = (block, self.clock() + self.duration)
        return {**action, "status": "would_block", "block": dict(block),
                "command": self._command(ip, "-A")}

    def unblock_ip(self, ip, reason="manual", block_id=None):
        ip = str(IPv4Address(ip))
        current = self._blocks.get(ip)
        if current and block_id is not None and current[0]["block_id"] != block_id:
            return {"mode": self.mode, "ip": ip, "block_id": block_id,
                    "status": "stale_block", "reason": reason, "command": None}
        previous = self._blocks.pop(ip, None)
        target_block_id = previous[0]["block_id"] if previous else block_id
        if self.mode == "enforced":
            reply = self.helper_client.unblock(ip, block_id=target_block_id)
            if reply["status"] == "stale_block":
                return {"mode": "enforced", "ip": ip, "block_id": block_id,
                        "status": "stale_block", "reason": reason, "command": None}
            unblocked = previous is not None and reply["status"] in ("unblocked", "already_unblocked")
            command = (reply.get("command") or nft_unblock_command(ip)) if unblocked else None
            return {"mode": "enforced", "ip": ip, "block_id": target_block_id,
                    "status": "unblocked" if unblocked else "already_unblocked",
                    "reason": reason, "command": command}
        return {"mode": self.mode, "ip": ip,
                "block_id": target_block_id,
                "status": "would_unblock" if previous else "not_simulated",
                "reason": reason, "command": self._command(ip, "-D") if previous else None}

    def expire(self):
        now = self.clock()
        return [self.unblock_ip(ip, reason="expired")
                for ip, (_, deadline) in list(self._blocks.items()) if now >= deadline]

    def list_active_blocks(self):
        return [dict(block) for block, _ in list(self._blocks.values())]
