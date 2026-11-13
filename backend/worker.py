"""Local response consumer with durable asynchronous sensor delivery."""

from collections import OrderedDict
from datetime import datetime, timezone
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Thread
import time
from uuid import UUID, uuid4

from backend.firewall import FirewallController
from sniffer.publisher import EventQueue
from sniffer.rules import ResponsePolicy


class ResponseDispatcher:
    def __init__(self, log_path, capacity=1024, policy=None, firewall=None, api_url=None,
                 api_token=None, sensor_id=None, outbox_path=None, transport=None):
        self.publisher = EventQueue(capacity)
        self.policy = policy if policy is not None else ResponsePolicy()
        self.firewall = firewall if firewall is not None else FirewallController()
        self.log_path = Path(log_path)
        self.api_url = str(api_url).rstrip("/") if api_url else None
        self.sensor_id = sensor_id or os.getenv("SENSOR_ID", "sensor-local")
        self.outbox_path = Path(outbox_path) if outbox_path else self.log_path.with_suffix(".outbox.sqlite3")
        self._transport = transport
        if self.api_url and transport is None:
            from backend.outbox import ApiTransport
            # An explicit credential is mandatory; never fall back to anonymous delivery.
            self._transport = ApiTransport(self.api_url, api_token or os.getenv("SENSOR_API_TOKEN", ""), self.sensor_id)
        self.processed = self.would_block = self.would_unblock = 0
        self.enforced_blocks = self.enforced_unblocks = 0
        self._next_heartbeat = 0.0
        self._error = self._thread = self._log = self._sender = self._outbox = None
        self._commands, self._seen_commands = Queue(maxsize=128), OrderedDict()

    def __enter__(self):
        if self._thread is not None or self.publisher.closed:
            raise RuntimeError("Dispatcher instances can only be started once")
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self._log = os.fdopen(descriptor, "a", encoding="utf-8", buffering=1)
        try:
            if self.firewall.mode == "enforced":
                self.firewall.start()
                self._next_heartbeat = time.monotonic() + 4.0
            if self.api_url:
                from backend.outbox import ApiSender, Outbox
                self._outbox = Outbox(self.outbox_path, self.api_url + "|" + self.sensor_id)
                if self.firewall.mode == "enforced":
                    reconcile_payload = {"mode": "enforced", "active_block_ids": [], "reason": "startup_rollback"}
                    self._write({"record_type": "reconcile", **reconcile_payload})
                    self._enqueue_api("reconcile:startup:" + str(uuid4()), "/api/sensor/reconcile", reconcile_payload)
                self._sender = ApiSender(self._outbox, self._transport, self._receive_commands)
                self._sender.start()
            elif self.firewall.mode == "enforced":
                self._write({"record_type": "reconcile", "mode": "enforced", "active_block_ids": [], "reason": "startup_rollback"})
            self._thread = Thread(target=self._run, name="securenet-response", daemon=True)
            self._thread.start()
        except Exception:
            if self.firewall.mode == "enforced":
                try:
                    self.firewall.rollback("startup_failed")
                except Exception:
                    pass
            if self._sender:
                self._sender.close()
            if self._outbox:
                self._outbox.close()
            self._log.close()
            raise
        return self

    def _write(self, record):
        self._log.write(json.dumps({"schema_version": 1, "mode": self.firewall.mode,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "policy": {"confidence_threshold": self.policy.confidence,
                       "min_flows": self.policy.min_flows, "window_seconds": self.policy.window,
                       "clock_mode": self.policy.clock_mode},
            "firewall_config": {"duration_seconds": self.firewall.duration,
                                "clock_mode": "monotonic",
                                "max_blocks": self.firewall.max_blocks,
                                "protected_cidrs": [str(cidr) for cidr in self.firewall.protected]}, **record},
                                   allow_nan=False) + "\n")

    def _enqueue_api(self, identity, path, payload):
        if self._outbox is not None:
            self._outbox.enqueue(identity, path, payload)

    def _receive_commands(self, commands):
        if not isinstance(commands, list) or len(commands) > 100:
            raise ValueError("Invalid command batch")
        for command in commands:
            if (not isinstance(command, dict) or command.get("operation") != "unblock"
                    or command.get("mode") != self.firewall.mode):
                raise ValueError("Unsupported sensor command")
            try:
                identity = str(UUID(command["command_id"]))
                block_id = str(UUID(command["block_id"]))
                ip = str(IPv4Address(command["ip"]))
            except (KeyError, TypeError, AttributeError) as exc:
                raise ValueError("Missing command identity or target") from exc
            if identity in self._seen_commands or self._outbox.contains("ack:" + identity):
                continue
            try:
                self._commands.put_nowait({"command_id": identity, "block_id": block_id, "ip": ip})
            except Full:
                return  # The server retains unacknowledged commands for the next poll.
            self._seen_commands[identity] = True
            if len(self._seen_commands) > 4096:
                self._seen_commands.popitem(last=False)

    def _handle_commands(self):
        while True:
            try:
                command = self._commands.get_nowait()
            except Empty:
                break
            action = self.firewall.unblock_ip(command["ip"], block_id=command["block_id"])
            action["action_id"] = str(uuid4())
            self._write({"record_type": "firewall", "command_id": command["command_id"], "action": action})
            self._enqueue_api("ack:" + command["command_id"],
                "/api/sensor/commands/" + command["command_id"] + "/ack", {"action": action})
            self.would_unblock += int(action["status"] == "would_unblock")
            self.enforced_unblocks += int(action["status"] == "unblocked")

    def _run(self):
        try:
            while True:
                if self.firewall.mode == "enforced" and time.monotonic() >= self._next_heartbeat:
                    self.firewall.heartbeat()
                    self._next_heartbeat = time.monotonic() + 4.0
                self._handle_commands()
                for action in self.firewall.expire():
                    action["action_id"] = str(uuid4())
                    self._write({"record_type": "firewall", "action": action})
                    self._enqueue_api("action:" + action["action_id"], "/api/sensor/firewall-events", action)
                    self.would_unblock += int(action["status"] == "would_unblock")
                    self.enforced_unblocks += int(action["status"] == "unblocked")
                try:
                    event = self.publisher.get(timeout=0.1)
                except Empty:
                    if self.publisher.closed and self.publisher.stats()["pending"] == 0:
                        break
                    continue
                decision = self.policy.evaluate(event)
                action = self.firewall.block_ip(event.src_ip, event.label) if decision.action == "candidate" else None
                payload = {"event": event.to_dict(), "decision": decision.to_dict(), "firewall": action}
                self._write({"record_type": "detection", **payload})
                self._enqueue_api("event:" + event.event_id, "/api/alerts/ingest", payload)
                self.processed += 1
                self.would_block += int(action is not None and action["status"] == "would_block")
                self.enforced_blocks += int(action is not None and action["status"] == "blocked")
                if self._sender and self._sender._error:
                    raise RuntimeError("API sender failed; pending messages remain in the outbox") from self._sender._error
        except Exception as exc:
            self._error = exc
            self.publisher.close()

    def check_health(self):
        if self._error is not None:
            raise RuntimeError("Response worker failed; check the audit log") from self._error
        if self._sender and self._sender._error:
            raise RuntimeError("API sender failed; pending messages remain in the outbox") from self._sender._error

    def publish(self, event):
        if self._thread is None:
            raise RuntimeError("Start the dispatcher before publishing")
        self.check_health()
        return self.publisher.publish(event)

    def close(self):
        self.publisher.close()
        if self._thread is not None:
            self._thread.join(timeout=10)
            if self._thread.is_alive():
                raise RuntimeError("Response worker did not stop within 10 seconds")
        rollback_error = None
        if self.firewall.mode == "enforced":
            reason = "lease_loss_rollback" if self._error is not None else "shutdown_rollback"
            reconcile_payload = {"mode": "enforced", "active_block_ids": [], "reason": reason}
            try:
                if self._log and not self._log.closed:
                    self._write({"record_type": "reconcile", **reconcile_payload})
                self._enqueue_api("reconcile:shutdown:" + str(uuid4()), "/api/sensor/reconcile", reconcile_payload)
            except Exception as exc:
                rollback_error = exc
            try:
                self.firewall.rollback("shutdown")
            except Exception as exc:
                if rollback_error is None:
                    rollback_error = exc
        try:
            if self._sender:
                self._sender.close()
        finally:
            if self._outbox:
                self._outbox.close()
            if self._log:
                self._log.close()
        if self._error:
            raise RuntimeError("Response worker failed; accepted events may be unlogged") from self._error
        if rollback_error:
            raise RuntimeError("Firewall rollback failed during shutdown") from rollback_error

    def stats(self):
        queue_stats = self.publisher.stats()
        delivery = self._outbox.stats() if self._outbox else {"pending": 0, "failed": 0}
        active_count = len(self.firewall.list_active_blocks())
        return {"mode": self.firewall.mode, **queue_stats, "processed": self.processed,
                "unlogged": queue_stats["accepted"] - self.processed,
                "would_block": self.would_block, "would_unblock": self.would_unblock,
                "enforced_blocks": self.enforced_blocks, "enforced_unblocks": self.enforced_unblocks,
                "api_forwarded": self._sender.forwarded if self._sender else 0,
                "api_failed": self._sender.failed if self._sender else 0,
                "api_pending": delivery["pending"], "api_dead_letters": delivery["failed"],
                "active_simulated_blocks": active_count if self.firewall.mode == "dry_run" else 0,
                "active_enforced_blocks": active_count if self.firewall.mode == "enforced" else 0,
                "worker_failed": self._error is not None, "log_path": str(self.log_path)}

    def __exit__(self, exc_type, exc, traceback):
        self.close()
