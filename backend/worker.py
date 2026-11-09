"""Single local consumer: policy -> simulated firewall -> append-only JSONL audit & API forwarder."""

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty
from threading import Thread

from backend.firewall import FirewallController
from sniffer.publisher import EventQueue
from sniffer.rules import ResponsePolicy


class ResponseDispatcher:
    def __init__(self, log_path, capacity=1024, policy=None, firewall=None, api_url=None):
        self.publisher = EventQueue(capacity)
        self.policy = policy if policy is not None else ResponsePolicy()
        self.firewall = firewall if firewall is not None else FirewallController()
        self.log_path = Path(log_path)
        self.api_url = str(api_url).rstrip("/") if api_url else None
        self.processed = self.would_block = self.would_unblock = 0
        self.api_forwarded = self.api_failed = 0
        self._error = self._thread = self._log = None

    def __enter__(self):
        if self._thread is not None or self.publisher.closed:
            raise RuntimeError("Dispatcher instances can only be started once")
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self._log = os.fdopen(descriptor, "a", encoding="utf-8", buffering=1)
        self._thread = Thread(target=self._run, name="securenet-response", daemon=True)
        self._thread.start()
        return self

    def _write(self, record):
        self._log.write(json.dumps({"schema_version": 1, "mode": "dry_run",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "policy": {"confidence_threshold": self.policy.confidence,
                       "min_flows": self.policy.min_flows, "window_seconds": self.policy.window},
            "firewall_config": {"duration_seconds": self.firewall.duration,
                                "protected_cidrs": [str(cidr) for cidr in self.firewall.protected]}, **record},
                                   allow_nan=False) + "\n")

    def _forward_to_api(self, event_dict, decision_dict, firewall_action):
        if not self.api_url:
            return
        payload = json.dumps({
            "event": event_dict,
            "decision": decision_dict,
            "firewall": firewall_action,
        }, allow_nan=False).encode("utf-8")
        req = urllib.request.Request(
            f"{self.api_url}/api/alerts/ingest",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if resp.status in (200, 201):
                    self.api_forwarded += 1
                else:
                    self.api_failed += 1
        except Exception:
            self.api_failed += 1

    def _run(self):
        try:
            while True:
                for action in self.firewall.expire():
                    self._write({"record_type": "firewall", "action": action})
                    self.would_unblock += 1
                try:
                    event = self.publisher.get(timeout=0.1)
                except Empty:
                    # A final publish can race the get timeout just before close.
                    # Once closed, no producer can add more; drain that last item too.
                    if self.publisher.closed and self.publisher.stats()["pending"] == 0:
                        break
                    continue
                decision = self.policy.evaluate(event)
                action = (self.firewall.block_ip(event.src_ip, event.label)
                          if decision.action == "candidate" else None)
                self._write({"record_type": "detection", "event": event.to_dict(),
                             "decision": decision.to_dict(), "firewall": action})
                if self.api_url:
                    self._forward_to_api(event.to_dict(), decision.to_dict(), action)
                self.processed += 1
                self.would_block += int(action is not None and action["status"] == "would_block")
        except Exception as exc:
            self._error = exc
            self.publisher.close()

    def publish(self, event):
        if self._thread is None:
            raise RuntimeError("Start the dispatcher before publishing")
        if self._error is not None:
            raise RuntimeError("Response worker failed; check the audit log") from self._error
        return self.publisher.publish(event)

    def close(self):
        self.publisher.close()
        if self._thread is not None:
            self._thread.join(timeout=10)
            if self._thread.is_alive():
                raise RuntimeError("Response worker did not stop within 10 seconds")
        if self._log is not None:
            self._log.close()
        if self._error is not None:
            raise RuntimeError("Response worker failed; accepted events may be unlogged") from self._error

    def stats(self):
        queue_stats = self.publisher.stats()
        return {"mode": "dry_run", **queue_stats, "processed": self.processed,
                "unlogged": queue_stats["accepted"] - self.processed,
                "would_block": self.would_block, "would_unblock": self.would_unblock,
                "api_forwarded": self.api_forwarded, "api_failed": self.api_failed,
                "active_simulated_blocks": len(self.firewall.list_active_blocks()),
                "worker_failed": self._error is not None, "log_path": str(self.log_path)}

    def __exit__(self, exc_type, exc, traceback):
        self.close()
