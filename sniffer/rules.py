"""Bounded repeated-flow policy for dry-run proposals, not calibrated prevention."""

from collections import OrderedDict, deque
from dataclasses import dataclass, asdict
import time

from sniffer.events import finite_number

AUTH_PORTS = frozenset({21, 22, 23, 3389, 5900})


@dataclass(frozen=True)
class Decision:
    action: str
    reason: str
    evidence_count: int = 0
    threat: str | None = None

    def to_dict(self):
        return {k: v for k, v in asdict(self).items() if v is not None}


class ResponsePolicy:
    def __init__(self, confidence=0.90, min_flows=3, window_seconds=60,
                 max_sources=4096, clock=time.monotonic, clock_mode="monotonic",
                 burst_rules=True, auth_burst_flows=10, flood_burst_flows=30,
                 burst_window_seconds=10.0):
        if clock_mode not in ("monotonic", "event_time"):
            raise ValueError("clock_mode must be monotonic or event_time")
        if not isinstance(burst_rules, bool):
            raise ValueError("burst_rules must be a boolean")
        self.clock_mode, self._watermark = clock_mode, float("-inf")
        self.confidence = finite_number(confidence, "confidence threshold", maximum=1)
        self.window = finite_number(window_seconds, "evidence window", minimum=0.001)
        self.burst_window = finite_number(burst_window_seconds, "burst window", minimum=0.001)
        for name, value in (("min_flows", min_flows), ("max_sources", max_sources),
                            ("auth_burst_flows", auth_burst_flows), ("flood_burst_flows", flood_burst_flows)):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10000:
                raise ValueError(f"{name} must be an integer from 1 to 10000")
        self.min_flows, self.max_sources, self.clock = min_flows, max_sources, clock
        self.burst_rules = burst_rules
        self.auth_burst_flows, self.flood_burst_flows = auth_burst_flows, flood_burst_flows
        self._evidence, self._seen = OrderedDict(), OrderedDict()
        self._auth_bursts, self._flood_bursts = OrderedDict(), OrderedDict()
        self._unblocked_at = OrderedDict()

    def clear_source(self, src_ip, unblocked_at=None):
        """Drop accumulated evidence for an unblocked source and ignore older live flows."""
        for store in (self._evidence, self._auth_bursts, self._flood_bursts):
            for key in [k for k in store if k[1] == src_ip]:
                del store[key]
        if unblocked_at is not None:
            self._unblocked_at[src_ip] = unblocked_at
            self._unblocked_at.move_to_end(src_ip)
            while len(self._unblocked_at) > self.max_sources:
                self._unblocked_at.popitem(last=False)

    def _prune_stores(self, now):
        cutoff, burst_cutoff = now - self.window, now - self.burst_window
        for store, limit in ((self._evidence, cutoff), (self._seen, cutoff),
                             (self._auth_bursts, burst_cutoff), (self._flood_bursts, burst_cutoff)):
            while store:
                first = next(iter(store))
                last_time = store[first][-1] if store is self._seen else store[first][-1][1]
                if last_time >= limit:
                    break
                store.popitem(last=False)

    def _record_burst(self, store, key, event_id, now, maxlen):
        history = store.setdefault(key, deque(maxlen=maxlen))
        cutoff = now - self.burst_window
        while history and history[0][1] < cutoff:
            history.popleft()
        history.append((event_id, now))
        store.move_to_end(key)
        while len(store) > self.max_sources:
            store.popitem(last=False)
        return len(history)

    def _evaluate_burst(self, event, now):
        if not self.burst_rules or event.features["Protocol"] != 6:
            return None
        dport = int(event.features["Dst Port"])
        if dport in AUTH_PORTS and event.features["Packet Length Max"] <= 512:
            count = self._record_burst(
                self._auth_bursts, (event.model_sha256, event.src_ip),
                event.event_id, now, self.auth_burst_flows,
            )
            if count >= self.auth_burst_flows:
                return Decision("candidate", "rule:auth_burst", count, threat="BRUTE_FORCE")
        elif dport not in AUTH_PORTS and dport != 53:
            count = self._record_burst(
                self._flood_bursts, (event.model_sha256, event.src_ip, event.dst_ip, dport),
                event.event_id, now, self.flood_burst_flows,
            )
            if count >= self.flood_burst_flows:
                return Decision("candidate", "rule:service_flood", count, threat="DOS")
        return None

    def evaluate(self, event):
        if self.clock_mode == "event_time":
            if any(value is None for value in (event.capture_start, event.capture_time, event.capture_available_at)):
                return Decision("alert", "capture_time_unavailable")
            now = event.capture_available_at.timestamp()
            if now < self._watermark:
                return Decision("alert", "late_capture_event")
        else:
            now = self.clock()
        self._watermark = max(self._watermark, now)
        self._prune_stores(now)
        # Historical label policies differ; they must not inherit unified response rules.
        if event.model_scope != "unified":
            return Decision("ignore", "benign") if event.label == "BENIGN" else Decision("alert", "historical_model_alert_only")
        if event.label == "WEB_ATTACK":
            return Decision("alert", "web_coverage_unvalidated")
        if event.event_id in self._seen:
            return Decision("ignore", "duplicate_event")
        self._seen[event.event_id] = (now,)
        if len(self._seen) > 8192:
            self._seen.popitem(last=False)
        if event.source == "live" and event.src_ip in self._unblocked_at:
            event_time = event.capture_time or event.observed_at
            if event_time <= self._unblocked_at[event.src_ip]:
                return Decision("ignore", "pre_unblock_stale_flow")
        if event.label != "BENIGN" and event.confidence >= self.confidence:
            cutoff = now - self.window
            key = (event.model_sha256, event.src_ip, event.label)
            history = self._evidence.setdefault(key, deque(maxlen=self.min_flows))
            while history and history[0][1] < cutoff:
                history.popleft()
            history.append((event.event_id, now))
            self._evidence.move_to_end(key)
            if len(self._evidence) > self.max_sources:
                self._evidence.popitem(last=False)
            if len(history) >= self.min_flows:
                return Decision("candidate", "repeated_high_score_flows", len(history))
            burst = self._evaluate_burst(event, now)
            return burst or Decision("alert", "insufficient_repeated_flows", len(history))
        burst = self._evaluate_burst(event, now)
        if burst is not None:
            return burst
        if event.label == "BENIGN":
            return Decision("ignore", "benign")
        return Decision("alert", "below_confidence_threshold")
