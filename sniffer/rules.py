"""Bounded repeated-flow policy for dry-run proposals, not calibrated prevention."""

from collections import OrderedDict, deque
from dataclasses import dataclass, asdict
import time

from sniffer.events import finite_number


@dataclass(frozen=True)
class Decision:
    action: str
    reason: str
    evidence_count: int = 0

    def to_dict(self):
        return asdict(self)


class ResponsePolicy:
    def __init__(self, confidence=0.90, min_flows=3, window_seconds=60,
                 max_sources=4096, clock=time.monotonic, clock_mode="monotonic"):
        if clock_mode not in ("monotonic", "event_time"):
            raise ValueError("clock_mode must be monotonic or event_time")
        self.clock_mode, self._watermark = clock_mode, float("-inf")
        self.confidence = finite_number(confidence, "confidence threshold", maximum=1)
        self.window = finite_number(window_seconds, "evidence window", minimum=0.001)
        for name, value in (("min_flows", min_flows), ("max_sources", max_sources)):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10000:
                raise ValueError(f"{name} must be an integer from 1 to 10000")
        self.min_flows, self.max_sources, self.clock = min_flows, max_sources, clock
        self._evidence, self._seen = OrderedDict(), OrderedDict()

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
        cutoff = now - self.window
        for store in (self._evidence, self._seen):
            while store:
                first = next(iter(store))
                last_time = store[first][-1] if store is self._seen else store[first][-1][1]
                if last_time >= cutoff:
                    break
                store.popitem(last=False)
        if event.label == "BENIGN":
            return Decision("ignore", "benign")
        # Historical label policies differ; they must not inherit unified response rules.
        if event.model_scope != "unified":
            return Decision("alert", "historical_model_alert_only")
        if event.label == "WEB_ATTACK":
            return Decision("alert", "web_coverage_unvalidated")
        if event.confidence < self.confidence:
            return Decision("alert", "below_confidence_threshold")
        if event.event_id in self._seen:
            return Decision("ignore", "duplicate_event")
        self._seen[event.event_id] = (now,)
        if len(self._seen) > 8192:
            self._seen.popitem(last=False)
        key = (event.model_sha256, event.src_ip, event.label)
        history = self._evidence.setdefault(key, deque(maxlen=self.min_flows))
        while history and history[0][1] < cutoff:
            history.popleft()
        history.append((event.event_id, now))
        self._evidence.move_to_end(key)
        if len(self._evidence) > self.max_sources:
            self._evidence.popitem(last=False)
        if len(history) < self.min_flows:
            return Decision("alert", "insufficient_repeated_flows", len(history))
        return Decision("candidate", "repeated_high_score_flows", len(history))
