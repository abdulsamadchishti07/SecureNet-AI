"""Bounded, nonblocking in-process event transport; no implicit broker fallback."""

from queue import Queue, Full
from threading import Lock

from sniffer.events import DetectionEvent


class EventQueue:
    """One-process transport. Overflow drops the incoming event and is counted."""

    def __init__(self, capacity=1024):
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ValueError("Queue capacity must be a positive integer")
        self._queue = Queue(maxsize=capacity)
        self._lock = Lock()
        self._closed = False
        self._accepted = self._dropped = 0

    def publish(self, event):
        if not isinstance(event, DetectionEvent):
            raise TypeError("Only validated DetectionEvent values can be published")
        with self._lock:
            if self._closed:
                raise RuntimeError("Event queue is closed")
            try:
                self._queue.put_nowait(event)
            except Full:
                self._dropped += 1
                return False
            self._accepted += 1
            return True

    def get(self, timeout=0.1):
        return self._queue.get(timeout=timeout)

    def close(self):
        with self._lock:
            self._closed = True

    @property
    def closed(self):
        with self._lock:
            return self._closed

    def stats(self):
        with self._lock:
            return {"accepted": self._accepted, "dropped": self._dropped,
                    "pending": self._queue.qsize(), "capacity": self._queue.maxsize}
