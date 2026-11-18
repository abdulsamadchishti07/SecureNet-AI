"""Best-effort bounded notifications; network I/O never runs in the response consumer."""

from collections import OrderedDict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from ipaddress import IPv4Address
import json
import logging
from queue import Empty, Full, Queue
import smtplib
import ssl
from threading import Event, Lock, Thread
import time
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID, uuid4

from backend.config import NotificationSettings

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class BlockNotification:
    event_id: str
    block_id: str
    ip: str
    threat: str
    mode: str
    observed_at: str
    sensor_id: str
    test: bool = False

    @classmethod
    def from_response(cls, event, action, sensor_id):
        if not action or (action.get("mode"), action.get("status")) not in (
                ("enforced", "blocked"), ("dry_run", "would_block")):
            return None
        block = action.get("block", {})
        if action.get("ip") != event.src_ip or block.get("ip") != event.src_ip:
            raise ValueError("Notification block target does not match the event")
        return cls(str(UUID(event.event_id)), str(UUID(block["block_id"])),
                   str(IPv4Address(event.src_ip)), event.label, action["mode"],
                   event.observed_at.isoformat(), sensor_id)

    def payload(self):
        return {"schema_version": 1, "type": "threat_block", **asdict(self),
                "enforced": self.mode == "enforced" and not self.test}

    def summary(self):
        state = "TEST" if self.test else "ENFORCED BLOCK" if self.mode == "enforced" else "SIMULATED BLOCK"
        return f"SecureNet AI {state}: {self.threat} from {self.ip}; block {self.block_id}; sensor {self.sensor_id}"


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Do not forward a webhook secret or security event to another destination.


class NotificationTransport:
    def __init__(self, config, timeout=3):
        self.config, self.timeout = config, timeout

    def smtp(self, alert):
        config = self.config
        message = EmailMessage()
        message["Subject"] = f"SecureNet AI: {'TEST' if alert.test else alert.mode} {alert.threat}"
        message["From"], message["To"] = config.SMTP_SENDER, config.ALERT_EMAIL_RECIPIENT
        message.set_content(alert.summary() + "\n\n" + json.dumps(alert.payload(), indent=2))
        kwargs = {"host": config.SMTP_HOST, "port": config.SMTP_PORT, "timeout": self.timeout}
        if config.SMTP_SECURITY == "ssl":
            connection = smtplib.SMTP_SSL(**kwargs, context=ssl.create_default_context())
        else:
            connection = smtplib.SMTP(**kwargs)
        with connection as smtp:
            if config.SMTP_SECURITY == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            if config.SMTP_USER:
                smtp.login(config.SMTP_USER, config.SMTP_PASSWORD)
            smtp.send_message(message)

    def webhook(self, alert):
        config = self.config
        if config.ALERT_WEBHOOK_FORMAT == "slack":
            payload = {"text": alert.summary()}
        elif config.ALERT_WEBHOOK_FORMAT == "discord":
            payload = {"content": alert.summary(), "allowed_mentions": {"parse": []}}
        else:
            payload = alert.payload()
        request = Request(config.ALERT_WEBHOOK_URL, data=json.dumps(payload).encode(),
                          headers={"Content-Type": "application/json", "User-Agent": "SecureNetAI/1"}, method="POST")
        # Direct delivery, no ambient proxies, redirects or response-body buffering.
        with build_opener(ProxyHandler({}), NoRedirects()).open(request, timeout=self.timeout) as response:
            if not 200 <= response.status < 300:
                raise OSError("Webhook rejected notification")


class NotificationManager:
    def __init__(self, config=None, transport=None, clock=time.monotonic, max_keys=4096):
        self.config = (config if config is not None else NotificationSettings()).validate_notifications()
        self.transport = transport if transport is not None else NotificationTransport(self.config)
        if isinstance(max_keys, bool) or not isinstance(max_keys, int) or max_keys < 1:
            raise ValueError("max_keys must be a positive integer")
        self.clock, self.max_keys = clock, max_keys
        self._queue = Queue(maxsize=self.config.ALERT_QUEUE_SIZE)
        self._lock, self._stop = Lock(), Event()
        self._thread = None
        self._in_flight = 0
        self._closed = False
        self._ips, self._blocks, self._window = OrderedDict(), OrderedDict(), deque()
        self._counts = dict(queued=0, sent=0, failed=0, logged=0, suppressed=0, dropped=0, abandoned=0)

    def start(self):
        if self._closed or self._thread is not None:
            raise RuntimeError("Notification manager can only be started once")
        if self.config.ALERT_NOTIFICATIONS_ENABLED:
            self._thread = Thread(target=self._run, name="securenet-notifications", daemon=True)
            self._thread.start()
        return self

    def dispatch_alert(self, alert):
        if alert is None:
            return False
        with self._lock:
            if (self._closed or not self.config.ALERT_NOTIFICATIONS_ENABLED
                    or (alert.mode == "dry_run" and not self.config.ALERT_INCLUDE_DRY_RUN and not alert.test)):
                return False
            if self._thread is None:
                raise RuntimeError("Start the notification manager before dispatching")
            try:
                self._queue.put_nowait(alert)
            except Full:
                self._counts["dropped"] += 1
                return False
            self._counts["queued"] += 1
            return True

    def _admit(self, alert):
        # Executed at send time so a stalled transport cannot bunch reserved quotas.
        now = self.clock()
        with self._lock:
            for store, ttl in ((self._ips, self.config.ALERT_COOLDOWN_SECONDS),
                               (self._blocks, max(3600, self.config.ALERT_COOLDOWN_SECONDS))):
                while store and next(iter(store.values())) <= now - ttl:
                    store.popitem(last=False)
            while self._window and self._window[0] <= now - 3600:
                self._window.popleft()
            if (alert.ip in self._ips or alert.block_id in self._blocks
                    or len(self._window) >= self.config.ALERT_MAX_PER_HOUR
                    or len(self._ips) >= self.max_keys or len(self._blocks) >= self.max_keys):
                self._counts["suppressed"] += 1
                return False
            # Attempts, including failures, consume budget. Active keys are never evicted.
            self._ips[alert.ip] = self._blocks[alert.block_id] = now
            self._window.append(now)
        return True

    def _deliver(self, alert):
        if not self._admit(alert):
            return
        channels = (["smtp"] if self.config.SMTP_HOST else []) + (["webhook"] if self.config.ALERT_WEBHOOK_URL else [])
        if not channels:
            LOG.warning("Notification log-only: %s", alert.summary())
            with self._lock:
                self._counts["logged"] += 1
        for channel in channels:
            try:
                getattr(self.transport, channel)(alert)
            except Exception:
                # SMTP/HTTP exception messages may contain credentials, URLs or response bodies.
                LOG.warning("Notification channel=%s failed; no automatic retry", channel)
                with self._lock:
                    self._counts["failed"] += 1
            else:
                with self._lock:
                    self._counts["sent"] += 1

    def _run(self):
        while not self._stop.is_set():
            try:
                alert = self._queue.get(timeout=0.05)
            except Empty:
                if self._closed:
                    return
                continue
            with self._lock:
                self._in_flight += 1
            try:
                self._deliver(alert)
            finally:
                with self._lock:
                    self._in_flight -= 1
                self._queue.task_done()

    def close(self, timeout=2):
        with self._lock:
            self._closed = True
        if self._thread:
            self._thread.join(timeout=timeout)
        self._stop.set()
        # A slow in-flight network attempt can finish on the daemon thread; discard the rest.
        while True:
            try:
                self._queue.get_nowait()
                self._queue.task_done()
                with self._lock:
                    self._counts["abandoned"] += 1
            except Empty:
                break

    def stats(self):
        with self._lock:
            return {**self._counts, "pending": self._queue.qsize(),
                    "in_flight": self._in_flight,
                    "enabled": self.config.ALERT_NOTIFICATIONS_ENABLED}


def test_notification(sensor_id="sensor-local"):
    """Explicitly marked synthetic message for the management CLI, never a real block."""
    return BlockNotification(str(uuid4()), str(uuid4()), "192.0.2.10", "PORTSCAN", "dry_run",
                             datetime.now(timezone.utc).isoformat(), sensor_id, test=True)
