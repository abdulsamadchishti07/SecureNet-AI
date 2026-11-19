"""Bounded delivery, flood resistance, transport safety and response integration."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import socketserver
import subprocess
import sys
from threading import Event, Thread
from uuid import uuid4

import pytest

from backend.config import NotificationSettings
from backend.firewall import FirewallController
from backend.notifier import (BlockNotification, NotificationManager, NotificationTransport,
                              test_notification as sample_notification)
from backend.worker import ResponseDispatcher
from sniffer.rules import ResponsePolicy


def config(**kwargs):
    return NotificationSettings(ALERT_NOTIFICATIONS_ENABLED=True,
                                ALERT_WEBHOOK_URL="http://127.0.0.1:9/lab", **kwargs)


class RecordingTransport:
    def __init__(self):
        self.messages = []
        self.called = Event()

    def webhook(self, alert):
        self.messages.append(alert)
        self.called.set()


def alert(ip="192.0.2.10", **kwargs):
    return replace(sample_notification(), ip=ip, mode="enforced", test=False, **kwargs)


@pytest.mark.parametrize("change", [
    {"ALERT_COOLDOWN_SECONDS": 599}, {"ALERT_MAX_PER_HOUR": 31}, {"ALERT_MAX_PER_HOUR": True},
    {"ALERT_QUEUE_SIZE": 0}, {"SMTP_PORT": 65536}, {"SMTP_SECURITY": "none"},
    {"ALERT_INCLUDE_DRY_RUN": "false"},
    {"ALERT_WEBHOOK_URL": "http://example.com/secret"}, {"ALERT_WEBHOOK_URL": "file:///tmp/x"},
    {"ALERT_WEBHOOK_URL": "https://u:password@example.com/path"},
    {"ALERT_WEBHOOK_URL": "https://example.com/#secret"},
    {"ALERT_WEBHOOK_URL": "https://example.com:bad/path"},
    {"ALERT_WEBHOOK_FORMAT": "invalid"},
    {"SMTP_HOST": "example.com", "SMTP_SECURITY": "plain"},
    {"SMTP_HOST": "example.com", "SMTP_SENDER": "bad\r\nInjected:yes"},
    {"SMTP_HOST": "localhost", "SMTP_SENDER": "sensor@example.com", "ALERT_EMAIL_RECIPIENT": "ops@example.com", "SMTP_USER": "user"},
])
def test_notification_config_fails_closed(change):
    with pytest.raises(ValueError):
        NotificationSettings(ALERT_NOTIFICATIONS_ENABLED=True, **change).validate_notifications()


def test_response_payload_only_new_confirmed_or_simulated_blocks(response_event_factory):
    event = response_event_factory()
    firewall = FirewallController()
    action = firewall.block_ip(event.src_ip, event.label)
    message = BlockNotification.from_response(event, action, "lab")
    assert message.mode == "dry_run" and not message.payload()["enforced"]
    assert "SIMULATED BLOCK" in message.summary()
    assert "features" not in message.payload()
    for status in ("already_simulated", "already_blocked", "protected", "capacity_reached", "unblocked"):
        assert BlockNotification.from_response(event, {**action, "status": status}, "lab") is None
    assert BlockNotification.from_response(event, None, "lab") is None
    enforced = BlockNotification.from_response(event, {**action, "mode": "enforced", "status": "blocked"}, "lab")
    assert enforced.payload()["enforced"] and "ENFORCED BLOCK" in enforced.summary()
    rule_benign = response_event_factory(label="BENIGN")
    rule_action = firewall.block_ip(rule_benign.src_ip, "BRUTE_FORCE")
    rule_msg = BlockNotification.from_response(rule_benign, {**rule_action, "mode": "enforced", "status": "blocked"}, "lab")
    assert rule_msg.threat == "BRUTE_FORCE"
    with pytest.raises(ValueError, match="target"):
        BlockNotification.from_response(event, {**action, "ip": "192.0.2.99"}, "lab")


def test_disabled_default_and_simulation_opt_in():
    transport = RecordingTransport()
    manager = NotificationManager(NotificationSettings(), transport).start()
    assert not manager.dispatch_alert(alert())
    manager.close()
    assert transport.messages == [] and manager._thread is None
    manager = NotificationManager(config(), transport).start()
    assert not manager.dispatch_alert(replace(alert(), mode="dry_run"))
    manager.close()
    manager = NotificationManager(config(ALERT_INCLUDE_DRY_RUN=True), transport).start()
    assert manager.dispatch_alert(replace(alert(), mode="dry_run"))
    manager.close()
    assert len(transport.messages) == 1


def test_ip_cooldown_and_block_dedup_survive_window_boundaries(manual_clock):
    transport = RecordingTransport()
    manager = NotificationManager(config(), transport, clock=manual_clock)
    first = alert()
    manager._deliver(first)
    manual_clock.advance(599)
    manager._deliver(alert())
    manual_clock.advance(1)
    manager._deliver(first)  # Block UUID still deduplicated after the IP cooldown.
    manager._deliver(alert())
    assert len(transport.messages) == 2
    assert manager.stats()["suppressed"] == 2
    manual_clock.advance(3000)
    manager._deliver(first)
    assert len(transport.messages) == 3


def test_global_sliding_hour_is_atomic_under_concurrent_flood(manual_clock):
    transport = RecordingTransport()
    manager = NotificationManager(config(), transport, clock=manual_clock)
    messages = [alert(f"192.0.2.{n}") for n in range(1, 101)]
    with ThreadPoolExecutor(max_workers=12) as executor:
        list(executor.map(manager._deliver, messages))
    assert len(transport.messages) == 30
    manual_clock.advance(3599)
    manager._deliver(alert("198.51.100.1"))
    assert len(transport.messages) == 30
    manual_clock.advance(1)
    manager._deliver(alert("198.51.100.1"))
    assert len(transport.messages) == 31


def test_failed_delivery_consumes_quota_and_redacts_secrets(manual_clock, caplog):
    class Offline:
        def webhook(self, message):
            raise OSError("https://secret.example/token SMTP_PASSWORD=private-value")
    manager = NotificationManager(config(ALERT_MAX_PER_HOUR=1), Offline(), clock=manual_clock)
    with caplog.at_level(logging.WARNING):
        manager._deliver(alert())
        manager._deliver(alert("192.0.2.11"))
    assert manager.stats()["failed"] == manager.stats()["suppressed"] == 1
    assert "private-value" not in caplog.text and "secret.example" not in caplog.text


def test_queue_overflow_and_shutdown_are_bounded():
    entered, release = Event(), Event()
    class Slow:
        def webhook(self, message):
            entered.set()
            release.wait(5)
    manager = NotificationManager(config(ALERT_QUEUE_SIZE=1), Slow()).start()
    assert manager.dispatch_alert(alert()) and entered.wait(2)
    assert manager.dispatch_alert(alert("192.0.2.11"))
    assert not manager.dispatch_alert(alert("192.0.2.12"))
    manager.close(timeout=0.01)
    assert manager.stats()["dropped"] == manager.stats()["abandoned"] == 1
    assert not manager.dispatch_alert(alert("192.0.2.13"))
    release.set()
    manager._thread.join(timeout=2)
    assert not manager._thread.is_alive()


def test_key_capacity_does_not_evict_live_cooldowns(manual_clock):
    transport = RecordingTransport()
    manager = NotificationManager(config(), transport, clock=manual_clock, max_keys=1)
    first = alert()
    manager._deliver(first)
    manager._deliver(alert("192.0.2.11"))
    manager._deliver(first)
    assert len(transport.messages) == 1
    assert manager.stats()["suppressed"] == 2


def test_log_only_is_throttled_and_not_counted_as_delivery(caplog):
    manager = NotificationManager(NotificationSettings(ALERT_NOTIFICATIONS_ENABLED=True))
    first = alert()
    with caplog.at_level(logging.INFO):
        manager._deliver(first)
        manager._deliver(first)
    assert manager.stats()["logged"] == manager.stats()["suppressed"] == 1
    assert manager.stats()["sent"] == 0
    assert "log-only" in caplog.text


@pytest.mark.parametrize("format_name,field", [("generic", "block_id"), ("slack", "text"), ("discord", "content")])
def test_real_loopback_webhook_payload_and_no_redirect(format_name, field):
    received = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(302 if self.path == "/redirect" else 204)
            self.send_header("Location", "/unexpected")
            self.end_headers()

        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        settings = NotificationSettings(ALERT_NOTIFICATIONS_ENABLED=True, ALERT_WEBHOOK_URL=url,
                                        ALERT_WEBHOOK_FORMAT=format_name)
        transport = NotificationTransport(settings)
        transport.webhook(alert())
        assert field in received[0]
        if format_name == "discord":
            assert received[0]["allowed_mentions"] == {"parse": []}
        settings.ALERT_WEBHOOK_URL = url + "/redirect"
        with pytest.raises(OSError):
            transport.webhook(alert())
        assert len(received) == 2  # Redirect never received a third request.
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("security", ["starttls", "ssl"])
def test_smtp_requires_verified_tls_before_login(monkeypatch, security):
    calls = []
    class SMTP:
        def __init__(self, **kwargs):
            calls.append(("connect", kwargs))
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def starttls(self, context):
            calls.append(("tls", context))
        def login(self, user, password):
            calls.append(("login", user))
        def send_message(self, message):
            calls.append(("send", message))
    monkeypatch.setattr("backend.notifier.smtplib.SMTP", SMTP)
    monkeypatch.setattr("backend.notifier.smtplib.SMTP_SSL", SMTP)
    settings = NotificationSettings(ALERT_NOTIFICATIONS_ENABLED=True, SMTP_HOST="smtp.example.com",
                                    SMTP_SECURITY=security, SMTP_USER="user", SMTP_PASSWORD="private",
                                    SMTP_SENDER="sensor@example.com", ALERT_EMAIL_RECIPIENT="ops@example.com")
    NotificationTransport(settings.validate_notifications()).smtp(alert())
    context = calls[0][1]["context"] if security == "ssl" else calls[1][1]
    assert context.check_hostname and context.verify_mode.name == "CERT_REQUIRED"
    assert [name for name, _ in calls][-2:] == ["login", "send"]
    assert "ENFORCED BLOCK" in calls[-1][1].get_content()


def test_real_loopback_smtp_delivery():
    received = []
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.wfile.write(b"220 localhost ready\r\n")
            while line := self.rfile.readline():
                verb = line.split()[0].upper()
                if verb == b"DATA":
                    self.wfile.write(b"354 send message\r\n")
                    lines = []
                    while (line := self.rfile.readline()) not in (b".\r\n", b""):
                        lines.append(line)
                    received.append(b"".join(lines).decode())
                if verb == b"QUIT":
                    self.wfile.write(b"221 bye\r\n")
                    return
                self.wfile.write(b"250 OK\r\n")
    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            settings = NotificationSettings(ALERT_NOTIFICATIONS_ENABLED=True, SMTP_HOST="127.0.0.1",
                SMTP_PORT=server.server_address[1], SMTP_SECURITY="plain", SMTP_SENDER="sensor@example.com",
                ALERT_EMAIL_RECIPIENT="ops@example.com")
            NotificationTransport(settings.validate_notifications()).smtp(alert())
            assert len(received) == 1 and "ENFORCED BLOCK" in received[0]
            assert "To: ops@example.com" in received[0]
        finally:
            server.shutdown()
            thread.join(timeout=2)


def test_response_worker_notifies_once_and_network_failure_does_not_break_processing(tmp_path, response_event_factory):
    class Offline:
        def webhook(self, message):
            raise OSError("offline")
    manager = NotificationManager(config(ALERT_INCLUDE_DRY_RUN=True), Offline())
    with ResponseDispatcher(tmp_path / "alerts.jsonl", policy=ResponsePolicy(min_flows=2), notifier=manager) as worker:
        for _ in range(8):
            worker.publish(response_event_factory())
    assert worker.stats()["processed"] == 8
    assert worker.stats()["notifications"]["failed"] == 1
    assert worker.stats()["notifications"]["queued"] == 1
    assert not worker.stats()["worker_failed"]


def test_confirmed_enforcement_dispatches_after_helper_success(tmp_path, response_event_factory):
    from backend.fw_helper import FwHelperServer
    from backend.fw_client import FwHelperClient
    transport = RecordingTransport()
    manager = NotificationManager(config(), transport)
    with FwHelperServer(socket_path=tmp_path / "helper.sock", runner=lambda *args, **kw: (0, "")):
        firewall = FirewallController(mode="enforced", helper_client=FwHelperClient(tmp_path / "helper.sock"),
                                      protected=["10.10.0.1/32"])
        with ResponseDispatcher(tmp_path / "confirmed.jsonl", policy=ResponsePolicy(min_flows=1),
                                firewall=firewall, notifier=manager) as worker:
            worker.publish(response_event_factory())
            assert transport.called.wait(2)
    assert len(transport.messages) == 1 and transport.messages[0].payload()["enforced"]


def test_failed_enforcement_never_emits_notification(tmp_path, response_event_factory):
    from backend.fw_helper import FwHelperServer
    from backend.fw_client import FwHelperClient
    transport = RecordingTransport()
    def runner(args, **kwargs):
        return (1, "denied") if args[:3] == ["nft", "add", "element"] else (0, "")
    with FwHelperServer(socket_path=tmp_path / "helper.sock", runner=runner):
        firewall = FirewallController(mode="enforced", helper_client=FwHelperClient(tmp_path / "helper.sock"),
                                      protected=["10.10.0.1/32"])
        with pytest.raises(RuntimeError, match="Response worker failed"):
            with ResponseDispatcher(tmp_path / "failed.jsonl", policy=ResponsePolicy(min_flows=1),
                    firewall=firewall, notifier=NotificationManager(config(), transport)) as worker:
                worker.publish(response_event_factory())
    assert not transport.messages


def test_management_preview_needs_no_database_or_network(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "invalid")
    monkeypatch.setenv("ALERT_NOTIFICATIONS_ENABLED", "false")
    result = subprocess.run([sys.executable, "-m", "backend.manage", "test-alert-notification"],
                            capture_output=True, text=True, check=True)
    message = json.loads(result.stdout)
    assert message["preview"] and message["alert"]["test"] and not message["alert"]["enforced"]


def test_management_invalid_notification_config_exits_cleanly(monkeypatch):
    monkeypatch.setenv("ALERT_COOLDOWN_SECONDS", "10")
    result = subprocess.run([sys.executable, "-m", "backend.manage", "test-alert-notification"],
                            capture_output=True, text=True)
    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    assert "ALERT_COOLDOWN_SECONDS" in result.stderr
