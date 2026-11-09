"""Durable retry, sensor lifecycle integration and slow-client isolation."""

import asyncio
import json
from threading import Event

import pytest

from backend.firewall import FirewallController
from backend.outbox import ApiTransport, DeliveryError, Outbox
from backend.realtime import ConnectionManager, WebSocketTickets
from backend.worker import ResponseDispatcher
from sniffer.rules import ResponsePolicy


class ClientTransport:
    """Exercise the real ASGI app without an external HTTP connection."""
    def __init__(self, client, headers):
        self.client, self.headers = client, headers
        self.ingested, self.acked, self.expired = Event(), Event(), Event()

    def request(self, path, payload=None):
        response = (self.client.get(path, headers=self.headers) if payload is None else
                    self.client.post(path, json=payload, headers=self.headers))
        if response.status_code >= 400:
            raise DeliveryError(f"HTTP {response.status_code}", response.status_code >= 500)
        if path == "/api/alerts/ingest":
            self.ingested.set()
        elif path.endswith("/ack"):
            self.acked.set()
        elif path == "/api/sensor/firewall-events":
            self.expired.set()
        return response.json()


def test_outbox_persists_order_and_retries_after_restart(tmp_path, manual_clock):
    path = tmp_path / "outbox.sqlite3"
    outbox = Outbox(path, "local|sensor", clock=manual_clock)
    outbox.enqueue("one", "/api/alerts/ingest", {"value": 1})
    outbox.enqueue("two", "/api/alerts/ingest", {"value": 2})
    outbox.failed("one", DeliveryError("offline"))
    assert outbox.next_message() is None  # Preserve causal order while the head retries.
    outbox.close()
    manual_clock.advance(3)
    restored = Outbox(path, "local|sensor", clock=manual_clock)
    assert restored.stats() == {"pending": 2, "failed": 0}
    assert restored.next_message()[0] == "one"
    restored.delivered("one")
    assert restored.next_message()[0] == "two"
    restored.close()


def test_outbox_bounds_retries_and_retains_dead_letters(tmp_path, manual_clock):
    outbox = Outbox(tmp_path / "retry.sqlite3", "local|sensor", clock=manual_clock)
    outbox.enqueue("event", "/ingest", {"value": 1})
    for _ in range(8):
        outbox.failed("event", DeliveryError("temporary"))
        manual_clock.advance(61)
    assert outbox.stats() == {"pending": 0, "failed": 1}
    assert outbox.contains("event")
    outbox.retry_failed()
    assert outbox.next_message()[0] == "event"
    outbox.failed("event", DeliveryError("HTTP 401", retryable=False))
    assert outbox.stats()["failed"] == 1
    outbox.close()


def test_outbox_identity_capacity_and_exclusive_owner(tmp_path):
    path = tmp_path / "bounded.sqlite3"
    outbox = Outbox(path, "local|sensor", capacity=1)
    outbox.enqueue("one", "/ingest", {"a": 1})
    outbox.enqueue("one", "/ingest", {"a": 1})
    with pytest.raises(ValueError, match="different payload"):
        outbox.enqueue("one", "/ingest", {"a": 2})
    with pytest.raises(RuntimeError, match="capacity"):
        outbox.enqueue("two", "/ingest", {"a": 2})
    with pytest.raises(RuntimeError, match="owns this outbox"):
        Outbox(path, "local|sensor")
    outbox.close()
    with pytest.raises(ValueError, match="different API or sensor"):
        Outbox(path, "other|sensor")
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("url,token", [("http://example.com", "s" * 40),
    ("https://user:password@example.com", "s" * 40), ("https://example.com?token=secret", "s" * 40),
    ("file:///tmp/file", "s" * 40), ("http://localhost:8000", "")])
def test_transport_rejects_unsafe_urls_or_missing_credentials(url, token):
    with pytest.raises(ValueError):
        ApiTransport(url, token, "sensor-local")


def test_outage_does_not_block_local_consumer_and_pending_message_survives(tmp_path, response_event_factory):
    called = Event()
    class Offline:
        def request(self, path, payload=None):
            called.set()
            raise DeliveryError("simulated outage")
    path = tmp_path / "offline.jsonl"
    with ResponseDispatcher(path, api_url="http://127.0.0.1:8000", transport=Offline()) as worker:
        for _ in range(5):
            assert worker.publish(response_event_factory())
        assert called.wait(timeout=2)
    stats = worker.stats()
    assert stats["processed"] == 5 and stats["worker_failed"] is False
    assert stats["api_pending"] == 5 and stats["api_failed"] >= 1
    assert len(path.read_text().splitlines()) == 5
    restored = Outbox(path.with_suffix(".outbox.sqlite3"), "http://127.0.0.1:8000|sensor-local")
    assert restored.stats()["pending"] == 5
    restored.close()


def test_mismatched_ack_is_retained_instead_of_counted_delivered(tmp_path, response_event_factory):
    class WrongAcknowledgement:
        def request(self, path, payload=None):
            if payload is None:
                return []
            return {"status": "ingested", "event_id": "wrong-event"}
    with ResponseDispatcher(tmp_path / "bad-ack.jsonl", api_url="http://127.0.0.1:8000",
                            transport=WrongAcknowledgement()) as worker:
        worker.publish(response_event_factory())
    assert worker.stats()["api_forwarded"] == 0
    assert worker.stats()["api_dead_letters"] == 1


def test_sensor_delivery_and_acknowledged_unblock_round_trip(
        backend_runtime, sensor_headers, admin_headers, response_event_factory, tmp_path):
    client = backend_runtime.client
    transport = ClientTransport(client, sensor_headers)
    policy = ResponsePolicy(min_flows=1)
    event = response_event_factory()
    with ResponseDispatcher(tmp_path / "agent.jsonl", policy=policy,
            api_url="http://127.0.0.1:8000", transport=transport) as worker:
        worker.publish(event)
        assert transport.ingested.wait(timeout=5)
        requested = client.post("/api/firewall/unblock/" + event.src_ip, headers=admin_headers)
        assert requested.status_code == 202 and requested.json()["status"] == "PENDING"
        assert transport.acked.wait(timeout=5)
        assert worker.firewall.list_active_blocks() == []
        assert len(client.get("/api/firewall/blocked?status=UNBLOCKED", headers=admin_headers).json()) == 1
    assert worker.stats()["api_pending"] == worker.stats()["api_dead_letters"] == 0
    records = [json.loads(line) for line in worker.log_path.read_text().splitlines()]
    assert records[-1]["record_type"] == "firewall"
    assert records[-1]["action"]["reason"] == "manual"


def test_sensor_expiry_reaches_database_in_causal_order(
        backend_runtime, sensor_headers, admin_headers, response_event_factory, manual_clock, tmp_path, monkeypatch):
    transport = ClientTransport(backend_runtime.client, sensor_headers)
    worker = ResponseDispatcher(tmp_path / "expiry.jsonl", policy=ResponsePolicy(min_flows=1),
        firewall=FirewallController(duration_seconds=1, clock=manual_clock),
        api_url="http://127.0.0.1:8000", transport=transport)
    write = worker._write
    def advance_after_detection(record):
        write(record)
        if record["record_type"] == "detection":
            manual_clock.advance(2)
    monkeypatch.setattr(worker, "_write", advance_after_detection)
    with worker:
        worker.publish(response_event_factory())
        assert transport.expired.wait(timeout=5)
    rows = backend_runtime.client.get("/api/firewall/blocked?status=EXPIRED", headers=admin_headers).json()
    assert len(rows) == 1
    assert worker.stats()["api_dead_letters"] == 0


def test_slow_websocket_cannot_delay_healthy_subscriber():
    async def scenario():
        class Socket:
            def __init__(self, slow=False):
                self.slow, self.received, self.closed = slow, asyncio.Queue(), asyncio.Event()
            async def accept(self):
                pass
            async def send_json(self, message):
                if self.slow:
                    await asyncio.Event().wait()
                self.received.put_nowait(message)
            async def close(self, code):
                self.closed.set()
        manager = ConnectionManager(capacity=1)
        slow, healthy = Socket(True), Socket()
        await manager.connect(slow)
        await manager.connect(healthy)
        for index in range(3):
            manager.broadcast({"index": index})
            assert await asyncio.wait_for(healthy.received.get(), 1) == {"index": index}
        await asyncio.wait_for(slow.closed.wait(), 1)
        assert id(healthy) in manager.connections
        await manager.close()
    asyncio.run(scenario())


def test_websocket_ticket_expiry_and_capacity(manual_clock):
    tickets = WebSocketTickets(clock=manual_clock, capacity=1)
    issued = tickets.issue(1, 1000)
    with pytest.raises(ValueError, match="capacity"):
        tickets.issue(2, 1000)
    manual_clock.advance(31)
    with pytest.raises(ValueError, match="expired"):
        tickets.consume(issued)
    assert tickets.consume(tickets.issue(2, 1000)) == (2, 1000)
