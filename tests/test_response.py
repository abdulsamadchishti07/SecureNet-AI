"""Event, transport, policy and audit regressions; no live prevention claim."""

from dataclasses import FrozenInstanceError, replace
from datetime import datetime
import json
from queue import Empty
from threading import Event

import pytest

from backend.firewall import FirewallController
from backend.worker import ResponseDispatcher
from sniffer.events import EventValidationError
from sniffer.publisher import EventQueue
from sniffer.rules import ResponsePolicy


def test_event_snapshot_is_immutable_and_json_serializable(response_event_factory):
    event = response_event_factory()
    record = event.to_dict()
    assert record["model_run"] == "unified_v1"
    assert record["source"] == "pcap"
    assert len(record["features"]) == 20
    assert len(record["probabilities"]) == 7
    assert record["observed_at"].endswith("+00:00")
    assert json.loads(json.dumps(record, allow_nan=False)) == record
    record["features"]["Src Port"] = 9
    assert event.features["Src Port"] == 40000
    with pytest.raises(TypeError):
        event.features["Src Port"] = 9
    with pytest.raises(FrozenInstanceError):
        event.label = "BENIGN"


@pytest.mark.parametrize("change", [
    {"src_ip": "1.2.3.4; touch /tmp/injection"}, {"dst_ip": "::1"},
    {"src_ip": 1}, {"source": "unknown"}, {"model_sha256": "bad"},
    {"observed_at": datetime(2026, 1, 1)}, {"confidence": float("nan")},
    {"confidence": True}, {"confidence": 1.1}, {"confidence": 0.5},
    {"probabilities": {}}, {"label": "UNKNOWN"}, {"event_id": "not-a-uuid"},
    {"model_scope": "friday"},
])
def test_invalid_event_metadata_is_rejected(response_event_factory, change):
    with pytest.raises(EventValidationError):
        replace(response_event_factory(), **change)


@pytest.mark.parametrize("column,value", [
    ("Src Port", -1), ("Src Port", 1.5), ("Src Port", 65536), ("Dst Port", 65536),
    ("Protocol", 256), ("Protocol", 6.5), ("Flow Duration", float("inf")),
    ("Flow IAT Mean", -0.1), ("Packet Length Mean", "1"), ("ACK Flag Count", True),
])
def test_invalid_event_features_are_rejected(response_event_factory, column, value):
    event = response_event_factory()
    with pytest.raises(EventValidationError):
        replace(event, features={**event.features, column: value})


def test_event_requires_all_features_and_consistent_probabilities(response_event_factory):
    event = response_event_factory()
    with pytest.raises(EventValidationError):
        replace(event, features={k: v for k, v in event.features.items() if k != "Flow Duration"})
    with pytest.raises(EventValidationError):
        replace(event, probabilities={**event.probabilities, "BENIGN": 0.9})


def test_queue_overflow_is_counted_and_close_drains_existing_events(response_event_factory):
    queue = EventQueue(capacity=1)
    event = response_event_factory()
    assert queue.publish(event)
    assert not queue.publish(response_event_factory())
    assert queue.stats() == {"accepted": 1, "dropped": 1, "pending": 1, "capacity": 1}
    queue.close()
    assert queue.get(timeout=0) is event
    with pytest.raises(Empty):
        queue.get(timeout=0)
    with pytest.raises(RuntimeError, match="closed"):
        queue.publish(event)
    with pytest.raises(TypeError):
        EventQueue().publish({"label": "PORTSCAN"})


@pytest.mark.parametrize("options", [
    {"confidence": float("nan")}, {"confidence": 1.1}, {"window_seconds": 0},
    {"min_flows": 0}, {"min_flows": True}, {"max_sources": 0},
])
def test_policy_configuration_is_validated(options):
    with pytest.raises(ValueError):
        ResponsePolicy(**options)


@pytest.mark.parametrize("label,confidence,reason", [
    ("BENIGN", 0.99, "benign"), ("WEB_ATTACK", 0.99, "web_coverage_unvalidated"),
    ("PORTSCAN", 0.89, "below_confidence_threshold"),
])
def test_policy_never_promotes_benign_web_or_low_score(response_event_factory, label, confidence, reason):
    policy = ResponsePolicy(min_flows=1)
    decision = policy.evaluate(response_event_factory(label=label, confidence=confidence))
    assert decision.action != "candidate"
    assert decision.reason == reason


def test_policy_requires_distinct_events_within_window_and_same_source(response_event_factory, manual_clock):
    policy = ResponsePolicy(min_flows=2, window_seconds=10, clock=manual_clock)
    first = response_event_factory()
    assert policy.evaluate(first).evidence_count == 1
    assert policy.evaluate(first).reason == "duplicate_event"
    assert policy.evaluate(response_event_factory(src_ip="10.10.0.8")).action == "alert"
    manual_clock.advance(11)
    assert policy.evaluate(response_event_factory()).action == "alert"
    decision = policy.evaluate(response_event_factory(confidence=0.90))
    assert decision.action == "candidate"
    assert decision.evidence_count == 2


def test_policy_separates_models_and_bounds_source_memory(response_event_factory):
    policy = ResponsePolicy(min_flows=2, max_sources=1)
    first = response_event_factory()
    assert policy.evaluate(first).action == "alert"
    changed_model = replace(response_event_factory(), model_sha256="b" * 64)
    assert policy.evaluate(changed_model).action == "alert"
    assert len(policy._evidence) == 1
    assert policy.evaluate(response_event_factory()).action == "alert"


def test_historical_scope_is_alert_only(response_event_factory):
    event = response_event_factory()
    event = replace(event, model_scope="friday",
                    probabilities={k: v for k, v in event.probabilities.items()
                                   if k in {"BENIGN", "BOTNET", "DDOS", "PORTSCAN"}})
    assert ResponsePolicy(min_flows=1).evaluate(event).reason == "historical_model_alert_only"


def test_dispatcher_drains_logs_all_decisions_and_appends(response_event_factory, tmp_path):
    path = tmp_path / "alerts.jsonl"
    policy = ResponsePolicy(min_flows=2)
    events = [response_event_factory(), response_event_factory(), response_event_factory(),
              response_event_factory(label="BENIGN"), response_event_factory(label="WEB_ATTACK")]
    with ResponseDispatcher(path, policy=policy) as worker:
        for event in events:
            assert worker.publish(event)
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert [r["event"]["event_id"] for r in records] == [e.event_id for e in events]
    assert [r["firewall"]["status"] for r in records if r["firewall"]] == ["would_block", "already_simulated"]
    assert worker.stats()["processed"] == 5
    assert worker.stats()["pending"] == worker.stats()["dropped"] == 0
    assert worker.stats()["would_block"] == 1
    assert all(r["mode"] == "dry_run" for r in records)
    with ResponseDispatcher(path) as second:
        assert second.publish(response_event_factory())
    assert len(path.read_text().splitlines()) == 6
    assert path.stat().st_mode & 0o777 == 0o600


def test_worker_failure_surfaces_instead_of_silent_loss(response_event_factory, tmp_path, monkeypatch):
    worker = ResponseDispatcher(tmp_path / "alerts.jsonl")
    entered_write = Event()

    def fail_write(record):
        entered_write.set()
        raise OSError("disk full")

    monkeypatch.setattr(worker, "_write", fail_write)
    with pytest.raises(RuntimeError, match="worker failed") as caught:
        with worker:
            worker.publish(response_event_factory())
            assert entered_write.wait(timeout=2)
    assert isinstance(caught.value.__cause__, OSError)
    assert worker.stats()["worker_failed"]
    assert worker.stats()["processed"] == 0
    with pytest.raises(RuntimeError, match="worker failed"):
        worker.publish(response_event_factory())


def test_shutdown_drains_a_publish_that_raced_the_queue_timeout(response_event_factory, tmp_path, monkeypatch):
    worker = ResponseDispatcher(tmp_path / "alerts.jsonl")
    queued = Event()
    original_get = worker.publisher.get
    first = True

    def timeout_after_final_publish(timeout):
        nonlocal first
        if first:
            first = False
            worker.publisher.publish(response_event_factory())
            worker.publisher.close()
            queued.set()
            raise Empty
        return original_get(timeout)

    monkeypatch.setattr(worker.publisher, "get", timeout_after_final_publish)
    with worker:
        assert queued.wait(timeout=2)
    assert worker.stats()["processed"] == 1
    assert worker.stats()["pending"] == worker.stats()["unlogged"] == 0


def test_idle_worker_expires_simulated_blocks(response_event_factory, manual_clock, tmp_path, monkeypatch):
    expired = Event()
    firewall = FirewallController(duration_seconds=1, clock=manual_clock)
    worker = ResponseDispatcher(tmp_path / "alerts.jsonl", firewall=firewall,
                                policy=ResponsePolicy(min_flows=1))
    write = worker._write

    def advance_after_detection(record):
        write(record)
        if record["record_type"] == "detection":
            manual_clock.advance(2)
        else:
            expired.set()

    monkeypatch.setattr(worker, "_write", advance_after_detection)
    with worker:
        worker.publish(response_event_factory())
        assert expired.wait(timeout=2)
    records = [json.loads(line) for line in worker.log_path.read_text().splitlines()]
    assert records[1]["action"]["status"] == "would_unblock"
    assert records[1]["action"]["reason"] == "expired"
    assert worker.stats()["active_simulated_blocks"] == 0
