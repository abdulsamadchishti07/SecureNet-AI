"""Capture-clock semantics and synthetic sensitivity; no independent calibration claim."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json

import pytest

from sniffer.calibration import calibrate, load_events
from sniffer.events import DetectionEvent, EventValidationError
from sniffer.extractor import FlowTable, Packet, RST, SYN
from sniffer.main import main
from sniffer.rules import ResponsePolicy

T0 = datetime(2023, 11, 14, tzinfo=timezone.utc)


def timed(factory, seconds, start=None, **kwargs):
    end = T0 + timedelta(seconds=seconds)
    return factory(capture_time=end, capture_start=end if start is None else T0 + timedelta(seconds=start),
                   capture_available_at=end, **kwargs)


def test_event_capture_metadata_roundtrip_and_observation_remains_processing(response_event_factory):
    event = timed(response_event_factory, 2, start=1)
    assert event.capture_time < event.observed_at
    assert event.to_dict()['capture_start'] == (T0 + timedelta(seconds=1)).isoformat()
    assert len(event.to_dict()['features']) == 20
    assert 'capture_time' not in response_event_factory().to_dict()
    flow = {**event.features, 'Src IP': event.src_ip, 'Dst IP': event.dst_ip,
            'flow_start_usec': int(T0.timestamp() * 1e6),
            'flow_end_usec': int((T0.timestamp() + 1) * 1e6),
            'flow_emitted_usec': int((T0.timestamp() + 6) * 1e6)}
    rebuilt = DetectionEvent.from_flow(flow, event.to_dict(), model_scope='unified',
                                      model_sha256='a' * 64, source='pcap')
    assert (rebuilt.capture_available_at - rebuilt.capture_time).total_seconds() == 5


@pytest.mark.parametrize('changes', [
    {'capture_time': datetime(2023, 1, 1)},
    {'capture_time': None}, {'capture_start': T0 + timedelta(seconds=5)},
    {'capture_available_at': T0 - timedelta(seconds=5)},
])
def test_invalid_capture_metadata_rejected(response_event_factory, changes):
    with pytest.raises(EventValidationError):
        replace(timed(response_event_factory, 1), **changes)


def test_fast_replay_boundary_equal_time_and_gap(response_event_factory):
    policy = ResponsePolicy(min_flows=3, window_seconds=10, clock_mode='event_time')
    assert policy.evaluate(timed(response_event_factory, 0)).evidence_count == 1
    assert policy.evaluate(timed(response_event_factory, 5)).evidence_count == 2
    assert policy.evaluate(timed(response_event_factory, 10)).action == 'candidate'
    assert policy.evaluate(timed(response_event_factory, 10)).action == 'candidate'
    assert policy.evaluate(timed(response_event_factory, 100)).evidence_count == 1


def test_late_event_rejected_and_benign_advances_watermark(response_event_factory):
    policy = ResponsePolicy(min_flows=2, clock_mode='event_time')
    policy.evaluate(timed(response_event_factory, 1))
    assert policy.evaluate(timed(response_event_factory, 100, label='BENIGN')).action == 'ignore'
    assert policy.evaluate(timed(response_event_factory, 2)).reason == 'late_capture_event'
    assert policy.evaluate(timed(response_event_factory, 101)).evidence_count == 1
    assert policy.evaluate(timed(response_event_factory, 99, label='BENIGN')).reason == 'late_capture_event'


def test_duplicate_and_missing_time_never_count(response_event_factory):
    policy = ResponsePolicy(min_flows=2, clock_mode='event_time')
    assert policy.evaluate(response_event_factory()).reason == 'capture_time_unavailable'
    event = timed(response_event_factory, 1)
    assert policy.evaluate(event).evidence_count == 1
    assert policy.evaluate(event).reason == 'duplicate_event'
    assert policy.evaluate(timed(response_event_factory, 2)).action == 'candidate'


def test_availability_not_end_time_drives_policy(response_event_factory):
    policy = ResponsePolicy(min_flows=2, window_seconds=5, clock_mode='event_time')
    first = replace(timed(response_event_factory, 1), capture_available_at=T0 + timedelta(seconds=10))
    second = replace(timed(response_event_factory, 2), capture_available_at=T0 + timedelta(seconds=20))
    assert policy.evaluate(first).evidence_count == 1
    assert policy.evaluate(second).evidence_count == 1


def test_flow_emission_records_expiry_and_eof_time():
    table = FlowTable()
    table.add(Packet(1_000_000, '10.0.0.1', 1234, '10.0.0.2', 80, 6, 0, SYN, None))
    table.add(Packet(1_000_044, '10.0.0.2', 80, '10.0.0.1', 1234, 6, 0, RST, None))
    row, = table.expire(7_000_000)
    assert row['flow_end_usec'] == 1_000_044
    assert row['flow_emitted_usec'] == 7_000_000
    assert table.flush(9_000_000) == []
    other = FlowTable()
    other.add(Packet(1, '10.0.0.1', 1234, '10.0.0.2', 53, 17, 4, 0, None))
    other.add(Packet(2, '10.0.0.2', 53, '10.0.0.1', 1234, 17, 4, 0, None))
    row, = other.flush(9)
    assert row['flow_emitted_usec'] == 9


def test_sensitivity_grid_labels_prediction_limits_and_truth(response_event_factory, tmp_path):
    events = [timed(response_event_factory, index, start=0) for index in range(3)]
    report = calibrate(events, min_flows=[2, 3, 4], windows=[60])
    assert [r['candidate_events'] for r in report['runs']] == [2, 1, 0]
    assert report['runs'][1]['first_candidate_delays'][0]['delay_seconds'] == 2
    assert report['runs'][0]['benign_triggered_candidates'] is None
    truth = {e.event_id: 'BENIGN' for e in events}
    assert calibrate(events, truth=truth)['runs'][0]['benign_triggered_candidates'] == 2
    with pytest.raises(ValueError, match='exactly'):
        calibrate(events, truth={})
    path = tmp_path / 'events.jsonl'
    path.write_text('\n'.join(json.dumps({'event': e.to_dict()}) for e in events))
    assert load_events(path) == events


@pytest.mark.parametrize('args', [
    ['-i', 'unused', '--predict', '--respond', '--clock-mode', 'event_time'],
    ['-r', 'unused', '--predict', '--clock-mode', 'event_time'],
])
def test_event_clock_requires_offline_response(args):
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2


@pytest.mark.parametrize('post_candidate', [True, False])
def test_false_candidate_before_attack_onset_does_not_hide_miss_or_latency(response_event_factory, post_candidate):
    early = timed(response_event_factory, 5)
    attack = timed(response_event_factory, 12, start=10, confidence=0.99 if post_candidate else 0.8)
    truth = {early.event_id: 'BENIGN', attack.event_id: 'PORTSCAN'}
    result = calibrate([early, attack], confidences=[0.9], min_flows=[1], windows=[60], truth=truth)['runs'][0]
    assert result['pre_onset_candidate_events'] == 1
    if post_candidate:
        assert result['first_candidate_delays'][0]['delay_seconds'] == 2
        assert result['sources_without_candidate'] == []
    else:
        assert result['first_candidate_delays'] == []
        assert result['sources_without_candidate'] == [early.src_ip]


def test_capture_clock_does_not_advance_runtime_firewall_ttl(response_event_factory, manual_clock):
    from backend.firewall import FirewallController
    firewall = FirewallController(clock=manual_clock, duration_seconds=5)
    policy = ResponsePolicy(min_flows=1, clock_mode='event_time')
    first, later = timed(response_event_factory, 1), timed(response_event_factory, 1000)
    assert policy.evaluate(first).action == 'candidate'
    firewall.block_ip(first.src_ip, first.label)
    assert policy.evaluate(later).action == 'candidate'
    assert firewall.expire() == []
    manual_clock.advance(6)
    assert len(firewall.expire()) == 1
