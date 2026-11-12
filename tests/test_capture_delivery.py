"""Optional capture metadata survives strict ingestion without changing legacy identities."""
from datetime import datetime, timedelta, timezone
import json

import pytest

from backend.models import Alert
from backend.service import fingerprint


def test_capture_timing_persisted_and_broadcast(backend_runtime, sensor_headers, admin_headers, payload_factory):
    body = payload_factory()
    capture = datetime(2023, 11, 14, tzinfo=timezone.utc)
    body['event'].update(capture_start=capture.isoformat(),
                         capture_time=(capture + timedelta(seconds=1)).isoformat(),
                         capture_available_at=(capture + timedelta(seconds=6)).isoformat())
    client = backend_runtime.client
    with client.websocket_connect('/ws/alerts', headers=admin_headers) as socket:
        assert client.post('/api/alerts/ingest', json=body, headers=sensor_headers).status_code == 201
        streamed = socket.receive_json()
        assert datetime.fromisoformat(streamed['capture_time']) == datetime.fromisoformat(body['event']['capture_time'])
    assert client.post('/api/alerts/ingest', json=body, headers=sensor_headers).status_code == 200
    with backend_runtime.sessions() as db:
        row = db.query(Alert).one()
        assert len(row.features) == 20
        assert datetime.fromisoformat(row.payload['event']['capture_available_at']) == datetime.fromisoformat(body['event']['capture_available_at'])
        assert row.observed_at > capture
    listed = client.get('/api/alerts', headers=admin_headers).json()
    assert datetime.fromisoformat(listed[0]['capture_start']) == datetime.fromisoformat(body['event']['capture_start'])
    body['event']['capture_available_at'] = (capture + timedelta(seconds=7)).isoformat()
    assert client.post('/api/alerts/ingest', json=body, headers=sensor_headers).status_code == 409


def test_legacy_fingerprint_stays_unchanged(backend_runtime, sensor_headers, payload_factory):
    from backend.schemas import AlertIngest
    body = payload_factory()
    normalized = AlertIngest.model_validate(body).model_dump(mode='json')
    for name in ('capture_time', 'capture_start', 'capture_available_at'):
        del normalized['event'][name]
    expected = fingerprint(normalized, sensor_headers['X-Sensor-ID'])
    client = backend_runtime.client
    assert client.post('/api/alerts/ingest', json=body, headers=sensor_headers).status_code == 201
    with backend_runtime.sessions() as db:
        assert db.query(Alert).one().payload_sha256 == expected
    assert client.post('/api/alerts/ingest', json=body, headers=sensor_headers).status_code == 200


@pytest.mark.parametrize('changes', [
    {'capture_time': '2023-01-01T00:00:00'},
    {'capture_start': '2023-01-01T00:00:00+00:00'},
    {'capture_start': '2024-01-01T00:00:00+00:00', 'capture_time': '2023-01-01T00:00:00+00:00'},
    {'capture_time': '2023-01-01T00:00:00+00:00', 'capture_available_at': '2022-01-01T00:00:00+00:00'},
])
def test_capture_delivery_validates_time_order(backend_runtime, sensor_headers, payload_factory, changes):
    body = payload_factory()
    body['event'].update(changes)
    assert backend_runtime.client.post('/api/alerts/ingest', json=body, headers=sensor_headers).status_code == 422
