"""Dashboard serving boundaries and SQL-backed chart contracts."""

from datetime import datetime, timedelta, timezone

import pytest


def test_dashboard_shell_and_assets_have_security_headers(backend_runtime):
    client = backend_runtime.client
    response = client.get("/")
    assert response.status_code == 200
    assert 'id="root"' in response.text and 'type="module"' in response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert "'unsafe-inline'" not in response.headers["content-security-policy"]
    for asset in ("test.js", "test.css"):
        fetched = client.get("/static/" + asset)
        assert fetched.status_code == 200
        assert fetched.headers["cache-control"] == "no-cache"
    assert client.get("/api/stats").status_code == 401


def test_missing_react_build_is_explicit_and_api_stays_available(backend_runtime, tmp_path):
    from fastapi.testclient import TestClient
    from backend.main import create_app
    app = create_app(backend_runtime.config, engine=backend_runtime.engine, frontend_dir=tmp_path / "missing-build")
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 503 and "npm run build" in response.json()["detail"]
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/stats").status_code == 401


@pytest.mark.parametrize("path", ["/static/../backend/.env", "/static/%2e%2e/backend/.env",
    "/static/../../runtime/admin-login.txt", "/static/%2e%2e%2fruntime%2fsensor.env",
    "/backend/.env", "/runtime/sensor.env", "/static/.env"])
def test_static_serving_does_not_expose_project_files(backend_runtime, path):
    assert backend_runtime.client.get(path).status_code == 404


def test_empty_analytics_and_bounds_require_authentication(backend_runtime, admin_headers):
    client = backend_runtime.client
    assert client.get("/api/analytics").status_code == 401
    data = client.get("/api/analytics", headers=admin_headers).json()
    assert data["total_flows"] == data["attack_flows"] == 0
    assert len(data["buckets"]) == 20 and data["top_sources"] == data["protocols"] == []
    for minutes in (0, 14, 10081):
        assert client.get("/api/analytics", params={"minutes": minutes}, headers=admin_headers).status_code == 422


def test_analytics_count_real_windowed_flows_and_exclude_benign_top_sources(
        backend_runtime, sensor_headers, admin_headers, payload_factory, monkeypatch):
    import backend.service as service
    fixed = datetime(2026, 11, 9, 14, 0, 0, tzinfo=timezone.utc)

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed

    monkeypatch.setattr(service, "datetime", FixedDatetime)
    for minutes, label in ((61, "PORTSCAN"), (59, "PORTSCAN"), (30, "PORTSCAN"), (1, "BENIGN")):
        body = payload_factory()
        body["event"]["observed_at"] = (fixed - timedelta(minutes=minutes)).isoformat()
        if label == "BENIGN":
            probabilities = body["event"]["probabilities"]
            probabilities["BENIGN"], probabilities["PORTSCAN"] = probabilities["PORTSCAN"], probabilities["BENIGN"]
            body["event"]["label"] = "BENIGN"
            body["decision"] = {"action": "ignore", "reason": "benign", "evidence_count": 0}
        assert backend_runtime.client.post("/api/alerts/ingest", headers=sensor_headers, json=body).status_code == 201
    data = backend_runtime.client.get("/api/analytics", headers=admin_headers).json()
    assert data["total_flows"] == 3 and data["attack_flows"] == 2
    assert sum(bucket["total"] for bucket in data["buckets"]) == 3
    assert sum(bucket["attacks"] for bucket in data["buckets"]) == 2
    assert data["top_sources"] == [{"ip": "10.10.0.9", "count": 2}]
    assert data["protocols"] == [{"protocol": 6, "count": 3}]
    assert data["time_basis"] == "observed_at"
