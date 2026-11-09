"""Tests for backend database, authentication, alerts service, and FastAPI REST API."""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base, get_db
from backend.models import User, Alert, BlockedIP
from backend.auth import hash_password, verify_password, create_access_token, decode_token
from backend.service import AlertService
from backend.main import app

# In-memory SQLite database with StaticPool for isolated backend unit tests
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# --- Authentication & Password Hash Tests ---
def test_password_hashing_and_verification():
    secret = "SuperSecret123!"
    hashed = hash_password(secret)
    assert hashed != secret
    assert verify_password(secret, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_jwt_token_generation_and_decoding():
    token = create_access_token({"sub": "admin_user", "admin": True})
    payload = decode_token(token)
    assert payload["sub"] == "admin_user"
    assert payload["admin"] is True
    assert payload["type"] == "access"


# --- Service Layer Tests ---
def test_alert_service_records_detection_and_firewall_blocks(db_session):
    event = {
        "event_id": "test-uuid-001",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "source": "pcap",
        "src_ip": "192.168.1.100",
        "dst_ip": "192.168.1.200",
        "src_port": 45678,
        "dst_port": 80,
        "protocol": 6,
        "label": "PORTSCAN",
        "confidence": 0.998,
        "probabilities": {"BENIGN": 0.002, "PORTSCAN": 0.998},
        "features": {"Src Port": 45678.0, "Dst Port": 80.0},
        "model_scope": "unified",
    }
    decision = {"action": "candidate", "reason": "repeated_high_score_flows"}
    firewall = {
        "status": "would_block",
        "ip": "192.168.1.100",
        "threat": "PORTSCAN",
        "mode": "dry_run",
        "command": ["iptables", "-A", "INPUT", "-s", "192.168.1.100", "-j", "DROP"],
        "block": {
            "blocked_at": datetime.now(timezone.utc).isoformat(),
            "unblock_at": datetime.now(timezone.utc).isoformat(),
        },
    }

    alert = AlertService.record_detection(db_session, event, decision, firewall)
    assert alert.id is not None
    assert alert.label == "PORTSCAN"
    assert alert.decision_action == "candidate"

    # Verify BlockedIP record was also created
    blocked_list = AlertService.list_blocked_ips(db_session)
    assert len(blocked_list) == 1
    assert blocked_list[0].ip == "192.168.1.100"
    assert blocked_list[0].status == "ACTIVE"

    # Test summary stats
    stats = AlertService.get_summary_stats(db_session)
    assert stats["total_events"] == 1
    assert stats["total_attacks"] == 1
    assert stats["active_blocked_ips"] == 1
    assert stats["threat_distribution"]["PORTSCAN"] == 1

    # Test unblock
    unblocked = AlertService.unblock_ip(db_session, "192.168.1.100")
    assert unblocked is not None
    assert unblocked.status == "UNBLOCKED"
    assert unblocked.unblocked_at is not None
    assert len(AlertService.list_blocked_ips(db_session, status="ACTIVE")) == 0


# --- FastAPI Endpoint Integration Tests ---
def test_api_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_api_user_registration_and_login_flow(client):
    # Register admin user
    reg_response = client.post(
        "/api/auth/register",
        json={"username": "admin", "email": "admin@example.com", "password": "password123"},
    )
    assert reg_response.status_code == 201
    user_data = reg_response.json()
    assert user_data["username"] == "admin"
    assert user_data["is_admin"] is True

    # Duplicate registration fails
    dup_response = client.post(
        "/api/auth/register",
        json={"username": "admin", "email": "other@example.com", "password": "password123"},
    )
    assert dup_response.status_code == 400

    # Login
    login_response = client.post(
        "/api/auth/login",
        data={"username": "admin", "password": "password123"},
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    # Access current user info with token
    me_response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_response.status_code == 200
    assert me_response.json()["username"] == "admin"

    # Request without token fails
    unauth_response = client.get("/api/auth/me")
    assert unauth_response.status_code == 401


def test_api_alert_ingestion_and_query_flow(client):
    # Ingest detection event via API
    event_payload = {
        "event": {
            "event_id": "api-test-001",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "source": "pcap",
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.1",
            "src_port": 12345,
            "dst_port": 22,
            "protocol": 6,
            "label": "BRUTE_FORCE",
            "confidence": 0.995,
            "model_scope": "unified",
        },
        "decision": {"action": "alert", "reason": "single_flow"},
    }
    ingest_res = client.post("/api/alerts/ingest", json=event_payload)
    assert ingest_res.status_code == 201
    assert ingest_res.json()["status"] == "ingested"

    # Query alerts
    alerts_res = client.get("/api/alerts")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) == 1
    assert alerts[0]["label"] == "BRUTE_FORCE"
    assert alerts[0]["src_ip"] == "10.0.0.5"

    # Query stats
    stats_res = client.get("/api/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_attacks"] == 1
    assert stats["threat_distribution"]["BRUTE_FORCE"] == 1


def test_firewall_management_api_routes(client, db_session):
    # 1. Whitelist endpoint
    wl_res = client.get("/api/firewall/whitelist")
    assert wl_res.status_code == 200
    assert "127.0.0.0/8" in wl_res.json()["protected_cidrs"]

    # 2. Block an IP directly via service
    blocked = BlockedIP(
        ip="192.168.1.100",
        threat="PORTSCAN",
        mode="dry_run",
        status="ACTIVE",
        blocked_at=datetime.now(timezone.utc),
        unblock_at=datetime.now(timezone.utc),
        command="iptables -w 2 -A INPUT -s 192.168.1.100 -j DROP",
    )
    db_session.add(blocked)
    db_session.commit()

    # 3. Query blocked list
    blocked_res = client.get("/api/firewall/blocked")
    assert blocked_res.status_code == 200
    blocks = blocked_res.json()
    assert len(blocks) == 1
    assert blocks[0]["ip"] == "192.168.1.100"

    # 4. Unblock requires authentication
    unblock_fail = client.post("/api/firewall/unblock/192.168.1.100")
    assert unblock_fail.status_code == 401

    # Register admin user to obtain token
    reg_res = client.post(
        "/api/auth/register",
        json={"username": "secadmin", "email": "secadmin@example.com", "password": "AdminPassword123!"},
    )
    assert reg_res.status_code == 201
    login_res = client.post(
        "/api/auth/login",
        data={"username": "secadmin", "password": "AdminPassword123!"},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Authenticated unblock
    unblock_success = client.post("/api/firewall/unblock/192.168.1.100", headers=headers)
    assert unblock_success.status_code == 200
    assert unblock_success.json()["status"] == "unblocked"

    # Verify no longer active
    active_res = client.get("/api/firewall/blocked?status=ACTIVE")
    assert len(active_res.json()) == 0


def test_response_dispatcher_api_forwarding(tmp_path, response_event_factory):
    from unittest.mock import patch
    from backend.worker import ResponseDispatcher

    event = response_event_factory()
    log_file = tmp_path / "alerts.jsonl"

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = mock_urlopen.return_value.__enter__.return_value
        mock_resp.status = 201

        dispatcher = ResponseDispatcher(
            log_file,
            api_url="http://127.0.0.1:8000",
        )
        with dispatcher:
            assert dispatcher.publish(event) is True

        assert dispatcher.stats()["processed"] == 1
        assert dispatcher.stats()["api_forwarded"] == 1
        assert dispatcher.stats()["api_failed"] == 0
        assert mock_urlopen.called

