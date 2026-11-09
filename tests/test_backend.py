"""Security and persistence regressions using private app instances and databases."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import bcrypt
from fastapi.testclient import TestClient
import jwt
import pytest
from sqlalchemy import Column, MetaData, Table, create_engine, inspect, select

from backend.auth import create_access_token, hash_password, verify_password
from backend.config import Settings
from backend.database import Base, init_db, sessions_for
from backend.firewall import FirewallController
from backend.main import create_app
from backend.manage import bootstrap_admin, migrate
from backend.models import Alert, BlockedIP, ResponseCommand, User
from backend.schemas import AlertIngest
from backend.service import AlertService

PASSWORD = "ReviewPassword123!"


@pytest.mark.parametrize("path", ["/api/alerts", "/api/stats", "/api/firewall/blocked", "/api/firewall/whitelist", "/api/sensor/commands"])
def test_monitoring_and_sensor_routes_reject_anonymous(backend_runtime, path):
    assert backend_runtime.client.get(path).status_code == 401


def test_health_is_public_and_first_registration_is_not(backend_runtime, payload_factory):
    client = backend_runtime.client
    assert client.get("/api/health").status_code == 200
    assert client.post("/api/auth/register", json={"username": "attacker", "email": "first@example.com", "password": PASSWORD}).status_code == 401
    assert client.post("/api/alerts/ingest", json=payload_factory()).status_code == 401
    with backend_runtime.sessions() as db:
        assert db.query(User).count() == db.query(Alert).count() == 0


def test_only_admin_can_register_or_request_unblock(backend_runtime, operator_headers, admin_headers):
    client = backend_runtime.client
    assert client.get("/api/auth/me", headers=operator_headers).json()["is_admin"] is False
    assert client.get("/api/alerts", headers=operator_headers).status_code == 200
    assert client.post("/api/auth/register", headers=operator_headers,
        json={"username": "new_operator", "email": "new@example.com", "password": PASSWORD}).status_code == 403
    assert client.post("/api/firewall/unblock/10.10.0.9", headers=operator_headers).status_code == 403
    assert client.post("/api/firewall/unblock/not-an-ip", headers=admin_headers).status_code == 422


def test_bootstrap_is_explicit_and_single_use(backend_runtime):
    runtime = backend_runtime
    def attempt(index):
        try:
            return bootstrap_admin(runtime.engine, f"admin_{index}", f"admin{index}@example.com", PASSWORD)
        except ValueError:
            return None
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, range(2)))
    assert sum(result is not None for result in results) == 1
    with runtime.sessions() as db:
        assert db.query(User).filter_by(is_admin=True).count() == 1


def test_duplicate_account_returns_conflict(backend_runtime, admin_headers):
    body = {"username": "operator_one", "email": "one@example.com", "password": PASSWORD}
    assert backend_runtime.client.post("/api/auth/register", headers=admin_headers, json=body).status_code == 201
    assert backend_runtime.client.post("/api/auth/register", headers=admin_headers, json=body).status_code == 409


@pytest.mark.parametrize("password", ["", "short", "a" * 73, "😀" * 19])
def test_password_policy_returns_validation_error(backend_runtime, admin_headers, password):
    response = backend_runtime.client.post("/api/auth/register", headers=admin_headers,
        json={"username": "password_user", "email": "password@example.com", "password": password})
    assert response.status_code == 422


def test_bcrypt_bounds_and_legacy_login(backend_runtime):
    assert verify_password("a" * 73, hash_password(PASSWORD)) is False
    assert verify_password("", hash_password(PASSWORD)) is False
    assert verify_password("😀" * 18, hash_password("😀" * 18))
    with backend_runtime.sessions() as db:
        db.add(User(username="legacy_user", email="legacy@example.com",
                    hashed_password=bcrypt.hashpw(b"short", bcrypt.gensalt()).decode(), is_admin=False))
        db.commit()
    client = backend_runtime.client
    assert client.post("/api/auth/login", data={"username": "legacy_user", "password": "short"}).status_code == 200
    assert client.post("/api/auth/login", data={"username": "legacy_user", "password": "a" * 73}).status_code == 401


@pytest.mark.parametrize("kind", ["expired", "missing_claims", "wrong_purpose", "bad_signature"])
def test_invalid_jwt_is_rejected(backend_runtime, admin_headers, kind):
    config = backend_runtime.config
    if kind == "expired":
        token = create_access_token({"sub": "1"}, timedelta(seconds=-1), config)
    elif kind == "missing_claims":
        token = jwt.encode({"sub": "1"}, config.SECRET_KEY, algorithm="HS256")
    elif kind == "wrong_purpose":
        token = jwt.encode({"sub": "1", "exp": datetime.now(timezone.utc) + timedelta(minutes=1),
            "iat": datetime.now(timezone.utc), "type": "refresh", "iss": "securenet-ai", "aud": "securenet-dashboard"},
            config.SECRET_KEY, algorithm="HS256")
    else:
        token = create_access_token({"sub": "1"}, configuration=config) + "broken"
    assert backend_runtime.client.get("/api/auth/me", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_inactive_account_cannot_log_in_or_use_existing_token(backend_runtime, admin_headers):
    with backend_runtime.sessions() as db:
        db.query(User).update({User.is_active: False})
        db.commit()
    assert backend_runtime.client.get("/api/auth/me", headers=admin_headers).status_code == 401
    assert backend_runtime.client.post("/api/auth/login", data={"username": "review_admin", "password": PASSWORD}).status_code == 401


@pytest.mark.parametrize("field,value", [("SECRET_KEY", ""), ("SECRET_KEY", "securenet-default-insecure-secret-key-change-in-production"),
    ("SENSOR_API_TOKEN", ""), ("DATABASE_URL", ""), ("CORS_ORIGINS", ("*",))])
def test_bad_config_fails_before_database_initialization(tmp_path, field, value):
    config = Settings(DATABASE_URL="sqlite:///" + str(tmp_path / "must-not-exist.sqlite"),
                      SECRET_KEY="u" * 40, SENSOR_API_TOKEN="s" * 40)
    setattr(config, field, value)
    with pytest.raises(ValueError):
        with TestClient(create_app(config)):
            pass
    assert not (tmp_path / "must-not-exist.sqlite").exists()


def test_database_initialization_never_falls_back(backend_runtime, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("primary schema failure")
    monkeypatch.setattr(Base.metadata, "create_all", fail)
    with pytest.raises(RuntimeError, match="primary schema failure"):
        init_db(backend_runtime.engine)


def test_sensor_credentials_are_separate_from_user_access(backend_runtime, admin_headers, sensor_headers, payload_factory):
    client = backend_runtime.client
    assert client.post("/api/alerts/ingest", json=payload_factory(), headers=admin_headers).status_code == 401
    assert client.get("/api/alerts", headers=sensor_headers).status_code == 401
    wrong_sensor = {**sensor_headers, "X-Sensor-ID": "another-sensor"}
    assert client.get("/api/sensor/commands", headers=wrong_sensor).status_code == 401


@pytest.mark.parametrize("field,value", [("src_ip", "bad"), ("src_port", -1), ("dst_port", 65536),
    ("protocol", 1000), ("confidence", 4), ("label", "UNKNOWN"), ("model_sha256", "invalid"),
    ("model_run", "wrong_run"), ("source", "invented"), ("observed_at", "2026-01-01T00:00:00"),
    ("probabilities", {}), ("features", {}), ("unexpected", True)])
def test_ingest_rejects_invalid_values(backend_runtime, sensor_headers, payload_factory, field, value):
    body = payload_factory()
    body["event"][field] = value
    assert backend_runtime.client.post("/api/alerts/ingest", headers=sensor_headers, json=body).status_code == 422


def test_ingest_requires_event_and_consistent_metadata(backend_runtime, sensor_headers, payload_factory):
    client = backend_runtime.client
    assert client.post("/api/alerts/ingest", json={"event": {}}, headers=sensor_headers).status_code == 422
    body = payload_factory()
    body["event"]["features"]["Src Port"] = 10
    assert client.post("/api/alerts/ingest", json=body, headers=sensor_headers).status_code == 422
    body = payload_factory(with_block=True)
    body["firewall"]["mode"] = "active"
    assert client.post("/api/alerts/ingest", json=body, headers=sensor_headers).status_code == 422


def test_idempotent_ingest_and_model_provenance(backend_runtime, sensor_headers, admin_headers, payload_factory):
    client, body = backend_runtime.client, payload_factory(with_block=True)
    first = client.post("/api/alerts/ingest", json=body, headers=sensor_headers)
    second = client.post("/api/alerts/ingest", json=body, headers=sensor_headers)
    assert (first.status_code, second.status_code) == (201, 200)
    assert first.json()["alert_id"] == second.json()["alert_id"]
    body["event"]["src_ip"] = "10.10.0.8"
    body["firewall"] = None
    body["decision"]["action"] = "alert"
    assert client.post("/api/alerts/ingest", json=body, headers=sensor_headers).status_code == 409
    with backend_runtime.sessions() as db:
        assert db.query(Alert).count() == db.query(BlockedIP).count() == 1
        row = db.query(Alert).one()
        assert row.model_sha256 == "a" * 64 and row.model_run == "unified_v1"
        assert row.payload["event"]["model_sha256"] == row.model_sha256
    assert client.get("/api/alerts", headers=admin_headers).json()[0]["model_sha256"] == "a" * 64


def test_concurrent_identical_ingest_is_one_transaction(backend_runtime, payload_factory):
    body = AlertIngest.model_validate(payload_factory(with_block=True))
    def ingest(_):
        with backend_runtime.sessions() as db:
            return AlertService.record_detection(db, body, "sensor-local").created
    with ThreadPoolExecutor(max_workers=2) as executor:
        created = list(executor.map(ingest, range(2)))
    assert sorted(created) == [False, True]
    with backend_runtime.sessions() as db:
        assert db.query(Alert).count() == db.query(BlockedIP).count() == 1


def test_expiry_and_manual_unblock_need_sensor_ack(backend_runtime, sensor_headers, admin_headers, payload_factory):
    client, body = backend_runtime.client, payload_factory(with_block=True)
    assert client.post("/api/alerts/ingest", json=body, headers=sensor_headers).status_code == 201
    block = body["firewall"]["block"]
    requested = client.post("/api/firewall/unblock/" + body["event"]["src_ip"], headers=admin_headers)
    assert requested.status_code == 202 and requested.json()["status"] == "PENDING"
    assert client.get("/api/firewall/blocked?status=UNBLOCKED", headers=admin_headers).json() == []
    commands = client.get("/api/sensor/commands", headers=sensor_headers).json()
    assert len(commands) == 1 and commands[0]["block_id"] == block["block_id"]
    action = {"action_id": str(uuid4()), "block_id": block["block_id"], "mode": "dry_run",
        "ip": block["ip"], "status": "would_unblock", "reason": "manual",
        "command": FirewallController._command(block["ip"], "-D")}
    path = "/api/sensor/commands/" + commands[0]["command_id"] + "/ack"
    assert client.post(path, json={"action": action}, headers=sensor_headers).status_code == 200
    assert client.post(path, json={"action": action}, headers=sensor_headers).status_code == 200
    assert client.get("/api/sensor/commands", headers=sensor_headers).json() == []
    assert len(client.get("/api/firewall/blocked?status=UNBLOCKED", headers=admin_headers).json()) == 1
    assert client.get("/api/stats", headers=admin_headers).json()["active_blocked_ips"] == 0


def test_overdue_block_not_reported_active_until_expiry_ack(backend_runtime, sensor_headers, admin_headers, payload_factory):
    body = payload_factory(with_block=True)
    now = datetime.now(timezone.utc)
    body["firewall"]["block"]["blocked_at"] = (now - timedelta(minutes=20)).isoformat()
    body["firewall"]["block"]["unblock_at"] = (now - timedelta(minutes=5)).isoformat()
    client = backend_runtime.client
    assert client.post("/api/alerts/ingest", json=body, headers=sensor_headers).status_code == 201
    assert client.get("/api/firewall/blocked", headers=admin_headers).json() == []
    assert len(client.get("/api/firewall/blocked?status=EXPIRY_PENDING", headers=admin_headers).json()) == 1
    block = body["firewall"]["block"]
    action = {"action_id": str(uuid4()), "block_id": block["block_id"], "mode": "dry_run", "ip": block["ip"],
              "status": "would_unblock", "reason": "expired", "command": FirewallController._command(block["ip"], "-D")}
    for _ in range(2):
        assert client.post("/api/sensor/firewall-events", headers=sensor_headers, json=action).status_code == 200
    assert len(client.get("/api/firewall/blocked?status=EXPIRED", headers=admin_headers).json()) == 1


def test_offset_timestamps_are_normalized_before_sqlite_storage(backend_runtime, sensor_headers, admin_headers, payload_factory):
    body = payload_factory(with_block=True)
    local_zone = timezone(timedelta(hours=5))
    now = datetime.now(timezone.utc)
    body["firewall"]["block"]["blocked_at"] = (now - timedelta(minutes=20)).astimezone(local_zone).isoformat()
    body["firewall"]["block"]["unblock_at"] = (now - timedelta(minutes=5)).astimezone(local_zone).isoformat()
    assert backend_runtime.client.post("/api/alerts/ingest", json=body, headers=sensor_headers).status_code == 201
    rows = backend_runtime.client.get("/api/firewall/blocked?status=EXPIRY_PENDING", headers=admin_headers).json()
    assert len(rows) == 1
    assert datetime.fromisoformat(rows[0]["unblock_at"]) == now - timedelta(minutes=5)


def test_websocket_rejects_anonymous_and_delivers_authenticated_events(backend_runtime, admin_headers, sensor_headers, payload_factory):
    from starlette.websockets import WebSocketDisconnect
    client = backend_runtime.client
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/alerts"):
            pass
    with client.websocket_connect("/ws/alerts", headers=admin_headers) as socket:
        body = payload_factory()
        assert client.post("/api/alerts/ingest", json=body, headers=sensor_headers).status_code == 201
        assert socket.receive_json()["event_id"] == body["event"]["event_id"]


def test_browser_websocket_ticket_is_authenticated_and_single_use(backend_runtime, admin_headers):
    from starlette.websockets import WebSocketDisconnect
    client = backend_runtime.client
    assert client.post("/api/auth/ws-ticket").status_code == 401
    issued = client.post("/api/auth/ws-ticket", headers=admin_headers)
    assert issued.status_code == 200 and issued.json()["expires_in"] == 30
    path = "/ws/alerts?ticket=" + issued.json()["ticket"]
    with client.websocket_connect(path):
        pass
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(path):
            pass


def test_configuration_generation_never_overwrites_secrets(tmp_path):
    from backend.manage import write_config
    path = tmp_path / "backend.env"
    write_config(path, "sqlite:///test.sqlite")
    original = path.read_bytes()
    assert path.stat().st_mode & 0o777 == 0o600
    assert b"SECRET_KEY=" in original and b"SENSOR_API_TOKEN=" in original
    with pytest.raises(FileExistsError):
        write_config(path, "sqlite:///other.sqlite")
    assert path.read_bytes() == original


def test_sensor_export_excludes_user_jwt_and_database_credentials(backend_runtime, tmp_path, monkeypatch, capsys):
    import backend.manage as manage
    path = tmp_path / "sensor.env"
    monkeypatch.setattr(manage, "settings", backend_runtime.config)
    monkeypatch.setattr("sys.argv", ["manage", "export-sensor-config", "--output", str(path)])
    manage.main()
    content = path.read_text()
    assert "SENSOR_API_TOKEN=" in content and "SENSOR_ID=" in content
    assert backend_runtime.config.SECRET_KEY not in content and "DATABASE_URL" not in content
    assert path.stat().st_mode & 0o777 == 0o600
    assert backend_runtime.config.SENSOR_API_TOKEN not in capsys.readouterr().out


def test_migration_preserves_legacy_rows_and_is_repeatable(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "legacy.sqlite"))
    extra = {"model_run", "model_sha256", "sensor_id", "payload_sha256", "payload"}
    legacy = Table("alerts", MetaData(), *(Column(c.name, c.type, primary_key=c.primary_key,
                   nullable=c.nullable) for c in Alert.__table__.columns if c.name not in extra))
    legacy.create(engine)
    with engine.begin() as connection:
        connection.execute(legacy.insert().values(event_id="historical-id", observed_at=datetime.now(timezone.utc),
            source="pcap", src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1, dst_port=2,
            protocol=6, label="BENIGN", confidence=0.9, model_scope="friday", decision_action="ignore",
            created_at=datetime.now(timezone.utc)))
    with pytest.raises(RuntimeError, match="Legacy database schema"):
        init_db(engine)
    migrate(engine)
    migrate(engine)
    with engine.connect() as connection:
        assert connection.execute(select(Alert.event_id)).scalars().all() == ["historical-id"]
    assert "model_sha256" in {column["name"] for column in inspect(engine).get_columns("alerts")}
    engine.dispose()
