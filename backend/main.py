"""Authenticated REST, sensor ingestion and isolated WebSocket delivery."""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from ipaddress import IPv4Address
from typing import Literal
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from backend.auth import (create_access_token, decode_token, get_current_user, get_settings,
                          hash_password, oauth2_scheme, require_admin, require_sensor, resolve_user, verify_password)
from backend.config import settings
from backend.database import create_database_engine, get_db, init_db, sessions_for
from backend.firewall import PROTECTED_CIDRS
from backend.models import User
from backend.realtime import ConnectionManager, WebSocketTickets
from backend.schemas import AlertIngest, CommandAck, FirewallActionIn, UserOut, UserRegister
from backend.service import AlertService, ConflictError, MissingRecordError


def create_app(configuration=None, engine=None):
    config = configuration or settings

    @asynccontextmanager
    async def lifespan(application):
        config.validate()
        selected = engine if engine is not None else create_database_engine(config.DATABASE_URL)
        try:
            await run_in_threadpool(init_db, selected)
            application.state.session_factory = sessions_for(selected)
            yield
        finally:
            await application.state.ws_manager.close()
            if engine is None:
                selected.dispose()

    application = FastAPI(title="SecureNet AI Backend API", version="1.1.0", lifespan=lifespan)
    application.state.settings = config
    application.state.ws_manager = ConnectionManager()
    application.state.ws_tickets = WebSocketTickets()
    application.add_middleware(CORSMiddleware, allow_origins=list(config.CORS_ORIGINS),
        allow_credentials=False, allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "X-Sensor-Token", "X-Sensor-ID"])

    @application.exception_handler(ConflictError)
    async def conflict_handler(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @application.exception_handler(MissingRecordError)
    async def missing_handler(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=404)

    @application.get("/api/health")
    def health():
        return {"status": "ok", "service": "SecureNet AI Backend", "response_mode": "dry_run"}

    @application.post("/api/auth/register", response_model=UserOut, status_code=201)
    def register(user_in: UserRegister, db: Session = Depends(get_db), admin=Depends(require_admin)):
        user = User(username=user_in.username, email=str(user_in.email),
                    hashed_password=hash_password(user_in.password), is_admin=user_in.is_admin)
        db.add(user)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(409, "Username or email already registered") from exc
        return user

    @application.post("/api/auth/login")
    def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db),
              config=Depends(get_settings)):
        user = db.query(User).filter_by(username=form.username).first()
        if user is None or not user.is_active or not verify_password(form.password, user.hashed_password):
            raise HTTPException(401, "Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
        return {"access_token": create_access_token({"sub": str(user.id)}, configuration=config),
                "token_type": "bearer", "expires_in": config.ACCESS_TOKEN_EXPIRE_MINUTES * 60}

    @application.get("/api/auth/me", response_model=UserOut)
    def me(user=Depends(get_current_user)):
        return user

    @application.post("/api/auth/ws-ticket")
    async def ws_ticket(user=Depends(get_current_user), token=Depends(oauth2_scheme)):
        expires = decode_token(token, config)["exp"]
        try:
            ticket = application.state.ws_tickets.issue(user.id, expires)
        except ValueError as exc:
            raise HTTPException(429, "Too many outstanding WebSocket tickets") from exc
        return {"ticket": ticket, "expires_in": 30}

    @application.get("/api/alerts")
    def alerts(skip: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500), label: str | None = None,
               min_confidence: float | None = Query(None, ge=0, le=1),
               db: Session = Depends(get_db), user=Depends(get_current_user)):
        rows = AlertService.list_alerts(db, skip, limit, label, min_confidence)
        return [{name: getattr(row, name) for name in ("id", "event_id", "observed_at", "source",
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "label", "confidence",
            "model_scope", "model_run", "model_sha256", "sensor_id", "decision_action", "decision_reason")}
            for row in rows]

    @application.get("/api/stats")
    def stats(db: Session = Depends(get_db), user=Depends(get_current_user)):
        return AlertService.get_summary_stats(db)

    @application.post("/api/alerts/ingest", status_code=201)
    async def ingest(payload: AlertIngest, response: Response,
                     db: Session = Depends(get_db), sensor_id=Depends(require_sensor)):
        result = await run_in_threadpool(AlertService.record_detection, db, payload, sensor_id)
        alert = result.alert
        if not result.created:
            response.status_code = 200
        else:
            application.state.ws_manager.broadcast({"event_id": alert.event_id, "label": alert.label,
                "src_ip": alert.src_ip, "dst_ip": alert.dst_ip, "confidence": alert.confidence,
                "action": alert.decision_action, "mode": "dry_run"})
        return {"status": "ingested" if result.created else "already_ingested",
                "event_id": alert.event_id, "alert_id": alert.id}

    @application.get("/api/firewall/blocked")
    def blocked(status: Literal["ACTIVE", "EXPIRY_PENDING", "UNBLOCK_REQUESTED", "EXPIRED", "UNBLOCKED"] = "ACTIVE",
                skip: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500),
                db: Session = Depends(get_db), user=Depends(get_current_user)):
        rows = AlertService.list_blocked_ips(db, status, skip, limit)
        return [{name: getattr(row, name) for name in ("id", "block_id", "sensor_id", "ip", "threat",
            "mode", "status", "blocked_at", "unblock_at", "unblocked_at", "command")} for row in rows]

    @application.post("/api/firewall/unblock/{ip}", status_code=202)
    def unblock(ip: IPv4Address, db: Session = Depends(get_db), admin=Depends(require_admin)):
        command = AlertService.request_unblock(db, ip, requested_by=admin.id)
        return {"status": command.status, "command_id": command.command_id, "ip": command.ip,
                "mode": "dry_run"}

    @application.get("/api/firewall/whitelist")
    def whitelist(user=Depends(get_current_user)):
        return {"protected_cidrs": list(PROTECTED_CIDRS), "scope": "built_in_defaults"}

    @application.post("/api/sensor/firewall-events")
    def firewall_event(action: FirewallActionIn, db: Session = Depends(get_db), sensor_id=Depends(require_sensor)):
        record = AlertService.record_firewall_event(db, action, sensor_id)
        return {"status": "recorded", "action_id": record.action_id}

    @application.get("/api/sensor/commands")
    def commands(db: Session = Depends(get_db), sensor_id=Depends(require_sensor)):
        return [{"command_id": row.command_id, "block_id": row.block_id, "ip": row.ip,
                 "operation": "unblock", "mode": "dry_run"}
                for row in AlertService.pending_commands(db, sensor_id)]

    @application.post("/api/sensor/commands/{command_id}/ack")
    def acknowledge(command_id: UUID, body: CommandAck, db: Session = Depends(get_db), sensor_id=Depends(require_sensor)):
        command = AlertService.acknowledge_command(db, command_id, body.action, sensor_id)
        return {"status": command.status, "command_id": command.command_id}

    @application.websocket("/ws/alerts")
    async def websocket_alerts(websocket: WebSocket):
        authorization = websocket.headers.get("authorization", "")
        token = authorization[7:] if authorization.lower().startswith("bearer ") else None

        def authenticate():
            with application.state.session_factory() as db:
                if token:
                    resolve_user(token, db, config)
                    return decode_token(token, config)["exp"]
                try:
                    user_id, expires = application.state.ws_tickets.consume(websocket.query_params.get("ticket"))
                except ValueError as exc:
                    raise HTTPException(401, "WebSocket authentication required") from exc
                user = db.get(User, user_id)
                if user is None or not user.is_active or expires <= datetime.now(timezone.utc).timestamp():
                    raise HTTPException(401, "Expired or inactive WebSocket session")
                return expires

        try:
            expires = await run_in_threadpool(authenticate)
        except HTTPException:
            await websocket.close(code=1008)
            return
        manager = application.state.ws_manager
        subscription = await manager.connect(websocket)
        if subscription is None:
            return
        try:
            remaining = max(0, expires - datetime.now(timezone.utc).timestamp())
            async with asyncio.timeout(remaining):
                while True:
                    await websocket.receive_text()
        except (WebSocketDisconnect, TimeoutError):
            pass
        finally:
            await manager.disconnect(subscription, code=1008)

    return application


app = create_app()
