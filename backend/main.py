"""FastAPI REST and WebSocket service for SecureNet AI."""

import json
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import (
    Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, status
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from backend.auth import (
    create_access_token, get_current_user, hash_password, verify_password
)
from backend.database import get_db, init_db
from backend.models import User
from backend.service import AlertService
from backend.firewall import PROTECTED_CIDRS


# --- WebSocket Connection Manager ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


ws_manager = ConnectionManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB tables on startup
    init_db()
    yield


app = FastAPI(
    title="SecureNet AI Backend API",
    description="Network Threat Detection and Automated Response Management Service",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for dashboard UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Pydantic Request/Response Schemas ---
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    is_admin: bool


class AlertIngest(BaseModel):
    event: Dict[str, Any]
    decision: Optional[Dict[str, Any]] = None
    firewall: Optional[Dict[str, Any]] = None


# --- Health & Status Routes ---
@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "SecureNet AI Backend", "version": "1.0.0"}


# --- Authentication Routes ---
@app.post("/api/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(user_in: UserRegister, db: Session = Depends(get_db)):
    existing = db.query(User).filter(
        (User.username == user_in.username) | (User.email == user_in.email)
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered",
        )
    # First registered user is automatically an admin
    user_count = db.query(User).count()
    user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        is_admin=(user_count == 0),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/api/auth/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username, "admin": user.is_admin})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/auth/me", response_model=UserOut)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user


# --- Alert Monitoring & Ingestion Routes ---
@app.get("/api/alerts")
def get_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    label: Optional[str] = None,
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0),
    db: Session = Depends(get_db),
):
    """Retrieve paginated threat alerts with optional filtering."""
    alerts = AlertService.list_alerts(db, skip=skip, limit=limit, label=label, min_confidence=min_confidence)
    return [
        {
            "id": a.id,
            "event_id": a.event_id,
            "observed_at": a.observed_at.isoformat(),
            "source": a.source,
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "src_port": a.src_port,
            "dst_port": a.dst_port,
            "protocol": a.protocol,
            "label": a.label,
            "confidence": a.confidence,
            "model_scope": a.model_scope,
            "decision_action": a.decision_action,
            "decision_reason": a.decision_reason,
        }
        for a in alerts
    ]


@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    """Summary statistics for dashboard cards and charts."""
    return AlertService.get_summary_stats(db)


@app.post("/api/alerts/ingest", status_code=status.HTTP_201_CREATED)
async def ingest_alert(payload: AlertIngest, db: Session = Depends(get_db)):
    """Ingest a detection event from the sniffer or external probe and broadcast via WebSockets."""
    alert = AlertService.record_detection(
        db=db,
        event=payload.event,
        decision=payload.decision,
        firewall=payload.firewall,
    )
    broadcast_payload = {
        "event_id": alert.event_id,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "src_port": alert.src_port,
        "dst_port": alert.dst_port,
        "label": alert.label,
        "confidence": alert.confidence,
        "action": alert.decision_action,
        "firewall": payload.firewall,
        "observed_at": alert.observed_at.isoformat(),
    }
    await ws_manager.broadcast(broadcast_payload)
    return {"status": "ingested", "event_id": alert.event_id, "alert_id": alert.id}


# --- Firewall Management Routes ---
@app.get("/api/firewall/blocked")
def get_blocked_ips(status: str = "ACTIVE", db: Session = Depends(get_db)):
    """List currently blocked IP addresses."""
    records = AlertService.list_blocked_ips(db, status=status)
    return [
        {
            "id": r.id,
            "ip": r.ip,
            "threat": r.threat,
            "mode": r.mode,
            "status": r.status,
            "blocked_at": r.blocked_at.isoformat(),
            "unblock_at": r.unblock_at.isoformat(),
            "unblocked_at": r.unblocked_at.isoformat() if r.unblocked_at else None,
            "command": r.command,
        }
        for r in records
    ]


@app.post("/api/firewall/unblock/{ip}")
def unblock_ip(ip: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Administrative action: manually remove an IP from blocked status."""
    record = AlertService.unblock_ip(db, ip)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No active block found for {ip}")
    return {"status": "unblocked", "ip": ip, "unblocked_at": record.unblocked_at.isoformat()}


@app.get("/api/firewall/whitelist")
def get_whitelist():
    """List protected CIDRs and immunity subnets."""
    return {"protected_cidrs": sorted(PROTECTED_CIDRS)}


# --- WebSocket Stream for Live Dashboard ---
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep-alive receive ping
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
