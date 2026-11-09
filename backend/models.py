"""SQLAlchemy database models for SecureNet AI."""

from datetime import datetime, timezone
from sqlalchemy import (
    Boolean, Column, DateTime, Float, Integer, JSON, String
)

from backend.database import Base
from sqlalchemy.types import TypeDecorator


class UTCDateTime(TypeDecorator):
    """Preserve UTC awareness when SQLite returns timestamps without tzinfo."""
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.utcoffset() is None:
            raise ValueError("Database timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return (value.replace(tzinfo=timezone.utc) if value.utcoffset() is None else value.astimezone(timezone.utc))


class User(Base):
    """Administrative and operator dashboard accounts."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(UTCDateTime(), default=lambda: datetime.now(timezone.utc), nullable=False)


class Alert(Base):
    """Detection events and threat incidents produced by the ML engine."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    observed_at = Column(UTCDateTime(), nullable=False, index=True)
    source = Column(String(32), default="live", nullable=False)
    src_ip = Column(String(64), index=True, nullable=False)
    dst_ip = Column(String(64), nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(Integer, nullable=False)
    label = Column(String(32), index=True, nullable=False)
    confidence = Column(Float, nullable=False)
    probabilities = Column(JSON, nullable=True)
    features = Column(JSON, nullable=True)
    model_scope = Column(String(32), default="unified", nullable=False)
    model_run = Column(String(64), nullable=True)
    model_sha256 = Column(String(64), nullable=True)
    sensor_id = Column(String(64), nullable=True, index=True)
    payload_sha256 = Column(String(64), nullable=True)
    payload = Column(JSON, nullable=True)
    decision_action = Column(String(32), default="alert", nullable=False)
    decision_reason = Column(String(128), nullable=True)
    created_at = Column(UTCDateTime(), default=lambda: datetime.now(timezone.utc), nullable=False)


class BlockedIP(Base):
    """Firewall block state, history, and scheduled unblock expiry."""
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(64), index=True, nullable=False)
    block_id = Column(String(36), nullable=True, unique=True, index=True)
    sensor_id = Column(String(64), nullable=True, index=True)
    threat = Column(String(32), nullable=False)
    mode = Column(String(32), default="dry_run", nullable=False)
    command = Column(JSON, nullable=True)
    status = Column(String(32), default="ACTIVE", index=True, nullable=False)  # ACTIVE, EXPIRED, UNBLOCKED
    blocked_at = Column(UTCDateTime(), nullable=False, index=True)
    unblock_at = Column(UTCDateTime(), nullable=False)
    unblocked_at = Column(UTCDateTime(), nullable=True)
    created_at = Column(UTCDateTime(), default=lambda: datetime.now(timezone.utc), nullable=False)


class BootstrapState(Base):
    __tablename__ = "bootstrap_state"
    id = Column(Integer, primary_key=True)


class FirewallEvent(Base):
    __tablename__ = "firewall_events"
    action_id = Column(String(36), primary_key=True)
    sensor_id = Column(String(64), nullable=False, index=True)
    block_id = Column(String(36), nullable=False, index=True)
    payload_sha256 = Column(String(64), nullable=False)
    payload = Column(JSON, nullable=False)
    created_at = Column(UTCDateTime(), default=lambda: datetime.now(timezone.utc), nullable=False)


class ResponseCommand(Base):
    __tablename__ = "response_commands"
    command_id = Column(String(36), primary_key=True)
    block_id = Column(String(36), nullable=False, unique=True)
    sensor_id = Column(String(64), nullable=False, index=True)
    ip = Column(String(64), nullable=False)
    requested_by = Column(Integer, nullable=False)
    status = Column(String(24), default="PENDING", nullable=False, index=True)
    result = Column(JSON, nullable=True)
    created_at = Column(UTCDateTime(), default=lambda: datetime.now(timezone.utc), nullable=False)
    acknowledged_at = Column(UTCDateTime(), nullable=True)
