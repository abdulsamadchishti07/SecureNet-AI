"""SQLAlchemy database models for SecureNet AI."""

from datetime import datetime, timezone
from sqlalchemy import (
    Boolean, Column, DateTime, Float, Integer, JSON, String, Text, func
)

from backend.database import Base


class User(Base):
    """Administrative and operator dashboard accounts."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class Alert(Base):
    """Detection events and threat incidents produced by the ML engine."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    observed_at = Column(DateTime(timezone=True), nullable=False)
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
    decision_action = Column(String(32), default="alert", nullable=False)
    decision_reason = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class BlockedIP(Base):
    """Firewall block state, history, and scheduled unblock expiry."""
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(64), index=True, nullable=False)
    threat = Column(String(32), nullable=False)
    mode = Column(String(32), default="dry_run", nullable=False)
    command = Column(JSON, nullable=True)
    status = Column(String(32), default="ACTIVE", index=True, nullable=False)  # ACTIVE, EXPIRED, UNBLOCKED
    blocked_at = Column(DateTime(timezone=True), nullable=False)
    unblock_at = Column(DateTime(timezone=True), nullable=False)
    unblocked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
