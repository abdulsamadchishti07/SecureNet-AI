"""Database engine, session management, and base schema."""

import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from backend.config import settings

logger = logging.getLogger("securenet.database")

DATABASE_URL = settings.DATABASE_URL


def _create_configured_engine(url: str):
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args, pool_pre_ping=True)


engine = _create_configured_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency for yielding database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db(target_engine=None):
    """Create all registered database tables with graceful fallback if primary DB is offline."""
    global engine, SessionLocal
    eng = target_engine or engine
    try:
        Base.metadata.create_all(bind=eng)
    except Exception as exc:
        if eng == engine and not DATABASE_URL.startswith("sqlite"):
            safe_host = DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else DATABASE_URL
            logger.warning(
                "Primary database (%s) unavailable: %s. Falling back to local SQLite.",
                safe_host,
                exc,
            )
            fallback_url = "sqlite:///./securenet.db"
            engine = _create_configured_engine(fallback_url)
            SessionLocal.configure(bind=engine)
            Base.metadata.create_all(bind=engine)
        else:
            raise
