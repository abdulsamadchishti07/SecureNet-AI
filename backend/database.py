"""Database engine, session management, and base schema."""

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import declarative_base, sessionmaker
from starlette.requests import HTTPConnection


def create_database_engine(url: str):
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args, pool_pre_ping=True)


Base = declarative_base()


def get_db(connection: HTTPConnection):
    """FastAPI dependency for yielding database sessions."""
    db = connection.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


def init_db(engine):
    """Initialize only the selected database; failures never select another store."""
    inspector = inspect(engine)
    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        present = {column["name"] for column in inspector.get_columns(table.name)}
        if set(table.columns.keys()) - present:
            raise RuntimeError("Legacy database schema: back up and run python -m backend.manage migrate")
    if inspector.has_table("blocked_ips"):
        unique = inspector.get_unique_constraints("blocked_ips") + [
            index for index in inspector.get_indexes("blocked_ips") if index.get("unique")]
        if not any(item["column_names"] == ["block_id"] for item in unique):
            raise RuntimeError("Legacy database schema: back up and run python -m backend.manage migrate")
    Base.metadata.create_all(bind=engine)


def sessions_for(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine, expire_on_commit=False)
