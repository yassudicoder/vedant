"""
PhishGuard database engine, session factory, declarative base, and helpers.

SQLAlchemy 2.x with SQLite (WAL mode) or PostgreSQL via DATABASE_URL.
"""
from __future__ import annotations

from collections.abc import Generator
from typing import Any

from sqlalchemy import event, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.config import settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


_connect_args: dict[str, Any] = {}
if settings.DATABASE_URL.startswith("sqlite"):
    _connect_args["check_same_thread"] = False

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=_connect_args,
    pool_pre_ping=True,
)

# Enable WAL journal mode for SQLite (better concurrent-read performance).
if settings.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection: Any, _connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a SQLAlchemy session and ensures cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables that do not yet exist."""
    # Import models so they are registered on Base.metadata before create_all.
    import backend.models  # noqa: F401

    Base.metadata.create_all(bind=engine)

    # Quick connectivity check.
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
