"""Async SQLAlchemy engine and session management.

Supports SQLite (single-node/dev) and PostgreSQL (+TimescaleDB) for production.
The database URL is configured via ``SENTRY_DATABASE_URL``.
"""
from __future__ import annotations

import logging
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from ..config import settings

logger = logging.getLogger("sentry.db")

_engine_kwargs: dict = {"echo": False, "pool_pre_ping": True}
if settings.database_url.startswith("sqlite"):
    _engine_kwargs["connect_args"] = {"timeout": 30}

engine = create_async_engine(settings.database_url, **_engine_kwargs)
session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
async_session = session_factory


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncIterator[AsyncSession]:
    async with session_factory() as session:
        try:
            yield session
        finally:
            await session.close()


async def close_db() -> None:
    """Release pooled connections so a new event loop can start cleanly."""
    await engine.dispose()


async def init_db() -> None:
    """Create tables if absent, and enable Timescale hypertables when configured."""
    from . import models  # noqa: F401 — ensure models are registered

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    if settings.timescale_enabled and settings.database_url.startswith("postgresql"):
        await _enable_timescale()
    logger.info("Database ready (%s)", _dialect())


async def _enable_timescale() -> None:
    from sqlalchemy import text

    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS timescaledb"))
            for table in ("flow_logs", "detections", "audit_log"):
                await conn.execute(
                    text(f"SELECT create_hypertable('{table}', 'timestamp', if_not_exists => TRUE)")
                )
                await conn.execute(
                    text(
                        f"SELECT add_retention_policy('{table}', "
                        f"INTERVAL '{int(settings.retention_days)} days', if_not_exists => TRUE)"
                    )
                )
        logger.info("TimescaleDB hypertables enabled")
    except Exception as exc:  # pragma: no cover
        if settings.is_production:
            logger.exception("TimescaleDB setup failed in production")
            raise
        logger.warning("TimescaleDB setup skipped: %s", exc)


def _dialect() -> str:
    return "sqlite" if settings.database_url.startswith("sqlite") else "postgresql"
