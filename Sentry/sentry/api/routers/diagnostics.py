"""Sanitized operational diagnostics and audit-log access."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import settings
from ...db import get_db
from ...db.models import AuditLog, MitigationAction, Sensor
from ..deps import require_admin
from ..state import app_state

router = APIRouter(prefix="/api", tags=["operations"])


@router.get("/diagnostics")
async def diagnostics(db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    await db.execute(text("SELECT 1"))
    active_since = datetime.now(timezone.utc) - timedelta(minutes=5)
    active_sensors = (await db.execute(select(func.count()).select_from(Sensor).where(
        Sensor.last_heartbeat >= active_since))).scalar() or 0
    pending_actions = (await db.execute(select(func.count()).select_from(MitigationAction).where(
        MitigationAction.status.in_(["pending_approval", "queued", "failed", "release_failed"])))).scalar() or 0
    llm_healthy = False
    if app_state.llm:
        try:
            llm_healthy = await app_state.llm.health_check()
        except Exception:
            pass
    return {
        "status": "healthy" if app_state.engine else "degraded",
        "version": settings.app_version,
        "environment": settings.environment,
        "database": {"status": "connected", "timescale": settings.timescale_enabled},
        "ingestion": {
            "queue_depth": app_state.pipeline.queue.qsize() if app_state.pipeline else None,
            "queue_capacity": app_state.pipeline.queue.maxsize if app_state.pipeline else None,
            "nats_configured": bool(settings.nats_url),
            "nats_connected": app_state.nats_connected,
            "nats_error": app_state.nats_error,
        },
        "detection": {
            "mode": app_state.engine.mode if app_state.engine else "unavailable",
            "moe_version": app_state.engine.moe.version if app_state.engine else "none",
        },
        "integrations": {
            "llm_configured": app_state.llm is not None,
            "llm_healthy": llm_healthy,
            "webhook_configured": bool(settings.webhook_url),
            "webhook_queue_depth": app_state.webhooks.queue.qsize() if app_state.webhooks else None,
            "ai_triage": app_state.pipeline.triage.stats if app_state.pipeline and app_state.pipeline.triage else None,
        },
        "response": {"mode": settings.response_mode, "pending_actions": pending_actions},
        "active_sensors": active_sensors,
    }


@router.get("/audit")
async def audit_log(
    action: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    q = select(AuditLog)
    if action:
        q = q.where(AuditLog.action == action)
    rows = (await db.execute(q.order_by(AuditLog.timestamp.desc()).limit(limit))).scalars().all()
    return [{
        "id": row.id, "timestamp": row.timestamp, "user_id": row.user_id,
        "action": row.action, "resource": row.resource, "detail": row.detail,
    } for row in rows]
