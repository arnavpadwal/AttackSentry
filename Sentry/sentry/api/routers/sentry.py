"""Sentry engine status / train / retrain routes."""
from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_db
from ...db.models import FlowLog, Host, Incident
from ..audit import add_audit
from ..deps import get_current_user, require_admin
from ..schemas import SentryStatusOut
from ..state import app_state

router = APIRouter(prefix="/api/sentry", tags=["sentry"])


@router.get("/status", response_model=SentryStatusOut)
async def status(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    engine = app_state.engine
    active_hosts = (await db.execute(select(func.count()).select_from(Host))).scalar() or 0
    active_incidents = (await db.execute(
        select(func.count()).select_from(Incident).where(Incident.status == "open")
    )).scalar() or 0
    llm_healthy = False
    if app_state.llm:
        try:
            llm_healthy = await app_state.llm.health_check()
        except Exception:
            llm_healthy = False

    mode = engine.mode if engine else "booting"
    progress = engine._monitoring_progress() if engine else 0.0
    # This is deliberately database-backed: process memory resets on a deploy
    # and produced a misleading lifetime count after every restart.
    flows = (await db.execute(select(func.count()).select_from(FlowLog))).scalar() or 0

    return SentryStatusOut(
        mode=mode,
        baseline_progress_pct=progress,
        uptime_seconds=int(time.time() - app_state.started_at),
        active_hosts=active_hosts,
        flows_processed=flows,
        model_versions={"autoencoder": engine.state.get("model_version", "none") if engine else "none"},
        moe_bundle_version=engine.moe.version if engine else "none",
        active_incidents=active_incidents,
        llm_healthy=llm_healthy,
    )


@router.post("/reset")
async def reset(
    learn_time: float | None = None,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Clear the environment baseline/model and return to monitoring.

    Destructive for the learned baseline, but not for incidents, evidence, or
    audit history. Intended for demo environments and deliberate re-baselining.
    """
    engine = app_state.engine
    if not engine:
        return {"status": "error", "message": "Engine not ready"}
    engine.reset(learn_time)
    add_audit(db, user, "sentry.reset", "engine", {"learn_time": learn_time})
    await db.commit()
    return {"status": "reset", "mode": engine.mode}


@router.post("/train")
async def train(user=Depends(require_admin)):
    engine = app_state.engine
    if not engine:
        return {"status": "error", "message": "Engine not ready"}
    asyncio.create_task(_run_train(engine))
    return {"status": "training_started"}


@router.post("/retrain")
async def retrain(user=Depends(require_admin)):
    engine = app_state.engine
    if not engine:
        return {"status": "error", "message": "Engine not ready"}
    asyncio.create_task(_run_train(engine))
    return {"status": "retrain_started"}


@router.get("/baseline-progress")
async def baseline_progress(user=Depends(get_current_user)):
    engine = app_state.engine
    if not engine:
        return {"progress_pct": 0.0, "estimated_remaining_hours": 0}
    return {"progress_pct": engine._monitoring_progress(), "mode": engine.mode}


async def _run_train(engine):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, engine.train_models)
