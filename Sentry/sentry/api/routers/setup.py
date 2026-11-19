"""Setup / onboarding routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_db
from ...db.models import SystemConfig
from ..deps import get_current_user, require_admin
from ..schemas import SetupStatus

router = APIRouter(prefix="/api/setup", tags=["setup"])

_DONE = {"is_setup_complete": True, "current_step": 7,
         "steps_completed": ["welcome", "auth", "environment", "sensors", "integrations", "baseline", "review"]}


@router.get("/status", response_model=SetupStatus)
async def status(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    cfg = (await db.execute(select(SystemConfig).where(SystemConfig.key == "setup"))).scalar_one_or_none()
    if not cfg:
        return SetupStatus(is_setup_complete=False, current_step=0, steps_completed=[])
    return SetupStatus(**cfg.value)


@router.post("/complete")
async def complete(db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    cfg = (await db.execute(select(SystemConfig).where(SystemConfig.key == "setup"))).scalar_one_or_none()
    if cfg:
        cfg.value = _DONE
    else:
        db.add(SystemConfig(key="setup", value=_DONE))
    await db.commit()
    return {"status": "ok"}
