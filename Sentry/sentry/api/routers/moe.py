"""MoE explainability routes."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_db
from ...db.models import Detection
from ...ml.bundle import EXPERT_NAMES
from ..deps import get_current_user
from ..schemas import MoeClassification, MoeExpertPerformance, MoeRoutingStat

router = APIRouter(prefix="/api/moe", tags=["moe"])


@router.get("/routing-stats", response_model=list[MoeRoutingStat])
async def routing_stats(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    q = select(Detection.primary_expert, func.count()).where(Detection.timestamp >= since).group_by(Detection.primary_expert)
    counts = dict((await db.execute(q)).all())
    total = sum(counts.values()) or 1
    out = []
    for expert in EXPERT_NAMES:
        c = counts.get(expert, 0)
        out.append(MoeRoutingStat(expert=expert, share=round(c / total, 4), count=c))
    return out


@router.get("/expert-performance", response_model=list[MoeExpertPerformance])
async def expert_performance(user=Depends(get_current_user)):
    from ..state import app_state
    out = []
    if app_state.engine and app_state.engine.moe.bundle:
        manifest = app_state.engine.moe.bundle.manifest
        for expert in EXPERT_NAMES:
            m = (manifest.get("experts") or {}).get(expert, {})
            out.append(MoeExpertPerformance(
                expert=expert,
                f1=m.get("f1", 0.0),
                roc_auc=m.get("roc_auc", 0.0),
                precision=m.get("precision", 0.0),
                recall=m.get("recall", 0.0),
            ))
    return out


@router.get("/recent-classifications", response_model=list[MoeClassification])
async def recent(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    q = select(Detection).order_by(Detection.timestamp.desc()).limit(50)
    items = (await db.execute(q)).scalars().all()
    return [
        MoeClassification(
            id=d.id, timestamp=d.timestamp, detection_type=d.detection_type,
            primary_expert=d.primary_expert, moe_score=d.moe_score,
            expert_distribution=d.expert_distribution, severity=d.severity,
        )
        for d in items
    ]
