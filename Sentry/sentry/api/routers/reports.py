"""Reports routes (investor / research / export)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_db
from ...db.models import Detection, FlowLog, Host, Incident
from ..deps import get_current_user
from ..schemas import ReportResponse

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/investor", response_model=ReportResponse)
async def investor(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    since = datetime.now(timezone.utc) - timedelta(days=30)
    alerts = (await db.execute(select(func.count()).select_from(Detection).where(Detection.timestamp >= since))).scalar() or 0
    critical = (await db.execute(
        select(func.count()).select_from(Detection).where(Detection.severity == "critical", Detection.timestamp >= since)
    )).scalar() or 0
    hosts = (await db.execute(select(func.count()).select_from(Host))).scalar() or 0
    incidents = (await db.execute(select(func.count()).select_from(Incident).where(Incident.created_at >= since))).scalar() or 0
    flows = (await db.execute(select(func.count()).select_from(FlowLog).where(FlowLog.timestamp >= since))).scalar() or 0
    return ReportResponse(
        title="Investor Security Report",
        generated_at=datetime.now(timezone.utc),
        metrics={
            "alerts_30d": alerts,
            "critical_30d": critical,
            "hosts_monitored": hosts,
            "incidents_30d": incidents,
            "flows_analyzed_30d": flows,
            "mttr_seconds": "—",
        },
        sections=[
            {"heading": "Executive Summary", "body": "AttackSentry detected and triaged threats autonomously over the reporting period."},
            {"heading": "Threat Landscape", "body": f"{alerts} alerts across {incidents} correlated incidents."},
        ],
    )


@router.get("/research", response_model=ReportResponse)
async def research(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    since = datetime.now(timezone.utc) - timedelta(days=30)
    top_experts = dict((await db.execute(
        select(Detection.primary_expert, func.count()).where(Detection.timestamp >= since).group_by(Detection.primary_expert)
    )).all())
    return ReportResponse(
        title="Research Report",
        generated_at=datetime.now(timezone.utc),
        metrics={"expert_distribution": top_experts},
        sections=[
            {"heading": "Detection Model Analysis", "body": "Expert routing distribution over the last 30 days."},
        ],
    )
