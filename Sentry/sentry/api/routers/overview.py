"""Overview / traffic summary routes."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_db
from ...db.models import Detection, FlowLog, Host, Incident, Sensor
from ..deps import get_current_user
from ..schemas import TrafficSummary

router = APIRouter(prefix="/api/traffic", tags=["overview"])


@router.get("/recent")
async def recent_flows(limit: int = 200, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    """Seed the live chart from persisted telemetry after login or reconnect."""
    limit = max(1, min(limit, 1000))
    rows = (await db.execute(select(FlowLog).order_by(FlowLog.timestamp.desc()).limit(limit))).scalars().all()
    return [{"timestamp": row.timestamp.timestamp(), "src_ip": row.src_ip, "dst_ip": row.dst_ip or "",
             "dst_port": row.dst_port, "protocol": row.protocol, "bytes_in": row.bytes_received,
             "bytes_out": row.bytes_sent} for row in reversed(rows)]


@router.get("/summary", response_model=TrafficSummary)
async def summary(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=24)
    live_since = now - timedelta(seconds=60)
    flows_24h = (await db.execute(
        select(func.count()).select_from(FlowLog).where(FlowLog.timestamp >= since)
    )).scalar() or 0
    alerts_24h = (await db.execute(
        select(func.count()).select_from(Detection).where(Detection.timestamp >= since)
    )).scalar() or 0

    sev_counts = dict((await db.execute(
        select(Detection.severity, func.count()).where(Detection.timestamp >= since).group_by(Detection.severity)
    )).all())

    entities = (await db.execute(
        select(func.count()).select_from(Host).where(Host.risk_score >= 20)
    )).scalar() or 0
    # A registered sensor is not necessarily collecting.  Only count sensors
    # that have checked in recently, so an offline appliance cannot make the
    # dashboard look healthy.
    sensor_cutoff = now - timedelta(minutes=5)
    sensors = (await db.execute(
        select(func.count()).select_from(Sensor).where(
            Sensor.status == "online", Sensor.last_heartbeat >= sensor_cutoff
        )
    )).scalar() or 0
    live_totals = (await db.execute(
        select(
            func.coalesce(func.sum(FlowLog.bytes_sent + FlowLog.bytes_received), 0),
            func.coalesce(func.sum(FlowLog.packets_sent + FlowLog.packets_received), 0),
            func.count(),
        ).where(FlowLog.timestamp >= live_since)
    )).one()

    # Threat level = blend of the riskiest entity and the worst open incident,
    # so it reflects current posture rather than raw alert volume (which would
    # trivially saturate under a flood).
    max_risk = (await db.execute(select(func.max(Host.risk_score)))).scalar() or 0.0
    open_severities = (await db.execute(select(Incident.severity).where(Incident.status == "open"))).scalars().all()
    open_sev = max(open_severities, key=lambda value: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(value, 0), default="")
    incident_score = {"critical": 100, "high": 75, "medium": 50, "low": 25}.get(open_sev, 0)
    threat_level = round(min(100.0, 0.5 * float(max_risk) + 0.5 * incident_score))

    return TrafficSummary(
        bytes_per_sec=float(live_totals[0]) / 60.0,
        packets_per_sec=float(live_totals[1]) / 60.0,
        active_flows=int(live_totals[2]),
        total_flows_24h=flows_24h,
        total_alerts_24h=alerts_24h,
        critical_24h=sev_counts.get("critical", 0),
        high_24h=sev_counts.get("high", 0),
        medium_24h=sev_counts.get("medium", 0),
        low_24h=sev_counts.get("low", 0),
        entities_at_risk=entities,
        active_sensors=sensors,
        threat_level=threat_level,
    )
