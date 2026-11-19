"""Hosts / entity 360 routes."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_db
from ...db.models import Detection, FlowLog, Host
from ..deps import get_current_user
from ..schemas import AlertOut, HostDetail, HostOut, TimeSeries

router = APIRouter(prefix="/api/hosts", tags=["hosts"])


@router.get("", response_model=list[HostOut])
async def list_hosts(
    group: str | None = None,
    risk_min: float = 0.0,
    limit: int = Query(200, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    q = select(Host)
    if group:
        q = q.where(Host.group_name == group)
    if risk_min > 0:
        q = q.where(Host.risk_score >= risk_min)
    q = q.order_by(Host.risk_score.desc()).limit(limit)
    items = (await db.execute(q)).scalars().all()
    return [HostOut.model_validate(h) for h in items]


@router.get("/{host_id}", response_model=HostDetail)
async def get_host(host_id: str, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    h = (await db.execute(select(Host).where(Host.id == host_id))).scalar_one_or_none()
    if not h:
        raise HTTPException(404, "Host not found")
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    alert_count = (await db.execute(
        select(func.count()).select_from(Detection).where(Detection.src_ip == h.ip_address, Detection.timestamp >= since)
    )).scalar() or 0
    detail = HostDetail.model_validate(h)
    detail.alert_count = alert_count
    return detail


@router.get("/{host_id}/traffic", response_model=TimeSeries)
async def host_traffic(host_id: str, range: str = "24h", db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    h = (await db.execute(select(Host).where(Host.id == host_id))).scalar_one_or_none()
    if not h:
        raise HTTPException(404, "Host not found")
    hours = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}.get(range, 24)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    q = select(FlowLog).where(FlowLog.src_ip == h.ip_address, FlowLog.timestamp >= since).order_by(FlowLog.timestamp)
    flows = (await db.execute(q)).scalars().all()
    if not flows:
        return TimeSeries(timestamps=[], values=[])
    ts = [f.timestamp.timestamp() for f in flows]
    vals = [f.bytes_sent + f.bytes_received for f in flows]
    return TimeSeries(timestamps=ts, values=vals)


@router.get("/{host_id}/anomaly-history", response_model=TimeSeries)
async def host_anomaly(host_id: str, range: str = "24h", db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    h = (await db.execute(select(Host).where(Host.id == host_id))).scalar_one_or_none()
    if not h:
        raise HTTPException(404, "Host not found")
    hours = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}.get(range, 24)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    q = select(Detection).where(Detection.src_ip == h.ip_address, Detection.timestamp >= since).order_by(Detection.timestamp)
    dets = (await db.execute(q)).scalars().all()
    ts = [d.timestamp.timestamp() for d in dets]
    vals = [d.anomaly_score for d in dets]
    return TimeSeries(timestamps=ts, values=vals)


@router.get("/{host_id}/alerts", response_model=list[AlertOut])
async def host_alerts(host_id: str, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    h = (await db.execute(select(Host).where(Host.id == host_id))).scalar_one_or_none()
    if not h:
        raise HTTPException(404, "Host not found")
    q = select(Detection).where(Detection.src_ip == h.ip_address).order_by(Detection.timestamp.desc()).limit(50)
    items = (await db.execute(q)).scalars().all()
    return [AlertOut.model_validate(d) for d in items]


@router.patch("/{host_id}", response_model=HostOut)
async def update_host(host_id: str, body: dict, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    h = (await db.execute(select(Host).where(Host.id == host_id))).scalar_one_or_none()
    if not h:
        raise HTTPException(404, "Host not found")
    for field in ("hostname", "group_name", "status", "tags", "os_info"):
        if field in body:
            setattr(h, field, body[field])
    await db.commit()
    return HostOut.model_validate(h)
