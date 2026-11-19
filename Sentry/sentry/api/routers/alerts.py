"""Alerts (detections) + playbooks routes."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_db
from ...db.models import Detection, Playbook
from ..audit import add_audit
from ..deps import get_current_user, require_analyst
from ..schemas import (
    AlertOut,
    AlertStatusUpdate,
    PaginatedAlerts,
    PlaybookOut,
)

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=PaginatedAlerts)
async def list_alerts(
    severity: str | None = None,
    status: str | None = None,
    expert: str | None = None,
    entity: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    range: str = "24h",
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    q = select(Detection)
    count_q = select(func.count()).select_from(Detection)
    filters = []
    if severity:
        filters.append(Detection.severity.in_(severity.split(",")))
    if status:
        filters.append(Detection.status.in_(status.split(",")))
    if expert:
        filters.append(Detection.primary_expert.in_(expert.split(",")))
    if entity:
        filters.append(Detection.src_ip == entity)
    if range != "all":
        hours = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}.get(range, 24)
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        filters.append(Detection.timestamp >= since)
    if filters:
        q = q.where(*filters)
        count_q = count_q.where(*filters)

    total = (await db.execute(count_q)).scalar() or 0
    q = q.order_by(Detection.timestamp.desc()).offset((page - 1) * page_size).limit(page_size)
    items = (await db.execute(q)).scalars().all()
    return PaginatedAlerts(
        items=[AlertOut.model_validate(d) for d in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/export")
async def export_alerts(
    format: str = "csv", range: str = "24h",
    db: AsyncSession = Depends(get_db), user=Depends(get_current_user),
):
    q = select(Detection).order_by(Detection.timestamp.desc()).limit(10000)
    items = (await db.execute(q)).scalars().all()
    fields = ["id", "timestamp", "severity", "confidence", "detection_type", "anomaly_score",
              "src_ip", "dst_ip", "dst_port", "primary_expert", "status"]
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    for d in items:
        writer.writerow({f: getattr(d, f) for f in fields})
    out.seek(0)
    return StreamingResponse(out, media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=alerts.csv"})


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    d = (await db.execute(select(Detection).where(Detection.id == alert_id))).scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Alert not found")
    return AlertOut.model_validate(d)


@router.patch("/{alert_id}/status", response_model=AlertOut)
async def update_alert(alert_id: str, body: AlertStatusUpdate, db: AsyncSession = Depends(get_db), user=Depends(require_analyst)):
    d = (await db.execute(select(Detection).where(Detection.id == alert_id))).scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Alert not found")
    d.status = body.status
    if body.assigned_to is not None:
        d.assigned_to = body.assigned_to
    add_audit(db, user, "detection.status", f"detection:{d.id}", {"status": body.status, "assigned_to": body.assigned_to})
    await db.commit()
    return AlertOut.model_validate(d)


@router.get("/{alert_id}/playbook", response_model=PlaybookOut)
async def get_playbook(alert_id: str, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    p = (await db.execute(select(Playbook).where(Playbook.detection_id == alert_id))).scalar_one_or_none()
    if not p:
        # Playbooks are written once per incident, usually against the first
        # detection. A later correlated detection still needs the same plan.
        detection = (await db.execute(select(Detection).where(Detection.id == alert_id))).scalar_one_or_none()
        if detection and detection.incident_id:
            p = (await db.execute(
                select(Playbook).where(Playbook.incident_id == detection.incident_id)
                .order_by(Playbook.created_at.desc()).limit(1)
            )).scalar_one_or_none()
    if not p:
        raise HTTPException(404, "No playbook for this alert")
    from .incidents import _is_placeholder_playbook
    if _is_placeholder_playbook(p) and p.incident_id:
        # Alert and incident views must not disagree: retry the incident
        # assessment instead of serving a stale "LLM offline" result.
        from .incidents import generate_incident_playbook
        return await generate_incident_playbook(p.incident_id, db, user)
    return PlaybookOut.model_validate(p)
