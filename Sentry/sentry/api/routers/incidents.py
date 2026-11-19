"""Incident (correlated alert) routes."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_db
from ...db.models import Detection, Incident, Playbook
from ..audit import add_audit
from ..deps import get_current_user, require_analyst
from ..schemas import AlertOut, BulkIncidentUpdate, IncidentOut, IncidentStatusUpdate, PlaybookOut
from ..state import app_state

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


def _is_placeholder_playbook(playbook: Playbook | None) -> bool:
    return bool(playbook and (
        playbook.is_fallback or not playbook.steps or
        not playbook.attack_summary or playbook.attack_summary.strip().upper() == "N/A"
    ))


@router.patch("/bulk/status")
async def bulk_update_incidents(body: BulkIncidentUpdate, db: AsyncSession = Depends(get_db), user=Depends(require_analyst)):
    now = datetime.now(timezone.utc)
    values = {"status": body.status, "resolved_at": now if body.status == "resolved" else None}
    result = await db.execute(update(Incident).where(Incident.id.in_(body.incident_ids)).values(**values))
    add_audit(db, user, "incident.bulk_status", "incidents", {
        "status": body.status, "requested": len(body.incident_ids), "updated": result.rowcount,
    })
    await db.commit()
    return {"updated": result.rowcount or 0, "status": body.status}


@router.get("/summary")
async def incident_summary(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    """Posture counters for the console; never truncated by a page limit."""
    by_severity = dict((await db.execute(
        select(Incident.severity, func.count()).where(Incident.status == "open").group_by(Incident.severity)
    )).all())
    by_family = dict((await db.execute(
        select(Incident.family, func.count()).where(Incident.status == "open").group_by(Incident.family)
    )).all())
    by_status = dict((await db.execute(
        select(Incident.status, func.count()).group_by(Incident.status)
    )).all())
    return {
        "total": sum(by_status.values()),
        "open": by_status.get("open", 0),
        "acknowledged": by_status.get("acknowledged", 0),
        "resolved": by_status.get("resolved", 0),
        "by_severity": by_severity,
        "by_family": by_family,
    }


@router.get("", response_model=list[IncidentOut])
async def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    family: str | None = None,
    q: str | None = None,
    sort: str = Query("recent", pattern="^(recent|severity)$"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    query = select(Incident)
    filters = []
    if status:
        filters.append(Incident.status == status)
    if severity:
        filters.append(Incident.severity == severity)
    if family:
        filters.append(Incident.family == family)
    if q:
        needle = f"%{q.strip()}%"
        filters.append(or_(Incident.entity.ilike(needle), Incident.family.ilike(needle), Incident.id.ilike(needle)))
    if filters:
        query = query.where(*filters)
    if sort == "severity":
        rank = case(
            {"critical": 4, "high": 3, "medium": 2, "low": 1},
            value=Incident.severity,
            else_=0,
        )
        query = query.order_by(rank.desc(), Incident.last_seen.desc())
    else:
        query = query.order_by(Incident.last_seen.desc())
    query = query.offset(offset).limit(limit)
    items = (await db.execute(query)).scalars().all()
    return [IncidentOut.model_validate(i) for i in items]


@router.get("/{incident_id}", response_model=IncidentOut)
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    i = (await db.execute(select(Incident).where(Incident.id == incident_id))).scalar_one_or_none()
    if not i:
        raise HTTPException(404, "Incident not found")
    return IncidentOut.model_validate(i)


@router.get("/{incident_id}/alerts", response_model=list[AlertOut])
async def incident_alerts(incident_id: str, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    q = select(Detection).where(Detection.incident_id == incident_id).order_by(Detection.timestamp.desc())
    items = (await db.execute(q)).scalars().all()
    return [AlertOut.model_validate(d) for d in items]


@router.get("/{incident_id}/playbook", response_model=PlaybookOut)
async def incident_playbook(incident_id: str, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    p = (await db.execute(select(Playbook).where(Playbook.incident_id == incident_id)
                          .order_by(Playbook.created_at.desc()).limit(1))).scalar_one_or_none()
    if not p:
        raise HTTPException(404, "No playbook for this incident")
    if _is_placeholder_playbook(p):
        # A fallback is never final. Retry transparently when the operator
        # revisits an incident after the local model becomes available.
        return await generate_incident_playbook(incident_id, db, user)
    return PlaybookOut.model_validate(p)


@router.post("/{incident_id}/playbook/generate", response_model=PlaybookOut)
async def generate_incident_playbook(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Generate an assessment for an existing incident on analyst request.

    Playbooks normally begin when a new incident is created.  This endpoint
    backfills historic/correlated incidents and prevents a permanent
    "assessment pending" state after an LLM outage or deployment restart.
    """
    existing = (await db.execute(
        select(Playbook).where(Playbook.incident_id == incident_id)
        .order_by(Playbook.created_at.desc()).limit(1)
    )).scalar_one_or_none()
    if existing and not _is_placeholder_playbook(existing):
        return PlaybookOut.model_validate(existing)
    if _is_placeholder_playbook(existing):
        # A fallback is intentionally provisional.  Once the local model is
        # available, replace it instead of making the analyst stare at an old
        # "LLM offline" result forever.
        await db.execute(delete(Playbook).where(Playbook.id == existing.id))
        await db.commit()

    incident = (await db.execute(select(Incident).where(Incident.id == incident_id))).scalar_one_or_none()
    detection = (await db.execute(
        select(Detection).where(Detection.incident_id == incident_id)
        .order_by(Detection.timestamp.desc()).limit(1)
    )).scalar_one_or_none()
    if not incident or not detection:
        raise HTTPException(404, "Incident evidence is unavailable")
    if not app_state.pipeline or not app_state.llm:
        raise HTTPException(503, "AI assessment service is not available")

    report = {
        "incident_id": incident.id,
        "severity": detection.severity,
        "confidence": detection.confidence,
        "detection_type": detection.detection_type,
        "anomaly_score": detection.anomaly_score,
        "entity_risk": detection.entity_risk,
        "reason": detection.reason,
        "context": {
            "src_ip": detection.src_ip,
            "dst_ip": detection.dst_ip,
            "dst_port": detection.dst_port,
            "protocol": detection.protocol,
            "group": detection.group_name,
            "identity": detection.identity,
            "subnet": detection.subnet,
        },
        "classification": {
            "primary_expert": detection.primary_expert,
            "expert_distribution": detection.expert_distribution or {},
            "expert_probs": detection.expert_probs or {},
            "moe_score": detection.moe_score,
        },
        "triggering_log": detection.raw_flow or {},
    }
    await app_state.pipeline._generate_and_persist_playbook(detection.id, report)
    p = (await db.execute(
        select(Playbook).where(Playbook.incident_id == incident_id)
        .order_by(Playbook.created_at.desc()).limit(1)
    )).scalar_one_or_none()
    if not p:
        raise HTTPException(502, "Assessment generation did not return a playbook")
    add_audit(db, user, "incident.playbook_generated", f"incident:{incident_id}", {})
    await db.commit()
    return PlaybookOut.model_validate(p)


@router.patch("/{incident_id}/status", response_model=IncidentOut)
async def update_incident(incident_id: str, body: IncidentStatusUpdate, db: AsyncSession = Depends(get_db), user=Depends(require_analyst)):
    i = (await db.execute(select(Incident).where(Incident.id == incident_id))).scalar_one_or_none()
    if not i:
        raise HTTPException(404, "Incident not found")
    new_status = body.status
    i.status = new_status
    if new_status == "resolved":
        i.resolved_at = datetime.now(timezone.utc)
    else:
        i.resolved_at = None
    add_audit(db, user, "incident.status", f"incident:{i.id}", {"status": new_status})
    await db.commit()
    return IncidentOut.model_validate(i)
