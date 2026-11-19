"""Human-approved and policy-controlled mitigation workflows."""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_db
from ...db.models import Incident, MitigationAction
from ...response import dispatch_mitigation, dispatch_release
from ..audit import add_audit
from ..deps import get_current_user, require_admin, require_analyst
from ..schemas import MitigationCreate, MitigationOut
from ..state import app_state

router = APIRouter(prefix="/api/mitigations", tags=["response"])


@router.get("", response_model=list[MitigationOut])
async def list_actions(status: str | None = None, limit: int = Query(100, ge=1, le=500),
                       db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    q = select(MitigationAction)
    if status:
        q = q.where(MitigationAction.status == status)
    rows = (await db.execute(q.order_by(MitigationAction.created_at.desc()).limit(limit))).scalars().all()
    return [MitigationOut.model_validate(row) for row in rows]


@router.post("", response_model=MitigationOut)
async def request_action(body: MitigationCreate, db: AsyncSession = Depends(get_db), user=Depends(require_analyst)):
    incident = (await db.execute(select(Incident).where(Incident.id == body.incident_id))).scalar_one_or_none()
    if not incident:
        raise HTTPException(404, "Incident not found")
    try:
        ipaddress.ip_address(incident.entity)
    except ValueError:
        raise HTTPException(422, "Incident entity is not a valid IP mitigation target")
    action = MitigationAction(
        incident_id=incident.id, entity=incident.entity, action=body.action,
        mode="manual", status="pending_approval", reason=body.reason,
        requested_by=user.id, expires_at=datetime.now(timezone.utc) + timedelta(minutes=body.ttl_minutes),
    )
    db.add(action)
    await db.flush()
    add_audit(db, user, "mitigation.request", f"mitigation:{action.id}", {"action": action.action, "entity": action.entity})
    await db.commit()
    await db.refresh(action)
    return MitigationOut.model_validate(action)


@router.post("/{action_id}/release", response_model=MitigationOut)
async def release_action(action_id: str, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    action = (await db.execute(select(MitigationAction).where(MitigationAction.id == action_id))).scalar_one_or_none()
    if not action:
        raise HTTPException(404, "Mitigation not found")
    if action.status not in {"dispatched", "release_failed"}:
        raise HTTPException(409, f"Cannot release mitigation in {action.status} state")
    action.status = "release_queued"
    add_audit(db, user, "mitigation.release", f"mitigation:{action.id}", {"action": action.action, "entity": action.entity})
    await db.commit()
    await db.refresh(action)
    app_state.track_task(dispatch_release(action.id, app_state.webhooks))
    return MitigationOut.model_validate(action)


@router.post("/{action_id}/approve", response_model=MitigationOut)
async def approve_action(action_id: str, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    action = (await db.execute(select(MitigationAction).where(MitigationAction.id == action_id))).scalar_one_or_none()
    if not action:
        raise HTTPException(404, "Mitigation not found")
    if action.status not in {"pending_approval", "failed"}:
        raise HTTPException(409, f"Cannot approve mitigation in {action.status} state")
    action.status = "queued"
    action.approved_by = user.id
    add_audit(db, user, "mitigation.approve", f"mitigation:{action.id}", {"action": action.action, "entity": action.entity})
    await db.commit()
    await db.refresh(action)
    app_state.track_task(dispatch_mitigation(action.id, app_state.webhooks))
    return MitigationOut.model_validate(action)


@router.post("/{action_id}/cancel", response_model=MitigationOut)
async def cancel_action(action_id: str, db: AsyncSession = Depends(get_db), user=Depends(require_analyst)):
    action = (await db.execute(select(MitigationAction).where(MitigationAction.id == action_id))).scalar_one_or_none()
    if not action:
        raise HTTPException(404, "Mitigation not found")
    if action.status not in {"pending_approval", "queued", "failed"}:
        raise HTTPException(409, f"Cannot cancel mitigation in {action.status} state")
    action.status = "cancelled"
    add_audit(db, user, "mitigation.cancel", f"mitigation:{action.id}")
    await db.commit()
    return MitigationOut.model_validate(action)
