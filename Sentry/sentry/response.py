"""Policy evaluation and auditable response dispatch."""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from .config import settings
from .db import session_factory
from .db.models import Incident, MitigationAction

logger = logging.getLogger("sentry.response")
SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def response_policy_matches(detection: dict) -> bool:
    if settings.response_mode == "disabled":
        return False
    severity_ok = SEVERITY.get(detection.get("severity", "low"), 0) >= SEVERITY[settings.response_min_severity]
    confidence_ok = float(detection.get("confidence", 0)) >= settings.response_min_confidence
    entity = (detection.get("context") or {}).get("src_ip", "")
    try:
        ipaddress.ip_address(entity)
    except ValueError:
        return False
    return severity_ok and confidence_ok and detection.get("fidelity_action") in {"create", "escalate"}


def new_policy_action(detection: dict) -> MitigationAction:
    now = datetime.now(timezone.utc)
    mode = settings.response_mode
    action, target = recommended_response(detection)
    return MitigationAction(
        incident_id=detection["incident_id"],
        entity=target,
        action=action,
        mode=mode,
        status="queued" if mode == "automatic" else "pending_approval",
        reason=f"Attack-aware policy: {detection.get('detection_type', 'anomaly')}; {detection['severity']} severity, {detection['confidence']:.1%} confidence",
        requested_by="policy-engine",
        expires_at=now + timedelta(minutes=settings.response_ttl_minutes),
    )


def recommended_response(detection: dict) -> tuple[str, str]:
    """Select the least-disruptive useful control for the classified attack."""
    ctx = detection.get("context") or {}
    attack = str(detection.get("detection_type") or "").casefold()
    src, dst = str(ctx.get("src_ip") or ""), str(ctx.get("dst_ip") or "")
    if settings.response_action != "dynamic":
        return settings.response_action, src
    if "ddos" in attack or "flood" in attack or "dos (" in attack:
        return "rate_limit", dst or src
    if "brute" in attack or "scan" in attack or "probing" in attack:
        return "block_ip", src
    return "isolate_host", src


async def dispatch_mitigation(action_id: str, dispatcher) -> None:
    """Send a mitigation request and persist the provider outcome."""
    async with session_factory() as db:
        action = (await db.execute(select(MitigationAction).where(MitigationAction.id == action_id))).scalar_one_or_none()
        if not action or action.status not in {"queued", "retrying"}:
            return
        if action.expires_at and action.expires_at < datetime.now(timezone.utc):
            action.status = "expired"
            await db.commit()
            return
        payload = {
            "action_id": action.id,
            "incident_id": action.incident_id,
            "action": action.action,
            "target": {"type": "ip", "value": action.entity},
            "expires_at": action.expires_at.isoformat() if action.expires_at else None,
            "reason": action.reason,
            "mode": action.mode,
        }
        ok, message = await dispatcher.send("com.attacksentry.response.requested", payload)
        action.status = "dispatched" if ok else "failed"
        action.executed_at = datetime.now(timezone.utc) if ok else None
        action.provider_message = message
        if ok and settings.response_auto_resolve:
            incident = (await db.execute(select(Incident).where(Incident.id == action.incident_id))).scalar_one_or_none()
            if incident and incident.status != "resolved":
                incident.status = "resolved"
                incident.resolved_at = datetime.now(timezone.utc)
        await db.commit()
        logger.info("Mitigation delivery completed", extra={
            "action_id": action.id, "incident_id": action.incident_id,
            "action": action.action, "status": action.status,
        })


async def dispatch_release(action_id: str, dispatcher) -> None:
    """Release a previously dispatched, time-bounded control."""
    async with session_factory() as db:
        action = (await db.execute(select(MitigationAction).where(MitigationAction.id == action_id))).scalar_one_or_none()
        if not action or action.status not in {"release_queued", "release_failed"}:
            return
        payload = {
            "action_id": action.id, "incident_id": action.incident_id,
            "action": action.action, "target": {"type": "ip", "value": action.entity},
            "reason": "Control lifetime expired or operator requested release",
        }
        ok, message = await dispatcher.send("com.attacksentry.response.release_requested", payload)
        action.status = "released" if ok else "release_failed"
        action.provider_message = message
        await db.commit()
        logger.info("Mitigation release completed", extra={
            "action_id": action.id, "incident_id": action.incident_id, "status": action.status,
        })
