"""Small audit helper used by state-changing API routes."""
from __future__ import annotations

from typing import Any

from ..db.models import AuditLog, User


def add_audit(db, user: User, action: str, resource: str, detail: dict[str, Any] | None = None) -> None:
    db.add(AuditLog(user_id=user.id, action=action, resource=resource, detail=detail or {}))
