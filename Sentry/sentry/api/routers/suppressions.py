"""Suppression rule management routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.fidelity import SuppressionRule as FidelityRule
from ...db import get_db
from ...db.models import SuppressionRule
from ..audit import add_audit
from ..deps import get_current_user, require_admin
from ..schemas import SuppressionRuleCreate, SuppressionRuleOut, SuppressionRuleUpdate
from ..state import app_state

router = APIRouter(prefix="/api/suppressions", tags=["suppressions"])


def _sync_fidelity(db_rules) -> None:
    if app_state.engine:
        app_state.engine.fidelity.suppression_rules = [
            FidelityRule(entity=r.entity, subnet=r.subnet, attack_family=r.attack_family, reason=r.reason)
            for r in db_rules if r.is_active
        ]


@router.get("", response_model=list[SuppressionRuleOut])
async def list_rules(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    items = (await db.execute(select(SuppressionRule))).scalars().all()
    return [SuppressionRuleOut.model_validate(r) for r in items]


@router.post("", response_model=SuppressionRuleOut)
async def create_rule(body: SuppressionRuleCreate, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    r = SuppressionRule(**body.model_dump())
    db.add(r)
    add_audit(db, user, "suppression.create", f"suppression:{r.id}", {"name": r.name})
    await db.commit()
    await db.refresh(r)
    _sync_fidelity((await db.execute(select(SuppressionRule))).scalars().all())
    return SuppressionRuleOut.model_validate(r)


@router.patch("/{rule_id}", response_model=SuppressionRuleOut)
async def update_rule(rule_id: str, body: SuppressionRuleUpdate, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    r = (await db.execute(select(SuppressionRule).where(SuppressionRule.id == rule_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Rule not found")
    changes = body.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(r, field, value)
    if not any((r.entity, r.subnet, r.attack_family)):
        raise HTTPException(422, "At least one entity, subnet, or attack family is required")
    add_audit(db, user, "suppression.update", f"suppression:{r.id}", {"fields": sorted(changes)})
    await db.commit()
    _sync_fidelity((await db.execute(select(SuppressionRule))).scalars().all())
    return SuppressionRuleOut.model_validate(r)


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    r = (await db.execute(select(SuppressionRule).where(SuppressionRule.id == rule_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Rule not found")
    add_audit(db, user, "suppression.delete", f"suppression:{r.id}", {"name": r.name})
    await db.delete(r)
    await db.commit()
    _sync_fidelity((await db.execute(select(SuppressionRule))).scalars().all())
    return {"status": "ok"}
