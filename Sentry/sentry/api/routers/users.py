"""User management routes (admin only)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_db
from ...db.models import User
from ..audit import add_audit
from ..deps import require_admin
from ..schemas import UserCreate, UserOut, UserUpdate
from ..security import hash_password

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserOut])
async def list_users(db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    items = (await db.execute(select(User).order_by(User.created_at))).scalars().all()
    return [UserOut.model_validate(u) for u in items]


@router.post("", response_model=UserOut)
async def create_user(body: UserCreate, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    existing = (await db.execute(
        select(User).where((User.username == body.username) | (User.email == body.email))
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(400, "Username or email already exists")
    u = User(email=body.email, username=body.username, full_name=body.full_name,
             hashed_password=hash_password(body.password), role=body.role)
    db.add(u)
    add_audit(db, user, "user.create", f"user:{body.username}", {"role": body.role})
    await db.commit()
    await db.refresh(u)
    return UserOut.model_validate(u)


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(user_id: str, body: UserUpdate, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found")
    if body.email and body.email != u.email:
        duplicate = (await db.execute(select(User).where(User.email == body.email, User.id != u.id))).scalar_one_or_none()
        if duplicate:
            raise HTTPException(400, "Email already exists")
    demoting_admin = u.role == "admin" and (
        (body.role is not None and body.role != "admin") or body.is_active is False
    )
    if demoting_admin:
        active_admins = (await db.execute(
            select(func.count()).select_from(User).where(User.role == "admin", User.is_active.is_(True))
        )).scalar() or 0
        if active_admins <= 1:
            raise HTTPException(400, "At least one active administrator is required")
    if u.id == user.id and body.is_active is False:
        raise HTTPException(400, "You cannot deactivate your own account")
    for f in ("email", "full_name", "role", "is_active"):
        if getattr(body, f) is not None:
            setattr(u, f, getattr(body, f))
    if body.password:
        u.hashed_password = hash_password(body.password)
    add_audit(db, user, "user.update", f"user:{u.id}", {"fields": sorted(body.model_dump(exclude_none=True))})
    await db.commit()
    return UserOut.model_validate(u)


@router.delete("/{user_id}")
async def delete_user(user_id: str, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found")
    if u.id == user.id:
        raise HTTPException(400, "You cannot delete your own active session account")
    if u.role == "admin":
        active_admins = (await db.execute(
            select(func.count()).select_from(User).where(User.role == "admin", User.is_active.is_(True))
        )).scalar() or 0
        if active_admins <= 1:
            raise HTTPException(400, "At least one active administrator is required")
    add_audit(db, user, "user.delete", f"user:{u.id}", {"username": u.username})
    await db.delete(u)
    await db.commit()
    return {"status": "ok"}
