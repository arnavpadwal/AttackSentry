"""Authentication routes (JWT via httpOnly cookies)."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_db
from ...db.models import User
from ..audit import add_audit
from ..deps import get_current_user
from ..schemas import ChangePasswordRequest, LoginRequest, TokenResponse, UserOut
from ..security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

_LOGIN_WINDOW_SECONDS = 300
_LOGIN_MAX_FAILURES = 8
_login_failures: dict[str, deque[float]] = defaultdict(deque)


def _client_key(request: Request, username: str) -> str:
    host = request.client.host if request.client else "unknown"
    return f"{host}:{username.casefold()}"


def _enforce_login_limit(key: str) -> None:
    now = time.monotonic()
    failures = _login_failures[key]
    while failures and now - failures[0] > _LOGIN_WINDOW_SECONDS:
        failures.popleft()
    if len(failures) >= _LOGIN_MAX_FAILURES:
        raise HTTPException(429, "Too many login attempts; try again in a few minutes")

def _set_cookies(response: Response, access: str, refresh: str) -> None:
    from ...config import settings

    cookie_opts = {
        "httponly": True,
        "samesite": "lax",
        "secure": settings.cookie_secure,
        "path": "/",
    }
    response.set_cookie(
        "access_token", access, **cookie_opts,
        max_age=settings.access_token_expire_minutes * 60,
    )
    response.set_cookie(
        "refresh_token", refresh, **cookie_opts,
        max_age=settings.refresh_token_expire_days * 86400,
    )


@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    client_key = _client_key(request, data.username)
    _enforce_login_limit(client_key)
    result = await db.execute(select(User).where(User.username == data.username))
    user = result.scalar_one_or_none()
    if not user or not user.is_active or not verify_password(data.password, user.hashed_password):
        _login_failures[client_key].append(time.monotonic())
        raise HTTPException(401, "Invalid credentials")
    _login_failures.pop(client_key, None)
    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    access = create_access_token(user.id, user.role)
    refresh = create_refresh_token(user.id)
    _set_cookies(response, access, refresh)
    return TokenResponse(access_token=access, refresh_token=refresh, user=UserOut.model_validate(user))


@router.post("/refresh", response_model=TokenResponse)
async def refresh(response: Response, refresh_token: str | None = Cookie(None), db: AsyncSession = Depends(get_db)):
    token = refresh_token or ""
    if not token:
        raise HTTPException(401, "Missing refresh token")
    payload = decode_token(token)
    if payload.get("type") != "refresh":
        raise HTTPException(401, "Invalid refresh token")
    result = await db.execute(select(User).where(User.id == payload["sub"]))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(401, "User not found")
    access = create_access_token(user.id, user.role)
    refresh_new = create_refresh_token(user.id)
    _set_cookies(response, access, refresh_new)
    return TokenResponse(access_token=access, refresh_token=refresh_new, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)):
    return UserOut.model_validate(user)


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"status": "ok"}


@router.post("/change-password")
async def change_password(
    data: ChangePasswordRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not verify_password(data.current_password, user.hashed_password):
        raise HTTPException(400, "Current password is incorrect")
    if data.current_password == data.new_password:
        raise HTTPException(400, "New password must be different")
    user.hashed_password = hash_password(data.new_password)
    add_audit(db, user, "user.password.change", f"user:{user.id}")
    await db.commit()
    return {"status": "ok"}


@router.get("/health")
async def health():
    return {"status": "ok"}
