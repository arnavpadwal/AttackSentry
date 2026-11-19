"""Endpoint device approval / whitelisting routes."""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_db
from ...db.models import Device
from ..audit import add_audit
from ..deps import get_current_user, require_admin, require_analyst
from ..schemas import DeviceApprove, DeviceOut, DeviceUpdate

router = APIRouter(prefix="/api/devices", tags=["devices"])


def _out(d: Device) -> DeviceOut:
    return DeviceOut(
        id=d.id, hostname=d.hostname, ip=d.ip, mac=d.mac or "", os=d.os or "",
        fingerprint=d.fingerprint or "", status=d.status, whitelist=d.whitelist,
        blacklist=d.blacklist, timeout_hours=d.timeout_hours, first_seen=d.first_seen,
        approved_at=d.approved_at, parent_device_id=d.parent_device_id,
        custom_tag=d.custom_tag, approval_caveat=d.approval_caveat,
    )


@router.get("/pending", response_model=list[DeviceOut])
async def pending(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    items = (await db.execute(select(Device).where(Device.status == "pending"))).scalars().all()
    return [_out(d) for d in items]


@router.get("", response_model=list[DeviceOut])
async def list_devices(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    items = (await db.execute(select(Device).where(Device.status == "approved"))).scalars().all()
    return [_out(d) for d in items]


@router.post("/{device_id}/approve", response_model=DeviceOut)
async def approve(device_id: str, body: DeviceApprove, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    d = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Device not found")
    d.status = "approved"
    d.approved_at = time.time()
    d.timeout_hours = body.timeout_hours
    d.approval_caveat = body.caveat
    add_audit(db, user, "device.approve", f"device:{d.id}", {"timeout_hours": body.timeout_hours})
    await db.commit()
    return _out(d)


@router.post("/{device_id}/reject", response_model=DeviceOut)
async def reject(device_id: str, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    d = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Device not found")
    d.status = "rejected"
    add_audit(db, user, "device.reject", f"device:{d.id}")
    await db.commit()
    return _out(d)


@router.patch("/{device_id}", response_model=DeviceOut)
async def update(device_id: str, body: DeviceUpdate, db: AsyncSession = Depends(get_db), user=Depends(require_analyst)):
    d = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Device not found")
    for f in ("hostname", "os", "custom_tag"):
        if getattr(body, f) is not None:
            setattr(d, f, getattr(body, f))
    add_audit(db, user, "device.update", f"device:{d.id}", {"fields": sorted(body.model_dump(exclude_none=True))})
    await db.commit()
    return _out(d)


@router.delete("/{device_id}")
async def delete(device_id: str, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    d = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Device not found")
    add_audit(db, user, "device.delete", f"device:{d.id}", {"ip": d.ip})
    await db.delete(d)
    await db.commit()
    return {"status": "ok"}
