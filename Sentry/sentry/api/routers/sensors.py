"""Sensor management routes (list / register / heartbeat + API keys)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import settings
from ...db import get_db
from ...db.models import APIKey, Sensor
from ..audit import add_audit
from ..deps import get_current_user, require_admin
from ..schemas import SensorCreate, SensorOut
from ..security import generate_api_key, hash_api_secret
from .ingest import _authenticate

router = APIRouter(prefix="/api/sensors", tags=["sensors"])


@router.get("", response_model=list[SensorOut])
async def list_sensors(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    items = (await db.execute(select(Sensor).order_by(Sensor.name))).scalars().all()
    return [SensorOut.model_validate(s) for s in items]


@router.post("", response_model=SensorOut)
async def create_sensor(body: SensorCreate, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    s = Sensor(**body.model_dump())
    db.add(s)
    add_audit(db, user, "sensor.create", f"sensor:{s.id}", {"name": s.name})
    await db.commit()
    await db.refresh(s)
    return SensorOut.model_validate(s)


@router.post("/{sensor_id}/api-key")
async def create_sensor_api_key(sensor_id: str, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    s = (await db.execute(select(Sensor).where(Sensor.id == sensor_id))).scalar_one_or_none()
    if not s:
        raise HTTPException(404, "Sensor not found")
    key_id, secret = generate_api_key()
    db.add(APIKey(name=f"sensor-{s.name}", key_id=key_id, secret_hash=hash_api_secret(secret), owner_type="sensor"))
    add_audit(db, user, "sensor.api_key.create", f"sensor:{s.id}", {"key_id": key_id})
    await db.commit()
    # Secret is returned exactly once.
    return {"key_id": key_id, "secret": secret}


@router.get("/{sensor_id}/config", response_class=PlainTextResponse)
async def download_sensor_config(
    sensor_id: str,
    platform: Literal["linux", "windows"] = Query("linux"),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Return a non-secret, platform-ready sensor configuration template."""
    sensor = (await db.execute(select(Sensor).where(Sensor.id == sensor_id))).scalar_one_or_none()
    if not sensor:
        raise HTTPException(404, "Sensor not found")
    parsed = urlsplit(settings.nats_url or "nats://127.0.0.1:4222")
    host = parsed.hostname or "127.0.0.1"
    netloc = f"{host}:{parsed.port or 4222}"
    safe_url = urlunsplit((parsed.scheme or "nats", netloc, parsed.path, "", ""))
    username = parsed.username or "attacksentry"
    values = {
        "SENTRY_HEADLESS": "1",
        "SENTRY_NATS_URL": safe_url,
        "SENTRY_NATS_USERNAME": username,
        "SENTRY_NATS_PASSWORD": "REPLACE_WITH_NATS_PASSWORD",
        "SENTRY_SUBJECT": settings.nats_subject,
        "SENTRY_SENSOR_ID": sensor.id,
    }
    if platform == "windows":
        content = "\r\n".join(f'$env:{key}="{value}"' for key, value in values.items()) + "\r\n.\\attacksentry-sensor.exe\r\n"
        filename = f"attacksentry-sensor-{sensor.id}.ps1"
    else:
        content = "\n".join(f"{key}={value}" for key, value in values.items()) + "\n"
        filename = f"attacksentry-sensor-{sensor.id}.env"
    add_audit(db, user, "sensor.config.download", f"sensor:{sensor.id}", {"platform": platform})
    await db.commit()
    return PlainTextResponse(content, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.post("/{sensor_id}/heartbeat")
async def heartbeat(
    sensor_id: str,
    body: dict | None = None,
    db: AsyncSession = Depends(get_db),
    _: bool = Depends(_authenticate),
):
    s = (await db.execute(select(Sensor).where(Sensor.id == sensor_id))).scalar_one_or_none()
    if not s:
        raise HTTPException(404, "Sensor not found")
    s.last_heartbeat = datetime.now(timezone.utc)
    s.status = "online"
    if body:
        s.flows_per_second = body.get("flows_per_second", s.flows_per_second)
        s.total_flows = body.get("total_flows", s.total_flows)
    await db.commit()
    return {"status": "authenticated"}
