"""Ingestion routes: REST flow ingest with sensor API-key authentication."""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select

from ...db.models import APIKey
from ..schemas import IngestResponse
from ..security import verify_api_secret
from ..state import app_state

logger = logging.getLogger("sentry.ingest")

router = APIRouter(prefix="/api/ingest", tags=["ingestion"])


async def _authenticate(
    key_id: Optional[str] = Header(None, alias="X-Sentry-Key-ID"),
    secret: Optional[str] = Header(None, alias="X-Sentry-Secret"),
) -> bool:
    if not key_id or not secret:
        raise HTTPException(401, "Missing sensor credentials")
    from ...db import session_factory
    async with session_factory() as db:
        key = (await db.execute(
            select(APIKey).where(APIKey.key_id == key_id, APIKey.is_active.is_(True))
        )).scalar_one_or_none()
    if not key or not verify_api_secret(secret, key.secret_hash):
        raise HTTPException(401, "Invalid sensor credentials")
    return True


MAX_INGEST_BYTES = 2 * 1024 * 1024
MAX_BATCH_SIZE = 1000


async def _read_ingest_body(request: Request) -> Any:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_INGEST_BYTES:
                raise HTTPException(413, "Ingest payload exceeds 2 MiB")
        except ValueError:
            raise HTTPException(400, "Invalid Content-Length header")
    raw = await request.body()
    if len(raw) > MAX_INGEST_BYTES:
        raise HTTPException(413, "Ingest payload exceeds 2 MiB")
    try:
        import json
        return json.loads(raw)
    except (ValueError, TypeError):
        raise HTTPException(400, "Invalid JSON payload")


@router.post("/flow", response_model=IngestResponse)
async def ingest_flow(request: Request, _: None = Depends(_authenticate)):
    body = await _read_ingest_body(request)
    flows = body if isinstance(body, list) else [body]
    if len(flows) > MAX_BATCH_SIZE:
        raise HTTPException(413, f"Batch exceeds {MAX_BATCH_SIZE} flows")
    if any(not isinstance(flow, dict) for flow in flows):
        raise HTTPException(422, "Each flow must be a JSON object")
    pipeline = getattr(app_state, "pipeline", None)
    if pipeline is None:
        dets = [app_state.engine.process_flow(f) for f in flows]
        dets = [d for d in dets if d]
        if dets:
            return IngestResponse(status="processed", detection_id=dets[0].get("incident_id"),
                                  incident_id=dets[0].get("incident_id"), action=dets[0].get("fidelity_action"))
        return IngestResponse(status="processed")
    for f in flows:
        await pipeline.enqueue(f, source="rest")
    return IngestResponse(status="received")


@router.post("/cloud")
async def ingest_cloud(body: dict, _: None = Depends(_authenticate)):
    logger.info("Received cloud telemetry: %s", body.get("provider"))
    return {"status": "received"}
