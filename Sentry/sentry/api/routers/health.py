"""Health / readiness probes (unauthenticated, for orchestrators)."""
from __future__ import annotations

from fastapi import APIRouter, Response, status

from ..state import app_state

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz():
    return {"status": "ok", "mode": app_state.engine.mode if app_state.engine else "booting"}


@router.get("/readyz")
async def readyz(response: Response):
    if app_state.engine is None:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready"}
    return {"status": "ready", "mode": app_state.engine.mode}
