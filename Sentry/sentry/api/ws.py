"""WebSocket feeds backed by the in-process event bus (real telemetry/alerts)."""
from __future__ import annotations

import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .events import bus
from .security import decode_token

router = APIRouter(tags=["websocket"])


async def _stream(ws: WebSocket, channel: str) -> None:
    token = ws.cookies.get("access_token")
    try:
        payload = decode_token(token or "")
        if payload.get("type") != "access":
            raise ValueError("invalid token type")
    except Exception:
        await ws.close(code=4401, reason="Authentication required")
        return

    await ws.accept()
    q = await bus.subscribe(channel)
    try:
        while True:
            payload = await q.get()
            await ws.send_text(json.dumps(payload, default=str))
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        await bus.unsubscribe(channel, q)


@router.websocket("/ws/telemetry")
async def telemetry_ws(ws: WebSocket):
    await _stream(ws, "telemetry")


@router.websocket("/ws/traffic")
async def traffic_ws(ws: WebSocket):
    await _stream(ws, "traffic")


@router.websocket("/ws/alerts")
async def alerts_ws(ws: WebSocket):
    await _stream(ws, "alerts")


@router.websocket("/ws/incidents")
async def incidents_ws(ws: WebSocket):
    await _stream(ws, "incidents")
