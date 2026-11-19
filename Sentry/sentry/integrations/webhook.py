"""Bounded, signed generic webhook delivery for SIEM/SOAR integrations."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger("sentry.integrations.webhook")


class WebhookDispatcher:
    def __init__(self, max_queue: int = 1000):
        self.queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue(maxsize=max_queue)
        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run(), name="webhook-dispatcher")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def enqueue(self, event_type: str, payload: dict[str, Any]) -> bool:
        if not settings.webhook_url:
            return False
        try:
            self.queue.put_nowait((event_type, payload))
            return True
        except asyncio.QueueFull:
            logger.error("Webhook queue full", extra={"event_type": event_type})
            return False

    async def _run(self) -> None:
        while self._running:
            item = None
            try:
                item = await self.queue.get()
                event_type, payload = item
                ok, message = await self.send(event_type, payload)
                log = logger.info if ok else logger.error
                log("Webhook delivery", extra={"event_type": event_type, "result": message})
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Webhook dispatcher error")
            finally:
                if item is not None:
                    self.queue.task_done()

    async def send(self, event_type: str, payload: dict[str, Any]) -> tuple[bool, str]:
        if not settings.webhook_url:
            return False, "Webhook URL is not configured"
        event_id = str(uuid.uuid4())
        envelope = {
            "specversion": "1.0",
            "id": event_id,
            "source": "attacksentry",
            "type": event_type,
            "time": int(time.time()),
            "data": payload,
        }
        body = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode()
        timestamp = str(envelope["time"])
        signed = timestamp.encode() + b"." + body
        signature = hmac.new(settings.webhook_secret.encode(), signed, hashlib.sha256).hexdigest()
        headers = {
            "Content-Type": "application/cloudevents+json",
            "User-Agent": f"AttackSentry/{settings.app_version}",
            "X-AttackSentry-Event": event_type,
            "X-AttackSentry-Delivery": event_id,
            "X-AttackSentry-Timestamp": timestamp,
            "X-AttackSentry-Signature": f"sha256={signature}",
        }
        last_error = "delivery failed"
        async with httpx.AsyncClient(timeout=settings.webhook_timeout, follow_redirects=False) as client:
            for attempt in range(3):
                try:
                    response = await client.post(settings.webhook_url, content=body, headers=headers)
                    if 200 <= response.status_code < 300:
                        return True, f"HTTP {response.status_code}"
                    last_error = f"HTTP {response.status_code}"
                    if response.status_code < 500 and response.status_code != 429:
                        break
                except httpx.HTTPError as exc:
                    last_error = exc.__class__.__name__
                if attempt < 2:
                    await asyncio.sleep(2 ** attempt)
        return False, last_error
