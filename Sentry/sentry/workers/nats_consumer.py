"""NATS JetStream consumer for sensor -> core streaming (optional)."""
from __future__ import annotations

import asyncio
import json
import logging

from ..config import settings
from .pipeline import IngestionPipeline

logger = logging.getLogger("sentry.nats")


async def run_nats_consumer(pipeline: IngestionPipeline) -> None:
    from ..api.state import app_state
    if not settings.nats_url:
        logger.info("NATS disabled (SENTRY_NATS_URL empty) — REST ingestion only.")
        return

    try:
        import nats
        from nats.js.api import StreamConfig
    except ImportError:  # pragma: no cover
        logger.warning("nats-py not installed — NATS ingestion disabled.")
        return

    while True:
        nc = None
        try:
            nc = await nats.connect(settings.nats_url, connect_timeout=5, max_reconnect_attempts=-1)
            js = nc.jetstream()
            await js.add_stream(StreamConfig(name=settings.nats_stream, subjects=[settings.nats_subject]))
            sub = await js.pull_subscribe(settings.nats_subject, durable="sentry-core")
            app_state.nats_connected = True
            app_state.nats_error = None
            logger.info("NATS consumer ready", extra={"subject": settings.nats_subject, "stream": settings.nats_stream})
            while True:
                try:
                    msgs = await sub.fetch(batch=100, timeout=5)
                except nats.errors.TimeoutError:
                    continue
                for msg in msgs:
                    try:
                        flow = json.loads(msg.data)
                        if await pipeline.enqueue(flow, source="nats"):
                            await msg.ack()
                        else:
                            await msg.nak(delay=2)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        logger.warning("Rejected malformed NATS flow message")
                        await msg.term()
        except asyncio.CancelledError:
            if nc:
                await nc.close()
            raise
        except Exception as exc:
            app_state.nats_connected = False
            app_state.nats_error = exc.__class__.__name__
            logger.warning("NATS consumer unavailable; retrying", extra={"error": str(exc)})
            if nc:
                await nc.close()
            await asyncio.sleep(3)
