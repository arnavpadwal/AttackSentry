"""FastAPI application factory for AttackSentry."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import select

from ..config import settings
from ..db import close_db, init_db, session_factory
from ..db.models import SuppressionRule
from ..llm.service import LLMTriageService
from ..logging_conf import request_id_var, setup_logging
from ..workers.nats_consumer import run_nats_consumer
from ..workers.pipeline import IngestionPipeline

setup_logging()
logger = logging.getLogger("sentry.api")


def _build_engine():
    from ..core.engine import SentryEngine

    return SentryEngine(
        env_id="default_env",
        base_path=Path(settings.data_dir),
        models_dir=Path(settings.models_dir),
        baseline_hours=settings.baseline_hours,
        reservoir_size=settings.reservoir_size,
        incident_window=settings.incident_window_seconds,
        suppression_window=settings.suppression_window_seconds,
        decay_hours=24.0,
        min_attack_confidence=settings.min_attack_confidence,
        strong_anomaly_threshold=settings.strong_anomaly_threshold,
        zero_day_max_confidence=settings.zero_day_max_confidence,
    )


async def _sync_suppressions(engine) -> None:
    from ..core.fidelity import SuppressionRule as FidelityRule
    async with session_factory() as db:
        rules = (await db.execute(select(SuppressionRule).where(SuppressionRule.is_active.is_(True)))).scalars().all()
    engine.fidelity.suppression_rules = [
        FidelityRule(entity=r.entity, subnet=r.subnet, attack_family=r.attack_family, reason=r.reason)
        for r in rules
    ]


@asynccontextmanager
async def lifespan(app: FastAPI):
    from .bootstrap import bootstrap
    from .state import app_state

    await init_db()
    await bootstrap()

    engine = _build_engine()
    llm = LLMTriageService() if settings.llm_provider != "none" else None
    await _sync_suppressions(engine)

    pipeline = IngestionPipeline(engine, llm=llm)
    await pipeline.start()

    app_state.engine = engine
    app_state.llm = llm
    app_state.pipeline = pipeline
    app_state.webhooks = pipeline.webhooks

    if settings.nats_url:
        app.state.nats_task = _create_nats_task(pipeline)
    else:
        logger.warning(
            "SENTRY_NATS_URL is empty — sensor streaming is disabled; REST ingestion remains available"
        )

    logger.info(
        "AttackSentry ready — mode=%s, moe=%s, llm=%s",
        engine.mode, engine.moe.version, "on" if llm else "off",
    )
    yield

    await pipeline.stop()
    pending = list(app_state.background_tasks)
    nats_task = getattr(app.state, "nats_task", None)
    if nats_task:
        pending.append(nats_task)
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    await close_db()


def _create_nats_task(pipeline):
    import asyncio
    return asyncio.create_task(run_nats_consumer(pipeline))


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name, version=settings.app_version,
                  docs_url="/api/docs", redoc_url=None, lifespan=lifespan)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def security_headers(request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))[:128]
        token = request_id_var.set(request_id)
        started = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("Unhandled request error", extra={"method": request.method, "path": request.url.path})
            raise
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = request_id
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self' ws: wss:; frame-ancestors 'none'",
        )
        if settings.cookie_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        logger.info("HTTP request", extra={
            "request_id": request_id, "method": request.method, "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
        })
        return response

    from .routers import (
        alerts,
        auth,
        devices,
        diagnostics,
        health,
        hosts,
        incidents,
        ingest,
        mitigations,
        moe,
        network,
        overview,
        reports,
        sensors,
        sentry,
        settings_router,
        setup,
        suppressions,
        users,
    )
    from .ws import router as ws_router

    app.include_router(auth.router)
    app.include_router(health.router)
    app.include_router(diagnostics.router)
    app.include_router(alerts.router)
    app.include_router(incidents.router)
    app.include_router(mitigations.router)
    app.include_router(hosts.router)
    app.include_router(devices.router)
    app.include_router(sentry.router)
    app.include_router(moe.router)
    app.include_router(network.router)
    app.include_router(reports.router)
    app.include_router(settings_router.router)
    app.include_router(overview.router)
    app.include_router(users.router)
    app.include_router(sensors.router)
    app.include_router(suppressions.router)
    app.include_router(ingest.router)
    app.include_router(setup.router)
    app.include_router(ws_router)

    if settings.metrics_enabled:
        @app.get("/metrics")
        async def metrics():
            return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    if settings.serve_static:
        from .spa import SPAStaticFiles
        app.mount("/", SPAStaticFiles(directory=settings.static_dir, html=True), name="spa")

    return app


app = create_app()
