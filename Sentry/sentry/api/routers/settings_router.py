"""Settings routes (LLM, thresholds, integrations)."""
from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import settings as cfg
from ...db import get_db
from ...db.models import SystemConfig
from ..audit import add_audit
from ..deps import get_current_user, require_admin
from ..schemas import LLMTestResult, SettingsOut, SettingsUpdate

router = APIRouter(prefix="/api", tags=["settings"])


@router.get("/settings", response_model=SettingsOut)
async def get_settings(user=Depends(get_current_user)):
    return _settings_out()


@router.patch("/settings", response_model=SettingsOut)
async def update_settings(body: SettingsUpdate, user=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    # Runtime-tunable settings are persisted in system_config and applied by
    # the engine/fidelity where relevant. Static config still requires env.
    cfg_map = {"baseline_hours", "default_alert_threshold", "incident_window_seconds",
               "suppression_window_seconds", "retention_days", "llm_provider",
               "llm_base_url", "llm_model", "webhook_url", "webhook_min_severity",
               "response_mode", "response_min_severity", "response_min_confidence",
               "response_action", "response_ttl_minutes"}
    cfg_map.add("response_auto_resolve")
    cfg_map.update({"enforcement_mode", "response_max_auto_per_10m"})
    if body.webhook_url is not None:
        _validate_webhook_url(body.webhook_url)
    candidate_url = body.webhook_url if body.webhook_url is not None else cfg.webhook_url
    candidate_secret = body.webhook_secret if body.webhook_secret is not None else cfg.webhook_secret
    if candidate_url and len(candidate_secret) < 16:
        raise HTTPException(422, "A webhook signing secret of at least 16 characters is required")
    # Automatic mode always has an adapter: the signed webhook when configured,
    # otherwise the local enforcement adapter (simulate or nftables).
    updates = {k: v for k, v in body.model_dump().items() if v is not None and k in cfg_map}
    for key, val in updates.items():
        setattr(cfg, key, val)
    if body.webhook_secret is not None:
        cfg.webhook_secret = body.webhook_secret
    if body.llm_api_key is not None:
        cfg.llm_api_key = body.llm_api_key
    stored = (await db.execute(select(SystemConfig).where(SystemConfig.key == "runtime_settings"))).scalar_one_or_none()
    if stored:
        stored.value = (stored.value or {}) | updates
    else:
        db.add(SystemConfig(key="runtime_settings", value=updates))
    secret_fields = ({"webhook_secret"} if body.webhook_secret is not None else set()) | ({"llm_api_key"} if body.llm_api_key is not None else set())
    changed_fields = sorted(set(updates) | secret_fields)
    add_audit(db, user, "settings.update", "system:runtime_settings", {"fields": changed_fields})
    if "retention_days" in updates and cfg.timescale_enabled and cfg.database_url.startswith("postgresql"):
        days = int(updates["retention_days"])
        for table in ("flow_logs", "detections", "audit_log"):
            await db.execute(text(f"SELECT remove_retention_policy('{table}', if_exists => TRUE)"))
            await db.execute(text(f"SELECT add_retention_policy('{table}', INTERVAL '{days} days')"))
    await db.commit()
    if app_state_set():
        _apply_runtime(cfg)
    return _settings_out()


@router.post("/settings/test-llm", response_model=LLMTestResult)
async def test_llm(user=Depends(require_admin)):
    from ..state import app_state
    if not app_state.llm:
        return LLMTestResult(healthy=False, message="LLM service not configured")
    try:
        # A models-list request only proves the server is listening.  Execute a
        # minimal completion so Settings verifies the selected model too.
        content = await app_state.llm.provider.generate([
            {"role": "user", "content": "Reply with exactly: AttackSentry LLM test passed."},
        ])
        return LLMTestResult(healthy=bool(content.strip()), message="LLM completion succeeded")
    except Exception as exc:
        return LLMTestResult(healthy=False, message=f"LLM completion failed: {str(exc)[:240]}")


@router.post("/settings/test-webhook", response_model=LLMTestResult)
async def test_webhook(user=Depends(require_admin)):
    from ..state import app_state
    if not app_state.webhooks:
        return LLMTestResult(healthy=False, message="Webhook dispatcher is unavailable")
    healthy, message = await app_state.webhooks.send("com.attacksentry.integration.test", {
        "message": "AttackSentry webhook test", "requested_by": user.username,
    })
    return LLMTestResult(healthy=healthy, message=message)


def app_state_set() -> bool:
    from ..state import app_state
    return app_state.engine is not None


def _apply_runtime(cfg) -> None:
    from ..state import app_state
    if app_state.engine:
        app_state.engine.fidelity.incident_window = cfg.incident_window_seconds
        app_state.engine.fidelity.suppression_window = cfg.suppression_window_seconds
    # The provider captures endpoint/model values at construction time. Rebuild
    # it immediately so Settings changes take effect without a service restart.
    from ...llm.service import LLMTriageService
    app_state.llm = LLMTriageService() if cfg.llm_provider != "none" else None
    if app_state.pipeline:
        app_state.pipeline.llm = app_state.llm
        # The batcher captured the previous provider. Rebuild it so the next
        # incident is triaged with the model the operator just selected.
        from ...llm.batcher import TriageBatcher
        old = app_state.pipeline.triage
        app_state.pipeline.triage = (
            TriageBatcher(app_state.llm, app_state.pipeline._persist_playbook)
            if app_state.llm else None
        )
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop:
            if old:
                loop.create_task(old.stop())
            if app_state.pipeline.triage:
                loop.create_task(app_state.pipeline.triage.start())


def _validate_webhook_url(url: str) -> None:
    if not url:
        return
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(422, "Webhook must be an http(s) URL without embedded credentials")
    if cfg.is_production and parsed.scheme != "https":
        raise HTTPException(422, "Webhook must use HTTPS in production")


def _settings_out() -> SettingsOut:
    return SettingsOut(
        llm_provider=cfg.llm_provider, llm_base_url=cfg.llm_base_url, llm_model=cfg.llm_model,
        baseline_hours=cfg.baseline_hours, default_alert_threshold=cfg.default_alert_threshold,
        incident_window_seconds=cfg.incident_window_seconds,
        suppression_window_seconds=cfg.suppression_window_seconds,
        retention_days=cfg.retention_days, webhook_url=cfg.webhook_url,
        webhook_min_severity=cfg.webhook_min_severity,
        webhook_secret_configured=bool(cfg.webhook_secret), response_mode=cfg.response_mode,
        response_min_severity=cfg.response_min_severity,
        response_min_confidence=cfg.response_min_confidence,
        response_action=cfg.response_action, response_ttl_minutes=cfg.response_ttl_minutes,
        response_auto_resolve=cfg.response_auto_resolve,
        enforcement_mode=cfg.enforcement_mode,
        response_max_auto_per_10m=cfg.response_max_auto_per_10m,
    )
