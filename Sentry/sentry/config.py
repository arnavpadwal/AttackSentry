"""Application configuration.

All values are overridable via environment variables (prefix ``SENTRY_``) or a
``.env`` file. No secrets should be hardcoded — production deployments must
supply ``SENTRY_SECRET_KEY``, ``SENTRY_DATABASE_URL`` and ``SENTRY_LLM_API_KEY``
via the environment or a secret store.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_BASE_DIR = Path(__file__).resolve().parent.parent  # Sentry/


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTRY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- App ---
    app_name: str = "AttackSentry"
    app_version: str = "1.0.0"
    environment: str = "development"  # production | staging | development
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]
    serve_static: bool = False
    static_dir: str = str(_BASE_DIR / "static")

    # --- Security / Auth ---
    # MUST be overridden in production (SENTRY_SECRET_KEY).
    secret_key: str = "dev-only-change-me"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    cookie_secure: bool = True
    # Bootstrap admin created on first run if no users exist.
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = ""
    bootstrap_admin_email: str = "admin@localhost"

    # --- Data ---
    # sqlite+aiosqlite:///... for single-node/dev; postgresql+psycopg://... for prod.
    database_url: str = f"sqlite+aiosqlite:///{_BASE_DIR / 'attacksentry.db'}"
    timescale_enabled: bool = False
    retention_days: int = 30
    retention_cleanup_hours: float = 6.0

    # --- Models ---
    models_dir: str = str(_BASE_DIR / "models")
    data_dir: str = str(_BASE_DIR / "data")
    baseline_hours: float = 72.0
    reservoir_size: int = 5000

    # --- Ingestion / Messaging ---
    # NATS JetStream for sensor -> core streaming. Empty string disables NATS
    # (REST ingestion still available).
    nats_url: str = ""
    nats_subject: str = "sentry.flows"
    nats_stream: str = "SENTRY"
    sensor_api_key: str = ""

    # --- Integrations / automated response ---
    # Generic signed webhook for SIEM/SOAR/ticketing receivers. The secret is
    # environment-only and is never returned by the API.
    webhook_url: str = ""
    webhook_secret: str = ""
    webhook_timeout: float = 10.0
    webhook_min_severity: str = "high"
    # disabled | approval | automatic. Automatic actions are still bounded by
    # severity/score, an allow-list of actions, and an expiry time.
    response_mode: str = "disabled"
    response_min_severity: str = "critical"
    response_min_confidence: float = 0.90
    response_action: str = "dynamic"
    response_ttl_minutes: int = 60
    response_auto_resolve: bool = False

    # --- LLM ---
    llm_provider: str = "openai"  # openai | anthropic | none
    llm_base_url: str = "http://127.0.0.1:1234"
    llm_api_key: str = "not-needed"
    llm_model: str = "default"
    llm_timeout: float = 60.0
    llm_max_tokens: int = 4096
    llm_temperature: float = 0.3
    llm_include_sensitive_context: bool = False
    # Triage is batched per incident and serialized to protect local/cloud
    # providers from alert storms. A burst of detections becomes one dossier.
    llm_batch_window_seconds: float = 3.0
    llm_batch_max_evidence: int = 12
    llm_max_concurrency: int = 2
    llm_min_interval_seconds: float = 1.0
    llm_max_retries: int = 3
    llm_queue_capacity: int = 500

    # --- Detection tuning ---
    incident_window_seconds: int = 300
    suppression_window_seconds: int = 600
    entity_score_decay_hours: float = 24.0
    default_alert_threshold: float = 0.7
    # Minimum calibrated MoE score to raise an incident (anomalies below this
    # are treated as benign variation unless the deviation is extreme).
    min_attack_confidence: float = 0.5
    # Combined anomaly score above which an incident is raised even if the MoE
    # is unsure (catches novel/zero-day deviations).
    strong_anomaly_threshold: float = 50.0
    # A strong anomaly below this MoE score is labelled zero-day instead of
    # being force-fitted to a known expert.
    zero_day_max_confidence: float = 0.10

    # --- Observability ---
    metrics_enabled: bool = True
    log_level: str = "INFO"
    log_format: str = "json"  # json | console

    @model_validator(mode="after")
    def validate_security_defaults(self) -> "Settings":
        """Refuse unsafe defaults when the service is explicitly production."""
        if self.is_production:
            if self.secret_key == "dev-only-change-me" or len(self.secret_key) < 32:
                raise ValueError(
                    "SENTRY_SECRET_KEY must be a unique value of at least 32 characters in production"
                )
            if len(self.bootstrap_admin_password) < 12:
                raise ValueError(
                    "SENTRY_BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters in production"
                )
            if self.database_url.startswith("sqlite"):
                raise ValueError("SENTRY_DATABASE_URL must use PostgreSQL in production")
            if self.webhook_url and not self.webhook_url.startswith("https://"):
                raise ValueError("SENTRY_WEBHOOK_URL must use HTTPS in production")
        if self.webhook_url and len(self.webhook_secret) < 16:
            raise ValueError("SENTRY_WEBHOOK_SECRET must be at least 16 characters when a webhook is configured")
        if self.response_mode not in {"disabled", "approval", "automatic"}:
            raise ValueError("SENTRY_RESPONSE_MODE must be disabled, approval, or automatic")
        if self.response_action not in {"dynamic", "isolate_host", "block_ip", "rate_limit"}:
            raise ValueError("SENTRY_RESPONSE_ACTION is not supported")
        if self.webhook_min_severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("SENTRY_WEBHOOK_MIN_SEVERITY is invalid")
        if self.response_min_severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("SENTRY_RESPONSE_MIN_SEVERITY is invalid")
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def resolve_model_dir(self) -> Path:
        p = Path(self.models_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    def resolve_data_dir(self) -> Path:
        p = Path(self.data_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
