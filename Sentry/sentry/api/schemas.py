"""Pydantic schemas for the AttackSentry API."""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

from ..core.frameworks import framework_map


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- Auth ---
class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class UserOut(ORMModel):
    id: str
    email: str
    username: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    user: UserOut


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)


class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=1024)
    full_name: Optional[str] = None
    role: Literal["admin", "analyst", "viewer"] = "analyst"


class UserUpdate(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[Literal["admin", "analyst", "viewer"]] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=12, max_length=1024)


# --- Detections / Alerts ---
class AlertOut(ORMModel):
    id: str
    incident_id: Optional[str] = None
    timestamp: datetime
    severity: str
    confidence: float
    entity_risk: float
    detection_type: str
    anomaly_score: float
    reason: Optional[str] = None
    status: str
    assigned_to: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    group_name: Optional[str] = None
    identity: Optional[str] = None
    device_type: Optional[str] = None
    process_name: Optional[str] = None
    subnet: Optional[str] = None
    primary_expert: Optional[str] = None
    expert_distribution: dict = Field(default_factory=dict)
    expert_probs: dict = Field(default_factory=dict)
    moe_score: float = 0.0
    raw_flow: dict = Field(default_factory=dict)
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_description: Optional[str] = None

    @computed_field
    @property
    def frameworks(self) -> dict:
        return framework_map(self.detection_type, self.primary_expert)


class AlertStatusUpdate(BaseModel):
    status: Literal["new", "acknowledged", "resolved", "false_positive"]
    assigned_to: Optional[str] = None


class PaginatedAlerts(BaseModel):
    items: list[AlertOut]
    total: int
    page: int
    page_size: int
    total_pages: int


class IncidentOut(ORMModel):
    id: str
    created_at: datetime
    last_seen: datetime
    entity: str
    family: str
    count: int
    peak_signal: float
    severity: str
    status: str
    resolved_at: Optional[datetime] = None


class BulkIncidentUpdate(BaseModel):
    incident_ids: list[str] = Field(min_length=1, max_length=100)
    status: Literal["open", "acknowledged", "resolved"]


class IncidentStatusUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]


# --- Playbooks ---
class PlaybookOut(ORMModel):
    id: str
    detection_id: Optional[str] = None
    incident_id: Optional[str] = None
    created_at: datetime
    attack_summary: str
    technical_analysis: Optional[str] = None
    severity: str
    confidence: str
    mitre_attack: dict = Field(default_factory=dict)
    steps: list[dict] = Field(default_factory=list)
    false_positive_assessment: Optional[str] = None
    is_fallback: bool = False


# --- Hosts / Entities ---
class HostOut(ORMModel):
    id: str
    ip_address: str
    hostname: Optional[str] = None
    group_name: Optional[str] = None
    risk_score: float
    status: str
    identity: Optional[str] = None
    device_type: Optional[str] = None
    tags: list = Field(default_factory=list)
    last_seen: Optional[datetime] = None
    baseline_status: str
    os_info: Optional[str] = None
    created_at: Optional[datetime] = None


class HostDetail(HostOut):
    alert_count: int = 0
    incident_count: int = 0
    total_bytes_24h: int = 0
    top_protocols: list[dict] = Field(default_factory=list)


class TimeSeries(BaseModel):
    timestamps: list[float]
    values: list[float]


# --- Devices ---
class DeviceOut(BaseModel):
    id: str
    hostname: str
    ip: str
    mac: str
    os: str
    fingerprint: str
    status: str
    whitelist: list[str] = Field(default_factory=list)
    blacklist: list[str] = Field(default_factory=list)
    timeout_hours: Optional[float] = None
    first_seen: float
    approved_at: Optional[float] = None
    parent_device_id: Optional[str] = None
    custom_tag: Optional[str] = None
    approval_caveat: Optional[str] = None


class DeviceApprove(BaseModel):
    timeout_hours: Optional[float] = None
    caveat: Optional[str] = None


class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    os: Optional[str] = None
    custom_tag: Optional[str] = None


# --- Sentry status ---
class SentryStatusOut(BaseModel):
    mode: str
    baseline_progress_pct: float
    uptime_seconds: int
    active_hosts: int
    flows_processed: int
    model_versions: dict = Field(default_factory=dict)
    moe_bundle_version: str = "none"
    active_incidents: int = 0
    llm_healthy: bool = False


# --- MoE ---
class MoeRoutingStat(BaseModel):
    expert: str
    share: float
    count: int


class MoeExpertPerformance(BaseModel):
    expert: str
    f1: float
    roc_auc: float
    precision: float
    recall: float


class MoeClassification(BaseModel):
    id: str
    timestamp: datetime
    detection_type: str
    primary_expert: Optional[str] = None
    moe_score: float
    expert_distribution: dict = Field(default_factory=dict)
    severity: str


# --- Traffic / overview ---
class TrafficSummary(BaseModel):
    bytes_per_sec: float
    packets_per_sec: float
    active_flows: int
    total_flows_24h: int
    total_alerts_24h: int
    critical_24h: int
    high_24h: int
    medium_24h: int
    low_24h: int
    entities_at_risk: int
    active_sensors: int
    threat_level: int = 0


# --- Settings ---
class SettingsOut(BaseModel):
    llm_provider: str
    llm_base_url: str
    llm_model: str
    baseline_hours: float
    default_alert_threshold: float
    incident_window_seconds: int
    suppression_window_seconds: int
    retention_days: int
    webhook_url: str = ""
    webhook_min_severity: Literal["low", "medium", "high", "critical"] = "high"
    webhook_secret_configured: bool = False
    response_mode: Literal["disabled", "approval", "automatic"] = "disabled"
    response_min_severity: Literal["low", "medium", "high", "critical"] = "critical"
    response_min_confidence: float = 0.9
    response_action: Literal["dynamic", "isolate_host", "block_ip", "rate_limit"] = "dynamic"
    response_ttl_minutes: int = 60
    response_auto_resolve: bool = False


class SettingsUpdate(BaseModel):
    llm_provider: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_model: Optional[str] = None
    llm_api_key: Optional[str] = None
    baseline_hours: Optional[float] = Field(default=None, ge=0.05, le=720)
    default_alert_threshold: Optional[float] = Field(default=None, ge=0, le=1)
    incident_window_seconds: Optional[int] = Field(default=None, ge=30, le=86400)
    suppression_window_seconds: Optional[int] = Field(default=None, ge=30, le=604800)
    retention_days: Optional[int] = Field(default=None, ge=1, le=3650)
    webhook_url: Optional[str] = Field(default=None, max_length=2048)
    webhook_secret: Optional[str] = Field(default=None, min_length=16, max_length=1024)
    webhook_min_severity: Optional[Literal["low", "medium", "high", "critical"]] = None
    response_mode: Optional[Literal["disabled", "approval", "automatic"]] = None
    response_min_severity: Optional[Literal["low", "medium", "high", "critical"]] = None
    response_min_confidence: Optional[float] = Field(default=None, ge=0, le=1)
    response_action: Optional[Literal["dynamic", "isolate_host", "block_ip", "rate_limit"]] = None
    response_ttl_minutes: Optional[int] = Field(default=None, ge=5, le=10080)
    response_auto_resolve: Optional[bool] = None


class LLMTestResult(BaseModel):
    healthy: bool
    message: str


class MitigationOut(ORMModel):
    id: str
    incident_id: str
    entity: str
    action: str
    mode: str
    status: str
    reason: str
    requested_by: Optional[str] = None
    approved_by: Optional[str] = None
    created_at: datetime
    expires_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    provider_message: Optional[str] = None


class MitigationCreate(BaseModel):
    incident_id: str = Field(min_length=1, max_length=128)
    action: Literal["isolate_host", "block_ip", "rate_limit"] = "isolate_host"
    reason: str = Field(min_length=3, max_length=1000)
    ttl_minutes: int = Field(default=60, ge=5, le=10080)


# --- Sensors ---
class SensorOut(ORMModel):
    id: str
    name: str
    sensor_type: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    status: str
    version: Optional[str] = None
    last_heartbeat: Optional[datetime] = None
    flows_per_second: float
    total_flows: int
    network_segments: list = Field(default_factory=list)
    created_at: Optional[datetime] = None


class SensorCreate(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    sensor_type: str = "virtual"
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    network_segments: list[str] = Field(default_factory=list)


# --- Suppression rules ---
class SuppressionRuleOut(ORMModel):
    id: str
    name: str
    entity: Optional[str] = None
    subnet: Optional[str] = None
    attack_family: Optional[str] = None
    reason: str
    is_active: bool
    created_at: Optional[datetime] = None


class SuppressionRuleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    entity: Optional[str] = None
    subnet: Optional[str] = None
    attack_family: Optional[str] = Field(default=None, max_length=128)
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("entity")
    @classmethod
    def valid_entity(cls, value: str | None) -> str | None:
        if value:
            import ipaddress
            return str(ipaddress.ip_address(value))
        return value

    @field_validator("subnet")
    @classmethod
    def valid_subnet(cls, value: str | None) -> str | None:
        if value:
            import ipaddress
            return str(ipaddress.ip_network(value, strict=False))
        return value

    @model_validator(mode="after")
    def at_least_one_scope(self):
        if not any((self.entity, self.subnet, self.attack_family)):
            raise ValueError("At least one entity, subnet, or attack family is required")
        return self


class SuppressionRuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=128)
    entity: Optional[str] = None
    subnet: Optional[str] = None
    attack_family: Optional[str] = Field(default=None, max_length=128)
    reason: Optional[str] = Field(default=None, min_length=3, max_length=500)
    is_active: Optional[bool] = None

    _valid_entity = field_validator("entity")(SuppressionRuleCreate.valid_entity.__func__)
    _valid_subnet = field_validator("subnet")(SuppressionRuleCreate.valid_subnet.__func__)


# --- Reports ---
class ReportResponse(BaseModel):
    title: str
    generated_at: datetime
    sections: list[dict] = Field(default_factory=list)
    metrics: dict = Field(default_factory=dict)


# --- Setup ---
class SetupStatus(BaseModel):
    is_setup_complete: bool
    current_step: int
    steps_completed: list[str] = Field(default_factory=list)


# --- Ingest ---
class IngestResponse(BaseModel):
    status: str
    detection_id: Optional[str] = None
    incident_id: Optional[str] = None
    action: Optional[str] = None
