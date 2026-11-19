"""SQLAlchemy ORM models for AttackSentry."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    username: Mapped[str] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String)
    full_name: Mapped[str | None] = mapped_column(String, nullable=True)
    role: Mapped[str] = mapped_column(String, default="analyst")  # admin|analyst|viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String)
    key_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    secret_hash: Mapped[str] = mapped_column(String)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    owner_type: Mapped[str] = mapped_column(String, default="sensor")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Sensor(Base):
    __tablename__ = "sensors"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String)
    sensor_type: Mapped[str] = mapped_column(String, default="virtual")
    hostname: Mapped[str | None] = mapped_column(String, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, default="pending")
    version: Mapped[str | None] = mapped_column(String, nullable=True)
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    flows_per_second: Mapped[float] = mapped_column(Float, default=0)
    total_flows: Mapped[int] = mapped_column(Integer, default=0)
    network_segments: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    ip_address: Mapped[str] = mapped_column(String, unique=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String, nullable=True)
    group_name: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    status: Mapped[str] = mapped_column(String, default="active")
    identity: Mapped[str | None] = mapped_column(String, nullable=True)
    device_type: Mapped[str | None] = mapped_column(String, nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    baseline_status: Mapped[str] = mapped_column(String, default="monitoring")
    os_info: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class FlowLog(Base):
    __tablename__ = "flow_logs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, primary_key=True, index=True)
    src_ip: Mapped[str] = mapped_column(String, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    src_port: Mapped[int] = mapped_column(Integer, default=0)
    dst_port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[int] = mapped_column(Integer, default=0)
    bytes_sent: Mapped[int] = mapped_column(Integer, default=0)
    bytes_received: Mapped[int] = mapped_column(Integer, default=0)
    packets_sent: Mapped[int] = mapped_column(Integer, default=0)
    packets_received: Mapped[int] = mapped_column(Integer, default=0)
    duration: Mapped[float] = mapped_column(Float, default=0)
    sensor_id: Mapped[str | None] = mapped_column(String, nullable=True)
    identity: Mapped[str | None] = mapped_column(String, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String, nullable=True)
    subnet: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    entity: Mapped[str] = mapped_column(String, index=True)
    family: Mapped[str] = mapped_column(String)
    count: Mapped[int] = mapped_column(Integer, default=1)
    peak_signal: Mapped[float] = mapped_column(Float, default=0)
    severity: Mapped[str] = mapped_column(String, index=True)
    status: Mapped[str] = mapped_column(String, default="open")  # open|acknowledged|resolved
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    incident_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, primary_key=True, index=True)
    env_id: Mapped[str | None] = mapped_column(String, nullable=True)
    severity: Mapped[str] = mapped_column(String, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0)
    entity_risk: Mapped[float] = mapped_column(Float, default=0)
    detection_type: Mapped[str] = mapped_column(String, index=True)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0)
    global_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    group_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    host_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String, default="new", index=True)
    assigned_to: Mapped[str | None] = mapped_column(String, nullable=True)

    src_ip: Mapped[str] = mapped_column(String, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[int | None] = mapped_column(Integer, nullable=True)
    group_name: Mapped[str | None] = mapped_column(String, nullable=True)
    identity: Mapped[str | None] = mapped_column(String, nullable=True)
    device_type: Mapped[str | None] = mapped_column(String, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String, nullable=True)
    process_id: Mapped[str | None] = mapped_column(String, nullable=True)
    subnet: Mapped[str | None] = mapped_column(String, nullable=True)

    primary_expert: Mapped[str | None] = mapped_column(String, nullable=True)
    expert_distribution: Mapped[dict] = mapped_column(JSON, default=dict)
    expert_probs: Mapped[dict] = mapped_column(JSON, default=dict)
    moe_score: Mapped[float] = mapped_column(Float, default=0)

    raw_flow: Mapped[dict] = mapped_column(JSON, default=dict)
    mitre_tactic: Mapped[str | None] = mapped_column(String, nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String, nullable=True)
    mitre_description: Mapped[str | None] = mapped_column(String, nullable=True)


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    detection_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    incident_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    attack_summary: Mapped[str] = mapped_column(Text)
    technical_analysis: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String)
    confidence: Mapped[str] = mapped_column(String, default="medium")
    mitre_attack: Mapped[dict] = mapped_column(JSON, default=dict)
    steps: Mapped[list] = mapped_column(JSON, default=list)
    sources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    false_positive_assessment: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_fallback: Mapped[bool] = mapped_column(Boolean, default=False)


class MitigationAction(Base):
    """Auditable response request dispatched to an external enforcement adapter."""

    __tablename__ = "mitigation_actions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(String, index=True)
    entity: Mapped[str] = mapped_column(String, index=True)
    action: Mapped[str] = mapped_column(String)
    mode: Mapped[str] = mapped_column(String)  # manual|approval|automatic
    status: Mapped[str] = mapped_column(String, default="pending", index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    requested_by: Mapped[str | None] = mapped_column(String, nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    provider_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    hostname: Mapped[str] = mapped_column(String)
    ip: Mapped[str] = mapped_column(String, index=True)
    mac: Mapped[str | None] = mapped_column(String, nullable=True)
    os: Mapped[str | None] = mapped_column(String, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, default="pending")  # pending|approved|rejected
    whitelist: Mapped[list] = mapped_column(JSON, default=list)
    blacklist: Mapped[list] = mapped_column(JSON, default=list)
    timeout_hours: Mapped[float | None] = mapped_column(Float, nullable=True)
    first_seen: Mapped[float] = mapped_column(Float, default=0)
    approved_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    parent_device_id: Mapped[str | None] = mapped_column(String, nullable=True)
    custom_tag: Mapped[str | None] = mapped_column(String, nullable=True)
    approval_caveat: Mapped[str | None] = mapped_column(String, nullable=True)


class SuppressionRule(Base):
    __tablename__ = "suppression_rules"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String)
    entity: Mapped[str | None] = mapped_column(String, nullable=True)
    subnet: Mapped[str | None] = mapped_column(String, nullable=True)
    attack_family: Mapped[str | None] = mapped_column(String, nullable=True)
    reason: Mapped[str] = mapped_column(String, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class SystemConfig(Base):
    __tablename__ = "system_config"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, primary_key=True, index=True)
    user_id: Mapped[str | None] = mapped_column(String, nullable=True)
    action: Mapped[str] = mapped_column(String)
    resource: Mapped[str | None] = mapped_column(String, nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
