"""Prometheus metrics for the AttackSentry core and API."""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

FLOWS_INGESTED = Counter(
    "sentry_flows_ingested_total",
    "Total flow records ingested",
    ["source"],
)
FLOWS_PROCESSED = Counter(
    "sentry_flows_processed_total",
    "Total flow records processed by the engine",
)
ANOMALIES_DETECTED = Counter(
    "sentry_anomalies_detected_total",
    "Total anomalies flagged by the autoencoder layer",
    ["expert"],
)
INCIDENTS_CREATED = Counter(
    "sentry_incidents_created_total",
    "Total correlated incidents created",
    ["severity"],
)
INCIDENTS_MERGED = Counter(
    "sentry_incidents_merged_total",
    "Duplicate detections merged into existing incidents",
)
LLM_TRIAGES = Counter(
    "sentry_llm_triages_total",
    "LLM triage requests",
    ["outcome"],  # success | fallback | error
)
INFERENCE_LATENCY = Histogram(
    "sentry_inference_latency_seconds",
    "End-to-end flow inference latency",
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)
INGEST_QUEUE_DEPTH = Gauge("sentry_ingest_queue_depth", "Pending ingest queue depth")
LLM_QUEUE_DEPTH = Gauge("sentry_llm_queue_depth", "Incidents waiting for AI triage")
LLM_BATCH_SIZE = Histogram(
    "sentry_llm_batch_size",
    "Detections bundled into one AI triage request",
    buckets=(1, 2, 5, 10, 25, 50, 100, 250, 500),
)
LLM_RATE_LIMITED = Counter(
    "sentry_llm_rate_limited_total",
    "AI provider rate-limit responses that forced a retry",
)
LLM_TRIAGE_LATENCY = Histogram(
    "sentry_llm_triage_latency_seconds",
    "Time from triage enqueue to persisted playbook",
    buckets=(0.5, 1, 2, 5, 10, 20, 30, 60, 120, 300),
)
ENGINE_MODE = Gauge(
    "sentry_engine_mode",
    "Current engine mode: 0=monitoring, 1=training, 2=active",
)
ACTIVE_ENTITIES = Gauge("sentry_active_entities", "Number of tracked entities")
