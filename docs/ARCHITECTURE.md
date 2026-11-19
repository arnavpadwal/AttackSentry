# Architecture

AttackSentry is a three-tier, local-first NDR platform. Flow metadata moves from a
Rust sensor to a Python detection core, then to a React operations console.

```
Sensor (Rust)                 Core (Python / FastAPI)                  Console (React)
┌──────────────────┐          ┌──────────────────────────────────┐     ┌─────────────────┐
│ libpcap capture   │  NATS    │ ingestion queue (backpressure)   │HTTP │ Overview         │
│ bidirectional     │ ───────▶ │ canonical feature extractor      │ /WS │ Incident queue   │
│ flow table        │  or REST │ hierarchical autoencoder         │ ──▶ │ Incident detail  │
│ statistics        │          │ MoE attribution + calibration    │     │ Assets / Network │
│ identity/subnet   │          │ incident fidelity + grouping     │     │ Response center  │
└──────────────────┘          │ batched AI triage + playbooks    │     │ Settings / IAM   │
                              │ PostgreSQL+Timescale / SQLite    │     └─────────────────┘
                              └──────────────────────────────────┘
```

## 1. Components

| Tier | Component | Responsibility |
|---|---|---|
| 1 | `sentry_sensor` (Rust) | Packet capture, bidirectional flow state, 28 base features, subnet/identity context, JSON export over NATS, optional GUI and kill switch |
| 2 | `Sentry` (Python) | Ingestion, feature engineering, baselining, anomaly scoring, MoE attribution, incident correlation, response policy, AI triage, API/WebSocket, persistence |
| 3 | `UI/frontend` (React) | Operator console: posture, incident queue, evidence, response, assets, network analytics, reports, IAM, settings |

## 2. Canonical feature schema

`Sentry/sentry/core/schema.py` is the single source of truth shared by the sensor,
runtime, and training pipeline.

* **28 base features** — flow identity, volume, directional packet-length statistics,
  inter-arrival-time statistics, throughput, and TCP flags.
* **14 derived ratio features** — byte/packet/flag/IAT ratios, computed by
  `core/features.py` identically at training and inference time.
* **42-feature canonical vector** — the input to the autoencoder and every expert.

Missing or aliased fields are normalised by `records_to_frame`; the core never
expects a specific exporter dialect.

## 3. Detection lifecycle

1. **Monitoring** — per-entity Welford statistics and reservoir samples are stored in
   `data/<env>/baseline.db` at global, group/subnet, and host granularity.
2. **Training** — when the learning window expires (default 72 h), three autoencoders
   (bottleneck 8/6/4) are trained on the collected normal traffic. Each level keeps
   its own validation threshold (99th percentile); the model is written to
   `data/<env>/sentry_model.pt`.
3. **Active** — every flow is scored as `α·global + β·group + γ·host`; scores at or
   above 1.0 are anomalous. A confidence gate requires MoE confirmation, except for
   extreme deviations. If the strong anomaly's calibrated MoE score is below
   `SENTRY_ZERO_DAY_MAX_CONFIDENCE` (default 0.10), the detection is labelled
   `Zero-Day / Unknown Anomaly` and grouped as `Behavioral Anomaly` instead of being
   force-fitted to a known expert.
4. **Attribution** — the MoE bundle contains five LightGBM experts (Varuna, Rudra,
   Maya, Indra, Garuda), a LightGBM gating network, and isotonic calibration. The
   bundle manifest records schema version, features, threshold, and metrics.
5. **Fidelity** — raw anomalies are not alerts. The fidelity engine merges repeated
   detections by `(correlation scope, canonical family)`, suppresses re-arrivals,
   escalates severity on recurrence, and maintains a decaying entity risk score.
6. **AI triage** — new incidents enter a bounded queue. A debounce window folds
   related detections into one evidence dossier; workers are concurrency-limited and
   serialized by a minimum interval. Rate-limit responses are retried with backoff.
   A deterministic fallback is persisted when the provider is unavailable.

## 4. Attack grouping

Detection labels remain specific (`DDoS (DNS Reflection)`, `SSH-Bruteforce`), while
incident correlation uses a stable family (`DDoS`, `Credential Attack`,
`Reconnaissance`, `Command and Control`, `Exfiltration`, `Web Exploitation`,
`Exploitation`, `Behavioral Anomaly`).

* DDoS incidents are scoped to the **victim host**; port and protocol are evidence.
* Brute-force incidents are scoped to the targeted **service**.
* Scans are scoped to the **scanner/source**.
* Other families are scoped to the source entity.

This keeps a high-rate campaign as one case with many evidence records instead of
hundreds of duplicate incidents.

## 4.4 Framework mapping

Every detection response includes a computed `frameworks` map derived from its
canonical family: a NIST CSF 2.0 function and practice, an ISO/IEC 27001:2022 Annex A
control, and an OWASP Top 10 category where one applies. MITRE ATT&CK tactic and
technique remain on the detection. The mapping is intentionally small and stable so
operators can carry the same evidence into security review, audit, and reporting.

## 5. Data model

PostgreSQL + TimescaleDB is recommended for production; SQLite is the zero-setup
development fallback. Core tables:

`users`, `api_keys`, `sensors`, `hosts`, `devices`, `flow_logs`, `incidents`,
`detections`, `playbooks`, `mitigation_actions`, `suppression_rules`,
`system_config`, `audit_log`.

Alembic migrations live in `Sentry/alembic/`. Timescale hypertables are created for
`flow_logs`, `detections`, and `audit_log`; retention is enforced by Timescale
policies. SQLite deployments use a periodic retention task in the ingestion pipeline.

## 6. Model bundle

Offline training exports a self-contained directory:

```
Sentry/models/bundle_<version>/
├── model_card.json      # schema, features, metrics, threshold, provenance
├── experts/             # 5 LightGBM experts
├── gating/              # 5 LightGBM gating models
├── scaler.pkl
└── calibrator.pkl
```

`MoEPipeline` loads the newest bundle atomically. `bundle_latest` is a convenience
symlink. Retraining is optional and is not required to run the platform; the shipped
bundle is already calibrated.

## 7. Runtime topology

* **Single process** — the FastAPI app owns the engine, ingestion pipeline, WebSocket
  bus, and background tasks. Baselines are stateful, so run one backend replica
  unless state is externalised.
* **NATS JetStream** — optional transport between sensors and core. REST ingestion
  (`POST /api/ingest/flow`) is supported for constrained environments.
* **LLM** — any OpenAI-compatible endpoint, native LM Studio, or Ollama. Local-first
  is the default; external providers receive pseudonymised entities unless
  `SENTRY_LLM_INCLUDE_SENSITIVE_CONTEXT=true`.
* **Console** — the built SPA is served by nginx, which proxies `/api` and `/ws` to
  the backend. In development, Vite proxies the same paths.

## 7.1 Grounded triage

`sentry/knowledge/` ships an offline corpus (MITRE ATT&CK, OWASP Top 10, NIST
SP 800-61r2 / 800-53 / CSF 2.0, ISO/IEC 27001:2022, and AttackSentry runbooks).
A dependency-free BM25 index retrieves five passages per incident. The prompt
carries those passages, and the response is grounded before persistence:

* a technique ID the model invents is dropped and replaced from the retrieved or
  deterministic mapping;
* playbook steps are normalised to the allowed actions and priorities; analysis
  and escalation steps are never auto-executable, and neither is a step with no
  exact target;
* the retrieved citations are stored on the playbook and rendered under
  **References** in the console.

Rebuild the corpus with `scripts/build_knowledge_base.py --refresh`.

## 7.2 Autonomous response

With `SENTRY_RESPONSE_MODE=automatic`, a qualifying detection creates a
`MitigationAction` (`mode=automatic`) and dispatches it. The policy is bounded:
severity and confidence thresholds, a per-entity/action dedupe, a rolling
10-minute budget, an allow-list of actions, and a TTL that the reconciler
releases automatically. Every action records its `provider_message`, so a
simulated control is never presented as an enforced packet filter.

Dispatch prefers the signed webhook adapter. When no webhook is configured it
falls back to the local adapter: `simulate` records the control only, while
`nftables` installs a time-bounded element in an `inet attacksentry` set and
requires root. Rate limiting is refused by the local adapter because a host
firewall cannot mitigate an inbound flood; that action needs upstream scrubbing.

## 8. Degraded modes

| Condition | Behaviour |
|---|---|
| MoE bundle missing/incomplete | Backend starts; attribution is skipped and only strong AE deviations can create incidents |
| LLM unreachable | Deterministic incident playbook is persisted and labelled as fallback |
| NATS unavailable | REST ingestion continues; NATS consumer reconnects with backoff |
| Timescale unavailable | SQLite can be used for a single-node deployment |
| Backend restart | In-memory correlation state resets; persisted incidents and evidence remain |

## 9. Training pipeline

`Training/` contains the offline pipeline (`1_merge` → `8_build_bundle`). It expects
the cleaned parquet datasets described in `Training/README.md`. Training artifacts
and datasets are intentionally excluded from the repository because of their size.
