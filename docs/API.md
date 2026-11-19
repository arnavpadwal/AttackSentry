# API reference

Base URL: `http://<host>:8000`. Interactive schema: `/api/docs`.

Authentication is cookie-based JWT for users and header-based sensor keys for
ingestion. All non-ingestion endpoints require an authenticated session unless noted.

## Auth

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/login` | Login; sets `access_token` and `refresh_token` httpOnly cookies |
| POST | `/api/auth/refresh` | Rotate the session |
| GET | `/api/auth/me` | Current identity and role |
| POST | `/api/auth/logout` | Clear cookies |
| POST | `/api/auth/change-password` | Rotate the current password |

## Incidents

| Method | Path | Description |
|---|---|---|
| GET | `/api/incidents` | List incidents. Filters: `status`, `severity`, `family`, `q`, `sort=recent\|severity`, `limit`, `offset` |
| GET | `/api/incidents/summary` | Open counts by severity and family, plus status totals |
| GET | `/api/incidents/{id}` | Incident detail |
| GET | `/api/incidents/{id}/alerts` | Correlated evidence |
| GET | `/api/incidents/{id}/playbook` | Latest AI/fallback assessment |
| POST | `/api/incidents/{id}/playbook/generate` | Generate or replace a fallback assessment |
| PATCH | `/api/incidents/{id}/status` | Acknowledge, resolve, reopen |
| PATCH | `/api/incidents/bulk/status` | Bulk acknowledge/resolve (max 100) |

## Detections (alerts)

| Method | Path | Description |
|---|---|---|
| GET | `/api/alerts` | Paginated detections (`severity`, `status`, `expert`, `entity`, `range`, `page`, `page_size`) |
| GET | `/api/alerts/export?format=csv` | CSV export |
| GET | `/api/alerts/{id}` | Detection detail |
| PATCH | `/api/alerts/{id}/status` | Update status/assignee |
| GET | `/api/alerts/{id}/playbook` | Playbook for the detection |

Alert objects also carry a computed `frameworks` map: NIST CSF 2.0 function and
practice, ISO/IEC 27001:2022 Annex A control, and OWASP Top 10 category where
applicable. MITRE ATT&CK remains in `mitre_tactic` / `mitre_technique`.

## Assets and network

| Method | Path | Description |
|---|---|---|
| GET | `/api/hosts` | Observed entities (`group`, `risk_min`) |
| GET | `/api/hosts/{id}` | Entity detail |
| GET | `/api/hosts/{id}/traffic` | Traffic time series |
| GET | `/api/hosts/{id}/anomaly-history` | Anomaly history |
| GET | `/api/hosts/{id}/alerts` | Entity detections |
| PATCH | `/api/hosts/{id}` | Update identity/group/tags |
| GET | `/api/network/graph` | Flow graph |
| GET | `/api/mitre/coverage` | ATT&CK tactic coverage |

## Detection engine and MoE

| Method | Path | Description |
|---|---|---|
| GET | `/api/sentry/status` | Mode, baseline progress, uptime, bundle version, LLM health |
| POST | `/api/sentry/reset?learn_time=24` | Clear the environment baseline/model and return to monitoring (admin; incidents/evidence retained) |
| POST | `/api/sentry/train` | Trigger training (admin) |
| POST | `/api/sentry/retrain` | Retrigger training (admin) |
| GET | `/api/sentry/baseline-progress` | Learning progress |
| GET | `/api/moe/routing-stats` | Expert routing share (24 h) |
| GET | `/api/moe/expert-performance` | Per-expert metrics from the bundle |
| GET | `/api/moe/recent-classifications` | Recent attributions |

## Response and operations

| Method | Path | Description |
|---|---|---|
| GET | `/api/mitigations` | Auditable containment actions |
| POST | `/api/mitigations` | Request a manual action |
| POST | `/api/mitigations/{id}/approve` | Approve and dispatch (admin) |
| POST | `/api/mitigations/{id}/release` | Release a time-bounded control (admin) |
| POST | `/api/mitigations/{id}/cancel` | Cancel a pending request |
| GET | `/api/diagnostics` | Service, queue, DB, model, AI triage, and integration health (admin) |
| GET | `/api/audit` | Audit trail (admin) |

## Identity and access

| Method | Path | Description |
|---|---|---|
| GET | `/api/users` | List identities (admin) |
| POST | `/api/users` | Create identity (admin) |
| PATCH | `/api/users/{id}` | Update role, status, email, or password (admin) |
| DELETE | `/api/users/{id}` | Delete identity; last active admin is protected (admin) |
| GET | `/api/sensors` | List sensors |
| POST | `/api/sensors` | Register a sensor (admin) |
| POST | `/api/sensors/{id}/api-key` | Issue a sensor key (admin, returned once) |
| GET | `/api/sensors/{id}/config?platform=linux\|windows` | Non-secret environment template |
| POST | `/api/sensors/{id}/heartbeat` | Sensor-authenticated heartbeat |
| GET/POST | `/api/suppressions` | List/create suppression rules |
| PATCH/DELETE | `/api/suppressions/{id}` | Update/delete rule |

## Ingestion

| Method | Path | Description |
|---|---|---|
| POST | `/api/ingest/flow` | Ingest one flow or a batch (max 1000, 2 MiB) with `X-Sentry-Key-ID` and `X-Sentry-Secret` |
| POST | `/api/ingest/cloud` | Authenticated cloud telemetry envelope |

## Settings and reports

| Method | Path | Description |
|---|---|---|
| GET | `/api/settings` | Runtime settings |
| PATCH | `/api/settings` | Update settings (admin) |
| POST | `/api/settings/test-llm` | Test provider connectivity |
| POST | `/api/settings/test-webhook` | Send a signed test event (admin) |
| GET | `/api/traffic/summary?range=24h` | Traffic and posture summary |
| GET | `/api/traffic/recent?limit=200` | Recent flows for chart seeding |
| GET | `/api/reports/investor` | Executive report |
| GET | `/api/reports/research` | Detection research report |

## Observability

| Method | Path | Description |
|---|---|---|
| GET | `/healthz` | Liveness |
| GET | `/readyz` | Readiness |
| GET | `/metrics` | Prometheus metrics, including ingest/AI-queue depth |

## WebSockets

All feeds are authenticated by the `access_token` cookie and close with `4401` when
the session is invalid.

| Path | Payload |
|---|---|
| `/ws/telemetry` | Live flow records |
| `/ws/traffic` | Aggregated bytes/packets per second |
| `/ws/alerts` | Persisted detection objects |
| `/ws/incidents` | Incident create/merge events |

## AI triage behaviour

Incidents are queued, not generated per detection. A new incident opens one dossier;
detections inside the debounce window are folded into its evidence. Calls are
bounded by concurrency and a minimum interval, and rate-limit responses are retried.
The persisted playbook is labelled `is_fallback` when deterministic guidance was
used, and can be regenerated from the incident endpoint.
