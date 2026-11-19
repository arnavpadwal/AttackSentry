# AttackSentry — Security & Compliance

## 1. Authentication & authorization

* **Users** authenticate with username/password; passwords hashed with bcrypt. Access/refresh JWTs are issued as **httpOnly, SameSite=Lax cookies** (never stored in `localStorage`).
* **Roles**: `admin` (full control, identity/sensor/policy management), `analyst` (triage, containment requests, reports), `viewer` (read-only).
* **IAM guardrails**: the last active administrator cannot be demoted, deactivated, or deleted; users cannot deactivate or delete their own account; email and username uniqueness are enforced.
* **Sensors** authenticate with a hashed API key (`X-Sentry-Key-ID` + `X-Sentry-Secret` headers over TLS). Secrets are stored as SHA-256 hashes; raw secrets are returned exactly once at provisioning.
* **No hardcoded credentials.** Bootstrap admin is created on first run with a random password unless `SENTRY_BOOTSTRAP_ADMIN_PASSWORD` is set.

## 2. Secrets management

All secrets are supplied via environment variables / Docker secrets / Kubernetes Secrets:
`SENTRY_SECRET_KEY`, `SENTRY_DATABASE_URL`, `SENTRY_LLM_API_KEY`, `SENTRY_BOOTSTRAP_ADMIN_PASSWORD`, and (when enabled) `SENTRY_WEBHOOK_SECRET`.

Never commit `.env` files. The repository ships only `.env.example`.

## 3. Encryption in transit

* Sensor → core: NATS (with TLS in production) or HTTPS REST ingestion.
* Console → API: HTTPS (nginx ingress / reverse proxy); WebSocket upgrade over TLS.
* Local LLM traffic should stay on a private network or use TLS.

## 4. Privacy by design (metadata-only)

* AttackSentry inspects **L3/L4 metadata only** — no application-layer payload is captured or stored.
* IPs, hostnames, identities, and raw flow context are pseudonymised/redacted before LLM triage by default (`SENTRY_LLM_INCLUDE_SENSITIVE_CONTEXT=false`).
* AE and MoE inference runs on-premise. LLM inference is local only when a local provider is configured; review external-provider data handling before enabling it.

## 5. Data retention & GDPR

* Default flow retention is 30 days (`SENTRY_RETENTION_DAYS`). TimescaleDB enforces it with chunk-drop policies; SQLite runs a periodic `flow_logs` prune.
* Incidents, detections, playbooks, and audit records are retained as investigation evidence. Use the approved database retention/erasure process; do not delete evidence ad hoc during an investigation.

## 6. Audit logging

All administrative actions (user/sensor/suppression changes) are recorded in `audit_log` (actor, action, resource, detail) and queryable for compliance review.

Mitigation requests have a separate lifecycle record with requester, approver, target, reason, expiry, provider outcome, and release outcome. Generic webhook events are HMAC-SHA256 signed and do not execute local firewall commands on the backend.

AI triage is queued and rate-limited. A single evidence dossier is produced per incident; provider 429/5xx responses are retried with backoff. Playbooks produced without the provider are marked as fallback and can be regenerated.

## 7. Recommended hardening

* Set a strong `SENTRY_SECRET_KEY` (≥ 32 bytes) and rotate regularly.
* Front the API with a WAF/rate limiter; enable TLS everywhere.
* Set `SENTRY_COOKIE_SECURE=true` whenever the console is served over HTTPS (the production default). Local HTTP development may set it to `false`.
* Run the sensor with the minimum capability set (`CAP_NET_RAW`) — never enable the kill switch unless an isolated-response policy is explicitly required.
* Keep response mode `disabled` until the enforcement adapter has been tested in a non-production scope. `approval` is the recommended first operating mode; `automatic` requires a signed adapter and a tested release path.
* Enable TimescaleDB backups + PITR.
