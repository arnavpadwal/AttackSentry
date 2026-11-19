# Deployment & configuration

## 1. Requirements

| Mode | Requirements |
|---|---|
| Docker Compose | Docker Engine 24+, Compose v2, 4 CPU cores, 8 GB RAM, 50 GB free storage |
| Kubernetes | Helm 3.12+, a default StorageClass, ingress controller for external access |
| Bare metal | Python 3.12+, Node 20+ for the console build, libpcap for the sensor |
| Optional AI triage | LM Studio, Ollama, vLLM, or any OpenAI-compatible endpoint |

Ports: console `8080`, backend `8000`, NATS `4222` (loopback by default).

## 2. Docker Compose (recommended)

```bash
chmod +x attacksentry.sh
./attacksentry.sh start
```

The launcher generates `deploy/docker-compose/.env` on first run with unique
database, NATS, JWT, and administrator credentials, then prints the one-time admin
password. Open <http://localhost:8080> and sign in as `admin`.

```bash
./attacksentry.sh status
./attacksentry.sh logs
./attacksentry.sh doctor
./attacksentry.sh stop
```

The stack includes PostgreSQL/TimescaleDB, an authenticated NATS JetStream bus, the
backend, and the nginx-served console. The backend image includes the shipped model
bundle (`Sentry/models/bundle_latest`), so no separate model mount is required.

## 3. Development

```bash
# backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r Sentry/requirements.txt
cd Sentry && ../.venv/bin/python -m sentry

# console
cd UI/frontend && npm install && npm run dev
```

Or start both with `./start_all.sh`. The Vite console proxies `/api` and `/ws` to
`:8000`, so no cross-origin cookie configuration is needed.

First run bootstraps the administrator from `SENTRY_BOOTSTRAP_ADMIN_PASSWORD`.
Wipe `Sentry/attacksentry.db` to re-bootstrap a development instance.

## 4. Kubernetes (Helm)

```bash
helm install attacksentry deploy/helm/attacksentry \
  --namespace attacksentry --create-namespace \
  --set global.secretKey="$(openssl rand -hex 32)" \
  --set global.bootstrapAdminPassword="$(openssl rand -base64 18)" \
  --set database.password="$(openssl rand -hex 24)" \
  --set nats.password="$(openssl rand -hex 24)"
```

The chart runs one backend replica because baselines are local state. Mount a
persistent volume for `/app/data`. The model bundle ships in the backend image. See
`deploy/helm/attacksentry/values.yaml` for resources, LLM, webhook, and response
policy settings.

## 5. Bare-metal systemd

Templates are in `deploy/systemd/`:

```bash
sudo cp deploy/systemd/attacksentry-backend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now attacksentry-backend
```

Copy `deploy/systemd/sentry.env.example` to `/etc/attacksentry/sentry.env` and set
the secrets. The backend must run with a writable `SENTRY_DATA_DIR`.

## 6. Sensors

### Linux

```bash
sudo apt-get install libpcap0.8
sudo setcap cap_net_raw,cap_net_admin=eip ./attacksentry-sensor
SENTRY_HEADLESS=1 \
SENTRY_NATS_URL=nats://127.0.0.1:4222 \
SENTRY_NATS_USERNAME=attacksentry \
SENTRY_NATS_PASSWORD='<generated>' \
SENTRY_DEVICE=eth0 \
./attacksentry-sensor
```

### Windows

Install Npcap (review its redistribution terms), run as Administrator, and set the
same environment variables. The release workflow produces `AttackSentry-Sensor.exe`.

Register sensors in **Settings → Sensors** and download the non-secret environment
template. The secret is issued once and is never stored in plaintext.

Verify connectivity before starting capture:

```bash
SENTRY_TEST_CONNECTION=1 \
SENTRY_NATS_URL=nats://127.0.0.1:4222 \
SENTRY_NATS_USERNAME=attacksentry \
SENTRY_NATS_PASSWORD='<generated>' \
./attacksentry-sensor
```

The command prints `CONNECTED` and exits 0, or prints `FAILED: ...` and exits 2.
The GUI's **Connect to Sentry Service** button uses the same 6-second check, so an
unreachable host reports an error instead of hanging. The login screen shows the
configured service endpoint and prefills the NATS username.

In development, `start_all.sh` automatically connects the core to a local NATS bus
when `deploy/docker-compose/.env` contains the credentials. Set `SENTRY_NATS_URL`
explicitly if the bus runs elsewhere.

## 7. Configuration reference

All backend settings use the `SENTRY_` prefix and can be supplied by environment or
`Sentry/.env`.

| Variable | Default | Purpose |
|---|---|---|
| `SENTRY_SECRET_KEY` | dev placeholder | JWT/cookie signing key; required ≥32 chars in production |
| `SENTRY_BOOTSTRAP_ADMIN_PASSWORD` | generated | First-run admin password; required ≥12 chars in production |
| `SENTRY_DATABASE_URL` | SQLite | `postgresql+psycopg://...` in production |
| `SENTRY_TIMESCALE_ENABLED` | `false` | Create hypertables and retention policies |
| `SENTRY_NATS_URL` | empty | NATS endpoint; empty enables REST-only ingestion |
| `SENTRY_NATS_SUBJECT` / `_STREAM` | `sentry.flows` / `SENTRY` | Flow transport names |
| `SENTRY_BASELINE_HOURS` | `72` | Learning window before auto-training |
| `SENTRY_RETENTION_DAYS` | `30` | Flow/audit retention |
| `SENTRY_INCIDENT_WINDOW_SECONDS` | `300` | Correlation window |
| `SENTRY_SUPPRESSION_WINDOW_SECONDS` | `600` | Re-arrival suppression window |
| `SENTRY_MIN_ATTACK_CONFIDENCE` | `0.5` | MoE gate for an incident |
| `SENTRY_STRONG_ANOMALY_THRESHOLD` | `50` | AE-only incident gate for novel deviations |
| `SENTRY_LLM_PROVIDER` | `openai` | `openai`, `anthropic`, `lmstudio`, `ollama`, `auto`, `groq`, `none` |
| `SENTRY_LLM_BASE_URL` | `http://127.0.0.1:1234` | Provider endpoint |
| `SENTRY_LLM_MODEL` | `default` | Model identifier |
| `SENTRY_LLM_INCLUDE_SENSITIVE_CONTEXT` | `false` | Send raw IP/identity fields to the LLM |
| `SENTRY_LLM_BATCH_WINDOW_SECONDS` | `3` | Debounce window per incident |
| `SENTRY_LLM_BATCH_MAX_EVIDENCE` | `12` | Evidence records per AI dossier |
| `SENTRY_LLM_MAX_CONCURRENCY` | `2` | Concurrent AI calls |
| `SENTRY_LLM_MIN_INTERVAL_SECONDS` | `1` | Minimum gap between AI calls |
| `SENTRY_RESPONSE_MODE` | `disabled` | `disabled`, `approval`, or `automatic` |
| `SENTRY_RESPONSE_MIN_SEVERITY` | `critical` | Minimum severity for an automatic control |
| `SENTRY_RESPONSE_MIN_CONFIDENCE` | `0.9` | Minimum confidence for an automatic control |
| `SENTRY_RESPONSE_TTL_MINUTES` | `60` | Control lifetime; auto-released on expiry |
| `SENTRY_RESPONSE_MAX_AUTO_PER_10M` | `10` | Automatic controls allowed per rolling 10 minutes |
| `SENTRY_ENFORCEMENT_MODE` | `simulate` | `simulate` (record only) or `nftables` (root, this host) |
| `SENTRY_WEBHOOK_URL` / `_SECRET` | empty | Signed SIEM/SOAR enforcement adapter (preferred over local) |
| `SENTRY_RAG_ENABLED` | `true` | Ground AI triage in the bundled security corpus |
| `SENTRY_RAG_TOP_K` | `5` | Retrieved passages per triage call |
| `SENTRY_COOKIE_SECURE` | `true` | Set `false` only for local HTTP development |
| `SENTRY_LOG_FORMAT` | `json` | `json` or `console` |

Runtime-tunable values can also be changed from **Settings** by an administrator and
are persisted in the database; environment values remain the restart-safe defaults.

## 8. Operations

```bash
# health
curl -fsS http://localhost:8000/healthz
curl -fsS http://localhost:8000/readyz

# diagnostics (admin)
curl -fsS -b cookies.txt http://localhost:8000/api/diagnostics

# metrics
curl -fsS http://localhost:8000/metrics
```

* **Backups** — back up the database and `Sentry/data/` (baselines and model state).
* **Upgrade** — back up first; `alembic upgrade head` runs automatically in the
  container and in `start_all.sh`. Review release notes for schema changes.
* **Retention** — Timescale policies drop old chunks; SQLite prunes `flow_logs` on a
  six-hour task. Incidents, detections, and audit records are retained.
* **Scale** — keep one backend replica. Scale ingest horizontally with additional
  sensors and NATS; the detection engine is stateful per environment.

## 9. Simulation and validation

`scripts/attack_scenarios.py` trains a simulated corporate baseline and streams
every attack family the platform can attribute, plus three zero-day behaviours
(SMB lateral movement, ICMP covert tunnel, cryptomining).

```bash
# clean corporate baseline, then the complete matrix
python scripts/attack_scenarios.py --fresh-baseline

# just the zero-day set
python scripts/attack_scenarios.py --skip-baseline --scenario zero-day --count 20

# list scenario keys / expected attribution
python scripts/attack_scenarios.py --list-scenarios
```

`--fresh-baseline` calls `POST /api/sentry/reset` as an administrator: it clears the
environment model, not incidents, detections, or audit history. The baseline spans
finance, engineering, sales, data-center, and IoT subnets with normal web, DNS, SMB,
mail, and MQTT traffic.

Strong deviations with a very uncertain MoE verdict are labelled
`Zero-Day / Unknown Anomaly` and grouped as `Behavioral Anomaly`; known attacks keep
their expert attribution.

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| Login fails / loops | Confirm the API is reachable and cookies are not blocked; in local HTTP set `SENTRY_COOKIE_SECURE=false` |
| Engine stays in monitoring | Check `SENTRY_BASELINE_HOURS`; feed benign flows or trigger training from Settings |
| No detections | Confirm `/api/sentry/status` shows `mode=active` and a MoE bundle version |
| No sensors online | Check heartbeat freshness (<5 min), NATS credentials, and capture permissions |
| Console cannot reach API | Verify nginx `/api` proxy or Vite proxy; API must be on `:8000` |
| AI assessment is fallback | Start the provider, verify Settings → Test connection, regenerate the assessment |
| Alerts flood | Tune the incident window, add a scoped suppression, and verify the canonical family grouping |

## 10. Air-gapped deployments

The platform runs without internet access. Pre-pull the container images, keep the
model bundle in the backend image, and use a local LLM or `SENTRY_LLM_PROVIDER=none`.
The sensor and core do not phone home.
