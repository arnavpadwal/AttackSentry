# AttackSentry — Technical Project Report

**Version 1.0.0** · shipped model bundle `20260820-150548`

> **One-line pitch:** AttackSentry learns what normal looks like on a specific network,
> detects and attributes attacks in real time, groups them into incidents, and gives
> operators evidence-backed containment steps — on-premises and without inspecting payloads.

---

## 0. The mental model

AttackSentry does four jobs, in order:

1. **Learn** the environment: what is normal for each host, each subnet/group, and the whole network.
2. **Detect** a deviation from that normal with a hierarchical autoencoder.
3. **Attribute** the deviation to an attack family with five specialist models and a gating network.
4. **Operate** on it: correlate detections into incidents, attach evidence and framework mappings, run AI triage, and support an auditable containment action.

It is **not** an antivirus, EDR, or packet-capture forensics tool. It uses **L3/L4 flow
metadata only** — no payloads, no TLS decryption, no endpoint agents.

The rest of this document is the short version a teammate can read before a demo, followed
by a FAQ with the questions people actually ask.

---

## 1. System at a glance

```
Rust sensor                     Python core (FastAPI)                   React console
┌──────────────────┐            ┌────────────────────────────────┐      ┌──────────────────┐
│ libpcap capture   │  NATS      │ ingestion queue (bounded)      │ HTTP │ Overview          │
│ bidirectional     │ ────────▶  │ 42-feature extraction          │ /WS  │ Incident queue    │
│ flow table        │  or REST   │ hierarchical autoencoder       │ ───▶ │ Incident detail   │
│ 28 base features  │            │ 5-expert MoE + calibration     │      │ Assets / Network  │
│ subnet/identity   │            │ incident fidelity + grouping   │      │ Response center   │
└──────────────────┘            │ batched AI triage              │      │ Settings / IAM    │
                                │ PostgreSQL+Timescale / SQLite  │      └──────────────────┘
                                └────────────────────────────────┘
```

| Tier | Directory | Responsibility |
|---|---|---|
| 1 | `sentry_sensor/` | Packet capture → bidirectional flow state → JSON over NATS / REST |
| 2 | `Sentry/` | Features, baselining, AE, MoE, fidelity, AI triage, API, storage |
| 3 | `UI/frontend/` | Operator console: posture, triage, evidence, response, IAM, reports |

**Deployment shape:** one stateful backend replica (the baseline is local state), one
PostgreSQL/TimescaleDB (or SQLite for dev), one NATS JetStream, and any number of sensors.
The model bundle is baked into the backend image.

---

## 2. End-to-end data path

1. **Capture** — the sensor receives packets through libpcap and groups them into
   bidirectional flows keyed by the 5-tuple: source IP, destination IP, source port,
   destination port, protocol.
2. **Flow export** — a flow is emitted after **5 seconds of inactivity**, or immediately
   when a TCP `FIN`/`RST` is seen. The record carries the 28 base features plus context
   (sensor ID, subnet, identity if available).
3. **Transport** — the default is NATS JetStream (`sentry.flows`, stream `SENTRY`).
   REST ingestion (`POST /api/ingest/flow`) is the fallback and the path used by the demo
   simulator.
4. **Feature canonicalisation** — the core maps aliases, fills missing fields with `0`,
   and derives 14 ratio features. Result: **42 ordered features** shared by training
   and inference.
5. **Monitoring / training** — during the learning window the core keeps per-entity
   Welford statistics and reservoir samples. When the window ends it trains three
   autoencoders and switches to active mode.
6. **Scoring** — every flow gets a reconstruction error at global, group, and host
   level. A combined score above `1.0` is an anomaly.
7. **Attribution** — the anomaly is passed to the MoE (5 experts + gating + isotonic
   calibration). The result is a calibrated attack probability and a primary expert.
8. **Fidelity** — detections are correlated/merged/suppressed into incidents; severity
   and entity risk are calculated.
9. **AI triage** — a new incident enters a bounded, debounced queue. One evidence
   dossier is sent to the LLM; the playbook is stored with a deterministic fallback if
   the provider is unavailable.
10. **Console** — REST + WebSockets push the same persisted objects to the React UI.

---

## 3. Sensor and networking

### What is captured

| Item | Detail |
|---|---|
| Layer | L3/L4 headers only |
| Flow key | `(src_ip, dst_ip, src_port, dst_port, protocol)` with reverse-direction tracking |
| Expiry | 5 s idle, or TCP FIN/RST |
| Protocols | IPv4 and IPv6; TCP, UDP, and other IP protocols |
| Context | Sensor ID, source subnet (sensor `/24` derivation), optional identity/process fields |
| Not captured | Payload, TLS contents, HTTP bodies, DNS names, credentials |

### Why flows instead of packets

A flow is the smallest useful unit for NDR: it preserves who talked to whom, how much,
how fast, and with which TCP behaviour, while staying small enough to process at line
rate. The product deliberately does **not** store packet payloads; this keeps privacy and
storage costs down and works with encrypted traffic.

### Transport and auth

- Sensor → core: NATS JetStream with username/password (TLS recommended in production).
- Sensor identity is a registered sensor ID; ingestion uses a hashed API key
  (`X-Sentry-Key-ID` + `X-Sentry-Secret`).
- If NATS is unavailable, the core still accepts REST ingestion. The sensor retries NATS
  with backoff.
- The sensor has a one-command connectivity check:
  `SENTRY_TEST_CONNECTION=1 … ./attacksentry-sensor` → `CONNECTED` or `FAILED`.

### Important networking caveats

- Flow direction is inferred from the first packet and the reverse key; **NAT** can
  collapse multiple internal endpoints into one observed IP.
- Subnet grouping uses `/24` by default plus the sensor-provided `Subnet_Group`; a
  production deployment can supply a registry mapping.
- The sensor sees only traffic on the interface it captures. Switched traffic requires a
  SPAN/TAP or capture at the gateway.

---

## 4. Canonical feature schema

**28 base features + 14 derived ratios = 42 features.** This is defined in
`Sentry/sentry/core/schema.py` and is the contract between sensor, training, and inference.

| Group | Examples | Count |
|---|---|---|
| Identity/volume | `Protocol`, `Src_Port`, `Dst_Port`, `Flow_Duration`, fwd/bwd packets/bytes | 8 |
| Directional packet length | min/max/mean/std for forward and backward | 8 |
| Inter-arrival time | mean/std/max/min | 4 |
| Throughput | bytes/sec, packets/sec | 2 |
| TCP flags | FIN, SYN, RST, PSH, ACK, URG | 6 |
| Derived ratios | bytes/packet ratios, flag ratios, IAT coefficient of variation, packet-size ratios | 14 |

Why the ratios matter: they capture *shape* rather than absolute volume, so a small
office and a large data centre can share the same model. They are computed in exactly one
place (`core/features.py`) so training and serving cannot drift.

The Rust sensor emits the 28 base features. The Python core accepts canonical names or
known aliases (for example `Pkt_Len_Mean` → `Fwd_Pkt_Len_Mean`), so third-party flow
exporters can be adapted without changing the model.

---

## 5. Layer 1 — hierarchical autoencoder (unsupervised)

**Analogy:** three “normal meters” — one for the whole company, one for a department,
one for each individual host. An anomaly is a flow that looks wrong at one or more levels.

### Lifecycle

| Phase | What happens |
|---|---|
| Monitoring | Learn per host/group/global statistics + reservoir samples (default 72 h, `SENTRY_BASELINE_HOURS`) |
| Training | Fit three autoencoders on the collected normal samples; save `sentry_model.pt` |
| Active | Score every flow; anomalies go to MoE attribution |

### Model

```
42 features → Linear 64 → BatchNorm/ReLU → 32 → bottleneck (8 / 6 / 4) → 32 → 64 → 42
```

- Three separate AEs: **global** (bottleneck 8), **group/subnet** (6), **host** (4).
- Inputs are RobustScaler → MinMaxScaler, so extreme values do not dominate.
- Loss is MSE reconstruction error. A flow the model cannot reconstruct is unusual.

### Score

```
combined = 0.3 × global_score + 0.4 × group_score + 0.3 × host_score
```

Each level is normalised by its own threshold (99th percentile of validation
reconstruction error). **1.0 means “at the threshold”**; above 1.0 is an anomaly.
The thresholds are stored per entity, with a global fallback.

### Why three levels

- Global catches environment-wide shifts (new service, broad scan).
- Group catches departmental drift (a subnet behaving unlike itself).
- Host catches a single compromised machine (new ports, beaconing, unusual IAT).

A single global model would flag normal departmental differences as attacks; a single
host model would miss coordinated activity across many hosts.

### Practical notes

- The baseline is only as good as the learning window. If an attacker is active during
  monitoring, their traffic becomes “normal”. Keep the first 72 h clean or pre-seed from
  a known-good period.
- Retraining is per environment. `POST /api/sentry/reset` clears the AE model and baseline
  (incidents and evidence are retained); `POST /api/sentry/train` retrains.
- The AE is **not** the shipped MoE bundle and does not use labels.

---

## 6. Layer 2 — Mixture of Experts (supervised attribution)

**Analogy:** five specialists each know one attack world; a dispatcher learns which
specialist to trust for this flow; a calibration layer turns their combined opinion into
one probability.

| Expert | Dataset | Specialisation |
|---|---|---|
| **Varuna** | CIC-IDS-2017 | Web attacks, brute force, infiltration |
| **Rudra** | CICDDoS2019 | Reflection/amplification DDoS, floods |
| **Maya** | CTU-13 | Botnets, C2, IRC/P2P |
| **Indra** | NF-CICIDS2018-v3 | Cloud/infrastructure DoS, exploits |
| **Garuda** | NF-UNSW-NB15-v3 | Fuzzing, shellcode, probing |

Each expert is a LightGBM binary classifier trained on its own dataset. The **gating
network** is five LightGBM regressors trained to predict each expert's reliability on a
flow; its weights are normalised and used for a weighted average of expert probabilities.
The weighted score is then **isotonic-calibrated** so `0.9` means roughly a 90% empirical
attack probability.

### Shipped bundle metrics (`model_card.json`)

| Model | F1 | ROC-AUC | Precision | Recall |
|---|---:|---:|---:|---:|
| **Combined MoE** | **0.9967** | **0.9996** | **0.9970** | **0.9964** |
| Varuna | 0.9957 | 0.9999 | 0.9967 | 0.9946 |
| Rudra | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Maya | 0.4905 | 0.9964 | 0.9773 | 0.3274 |
| Indra | 0.9754 | 0.9958 | 0.9993 | 0.9526 |
| Garuda | 0.9991 | 1.0000 | 0.9989 | 0.9994 |

**Realistic 95% benign / 5% attack composition:** F1 **0.9898**, precision **0.9834**,
recall **0.9962**. This is the number to quote for deployment-like conditions; the
balanced “research” split is optimistic.

**Be honest about Maya.** Its standalone recall is 0.327 because CTU-13's botnet flows
are heavily imbalanced and overlap normal traffic. The gating network
reduces the impact, but a missed Maya detection is the most likely false negative in
this bundle. Improving CTU-13 features/augmentation is a known next step.

### Decision threshold

- `0.135`, selected on the realistic 95/5 validation set with a target **FPR ≤ 0.1%**.
- Scores below the threshold are not incidents; scores at/above it, combined with the AE
  gate, become detections.
- The threshold is stored in `model_card.json`; retraining can change both threshold and
  calibration.

### Leakage controls used during training

The training pipeline deliberately removes features that leak labels:

- `Init_Win_bytes_forward/backward` — null for DDoS flows, so the null pattern itself
  leaked the label.
- `Min_TTL` / `Max_TTL` for NF-UNSW-NB15-v3 — an IXIA test-bed artifact.
- Maya excludes `Src_Port` / `Dst_Port` to reduce dataset-specific shortcuts.

These choices make the reported metrics less spectacular but more defensible.

### Model bundle

```
Sentry/models/bundle_20260820-150548/
├── model_card.json      # version, features, metrics, threshold, provenance
├── experts/             # 5 LightGBM models
├── gating/              # 5 LightGBM gating models
├── scaler.pkl
└── calibrator.pkl
```

The runtime loads the bundle atomically. The default training sample is **300,000 rows
per dataset** (~1.5M rows total); the offline corpus has **114.7M rows** across five
public datasets. Training artifacts/datasets are not committed; `Training/README.md`
explains rebuilding.

---

### 6.1 Attack catalogue

The experts produce a calibrated attack probability; the engine then turns the primary
expert plus the flow shape into a human-readable detection label. This is the **complete
current catalogue**, including the fallback labels and the zero-day path.

| Detection label | Expert | Typical trigger (shape, not a signature) | Incident family | Simulator key |
|---|---|---|---|---|
| DDoS (DNS Reflection) | Rudra | UDP/53, huge forward packet/byte count, no response | DDoS | `ddos-dns` |
| DDoS (NTP Reflection) | Rudra | UDP/123, same amplification shape | DDoS | `ddos-ntp` |
| DDoS (SSDP Reflection) | Rudra | UDP/1900, same amplification shape | DDoS | `ddos-ssdp` |
| DDoS (LDAP Reflection) | Rudra | UDP/389, same amplification shape | DDoS | `ddos-ldap` |
| DDoS (SNMP Reflection) | Rudra | UDP/161, same amplification shape | DDoS | `ddos-snmp` |
| DDoS (UDP Flood) | Rudra | UDP, high packet rate, one-way volume | DDoS | `ddos-udp` |
| DDoS (TCP Flood) | Rudra | TCP, high SYN/volume, few responses | DDoS | `ddos-tcp` |
| DDoS (HTTP Flood) | Indra | TCP/80 or 443, high forward packet count | DDoS | `http-flood` |
| Port Scan | Indra | One or two packets to many ports/hosts | Reconnaissance | `syn-scan` |
| SSH-Bruteforce | Indra / Varuna | TCP/22, repeated short authentication flows | Credential Attack | `ssh-bruteforce` |
| FTP-BruteForce | Indra / Varuna | TCP/21, repeated login attempts | Credential Attack | `ftp-bruteforce` |
| RDP Brute Force / Infiltration | Indra / Varuna | TCP/3389, repeated short flows | Credential Attack | `rdp-bruteforce` |
| Web Attack (SQLi/XSS/Infiltration) | Varuna | TCP/80 or 443, request-heavy flow | Web Exploitation | `web-sqli` |
| DoS (Slowloris/SlowHTTPTest) | Indra | TCP/80 or 443, few packets but very long duration | DDoS | `slowloris` |
| C2 Beaconing | Maya | TCP, very few packets, long regular IAT | Command and Control | `c2-beacon` |
| IRC-Botnet (Neris/Rbot) | Maya | TCP/6667, long low-volume session | Command and Control | `irc-botnet` |
| Botnet Activity | Maya | Maya fallback for other botnet-like flows | Command and Control | covered by C2/IRC |
| Data Exfiltration | Rudra / Garuda / Varuna | TCP, external destination, large outbound byte count | Exfiltration | `data-exfiltration` |
| Service Exploit | Garuda | Common service port, exploit-like flow | Exploitation | `service-exploit` |
| Fuzzing / Exploit Probing | Garuda | URG flags, malformed/probing shape | Exploitation | `fuzzing` |
| Fuzzing / Analysis Attempt | Garuda | Unusual high port, no URG | Exploitation | `shellcode` |
| Generic Exploit / Shellcode | Garuda | Unusual low/non-service port | Exploitation | — |
| Cloud Infrastructure Exploit | Indra | Non-service high port with more than a scan | Exploitation | `cloud-infra` |
| Enterprise Network Anomaly | Varuna | Varuna fallback for an unusual internal flow | Behavioral Anomaly | — |
| Unknown Anomaly | — | No expert attribution available | Behavioral Anomaly | — |
| **Zero-Day / Unknown Anomaly** | — | **Any** strong AE deviation with MoE < 0.10 | Behavioral Anomaly | `smb-lateral`, `icmp-tunnel`, `cryptomining` |

**Important:** these labels are routing heuristics, not signatures. The primary expert
decides the branch; a different gating result can produce a different label for the same
flow. The **incident family** is the stable grouping layer, not the specific label.

The table lists **26 detection labels**. The simulator ships **21 known attack scenarios**
plus **3 zero-day fixtures**; the remaining labels (`Botnet Activity`, `Generic Exploit /
Shellcode`, `Enterprise Network Anomaly`, `Unknown Anomaly`) are engine fallbacks without a
dedicated scenario.

### Zero-day is a path, not a list

Zero-day detection does **not** depend on a new signature. It is the combination of:

```
hierarchical AE combined score ≥ 50
AND calibrated MoE score < 0.10
    → Zero-Day / Unknown Anomaly
    → Behavioral Anomaly incident family
```

That means **any** sufficiently extreme flow with uncertain attribution is treated as a
zero-day candidate. The three simulator examples — SMB lateral movement, ICMP covert
tunnel, and cryptomining — are only test fixtures; they are not special-cased in the
engine. If the MoE has at least moderate confidence (≥ 0.10), the flow is attributed to a
known expert even if it is novel; that is the deliberate trade-off between explanation
and novelty detection.

## 7. Layer 3 — incidents, fidelity, and zero-day

Raw anomalies are **not** alerts. The fidelity engine turns them into a low-noise queue.

### Correlation keys

| Attack family | Incident is scoped to | Example |
|---|---|---|
| DDoS | Victim host | All reflection/flood variants to one target become one case |
| Brute force | Targeted service | SSH brute force against one host:22 |
| Port scan | Scanner source | All destinations from one scanner |
| Other | Source entity | C2/exfil from one host |

Family labels are canonical (`DDoS`, `Credential Attack`, `Reconnaissance`,
`Command and Control`, `Exfiltration`, `Web Exploitation`, `Exploitation`,
`Behavioral Anomaly`). Specific detection types remain on each detection.

### Merge / suppress / severity

- **Merge** repeated detections for the same `(correlation key, family)` within
  `SENTRY_INCIDENT_WINDOW_SECONDS` (default 300 s).
- **Suppress** re-arrivals beyond the correlation window but inside
  `SENTRY_SUPPRESSION_WINDOW_SECONDS` (default 600 s).
- **Signal** = `0.5 × MoE score + 0.3 × normalised anomaly + 0.2 × expert agreement`.
- **Severity**: critical ≥ 0.90, high ≥ 0.75, medium ≥ 0.55, otherwise low.
- **Entity risk** accumulates with severity and signal, then decays exponentially
  (24 h half-life). Critical adds more than low, and diminishing headroom prevents a
  single burst from pinning every entity at 100.

### Zero-day path

A strong AE deviation with an uncertain MoE is not force-fitted to a known expert:

```
MoE score < 0.10 and combined anomaly ≥ 50
    → detection_type = "Zero-Day / Unknown Anomaly"
    → attack_family = "Behavioral Anomaly"
```

The evidence is still persisted, grouped, and sent to AI triage. The label tells the
analyst “the deviation is real; the attribution is not confident”.

### Framework mapping

Every alert response includes a computed mapping:

- **NIST CSF 2.0** function + practice (e.g. Respond / RS.MA)
- **ISO/IEC 27001:2022** Annex A control (e.g. A.8.20 Networks security)
- **OWASP Top 10** category where applicable (e.g. A03 Injection)
- **MITRE ATT&CK** tactic/technique remains on `mitre_tactic` / `mitre_technique`

This is deliberately a small, stable mapping so it can be used in review and reporting.

---

## 8. AI triage and response

### Batched triage

The LLM is **not** in the detection path. It explains and plans.

- New incident → one queued job. Later merge detections are folded into the same
  evidence dossier while the debounce window is open.
- Defaults: 3 s debounce, 12 evidence records, 2 concurrent workers, 1 s minimum gap,
  3 retries, 500-job queue.
- 429/5xx responses are retried with backoff; after two consecutive failures the provider
  circuit opens for 60 s so a broken provider cannot hold the whole queue.
- If the provider is unavailable, a deterministic playbook is stored and marked
  `is_fallback`; an analyst can regenerate it later.

### Privacy

Before external LLM calls, IPs, identities, hostnames, MACs, and raw flow fields are
pseudonymised unless `SENTRY_LLM_INCLUDE_SENSITIVE_CONTEXT=true`. Local providers
(LM Studio/Ollama) are the default recommendation.

### Containment lifecycle

`MitigationAction` records: incident, target, action, mode, status, reason, requester,
approver, created/expiry/executed timestamps, and provider outcome.

| Mode | Behaviour |
|---|---|
| `disabled` | No automated action (default) |
| `approval` | Action waits for an administrator |
| `automatic` | Dispatches only above severity/confidence gates, still bounded and expiring |

The backend does **not** change a local firewall itself; it sends a signed webhook to an
enforcement adapter, which keeps the product portable across environments.

---

## 9. API, database, and console

### API

FastAPI under `/api`, OpenAPI at `/api/docs`. Auth is httpOnly JWT cookies for users;
sensors use hashed API keys. Roles: `admin`, `analyst`, `viewer`. Key routes:

- `/api/ingest/flow` — REST flow ingestion
- `/api/alerts`, `/api/incidents`, `/api/hosts`, `/api/moe/*`
- `/api/sentry/status|reset|train|retrain`
- `/api/mitigations`, `/api/settings`, `/api/diagnostics`, `/api/audit`
- WebSockets: `/ws/telemetry`, `/ws/traffic`, `/ws/alerts`, `/ws/incidents`

### Database

| Table group | Purpose |
|---|---|
| `flow_logs` | Every observed flow (metadata) |
| `detections` | Attributed anomalies + evidence |
| `incidents` | Correlated cases |
| `playbooks` | AI/fallback response plans |
| `mitigation_actions` | Auditable containment lifecycle |
| `hosts`, `devices`, `sensors` | Asset/identity inventory |
| `users`, `api_keys`, `audit_log`, `suppression_rules`, `system_config` | IAM, audit, policy |

PostgreSQL + TimescaleDB is the production choice (hypertables for flow/detection/audit,
retention policies). SQLite is the zero-setup development fallback with a periodic flow
prune.

### Console

Overview · incident queue · incident workspace · assets/entities · network analytics ·
device control · response center · reports · settings/IAM. The UI defaults to light mode;
dark mode remains available.

---

## 10. Security and privacy

- **No payload capture**; L3/L4 metadata only.
- bcrypt password hashing; httpOnly/SameSite cookies; JWT issuer/audience checks.
- Hashed sensor API keys; secrets returned once.
- Last active administrator cannot be demoted, deactivated, or deleted; self-lockout is
  blocked.
- Audit log for user/sensor/suppression/response changes.
- HMAC-SHA256 signed webhook delivery; no redirect following.
- Production config validation refuses a short secret, missing admin password, SQLite,
  or non-HTTPS webhook.
- External LLM context is pseudonymised by default.
- Timescale/SQLite retention limits flow history.

---

## 11. Deployment and operations

| Mode | How |
|---|---|
| Docker Compose | `./attacksentry.sh start` → console `:8080`; DB, NATS, backend, nginx frontend |
| Kubernetes | Helm chart in `deploy/helm/attacksentry/` |
| Bare metal | `start_all.sh` (dev) or systemd units in `deploy/systemd/` |
| Sensor | Linux libpcap; Windows Npcap; headless or GUI |

The backend image uses **CPU-only PyTorch** and bakes in the model bundle plus Alembic
migrations. Health: `/healthz`, `/readyz`; metrics: `/metrics`; admin diagnostics:
`/api/diagnostics`.

Back up the database and `Sentry/data/` (baseline/model state). Keep one backend replica
unless state is externalised. Sensor connectivity can be checked with
`SENTRY_TEST_CONNECTION=1`.

---

## 12. Tests and validation

| Check | Result |
|---|---|
| Backend pytest | **33 passed** |
| Frontend TypeScript / Vitest / build | clean / 4 passed / passed |
| Sensor release build | passed (0 unit tests today) |
| Docker Compose | config valid; stack health + login verified |
| Docker image | model bundle + Alembic present; CPU torch |
| Simulated corporate baseline | trained successfully (`ae-202611041614`) |
| Known attack matrix | **21/21 scenarios produced incidents** |
| Zero-day matrix | **3/3 behaviours detected** |

The attack simulator (`scripts/attack_scenarios.py`) trains a corporate baseline across
Finance, Engineering, Sales, Data Center, and IoT, then exercises all known families and
three zero-day behaviours (SMB lateral movement, ICMP tunnel, cryptomining).

---

## 13. Metrics cheat sheet

| Metric | Plain meaning | Why it matters |
|---|---|---|
| **Precision** | Of the alerts we raise, how many are attacks | Directly controls analyst workload / false alarms |
| **Recall** | Of the attacks that exist, how many we catch | Controls missed detections |
| **F1** | Harmonic mean of precision and recall | One number when both matter |
| **ROC-AUC** | Ranking quality across all thresholds | Threshold-independent separability |
| **Average precision** | Area under the precision-recall curve | Better than ROC-AUC under heavy imbalance |
| **FPR** | False positives / all benign | Alert fatigue and business disruption |
| **FNR** | Missed attacks / all attacks | Security exposure |
| **Threshold** | The score above which we call it an attack | Moves the precision/recall trade-off |
| **Calibration** | Does `0.9` mean ~90%? | Makes the score usable in policy gates |

**Numbers to quote for the shipped bundle:** combined F1 **0.9967**; realistic 95/5 F1
**0.9898**; precision **0.9834**; recall **0.9962**; threshold **0.135**.
If someone wants one conservative sentence: “**~99% F1 on held-out research data and
~98.98% on a deployment-like 95/5 split, with a threshold chosen for ≤0.1% FPR.**”

---

## 14. Limitations and honest caveats

- **Baseline poisoning:** a 72 h learning window assumes mostly normal traffic. An
  attacker active from hour one becomes part of normal.
- **Metadata only:** no payload, DNS names, or TLS contents. Some attacks are invisible
  without L7 or endpoint context.
- **Public-dataset bias:** the experts were trained on five research datasets; real
  enterprise traffic differs. The AE is the environment-specific safety net.
- **Maya recall is weak** (0.327 standalone); C2/botnet coverage is the first model to
  improve.
- **Correlation is heuristic:** target/service/source scopes are deliberately simple;
  sophisticated multi-stage campaigns may need a graph model later.
- **LLM quality varies:** local models can return malformed JSON or fallback; the
  deterministic playbook is always available.
- **Single stateful backend:** baselines are local; HA needs an external state service.
- **No packet capture / no automated firewall:** response goes through a signed adapter
  and explicit policy.
- **Not yet built:** eBPF/XDP capture, BGP Flowspec, GNN lateral-movement detection,
  federated learning. These are future work, not current claims.

---

## 15. Five-minute demo

### 60-second talk track

1. **Problem:** “Attacks move at machine speed — network, cloud, agentic, identity — while
   manual triage falls behind. Every minute costs uptime and trust.”
2. **Learn:** “AttackSentry trains a baseline for this environment, not a generic internet
   baseline: global, per-subnet, and per-host.”
3. **Detect + attribute:** “A hierarchical autoencoder finds the deviation; five specialist
   models and a gating network name the attack family.”
4. **Understand:** “The incident workspace brings the evidence, MITRE mapping, NIST/ISO/OWASP
   context, and an AI-generated response sequence into one place.”
5. **Respond:** “Containment is a bounded, expiring, audited action — rate limit, isolate, or
   block — not an unreviewed firewall command.”
6. **Proof:** “The included simulator trains a corporate baseline and exercises 21 known
   attack scenarios plus three zero-day behaviours; the shipped bundle is ~99% realistic
   F1 at a threshold chosen for ≤0.1% FPR.”

```bash
# 1. Start development stack (backend :8000, console :5173)
./start_all.sh

# 2. Train a corporate baseline, then run the full matrix
python scripts/attack_scenarios.py --fresh-baseline

# 3. Or run only the zero-day set
python scripts/attack_scenarios.py --skip-baseline --scenario zero-day --count 20

# 4. List every scenario and its expected attribution
python scripts/attack_scenarios.py --list-scenarios
```

What to show, in order:

1. **Overview** — engine active, live chart, priority incidents.
2. **Incident queue** — severity/family grouping, filters, row actions.
3. **Incident detail** — AI assessment, evidence, response sequence, framework mapping.
4. **Response center** — request, approve, dispatch, expiry, audit trail.
5. **Settings → Access & IAM** — roles, activation, last-admin guard.
6. **Attack matrix** — known families + zero-day results.

---

## 16. FAQ

### AI and models

**Q: Why use an autoencoder instead of a supervised classifier for detection?**
A: The environment is unique and has no attack labels. An AE learns normal without
labels; supervised models would need labelled attacks for every customer network.

**Q: Why three autoencoders?**
A: Global, group, and host anomalies are different. A group-level spike may be normal for
a busy subnet but abnormal for a quiet one. The hierarchy filters local variation before
escalating.

**Q: What is a bottleneck?**
A: The narrow middle layer (8/6/4 neurons). It forces the model to compress normal
behaviour; if it cannot reconstruct a flow, the flow is unusual.

**Q: How is the anomaly threshold chosen?**
A: Each level uses the **99th percentile** of reconstruction error on held-out normal
validation data. The combined score is normalised so 1.0 = at threshold.

**Q: Why is the combined score `0.3/0.4/0.3`?**
A: It weights group context highest, then global and host equally. These are defaults in
`HierarchicalSentryModel`; they can be tuned per environment.

**Q: Why a Mixture of Experts instead of one classifier?**
A: Attack families have different feature distributions. Specialists preserve precision
on their domain; the gating network decides who to trust per flow.

**Q: How does the gating network work?**
A: Five LightGBM regressors predict each expert's reliability on the flow. Their outputs
are normalised into weights, then used to average expert probabilities.

**Q: What is isotonic calibration?**
A: A monotonic mapping from the raw weighted score to an empirical probability. It makes
`0.9` mean roughly 90%, which matters for policy gates.

**Q: Why is the threshold 0.135 and not 0.5?**
A: The threshold was selected on a realistic 95/5 split to keep FPR ≤0.1%. The calibrated
score distribution is skewed, so 0.135 is the operating point, not a “50/50” guess.

**Q: Why is Maya's F1 low?**
A: CTU-13 is small and imbalanced, and botnet flows overlap benign traffic. The gating
network limits the damage, but C2 recall is the weakest part of the bundle. It is a known
improvement target, not a hidden success.

**Q: What attacks can AttackSentry detect?**
A: The current catalogue covers eight DDoS variants, port scanning, SSH/FTP/RDP brute
force, web attacks, slow HTTP, C2/IRC botnets, data exfiltration, service/fuzzing/shellcode
exploits, cloud-infrastructure exploits, and generic enterprise anomalies. The full table
with triggers and simulator keys is §6.1.

**Q: What is the zero-day path?**
A: If the AE deviation is extreme (`combined ≥ 50`) but the MoE is very uncertain
(`< 0.10`), the detection is labelled `Zero-Day / Unknown Anomaly` and grouped as
`Behavioral Anomaly`. The evidence is kept; the model does not pretend to know the family.

**Q: Did you retrain the models?**
A: The shipped bundle is pre-trained. The simulator can train the **environment-specific
AE** (corporate baseline) via `--fresh-baseline`; the five experts/gating bundle is
rebuilt only with `Training/8_build_bundle.py`.

**Q: Can it detect encrypted traffic?**
A: It can detect behaviour from flow metadata (volume, timing, packet sizes, flags) even
when payload is encrypted. It cannot inspect decrypted contents.

**Q: Does the LLM detect attacks?**
A: No. Detection/attribution are deterministic ML. The LLM only writes the investigation
and response plan from the evidence dossier, with a deterministic fallback.

**Q: How do you avoid LLM rate limits under attack volume?**
A: One dossier per incident, 3 s debounce, max 12 evidence records, 2 workers, 1 s
minimum interval, retries/backoff, and a circuit breaker. A storm becomes a queue, not a
request flood.

### Metrics

**Q: What is precision vs recall?**
A: Precision = how many raised alerts were real. Recall = how many real attacks were
raised. You can be precise but miss attacks, or catch everything with noise.

**Q: Why not quote accuracy?**
A: With 95% benign traffic, a model that says “benign” to everything is 95% accurate and
useless. Precision/recall/F1 and FPR are the meaningful metrics.

**Q: Why is the realistic 95/5 metric lower than the balanced metric?**
A: The balanced research split has far more attacks than a real network. At 5% attacks,
false positives hurt precision much more; 0.9898 F1 is the deployment-like number.

**Q: What do ROC-AUC and average precision mean?**
A: ROC-AUC measures ranking across all thresholds. Average precision summarises the
precision-recall curve and is more informative under class imbalance.

**Q: What is FPR/FNR?**
A: FPR = benign flows incorrectly flagged / all benign. FNR = attacks missed / all
attacks. The threshold targets FPR ≤0.1% on the realistic split.

**Q: Are these numbers from live customer traffic?**
A: No. They are held-out results on public research datasets plus a simulated corporate
baseline. Treat them as benchmark evidence, not a guarantee for a specific network.

**Q: What is the model card?**
A: `Sentry/models/bundle_<version>/model_card.json` — the audit record with schema,
features, per-expert metrics, calibration, threshold, and provenance. It is the source of
truth over any slide or report.

### Networking

**Q: What exactly is a flow?**
A: A bidirectional conversation identified by the 5-tuple. It aggregates packets into
counts, byte volumes, packet-length stats, IAT stats, throughput, and TCP flags.

**Q: Why 5 seconds idle?**
A: It balances timely export against waiting for late packets. TCP FIN/RST closes a flow
immediately.

**Q: What is IAT?**
A: Inter-arrival time — the gap between packets. Low, regular IAT can indicate beaconing;
bursty IAT can indicate floods or scans.

**Q: Why no payload?**
A: Privacy, storage, encryption, and throughput. L3/L4 metadata is enough for the families
this product targets; payload inspection is explicitly out of scope.

**Q: How does the sensor send data?**
A: JSON over NATS JetStream (`sentry.flows` / stream `SENTRY`). REST
(`POST /api/ingest/flow`) is supported as a fallback and for the simulator.

**Q: What if NATS is down?**
A: The sensor retries with backoff; the core can still accept REST. The core warns when
NATS is disabled.

**Q: How are subnets/groups assigned?**
A: The sensor derives a `/24` source subnet and can stamp `Subnet_Group`; the core's
entity registry can override it. Unknown devices are kept as `Unknown` rather than dropped.

**Q: Does it support IPv6?**
A: Yes, the sensor parses IPv6 headers and uses hop limit/next header; ports are zero for
non-TCP/UDP protocols.

**Q: How does NAT affect it?**
A: NAT can make many internal hosts look like one external IP; flow direction is inferred
from the 5-tuple, not application semantics. Deploy the sensor inside the NAT boundary
where possible.

**Q: What throughput does it handle?**
A: The ingestion queue is bounded at 10,000 flows; throughput depends on hardware, model
bundle, and DB. The architecture is single stateful backend; benchmark on the target host
rather than quoting a generic number.

**Q: Can it ingest NetFlow/IPFIX?**
A: The core accepts canonical names and aliases; a third-party exporter can post to REST.
It does not include a native NetFlow/IPFIX collector — that is an adapter task.

### Incidents and response

**Q: Why group DDoS by target but scans by source?**
A: A DDoS campaign is defined by the victim; a scan is defined by the scanner. Using the
wrong scope creates either one giant incident or hundreds of duplicates.

**Q: Why are there still multiple incidents for one DDoS?**
A: Correlation is time-windowed (`300 s`) and family/target-scoped. Separate campaigns, or
traffic outside the window, remain separate cases; this preserves chronology.

**Q: What does “suppressed” mean?**
A: A repeat detection arrived after the correlation window but inside the suppression
window; it is recorded but not turned into a new incident.

**Q: Does the system auto-block?**
A: Default is `disabled`. `approval` requires an admin; `automatic` is gated by severity,
confidence, action allow-list, expiry, and a signed adapter. The backend never edits local
firewall rules directly.

**Q: What is the audit trail?**
A: `audit_log` for administrative changes plus the mitigation lifecycle record with
requester, approver, target, reason, expiry, provider message, and release outcome.

### Deployment and project

**Q: Why PostgreSQL/TimescaleDB?**
A: Flow/detection volume grows quickly; Timescale hypertables and retention policies keep
queries and storage manageable. SQLite is for single-node development.

**Q: Why one backend replica?**
A: The AE baseline, reservoirs, and in-memory fidelity state are local. Scaling out needs
shared state, which is explicit future work.

**Q: How do I reset the demo?**
A: `POST /api/sentry/reset` clears the AE model/baseline but keeps incidents and evidence.
Wipe `Sentry/attacksentry.db` for a completely fresh dev database.

**Q: What is the one-sentence explanation for a non-technical audience?**
A: “AttackSentry watches the shape of network traffic, learns what is normal for this
company, flags the flows that are not, tells you which kind of attack it looks like, and
gives the analyst a documented next step.”

**Q: What is the one-sentence explanation for a technical audience?**
A: “A Rust flow sensor feeds a FastAPI core that combines per-entity autoencoders with a
calibrated five-expert LightGBM MoE, then correlates detections into incidents and adds
batched LLM triage and signed containment.”

**Q: What is genuinely novel here?**
A: The combination of environment-specific hierarchical baselining, calibrated MoE
attribution, explicit zero-day handling, and incident-level AI triage in one on-prem
pipeline. The individual techniques are known; the integration and operator workflow are
the contribution.

---

*The model card and the code are the source of truth. If a slide, README, or old report
disagrees with `model_card.json` or the running API, trust the model card and the code.*
