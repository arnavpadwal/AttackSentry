# Analyst user guide

## Security overview

The overview is the operational starting point. It answers four questions:

1. Are critical incidents open?
2. Which entities carry the most risk?
3. Is detection fully active and are sensors reporting?
4. What changed in traffic and ATT&CK observations?

The threat-level gauge is prioritization context, not proof of compromise. Open the incident queue for evidence.

## Work the incident queue

AttackSentry correlates individual detections into incidents to reduce alert fatigue. Work incidents before raw detections.

1. Filter by severity, status, family, or entity; keep **Priority** sort for the default queue.
2. Open the incident and validate the affected entity.
3. Review every correlated detection, source/destination, process, identity, and MITRE mapping.
4. Acknowledge the incident when you take ownership.
5. Follow the response sequence, adapting it to the environment.
6. Resolve only after containment/remediation and a recurrence check.

Use **Detections** when hunting for a specific signal or validating why correlation occurred. Use the row menu for acknowledge, AI assessment, containment, and resolution without leaving the queue. Bulk acknowledge/resolve is available after selecting rows.

Incidents are grouped by canonical family: a DDoS campaign targeting one host is one case even when it uses several ports and protocols, and a credential campaign against one service is one case across many source addresses.

## Incident workspace

The incident header shows status, severity, affected entity, correlated-signal count, peak confidence, and timing. The assessment summarizes likely behavior. **Correlated evidence** links to the exact detections. **Response sequence** orders investigation, containment, eradication, and monitoring. **Framework mapping** carries the applicable NIST CSF 2.0 function, ISO 27001:2022 control, OWASP Top 10 category, and MITRE ATT&CK context.

AI-generated steps are recommendations, not automatic authorization. Confirm targets, scope, ownership, and rollback before applying a control.

## Detection detail

Detection detail explains:

- anomaly and entity-risk scores;
- calibrated MoE confidence and responsible expert;
- source, destination, process, identity, subnet, and group context;
- MITRE tactic and technique;
- response playbook and false-positive assessment.

Mark a detection false positive only when evidence supports that conclusion. Prefer a narrow, reviewed suppression instead of repeatedly closing the same benign pattern.

## Assets and entities

Use **Assets & entities** to investigate a host’s risk, traffic history, anomaly history, identity, operating system, and related alerts. Risk is a decaying prioritization score; a high score directs attention but does not replace evidence.

## Network analytics

The network view shows observed relationships and risk concentration. Use it to identify shared destinations, unexpected lateral paths, and clusters of affected entities. Packet payload is not captured; the graph is based on flow metadata.

## Device control

Device approval is an administrative trust signal, not a guarantee that a device is safe. Validate ownership and fingerprint before approving. Use blacklist/whitelist controls according to the organization’s access policy.

## Access and identity

Administrators manage identities in **Settings → Access & IAM**. Create analyst or
viewer accounts, change roles, and enable/disable accounts inline. The console
prevents removal of the last active administrator. Analysts can work incidents and
request containment; viewers are read-only. Passwords can be rotated from **My
account**.

## AI assessments

New incidents are triaged automatically. Related detections are batched into one
evidence dossier, so a high-rate attack produces one assessment rather than one
request per flow. If the provider is offline, a deterministic playbook is shown and
marked as fallback; use **AI assessment** to regenerate it once the provider is
healthy. AI output is guidance, not authorization.

## Severity and confidence

| Field | Interpretation |
|---|---|
| Critical | Immediate investigation and likely containment |
| High | Prompt investigation during the active response window |
| Medium | Validate context and monitor/escalate as evidence requires |
| Low | Hunt context or weak signal; do not ignore recurring patterns |
| Confidence | Calibrated attack likelihood from the attribution pipeline |
| Anomaly score | Deviation from learned environment behavior |
| Entity risk | Time-decayed accumulation of entity signals |
| Zero-Day / Unknown Anomaly | Strong deviation with an uncertain MoE verdict; evidence is real, attribution needs analyst validation |

Severity expresses operational urgency. Confidence expresses model certainty. They answer different questions.

## If something looks wrong

- No traffic: check sensor process, capture permissions/interface, NATS credentials, and NATS reachability.
- Console says monitoring: check baseline duration and sample progress.
- No AI assessment: detection remains active; check the provider from Settings and use fallback guidance.
- Repeated noise: validate baseline coverage, then request a narrow suppression with a reason and owner.
- Missing live updates: refresh once, then check `/readyz`, browser WebSocket status, and reverse-proxy WebSocket configuration.
