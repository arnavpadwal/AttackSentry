#!/usr/bin/env python3
"""Build the offline triage knowledge base.

Sources:
  * MITRE ATT&CK Enterprise (fetched from the official STIX dataset)
  * OWASP Top 10 (2021)
  * NIST SP 800-61r2 and NIST CSF 2.0
  * ISO/IEC 27001:2022 Annex A (monitoring and incident controls)
  * AttackSentry response runbooks (this project's own guidance)

The output is one JSONL file per source under
``Sentry/sentry/knowledge/data/``. Runtime retrieval is offline and
dependency-free; rerun this script only when refreshing the sources.

Usage::

    .venv/bin/python scripts/build_knowledge_base.py [--refresh]
"""
from __future__ import annotations

import argparse
import json
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "Sentry" / "sentry" / "knowledge" / "data"
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
CACHE = Path("/tmp/attacksentry-attack-stix.json")


def _clean(text: str) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[[^\]]*\]\([^)]*\)", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _clip(text: str, limit: int) -> str:
    text = _clean(text)
    if len(text) <= limit:
        return text
    cut = text[:limit]
    boundary = max(cut.rfind(". "), cut.rfind("; "))
    return (cut[: boundary + 1] if boundary > limit * 0.5 else cut).strip()


def _write(name: str, rows: list[dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / f"{name}.jsonl"
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"{path.name}: {len(rows)} chunks")


def build_mitre(refresh: bool) -> tuple[list[dict], dict]:
    if refresh or not CACHE.exists():
        print(f"Fetching {ATTACK_URL}")
        with urllib.request.urlopen(ATTACK_URL, timeout=180) as response:
            CACHE.write_bytes(response.read())
    bundle = json.loads(CACHE.read_text())
    rows: list[dict] = []
    catalog: dict[str, dict] = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next(
            (e for e in obj.get("external_references", []) if e.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext or not ext.get("external_id", "").startswith("T"):
            continue
        technique_id = ext["external_id"]
        tactics = [
            phase.get("phase_name", "").replace("-", " ").title()
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        description = _clip(obj.get("description", ""), 700)
        detection = _clip(obj.get("x_mitre_detection", ""), 500)
        platforms = [p for p in obj.get("x_mitre_platforms", []) if p != "None"]
        body = [f"{technique_id} {obj['name']}."]
        if tactics:
            body.append(f"Tactics: {', '.join(tactics)}.")
        if platforms:
            body.append(f"Platforms: {', '.join(platforms)}.")
        if description:
            body.append(f"Description: {description}")
        if detection:
            body.append(f"Detection guidance: {detection}")
        url = ext.get("url") or f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
        rows.append(
            {
                "id": f"mitre:{technique_id}",
                "source": "MITRE ATT&CK",
                "kind": "technique",
                "title": f"{technique_id} {obj['name']}",
                "url": url,
                "tactics": tactics,
                "text": " ".join(body),
            }
        )
        catalog[technique_id] = {
            "technique_id": technique_id,
            "name": obj["name"],
            "tactics": tactics,
            "url": url,
        }
    return rows, catalog


OWASP = [
    ("A01:2021", "Broken Access Control",
     "Access control enforces policy so users cannot act outside their intended permissions. Failures include acting as another user, viewing or modifying another account's data, and missing server-side checks on network-exposed endpoints. In NDR telemetry look for a single identity or host touching many object identifiers, unusual HTTP 403/401 clusters followed by 200 responses, or direct object-reference enumeration. Respond by confirming the identity, revoking the session, and fixing the missing authorization check.",
     "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    ("A02:2021", "Cryptographic Failures",
     "Cryptographic failures cover data exposed because encryption is missing, weak, or misused: plaintext protocols, weak TLS versions or ciphers, hard-coded keys, and missing certificate validation. Network detection: TLS 1.0/1.1 or null-cipher negotiation, plaintext HTTP/FTP/Telnet to sensitive services, self-signed or expired certificates in unexpected places. Response is to terminate the weak path, rotate exposed secrets, and enforce a modern TLS policy.",
     "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
    ("A03:2021", "Injection",
     "Injection occurs when untrusted data reaches an interpreter: SQL, NoSQL, OS command, ORM, LDAP, or XSS in the browser. Network signatures include SQL metacharacters in request parameters, union/select patterns, time-based blind probes, and script tags in reflected parameters. Respond by blocking the source at the edge, preserving the request as evidence, and fixing parameterised queries or output encoding.",
     "https://owasp.org/Top10/A03_2021-Injection/"),
    ("A04:2021", "Insecure Design",
     "Insecure design is a missing or ineffective control at the design level, not an implementation bug. Threat modelling, secure design patterns and reference architectures are required. In operations this appears as business flows that can be abused at scale, such as unlimited password reset or unrestricted scraping. Response is a design change with layered controls, not a single edge rule.",
     "https://owasp.org/Top10/A04_2021-Insecure_Design/"),
    ("A05:2021", "Security Misconfiguration",
     "The most common category: default accounts and passwords, unnecessary features or ports, verbose errors, missing hardening, permissive CORS, and missing security headers. Network detection: management planes exposed to user networks, default service banners, directory listing, and unusual outbound services. Response is to close the exposure, remove defaults, and add configuration baselines with drift detection.",
     "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    ("A06:2021", "Vulnerable and Outdated Components",
     "Components with known vulnerabilities or unsupported versions. Detection is indirect at the network layer: exploit attempts against a known CVE, version disclosure in banners, or a host requesting updates over cleartext. Response is to identify the exact component and version, patch or isolate, and verify no successful exploitation occurred before patching.",
     "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"),
    ("A07:2021", "Identification and Authentication Failures",
     "Weak authentication permits credential stuffing, brute force, default credentials, and session fixation. Network signals: many authentication failures across few accounts, one source spraying many accounts, impossible-travel logins, and session tokens reused from different networks. Respond by throttling or blocking the source, locking targeted identities, enforcing MFA, and checking for a successful login after the failures.",
     "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
    ("A08:2021", "Software and Data Integrity Failures",
     "Code and data are accepted without integrity verification: unsigned updates, insecure deserialization, and CI/CD pipeline compromise. Network signals: hosts fetching updates over HTTP, unexpected package registries, and serialized object payloads to application endpoints. Respond by stopping the update path, verifying signatures, and rebuilding from a trusted artifact.",
     "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"),
    ("A09:2021", "Security Logging and Monitoring Failures",
     "Detection requires sufficient logging, retention, and alerting. Failures include missing audit events, logs that are not monitored, and alerts with no response path. NDR relevance: if flow or authentication telemetry is missing for an asset, an attack against it is invisible. Response is to restore sensor coverage, define retention, and test the detection-to-response path.",
     "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"),
    ("A10:2021", "Server-Side Request Forgery",
     "SSRF occurs when a server fetches a URL supplied by the user, allowing access to internal services or cloud metadata. Network signals: an application host making requests to internal RFC1918 ranges, link-local metadata addresses, or unusual external destinations. Respond by blocking the egress path at the application boundary, restricting allowed destinations, and reviewing what the request reached.",
     "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"),
]

NIST_800_61 = [
    ("NIST SP 800-61r2 §3.2", "Incident response lifecycle: preparation",
     "Preparation covers establishing the incident response capability, communications, and preventing incidents. It includes asset inventory, a baseline of normal behaviour, trained responders, and pre-approved containment actions. In an NDR deployment, preparation means knowing which entities are critical, what normal traffic looks like, and who can approve a block or isolation.",
     "https://csrc.nist.gov/pubs/sp/800/61/r2/final"),
    ("NIST SP 800-61r2 §3.3", "Detection and analysis",
     "Detection and analysis validates whether an event is an incident, determines its scope and impact, and preserves evidence. Analysts correlate multiple signals, establish the timeline, and identify affected hosts, accounts, and data. NIST notes that precursors and indicators may come from IDS/IPS, flow analysis, and anomaly detection; each alert needs triage, not automatic acceptance.",
     "https://csrc.nist.gov/pubs/sp/800/61/r2/final"),
    ("NIST SP 800-61r2 §3.3.3", "Containment strategies",
     "Containment strategies are selected based on damage potential, evidence preservation, service availability, time and resources, and effectiveness. Short-term containment may isolate a host or block a source while preserving evidence; long-term containment applies a temporary fix and tighter monitoring before recovery. The chosen control must be reversible and documented with an expiry.",
     "https://csrc.nist.gov/pubs/sp/800/61/r2/final"),
    ("NIST SP 800-61r2 §3.3.4", "Evidence gathering and handling",
     "Collect evidence in order of volatility, from CPU registers and memory to network state, running processes, disk, and archived media. For network incidents, capture flow records, packet captures, logs, and authentication events before changing the environment. Preserve chain of custody and hash evidence where required.",
     "https://csrc.nist.gov/pubs/sp/800/61/r2/final"),
    ("NIST SP 800-61r2 §3.4", "Eradication and recovery",
     "Eradication removes the cause: malware, compromised accounts, and the exploited vulnerability. Recovery restores systems to normal operation with verification and heightened monitoring. Before restoring, confirm the entry path is closed and that persistence has been removed; after restoring, monitor for recurrence.",
     "https://csrc.nist.gov/pubs/sp/800/61/r2/final"),
    ("NIST SP 800-61r2 §3.5", "Post-incident activity",
     "Post-incident activity captures lessons learned, metrics, and evidence retention. It answers what happened, how well the response performed, and what changes prevent recurrence. Track time to detect, time to contain, and the controls that failed.",
     "https://csrc.nist.gov/pubs/sp/800/61/r2/final"),
]

NIST_CSF = [
    ("NIST CSF 2.0 GV", "Govern",
     "Govern sets risk management strategy, roles, and policy. It establishes the risk tolerance that determines when a detection becomes an incident and which response actions are pre-approved. Without governance, containment decisions are inconsistent between shifts.",
     "https://www.nist.gov/cyberframework"),
    ("NIST CSF 2.0 ID", "Identify",
     "Identify covers asset management, risk assessment, and improvement. For NDR it is the inventory of entities, their criticality, and expected behaviour, which is the baseline that makes an anomaly meaningful.",
     "https://www.nist.gov/cyberframework"),
    ("NIST CSF 2.0 PR", "Protect",
     "Protect covers identity management, access control, data security, platform security, and network segregation. Network controls such as boundary protection and segmentation reduce the blast radius of an intrusion and give containment points that already exist.",
     "https://www.nist.gov/cyberframework"),
    ("NIST CSF 2.0 DE", "Detect",
     "Detect covers continuous monitoring, adverse event analysis, and detection process improvement. NDR contributes network-level monitoring and anomaly analysis; detections must be correlated and validated before response.",
     "https://www.nist.gov/cyberframework"),
    ("NIST CSF 2.0 RS", "Respond",
     "Respond covers incident management, analysis, mitigation, and reporting. Response actions should be scoped, logged, communicated, and reversible where possible. Containment must be proportionate to the confidence and severity of the detection.",
     "https://www.nist.gov/cyberframework"),
    ("NIST CSF 2.0 RC", "Recover",
     "Recover covers recovery planning, execution, and communication. Restoration follows eradication, with verification against the baseline and heightened monitoring for recurrence.",
     "https://www.nist.gov/cyberframework"),
]

NIST_800_53 = [
    ("NIST SP 800-53 Rev.5 IR-4", "Incident handling",
     "IR-4 requires an incident handling capability covering preparation, detection, analysis, containment, eradication, recovery, and user response. The organisation coordinates with stakeholders, incorporates lessons learned, and protects incident information. Automated response actions must remain within the approved authority described by the plan.",
     "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home"),
    ("NIST SP 800-53 Rev.5 IR-5", "Incident monitoring",
     "IR-5 requires tracking and documenting incidents, including the status, the affected assets, and the response actions taken. An NDR console should preserve the detection-to-incident linkage and the action history for review.",
     "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home"),
    ("NIST SP 800-53 Rev.5 AU-6", "Audit record review, analysis, and reporting",
     "AU-6 requires reviewing and analysing audit records for indications of inappropriate activity, reporting findings, and adjusting audit levels when needed. Network flow and detection records are part of that evidence set.",
     "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home"),
    ("NIST SP 800-53 Rev.5 SI-4", "System monitoring",
     "SI-4 requires monitoring the system to detect attacks, indicators of compromise, and unauthorized local, network, and remote connections. Monitoring includes inbound and outbound traffic, and the results must be analysed and escalated.",
     "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home"),
    ("NIST SP 800-53 Rev.5 SC-7", "Boundary protection",
     "SC-7 requires monitoring and controlling communications at external and key internal boundaries, including denying traffic by default and restricting the flow of information. Edge blocks and rate limits used for containment belong to this control.",
     "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home"),
    ("NIST SP 800-53 Rev.5 SC-5", "Denial-of-service protection",
     "SC-5 requires protecting against or limiting the effects of denial-of-service incidents, including bandwidth exhaustion and resource depletion. Controls include rate limiting, traffic filtering, and upstream scrubbing.",
     "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home"),
]

ISO_27001 = [
    ("ISO 27001:2022 A.5.24", "Incident management planning and preparation",
     "Plan and prepare for managing information security incidents by defining processes, roles, responsibilities, and communication. The response plan should name who can approve containment and what the escalation path is.",
     "https://www.iso.org/standard/27001"),
    ("ISO 27001:2022 A.5.25", "Assessment and decision on information security events",
     "Assess information security events and decide whether they are incidents. Triage uses consistent criteria, including severity, confidence, affected assets, and whether the activity deviates from the baseline.",
     "https://www.iso.org/standard/27001"),
    ("ISO 27001:2022 A.5.26", "Response to information security incidents",
     "Respond to incidents using documented procedures. Containment should be proportionate, reversible where possible, and recorded with the evidence that justified it.",
     "https://www.iso.org/standard/27001"),
    ("ISO 27001:2022 A.5.27", "Learning from information security incidents",
     "Use incidents to strengthen controls, update risk assessments, and improve detection. Assign corrective actions and verify they close.",
     "https://www.iso.org/standard/27001"),
    ("ISO 27001:2022 A.5.28", "Collection of evidence",
     "Establish procedures for identification, collection, acquisition, and preservation of evidence related to information security events, in line with legal and internal requirements.",
     "https://www.iso.org/standard/27001"),
    ("ISO 27001:2022 A.8.15", "Logging",
     "Produce, store, protect, and analyse logs of activities, exceptions, faults, and other relevant events. Network flow metadata, authentication events, and detection outcomes belong in the evidence set.",
     "https://www.iso.org/standard/27001"),
    ("ISO 27001:2022 A.8.16", "Monitoring activities",
     "Monitor networks, systems, and applications for anomalous behaviour and take appropriate action. Alerts must be evaluated by a responder; an unmonitored queue is not monitoring.",
     "https://www.iso.org/standard/27001"),
    ("ISO 27001:2022 A.8.20", "Networks security",
     "Secure, manage, and control networks to protect information and connected systems. Segmentation and controlled egress limit lateral movement and give containment points.",
     "https://www.iso.org/standard/27001"),
    ("ISO 27001:2022 A.8.21", "Security of network services",
     "Define, implement, and monitor security mechanisms, service levels, and service requirements for network services, including those provided externally.",
     "https://www.iso.org/standard/27001"),
    ("ISO 27001:2022 A.8.22", "Segregation of networks",
     "Separate groups of information services, users, and information systems on networks. Segregation reduces the blast radius of a compromised host and restricts discovery.",
     "https://www.iso.org/standard/27001"),
    ("ISO 27001:2022 A.8.23", "Web filtering",
     "Manage access to external websites to reduce exposure to malicious content. Web filtering is also a containment point for command-and-control and exfiltration destinations.",
     "https://www.iso.org/standard/27001"),
    ("ISO 27001:2022 A.8.7", "Protection against malware",
     "Implement malware protection and monitor for malicious code, including network indicators and lateral movement. Detection should be paired with containment and recovery steps.",
     "https://www.iso.org/standard/27001"),
]

RUNBOOKS = [
    ("DDoS", "Volumetric and reflection denial of service",
     "Signals: sustained packet or bit rate far above baseline to one destination, many sources, short flow durations, high SYN or UDP ratio, and one victim. Immediate actions: confirm the victim and the ingress point, apply a scoped rate limit for the targeted service, enable upstream scrubbing or provider protection, and block only confirmed abusive source sets. Validate with packet rate, loss, and service latency against baseline. Release the control when the rate is stable for the agreed window.",
     "Volumetric floods can saturate a link before a host-based control acts; escalate to the upstream provider early."),
    ("Credential attack", "Brute force and credential stuffing",
     "Signals: one source failing authentication against many accounts, or many sources failing against one account, then a possible success. Immediate actions: throttle or block the source set, lock targeted identities, require MFA, and search for a successful login after the failures. Validate by checking the authentication outcome and session source. Rotate credentials for any account that succeeded.",
     "Do not block an entire shared egress range without checking for legitimate users behind it."),
    ("Reconnaissance", "Port scanning and service discovery",
     "Signals: a source touching many destination ports or many hosts in a short window, sequential port order, and short half-open connections. Immediate actions: throtte the scanner, block it at the edge if it is external, and check whether any probe reached a vulnerable service. Validate by reviewing follow-up connections to the probed ports.",
     "A scan from an internal host is more urgent than the same scan from an external host: it may be an already compromised asset."),
    ("Command and control", "Beaconing and remote access",
     "Signals: periodic connections with low jitter to an external destination, small request/response sizes, rare destination or SNI, and DNS tunnelling patterns. Immediate actions: isolate the internal host, block the destination at egress, and preserve flow and DNS evidence. Validate by confirming the persistence mechanism and checking for lateral movement. Do not release until the persistence is removed.",
     "Encrypted C2 cannot be confirmed from flow metadata alone; pair network evidence with endpoint telemetry."),
    ("Exfiltration", "Data leaving the network",
     "Signals: a large outbound volume to an unusual destination, off-hours transfer, many small uploads, or a spike in DNS query volume. Immediate actions: block the destination path, isolate the source host, and identify what data was accessible. Validate the volume and destination reputation. Escalate to data-owner and legal notification processes if sensitive data left.",
     "Preserve evidence before isolating if the host may hold the only copy of the transfer log."),
    ("Web exploitation", "Exploitation of a public-facing application",
     "Signals: exploit-like request patterns, path traversal, injection strings, unusual user agents, a 200 response following repeated errors, or a new outbound connection from the web server. Immediate actions: block the source at the edge, snapshot the request, and check whether the application spawned a shell or made an outbound connection. Validate the application logs and the process tree.",
     "Blocking the source is not eradication: the vulnerable endpoint still needs a fix."),
    ("Exploitation", "Service exploit and code execution",
     "Signals: exploit traffic against a service port, crash or restart of the service, a new listening port, or a child process making network connections. Immediate actions: isolate the host, preserve memory and logs, and identify the entry vulnerability. Validate by confirming the payload path and checking for persistence.",
     "Isolation before evidence capture can destroy volatile memory evidence; decide based on spread risk."),
    ("Behavioral anomaly", "Unclassified deviation from baseline",
     "Signals: a flow or entity that deviates from its learned baseline without matching a known signature. Immediate actions: review the entities, the time of day, the direction, and the peers. Correlation with other detections decides escalation. Validate against the baseline window before acting.",
     "An anomaly is a lead, not a verdict. Do not auto-contain on an unclassified deviation."),
]


def build_curated() -> None:
    rows = []
    for ref, title, text, url in OWASP:
        rows.append(
            {
                "id": f"owasp:{ref}",
                "source": "OWASP Top 10 2021",
                "kind": "standard",
                "title": f"{ref} {title}",
                "url": url,
                "text": f"{ref} {title}. {text}",
            }
        )
    _write("owasp_top10", rows)

    rows = []
    for ref, title, text, url in NIST_800_61:
        rows.append(
            {
                "id": f"nist80061:{ref}",
                "source": "NIST SP 800-61r2",
                "kind": "standard",
                "title": f"{ref} {title}",
                "url": url,
                "text": f"{title}. {text}",
            }
        )
    for ref, title, text, url in NIST_CSF:
        rows.append(
            {
                "id": f"nistcsf:{ref}",
                "source": "NIST Cybersecurity Framework 2.0",
                "kind": "standard",
                "title": f"{ref} {title}",
                "url": url,
                "text": f"{title}. {text}",
            }
        )
    for ref, title, text, url in NIST_800_53:
        rows.append(
            {
                "id": f"nist80053:{ref}",
                "source": "NIST SP 800-53 Rev.5",
                "kind": "control",
                "title": f"{ref} {title}",
                "url": url,
                "text": f"{title}. {text}",
            }
        )
    _write("nist", rows)

    rows = []
    for ref, title, text, url in ISO_27001:
        rows.append(
            {
                "id": f"iso27001:{ref}",
                "source": "ISO/IEC 27001:2022",
                "kind": "control",
                "title": f"{ref} {title}",
                "url": url,
                "text": f"{title}. {text}",
            }
        )
    _write("iso_27001", rows)

    rows = []
    for family, title, text, caveat in RUNBOOKS:
        rows.append(
            {
                "id": f"runbook:{family.lower().replace(' ', '-')}",
                "source": "AttackSentry response runbook",
                "kind": "runbook",
                "title": f"{family}: {title}",
                "url": "",
                "text": f"{title}. {text} Caveat: {caveat}",
            }
        )
    _write("runbooks", rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh", action="store_true", help="refetch the MITRE ATT&CK dataset")
    args = parser.parse_args()
    mitre_rows, catalog = build_mitre(args.refresh)
    _write("mitre_attack", mitre_rows)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "mitre_catalog.json").write_text(
        json.dumps(catalog, indent=1, sort_keys=True), encoding="utf-8"
    )
    print(f"mitre_catalog.json: {len(catalog)} techniques")
    build_curated()


if __name__ == "__main__":
    main()
