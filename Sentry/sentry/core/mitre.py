"""Deterministic MITRE ATT&CK mapping for detections.

Provides a tactic/technique/description for each detection so the MITRE
coverage matrix is always populated — even when the LLM triage service is
offline (the LLM may refine this with a more specific technique).
"""
from __future__ import annotations

from typing import Optional, Tuple

# family keyword -> (tactic, technique, description)
_FAMILY_MAP = [
    (("reflection", "amplification"), ("Impact", "T1498.002", "Reflection Amplification")),
    (("ddos", "flood"), ("Impact", "T1498", "Network Denial of Service")),
    (("botnet", "c2", "beacon", "irc"), ("Command and Control", "T1071", "Application Layer Protocol")),
    (("brute force", "bruteforce", "brute-force"), ("Credential Access", "T1110", "Brute Force")),
    (("service exploit", "remote service", "smb exploit"), ("Lateral Movement", "T1210", "Exploitation of Remote Services")),
    (("sqli", "xss", "web attack", "infiltration", "exploit public"), ("Initial Access", "T1190", "Exploit Public-Facing Application")),
    (("exfiltration", "exfil"), ("Exfiltration", "T1041", "Exfiltration Over C2 Channel")),
    (("scan", "port scan", "recon", "discovery"), ("Discovery", "T1046", "Network Service Discovery")),
    (("shellcode", "fuzzing", "backdoor", "exploit"), ("Execution", "T1059", "Command and Scripting Interpreter")),
    (("rdp", "remote"), ("Lateral Movement", "T1021", "Remote Services")),
    (("cloud", "infrastructure"), ("Initial Access", "T1078", "Valid Accounts")),
]

_EXPERT_MAP = {
    "Rudra": ("Impact", "T1498", "Network Denial of Service"),
    "Maya": ("Command and Control", "T1071", "Application Layer Protocol"),
    "Varuna": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "Indra": ("Lateral Movement", "T1021", "Remote Services"),
    "Garuda": ("Execution", "T1059", "Command and Scripting Interpreter"),
}

DEFAULT = ("Unknown", "Unknown", "Unknown")


def mitre_for(detection_type: Optional[str], primary_expert: Optional[str]) -> Tuple[str, str, str]:
    """Return (tactic, technique, description) for a detection."""
    text = (detection_type or "").lower()
    for keywords, mapping in _FAMILY_MAP:
        if any(k in text for k in keywords):
            return mapping
    if primary_expert in _EXPERT_MAP:
        return _EXPERT_MAP[primary_expert]
    return DEFAULT
