"""Map attack families to the frameworks operators already report against.

The mapping is deliberately small and stable: NIST CSF 2.0 function,
ISO/IEC 27001:2022 Annex A control, and OWASP Top 10 category. MITRE is carried
separately on each detection.
"""
from __future__ import annotations

from typing import Any, Dict

from .families import canonical_family

_BY_FAMILY: Dict[str, Dict[str, Any]] = {
    "DDoS": {
        "nist": {"function": "Respond (RS.MA)", "practice": "Incident management and service availability"},
        "iso": {"control": "A.8.20", "title": "Networks security"},
        "owasp": None,
    },
    "Credential Attack": {
        "nist": {"function": "Protect (PR.AA)", "practice": "Identity management, authentication and access control"},
        "iso": {"control": "A.8.5", "title": "Secure authentication"},
        "owasp": {"id": "A07", "name": "Identification and Authentication Failures"},
    },
    "Reconnaissance": {
        "nist": {"function": "Detect (DE.CM)", "practice": "Continuous monitoring"},
        "iso": {"control": "A.8.16", "title": "Monitoring activities"},
        "owasp": {"id": "A01", "name": "Broken Access Control"},
    },
    "Command and Control": {
        "nist": {"function": "Detect (DE.CM) / Respond (RS.AN)", "practice": "Continuous monitoring and incident analysis"},
        "iso": {"control": "A.8.16", "title": "Monitoring activities"},
        "owasp": None,
    },
    "Exfiltration": {
        "nist": {"function": "Respond (RS.AN)", "practice": "Incident analysis and data-loss response"},
        "iso": {"control": "A.8.12", "title": "Data leakage prevention"},
        "owasp": {"id": "A01", "name": "Broken Access Control"},
    },
    "Web Exploitation": {
        "nist": {"function": "Protect (PR.PS) / Detect (DE.CM)", "practice": "Secure configuration and continuous monitoring"},
        "iso": {"control": "A.8.28", "title": "Secure coding"},
        "owasp": {"id": "A03", "name": "Injection"},
    },
    "Exploitation": {
        "nist": {"function": "Respond (RS.MA)", "practice": "Incident management and vulnerability response"},
        "iso": {"control": "A.8.8", "title": "Management of technical vulnerabilities"},
        "owasp": {"id": "A06", "name": "Vulnerable and Outdated Components"},
    },
    "Behavioral Anomaly": {
        "nist": {"function": "Detect (DE.AE)", "practice": "Adverse event analysis"},
        "iso": {"control": "A.8.16", "title": "Monitoring activities"},
        "owasp": {"id": "A09", "name": "Security Logging and Monitoring Failures"},
    },
}


def framework_map(detection_type: str | None, primary_expert: str | None = None) -> Dict[str, Any]:
    """Return NIST/ISO/OWASP mappings for a detection label or expert."""
    family = canonical_family(detection_type or primary_expert)
    mapping = _BY_FAMILY.get(family, _BY_FAMILY["Behavioral Anomaly"])
    return {
        "family": family,
        "nist": mapping["nist"],
        "iso": mapping["iso"],
        "owasp": mapping["owasp"],
    }
