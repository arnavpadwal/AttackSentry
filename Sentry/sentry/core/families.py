"""Canonical attack-family grouping.

Detection labels stay specific (``DDoS (DNS Reflection)``); incident correlation
uses a small, stable family so a spray of variants becomes one case instead of
hundreds of duplicate alerts.
"""
from __future__ import annotations

FAMILIES = (
    "DDoS",
    "Credential Attack",
    "Reconnaissance",
    "Command and Control",
    "Exfiltration",
    "Web Exploitation",
    "Exploitation",
    "Behavioral Anomaly",
)

_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("DDoS", ("ddos", "flood", "dos (", "reflection")),
    ("Exfiltration", ("exfiltrat", "data theft", "large outbound")),
    ("Command and Control", ("c2", "beacon", "botnet", "irc-", "command and control")),
    ("Credential Attack", ("brute", "credential", "password")),
    ("Reconnaissance", ("port scan", "scan", "recon", "probing")),
    ("Web Exploitation", ("sql", "xss", "web attack", "web exploit", "infiltration")),
    ("Exploitation", ("exploit", "shellcode", "fuzz", "service exploit", "remote code")),
)


def canonical_family(label: str | None) -> str:
    """Map any detection label to a stable incident family."""
    text = (label or "").casefold()
    for family, needles in _RULES:
        if any(needle in text for needle in needles):
            return family
    return "Behavioral Anomaly"


def family_slug(family: str) -> str:
    return family.casefold().replace(" ", "-")
