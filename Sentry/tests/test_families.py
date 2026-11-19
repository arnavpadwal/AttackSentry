"""Canonical attack-family grouping."""
from __future__ import annotations

from sentry.core.families import canonical_family


def test_ddos_variants_share_one_family():
    assert canonical_family("DDoS (DNS Reflection)") == "DDoS"
    assert canonical_family("DDoS (HTTP Flood)") == "DDoS"
    assert canonical_family("UDP Flood") == "DDoS"


def test_credential_and_recon_are_separate():
    assert canonical_family("SSH-Bruteforce") == "Credential Attack"
    assert canonical_family("Port Scan") == "Reconnaissance"


def test_unknown_label_is_behavioral():
    assert canonical_family("Something New") == "Behavioral Anomaly"
    assert canonical_family(None) == "Behavioral Anomaly"
