"""Framework mapping for operator-facing evidence."""
from __future__ import annotations

from sentry.core.frameworks import framework_map


def test_ddos_maps_to_nist_and_iso():
    mapping = framework_map("DDoS (DNS Reflection)")
    assert mapping["family"] == "DDoS"
    assert mapping["nist"]["function"].startswith("Respond")
    assert mapping["iso"]["control"] == "A.8.20"
    assert mapping["owasp"] is None


def test_web_and_credential_mappings():
    web = framework_map("Web Attack (SQLi/XSS/Infiltration)")
    assert web["owasp"]["id"] == "A03"
    credential = framework_map("SSH-Bruteforce")
    assert credential["iso"]["control"] == "A.8.5"
    assert credential["owasp"]["id"] == "A07"


def test_unknown_family_is_monitoring():
    mapping = framework_map("Something New")
    assert mapping["family"] == "Behavioral Anomaly"
    assert mapping["iso"]["control"] == "A.8.16"
    assert mapping["owasp"]["id"] == "A09"
