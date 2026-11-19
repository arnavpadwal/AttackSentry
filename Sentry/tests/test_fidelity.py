"""Tests for the alert-fidelity engine (dedup / correlation / suppression)."""
from __future__ import annotations

from sentry.core.engine import SentryEngine
from sentry.core.fidelity import AlertFidelityEngine, SuppressionRule


def _weights(primary="Varuna"):
    w = {"Varuna": 0.05, "Rudra": 0.05, "Maya": 0.05, "Indra": 0.05, "Garuda": 0.05}
    w[primary] = 0.8
    return w


def test_first_detection_creates_incident():
    f = AlertFidelityEngine()
    d = f.evaluate("10.0.0.1", "10.0.0.0/24", "Varuna", 0.95, 2.0, _weights())
    assert d.action == "create"
    assert d.incident_count == 1
    assert d.incident_id


def test_duplicate_merges_into_same_incident():
    f = AlertFidelityEngine()
    d1 = f.evaluate("10.0.0.1", "10.0.0.0/24", "Varuna", 0.95, 2.0, _weights())
    d2 = f.evaluate("10.0.0.1", "10.0.0.0/24", "Varuna", 0.96, 2.1, _weights())
    assert d2.action == "merge"
    assert d2.incident_id == d1.incident_id
    assert d2.incident_count == 2


def test_different_entities_do_not_merge():
    f = AlertFidelityEngine()
    d1 = f.evaluate("10.0.0.1", "10.0.0.0/24", "Varuna", 0.95, 2.0, _weights())
    d2 = f.evaluate("10.0.0.2", "10.0.0.0/24", "Varuna", 0.95, 2.0, _weights())
    assert d2.action == "create"
    assert d2.incident_id != d1.incident_id


def test_distributed_sources_merge_when_attack_scope_matches():
    f = AlertFidelityEngine()
    d1 = f.evaluate("10.0.0.1", "10.0.0.0/24", "DDoS", 0.95, 2.0, _weights(),
                    correlation_key="target:192.168.1.10:53:17", incident_entity="192.168.1.10")
    d2 = f.evaluate("10.0.0.2", "10.0.0.0/24", "DDoS", 0.96, 2.1, _weights(),
                    correlation_key="target:192.168.1.10:53:17", incident_entity="192.168.1.10")
    assert d2.action == "merge"
    assert d2.incident_id == d1.incident_id
    assert d2.correlation_entity == "192.168.1.10"
    assert d2.unique_entities == 2


def test_distributed_attack_to_different_target_stays_separate():
    f = AlertFidelityEngine()
    d1 = f.evaluate("10.0.0.1", None, "DDoS", 0.95, 2.0, _weights(), correlation_key="target:a:53:17")
    d2 = f.evaluate("10.0.0.2", None, "DDoS", 0.95, 2.0, _weights(), correlation_key="target:b:53:17")
    assert d2.incident_id != d1.incident_id


def test_ddos_correlation_scope_uses_target_service():
    a = SentryEngine._correlation_scope("DDoS (DNS Reflection)", {"Src_IP": "1.1.1.1", "Dst_IP": "10.0.0.9", "Dst_Port": 53, "Protocol": 17})
    b = SentryEngine._correlation_scope("DDoS (DNS Reflection)", {"Src_IP": "2.2.2.2", "Dst_IP": "10.0.0.9", "Dst_Port": 53, "Protocol": 17})
    assert a == b
    assert a[1] == "10.0.0.9"


def test_suppression_rule_drops_detection():
    f = AlertFidelityEngine()
    f.add_suppression_rule(SuppressionRule(entity="10.0.0.99", reason="known-good"))
    d = f.evaluate("10.0.0.99", "10.0.0.0/24", "Varuna", 0.99, 3.0, _weights())
    assert d.action == "suppress"
    assert d.suppress_reason == "known-good"


def test_suppression_cidr_and_multiple_scopes_are_conjunctive():
    rule = SuppressionRule(subnet="10.20.0.0/16", attack_family="DDoS")
    assert rule.matches("10.20.1.9", "10.20.1.0/24", "DDoS")
    assert not rule.matches("10.21.1.9", "10.21.1.0/24", "DDoS")
    assert not rule.matches("10.20.1.9", "10.20.1.0/24", "Reconnaissance")
    assert not SuppressionRule().matches("10.20.1.9", None, "DDoS")


def test_severity_maps_from_signal():
    f = AlertFidelityEngine()
    assert f.severity_from_signal(0.95) == "critical"
    assert f.severity_from_signal(0.8) == "high"
    assert f.severity_from_signal(0.6) == "medium"
    assert f.severity_from_signal(0.2) == "low"


def test_entity_risk_increments():
    f = AlertFidelityEngine()
    d = f.evaluate("10.0.0.1", "10.0.0.0/24", "Varuna", 0.99, 3.0, _weights())
    assert d.entity_risk > 0
