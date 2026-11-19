"""Automated response policy safety checks."""
from __future__ import annotations

from sentry.config import settings
from sentry.response import new_policy_action, recommended_response, response_policy_matches


def _detection(**overrides):
    value = {
        "incident_id": "inc_test",
        "severity": "critical",
        "confidence": 0.97,
        "fidelity_action": "create",
        "context": {"src_ip": "10.20.30.40"},
    }
    value.update(overrides)
    return value


def test_response_policy_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(settings, "response_mode", "disabled")
    assert not response_policy_matches(_detection())


def test_response_policy_requires_all_safety_thresholds(monkeypatch):
    monkeypatch.setattr(settings, "response_mode", "approval")
    monkeypatch.setattr(settings, "response_min_severity", "critical")
    monkeypatch.setattr(settings, "response_min_confidence", 0.9)
    assert response_policy_matches(_detection())
    assert not response_policy_matches(_detection(severity="high"))
    assert not response_policy_matches(_detection(confidence=0.89))
    assert not response_policy_matches(_detection(context={"src_ip": "not-an-ip"}))


def test_policy_action_is_bounded_and_awaits_approval(monkeypatch):
    monkeypatch.setattr(settings, "response_mode", "approval")
    monkeypatch.setattr(settings, "response_action", "isolate_host")
    monkeypatch.setattr(settings, "response_ttl_minutes", 30)
    action = new_policy_action(_detection())
    assert action.status == "pending_approval"
    assert action.entity == "10.20.30.40"
    assert action.expires_at is not None


def test_dynamic_response_is_attack_specific(monkeypatch):
    monkeypatch.setattr(settings, "response_action", "dynamic")
    ddos = _detection(detection_type="DDoS (UDP Flood)", context={"src_ip": "1.1.1.1", "dst_ip": "10.0.0.5"})
    brute = _detection(detection_type="SSH Brute Force", context={"src_ip": "1.1.1.1", "dst_ip": "10.0.0.5"})
    c2 = _detection(detection_type="C2 Beaconing", context={"src_ip": "10.0.0.7", "dst_ip": "8.8.8.8"})
    assert recommended_response(ddos) == ("rate_limit", "10.0.0.5")
    assert recommended_response(brute) == ("block_ip", "1.1.1.1")
    assert recommended_response(c2) == ("isolate_host", "10.0.0.7")
