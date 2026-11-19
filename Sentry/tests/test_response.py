"""Automated response policy safety checks."""
from __future__ import annotations

import asyncio

from sentry.config import settings
from sentry.integrations.local_enforce import LocalEnforcer, ResponseDispatcher
from sentry.integrations.webhook import WebhookDispatcher
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
    external = _detection(detection_type="Service Exploit", context={"src_ip": "203.0.113.9", "dst_ip": "10.0.0.5"})
    assert recommended_response(external) == ("block_ip", "203.0.113.9")


def test_automatic_action_is_queued_and_ttl_is_capped(monkeypatch):
    monkeypatch.setattr(settings, "response_mode", "automatic")
    monkeypatch.setattr(settings, "response_action", "block_ip")
    monkeypatch.setattr(settings, "response_ttl_minutes", 99999)
    monkeypatch.setattr(settings, "response_ttl_max_minutes", 60)
    action = new_policy_action(_detection())
    assert action.status == "queued"
    assert action.mode == "automatic"
    delta = action.expires_at - action.created_at if action.created_at else None
    assert delta is None or delta.total_seconds() <= 60 * 60 + 1


def test_local_simulate_is_honest_and_validates_target(monkeypatch):
    monkeypatch.setattr(settings, "enforcement_mode", "simulate")
    enforcer = LocalEnforcer()
    ok, message = asyncio.run(enforcer.send("com.attacksentry.response.requested", {
        "action": "block_ip", "target": {"type": "ip", "value": "203.0.113.9"},
        "expires_at": None,
    }))
    assert ok and "simulated" in message and "no packet filter applied" in message

    ok, message = asyncio.run(enforcer.send("com.attacksentry.response.requested", {
        "action": "block_ip", "target": {"type": "ip", "value": "not-an-ip"},
    }))
    assert not ok and "not an IP" in message


def test_rate_limit_is_not_faked_as_a_host_block(monkeypatch):
    monkeypatch.setattr(settings, "enforcement_mode", "simulate")
    ok, message = asyncio.run(LocalEnforcer().send("com.attacksentry.response.requested", {
        "action": "rate_limit", "target": {"type": "ip", "value": "10.0.0.5"},
    }))
    assert ok and "upstream scrubbing" in message


def test_nftables_without_root_fails_closed(monkeypatch):
    monkeypatch.setattr(settings, "enforcement_mode", "nftables")
    monkeypatch.setattr("sentry.integrations.local_enforce.os.geteuid", lambda: 1000)
    ok, message = asyncio.run(LocalEnforcer().send("com.attacksentry.response.requested", {
        "action": "block_ip", "target": {"type": "ip", "value": "203.0.113.9"},
        "expires_at": None,
    }))
    assert not ok and "root" in message


def test_dispatcher_falls_back_to_local_without_webhook(monkeypatch):
    monkeypatch.setattr(settings, "webhook_url", "")
    dispatcher = ResponseDispatcher(WebhookDispatcher())
    ok, message = asyncio.run(dispatcher.send("com.attacksentry.response.requested", {
        "action": "block_ip", "target": {"type": "ip", "value": "203.0.113.9"},
        "expires_at": None,
    }))
    assert ok and "simulated" in message
