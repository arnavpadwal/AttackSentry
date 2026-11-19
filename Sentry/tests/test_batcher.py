"""Batched AI triage: one dossier per incident, not one call per detection."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from sentry.config import settings
from sentry.db import init_db, session_factory
from sentry.db.models import Detection
from sentry.llm.batcher import TriageBatcher


class FakeLLM:
    def __init__(self):
        self.calls = []

    async def generate_playbook(self, report):
        self.calls.append(report)
        return {
            "attack_summary": "Batched incident",
            "technical_analysis": "Evidence bundle",
            "severity": "high",
            "confidence": "high",
            "mitre_attack": {"tactic": "Impact", "technique": "T1498", "description": "Flood"},
            "playbook": [{
                "step_id": 1, "title": "Rate limit", "description": "Protect the target",
                "action_type": "block", "target": "10.0.0.1", "priority": "immediate",
                "auto_executable": False, "command_hint": None,
            }],
            "false_positive_assessment": "Low",
        }


@pytest.mark.asyncio
async def test_detections_are_batched_per_incident(monkeypatch):
    monkeypatch.setattr(settings, "llm_batch_window_seconds", 0.05)
    monkeypatch.setattr(settings, "llm_min_interval_seconds", 0.0)
    monkeypatch.setattr(settings, "llm_max_concurrency", 1)
    await init_db()
    now = datetime.now(timezone.utc)
    async with session_factory() as db:
        for index in range(10):
            db.add(Detection(
                id=f"batcher-{index}", incident_id="batcher-incident", timestamp=now,
                severity="high", confidence=0.9, entity_risk=40.0,
                detection_type="DDoS (HTTP Flood)", anomaly_score=2.5,
                src_ip=f"10.0.0.{index + 10}", dst_ip="10.0.0.1",
            ))
        await db.commit()

    llm = FakeLLM()
    persisted = []

    async def persist(detection_id, report, playbook):
        persisted.append((detection_id, report, playbook))

    batcher = TriageBatcher(llm, persist)
    await batcher.start()
    for index in range(10):
        batcher.enqueue(f"batcher-{index}", {
            "incident_id": "batcher-incident",
            "fidelity_action": "create" if index == 0 else "merge",
            "attack_family": "DDoS",
            "detection_type": "DDoS (HTTP Flood)",
            "severity": "high",
            "confidence": 0.9,
            "anomaly_score": 2.5,
            "entity_risk": 40.0,
            "incident_count": 10,
            "context": {"src_ip": "10.0.0.10", "dst_ip": "10.0.0.1"},
            "classification": {"primary_expert": "Rudra"},
        })
    await asyncio.sleep(1.2)
    await batcher.stop()

    assert len(llm.calls) == 1
    assert len(llm.calls[0]["evidence"]) == 10
    assert llm.calls[0]["incident_summary"]["detections"] == 10
    assert len(persisted) == 1
