"""Knowledge-base retrieval and grounding tests (offline)."""
from __future__ import annotations

from sentry.knowledge.grounding import ground_playbook
from sentry.knowledge.retriever import get_knowledge_base, retrieve


def _report(detection: str = "DDoS (DNS Reflection)", family: str = "DDoS") -> dict:
    return {
        "detection_type": detection,
        "family": family,
        "severity": "high",
        "reason": "UDP port 53 flood",
        "context": {"dst_port": 53, "protocol": "UDP", "src_ip": "203.0.113.7"},
        "primary_expert": "Rudra",
    }


def test_retrieval_prefers_reflection_amplification():
    kb = get_knowledge_base()
    hits = kb.search("DNS reflection amplification denial of service", top_k=3)
    ids = [hit.chunk.id for hit in hits]
    assert "mitre:T1498.002" in ids


def test_retrieval_covers_owasp_and_iso():
    kb = get_knowledge_base()
    assert any(hit.chunk.id.startswith("owasp:") for hit in kb.search("SQL injection web application", top_k=3))
    assert any("iso27001" in hit.chunk.id for hit in kb.search("logging monitoring evidence", top_k=5))


def test_retrieve_returns_citations_and_prompt_block():
    references, citations = retrieve(_report())
    assert "[1]" in references
    assert citations
    assert {"id", "source", "title", "url"} <= set(citations[0])


def test_grounding_replaces_invented_technique_id():
    playbook = {
        "attack_summary": "DNS reflection flood",
        "technical_analysis": "Volume against port 53",
        "severity": "high",
        "confidence": "high",
        "mitre_attack": {"technique_id": "T1139", "technique": "T1139 DNS Flood"},
        "playbook": [{"title": "Rate limit", "description": "Scope to victim", "target": "10.0.0.5"}],
    }
    _, citations = retrieve(_report())
    grounded = ground_playbook(playbook, _report(), citations)
    technique = grounded["mitre_attack"]
    assert technique["technique_id"] == "T1498.002"
    assert technique["technique_name"] == "Reflection Amplification"
    assert grounded["playbook"][0]["step_id"] == 1
    assert grounded["playbook"][0]["action_type"] == "investigate"
    assert grounded["sources"]


def test_grounding_keeps_valid_technique_and_normalises_steps():
    playbook = {
        "attack_summary": "SSH brute force",
        "technical_analysis": "Repeated authentication failures",
        "severity": "medium",
        "confidence": "high",
        "mitre_attack": {"technique": "T1110 Brute Force"},
        "playbook": [
            {"title": "Block source", "action_type": "block", "priority": "immediate", "target": "203.0.113.9"},
            {"title": "Hunt success", "action_type": "not-a-real-action", "priority": "whenever"},
        ],
    }
    grounded = ground_playbook(playbook, _report("SSH-Bruteforce", "Credential Attack"), [])
    assert grounded["mitre_attack"]["technique_id"] == "T1110"
    assert [step["step_id"] for step in grounded["playbook"]] == [1, 2]
    assert grounded["playbook"][1]["action_type"] == "investigate"
    assert grounded["playbook"][1]["priority"] == "standard"


def test_catalog_ids_are_unique_and_well_formed():
    catalog = get_knowledge_base().catalog
    assert len(catalog) > 500
    assert all(technique_id.startswith("T") for technique_id in catalog)
    assert all(entry["name"] for entry in catalog.values())
