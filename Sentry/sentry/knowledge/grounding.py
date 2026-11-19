"""Ground LLM triage output in the offline corpus.

The model may produce a plausible technique ID that does not exist. Every
identifier is checked against the ATT&CK catalog; unknown identifiers are
dropped and replaced from the deterministic detection mapping. Playbook
steps are normalised and capped, and the retrieved sources are attached to
the result so the console can show where a claim came from.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

from ..core.mitre import mitre_for
from .retriever import KnowledgeBase, get_knowledge_base

_TECH_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_ALLOWED_ACTIONS = {"block", "isolate", "investigate", "monitor", "escalate", "remediate"}
_ALLOWED_PRIORITIES = {"immediate", "urgent", "standard", "deferred"}
_MAX_STEPS = 6

_ACTION_ALIASES = {
    "rate_limit": "block", "ratelimit": "block", "throttle": "block", "filter": "block",
    "deny": "block", "drop": "block", "quarantine": "isolate", "contain": "isolate",
    "isolate_host": "isolate", "block_ip": "block", "hunt": "investigate",
    "analyze": "investigate", "validate": "investigate", "review": "investigate",
    "verify": "monitor", "watch": "monitor", "notify": "escalate", "escalation": "escalate",
    "patch": "remediate", "rotate": "remediate", "eradicate": "remediate", "restore": "remediate",
}
_PRIORITY_ALIASES = {
    "critical": "immediate", "p0": "immediate", "high": "urgent", "p1": "urgent",
    "medium": "standard", "normal": "standard", "p2": "standard", "low": "deferred", "p3": "deferred",
}


def extract_technique_ids(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        found.extend(m.upper() for m in _TECH_ID.findall(value))
    elif isinstance(value, dict):
        for key in ("technique_id", "id", "technique", "technique_name", "description"):
            found.extend(extract_technique_ids(value.get(key)))
    elif isinstance(value, Iterable):
        for item in value:
            found.extend(extract_technique_ids(item))
    return list(dict.fromkeys(found))


def _description(kb: KnowledgeBase, technique_id: str) -> str:
    chunk = kb.chunk(f"mitre:{technique_id}")
    if not chunk:
        return ""
    text = chunk.text
    marker = "Description: "
    if marker in text:
        text = text.split(marker, 1)[1].split("Detection guidance:", 1)[0]
    text = text.strip()
    if len(text) > 320:
        cut = text[:320]
        boundary = max(cut.rfind(". "), cut.rfind("; "))
        text = cut[: boundary + 1] if boundary > 120 else cut + "…"
    return text


def _entry(kb: KnowledgeBase, technique_id: str) -> dict[str, Any] | None:
    entry = kb.technique(technique_id)
    if not entry:
        return None
    return {
        "technique_id": technique_id,
        "technique_name": entry["name"],
        "tactic": ", ".join(entry.get("tactics") or []) or "Unknown",
        "description": _description(kb, technique_id),
        "url": entry.get("url", ""),
    }


def _deterministic(
    report: dict[str, Any],
    kb: KnowledgeBase,
    citations: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    # A retrieved technique is more specific than the coarse detection map.
    for citation in citations or []:
        if citation.get("id", "").startswith("mitre:"):
            entry = _entry(kb, citation["id"].split(":", 1)[1])
            if entry and entry not in result:
                result.append(entry)
            if len(result) >= 2:
                break
    if result:
        return result
    tactic, technique, description = mitre_for(
        report.get("detection_type"), report.get("primary_expert")
    )
    entry = _entry(kb, technique)
    if entry:
        if not entry["description"]:
            entry["description"] = description
        result.append(entry)
    if not result:
        for item in kb.techniques_for(str(report.get("detection_type") or ""), limit=2):
            candidate = _entry(kb, item["technique_id"])
            if candidate:
                result.append(candidate)
    return result


def _normalise_steps(steps: list[Any]) -> list[dict[str, Any]]:
    normalised: list[dict[str, Any]] = []
    for index, step in enumerate(steps[:_MAX_STEPS], start=1):
        if not isinstance(step, dict):
            continue
        title = str(step.get("title") or "").strip()
        if not title:
            continue
        action = str(step.get("action_type") or "investigate").strip().lower()
        action = _ACTION_ALIASES.get(action, action)
        priority = str(step.get("priority") or "standard").strip().lower()
        priority = _PRIORITY_ALIASES.get(priority, priority)
        action = action if action in _ALLOWED_ACTIONS else "investigate"
        priority = priority if priority in _ALLOWED_PRIORITIES else "standard"
        target = str(step.get("target") or "").strip()[:160]
        # Only a bounded, targeted control may run automatically. Analysis and
        # escalation never do, and neither does a step with no exact target.
        auto = bool(step.get("auto_executable"))
        if action in {"investigate", "escalate"} or not target:
            auto = False
        normalised.append(
            {
                "step_id": index,
                "title": title[:120],
                "description": str(step.get("description") or "").strip()[:600],
                "action_type": action,
                "target": target,
                "priority": priority,
                "auto_executable": auto,
                "command_hint": step.get("command_hint") if isinstance(step.get("command_hint"), str) else None,
            }
        )
    return normalised


def ground_playbook(
    playbook: dict[str, Any],
    report: dict[str, Any],
    citations: list[dict[str, str]] | None = None,
    kb: KnowledgeBase | None = None,
) -> dict[str, Any]:
    """Validate identifiers and steps against the corpus. Never raises."""
    kb = kb or get_knowledge_base()

    techniques: list[dict[str, Any]] = []
    for technique_id in extract_technique_ids(playbook.get("mitre_attack")):
        entry = _entry(kb, technique_id)
        if entry and entry not in techniques:
            techniques.append(entry)
    for entry in _deterministic(report, kb, citations):
        if entry not in techniques:
            techniques.append(entry)
    techniques = techniques[:3]

    if techniques:
        primary = techniques[0]
        playbook["mitre_attack"] = {
            "technique_id": primary["technique_id"],
            "technique_name": primary["technique_name"],
            "tactic": primary["tactic"],
            "technique": f"{primary['technique_id']} {primary['technique_name']}",
            "description": primary["description"],
            "url": primary["url"],
        }
        playbook["mitre_techniques"] = techniques
    else:
        playbook["mitre_attack"] = {
            "technique_id": "",
            "technique_name": "Unclassified",
            "tactic": "Unknown",
            "technique": "Unclassified",
            "description": "No ATT&CK technique matched this detection.",
            "url": "",
        }

    steps = _normalise_steps(playbook.get("playbook") or [])
    if steps:
        playbook["playbook"] = steps

    if citations:
        playbook["sources"] = citations
        playbook["grounded"] = True
    return playbook
