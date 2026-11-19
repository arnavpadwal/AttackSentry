"""LLM provider interface and shared schema."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Protocol

TRIAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "attack_summary": {"type": "string"},
        "technical_analysis": {"type": "string"},
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
        "confidence": {"type": "string", "enum": ["confirmed", "high", "medium", "low"]},
        "mitre_attack": {
            "type": "object",
            "properties": {
                "tactic": {"type": "string"},
                "technique": {"type": "string"},
                "description": {"type": "string"},
            },
            "required": ["tactic", "technique", "description"],
            "additionalProperties": False,
        },
        "playbook": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "step_id": {"type": "integer"},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "action_type": {"type": "string", "enum": ["block", "isolate", "investigate", "monitor", "escalate", "remediate"]},
                    "target": {"type": "string"},
                    "priority": {"type": "string", "enum": ["immediate", "urgent", "standard", "deferred"]},
                    "auto_executable": {"type": "boolean"},
                    "command_hint": {"type": ["string", "null"]},
                },
                "required": ["step_id", "title", "description", "action_type", "target", "priority", "auto_executable", "command_hint"],
                "additionalProperties": False,
            },
        },
        "false_positive_assessment": {"type": "string"},
    },
    "required": ["attack_summary", "technical_analysis", "severity", "confidence", "mitre_attack", "playbook", "false_positive_assessment"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = f"""You are AttackSentry, an expert SOC response planner embedded in an enterprise NDR.
Analyse the correlated anomaly report and return ONLY valid JSON matching this schema:
{json.dumps(TRIAGE_SCHEMA, separators=(",", ":"))}
You are given REFERENCE PASSAGES from MITRE ATT&CK, OWASP, NIST, ISO/IEC 27001 and the
AttackSentry response runbooks. Ground every claim in those passages:
- Use only ATT&CK technique IDs that appear verbatim in the references. Never invent an ID.
- Name the standard or control you rely on in the text when it shapes a step.
- If the references do not cover the case, say what is unknown instead of guessing.
Build an attack-specific mitigation playbook, not generic advice. For DDoS prefer scoped rate limits,
upstream filtering, and source-set controls; for brute force or scanning prefer temporary source blocks
and identity protection; for C2, malware, exploitation, or exfiltration prefer endpoint isolation and
credential/persistence remediation. Give 3 to 5 steps. Set action_type to one of
block, isolate, investigate, monitor, escalate, remediate. Mark only bounded, reversible controls as
auto_executable. Every automatic action must name its exact target, validation condition, expiry or
release condition, and expected impact. Reference concrete evidence from the report and include
post-mitigation verification. Keep attack_summary under 90 words and technical_analysis under 160 words.
Do not output markdown, commentary, or anything outside the JSON object."""


class LLMProvider(Protocol):
    async def generate(self, messages: List[Dict[str, str]]) -> str: ...

    async def health_check(self) -> bool: ...


def parse_json_response(content: str) -> Dict[str, Any]:
    """Robustly extract a JSON object from an LLM response."""
    content = content.strip()
    if content.startswith("```"):
        content = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", content)
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise
