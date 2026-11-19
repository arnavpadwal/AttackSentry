"""Async LLM triage service with fallback and rate limiting."""
from __future__ import annotations

import logging
import time
from typing import Any, Dict

from ..config import settings
from ..knowledge.grounding import ground_playbook
from ..knowledge.retriever import retrieve
from ..metrics import LLM_TRIAGES
from .base import SYSTEM_PROMPT, parse_json_response
from .local import LocalProvider
from .openai_compat import OpenAICompatProvider

logger = logging.getLogger("sentry.llm")

_REPAIR_PROMPT = """Return only one valid JSON object. It must contain a non-empty
attack_summary, technical_analysis, severity, confidence, mitre_attack, playbook,
and false_positive_assessment. playbook must be a non-empty array of steps, and
each step needs title, description, target, priority, and auto_executable. Do not
return {}, markdown, or any text outside the JSON object."""


class LLMTriageService:
    def __init__(self):
        provider_cls = LocalProvider if settings.llm_provider in {"auto", "lmstudio", "ollama"} else OpenAICompatProvider
        self.provider = provider_cls(
            provider=settings.llm_provider, base_url=settings.llm_base_url,
            model=settings.llm_model, api_key=settings.llm_api_key,
            timeout=settings.llm_timeout, max_tokens=settings.llm_max_tokens,
            temperature=settings.llm_temperature,
        ) if provider_cls is LocalProvider else provider_cls(
            base_url=settings.llm_base_url, model=settings.llm_model,
            api_key=settings.llm_api_key, timeout=settings.llm_timeout,
            max_tokens=settings.llm_max_tokens, temperature=settings.llm_temperature,
        )
        self._last_call = 0.0
        self._min_interval = 0.5
        self._consecutive_failures = 0
        self._blocked_until = 0.0

    async def generate_playbook(self, report: Dict[str, Any]) -> Dict[str, Any]:
        references, citations = retrieve(report)
        now = time.time()
        if now < self._blocked_until:
            LLM_TRIAGES.labels("fallback").inc()
            return _fallback(report, "AI provider cooling down after repeated failures", citations)
        if now - self._last_call < self._min_interval:
            await _sleep(self._min_interval - (now - self._last_call))
        self._last_call = time.time()

        user_message = _serialize(report)
        if references:
            user_message = (
                f"{user_message}\n\nREFERENCE PASSAGES (authoritative; cite only these "
                f"identifiers and controls):\n{references}"
            )
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ]
        try:
            content = await self.provider.generate(messages)
            try:
                playbook = ground_playbook(
                    _validate(parse_json_response(content)), report, citations
                )
            except Exception:
                # Smaller local models occasionally answer a long schema prompt
                # with `{}` or prose. Retry once with a compact repair prompt.
                repaired = await self.provider.generate([
                    {"role": "system", "content": _REPAIR_PROMPT},
                    {"role": "user", "content": user_message},
                ])
                playbook = ground_playbook(
                    _validate(parse_json_response(repaired)), report, citations
                )
            LLM_TRIAGES.labels("success").inc()
            self._consecutive_failures = 0
            return playbook
        except Exception as exc:
            logger.error("LLM triage failed: %s", exc)
            LLM_TRIAGES.labels("fallback").inc()
            self._consecutive_failures += 1
            if self._consecutive_failures >= 2:
                # Do not let a broken provider hold every queued incident for
                # the full request timeout. Fall back fast and probe again later.
                self._blocked_until = time.time() + 60.0
                logger.warning("AI provider circuit opened for 60s after repeated failures")
            return _fallback(report, str(exc), citations)

    async def health_check(self) -> bool:
        return await self.provider.health_check()


async def _sleep(secs: float) -> None:
    import asyncio
    await asyncio.sleep(secs)


def _serialize(report: Dict[str, Any]) -> str:
    import json
    if settings.llm_include_sensitive_context:
        return json.dumps(report, indent=2, default=str)
    return json.dumps(_redact(report), indent=2, default=str)


def _redact(value: Any, key: str = "") -> Any:
    """Pseudonymize sensitive network/identity fields before external triage."""
    sensitive = {"src_ip", "dst_ip", "ip", "identity", "user_id", "hostname", "mac", "raw_flow", "triggering_log"}
    if key.lower() in sensitive:
        if isinstance(value, (dict, list)):
            return "[REDACTED]"
        if value in (None, ""):
            return value
        import hashlib
        digest = hashlib.sha256(f"{settings.secret_key}:{value}".encode()).hexdigest()[:12]
        return f"entity-{digest}"
    if isinstance(value, dict):
        return {k: _redact(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item, key) for item in value]
    return value


def _validate(playbook: Dict[str, Any]) -> Dict[str, Any]:
    # Never convert an empty/model-refusal object into a fake successful
    # playbook.  Raising here routes the result through the clearly labelled
    # deterministic fallback instead of persisting N/A and no response steps.
    if not isinstance(playbook, dict):
        raise ValueError("LLM returned a non-object response")
    if "playbook" not in playbook and isinstance(playbook.get("steps"), list):
        playbook["playbook"] = playbook["steps"]
    summary = str(playbook.get("attack_summary") or "").strip()
    steps = playbook.get("playbook")
    if not summary or summary.upper() == "N/A" or not isinstance(steps, list) or not steps:
        raise ValueError("LLM response did not contain an attack summary and response steps")
    playbook["attack_summary"] = summary
    playbook.setdefault("technical_analysis", "")
    playbook.setdefault("severity", "medium")
    playbook.setdefault("confidence", "medium")
    playbook.setdefault("mitre_attack", {})
    playbook.setdefault("false_positive_assessment", "")
    for i, step in enumerate(steps):
        if not isinstance(step, dict) or not str(step.get("title") or "").strip():
            raise ValueError("LLM response contains an invalid response step")
        step.setdefault("step_id", i + 1)
    return playbook


def _fallback(
    report: Dict[str, Any],
    error: str,
    citations: list[dict[str, str]] | None = None,
    diagnostic: bool = True,
) -> Dict[str, Any]:
    ctx = report.get("context", {})
    src = ctx.get("src_ip", "Unknown")
    dst = ctx.get("dst_ip", "Unknown")
    sev = report.get("severity", "medium")
    attack = str(report.get("detection_type", "Unknown"))
    label = attack.casefold()
    if "ddos" in label or "flood" in label or "dos (" in label:
        steps = [
            {"step_id": 1, "title": "Rate-limit the attacked service", "description": f"Apply a temporary rate limit for traffic to {dst} and preserve allow-listed upstreams.", "action_type": "block", "target": dst, "priority": "immediate", "auto_executable": True, "command_hint": None},
            {"step_id": 2, "title": "Block confirmed abusive sources", "description": "Block high-volume source addresses observed across the correlated detections.", "action_type": "block", "target": "correlated source set", "priority": "urgent", "auto_executable": True, "command_hint": None},
            {"step_id": 3, "title": "Validate service recovery", "description": "Confirm latency, packet loss, and connection success return to baseline before releasing controls.", "action_type": "monitor", "target": dst, "priority": "urgent", "auto_executable": False, "command_hint": None},
        ]
    elif "brute" in label or "scan" in label:
        steps = [
            {"step_id": 1, "title": "Block the hostile source", "description": f"Temporarily block {src} at the nearest enforcement point.", "action_type": "block", "target": src, "priority": "immediate", "auto_executable": True, "command_hint": None},
            {"step_id": 2, "title": "Protect the targeted identity or service", "description": "Review authentication failures, lock compromised credentials, and enforce MFA where applicable.", "action_type": "remediate", "target": dst, "priority": "urgent", "auto_executable": False, "command_hint": None},
            {"step_id": 3, "title": "Hunt for successful access", "description": "Search subsequent sessions and lateral movement originating from the target.", "action_type": "investigate", "target": dst, "priority": "urgent", "auto_executable": False, "command_hint": None},
        ]
    else:
        steps = [
            {"step_id": 1, "title": "Isolate the affected endpoint", "description": f"Temporarily isolate {src} while preserving management access.", "action_type": "isolate", "target": src, "priority": "immediate", "auto_executable": True, "command_hint": None},
            {"step_id": 2, "title": "Collect and validate evidence", "description": "Review process, identity, destination, and related-flow evidence for compromise indicators.", "action_type": "investigate", "target": src, "priority": "urgent", "auto_executable": False, "command_hint": None},
            {"step_id": 3, "title": "Eradicate and monitor", "description": "Remove persistence, rotate exposed credentials, patch the entry path, and monitor recurrence before release.", "action_type": "remediate", "target": src, "priority": "standard", "auto_executable": False, "command_hint": None},
        ]
    result = {
        "attack_summary": f"AttackSentry correlated {attack} activity affecting {dst}.",
        "technical_analysis": (
            f"{report.get('reason', '')}\n\n"
            f"Local LLM diagnostic: {error[:300]}"
        ).strip() if diagnostic else str(report.get("reason") or "Correlated detection evidence.").strip(),
        "severity": sev,
        "confidence": "medium",
        "mitre_attack": {"tactic": "Unknown", "technique": "Unknown", "description": "LLM offline"},
        "playbook": steps,
        "false_positive_assessment": "LLM service unavailable — manual review required.",
        "_llm_error": error,
    }
    try:
        return ground_playbook(result, report, citations)
    except Exception:
        return result


def provisional_playbook(report: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic first plan, so no incident ever opens without guidance.

    The AI assessment replaces it when the batcher completes; until then the
    console shows a labelled fallback instead of an empty panel.
    """
    _, citations = retrieve(report)
    return _fallback(report, "assessment pending", citations, diagnostic=False)
