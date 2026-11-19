"""Alert fidelity: correlation, deduplication, suppression and scoring.

Turns raw autoencoder anomalies + MoE classifications into a low-noise feed of
*incidents*. A flood of similar flows from the same entity within a short window
is collapsed into a single incident; repeated signals escalate it. Suppression
rules let operators silence known-good noise.

State is in-memory (bounded TTL) because correlation is a short-window operation;
incidents are persisted by the API/database layer. A process restart can, at
worst, produce a few duplicate incidents for a few minutes.
"""
from __future__ import annotations

import ipaddress
import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..ml.bundle import EXPERT_NAMES

_SEVERITY_IMPACT = {"critical": 25.0, "high": 10.0, "medium": 5.0, "low": 1.0}


@dataclass
class SuppressionRule:
    entity: Optional[str] = None
    subnet: Optional[str] = None
    attack_family: Optional[str] = None
    reason: str = ""

    def matches(self, entity: str, subnet: Optional[str], family: str) -> bool:
        checks: list[bool] = []
        if self.entity:
            checks.append(self.entity == entity)
        if self.subnet:
            try:
                network = ipaddress.ip_network(self.subnet, strict=False)
                checks.append(ipaddress.ip_address(entity) in network)
            except ValueError:
                checks.append(False)
        if self.attack_family:
            checks.append(self.attack_family.casefold() == family.casefold())
        # Empty rules never suppress; when multiple selectors are specified,
        # all must match so a broad family cannot accidentally silence all hosts.
        return bool(checks) and all(checks)


@dataclass
class FidelityDecision:
    action: str  # create | merge | suppress
    incident_id: str
    severity: str
    confidence: float
    entity_risk: float
    incident_count: int
    suppress_reason: Optional[str] = None
    correlation_entity: Optional[str] = None
    unique_entities: int = 1


@dataclass
class _Incident:
    id: str
    entity: str
    family: str
    created_at: float
    last_seen: float
    count: int
    peak_signal: float
    sources: set[str] = field(default_factory=set)


@dataclass
class _EntityScore:
    risk: float = 0.0
    last_seen: float = 0.0


class AlertFidelityEngine:
    def __init__(
        self,
        incident_window_seconds: int = 300,
        suppression_window_seconds: int = 600,
        entity_score_decay_hours: float = 24.0,
    ):
        self.incident_window = incident_window_seconds
        self.suppression_window = suppression_window_seconds
        self.decay_hours = entity_score_decay_hours
        self._incidents: Dict[Tuple[str, str], _Incident] = {}
        self._entity_scores: Dict[str, _EntityScore] = {}
        self._suppressions: Dict[Tuple[str, str], float] = {}
        self.suppression_rules: List[SuppressionRule] = []
        self._counter = 0

    # ------------------------------------------------------------------ #
    def _prune(self, now: float) -> None:
        stale = [k for k, inc in self._incidents.items() if now - inc.last_seen > self.incident_window * 6]
        for k in stale:
            self._incidents.pop(k, None)
        stale_sup = [k for k, t in self._suppressions.items() if now - t > self.suppression_window]
        for k in stale_sup:
            self._suppressions.pop(k, None)

    def _decayed_risk(self, entity: str, now: float) -> float:
        s = self._entity_scores.get(entity)
        if not s:
            return 0.0
        elapsed_h = (now - s.last_seen) / 3600.0
        if elapsed_h <= 0:
            return s.risk
        return s.risk * math.pow(0.5, elapsed_h / self.decay_hours)

    def _bump_risk(self, entity: str, severity: str, signal: float, now: float, scale: float = 1.0) -> float:
        cur = self._decayed_risk(entity, now)
        # Risk is evidence-weighted, not a fixed counter. A high-confidence
        # critical signal moves risk materially more than a weak low signal;
        # diminishing headroom prevents a busy flow burst from pinning every
        # source at the same value.
        impact = _SEVERITY_IMPACT.get(severity, 5.0) * (0.35 + 0.65 * signal) * scale
        cur = min(100.0, cur + impact * (1.0 - cur / 125.0))
        self._entity_scores[entity] = _EntityScore(risk=cur, last_seen=now)
        return cur

    # ------------------------------------------------------------------ #
    def compute_signal(self, moe_score: float, combined_score: float, gating_weights: Dict[str, float]) -> float:
        # Expert agreement: entropy of the gating distribution (0 = fully certain).
        w = [max(gating_weights.get(n, 0.0), 1e-6) for n in EXPERT_NAMES]
        total = sum(w) or 1.0
        p = [x / total for x in w]
        entropy = -sum(x * math.log(x) for x in p) / math.log(len(p))  # normalised
        agreement = 1.0 - entropy
        norm_anom = min(combined_score / 2.0, 1.0)
        signal = 0.5 * moe_score + 0.3 * norm_anom + 0.2 * agreement
        return min(1.0, max(0.0, signal))

    @staticmethod
    def severity_from_signal(signal: float) -> str:
        if signal >= 0.9:
            return "critical"
        if signal >= 0.75:
            return "high"
        if signal >= 0.55:
            return "medium"
        return "low"

    # ------------------------------------------------------------------ #
    def evaluate(
        self,
        entity: str,
        subnet: Optional[str],
        family: str,
        moe_score: float,
        combined_score: float,
        gating_weights: Dict[str, float],
        correlation_key: Optional[str] = None,
        incident_entity: Optional[str] = None,
    ) -> FidelityDecision:
        now = time.time()
        self._prune(now)

        for rule in self.suppression_rules:
            if rule.matches(entity, subnet, family):
                return FidelityDecision("suppress", "", "low", 0.0, self._decayed_risk(entity, now), 0, rule.reason)

        signal = self.compute_signal(moe_score, combined_score, gating_weights)
        severity = self.severity_from_signal(signal)

        key = (correlation_key or entity, family)
        existing = self._incidents.get(key)

        if existing and (now - existing.last_seen) <= self.incident_window:
            existing.count += 1
            existing.last_seen = now
            existing.peak_signal = max(existing.peak_signal, signal)
            existing.sources.add(entity)
            sev = self.severity_from_signal(existing.peak_signal)
            # Do not inflate risk once per packet. Escalate only when an
            # incident reaches meaningful recurrence milestones.
            if existing.count in {2, 5, 10, 25, 50, 100}:
                risk = self._bump_risk(entity, sev, signal, now, scale=0.45)
            else:
                risk = self._decayed_risk(entity, now)
            return FidelityDecision("merge", existing.id, sev, signal, risk, existing.count,
                                    correlation_entity=existing.entity, unique_entities=len(existing.sources))
        elif existing and (now - existing.last_seen) <= self.suppression_window:
            # Suppress re-arrivals beyond the correlation window.
            self._suppressions[key] = now
            return FidelityDecision("suppress", existing.id, severity, signal, self._decayed_risk(entity, now), existing.count, "within suppression window")

        self._counter += 1
        incident_id = f"inc_{int(now)}_{self._counter:06d}"
        display_entity = incident_entity or entity
        self._incidents[key] = _Incident(incident_id, display_entity, family, now, now, 1, signal, {entity})
        risk = self._bump_risk(entity, severity, signal, now)
        return FidelityDecision("create", incident_id, severity, signal, risk, 1,
                                correlation_entity=display_entity, unique_entities=1)

    # ------------------------------------------------------------------ #
    def add_suppression_rule(self, rule: SuppressionRule) -> None:
        self.suppression_rules.append(rule)

    def remove_suppression_rule(self, index: int) -> None:
        if 0 <= index < len(self.suppression_rules):
            self.suppression_rules.pop(index)

    def active_incident_count(self) -> int:
        self._prune(time.time())
        return len(self._incidents)

    def entity_risks(self) -> Dict[str, float]:
        now = time.time()
        return {e: self._decayed_risk(e, now) for e in self._entity_scores}
