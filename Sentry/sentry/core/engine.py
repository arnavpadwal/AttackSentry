"""SentryEngine — orchestrates baselining, anomaly detection, MoE attribution
and incident fidelity for every ingested flow.

Lifecycle:
  monitoring  -> collect per-entity baselines + reservoirs
  training    -> fit the hierarchical autoencoder on collected reservoirs
  active      -> score flows: AE anomaly -> MoE classification -> fidelity
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np

from ..metrics import (
    ACTIVE_ENTITIES,
    ANOMALIES_DETECTED,
    ENGINE_MODE,
    FLOWS_PROCESSED,
    INFERENCE_LATENCY,
)
from .baseline import BaselineTracker
from .families import canonical_family
from .features import FeatureExtractor
from .fidelity import AlertFidelityEngine
from .models import HierarchicalSentryModel
from .moe import MoEPipeline
from .registry import EntityRegistry

logger = logging.getLogger("sentry.engine")

_MODE_VALUE = {"monitoring": 0, "training": 1, "active": 2}

_EXPERT_TO_ATTACK = {
    "Varuna": "Enterprise-borne Attack",
    "Rudra": "Distributed Denial of Service (DDoS)",
    "Maya": "Botnet Activity",
    "Indra": "Cloud-infrastructure Attack",
    "Garuda": "Generic Network Exploit",
}


class SentryEngine:
    def __init__(self, env_id: str, base_path: Path, models_dir: Path,
                 llm=None, baseline_hours: float = 72.0,
                 reservoir_size: int = 5000,
                 incident_window: int = 300, suppression_window: int = 600,
                 decay_hours: float = 24.0,
                 min_attack_confidence: float = 0.5,
                 strong_anomaly_threshold: float = 50.0,
                 zero_day_max_confidence: float = 0.10):
        self.env_id = env_id
        self.base_path = Path(base_path)
        self.env_dir = self.base_path / env_id
        self.env_dir.mkdir(parents=True, exist_ok=True)

        self.min_attack_confidence = min_attack_confidence
        self.strong_anomaly_threshold = strong_anomaly_threshold
        self.zero_day_max_confidence = zero_day_max_confidence

        self.registry = EntityRegistry(self.env_dir / "registry_config.json")
        self.extractor = FeatureExtractor()
        self.baseline = BaselineTracker(self.env_dir / "baseline.db", reservoir_size)
        self.moe = MoEPipeline(models_dir)
        self.fidelity = AlertFidelityEngine(incident_window, suppression_window, decay_hours)
        self.llm = llm
        self.sentry_model: Optional[HierarchicalSentryModel] = None

        self.state_file = self.env_dir / "state.json"
        self.baseline_hours = baseline_hours
        self.load_state()

        if self.state["mode"] == "active":
            self.load_sentry_model()

        self._publish = lambda detection: None  # set by the ingestion pipeline

    # ------------------------------------------------------------------ #
    # State
    # ------------------------------------------------------------------ #
    def load_state(self) -> None:
        if self.state_file.exists():
            with open(self.state_file) as f:
                self.state = json.load(f)
        else:
            self.state = {
                "mode": "monitoring",
                "start_time": datetime.now(timezone.utc).isoformat(),
                "monitoring_duration_hours": self.baseline_hours,
                "flows_processed": 0,
                "model_version": "none",
            }
            self.save_state()

    def save_state(self) -> None:
        with open(self.state_file, "w") as f:
            json.dump(self.state, f, indent=2)

    def reset(self, learn_time: Optional[float] = None) -> None:
        self.state = {
            "mode": "monitoring",
            "start_time": datetime.now(timezone.utc).isoformat(),
            "monitoring_duration_hours": learn_time or self.baseline_hours,
            "flows_processed": 0,
            "model_version": "none",
        }
        self.save_state()
        self.baseline.clear_all()
        self.sentry_model = None
        logger.info("Engine reset — fresh %sh monitoring phase.", self.state["monitoring_duration_hours"])

    @property
    def mode(self) -> str:
        return self.state["mode"]

    def load_sentry_model(self) -> None:
        model_path = self.env_dir / "sentry_model.pt"
        if model_path.exists():
            self.sentry_model = HierarchicalSentryModel.load(str(model_path))
            logger.info("Loaded Sentry anomaly model.")
        else:
            logger.warning("No anomaly model found — reverting to monitoring.")
            self.state["mode"] = "monitoring"
            self.save_state()

    def is_monitoring_complete(self) -> bool:
        start = datetime.fromisoformat(self.state["start_time"])
        dur = timedelta(hours=float(self.state["monitoring_duration_hours"]))
        return datetime.now(timezone.utc) >= (start + dur)

    def _monitoring_progress(self) -> float:
        if self.state["mode"] != "monitoring":
            return 100.0
        start = datetime.fromisoformat(self.state["start_time"])
        dur = float(self.state["monitoring_duration_hours"])
        elapsed = (datetime.now(timezone.utc) - start).total_seconds() / 3600.0
        return min(100.0, max(0.0, elapsed / dur * 100.0)) if dur > 0 else 100.0

    # ------------------------------------------------------------------ #
    # Flow processing
    # ------------------------------------------------------------------ #
    def process_flow(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        t0 = time.perf_counter()
        src_ip = flow.get("Src_IP")
        if not src_ip:
            return None

        context = self.registry.get_context(
            src_ip,
            provided_group=flow.get("Subnet_Group"),
            provided_identity=flow.get("User_ID"),
            provided_identity_type=flow.get("Identity_Type"),
        )

        try:
            features_df = self.extractor.extract([flow])
        except Exception as exc:
            logger.warning("Feature extraction failed for %s: %s", src_ip, exc)
            return None

        if features_df.empty:
            return None
        feat_vec = features_df.iloc[0].to_dict()

        detection: Optional[Dict[str, Any]] = None

        if self.state["mode"] == "monitoring":
            self._learn(src_ip, context, feat_vec, features_df.iloc[0].values)
            if self.is_monitoring_complete():
                logger.info("Monitoring complete — transitioning to training.")
                self.state["mode"] = "training"
                self.save_state()
                try:
                    self.train_models()
                except Exception as exc:
                    logger.error("Auto-training failed (%s) — reverting to monitoring.", exc)
                    self.state["mode"] = "monitoring"
                    self.save_state()

        elif self.state["mode"] == "training":
            # Complete a pending training pass (reservoirs already collected).
            try:
                self.train_models()
            except Exception as exc:
                logger.error("Training failed (%s) — reverting to monitoring.", exc)
                self.state["mode"] = "monitoring"
                self.save_state()

        elif self.state["mode"] == "active":
            detection = self._score(flow, context, features_df)

        ENGINE_MODE.set(_MODE_VALUE.get(self.state["mode"], 0))
        INFERENCE_LATENCY.observe(time.perf_counter() - t0)
        return detection

    def _learn(self, src_ip, context, feat_vec, vec) -> None:
        self.baseline.update_entity(src_ip, "host", feat_vec)
        self.baseline.update_entity(context["group"], "group", feat_vec)
        self.baseline.update_entity("GLOBAL", "global", feat_vec)
        self.baseline.add_to_reservoir(src_ip, vec)
        self.baseline.add_to_reservoir(context["group"], vec)
        self.baseline.add_to_reservoir("GLOBAL", vec)
        self.state["flows_processed"] = int(self.state.get("flows_processed", 0)) + 1
        FLOWS_PROCESSED.inc()
        if self.state["flows_processed"] % 1000 == 0:
            self.save_state()

    def _score(self, flow, context, features_df) -> Optional[Dict[str, Any]]:
        if not self.sentry_model:
            self.load_sentry_model()
            if not self.sentry_model:
                return None

        x = features_df.values.astype(np.float32)
        scores = self.sentry_model.get_anomaly_scores(x, group=context["group"], host=flow.get("Src_IP"))
        is_anomaly, combined = self.sentry_model.is_anomaly(scores)

        if not is_anomaly:
            return None

        moe = self.moe.predict(features_df)
        ANOMALIES_DETECTED.labels(moe.get("primary_expert") or "unknown").inc()

        # Confidence gate: an AE anomaly only becomes an incident when the MoE
        # confirms an attack, or the deviation is extreme. The latter is the
        # zero-day path: keep the evidence, but do not pretend a specialist
        # recognised it.
        moe_score = moe.get("moe_score", 0.0)
        if moe_score < self.min_attack_confidence and combined < self.strong_anomaly_threshold:
            return None
        zero_day = moe_score < self.zero_day_max_confidence and combined >= self.strong_anomaly_threshold

        if zero_day:
            predicted_attack = "Zero-Day / Unknown Anomaly"
            attack_family = "Behavioral Anomaly"
        else:
            predicted_attack = self._attribute_attack(flow, moe.get("primary_expert"))
            attack_family = canonical_family(predicted_attack)
        correlation_key, incident_entity = self._correlation_scope(predicted_attack, flow)

        decision = self.fidelity.evaluate(
            entity=flow.get("Src_IP"),
            subnet=flow.get("Source_Subnet") or flow.get("Subnet_Group"),
            family=attack_family,
            moe_score=moe.get("moe_score", 0.0),
            combined_score=combined,
            gating_weights=moe.get("gating_weights", {}),
            correlation_key=correlation_key,
            incident_entity=incident_entity,
        )

        reason = self._top_deviations(scores)

        detection = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "env_id": self.env_id,
            "incident_id": decision.incident_id,
            "fidelity_action": decision.action,
            "incident_count": decision.incident_count,
            "unique_entities": decision.unique_entities,
            "correlation_entity": decision.correlation_entity,
            "severity": decision.severity,
            "confidence": round(decision.confidence, 4),
            "entity_risk": round(decision.entity_risk, 1),
            "anomaly_score": round(combined, 4),
            "global_score": round(scores["global_score"], 6),
            "group_score": round(scores["group_score"], 6),
            "host_score": round(scores["host_score"], 6),
            "detection_type": predicted_attack,
            "attack_family": attack_family,
            "zero_day": zero_day,
            "reason": reason,
            "context": {
                "src_ip": flow.get("Src_IP"),
                "dst_ip": flow.get("Dst_IP"),
                "dst_port": flow.get("Dst_Port"),
                "protocol": flow.get("Protocol"),
                "group": context["group"],
                "identity": context["identity"],
                "identity_type": context["identity_type"],
                "device_type": flow.get("Identity_Type"),
                "process_name": flow.get("Process_Name"),
                "process_id": flow.get("Process_ID"),
                "subnet": flow.get("Source_Subnet") or flow.get("Subnet_Group"),
            },
            "classification": {
                "attack_family": attack_family,
                "zero_day": zero_day,
                "primary_expert": moe.get("primary_expert"),
                "expert_distribution": moe.get("gating_weights", {}),
                "expert_probs": moe.get("expert_probs", {}),
                "moe_score": moe.get("moe_score", 0.0),
                "is_attack": moe.get("is_attack", False),
            },
            "triggering_log": self._sanitize(flow),
        }

        if decision.action == "suppress":
            logger.info("Suppressed %s for %s", attack_family, flow.get("Src_IP"))
            if self._publish:
                self._publish(detection)
            return None

        logger.warning(
            "INCIDENT [%s] %s | %s | entity=%s | count=%d | conf=%.2f",
            decision.action.upper(), decision.severity, predicted_attack,
            flow.get("Src_IP"), decision.incident_count, decision.confidence,
        )

        # LLM triage is performed by the (async) ingestion pipeline after
        # persistence, keeping the engine CPU-bound and synchronous.
        if self._publish:
            self._publish(detection)
        return detection

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _top_deviations(self, scores) -> str:
        feat_names = self.extractor.selected_features
        try:
            total = scores["feature_errors"]["host"] + scores["feature_errors"]["group"]
            top = np.argsort(total)[-3:][::-1]
            reasons = []
            for idx in top:
                name = feat_names[idx] if idx < len(feat_names) else f"f{idx}"
                reasons.append(f"Unusual {name.replace('_', ' ')}")
            return f"Anomalous behavior detected: {', '.join(reasons)}"
        except Exception:
            return "Anomalous behavior detected."

    @staticmethod
    def _attribute_attack(flow: Dict[str, Any], primary_expert: Optional[str]) -> str:
        port = flow.get("Dst_Port")
        proto = flow.get("Protocol")
        fwd_pkts = flow.get("Total_Fwd_Packets", 1)
        fwd_bytes = flow.get("Total_Fwd_Bytes", 0)
        dst_ip = flow.get("Dst_IP", "")

        # Large outbound transfer over TCP to an external host => exfiltration.
        if primary_expert in ("Rudra", "Garuda", "Varuna") and proto == 6 and fwd_bytes >= 1_000_000:
            if not dst_ip.startswith(("192.168.", "10.", "172.")):
                return "Data Exfiltration"

        if primary_expert == "Rudra":
            m = {53: "DDoS (DNS Reflection)", 123: "DDoS (NTP Reflection)",
                 1900: "DDoS (SSDP Reflection)", 389: "DDoS (LDAP Reflection)",
                 161: "DDoS (SNMP Reflection)"}
            if port in m:
                return m[port]
            if proto == 17:
                return "DDoS (UDP Flood)"
            return "DDoS (TCP Flood)"
        if primary_expert == "Indra":
            if port == 22:
                return "SSH-Bruteforce"
            if port == 21:
                return "FTP-BruteForce"
            if port in (80, 443):
                return "DDoS (HTTP Flood)" if fwd_pkts > 50 else "DoS (Slowloris/SlowHTTPTest)"
            if port == 3389:
                return "RDP Brute Force"
            if port and port not in (80, 443, 22, 21, 3389) and fwd_pkts <= 2:
                return "Port Scan"
            return "Cloud Infrastructure Exploit"
        if primary_expert == "Maya":
            if port == 6667:
                return "IRC-Botnet (Neris/Rbot)"
            if proto == 6 and fwd_pkts <= 5:
                return "C2 Beaconing"
            return "Botnet Activity"
        if primary_expert == "Garuda":
            if flow.get("URG_Flag_Count", 0) > 0:
                return "Fuzzing / Exploit Probing"
            if port in (20, 21, 22, 23, 25, 53, 80, 110, 143, 443):
                return "Service Exploit"
            return "Fuzzing / Analysis Attempt" if port and port > 1024 else "Generic Exploit / Shellcode"
        if primary_expert == "Varuna":
            if port == 22:
                return "SSH Brute Force"
            if port == 21:
                return "FTP Brute Force"
            if port in (80, 443):
                return "Web Attack (SQLi/XSS/Infiltration)"
            if port == 3389:
                return "RDP Infiltration"
            return "Enterprise Network Anomaly"
        return _EXPERT_TO_ATTACK.get(primary_expert, "Unknown Anomaly")

    @staticmethod
    def _correlation_scope(attack: str, flow: Dict[str, Any]) -> tuple[str, str]:
        """Return an attack-aware incident key and the entity shown to analysts."""
        src = str(flow.get("Src_IP") or "unknown")
        dst = str(flow.get("Dst_IP") or "unknown")
        port = str(flow.get("Dst_Port") or 0)
        label = attack.casefold()
        if "ddos" in label or "dos (" in label or "flood" in label:
            # The victim host is the case; port/protocol are evidence, not a
            # reason to open a separate incident per service.
            return f"target:{dst}", dst
        if "brute" in label:
            return f"service:{dst}:{port}:{attack}", dst
        if "port scan" in label or "recon" in label:
            return f"scanner:{src}:{dst}", src
        return f"source:{src}", src

    @staticmethod
    def _sanitize(flow: Dict[str, Any]) -> Dict[str, Any]:
        """Strip non-serialisable values from a raw flow record."""
        out = {}
        for k, v in flow.items():
            if isinstance(v, (str, int, float, bool)) or v is None:
                out[k] = v
            else:
                out[k] = str(v)
        return out

    @staticmethod
    def _fallback_playbook(detection: Dict[str, Any]) -> Dict[str, Any]:
        sev = detection.get("severity", "medium")
        ip = detection.get("context", {}).get("src_ip", "Unknown")
        return {
            "attack_summary": f"Automated detection: {detection.get('detection_type', 'Unknown')} from {ip}.",
            "technical_analysis": detection.get("reason", ""),
            "severity": sev,
            "confidence": "medium",
            "mitre_attack": {"tactic": "Unknown", "technique": "Unknown", "description": "LLM offline"},
            "playbook": [
                {"step_id": 1, "title": "Investigate Source Host", "description": f"Review recent activity from {ip}.", "action_type": "investigate", "target": ip, "priority": "immediate", "auto_executable": False, "command_hint": None},
                {"step_id": 2, "title": "Escalate to SOC", "description": "Forward this alert to the SOC lead for manual review.", "action_type": "escalate", "target": "SOC Team", "priority": "urgent", "auto_executable": False, "command_hint": None},
            ],
            "false_positive_assessment": "LLM service unavailable — manual review required.",
            "_llm_error": "LLM unavailable",
        }

    # ------------------------------------------------------------------ #
    # Training
    # ------------------------------------------------------------------ #
    def train_models(self) -> bool:
        from .models import HierarchicalSentryModel

        logger.info("Starting auto-training…")
        global_res = self.baseline.get_reservoir("GLOBAL")
        if len(global_res) < 100:
            logger.warning("Insufficient global data (%d) — extending monitoring.", len(global_res))
            self.state["mode"] = "monitoring"
            self.save_state()
            return False

        group_data = self._pool_reservoirs("group")
        host_data = self._pool_reservoirs("host", cap_entities=500)

        model = HierarchicalSentryModel(in_dim=global_res.shape[1])
        model.fit(global_data=global_res, group_data=group_data, host_data=host_data)

        # Per-entity thresholds from each group/host reservoir.
        model.group_thresholds = self._entity_thresholds(model, "group")
        model.host_thresholds = self._entity_thresholds(model, "host")

        model_path = self.env_dir / "sentry_model.pt"
        model.save(str(model_path))

        self.state["mode"] = "active"
        self.state["model_version"] = f"ae-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}"
        self.save_state()
        self.sentry_model = model
        ACTIVE_ENTITIES.set(len(self.baseline.get_all_by_type("host")))
        logger.info("Model trained and active. System is LIVE.")
        return True

    def _pool_reservoirs(self, entity_type: str, cap_entities: int = 10_000) -> Optional[np.ndarray]:
        res = self.baseline.get_all_by_type(entity_type)
        if not res:
            return None
        arrays = list(res.values())[:cap_entities]
        arrays = [a for a in arrays if a.ndim == 2 and a.shape[0] > 0]
        if not arrays:
            return None
        return np.vstack(arrays)

    def _entity_thresholds(self, model, entity_type: str) -> Dict[str, float]:
        """Compute a per-entity reconstruction-error threshold using the fitted AEs."""
        res = self.baseline.get_all_by_type(entity_type)
        thresholds: Dict[str, float] = {}
        for eid, arr in res.items():
            if arr.ndim != 2 or arr.shape[0] < 50:
                continue
            try:
                import torch
                ae = model.group_ae if entity_type == "group" else model.host_ae
                xt = model._scale(arr.astype(np.float32))
                ae.eval()
                with torch.no_grad():
                    recon = ae(xt)
                    errs = torch.mean((xt - recon) ** 2, dim=1).numpy()
                thresholds[eid] = float(np.quantile(errs, 0.99))
            except Exception as exc:
                logger.debug("Threshold for %s failed: %s", eid, exc)
        return thresholds
