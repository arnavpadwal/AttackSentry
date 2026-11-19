"""End-to-end engine test: monitoring -> training -> active scoring."""
from __future__ import annotations

from pathlib import Path

import numpy as np

from sentry.core.engine import SentryEngine

_SEED = 42


def _benign_flow(rng: np.random.Generator, i: int) -> dict:
    return {
        "Src_IP": f"10.0.{i % 50}.{i % 250 + 1}",
        "Dst_IP": "8.8.8.8",
        "Src_Port": int(rng.integers(20000, 60000)),
        "Dst_Port": 443,
        "Protocol": 6,
        "Flow_Duration": float(rng.uniform(0.1, 3.0)),
        "Total_Fwd_Packets": int(rng.integers(2, 30)),
        "Total_Bwd_Packets": int(rng.integers(2, 25)),
        "Total_Fwd_Bytes": int(rng.integers(500, 20000)),
        "Total_Bwd_Bytes": int(rng.integers(500, 15000)),
        "Fwd_Pkt_Len_Min": float(rng.uniform(40, 200)),
        "Fwd_Pkt_Len_Max": float(rng.uniform(200, 1400)),
        "Fwd_Pkt_Len_Mean": float(rng.uniform(200, 800)),
        "Fwd_Pkt_Len_Std": float(rng.uniform(20, 300)),
        "Bwd_Pkt_Len_Min": float(rng.uniform(40, 200)),
        "Bwd_Pkt_Len_Max": float(rng.uniform(200, 1400)),
        "Bwd_Pkt_Len_Mean": float(rng.uniform(200, 800)),
        "Bwd_Pkt_Len_Std": float(rng.uniform(20, 300)),
        "Flow_IAT_Mean": float(rng.uniform(0.01, 0.5)),
        "Flow_IAT_Std": float(rng.uniform(0.01, 0.3)),
        "Flow_IAT_Max": float(rng.uniform(0.05, 1.0)),
        "Flow_IAT_Min": float(rng.uniform(0.0, 0.05)),
        "Flow_Bytes_Sec": float(rng.uniform(500, 20000)),
        "Flow_Packets_Sec": float(rng.uniform(1, 50)),
        "FIN_Flag_Count": 0, "SYN_Flag_Count": 1, "RST_Flag_Count": 0,
        "PSH_Flag_Count": int(rng.integers(0, 10)),
        "ACK_Flag_Count": int(rng.integers(1, 20)),
        "URG_Flag_Count": 0,
    }


def _attack_flow() -> dict:
    """Extreme flow that should deviate strongly from the benign baseline."""
    return {
        "Src_IP": "10.0.1.7", "Dst_IP": "8.8.8.8", "Src_Port": 55555, "Dst_Port": 53,
        "Protocol": 17, "Flow_Duration": 60.0,
        "Total_Fwd_Packets": 100000, "Total_Bwd_Packets": 0,
        "Total_Fwd_Bytes": 50_000_000, "Total_Bwd_Bytes": 0,
        "Fwd_Pkt_Len_Min": 500.0, "Fwd_Pkt_Len_Max": 1500.0,
        "Fwd_Pkt_Len_Mean": 512.0, "Fwd_Pkt_Len_Std": 10.0,
        "Bwd_Pkt_Len_Min": 0.0, "Bwd_Pkt_Len_Max": 0.0, "Bwd_Pkt_Len_Mean": 0.0, "Bwd_Pkt_Len_Std": 0.0,
        "Flow_IAT_Mean": 0.0001, "Flow_IAT_Std": 0.0001, "Flow_IAT_Max": 0.001, "Flow_IAT_Min": 0.0,
        "Flow_Bytes_Sec": 833_333.0, "Flow_Packets_Sec": 1666.0,
        "FIN_Flag_Count": 0, "SYN_Flag_Count": 0, "RST_Flag_Count": 0,
        "PSH_Flag_Count": 0, "ACK_Flag_Count": 0, "URG_Flag_Count": 0,
    }


def _make_engine(tmp_path: Path) -> SentryEngine:
    return SentryEngine(
        env_id="test_env",
        base_path=tmp_path,
        models_dir=tmp_path / "models",
        baseline_hours=72.0,
        reservoir_size=2000,
    )


def test_full_lifecycle(tmp_path):
    rng = np.random.default_rng(_SEED)
    engine = _make_engine(tmp_path)

    # Monitoring: collect baseline.
    for i in range(400):
        engine.process_flow(_benign_flow(rng, i))

    assert engine.mode == "monitoring"
    assert engine.state["flows_processed"] == 400

    # Training.
    ok = engine.train_models()
    assert ok is True
    assert engine.mode == "active"
    assert engine.sentry_model is not None

    # Benign flow -> no detection (allow a rare FP but assert structure).
    for i in range(20):
        det = engine.process_flow(_benign_flow(rng, 1000 + i))
        if det is not None:
            assert "incident_id" in det

    # Attack flow -> detection with required fields.
    det = engine.process_flow(_attack_flow())
    assert det is not None, "expected an anomaly detection for the attack flow"
    for key in ("incident_id", "severity", "confidence", "detection_type",
                "anomaly_score", "context", "classification", "fidelity_action"):
        assert key in det, f"missing {key}"
    assert "primary_expert" in det["classification"]
    # No bundle is loaded in this fixture, so a strong AE deviation is the
    # explicit zero-day path rather than a forced known attribution.
    assert det["classification"]["zero_day"] is True
    assert det["detection_type"] == "Zero-Day / Unknown Anomaly"
    assert det["attack_family"] == "Behavioral Anomaly"
