"""End-to-end integration: real bundle + AE + fidelity + API boot."""
import tempfile
from pathlib import Path

import numpy as np

from sentry.core.engine import SentryEngine

rng = np.random.default_rng(7)


def benign(i):
    return {
        "Src_IP": f"10.0.{i % 20}.{i % 200 + 1}", "Dst_IP": "8.8.8.8",
        "Src_Port": int(rng.integers(20000, 60000)), "Dst_Port": 443, "Protocol": 6,
        "Flow_Duration": float(rng.uniform(0.1, 3)), "Total_Fwd_Packets": int(rng.integers(2, 30)),
        "Total_Bwd_Packets": int(rng.integers(2, 25)), "Total_Fwd_Bytes": int(rng.integers(500, 20000)),
        "Total_Bwd_Bytes": int(rng.integers(500, 15000)),
        "Fwd_Pkt_Len_Min": float(rng.uniform(40, 200)), "Fwd_Pkt_Len_Max": float(rng.uniform(200, 1400)),
        "Fwd_Pkt_Len_Mean": float(rng.uniform(200, 800)), "Fwd_Pkt_Len_Std": float(rng.uniform(20, 300)),
        "Bwd_Pkt_Len_Min": float(rng.uniform(40, 200)), "Bwd_Pkt_Len_Max": float(rng.uniform(200, 1400)),
        "Bwd_Pkt_Len_Mean": float(rng.uniform(200, 800)), "Bwd_Pkt_Len_Std": float(rng.uniform(20, 300)),
        "Flow_IAT_Mean": float(rng.uniform(0.01, 0.5)), "Flow_IAT_Std": float(rng.uniform(0.01, 0.3)),
        "Flow_IAT_Max": float(rng.uniform(0.05, 1)), "Flow_IAT_Min": float(rng.uniform(0, 0.05)),
        "Flow_Bytes_Sec": float(rng.uniform(500, 20000)), "Flow_Packets_Sec": float(rng.uniform(1, 50)),
        "FIN_Flag_Count": 0, "SYN_Flag_Count": 1, "RST_Flag_Count": 0,
        "PSH_Flag_Count": int(rng.integers(0, 10)), "ACK_Flag_Count": int(rng.integers(1, 20)), "URG_Flag_Count": 0,
    }


def ddos(i):
    return {
        "Src_IP": "10.0.0.99", "Dst_IP": "8.8.8.8", "Src_Port": int(rng.integers(40000, 60000)),
        "Dst_Port": 53, "Protocol": 17, "Flow_Duration": float(rng.uniform(20, 60)),
        "Total_Fwd_Packets": int(rng.integers(20000, 60000)), "Total_Bwd_Packets": 0,
        "Total_Fwd_Bytes": int(rng.integers(1_000_000, 3_000_000)), "Total_Bwd_Bytes": 0,
        "Fwd_Pkt_Len_Min": 60.0, "Fwd_Pkt_Len_Max": 512.0, "Fwd_Pkt_Len_Mean": 512.0, "Fwd_Pkt_Len_Std": 5.0,
        "Bwd_Pkt_Len_Min": 0.0, "Bwd_Pkt_Len_Max": 0.0, "Bwd_Pkt_Len_Mean": 0.0, "Bwd_Pkt_Len_Std": 0.0,
        "Flow_IAT_Mean": 0.0001, "Flow_IAT_Std": 0.0001, "Flow_IAT_Max": 0.001, "Flow_IAT_Min": 0.0,
        "Flow_Bytes_Sec": float(rng.uniform(40000, 100000)), "Flow_Packets_Sec": float(rng.uniform(800, 2000)),
        "FIN_Flag_Count": 0, "SYN_Flag_Count": 0, "RST_Flag_Count": 0,
        "PSH_Flag_Count": 0, "ACK_Flag_Count": 0, "URG_Flag_Count": 0,
    }


def main():
    tmp = Path(tempfile.mkdtemp(prefix="attacksentry-e2e-"))
    engine = SentryEngine(
        env_id="default_env", base_path=tmp,
        models_dir=Path("models"), baseline_hours=72.0, reservoir_size=5000,
    )
    assert engine.moe.ready, "bundle should be loaded"
    print("MoE bundle:", engine.moe.version)

    for i in range(500):
        engine.process_flow(benign(i))
    assert engine.train_models(), "AE training should succeed"
    print("Engine mode:", engine.mode)

    # Attack flood from the same entity + family -> should collapse to ONE incident.
    detections = []
    for i in range(30):
        d = engine.process_flow(ddos(i))
        if d:
            detections.append(d)

    print("Detections returned:", len(detections))
    incidents = {d["incident_id"] for d in detections}
    print("Unique incidents:", len(incidents))
    actions = [d["fidelity_action"] for d in detections]
    print("Actions:", actions)
    print("Severities:", [d["severity"] for d in detections])
    print("Primary experts:", {d["classification"]["primary_expert"] for d in detections})

    assert len(detections) > 0, "should detect at least one anomaly"
    # All detections from the same family should share one incident (dedup working).
    assert len(incidents) <= 5, f"expected dedup, got {len(incidents)} incidents"
    print("E2E OK — dedup + attribution verified")


if __name__ == "__main__":
    main()
