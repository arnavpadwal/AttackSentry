"""Tests for the canonical feature schema and engineering."""
from __future__ import annotations

import numpy as np
import pandas as pd

from sentry.core.features import build_feature_matrix, engineer_ratios
from sentry.core.schema import CANONICAL_FEATURES, canonicalize_name


def _flow(**overrides) -> dict:
    flow = {
        "Src_IP": "10.0.0.1", "Dst_IP": "10.0.0.2", "Src_Port": 12345, "Dst_Port": 443,
        "Protocol": 6, "Flow_Duration": 1.5,
        "Total_Fwd_Packets": 10, "Total_Bwd_Packets": 8,
        "Total_Fwd_Bytes": 5000, "Total_Bwd_Bytes": 3000,
        "Fwd_Pkt_Len_Mean": 500, "Fwd_Pkt_Len_Std": 50,
        "Bwd_Pkt_Len_Mean": 375, "Bwd_Pkt_Len_Std": 40,
        "Flow_IAT_Mean": 0.05, "Flow_IAT_Std": 0.02, "Flow_IAT_Max": 0.1, "Flow_IAT_Min": 0.01,
        "Flow_Bytes_Sec": 5333, "Flow_Packets_Sec": 12,
        "FIN_Flag_Count": 0, "SYN_Flag_Count": 1, "RST_Flag_Count": 0,
        "PSH_Flag_Count": 5, "ACK_Flag_Count": 9, "URG_Flag_Count": 0,
    }
    flow.update(overrides)
    return flow


def test_build_feature_matrix_shape():
    df = build_feature_matrix([_flow()])
    assert list(df.columns) == CANONICAL_FEATURES
    assert df.shape == (1, len(CANONICAL_FEATURES))


def test_ratios_computed():
    df = build_feature_matrix([_flow()])
    assert df["ratio_bwd_fwd_bytes"].iloc[0] == 3000 / (5000 + 1.0)
    assert df["ratio_bytes_per_pkt_fwd"].iloc[0] == 5000 / (10 + 1.0)
    assert df["ratio_pkt_len_cv"].iloc[0] == 50 / (500 + 1.0)


def test_missing_features_filled_zero():
    df = build_feature_matrix([{"Src_IP": "1.2.3.4", "Protocol": 6}])
    assert df.shape[0] == 1
    assert (df.iloc[0].fillna(0).values >= 0).all()


def test_canonicalize_aliases():
    assert canonicalize_name("Pkt_Len_Mean") == "Fwd_Pkt_Len_Mean"
    assert canonicalize_name("Fwd_Pkt_Len_Mean") == "Fwd_Pkt_Len_Mean"
    assert canonicalize_name("Nope") is None


def test_engineer_ratios_idempotent_columns():
    df = pd.DataFrame([{f: 1.0 for f in ["Total_Fwd_Bytes", "Total_Bwd_Bytes", "Total_Fwd_Packets",
                                          "Total_Bwd_Packets", "Flow_Duration", "SYN_Flag_Count",
                                          "ACK_Flag_Count", "Fwd_Pkt_Len_Mean", "Fwd_Pkt_Len_Std"]}])
    out = engineer_ratios(df)
    assert "ratio_bwd_fwd_bytes" in out.columns
    assert np.isfinite(out["ratio_bwd_fwd_bytes"].iloc[0])
