"""Feature engineering: canonical vector + derived ratios.

This is the *only* place ratio features are computed so that training and
inference remain bit-identical. The offline pipeline (training/8_build_bundle.py)
imports ``engineer_ratios`` from here.
"""
from __future__ import annotations

from typing import Dict, List, Sequence

import numpy as np
import pandas as pd

from .schema import (
    BASE_FEATURES,
    CANONICAL_FEATURES,
    RATIO_FEATURES,
    canonicalize_name,
)

_EPS = 1.0


def engineer_ratios(df: pd.DataFrame) -> pd.DataFrame:
    """Add derived ratio features to a DataFrame containing base features.

    Mutates a copy; missing source columns are treated as absent (feature = 0).
    """
    df = df.copy()
    cols = set(df.columns)

    def _has(*names: str) -> bool:
        return all(n in cols for n in names)

    if _has("Total_Bwd_Bytes", "Total_Fwd_Bytes"):
        df["ratio_bwd_fwd_bytes"] = (
            df["Total_Bwd_Bytes"] / (df["Total_Fwd_Bytes"] + _EPS)
        ).clip(0, 1000)
    if _has("Total_Bwd_Packets", "Total_Fwd_Packets"):
        df["ratio_bwd_fwd_pkts"] = (
            df["Total_Bwd_Packets"] / (df["Total_Fwd_Packets"] + _EPS)
        ).clip(0, 1000)
    if _has("Total_Fwd_Bytes", "Total_Fwd_Packets"):
        df["ratio_bytes_per_pkt_fwd"] = (
            df["Total_Fwd_Bytes"] / (df["Total_Fwd_Packets"] + _EPS)
        ).clip(0, 65536)
    if _has("Total_Fwd_Bytes", "Flow_Duration"):
        df["ratio_fwd_throughput"] = (
            df["Total_Fwd_Bytes"] / (df["Flow_Duration"] + _EPS)
        ).clip(0, 1e6)

    if _has("SYN_Flag_Count", "Total_Fwd_Packets"):
        df["ratio_syn_per_pkt"] = (
            df["SYN_Flag_Count"] / (df["Total_Fwd_Packets"] + _EPS)
        ).clip(0, 1)
    if _has("ACK_Flag_Count", "SYN_Flag_Count"):
        df["ratio_ack_syn"] = (
            df["ACK_Flag_Count"] / (df["SYN_Flag_Count"] + _EPS)
        ).clip(0, 1000)
    if _has("RST_Flag_Count", "Total_Fwd_Packets"):
        df["ratio_rst_per_pkt"] = (
            df["RST_Flag_Count"] / (df["Total_Fwd_Packets"] + _EPS)
        ).clip(0, 1)
    if _has("PSH_Flag_Count", "ACK_Flag_Count"):
        df["ratio_psh_ack"] = (
            df["PSH_Flag_Count"] / (df["ACK_Flag_Count"] + _EPS)
        ).clip(0, 10)
    if _has("FIN_Flag_Count", "SYN_Flag_Count"):
        df["ratio_fin_syn"] = (
            df["FIN_Flag_Count"] / (df["SYN_Flag_Count"] + _EPS)
        ).clip(0, 10)

    if _has("Fwd_Pkt_Len_Std", "Fwd_Pkt_Len_Mean"):
        df["ratio_pkt_len_cv"] = (
            df["Fwd_Pkt_Len_Std"] / (df["Fwd_Pkt_Len_Mean"] + _EPS)
        ).clip(0, 10)
    if _has("Flow_IAT_Std", "Flow_IAT_Mean"):
        df["ratio_iat_cv"] = (
            df["Flow_IAT_Std"] / (df["Flow_IAT_Mean"] + _EPS)
        ).clip(0, 10)
    if _has("Flow_IAT_Max", "Flow_IAT_Min", "Flow_IAT_Mean"):
        df["ratio_iat_range"] = (
            (df["Flow_IAT_Max"] - df["Flow_IAT_Min"]) / (df["Flow_IAT_Mean"] + _EPS)
        ).clip(0, 100)
    if _has("Flow_IAT_Std"):
        df["ratio_fwd_bwd_iat_std"] = df["Flow_IAT_Std"].clip(0, 100)
    if _has("Bwd_Pkt_Len_Mean", "Fwd_Pkt_Len_Mean"):
        df["ratio_bwd_fwd_pkt_size"] = (
            df["Bwd_Pkt_Len_Mean"] / (df["Fwd_Pkt_Len_Mean"] + _EPS)
        ).clip(0, 1000)

    # Ensure every ratio column exists, filled with 0 where not computable.
    for r in RATIO_FEATURES:
        if r not in df.columns:
            df[r] = 0.0
    ratio_cols = [c for c in df.columns if c in RATIO_FEATURES]
    df[ratio_cols] = df[ratio_cols].replace([np.inf, -np.inf], 0).fillna(0)
    return df


def records_to_frame(records: Sequence[Dict]) -> pd.DataFrame:
    """Normalise raw telemetry records into a DataFrame of base features.

    Accepts canonical names or known aliases (see schema._ALIASES). Missing
    features are filled with 0 — identical to the training pipeline's handling
    of structurally-absent columns.
    """
    rows: List[Dict[str, float]] = []
    for rec in records:
        row: Dict[str, float] = {f: 0.0 for f in BASE_FEATURES}
        for key, val in rec.items():
            canon = canonicalize_name(key)
            if canon is None or canon not in row:
                continue
            try:
                row[canon] = float(val) if val is not None else 0.0
            except (TypeError, ValueError):
                row[canon] = 0.0
        rows.append(row)
    return pd.DataFrame(rows, columns=BASE_FEATURES)


def build_feature_matrix(records: Sequence[Dict]) -> pd.DataFrame:
    """Return the full canonical feature matrix (base + ratios) for records."""
    base = records_to_frame(records)
    return engineer_ratios(base)[CANONICAL_FEATURES]


class FeatureExtractor:
    """Thin wrapper around :func:`build_feature_matrix` for the engine."""

    selected_features = CANONICAL_FEATURES

    def extract(self, records: Sequence[Dict]) -> pd.DataFrame:
        return build_feature_matrix(records)
