"""Canonical telemetry & feature schema.

This module is the single source of truth for the numeric feature vector shared
by the Rust sensor, the Python core, and the offline training pipeline. Any
change to the schema must be accompanied by a retrain (see training/8_build_bundle.py).

Design:
  * ``BASE_FEATURES``  — numeric features the sensor computes directly from a
    packet capture (NetFlow + bidirectional packet/IAT statistics).
  * ``RATIO_FEATURES`` — deterministic derived features (engineered ratios) that
    are computed identically at training and inference time.
  * ``CANONICAL_FEATURES`` — BASE + RATIO, the ordered input vector for the
    autoencoder, experts and gating network.
"""
from __future__ import annotations

from typing import Dict, List

# --------------------------------------------------------------------------- #
# Base (sensor-computable) numeric features — order is part of the schema.
# --------------------------------------------------------------------------- #
BASE_FEATURES: List[str] = [
    # Connection identity / volume (Tier 1)
    "Protocol",
    "Src_Port",
    "Dst_Port",
    "Flow_Duration",
    "Total_Fwd_Packets",
    "Total_Bwd_Packets",
    "Total_Fwd_Bytes",
    "Total_Bwd_Bytes",
    # Bidirectional packet-length statistics (Tier 2)
    "Fwd_Pkt_Len_Min",
    "Fwd_Pkt_Len_Max",
    "Fwd_Pkt_Len_Mean",
    "Fwd_Pkt_Len_Std",
    "Bwd_Pkt_Len_Min",
    "Bwd_Pkt_Len_Max",
    "Bwd_Pkt_Len_Mean",
    "Bwd_Pkt_Len_Std",
    # Inter-arrival time statistics (Tier 2)
    "Flow_IAT_Mean",
    "Flow_IAT_Std",
    "Flow_IAT_Max",
    "Flow_IAT_Min",
    # Throughput / intensity (Tier 2)
    "Flow_Bytes_Sec",
    "Flow_Packets_Sec",
    # TCP flag counts (Tier 2)
    "FIN_Flag_Count",
    "SYN_Flag_Count",
    "RST_Flag_Count",
    "PSH_Flag_Count",
    "ACK_Flag_Count",
    "URG_Flag_Count",
]

# --------------------------------------------------------------------------- #
# Derived ratio features (computed identically in training and inference).
# --------------------------------------------------------------------------- #
RATIO_FEATURES: List[str] = [
    "ratio_bwd_fwd_bytes",
    "ratio_bwd_fwd_pkts",
    "ratio_bytes_per_pkt_fwd",
    "ratio_fwd_throughput",
    "ratio_syn_per_pkt",
    "ratio_ack_syn",
    "ratio_rst_per_pkt",
    "ratio_psh_ack",
    "ratio_fin_syn",
    "ratio_pkt_len_cv",
    "ratio_iat_cv",
    "ratio_iat_range",
    "ratio_fwd_bwd_iat_std",
    "ratio_bwd_fwd_pkt_size",
]

CANONICAL_FEATURES: List[str] = BASE_FEATURES + RATIO_FEATURES

# --------------------------------------------------------------------------- #
# Non-numeric context fields (never fed to models).
# --------------------------------------------------------------------------- #
CONTEXT_FIELDS: List[str] = [
    "Src_IP",
    "Dst_IP",
    "User_ID",
    "Identity_Type",
    "Process_Name",
    "Process_ID",
    "Subnet_Group",
    "Source_Subnet",
    "Timestamp",
]

# --------------------------------------------------------------------------- #
# Name mapping: alternative telemetry names -> canonical base feature.
# Allows the core to ingest NetFlow-style records that use non-canonical names
# (e.g. sensor v1 or third-party exporters) and normalise them.
# --------------------------------------------------------------------------- #
_ALIASES: Dict[str, str] = {
    "Pkt_Len_Mean": "Fwd_Pkt_Len_Mean",
    "Pkt_Len_Std": "Fwd_Pkt_Len_Std",
    "Pkt_Len_Min": "Fwd_Pkt_Len_Min",
    "Pkt_Len_Max": "Fwd_Pkt_Len_Max",
    "Max_Pkt_Len": "Fwd_Pkt_Len_Max",
    "Flow_IAT_Total": "Flow_IAT_Mean",
    "Fwd_IAT_Total": "Flow_IAT_Mean",
    "Bwd_IAT_Total": "Flow_IAT_Std",
    "Fwd_IAT_Mean": "Flow_IAT_Mean",
    "Bwd_IAT_Mean": "Flow_IAT_Std",
    "Fwd_IAT_Std": "Flow_IAT_Std",
    "Bwd_IAT_Std": "Flow_IAT_Std",
    "Fwd_Packets_Sec": "Flow_Packets_Sec",
    "Bwd_Packets_Sec": "Flow_Packets_Sec",
    "Shortest_Flow_Pkt": "Fwd_Pkt_Len_Min",
    "Longest_Flow_Pkt": "Fwd_Pkt_Len_Max",
}

# Map unified-dataset training columns -> canonical base feature (for training).
TRAINING_COLUMN_MAP: Dict[str, str] = {
    "Protocol": "Protocol",
    "Src_Port": "Src_Port",
    "Dst_Port": "Dst_Port",
    "Flow_Duration": "Flow_Duration",
    "Total_Fwd_Packets": "Total_Fwd_Packets",
    "Total_Bwd_Packets": "Total_Bwd_Packets",
    "Total_Fwd_Bytes": "Total_Fwd_Bytes",
    "Total_Bwd_Bytes": "Total_Bwd_Bytes",
    "Fwd_Pkt_Len_Min": "Fwd_Pkt_Len_Min",
    "Fwd_Pkt_Len_Max": "Fwd_Pkt_Len_Max",
    "Fwd_Pkt_Len_Mean": "Fwd_Pkt_Len_Mean",
    "Fwd_Pkt_Len_Std": "Fwd_Pkt_Len_Std",
    "Bwd_Pkt_Len_Min": "Bwd_Pkt_Len_Min",
    "Bwd_Pkt_Len_Max": "Bwd_Pkt_Len_Max",
    "Bwd_Pkt_Len_Mean": "Bwd_Pkt_Len_Mean",
    "Bwd_Pkt_Len_Std": "Bwd_Pkt_Len_Std",
    "Pkt_Len_Min": "Fwd_Pkt_Len_Min",
    "Pkt_Len_Max": "Fwd_Pkt_Len_Max",
    "Pkt_Len_Mean": "Fwd_Pkt_Len_Mean",
    "Pkt_Len_Std": "Fwd_Pkt_Len_Std",
    "Flow_IAT_Mean": "Flow_IAT_Mean",
    "Flow_IAT_Std": "Flow_IAT_Std",
    "Flow_IAT_Max": "Flow_IAT_Max",
    "Flow_IAT_Min": "Flow_IAT_Min",
    "Flow_Bytes_Sec": "Flow_Bytes_Sec",
    "Flow_Packets_Sec": "Flow_Packets_Sec",
    "FIN_Flag_Count": "FIN_Flag_Count",
    "SYN_Flag_Count": "SYN_Flag_Count",
    "RST_Flag_Count": "RST_Flag_Count",
    "PSH_Flag_Count": "PSH_Flag_Count",
    "ACK_Flag_Count": "ACK_Flag_Count",
    "URG_Flag_Count": "URG_Flag_Count",
}


def canonicalize_name(name: str) -> str | None:
    """Return the canonical base feature name for an arbitrary input name."""
    if name in BASE_FEATURES:
        return name
    return _ALIASES.get(name)
