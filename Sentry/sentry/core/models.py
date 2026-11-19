"""Hierarchical Autoencoder for unsupervised anomaly detection.

Three autoencoders (global / group / host) with distinct bottleneck sizes learn
normal traffic at three granularities. Reconstruction errors are normalised by
per-entity thresholds (so a score of 1.0 == "at threshold") and combined into a
single anomaly score.

Thresholds are selected from a held-out validation split per entity (with a
min-sample fallback), instead of an arbitrary fixed percentile multiplier.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
from sklearn.preprocessing import MinMaxScaler, RobustScaler

from .schema import CANONICAL_FEATURES

logger = logging.getLogger("sentry.models")

# The autoencoder is tiny (42->64->32->8); CPU is faster than GPU kernel launch
# overhead and avoids VRAM contention with the local LLM. Override with
# SENTRY_TORCH_DEVICE=cuda to force GPU.
DEVICE = os.environ.get("SENTRY_TORCH_DEVICE", "cpu")


class Autoencoder(nn.Module):
    """Symmetric autoencoder with a configurable bottleneck and dropout."""

    def __init__(self, in_dim: int, bottleneck: int = 8, dropout: float = 0.1):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(in_dim, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, bottleneck),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Linear(64, in_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


class HierarchicalSentryModel:
    def __init__(self, in_dim: int):
        self.in_dim = in_dim
        self.features = CANONICAL_FEATURES[:in_dim] if in_dim <= len(CANONICAL_FEATURES) else list(CANONICAL_FEATURES)
        self.global_ae = Autoencoder(in_dim, bottleneck=8)
        self.group_ae = Autoencoder(in_dim, bottleneck=6)
        self.host_ae = Autoencoder(in_dim, bottleneck=4)

        self.scaler_robust = RobustScaler()
        self.scaler_minmax = MinMaxScaler(feature_range=(0, 1))

        self.global_threshold: float = 0.0
        self.group_thresholds: Dict[str, float] = {}
        self.host_thresholds: Dict[str, float] = {}
        self.level_thresholds: Dict[str, float] = {}
        self.default_threshold: float = 0.0

        self.alpha = 0.3
        self.beta = 0.4
        self.gamma = 0.3

    # ------------------------------------------------------------------ #
    # Training
    # ------------------------------------------------------------------ #
    def fit(
        self,
        global_data: np.ndarray,
        group_data: Optional[np.ndarray] = None,
        host_data: Optional[np.ndarray] = None,
        epochs: int = 60,
        batch_size: int = 64,
        lr: float = 1e-3,
        early_stop_patience: int = 8,
        val_frac: float = 0.1,
        quantile: float = 0.99,
        min_samples: int = 50,
    ) -> "HierarchicalSentryModel":
        if len(global_data) < min_samples:
            raise ValueError(
                f"Insufficient data for training (got {len(global_data)}, need {min_samples})"
            )

        # Robust-scale then min-max scale to [0,1] for AE stability.
        self.scaler_robust.fit(global_data)
        robust = self.scaler_robust.transform(global_data)
        self.scaler_minmax.fit(robust)

        def _scaled(x: np.ndarray) -> np.ndarray:
            return self.scaler_minmax.transform(self.scaler_robust.transform(x))

        datasets = {
            "global": (self.global_ae, _scaled(global_data)),
        }
        if group_data is not None and len(group_data) >= min_samples:
            datasets["group"] = (self.group_ae, _scaled(group_data))
        if host_data is not None and len(host_data) >= min_samples:
            datasets["host"] = (self.host_ae, _scaled(host_data))

        thresholds: Dict[str, float] = {}
        for name, (ae, x_scaled) in datasets.items():
            x_tr, x_val = _split(x_scaled, val_frac)
            self._train_ae(ae, x_tr, x_val, name, epochs, batch_size, lr, early_stop_patience)
            errs = self._recon_errors(ae, torch.from_numpy(x_val).float())
            thresholds[name] = float(np.quantile(errs, quantile))
            logger.info(
                "%s AE threshold (99th pct of val): %.6f", name.capitalize(), thresholds[name]
            )

        # Each level keeps its own calibration; the global threshold is never
        # replaced by the last level trained (host-only thresholds were a bug).
        self.level_thresholds = thresholds
        self.global_threshold = thresholds.get("global", 0.0)
        self.default_threshold = self.global_threshold
        # Per-entity thresholds default to the global one; the engine can
        # override with entity-specific thresholds learned per group/host.
        self.group_thresholds = {}
        self.host_thresholds = {}
        return self

    @staticmethod
    def _train_ae(ae, x_tr, x_val, name, epochs, batch_size, lr, patience):
        x_tr_t = torch.from_numpy(x_tr).float().to(DEVICE)
        loader = torch.utils.data.DataLoader(
            torch.utils.data.TensorDataset(x_tr_t), batch_size=batch_size, shuffle=True
        )
        opt = torch.optim.AdamW(ae.parameters(), lr=lr, weight_decay=1e-5)
        criterion = nn.MSELoss()
        ae.to(DEVICE)

        best_loss, stale = float("inf"), 0
        x_val_t = torch.from_numpy(x_val).float().to(DEVICE)
        for epoch in range(epochs):
            ae.train()
            for (batch,) in loader:
                opt.zero_grad()
                loss = criterion(ae(batch), batch)
                loss.backward()
                opt.step()
            ae.eval()
            with torch.no_grad():
                val_loss = criterion(ae(x_val_t), x_val_t).item()
            if val_loss < best_loss - 1e-6:
                best_loss, stale = val_loss, 0
            else:
                stale += 1
                if stale >= patience:
                    logger.info("%s AE early-stopped at epoch %d", name, epoch + 1)
                    break
        ae.to("cpu")

    @staticmethod
    def _recon_errors(ae, x: torch.Tensor) -> np.ndarray:
        ae.eval()
        with torch.no_grad():
            recon = ae(x)
            return torch.mean((x - recon) ** 2, dim=1).cpu().numpy()

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #
    def _scale(self, x_raw: np.ndarray) -> torch.Tensor:
        robust = self.scaler_robust.transform(x_raw)
        scaled = self.scaler_minmax.transform(robust)
        return torch.from_numpy(scaled).float()

    def get_anomaly_scores(
        self, x_raw: np.ndarray, group: str = "GLOBAL", host: str = "GLOBAL"
    ) -> Dict[str, Any]:
        x = self._scale(x_raw)
        g_err, g_feat = self._errs(self.global_ae, x)
        grp_err, grp_feat = self._errs(self.group_ae, x)
        h_err, h_feat = self._errs(self.host_ae, x)

        g_norm = g_err / self.global_threshold if self.global_threshold > 0 else 0.0
        grp_thr = self.group_thresholds.get(group, self.default_threshold) or self.global_threshold or 1e-9
        h_thr = self.host_thresholds.get(host, self.default_threshold) or self.global_threshold or 1e-9
        grp_norm = grp_err / grp_thr
        h_norm = h_err / h_thr

        combined = self.alpha * g_norm + self.beta * grp_norm + self.gamma * h_norm

        return {
            "global_score": float(g_err),
            "group_score": float(grp_err),
            "host_score": float(h_err),
            "combined_score": float(combined),
            "feature_errors": {
                "global": g_feat,
                "group": grp_feat,
                "host": h_feat,
            },
        }

    def is_anomaly(self, scores: Dict[str, Any], threshold: float = 1.0) -> Tuple[bool, float]:
        return scores["combined_score"] > threshold, scores["combined_score"]

    @staticmethod
    def _errs(ae: nn.Module, x: torch.Tensor) -> Tuple[float, np.ndarray]:
        ae.eval()
        with torch.no_grad():
            recon = ae(x)
            feat_err = ((x - recon) ** 2).squeeze(0).cpu().numpy()
            mse = torch.mean((x - recon) ** 2).item()
        return mse, feat_err

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #
    def save(self, path: str) -> None:
        torch.save(
            {
                "in_dim": self.in_dim,
                "features": self.features,
                "global_ae": self.global_ae.state_dict(),
                "group_ae": self.group_ae.state_dict(),
                "host_ae": self.host_ae.state_dict(),
                "scaler_robust": self.scaler_robust,
                "scaler_minmax": self.scaler_minmax,
                "global_threshold": self.global_threshold,
                "group_thresholds": self.group_thresholds,
                "host_thresholds": self.host_thresholds,
                "level_thresholds": self.level_thresholds,
                "default_threshold": self.default_threshold,
                "alpha": self.alpha,
                "beta": self.beta,
                "gamma": self.gamma,
            },
            path,
        )
        logger.info("Hierarchical model saved to %s", path)

    @classmethod
    def load(cls, path: str) -> "HierarchicalSentryModel":
        state = torch.load(path, map_location="cpu", weights_only=False)
        model = cls(state["in_dim"])
        model.features = state.get("features", model.features)
        model.global_ae.load_state_dict(state["global_ae"])
        model.group_ae.load_state_dict(state["group_ae"])
        model.host_ae.load_state_dict(state["host_ae"])
        model.scaler_robust = state.get("scaler_robust", RobustScaler())
        model.scaler_minmax = state.get("scaler_minmax", MinMaxScaler(feature_range=(0, 1)))
        model.global_threshold = state.get("global_threshold", 0.0)
        model.group_thresholds = state.get("group_thresholds", {})
        model.host_thresholds = state.get("host_thresholds", {})
        model.level_thresholds = state.get("level_thresholds", {})
        model.default_threshold = state.get("default_threshold", 0.0)
        model.alpha = state.get("alpha", 0.3)
        model.beta = state.get("beta", 0.4)
        model.gamma = state.get("gamma", 0.2)
        return model


def _split(x: np.ndarray, val_frac: float) -> Tuple[np.ndarray, np.ndarray]:
    if val_frac <= 0 or len(x) < 20:
        return x, x
    n_val = max(1, int(len(x) * val_frac))
    idx = np.random.RandomState(42).permutation(len(x))
    return x[idx[n_val:]], x[idx[:n_val]]
