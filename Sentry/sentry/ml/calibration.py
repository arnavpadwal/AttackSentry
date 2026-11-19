"""Probability calibration for the MoE decision score.

The raw weighted-average of expert probabilities is not a well-calibrated
probability (its distribution is skewed). We fit an isotonic regression on a
held-out validation split so that ``moe_score`` reflects an empirical
probability of attack — enabling a single, interpretable decision threshold.
"""
from __future__ import annotations

import numpy as np
from sklearn.isotonic import IsotonicRegression


class Calibrator:
    """Monotonic isotonic calibration of a scalar score -> probability."""

    def __init__(self) -> None:
        self._iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
        self._fitted = False

    def fit(self, scores: np.ndarray, labels: np.ndarray) -> "Calibrator":
        scores = np.asarray(scores, dtype=np.float64).reshape(-1)
        labels = np.asarray(labels, dtype=np.float64).reshape(-1)
        self._iso.fit(scores, labels)
        self._fitted = True
        return self

    def predict(self, scores: np.ndarray) -> np.ndarray:
        scores = np.asarray(scores, dtype=np.float64).reshape(-1)
        if not self._fitted:
            return scores
        return self._iso.predict(scores)

    def __getstate__(self):
        return {"_iso": self._iso, "_fitted": self._fitted}

    def __setstate__(self, state):
        self._iso = state["_iso"]
        self._fitted = state["_fitted"]
