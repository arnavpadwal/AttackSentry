"""Mixture-of-Experts classification pipeline.

Wraps a versioned :class:`sentry.ml.bundle.ModelBundle`. The runtime never
globs raw files or zero-fills model inputs ad hoc — the bundle carries the
exact feature schema, scaler and calibration produced at training time.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

import pandas as pd

from ..ml.bundle import ModelBundle

logger = logging.getLogger("sentry.moe")


class MoEPipeline:
    def __init__(self, models_dir: Path):
        self.models_dir = Path(models_dir)
        self.bundle: Optional[ModelBundle] = self._load_latest()

    def _load_latest(self) -> Optional[ModelBundle]:
        bundles = sorted(self.models_dir.glob("bundle_*"))
        if not bundles:
            # Legacy fallback: models at the repo root (experts/ + gating/).
            legacy = self.models_dir / "experts"
            if not legacy.exists():
                logger.warning("No model bundle found in %s — MoE disabled.", self.models_dir)
                return None
            logger.warning("Using legacy model layout (experts/ + gating/). Run training/8_build_bundle.py.")
            try:
                return ModelBundle.load(self.models_dir)
            except Exception as exc:
                logger.error("Legacy model layout is incomplete: %s", exc)
                return None
        latest = bundles[-1]
        try:
            return ModelBundle.load(latest)
        except Exception as exc:  # pragma: no cover
            logger.error("Failed to load bundle %s: %s", latest, exc)
            return None

    @property
    def ready(self) -> bool:
        return self.bundle is not None

    @property
    def version(self) -> str:
        return self.bundle.version if self.bundle else "none"

    def predict(self, features_df: pd.DataFrame) -> Dict[str, Any]:
        if not self.bundle:
            return {
                "expert_probs": {}, "gating_weights": {}, "moe_score": 0.0,
                "primary_expert": None, "is_attack": False, "threshold": 0.5,
            }
        return self.bundle.predict(features_df)
