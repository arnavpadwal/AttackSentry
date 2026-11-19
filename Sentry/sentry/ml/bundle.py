"""Model bundle: versioned MoE pipeline artifacts.

A bundle is a directory (or a single ``.tar.gz``) produced by the offline
training pipeline and loaded by the runtime :class:`sentry.core.moe.MoEPipeline`.
It guarantees that training and inference share the exact feature schema,
scaling and calibration.
"""
from __future__ import annotations

import json
import logging
import shutil
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
import xgboost as xgb

from ..core.schema import CANONICAL_FEATURES
from .calibration import Calibrator

logger = logging.getLogger("sentry.ml.bundle")

SCHEMA_VERSION = "1.0"
EXPERT_NAMES = ["Varuna", "Rudra", "Maya", "Indra", "Garuda"]


@dataclass
class Expert:
    name: str
    kind: str  # lgb | xgb | rf
    model: Any
    feature_names: List[str]

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        x = X.reindex(columns=self.feature_names, fill_value=0.0).values.astype(np.float32)
        if self.kind == "lgb":
            return self.model.predict(x).astype(np.float32)
        if self.kind == "xgb":
            return self.model.predict(
                xgb.DMatrix(x, feature_names=self.feature_names)
            ).astype(np.float32)
        # RandomForest / sklearn
        return self.model.predict_proba(x)[:, 1].astype(np.float32)


@dataclass
class ModelBundle:
    """Loaded MoE bundle. Use :meth:`ModelBundle.load` to instantiate."""

    path: Path
    manifest: Dict[str, Any]
    experts: Dict[str, Expert] = field(default_factory=dict)
    gating_models: List[Any] = field(default_factory=list)
    scaler: Any = None
    calibrator: Optional[Calibrator] = None
    features: List[str] = field(default_factory=lambda: list(CANONICAL_FEATURES))

    @property
    def version(self) -> str:
        return self.manifest.get("version", "unknown")

    @property
    def threshold(self) -> float:
        return float(self.manifest.get("threshold", 0.5))

    # ------------------------------------------------------------------ #
    # Loading
    # ------------------------------------------------------------------ #
    @classmethod
    def load(cls, bundle_dir: Path) -> "ModelBundle":
        bundle_dir = Path(bundle_dir)
        # Support a single archive as well as an exploded directory.
        if bundle_dir.is_file() and bundle_dir.suffix in (".tar", ".gz", ".tgz"):
            bundle_dir = _extract_archive(bundle_dir)

        manifest_path = bundle_dir / "model_card.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"model_card.json missing in {bundle_dir}")

        manifest = json.loads(manifest_path.read_text())
        bundle = cls(path=bundle_dir, manifest=manifest)
        bundle.features = manifest.get("features", CANONICAL_FEATURES)

        bundle._load_experts()
        bundle._load_gating()
        bundle._load_scaler()
        bundle._load_calibration()
        logger.info(
            "Loaded model bundle %s (schema %s, %d experts, %d gating models)",
            bundle.version,
            manifest.get("schema_version"),
            len(bundle.experts),
            len(bundle.gating_models),
        )
        return bundle

    def _load_experts(self) -> None:
        experts_dir = self.path / "experts"
        if not experts_dir.exists():
            return
        # Map dataset substrings (in the filename) to expert identity.
        dataset_to_expert = {
            "CIC_IDS_2017": "Varuna",
            "CIC-IDS-2017": "Varuna",
            "CICDDoS2019": "Rudra",
            "CTU_13": "Maya",
            "CTU-13": "Maya",
            "NF_CICIDS2018_v3": "Indra",
            "NF_CICIDS2018-v3": "Indra",
            "NF_UNSW_NB15_v3": "Garuda",
            "NF_UNSW-NB15-v3": "Garuda",
        }
        for mpath in experts_dir.iterdir():
            stem = mpath.stem
            name = None
            for key, expert_name in dataset_to_expert.items():
                if key in stem:
                    name = expert_name
                    break
            if name is None:
                continue
            if mpath.suffix == ".lgb":
                kind, model = "lgb", lgb.Booster(model_file=str(mpath))
                feats = model.feature_name()
            elif mpath.suffix == ".xgb":
                kind, model = "xgb", xgb.Booster()
                model.load_model(str(mpath))
                feats = model.feature_names
            elif mpath.suffix in (".pkl", ".joblib"):
                kind, model = "rf", joblib.load(str(mpath))
                feats = getattr(model, "feature_names_in_", None) or self.features
            else:
                continue
            feats = list(feats)
            if feats and all(str(f).startswith("Column_") for f in feats):
                subsets = self.manifest.get("expert_feature_subsets", {})
                feats = list(subsets.get(name, self.features))
            self.experts[name] = Expert(name=name, kind=kind, model=model, feature_names=feats)

    def _load_gating(self) -> None:
        gating_dir = self.path / "gating"
        if not gating_dir.exists():
            return
        for i in sorted(range(10)):
            f = gating_dir / f"expert_{i}.lgb"
            if f.exists():
                self.gating_models.append(lgb.Booster(model_file=str(f)))

    def _load_scaler(self) -> None:
        p = self.path / "scaler.pkl"
        if p.exists():
            self.scaler = joblib.load(str(p))

    def _load_calibration(self) -> None:
        p = self.path / "calibrator.pkl"
        if p.exists():
            self.calibrator = joblib.load(str(p))

    # ------------------------------------------------------------------ #
    # Prediction
    # ------------------------------------------------------------------ #
    def expert_probs(self, X: pd.DataFrame) -> np.ndarray:
        probs = []
        for name in EXPERT_NAMES:
            expert = self.experts.get(name)
            if expert is None:
                probs.append(0.5)
                continue
            try:
                probs.append(float(expert.predict_proba(X)[0]))
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Expert %s prediction failed: %s", name, exc)
                probs.append(0.5)
        return np.asarray(probs, dtype=np.float64)

    def gating_weights(self, X: pd.DataFrame) -> np.ndarray:
        if not self.gating_models:
            return np.ones(len(EXPERT_NAMES)) / len(EXPERT_NAMES)
        feats = self.gating_models[0].feature_name()
        x = X.reindex(columns=feats, fill_value=0.0)
        raw = np.array([m.predict(x)[0] for m in self.gating_models])
        raw = np.clip(raw, 0.0, None)
        total = raw.sum()
        if total <= 0:
            return np.ones(len(raw)) / len(raw)
        return raw / total

    def predict(self, X: pd.DataFrame) -> Dict[str, Any]:
        probs = self.expert_probs(X)
        weights = self.gating_weights(X)
        raw_score = float(np.dot(probs, weights))
        score = self.calibrator.predict(np.array([raw_score]))[0] if self.calibrator else raw_score
        primary = EXPERT_NAMES[int(np.argmax(weights))]
        return {
            "expert_probs": dict(zip(EXPERT_NAMES, probs.tolist())),
            "gating_weights": dict(zip(EXPERT_NAMES, weights.tolist())),
            "moe_score": float(score),
            "raw_score": raw_score,
            "primary_expert": primary,
            "is_attack": bool(score >= self.threshold),
            "threshold": self.threshold,
        }


def _extract_archive(archive: Path) -> Path:
    dest = archive.with_suffix("") / ".extracted"
    dest = Path(str(dest).replace(".extracted", ""))  # keep simple
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:*") as tf:
        tf.extractall(dest)
    return dest


def package_bundle(bundle_dir: Path, output: Path) -> Path:
    """Create a single ``.tar.gz`` archive from an exploded bundle directory."""
    output = Path(output)
    with tarfile.open(output, "w:gz") as tf:
        tf.add(bundle_dir, arcname=output.stem)
    return output
