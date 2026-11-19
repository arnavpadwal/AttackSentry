"""Sentry core: engine, models, features, baselining and fidelity.

Imports are intentionally lazy (see ``__getattr__``) to avoid circular imports
between the core and the ``sentry.ml`` model-bundle package.
"""
from __future__ import annotations

from typing import Any

__all__ = ["SentryEngine", "FeatureExtractor", "HierarchicalSentryModel", "MoEPipeline"]


def __getattr__(name: str) -> Any:
    if name == "SentryEngine":
        from .engine import SentryEngine
        return SentryEngine
    if name == "FeatureExtractor":
        from .features import FeatureExtractor
        return FeatureExtractor
    if name == "HierarchicalSentryModel":
        from .models import HierarchicalSentryModel
        return HierarchicalSentryModel
    if name == "MoEPipeline":
        from .moe import MoEPipeline
        return MoEPipeline
    raise AttributeError(name)
