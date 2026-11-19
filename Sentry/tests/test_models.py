"""Per-level autoencoder calibration."""
from __future__ import annotations

import numpy as np

from sentry.core.models import HierarchicalSentryModel


def test_each_level_keeps_its_own_threshold():
    rng = np.random.default_rng(7)
    in_dim = 42
    model = HierarchicalSentryModel(in_dim)
    model.fit(
        global_data=rng.normal(0, 1, (300, in_dim)).astype(np.float32),
        group_data=rng.normal(0, 4, (200, in_dim)).astype(np.float32),
        host_data=rng.normal(0, 12, (120, in_dim)).astype(np.float32),
        epochs=1,
        batch_size=64,
        min_samples=50,
    )
    assert set(model.level_thresholds) == {"global", "group", "host"}
    assert model.global_threshold == model.level_thresholds["global"]
    assert model.default_threshold == model.level_thresholds["global"]
    assert model.global_threshold != model.level_thresholds["host"]
