"""Persistent statistical baselining + reservoir sampling per entity.

Tracks running Welford statistics and a bounded reservoir of sample feature
vectors for the Global / Group / Host autoencoders. Backed by SQLite (WAL) so
the baseline survives restarts during the learning window.
"""
from __future__ import annotations

import json
import logging
import pickle
import sqlite3
import zlib
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger("sentry.baseline")

_META_FEATURES_KEY = "__features__"


class BaselineTracker:
    def __init__(self, db_path: Path, reservoir_size: int = 5000):
        self.db_path = str(Path(db_path).resolve())
        self.reservoir_size = reservoir_size
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS baselines (
                    entity_id TEXT PRIMARY KEY,
                    entity_type TEXT,
                    feature_stats TEXT,
                    reservoir BLOB
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def clear_all(self) -> None:
        conn = self._connect()
        try:
            conn.execute("DROP TABLE IF EXISTS baselines")
            conn.commit()
        finally:
            conn.close()
        self._init_db()
        logger.info("Baseline database cleared.")

    # ------------------------------------------------------------------ #
    # Stats (Welford)
    # ------------------------------------------------------------------ #
    def update_entity(self, entity_id: str, entity_type: str, features: Dict[str, float]) -> None:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT feature_stats FROM baselines WHERE entity_id = ?", (entity_id,))
            row = cur.fetchone()
            stats = json.loads(row[0]) if row and row[0] else {}
            stats.pop(_META_FEATURES_KEY, None)

            for feat, val in features.items():
                if val is None or not np.isfinite(val):
                    continue
                s = stats.setdefault(feat, {"count": 0, "mean": 0.0, "M2": 0.0})
                s["count"] += 1
                delta = val - s["mean"]
                s["mean"] += delta / s["count"]
                delta2 = val - s["mean"]
                s["M2"] += delta * delta2

            stats[_META_FEATURES_KEY] = list(features.keys())
            conn.execute(
                "INSERT OR REPLACE INTO baselines (entity_id, entity_type, feature_stats, reservoir) "
                "VALUES (?, ?, ?, (SELECT reservoir FROM baselines WHERE entity_id = ?))",
                (entity_id, entity_type, json.dumps(stats), entity_id),
            )
            conn.commit()
        finally:
            conn.close()

    def get_z_score(self, entity_id: str, feature: str, value: float) -> float:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT feature_stats FROM baselines WHERE entity_id = ?", (entity_id,))
            row = cur.fetchone()
            if not row or not row[0]:
                return 0.0
            stats = json.loads(row[0])
            s = stats.get(feature)
            if not s or s["count"] < 2:
                return 0.0
            var = s["M2"] / (s["count"] - 1)
            std = np.sqrt(var)
            if std < 1e-9:
                return 0.0
            return (value - s["mean"]) / std
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # Reservoir sampling (Algorithm R)
    # ------------------------------------------------------------------ #
    def add_to_reservoir(self, entity_id: str, flow_vec: np.ndarray) -> None:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT reservoir, feature_stats FROM baselines WHERE entity_id = ?", (entity_id,)
            )
            row = cur.fetchone()
            if not row:
                return
            res_blob, stats_json = row
            reservoir = pickle.loads(zlib.decompress(res_blob)) if res_blob else []
            stats = json.loads(stats_json) if stats_json else {}
            n_seen = max((s.get("count", 0) for s in stats.values() if isinstance(s, dict)), default=0)

            if len(reservoir) < self.reservoir_size:
                reservoir.append(flow_vec)
            elif n_seen > 0:
                j = int(np.random.randint(0, n_seen))
                if j < self.reservoir_size:
                    reservoir[j] = flow_vec

            conn.execute(
                "UPDATE baselines SET reservoir = ? WHERE entity_id = ?",
                (zlib.compress(pickle.dumps(reservoir)), entity_id),
            )
            conn.commit()
        finally:
            conn.close()

    def get_reservoir(self, entity_id: str) -> np.ndarray:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT reservoir FROM baselines WHERE entity_id = ?", (entity_id,))
            row = cur.fetchone()
            if not row or not row[0]:
                return np.empty((0, 0))
            return np.array(pickle.loads(zlib.decompress(row[0])))
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # Bulk access for training
    # ------------------------------------------------------------------ #
    def get_all_by_type(self, entity_type: str) -> Dict[str, np.ndarray]:
        """Return {entity_id: reservoir_matrix} for a given entity type."""
        conn = self._connect()
        out: Dict[str, np.ndarray] = {}
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT entity_id, reservoir FROM baselines WHERE entity_type = ?", (entity_type,)
            )
            for eid, blob in cur.fetchall():
                if blob:
                    out[eid] = np.array(pickle.loads(zlib.decompress(blob)))
        finally:
            conn.close()
        return out

    def feature_order(self) -> Optional[List[str]]:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT feature_stats FROM baselines WHERE entity_id = 'GLOBAL'")
            row = cur.fetchone()
            if not row or not row[0]:
                return None
            return json.loads(row[0]).get(_META_FEATURES_KEY)
        finally:
            conn.close()
