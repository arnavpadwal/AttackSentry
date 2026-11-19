#!/usr/bin/env python3
"""One-off incident consolidation for SQLite deployments.

Groups existing incidents by canonical attack family and attack scope (target
service for DDoS, source for host-centric attacks), merges duplicate evidence,
and rewrites the incident family labels. Safe to run repeatedly.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "Sentry"))
from sentry.core.families import canonical_family  # noqa: E402


def _parse(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def regroup(db_path: Path, window_hours: float = 24.0) -> None:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    incidents = {row["id"]: dict(row) for row in con.execute("SELECT * FROM incidents")}
    detections = [dict(row) for row in con.execute(
        "SELECT id, incident_id, detection_type, src_ip, dst_ip, dst_port, protocol, timestamp FROM detections"
    )]

    latest_label: dict[str, str] = {}
    for detection in detections:
        if detection["incident_id"] and detection["detection_type"]:
            latest_label[detection["incident_id"]] = detection["detection_type"]

    buckets: dict[tuple, set[str]] = defaultdict(set)
    for detection in detections:
        incident_id = detection["incident_id"]
        if not incident_id or incident_id not in incidents:
            continue
        incident = incidents[incident_id]
        family = canonical_family(detection["detection_type"] or incident["family"])
        if family == "DDoS":
            scope = f"target:{detection['dst_ip']}"
        else:
            scope = f"source:{detection['src_ip']}"
        created = _parse(incident.get("created_at"))
        bucket = int(created.timestamp() // max(3600, window_hours * 3600))
        buckets[(family, scope, bucket)].add(incident_id)

    merged = 0
    for (family, scope, _bucket), ids in buckets.items():
        if len(ids) < 2:
            continue
        ordered = sorted(ids, key=lambda incident_id: incidents[incident_id].get("created_at") or "")
        canonical = ordered[0]
        duplicates = ordered[1:]
        detections_in_group = [d for d in detections if d["incident_id"] in ids]
        if not detections_in_group:
            continue
        scope_ip = scope.split(":", 1)[1].split(":")[0]
        last_seen = max((d["timestamp"] for d in detections_in_group if d["timestamp"]), default=incidents[canonical].get("last_seen"))
        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        severity = max(
            (i["severity"] for i in incidents.values() if i["id"] in ids),
            key=lambda value: severity_rank.get(value, 0),
        )
        peak = max(float(i.get("peak_signal") or 0) for i in incidents.values() if i["id"] in ids)
        con.execute(
            "UPDATE incidents SET entity=?, family=?, count=?, last_seen=?, severity=?, peak_signal=? WHERE id=?",
            (scope_ip, family, len(detections_in_group), last_seen, severity, peak, canonical),
        )
        con.execute("UPDATE detections SET incident_id=? WHERE incident_id IN (%s)" % ",".join("?" * len(duplicates)),
                    [canonical, *duplicates])
        con.execute("UPDATE playbooks SET incident_id=? WHERE incident_id IN (%s)" % ",".join("?" * len(duplicates)),
                    [canonical, *duplicates])
        con.execute("UPDATE mitigation_actions SET incident_id=? WHERE incident_id IN (%s)" % ",".join("?" * len(duplicates)),
                    [canonical, *duplicates])
        con.execute("DELETE FROM incidents WHERE id IN (%s)" % ",".join("?" * len(duplicates)), duplicates)
        merged += len(duplicates)

    # Even unmerged incidents should carry the stable family label.
    for incident_id, incident in incidents.items():
        family = canonical_family(latest_label.get(incident_id) or incident.get("family"))
        con.execute("UPDATE incidents SET family=? WHERE id=?", (family, incident_id))

    con.commit()
    remaining = con.execute("SELECT count(*) FROM incidents").fetchone()[0]
    con.close()
    print(f"Consolidated {merged} duplicate incidents; {remaining} incidents remain.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=ROOT / "Sentry" / "attacksentry.db")
    parser.add_argument("--window-hours", type=float, default=24.0)
    args = parser.parse_args()
    regroup(args.db, args.window_hours)
