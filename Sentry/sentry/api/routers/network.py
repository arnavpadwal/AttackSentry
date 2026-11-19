"""Network graph + MITRE ATT&CK coverage routes."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_db
from ...db.models import Detection, FlowLog, Host
from ..deps import get_current_user

router = APIRouter(tags=["network"])


@router.get("/api/network/graph")
async def network_graph(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    """Nodes (entities) + edges (recent flow relationships) for the visualizer."""
    hosts = (await db.execute(select(Host))).scalars().all()

    host_ips = {h.ip_address for h in hosts}
    groups = {h.group_name or "unassigned" for h in hosts}
    nodes = [
        {
            "id": h.id,
            "ip": h.ip_address,
            "hostname": h.hostname or h.ip_address,
            "group": h.group_name or "unknown",
            "risk": round(h.risk_score, 1),
            "status": h.status,
            "external": False, "node_type": "host", "vlan": None,
        }
        for h in hosts
    ]

    # Recent flow edges.
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    flows = (await db.execute(
        select(FlowLog).where(FlowLog.timestamp >= since).order_by(FlowLog.timestamp.desc()).limit(2000)
    )).scalars().all()

    vlan_by_ip = {f.src_ip: f.subnet for f in flows if f.src_ip and f.subnet}
    for node in nodes:
        node["vlan"] = vlan_by_ip.get(node["ip"])

    edge_agg: dict = {}
    external_nodes: dict = {}
    for f in flows:
        src, dst = f.src_ip, f.dst_ip
        if not src or not dst:
            continue
        for ip in (dst,):
            if ip and ip not in host_ips and ip not in external_nodes:
                external_nodes[ip] = {"id": f"ext-{ip}", "ip": ip, "hostname": ip,
                                      "group": "external", "risk": 0.0, "status": "external", "external": True}
        key = (src, dst)
        agg = edge_agg.setdefault(key, {"src": src, "dst": dst, "flows": 0, "bytes": 0})
        agg["flows"] += 1
        agg["bytes"] += (f.bytes_sent or 0) + (f.bytes_received or 0)

    # Add logical group/VLAN anchors so the graph communicates hierarchy.
    group_nodes = [{"id": f"group-{g}", "ip": f"group:{g}", "hostname": g, "group": g,
                    "risk": 0.0, "status": "logical", "external": False, "node_type": "group", "vlan": None}
                   for g in sorted(groups)]
    hierarchy_edges = [{"id": f"group-{h.group_name or 'unassigned'}-{h.id}",
                        "src": f"group-{h.group_name or 'unassigned'}", "dst": h.ip_address,
                        "flows": 0, "bytes": 0, "relation": "contains"} for h in hosts]
    edges = [
        {"id": f"{e['src']}-{e['dst']}", "src": e["src"], "dst": e["dst"],
         "flows": e["flows"], "bytes": e["bytes"], "relation": "communicates"}
        for e in edge_agg.values()
    ]

    return {"nodes": group_nodes + nodes + list(external_nodes.values()), "edges": hierarchy_edges + edges}


@router.get("/api/mitre/coverage")
async def mitre_coverage(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    """MITRE ATT&CK tactic/technique coverage from detections."""
    rows = (await db.execute(
        select(Detection.mitre_tactic, Detection.mitre_technique, func.count())
        .where(Detection.mitre_tactic.isnot(None), Detection.mitre_tactic != "Unknown")
        .group_by(Detection.mitre_tactic, Detection.mitre_technique)
    )).all()

    tactic_counts: Counter = Counter()
    techniques = []
    for tactic, technique, count in rows:
        if not tactic or not technique or technique == "Unknown":
            continue
        tactic_counts[tactic] += count
        techniques.append({"tactic": tactic, "technique": technique, "count": count})

    total = sum(tactic_counts.values())
    tactics = [
        {"tactic": t, "count": c, "pct": round(c / total * 100, 1) if total else 0.0}
        for t, c in tactic_counts.most_common()
    ]
    return {"tactics": tactics, "techniques": techniques, "total": total}
