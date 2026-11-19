"""Ingestion pipeline: async queue worker that drives the engine and persists."""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy import delete, select

from ..api.events import bus
from ..api.schemas import AlertOut
from ..config import settings
from ..core.mitre import mitre_for
from ..db import session_factory
from ..db.models import Detection, FlowLog, Host, Incident, MitigationAction, Playbook, Sensor
from ..integrations import WebhookDispatcher
from ..integrations.local_enforce import ResponseDispatcher
from ..llm.batcher import TriageBatcher
from ..metrics import FLOWS_INGESTED, INCIDENTS_CREATED, INGEST_QUEUE_DEPTH
from ..response import (
    SEVERITY,
    auto_action_budget_available,
    dispatch_mitigation,
    dispatch_release,
    new_policy_action,
    recommended_response,
    response_policy_matches,
)

logger = logging.getLogger("sentry.pipeline")


class IngestionPipeline:
    def __init__(self, engine, llm=None):
        self.engine = engine
        self.llm = llm
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._traffic_accum: Dict[str, float] = {"bytes": 0.0, "packets": 0.0, "flows": 0.0}
        self._last_traffic_emit = time.time()
        self.webhooks = WebhookDispatcher()
        self.response_dispatch = ResponseDispatcher(self.webhooks)
        self._background_tasks: set[asyncio.Task] = set()
        self._response_reconciler: Optional[asyncio.Task] = None
        self.triage: Optional[TriageBatcher] = (
            TriageBatcher(llm, self._persist_playbook) if llm else None
        )
        self._retention_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run())
        await self.webhooks.start()
        if self.triage:
            await self.triage.start()
        self._response_reconciler = asyncio.create_task(self._reconcile_response_expiry())
        self._retention_task = asyncio.create_task(self._retention_loop())
        logger.info("Ingestion pipeline started")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self.webhooks.stop()
        if self.triage:
            await self.triage.stop()
        pending = list(self._background_tasks)
        if self._response_reconciler:
            pending.append(self._response_reconciler)
        if self._retention_task:
            pending.append(self._retention_task)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._background_tasks.clear()

    async def enqueue(self, flow: Dict[str, Any], source: str = "rest") -> bool:
        try:
            self.queue.put_nowait((flow, source))
        except asyncio.QueueFull:
            logger.warning("Ingest queue full — dropping flow (backpressure)")
            return False
        INGEST_QUEUE_DEPTH.set(self.queue.qsize())
        return True

    async def _run(self) -> None:
        loop = asyncio.get_event_loop()
        while self._running:
            item = None
            try:
                item = await self.queue.get()
                flow, source = item
                INGEST_QUEUE_DEPTH.set(self.queue.qsize())
                detection = await loop.run_in_executor(None, self.engine.process_flow, flow)
                await self._handle(flow, source, detection)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("Pipeline error: %s", exc)
            finally:
                if item is not None:
                    self.queue.task_done()

    async def _handle(self, flow, source, detection) -> None:
        FLOWS_INGESTED.labels(source).inc()
        await self._persist_flow(flow, source, detection)
        await self._emit_telemetry(flow, detection)

    # ------------------------------------------------------------------ #
    async def _persist_flow(self, flow, source, detection) -> None:
        try:
            async with session_factory() as db:
                fl = FlowLog(
                    src_ip=flow.get("Src_IP"),
                    dst_ip=flow.get("Dst_IP"),
                    src_port=flow.get("Src_Port", 0),
                    dst_port=flow.get("Dst_Port", 0),
                    protocol=flow.get("Protocol", 0),
                    bytes_sent=flow.get("Total_Fwd_Bytes", 0),
                    bytes_received=flow.get("Total_Bwd_Bytes", 0),
                    packets_sent=flow.get("Total_Fwd_Packets", 0),
                    packets_received=flow.get("Total_Bwd_Packets", 0),
                    duration=flow.get("Flow_Duration", 0),
                    sensor_id=flow.get("Sensor_ID"),
                    identity=flow.get("User_ID"),
                    process_name=flow.get("Process_Name"),
                    subnet=flow.get("Source_Subnet") or flow.get("Subnet_Group"),
                    anomaly_score=detection["anomaly_score"] if detection else 0.0,
                )
                db.add(fl)
                await self._upsert_host(db, flow, detection)
                await self._update_sensor(db, flow)
                await db.commit()
        except Exception as exc:
            logger.error("Flow persistence failed: %s", exc)

    @staticmethod
    async def _upsert_host(db, flow, detection) -> None:
        ip = flow.get("Src_IP")
        if not ip:
            return
        host = (await db.execute(select(Host).where(Host.ip_address == ip))).scalar_one_or_none()
        if not host:
            host = Host(ip_address=ip, group_name=flow.get("Subnet_Group"),
                        identity=flow.get("User_ID"), device_type=flow.get("Identity_Type"),
                        hostname=flow.get("Hostname"),
                        os_info=flow.get("OS"))
            db.add(host)
        else:
            if flow.get("Hostname") and not host.hostname:
                host.hostname = flow.get("Hostname")
            if flow.get("OS") and not host.os_info:
                host.os_info = flow.get("OS")
        host.last_seen = datetime.now(timezone.utc)
        if detection:
            host.risk_score = detection.get("entity_risk", host.risk_score)
            host.baseline_status = "active"

    @staticmethod
    async def _update_sensor(db, flow) -> None:
        sensor_id = flow.get("Sensor_ID")
        if not sensor_id:
            return
        sensor = (await db.execute(select(Sensor).where(Sensor.id == sensor_id))).scalar_one_or_none()
        if sensor:
            sensor.status = "online"
            sensor.last_heartbeat = datetime.now(timezone.utc)
            sensor.total_flows = (sensor.total_flows or 0) + 1

    # ------------------------------------------------------------------ #
    async def _emit_telemetry(self, flow, detection) -> None:
        payload = {
            "timestamp": time.time(),
            "src_ip": flow.get("Src_IP"),
            "dst_ip": flow.get("Dst_IP"),
            "dst_port": flow.get("Dst_Port"),
            "protocol": flow.get("Protocol"),
            "bytes_out": flow.get("Total_Fwd_Bytes", 0),
            "bytes_in": flow.get("Total_Bwd_Bytes", 0),
        }
        await bus.publish("telemetry", payload)

        self._traffic_accum["bytes"] += flow.get("Total_Fwd_Bytes", 0) + flow.get("Total_Bwd_Bytes", 0)
        self._traffic_accum["packets"] += flow.get("Total_Fwd_Packets", 0) + flow.get("Total_Bwd_Packets", 0)
        self._traffic_accum["flows"] += 1
        now = time.time()
        if now - self._last_traffic_emit >= 1.0:
            await bus.publish("traffic", {
                "timestamp": now,
                "bytes_per_sec": self._traffic_accum["bytes"],
                "packets_per_sec": self._traffic_accum["packets"],
                "active_flows": self._traffic_accum["flows"],
            })
            self._traffic_accum = {"bytes": 0.0, "packets": 0.0, "flows": 0.0}
            self._last_traffic_emit = now

        if detection:
            alert_event = await self._persist_detection(detection)
            # Websocket consumers receive the same stable, serialised object as
            # the REST API.  Publishing the engine payload here used to omit the
            # database alert id, making notifications impossible to de-duplicate
            # or open reliably.
            await bus.publish("alerts", alert_event)

    # ------------------------------------------------------------------ #
    async def _persist_detection(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        ctx = detection.get("context", {})
        clf = detection.get("classification", {})
        async with session_factory() as db:
            # Upsert incident
            incident = (await db.execute(select(Incident).where(Incident.id == detection["incident_id"]))).scalar_one_or_none()
            incident_created = not incident
            family = detection.get("attack_family") or detection.get("detection_type") or "Behavioral Anomaly"
            if incident_created:
                incident = Incident(
                    id=detection["incident_id"], entity=detection.get("correlation_entity") or ctx.get("src_ip", ""),
                    family=family,
                    count=detection.get("incident_count", 1),
                    peak_signal=detection.get("confidence", 0.0),
                    severity=detection["severity"],
                )
                db.add(incident)
                INCIDENTS_CREATED.labels(detection["severity"]).inc()
            else:
                incident.count = detection.get("incident_count", incident.count)
                incident.last_seen = datetime.now(timezone.utc)
                incident.severity = detection["severity"]
                incident.family = family
                incident.peak_signal = max(incident.peak_signal, detection.get("confidence", 0.0))

            tactic, technique, description = mitre_for(
                detection.get("detection_type"), clf.get("primary_expert")
            )
            d = Detection(
                incident_id=detection["incident_id"],
                timestamp=datetime.now(timezone.utc),
                env_id=detection.get("env_id"),
                severity=detection["severity"],
                confidence=detection["confidence"],
                entity_risk=detection["entity_risk"],
                detection_type=detection["detection_type"],
                anomaly_score=detection["anomaly_score"],
                mitre_tactic=tactic,
                mitre_technique=technique,
                mitre_description=description,
                global_score=detection.get("global_score"),
                group_score=detection.get("group_score"),
                host_score=detection.get("host_score"),
                reason=detection.get("reason"),
                src_ip=ctx.get("src_ip"),
                dst_ip=ctx.get("dst_ip"),
                dst_port=ctx.get("dst_port"),
                protocol=ctx.get("protocol"),
                group_name=ctx.get("group"),
                identity=ctx.get("identity"),
                device_type=ctx.get("device_type"),
                process_name=ctx.get("process_name"),
                process_id=ctx.get("process_id"),
                subnet=ctx.get("subnet"),
                primary_expert=clf.get("primary_expert"),
                expert_distribution=clf.get("expert_distribution", {}),
                expert_probs=clf.get("expert_probs", {}),
                moe_score=clf.get("moe_score", 0.0),
                raw_flow=detection.get("triggering_log", {}),
            )
            db.add(d)
            await db.commit()
            await db.refresh(d)
            alert_event = AlertOut.model_validate(d).model_dump(mode="json")
            await bus.publish("incidents", {
                "id": incident.id,
                "entity": incident.entity,
                "family": incident.family,
                "severity": incident.severity,
                "status": incident.status,
                "count": incident.count,
                "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
            })

            mitigation = None
            if response_policy_matches(detection):
                selected_action, selected_target = recommended_response(detection)
                existing = (await db.execute(select(MitigationAction).where(
                    MitigationAction.incident_id == detection["incident_id"],
                    MitigationAction.action == selected_action,
                    MitigationAction.status.in_(["pending_approval", "queued", "dispatched"]),
                ))).scalar_one_or_none()
                if not existing:
                    # Entity-level dedupe: a storm must not queue the same
                    # control repeatedly under different incidents.
                    existing = (await db.execute(select(MitigationAction).where(
                        MitigationAction.entity == selected_target,
                        MitigationAction.action == selected_action,
                        MitigationAction.status.in_(["pending_approval", "queued", "dispatched"]),
                    ))).scalar_one_or_none()
                allowed = True
                if not existing and settings.response_mode == "automatic":
                    allowed = await auto_action_budget_available(db)
                    if not allowed:
                        logger.warning("Automatic response budget exhausted; holding %s for %s",
                                       selected_action, selected_target)
                if not existing and allowed:
                    mitigation = new_policy_action(detection)
                    db.add(mitigation)
                    await db.commit()
                    await db.refresh(mitigation)

            # AI triage is queued, debounced per incident, and rate-limited so a
            # detection storm produces one evidence dossier rather than one call
            # per flow.
            if detection.get("fidelity_action") in {"create", "merge"} and self.triage:
                self.triage.enqueue(d.id, detection)

            # Every incident opens with a deterministic, grounded plan. The AI
            # assessment replaces it when the batcher completes, so the console
            # never shows an empty playbook panel.
            if detection.get("fidelity_action") in {"create", "escalate"}:
                has_plan = await db.scalar(
                    select(Playbook.id).where(Playbook.incident_id == detection["incident_id"]).limit(1)
                )
                if not has_plan:
                    from ..llm.service import provisional_playbook
                    try:
                        plan = provisional_playbook(detection)
                        db.add(Playbook(
                            detection_id=d.id,
                            incident_id=detection["incident_id"],
                            attack_summary=plan.get("attack_summary", ""),
                            technical_analysis=plan.get("technical_analysis"),
                            severity=plan.get("severity", detection.get("severity", "medium")),
                            confidence=plan.get("confidence", "medium"),
                            mitre_attack=plan.get("mitre_attack", {}),
                            steps=plan.get("playbook", []),
                            sources=plan.get("sources", []),
                            false_positive_assessment=plan.get("false_positive_assessment"),
                            is_fallback=True,
                        ))
                        await db.commit()
                    except Exception:
                        logger.exception("Provisional playbook could not be stored")

            if detection.get("fidelity_action") in {"create", "escalate"}:
                severity = detection.get("severity", "low")
                if SEVERITY.get(severity, 0) >= SEVERITY[settings.webhook_min_severity]:
                    self.webhooks.enqueue("com.attacksentry.incident.detected", {
                        "incident_id": detection["incident_id"],
                        "entity": ctx.get("src_ip"),
                        "severity": severity,
                        "confidence": detection.get("confidence", 0),
                        "family": detection.get("detection_type") or "Behavioral anomaly",
                        "detection_type": detection.get("detection_type"),
                        "fidelity_action": detection.get("fidelity_action"),
                    })
            if mitigation and mitigation.status == "queued":
                task = asyncio.create_task(dispatch_mitigation(mitigation.id, self.response_dispatch))
                self._track(task)

            return alert_event

    async def _llm_triage(self, detection: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            return await self.llm.generate_playbook(detection)
        except Exception as exc:
            logger.error("LLM triage failed: %s", exc)
            return None

    async def _retention_loop(self) -> None:
        while self._running:
            try:
                await self._enforce_retention()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Retention cleanup failed")
            await asyncio.sleep(max(1.0, settings.retention_cleanup_hours) * 3600)

    @staticmethod
    async def _enforce_retention() -> None:
        # PostgreSQL uses Timescale retention policies; SQLite needs an explicit
        # prune so a long-running dev instance does not grow without bound.
        if not settings.database_url.startswith("sqlite"):
            return
        cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, int(settings.retention_days)))
        async with session_factory() as db:
            result = await db.execute(delete(FlowLog).where(FlowLog.timestamp < cutoff))
            await db.commit()
        if result.rowcount:
            logger.info("Retention pruned %d flow records older than %s", result.rowcount, cutoff.date())

    def _track(self, task: asyncio.Task) -> None:
        """Keep a reference and surface failures instead of dropping them."""
        self._background_tasks.add(task)

        def _done(finished: asyncio.Task) -> None:
            self._background_tasks.discard(finished)
            if not finished.cancelled() and finished.exception():
                logger.error("Background response task failed: %s", finished.exception())

        task.add_done_callback(_done)

    async def _reconcile_response_expiry(self) -> None:
        while self._running:
            try:
                now = datetime.now(timezone.utc)
                async with session_factory() as db:
                    rows = (await db.execute(select(MitigationAction).where(
                        MitigationAction.status == "dispatched",
                        MitigationAction.expires_at.is_not(None),
                        MitigationAction.expires_at <= now,
                    ).limit(100))).scalars().all()
                    ids = [row.id for row in rows]
                    for row in rows:
                        row.status = "release_queued"
                    if rows:
                        await db.commit()
                for action_id in ids:
                    await dispatch_release(action_id, self.response_dispatch)
                # Recover automatic controls left queued by a crash or restart.
                async with session_factory() as db:
                    stuck = (await db.execute(select(MitigationAction.id).where(
                        MitigationAction.mode == "automatic",
                        MitigationAction.status == "queued",
                        MitigationAction.created_at <= now - timedelta(seconds=60),
                    ).limit(20))).scalars().all()
                for action_id in stuck:
                    await dispatch_mitigation(action_id, self.response_dispatch)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Response expiry reconciliation failed")
            await asyncio.sleep(30)

    async def _generate_and_persist_playbook(self, detection_id: str, detection: Dict[str, Any]) -> None:
        playbook = await self._llm_triage(detection)
        if playbook:
            await self._persist_playbook(detection_id, detection, playbook)

    async def _persist_playbook(
        self, detection_id: str, detection: Dict[str, Any], playbook: Dict[str, Any]
    ) -> None:
        async with session_factory() as db:
            d = (await db.execute(select(Detection).where(Detection.id == detection_id))).scalar_one_or_none()
            if not d:
                return
            db.add(Playbook(
                detection_id=d.id, incident_id=detection["incident_id"],
                attack_summary=playbook.get("attack_summary", ""),
                technical_analysis=playbook.get("technical_analysis"),
                severity=playbook.get("severity", detection["severity"]),
                confidence=playbook.get("confidence", "medium"),
                mitre_attack=playbook.get("mitre_attack", {}),
                steps=playbook.get("playbook", []),
                sources=playbook.get("sources", []),
                false_positive_assessment=playbook.get("false_positive_assessment"),
                is_fallback="_llm_error" in playbook,
            ))
            ma = playbook.get("mitre_attack") or {}
            if ma.get("technique") and ma["technique"] not in ("Unknown", None):
                d.mitre_tactic = ma.get("tactic") or d.mitre_tactic
                d.mitre_technique = ma["technique"]
                d.mitre_description = ma.get("description") or d.mitre_description
            await db.commit()
