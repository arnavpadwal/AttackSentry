"""Batched, rate-limited incident triage.

An alert storm must not become an LLM request storm. Detections are grouped by
incident, held for a short debounce window, and sent as one evidence dossier.
Workers are bounded, calls are serialized by a minimum interval, and rate-limit
responses are retried with exponential backoff.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional

from sqlalchemy import select

from ..config import settings
from ..db import session_factory
from ..db.models import Detection, Playbook
from ..metrics import (
    LLM_BATCH_SIZE,
    LLM_QUEUE_DEPTH,
    LLM_RATE_LIMITED,
    LLM_TRIAGE_LATENCY,
)

logger = logging.getLogger("sentry.llm.batcher")


@dataclass
class TriageJob:
    incident_id: str
    family: str
    detection_ids: list[str] = field(default_factory=list)
    detection_type: str = "Behavioral anomaly"
    severity: str = "low"
    confidence: float = 0.0
    entity_risk: float = 0.0
    anomaly_score: float = 0.0
    reason: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    classification: Dict[str, Any] = field(default_factory=dict)
    event_count: int = 1
    first_enqueued: float = field(default_factory=time.time)
    last_enqueued: float = field(default_factory=time.time)
    attempts: int = 0


class TriageBatcher:
    def __init__(
        self,
        llm,
        persist: Callable[[str, Dict[str, Any], Dict[str, Any]], Awaitable[None]],
    ):
        self.llm = llm
        self.persist = persist
        self._pending: Dict[str, TriageJob] = {}
        self._inflight: set[str] = set()
        self._tasks: set[asyncio.Task] = set()
        self._running = False
        self._loop_task: Optional[asyncio.Task] = None
        self._sem = asyncio.Semaphore(max(1, settings.llm_max_concurrency))
        self._throttle_lock = asyncio.Lock()
        self._last_call = 0.0

    async def start(self) -> None:
        self._running = True
        self._loop_task = asyncio.create_task(self._loop(), name="llm-triage-batcher")
        logger.info(
            "AI triage batcher started (window=%.1fs, concurrency=%d, interval=%.1fs)",
            settings.llm_batch_window_seconds,
            settings.llm_max_concurrency,
            settings.llm_min_interval_seconds,
        )

    async def stop(self) -> None:
        self._running = False
        if self._loop_task:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
        pending = list(self._tasks)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._tasks.clear()
        if self._pending:
            logger.warning("AI triage stopped with %d unprocessed incidents", len(self._pending))
        self._pending.clear()
        LLM_QUEUE_DEPTH.set(0)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "queued": len(self._pending),
            "inflight": len(self._inflight),
            "window_seconds": settings.llm_batch_window_seconds,
            "concurrency": settings.llm_max_concurrency,
            "min_interval_seconds": settings.llm_min_interval_seconds,
        }

    def enqueue(self, detection_id: str, detection: Dict[str, Any]) -> None:
        incident_id = detection.get("incident_id")
        if not incident_id:
            return
        job = self._pending.get(incident_id)
        if job is None:
            # Only a new incident opens a dossier. Later merges are folded into
            # that job while it is still within the debounce window.
            if detection.get("fidelity_action") != "create":
                return
            if len(self._pending) >= settings.llm_queue_capacity:
                oldest = min(self._pending, key=lambda key: self._pending[key].first_enqueued)
                self._pending.pop(oldest, None)
                logger.warning("AI triage queue full — dropped oldest incident %s", oldest)
            job = TriageJob(
                incident_id=incident_id,
                family=str(
                    detection.get("attack_family")
                    or detection.get("detection_type")
                    or "Behavioral Anomaly"
                ),
            )
            self._pending[incident_id] = job
        if detection_id and detection_id not in job.detection_ids:
            job.detection_ids.append(detection_id)
        job.detection_type = detection.get("detection_type") or job.detection_type
        job.severity = detection.get("severity") or job.severity
        job.confidence = max(job.confidence, float(detection.get("confidence") or 0))
        job.entity_risk = max(job.entity_risk, float(detection.get("entity_risk") or 0))
        job.anomaly_score = max(job.anomaly_score, float(detection.get("anomaly_score") or 0))
        job.event_count = max(job.event_count, int(detection.get("incident_count") or 1))
        job.reason = detection.get("reason") or job.reason
        job.context = detection.get("context") or job.context
        job.classification = detection.get("classification") or job.classification
        job.last_enqueued = time.time()
        LLM_QUEUE_DEPTH.set(len(self._pending))

    async def _loop(self) -> None:
        while self._running:
            now = time.time()
            ready = [
                incident_id
                for incident_id, job in self._pending.items()
                if incident_id not in self._inflight
                and now - job.first_enqueued >= settings.llm_batch_window_seconds
            ]
            for incident_id in ready[:8]:
                job = self._pending.pop(incident_id, None)
                if not job:
                    continue
                self._inflight.add(incident_id)
                task = asyncio.create_task(self._run_job(job))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
            LLM_QUEUE_DEPTH.set(len(self._pending))
            await asyncio.sleep(0.25)

    async def _run_job(self, job: TriageJob) -> None:
        started = time.perf_counter()
        async with self._sem:
            try:
                if await self._has_real_playbook(job.incident_id):
                    return
                report = await self._build_report(job)
                await self._throttle()
                playbook = await self.llm.generate_playbook(report)
                error = str(playbook.get("_llm_error") or "").casefold()
                if ("429" in error or "rate limit" in error) and job.attempts < settings.llm_max_retries:
                    job.attempts += 1
                    LLM_RATE_LIMITED.inc()
                    delay = min(60.0, 5.0 * (2 ** (job.attempts - 1)))
                    job.first_enqueued = time.time() + delay
                    self._pending[job.incident_id] = job
                    logger.warning(
                        "AI provider rate-limited incident %s — retry %d in %.0fs",
                        job.incident_id, job.attempts, delay,
                    )
                    return
                await self.persist(job.detection_ids[-1], report, playbook)
                LLM_BATCH_SIZE.observe(max(1, len(job.detection_ids)))
                LLM_TRIAGE_LATENCY.observe(time.perf_counter() - started)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("AI triage failed for incident %s", job.incident_id)
            finally:
                self._inflight.discard(job.incident_id)
                LLM_QUEUE_DEPTH.set(len(self._pending))

    async def _throttle(self) -> None:
        async with self._throttle_lock:
            wait = settings.llm_min_interval_seconds - (time.monotonic() - self._last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()

    @staticmethod
    async def _has_real_playbook(incident_id: str) -> bool:
        async with session_factory() as db:
            playbook = (await db.execute(
                select(Playbook).where(Playbook.incident_id == incident_id)
                .order_by(Playbook.created_at.desc()).limit(1)
            )).scalar_one_or_none()
        return bool(playbook and not playbook.is_fallback and playbook.steps)

    async def _build_report(self, job: TriageJob) -> Dict[str, Any]:
        async with session_factory() as db:
            rows = (await db.execute(
                select(Detection).where(Detection.incident_id == job.incident_id)
                .order_by(Detection.timestamp.desc())
                .limit(max(1, settings.llm_batch_max_evidence))
            )).scalars().all()

        evidence = [
            {
                "timestamp": row.timestamp.isoformat(),
                "detection_type": row.detection_type,
                "severity": row.severity,
                "confidence": round(float(row.confidence or 0), 3),
                "src_ip": row.src_ip,
                "dst_ip": row.dst_ip,
                "dst_port": row.dst_port,
                "protocol": row.protocol,
                "primary_expert": row.primary_expert,
                "moe_score": round(float(row.moe_score or 0), 4),
                "anomaly_score": round(float(row.anomaly_score or 0), 4),
                "reason": row.reason,
            }
            for row in rows
        ]
        latest = rows[0] if rows else None
        entities = sorted({row.src_ip for row in rows if row.src_ip})
        targets = sorted({row.dst_ip for row in rows if row.dst_ip})
        return {
            "incident_id": job.incident_id,
            "attack_family": job.family,
            "detection_type": job.detection_type,
            "severity": job.severity,
            "confidence": round(job.confidence, 3),
            "anomaly_score": round(job.anomaly_score, 3),
            "entity_risk": round(job.entity_risk, 1),
            "reason": job.reason,
            "context": job.context or ({
                "src_ip": latest.src_ip if latest else None,
                "dst_ip": latest.dst_ip if latest else None,
                "dst_port": latest.dst_port if latest else None,
                "protocol": latest.protocol if latest else None,
                "group": latest.group_name if latest else None,
                "identity": latest.identity if latest else None,
                "subnet": latest.subnet if latest else None,
            }),
            "classification": job.classification,
            "incident_summary": {
                "detections": job.event_count,
                "evidence_sampled": len(evidence),
                "source_entities": entities[:25],
                "targets": targets[:25],
                "first_seen": rows[-1].timestamp.isoformat() if rows else None,
                "last_seen": rows[0].timestamp.isoformat() if rows else None,
            },
            "evidence": evidence,
        }
