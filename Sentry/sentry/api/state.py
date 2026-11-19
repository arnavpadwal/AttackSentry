"""Shared runtime state shared between the API and the ingestion pipeline."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AppState:
    engine: Any = None
    started_at: float = field(default_factory=time.time)
    llm: Any = None
    pipeline: Any = None
    webhooks: Any = None
    nats_connected: bool = False
    nats_error: str | None = None
    background_tasks: set[asyncio.Task] = field(default_factory=set)

    def track_task(self, coroutine) -> asyncio.Task:
        task = asyncio.create_task(coroutine)
        self.background_tasks.add(task)
        task.add_done_callback(self.background_tasks.discard)
        return task


app_state = AppState()
