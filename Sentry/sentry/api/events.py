"""In-process pub/sub bus for pushing live events to WebSocket clients."""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any, Dict, Set


class EventBus:
    def __init__(self) -> None:
        self._subs: Dict[str, Set[asyncio.Queue]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def subscribe(self, channel: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        async with self._lock:
            self._subs[channel].add(q)
        return q

    async def unsubscribe(self, channel: str, q: asyncio.Queue) -> None:
        async with self._lock:
            self._subs[channel].discard(q)

    async def publish(self, channel: str, payload: Any) -> None:
        async with self._lock:
            subs = list(self._subs[channel])
        for q in subs:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                    q.put_nowait(payload)
                except Exception:
                    pass


bus = EventBus()
