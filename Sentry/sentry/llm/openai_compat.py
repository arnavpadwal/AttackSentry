"""OpenAI-compatible provider (LM Studio, Ollama, vLLM, OpenAI, Azure)."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx

from ..metrics import LLM_RATE_LIMITED

logger = logging.getLogger("sentry.llm.openai")


class OpenAICompatProvider:
    def __init__(self, base_url: str, model: str, api_key: str = "not-needed",
                 timeout: float = 120.0, max_tokens: int = 2048, temperature: float = 0.3):
        self.base_url = base_url.rstrip("/")
        self.endpoint = f"{self.base_url}/v1/chat/completions"
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.temperature = temperature

    async def _model_name(self, client: httpx.AsyncClient) -> str:
        if self.model != "default":
            return self.model
        # LM Studio can list downloaded (not merely loaded) models here.  Do
        # not silently select an arbitrary first item: it can yield a model-not-
        # loaded error while a different model is actively serving requests.
        return "default"

    async def generate(self, messages: List[Dict[str, str]]) -> str:
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            model = await self._model_name(client)
            payload: Dict[str, Any] = {
                "model": model,
                "messages": messages,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
            }
            # LM Studio models differ in grammar/JSON-schema support. The
            # system prompt already requires the schema, while omitting the API
            # constraint keeps local reasoning models compatible.
            host = (urlparse(self.base_url).hostname or "").lower()
            is_local = host in {"127.0.0.1", "localhost", "host.docker.internal"}
            if not is_local:
                payload["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {"name": "anomaly_triage", "strict": True, "schema": _SCHEMA},
                }
            r = await self._post_with_retry(client, payload, headers)
            if 400 <= r.status_code < 500 and "response_format" in payload:
                # LM Studio runtimes vary in structured-output support. Retry
                # every client-side rejection without it rather than assuming
                # one specific HTTP status code.
                payload.pop("response_format", None)
                r = await self._post_with_retry(client, payload, headers)
            r.raise_for_status()
            data = r.json()
            return _extract_content(data)

    async def _post_with_retry(self, client, payload, headers):
        last = None
        for attempt in range(3):
            last = await client.post(self.endpoint, json=payload, headers=headers)
            if last.status_code != 429 and last.status_code < 500:
                return last
            if last.status_code == 429:
                LLM_RATE_LIMITED.inc()
            if attempt < 2:
                retry_after = last.headers.get("retry-after")
                try:
                    delay = float(retry_after) if retry_after else 2.0 * (2 ** attempt)
                except ValueError:
                    delay = 2.0 * (2 ** attempt)
                logger.warning("AI provider returned %s — retrying in %.1fs", last.status_code, delay)
                await asyncio.sleep(min(delay, 30.0))
        return last

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{self.base_url}/v1/models")
                return r.status_code == 200
        except Exception:
            return False


def _extract_content(data: Dict[str, Any]) -> str:
    if "choices" in data and data["choices"]:
        c = data["choices"][0]
        msg = c.get("message", {})
        content = msg.get("content", "") or c.get("text", "")
        # Reasoning models (e.g. Qwen3.5 reasoning distillations) sometimes put
        # the answer in `reasoning_content` and leave `content` empty, especially
        # in structured-output mode.
        if not content:
            content = msg.get("reasoning_content", "")
        if content:
            return content
    if "output" in data and data["output"]:
        out = data["output"][0]
        if out.get("type") == "message":
            return out.get("content", "")
    return data.get("content", "")


from .base import TRIAGE_SCHEMA as _SCHEMA  # noqa: E402
