"""Native local LLM providers: LM Studio v1 and Ollama, with auto selection."""
from __future__ import annotations

import asyncio
from typing import Dict, List

import httpx


class LocalProvider:
    """Probe LM Studio first, then Ollama; use an already resident model first."""

    def __init__(self, provider: str, base_url: str, model: str, api_key: str, timeout: float, max_tokens: int, temperature: float):
        self.provider = provider
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.temperature = temperature

    async def generate(self, messages: List[Dict[str, str]]) -> str:
        candidates = self._candidates()
        errors: list[str] = []
        for kind, url in candidates:
            for attempt in range(3):
                try:
                    if kind == "lmstudio":
                        return await self._lmstudio(url, messages)
                    return await self._ollama(url, messages)
                except Exception as exc:
                    text = str(exc).casefold()
                    transient = "429" in text or "503" in text or "timeout" in text
                    if transient and attempt < 2:
                        await asyncio.sleep(2.0 * (2 ** attempt))
                        continue
                    errors.append(f"{kind}: {exc}")
                    break
        raise RuntimeError("; ".join(errors) or "No local LLM provider is reachable")

    async def health_check(self) -> bool:
        for kind, base in self._candidates():
            try:
                async with httpx.AsyncClient(timeout=5) as client:
                    path = "/api/v1/models" if kind == "lmstudio" else "/api/tags"
                    response = await client.get(f"{base}{path}", headers=self._headers())
                    if response.status_code == 200:
                        return True
            except Exception:
                continue
        return False

    def _candidates(self) -> list[tuple[str, str]]:
        lm = self.base_url if self.provider == "lmstudio" else "http://127.0.0.1:1234"
        ollama = self.base_url if self.provider == "ollama" else "http://127.0.0.1:11434"
        if self.provider == "lmstudio":
            return [("lmstudio", lm)]
        if self.provider == "ollama":
            return [("ollama", ollama)]
        return [("lmstudio", lm), ("ollama", ollama)]

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key and self.api_key != "not-needed":
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def _lmstudio(self, base: str, messages: List[Dict[str, str]]) -> str:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            model = await self._lm_model(client, base)
            system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
            prompt = "\n\n".join(m["content"] for m in messages if m["role"] != "system")
            response = await client.post(f"{base}/api/v1/chat", headers=self._headers(), json={
                "model": model, "system_prompt": system, "input": prompt,
                # Keep the native v1 payload to its documented portable core.
                "store": False,
            })
            response.raise_for_status()
            body = response.json()
            output = body.get("output", [])
            text = "".join(item.get("content", "") for item in output if isinstance(item, dict))
            if not text:
                raise RuntimeError(f"LM Studio returned no message content: {body}")
            return text

    async def _lm_model(self, client: httpx.AsyncClient, base: str) -> str:
        response = await client.get(f"{base}/api/v1/models", headers=self._headers(), timeout=10)
        response.raise_for_status()
        body = response.json()
        models = body.get("data") or body.get("models") or []
        loaded = [m.get("id") for m in models if str(m.get("state") or m.get("status") or "").lower() in {"loaded", "idle", "active"}]
        # Prefer the explicitly selected model when it is resident. Other
        # loaded models may be unrelated interactive-chat workloads.
        if self.model in loaded:
            return self.model
        if loaded:
            return loaded[0]
        if self.model and self.model != "default":
            # Native v1 automatically loads an available selected model.
            return self.model
        if models:
            return models[0].get("id")
        raise RuntimeError("LM Studio has no available models")

    async def _ollama(self, base: str, messages: List[Dict[str, str]]) -> str:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            model = await self._ollama_model(client, base)
            system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
            prompt = "\n\n".join(m["content"] for m in messages if m["role"] != "system")
            response = await client.post(f"{base}/api/generate", json={
                "model": model, "system": system, "prompt": prompt, "stream": False,
                "options": {"temperature": self.temperature, "num_predict": self.max_tokens},
            })
            response.raise_for_status()
            text = response.json().get("response", "")
            if not text:
                raise RuntimeError("Ollama returned no message content")
            return text

    async def _ollama_model(self, client: httpx.AsyncClient, base: str) -> str:
        running = await client.get(f"{base}/api/ps", timeout=10)
        if running.status_code == 200 and running.json().get("models"):
            return running.json()["models"][0]["name"]
        if self.model and self.model != "default":
            return self.model
        tags = await client.get(f"{base}/api/tags", timeout=10)
        tags.raise_for_status()
        models = tags.json().get("models", [])
        if models:
            return models[0]["name"]
        raise RuntimeError("Ollama has no installed models")
