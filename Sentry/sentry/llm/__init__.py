"""LLM triage layer: pluggable, async, with structured-output and fallback.

Supports any OpenAI-compatible endpoint (LM Studio, Ollama, vLLM, OpenAI, Azure)
plus Anthropic. The provider is chosen via ``SENTRY_LLM_PROVIDER``.
"""
