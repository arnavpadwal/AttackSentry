"""Offline knowledge base for triage: MITRE ATT&CK, OWASP, NIST, ISO and runbooks."""
from __future__ import annotations

from .retriever import KnowledgeBase, get_knowledge_base

__all__ = ["KnowledgeBase", "get_knowledge_base"]
