"""BM25 retrieval over the bundled security corpus.

No external service and no model: the index is built once from the JSONL
files in ``data/`` and queried with the same vocabulary the triage report
uses. That keeps triage deterministic and offline.
"""
from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

DATA_DIR = Path(__file__).with_name("data")

_TOKEN_RE = re.compile(r"[a-z0-9]+(?:\.[0-9]+)?")
_STOPWORDS = frozenset(
    """a an and are as at be by for from has have if in into is it its of on or
    that the their then there these this to was were will with without""".split()
)

# Detection vocabulary -> standard wording used by the sources.
_SYNONYMS: dict[str, tuple[str, ...]] = {
    "ddos": ("denial", "service", "flood", "impact", "t1498"),
    "dos": ("denial", "service", "t1498"),
    "reflection": ("reflection", "amplification", "t1498.002", "spoofed"),
    "amplification": ("amplification", "reflection", "t1498.002"),
    "bruteforce": ("brute", "force", "password", "guessing", "t1110"),
    "brute": ("brute", "force", "password", "t1110"),
    "scan": ("scan", "discovery", "enumeration", "t1046"),
    "recon": ("reconnaissance", "discovery", "scan", "t1046"),
    "beacon": ("command", "control", "beacon", "c2", "t1071"),
    "c2": ("command", "control", "c2", "t1071"),
    "exfil": ("exfiltration", "t1041", "data", "transfer"),
    "exfiltration": ("exfiltration", "t1041", "data", "transfer"),
    "sqli": ("injection", "sql", "a03", "t1190"),
    "sql": ("injection", "sql", "a03", "t1190"),
    "xss": ("injection", "script", "a03"),
    "web": ("web", "application", "exploitation", "t1190"),
    "rdp": ("remote", "services", "t1021", "lateral"),
    "rdpbrute": ("remote", "services", "brute", "t1110", "t1021"),
    "fuzz": ("exploitation", "service", "t1190", "t1059"),
    "exploit": ("exploitation", "t1190", "t1059"),
    "malware": ("malware", "execution", "t1059", "t1204"),
    "dns": ("dns", "t1071.004", "t1498.002"),
    "containment": ("containment", "response", "isolation", "block"),
    "playbook": ("response", "handling", "containment", "recovery"),
    "logging": ("logging", "monitoring", "a.8.15", "a.8.16"),
    "evidence": ("evidence", "collection", "preservation"),
}

_K1 = 1.5
_B = 0.75


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.casefold()) if t not in _STOPWORDS and len(t) > 1]


@dataclass(frozen=True)
class Chunk:
    id: str
    source: str
    kind: str
    title: str
    text: str
    url: str = ""
    tactics: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Hit:
    chunk: Chunk
    score: float


@dataclass
class _Doc:
    chunk: Chunk
    tokens: list[str]
    length: int
    counts: dict[str, int]


class KnowledgeBase:
    """A small, read-only BM25 index. Safe to share across tasks."""

    def __init__(self, chunks: Iterable[Chunk], catalog: dict[str, dict[str, Any]]):
        self._docs = [
            _Doc(chunk=c, tokens=t, length=len(t), counts=_counts(t))
            for c in chunks
            for t in [_tokens(f"{c.title} {c.text} {' '.join(c.tactics)}")]
        ]
        self.catalog = catalog
        self._by_id = {doc.chunk.id: doc.chunk for doc in self._docs}
        self._df: dict[str, int] = {}
        for doc in self._docs:
            for term in doc.counts:
                self._df[term] = self._df.get(term, 0) + 1
        self._avg = (sum(d.length for d in self._docs) / len(self._docs)) if self._docs else 0.0
        self._n = len(self._docs)

    def __len__(self) -> int:
        return self._n

    def _idf(self, term: str) -> float:
        df = self._df.get(term, 0)
        return math.log(1 + (self._n - df + 0.5) / (df + 0.5))

    def search(self, query: str, top_k: int = 5, kinds: frozenset[str] | None = None) -> list[Hit]:
        terms = _tokens(self._expand(query))
        if not terms:
            return []
        scored: list[Hit] = []
        for doc in self._docs:
            if kinds and doc.chunk.kind not in kinds:
                continue
            score = 0.0
            for term in terms:
                freq = doc.counts.get(term, 0)
                if not freq:
                    continue
                denom = freq + _K1 * (1 - _B + _B * doc.length / (self._avg or 1))
                score += self._idf(term) * freq * (_K1 + 1) / denom
            if score > 0:
                scored.append(Hit(doc.chunk, score))
        scored.sort(key=lambda h: h.score, reverse=True)
        return scored[:top_k]

    def _expand(self, query: str) -> str:
        extra: list[str] = []
        lowered = query.casefold().replace("-", "").replace(" ", "")
        for key, values in _SYNONYMS.items():
            if key in lowered:
                extra.extend(values)
        return f"{query} {' '.join(extra)}" if extra else query

    def technique(self, technique_id: str) -> dict[str, Any] | None:
        return self.catalog.get(technique_id.upper())

    def chunk(self, chunk_id: str) -> Chunk | None:
        return self._by_id.get(chunk_id)

    def techniques_for(self, text: str, limit: int = 3) -> list[dict[str, Any]]:
        """Return catalog techniques ranked for a short detection label."""
        seen: set[str] = set()
        result: list[dict[str, Any]] = []
        for hit in self.search(text, top_k=limit * 3, kinds=frozenset({"technique"})):
            technique_id = hit.chunk.id.split(":", 1)[1]
            entry = self.catalog.get(technique_id)
            if not entry or technique_id in seen:
                continue
            seen.add(technique_id)
            result.append(entry)
            if len(result) >= limit:
                break
        return result


def _counts(tokens: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for token in tokens:
        counts[token] = counts.get(token, 0) + 1
    return counts


def load_chunks(data_dir: Path = DATA_DIR) -> list[Chunk]:
    chunks: list[Chunk] = []
    for path in sorted(data_dir.glob("*.jsonl")):
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                chunks.append(
                    Chunk(
                        id=row["id"],
                        source=row["source"],
                        kind=row.get("kind", "reference"),
                        title=row["title"],
                        text=row["text"],
                        url=row.get("url", ""),
                        tactics=tuple(row.get("tactics") or ()),
                    )
                )
    return chunks


def load_catalog(data_dir: Path = DATA_DIR) -> dict[str, dict[str, Any]]:
    path = data_dir / "mitre_catalog.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def get_knowledge_base() -> KnowledgeBase:
    return KnowledgeBase(load_chunks(), load_catalog())


def format_references(hits: list[Hit], max_chars: int = 4500) -> str:
    """Render hits as compact, citable passages for the prompt."""
    blocks: list[str] = []
    used = 0
    for index, hit in enumerate(hits, start=1):
        source = hit.chunk.source
        title = hit.chunk.title
        body = hit.chunk.text
        if len(body) > 900:
            body = body[:900].rsplit(" ", 1)[0] + "…"
        block = f"[{index}] {source} — {title}\n{body}"
        if hit.chunk.url:
            block += f"\nRef: {hit.chunk.url}"
        if used + len(block) > max_chars:
            break
        blocks.append(block)
        used += len(block)
    return "\n\n".join(blocks)


def build_query(report: dict[str, Any]) -> str:
    """Turn a triage report into one retrieval query."""
    context = report.get("context") or {}
    parts = [
        str(report.get("detection_type") or ""),
        str(report.get("family") or ""),
        str(report.get("reason") or "")[:300],
        str(context.get("protocol") or ""),
        str(context.get("src_port") or ""),
        str(context.get("dst_port") or ""),
        "response playbook containment detection",
    ]
    return " ".join(part for part in parts if part)


def rag_enabled() -> bool:
    return os.getenv("SENTRY_RAG_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}


def retrieve(report: dict[str, Any], top_k: int | None = None, max_chars: int | None = None) -> tuple[str, list[dict[str, str]]]:
    """Return (prompt block, source citations) for a report."""
    if not rag_enabled():
        return "", []
    kb = get_knowledge_base()
    k = top_k or int(os.getenv("SENTRY_RAG_TOP_K", "5"))
    budget = max_chars or int(os.getenv("SENTRY_RAG_MAX_CHARS", "4500"))
    hits = kb.search(build_query(report), top_k=k)
    citations = _dedupe_citations(hits)
    return format_references(hits, budget), citations


def _dedupe_citations(hits: list[Hit]) -> list[dict[str, str]]:
    seen: set[str] = set()
    result: list[dict[str, str]] = []
    for hit in hits:
        if hit.chunk.id in seen:
            continue
        seen.add(hit.chunk.id)
        result.append(
            {
                "id": hit.chunk.id,
                "source": hit.chunk.source,
                "title": hit.chunk.title,
                "url": hit.chunk.url,
            }
        )
    return result
