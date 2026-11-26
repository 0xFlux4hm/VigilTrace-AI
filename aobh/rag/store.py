"""store.py — Report, ReportCorpus and the package-default index path.

Ported from autonomous-bug-hunter/rag/rag_store.py (local RAG store over the
disclosed HackerOne report corpus, source: https://github.com/reddelexc/
hackerone-reports — publicly disclosed reports). The original single module
was split along its existing function/class boundaries:

  chunker.py      STOPWORDS / SYNONYMS / TECH_VOCAB / TOKEN_RE, tokenize, expand_query
  embeddings.py   VectorScorer (optional embedding backend, OFF by default)
  vectorstore.py  JSONL index load/save
  retriever.py    InMemoryBM25 (classic BM25 scoring)
  dedup.py        link/title dedupe + find-similar query construction

Every moved name is re-exported here, so old call sites keep working
unchanged (`from aobh.rag.store import ReportCorpus, tokenize, ...`).

Design goals (unchanged):
  * zero third-party dependencies (stdlib only) so it runs inside any agent sandbox;
  * BM25 lexical retrieval + a "signal boost" from upvotes/bounty (rewards = evidence
    the pattern was accepted and impactful);
  * synonym expansion so agent slang matches the corpus' CWE-style naming;
  * filterable by vuln_type / program / min_upvotes / min_bounty;
  * swappable scorer: see embeddings.VectorScorer for plugging an embedding
    backend without changing the tool layer.

Startup builds the inverted index in memory (~15k short docs -> <100ms, a few MB).
For much larger corpora swap retriever.InMemoryBM25 for SQLite FTS5; the
tool-facing API below stays identical.
"""
from __future__ import annotations

import csv
import math
import os
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from aobh.rag.chunker import STOPWORDS, SYNONYMS, TECH_VOCAB, TOKEN_RE, expand_query, tokenize
from aobh.rag.dedup import build_similar_query, tech_terms, title_key, unique_by_link
from aobh.rag.embeddings import VectorScorer
from aobh.rag.retriever import InMemoryBM25
from aobh.rag.vectorstore import load_jsonl, save_jsonl

__all__ = [
    "STOPWORDS", "SYNONYMS", "TECH_VOCAB", "TOKEN_RE", "tokenize", "expand_query",
    "Report", "_boost", "InMemoryBM25", "ReportCorpus", "VectorScorer",
    "build_similar_query", "default_index_path", "load_jsonl", "main",
    "save_jsonl", "tech_terms", "title_key", "unique_by_link",
]


@dataclass
class Report:
    program: str
    title: str
    link: str
    upvotes: int
    bounty: float
    vuln_type: str
    # filled at index time
    doc_tokens: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "program": self.program, "title": self.title, "link": self.link,
            "upvotes": self.upvotes, "bounty": self.bounty, "vuln_type": self.vuln_type,
        }


def _boost(r: Report) -> float:
    """Ranking boost from community/monetary signal. Range ~1.0 .. ~2.2."""
    return 1.0 + 0.15 * math.log1p(r.upvotes) + 0.10 * math.log1p(r.bounty / 100.0)


class ReportCorpus:
    def __init__(self, reports: list[Report]):
        # normalize: empty vuln_type -> "Unspecified", dedupe by link
        clean = []
        for r in unique_by_link(reports):
            r.vuln_type = r.vuln_type.strip() or "Unspecified"
            r.doc_tokens = tokenize(r.title) + tokenize(r.vuln_type) * 2 + tokenize(r.program)
            clean.append(r)
        self.reports = clean
        self.bm25 = InMemoryBM25([r.doc_tokens for r in clean])

    # ---------- loading ----------
    @classmethod
    def from_jsonl(cls, path: str | Path) -> "ReportCorpus":
        return cls(Report(**rec) for rec in load_jsonl(path))

    @classmethod
    def from_csv(cls, path: str | Path) -> "ReportCorpus":
        rows = csv.DictReader(Path(path).read_text(encoding="utf-8", errors="replace").splitlines())
        reports = [
            Report(
                program=(row.get("program") or "").strip(),
                title=(row.get("title") or "").strip(),
                link=(row.get("link") or "").strip(),
                upvotes=int(row["upvotes"] or 0) if str(row.get("upvotes") or "").strip().isdigit() else 0,
                bounty=float(row["bounty"]) if str(row.get("bounty") or "").replace(".", "").strip().lstrip(".").isdigit() else 0.0,
                vuln_type=(row.get("vuln_type") or "").strip(),
            )
            for row in rows
        ]
        return cls(reports)

    # ---------- retrieval ----------
    def _filters(self, r: Report, vuln_type: str | None, program: str | None,
                 min_upvotes: int, min_bounty: float | None) -> bool:
        if vuln_type and vuln_type.lower() not in r.vuln_type.lower():
            return False
        if program and program.lower() not in r.program.lower():
            return False
        if r.upvotes < min_upvotes:
            return False
        if min_bounty is not None and r.bounty < min_bounty:
            return False
        return True

    def query(self, text: str, vuln_type: str | None = None, program: str | None = None,
              min_upvotes: int = 0, min_bounty: float | None = None,
              limit: int = 8, dedup_titles: bool = True) -> list[dict]:
        q = expand_query(text)
        hits = []
        seen_titles: set[str] = set()
        for i, r in enumerate(self.reports):
            if not self._filters(r, vuln_type, program, min_upvotes, min_bounty):
                continue
            s = self.bm25.score(q, i)
            if s <= 0:
                continue
            key = title_key(r.title)
            if dedup_titles and key in seen_titles:
                continue
            seen_titles.add(key)
            hits.append((s * _boost(r), r))
        hits.sort(key=lambda x: -x[0])
        return [
            {**r.to_dict(), "score": round(s, 3)}
            for s, r in hits[:limit]
        ]

    def find_similar(self, target_description: str, vuln_type: str | None = None,
                     limit: int = 8) -> list[dict]:
        """Ground a target's tech stack / surface in analogous disclosed reports."""
        return self.query(build_similar_query(target_description),
                          vuln_type=vuln_type, limit=limit)

    def pattern_stats(self, keywords: str | None = None, program: str | None = None,
                      top_n: int = 15) -> dict:
        """Vulnerability-type heat map (count / engagement / reward) over the corpus."""
        subset = []
        kw_tokens = tokenize(keywords) if keywords else []
        for r in self.reports:
            if program and program.lower() not in r.program.lower():
                continue
            if kw_tokens and not any(t in r.doc_tokens for t in kw_tokens):
                continue
            subset.append(r)
        groups: dict[str, list[Report]] = defaultdict(list)
        for r in subset:
            groups[r.vuln_type].append(r)
        stats = []
        for vt, rs in groups.items():
            ups = [x.upvotes for x in rs]
            paid = [x.bounty for x in rs if x.bounty > 0]
            stats.append({
                "vuln_type": vt,
                "count": len(rs),
                "median_upvotes": statistics.median(ups) if ups else 0,
                "paid_share": round(len(paid) / len(rs), 2) if rs else 0.0,
                "avg_bounty_paid": round(sum(paid) / len(paid), 0) if paid else 0.0,
                "max_bounty": max(x.bounty for x in rs) if rs else 0.0,
                "example": sorted(rs, key=lambda x: -x.upvotes)[0].to_dict(),
            })
        stats.sort(key=lambda s: -(s["count"] * math.log1p(s["median_upvotes"])))
        return {
            "total_matching": len(subset),
            "vuln_types": stats[:top_n],
        }

    def playbook(self, hypothesis: str, endpoint_context: str | None = None,
                 limit: int = 6) -> dict:
        """Ground a hypothesis in precedent reports + mechanically extract technique hints."""
        grounding = self.query(
            hypothesis + " " + (endpoint_context or ""), limit=limit, min_upvotes=2
        )
        if not grounding:
            grounding = self.query(hypothesis, limit=limit)
        vt_hist = Counter(g["vuln_type"] for g in grounding)
        # technique keywords = frequent content nouns across matched titles
        freq = Counter()
        for g in grounding:
            freq.update(tokenize(g["title"]))
        technique = [t for t, n in freq.most_common(20) if n >= 2][:10]
        return {
            "hypothesis": hypothesis,
            "matched_reports": grounding,
            "dominant_vuln_types": [{"type": t, "n": n} for t, n in vt_hist.most_common(5)],
            "technique_keywords": technique,
        }


def default_index_path() -> Path:
    """Package-bundled index (aobh/rag/index/reports.jsonl).

    Overridden by env H1_INDEX_PATH: a non-blank value wins; empty/unset
    resolves inside the installed package.
    """
    env = os.environ.get("H1_INDEX_PATH", "").strip()
    if env:
        return Path(env)
    return Path(__file__).resolve().parent / "index" / "reports.jsonl"


def main() -> int:
    """CLI: build/inspect the index.  python -m aobh.rag.store <csv|jsonl> [query]"""
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else default_index_path()
    corpus = ReportCorpus.from_jsonl(path) if path.suffix == ".jsonl" else ReportCorpus.from_csv(path)
    print(f"indexed {len(corpus.reports)} unique reports from {path}")
    if len(sys.argv) > 2:
        for hit in corpus.query(sys.argv[2], limit=5):
            print(f"  [{hit['upvotes']}↑ ${hit['bounty']:,.0f}] ({hit['vuln_type']}) {hit['title'][:90]}  {hit['link']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
