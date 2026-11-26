"""dedup.py — duplicate suppression and find-similar logic.

Split out of rag_store.py along the existing logic boundaries:

  * unique_by_link       — corpus normalization dedupe (ReportCorpus.__init__)
  * title_key            — normalized-title key used to suppress duplicate
                           hits in ReportCorpus.query (dedup_titles=True)
  * tech_terms           — TECH_VOCAB extraction from find_similar
  * build_similar_query  — the find_similar query construction (tech terms
                           weigh double: they define the analogy)

All functions are pure and duck-typed on Report, so importing this module
never imports store.py (no import cycle).
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Iterable, Iterator

from aobh.rag.chunker import TECH_VOCAB, tokenize

if TYPE_CHECKING:  # pragma: no cover
    from aobh.rag.store import Report


def unique_by_link(reports: Iterable["Report"]) -> Iterator["Report"]:
    """Yield the first occurrence per report link (keeps input order)."""
    seen: set[str] = set()
    for r in reports:
        if r.link in seen:
            continue
        seen.add(r.link)
        yield r


def title_key(title: str) -> str:
    """Normalized title key: lowercase, alphanumeric-only, first 80 chars."""
    return re.sub(r"[^a-z0-9]", "", title.lower())[:80]


def tech_terms(tokens: list[str]) -> list[str]:
    """Tech-stack tokens (TECH_VOCAB, dot-tolerant) found in `tokens`."""
    return [t for t in tokens if t in TECH_VOCAB or t.replace(".", "") in TECH_VOCAB]


def build_similar_query(target_description: str) -> str:
    """find_similar query construction: description tokens plus tech terms
    repeated (tech terms weigh double so matches are grounded in the same
    kind of technology rather than the same words)."""
    toks = tokenize(target_description)
    tech = tech_terms(toks)
    return " ".join(toks + tech)
