"""retriever.py — BM25 scoring over pre-tokenized documents.

Split out of rag_store.py unchanged: classic BM25 (k1=1.5, b=0.75) built in
memory at startup (~15k short docs -> <100ms, a few MB). For much larger
corpora swap this class for SQLite FTS5; the ReportCorpus API stays identical.
"""
from __future__ import annotations

import math
from collections import Counter


class InMemoryBM25:
    """Classic BM25 (k1=1.5, b=0.75) over pre-tokenized docs."""

    K1, B = 1.5, 0.75

    def __init__(self, docs: list[list[str]]):
        self.docs = docs
        self.N = len(docs)
        self.avgdl = sum(len(d) for d in docs) / max(self.N, 1) or 1.0
        self.tf: list[Counter] = [Counter(d) for d in docs]
        self.df: Counter = Counter()
        for c in self.tf:
            self.df.update(c.keys())

    def idf(self, term: str) -> float:
        n = self.df.get(term, 0)
        return math.log((self.N - n + 0.5) / (n + 0.5) + 1.0)

    def score(self, query_tokens: list[str], i: int) -> float:
        c = self.tf[i]
        dl = len(self.docs[i]) or 1
        s = 0.0
        for t in query_tokens:
            f = c.get(t, 0)
            if not f:
                continue
            s += self.idf(t) * f * (self.K1 + 1) / (f + self.K1 * (1 - self.B + self.B * dl / self.avgdl))
        return s
