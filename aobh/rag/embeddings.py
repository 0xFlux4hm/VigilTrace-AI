"""embeddings.py — optional embedding backend (OFF by default).

Implement `score` returning a similarity in [0,1] per doc and swap it into
ReportCorpus via `attach_scorer`; the tool layer is unchanged. Works with
sentence-transformers locally or any OpenAI-compatible /v1/embeddings endpoint.
Split out of rag_store.py unchanged.
"""
from __future__ import annotations


class VectorScorer:
    def __init__(self, model: str = "all-MiniLM-L6-v2", endpoint: str | None = None):
        raise NotImplementedError(
            "Bring your own embeddings: subclass and implement embed(texts). "
            "Set RAG_VECTOR_BACKEND=custom and call corpus.attach_scorer(...) at startup."
        )
