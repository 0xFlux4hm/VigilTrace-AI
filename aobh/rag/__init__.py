"""aobh.rag — disclosed-report corpus over the HackerOne data set.

Local, stdlib-only RAG: ingest (CSV -> JSONL cache), tokenize/expand, BM25
retrieval with community/monetary boost, find-similar tech-stack grounding,
pattern statistics and playbook building. The bundled index ships at
aobh/rag/index/reports.jsonl (override with env H1_INDEX_PATH).

Modules:
    chunker      vocabulary tables + tokenize/expand_query
    embeddings   optional VectorScorer backend stub (OFF by default)
    vectorstore  JSONL index load/save
    retriever    BM25 scoring (InMemoryBM25)
    dedup        link/title dedupe + find-similar query construction
    store        Report, ReportCorpus, default_index_path, CLI (re-exports all)
    ingest       CSV normalization into the JSONL cache
    tools        the four rag_* tool handlers (group "rag")
"""
