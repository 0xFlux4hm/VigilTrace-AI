"""vectorstore.py — JSONL index load/save for the RAG corpus.

One JSON object per line (ensure_ascii=False) — the exact cache format that
ingest.py writes and ReportCorpus.from_jsonl reads. The reader reproduces the
line handling of rag_store.py verbatim (read_text + splitlines, blank lines
skipped); the writer reproduces the fallback build in the proven MCP server.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable


def load_jsonl(path: str | Path) -> list[dict]:
    """Parse a JSONL index into a list of dicts (blank lines skipped)."""
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def save_jsonl(path: str | Path, records: Iterable[dict]) -> int:
    """Write one JSON object per line. Returns the number of records written."""
    out = Path(path)
    n = 0
    with out.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    return n
