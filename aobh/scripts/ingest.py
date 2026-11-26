#!/usr/bin/env python3
"""Rebuild the RAG index from the disclosed-reports CSV (wrapper around
aobh.rag.ingest). Default CSV is the bundled corpus."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aobh.tools.cli import _cmd_ingest  # noqa: E402

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Rebuild the RAG index from the disclosed-reports CSV.")
    ap.add_argument("--csv", default=str(ROOT / "aobh" / "rag" / "data" / "hackerone_reports.csv"))
    ap.add_argument("--index", default="")
    a = ap.parse_args()
    sys.exit(_cmd_ingest(a.csv, a.index))
