#!/usr/bin/env python3
"""Offline end-to-end smoke (no Burp needed) — thin wrapper around
`aobh smoke`; see aobh/tools/cli.py run_smoke()."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aobh.tools.cli import run_smoke  # noqa: E402

if __name__ == "__main__":
    sys.exit(run_smoke())
