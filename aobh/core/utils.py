"""utils.py — shared helpers: ids, timestamps, response envelopes, atomic writes.

The engines speak one envelope everywhere (MCP layer, bridge, tests):

    {"ok": true, "data": ...}
    {"ok": false, "error": "<code>", "hint": "operator-facing hint"}
"""

from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path
from typing import Any


def utcnow_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def ok(data: Any = None, **extra: Any) -> dict:
    out: dict = {"ok": True}
    if data is not None:
        out["data"] = data
    out.update(extra)
    return out


def err(error: str, hint: str = "", **extra: Any) -> dict:
    out = {"ok": False, "error": error, "hint": hint}
    out.update(extra)
    return out


def truncate(text: str, limit: int = 300) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def atomic_write_json(path: str | os.PathLike, obj: Any) -> None:
    """Write JSON atomically (tmp file in the same directory + os.replace) so a
    crash never leaves a half-written state document behind."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + f".tmp{os.getpid()}")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, p)


def append_jsonl(path: str | os.PathLike, obj: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
