#!/usr/bin/env python3
"""tools.py — the MCP registry surface for the orchestrator engine (14 tools).

register(engagement_dir) wires a MissionCore over the engagement dir and
returns the handler map the MCP server registers for manifest group
"mission_control" (aobh/tools/tools.json — the single source of truth for
schemas; this module is the single source for dispatch).

    signature : handler(args: dict) -> dict   (ONE positional dict)
    envelopes : handlers return {ok, data}; failures return
                {ok: false, error, hint}

Reproduces the proven rag/server.py dispatch exactly (MissionError → its
error/hint; MissionStoreError → unreadable-state hint; TypeError → "bad
arguments"; KeyError → "missing required argument"), with schema hints read
lazily from the manifest and a generic fallback when it cannot be loaded —
callers must never depend on the manifest being readable.

The old 17-tool surface folded to 14:
    task_list        → mission_status summarizes the queue (method stays public)
    check_duplicates → validate_finding(dedup_only=true) (local verdict, no write)
    notify_operator  → mission_control action="notify" (method stays public)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from aobh.orchestrator.engine import MissionCore, MissionError
from aobh.orchestrator.store import MissionStoreError

_MANIFEST_PATH = Path(__file__).resolve().parent.parent / "tools" / "tools.json"
_manifest_cache: dict | None = None

_HANDLERS = {
    "mission_init":      "mission_init",
    "mission_status":    "mission_status",
    "mission_control":   "mission_control",
    "task_enqueue":      "task_enqueue",
    "task_next":         "task_next",
    "task_update":       "task_update",
    "coverage_update":   "coverage_update",
    "coverage_gaps":     "coverage_gaps",
    "event_emit":        "event_emit",
    "memory_save":       "memory_save",
    "memory_search":     "memory_search",
    "budget_status":     "budget_status",
    "request_approval":  "request_approval",
    "validate_finding":  "validate_finding",
}


def _schema_hint(name: str) -> str:
    """Schema hint for an argument error, read lazily from the manifest."""
    global _manifest_cache
    try:
        if _manifest_cache is None:
            _manifest_cache = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
        schema = [t["inputSchema"] for t in _manifest_cache.get("tools", []) if t.get("name") == name]
        return ("Schema: " + json.dumps(schema))[:400]
    except Exception:
        return f"Schema: see aobh/tools/tools.json, group mission_control, tool {name}"


def _run_tool(core: MissionCore, name: str, args: dict) -> dict:
    try:
        handler = getattr(core, _HANDLERS[name])
        return handler(**args)  # handlers already return the {ok, data} envelope
    except MissionError as e:
        return {"ok": False, "error": e.error, "hint": e.hint}
    except MissionStoreError as e:
        return {"ok": False, "error": str(e),
                "hint": "Mission state unreadable — check the engagement dir / call mission_init."}
    except TypeError as e:
        return {"ok": False, "error": f"bad arguments for {name}: {e}",
                "hint": _schema_hint(name)}
    except KeyError as e:
        return {"ok": False, "error": f"missing required argument {e}",
                "hint": _schema_hint(name)}


def register(engagement_dir: str) -> dict[str, Callable]:
    """Build the 14-tool handler map over `engagement_dir`.

    Each handler takes ONE positional dict of arguments and returns the
    response envelope — the MCP registry calls it exactly that way.
    """
    core = MissionCore(engagement_dir or None)
    tools: dict[str, Callable] = {}

    def _make(name: str) -> Callable:
        def handler(args: dict) -> dict:
            return _run_tool(core, name, args if isinstance(args, dict) else {})
        handler.__name__ = name
        handler.__doc__ = f"mission_control tool {name} (args: dict -> envelope dict)"
        return handler

    for name in _HANDLERS:
        tools[name] = _make(name)
    return tools
