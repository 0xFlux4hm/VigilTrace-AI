"""tools.py — registration of the four `waf` group tools (original names kept,
no folding; schemas cross-checked against aobh/tools/tools.json).

    register(config: dict | None = None) -> dict[str, Callable]

maps tool name -> handler; each handler takes ONE positional dict of arguments
and returns the envelope every tool speaks:

    {"ok": True, "data": ...}  |  {"ok": False, "error", "hint"}

Envelope semantics reproduced exactly from the proven rag/server.py
(_run_module_tool): engine errors become the error envelope, bad argument
types/slots and unknown tool names get the schema pasted into the hint.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from aobh.core.bridge import BridgeClient
from aobh.waf.core import WafCore, WafError

HANDLERS = {
    "waf_fingerprint": "waf_fingerprint",
    "waf_probe":       "waf_probe",
    "waf_adapt":       "waf_adapt",
    "waf_test_bypass": "waf_test_bypass",
}

_MANIFEST = Path(__file__).resolve().parents[1] / "tools" / "tools.json"


def tool_schemas() -> list[dict]:
    """The group's tool schemas, read from the shipped manifest (group == "waf")."""
    data = json.loads(_MANIFEST.read_text())
    return [t for t in data["tools"] if t.get("group") == "waf"]


def _schema_hint(name: str) -> str:
    return ("Schema: " + json.dumps([t["inputSchema"] for t in tool_schemas()
                                     if t["name"] == name]))[:400]


def _run(core: WafCore, name: str, args: dict) -> dict:
    try:
        handler = getattr(core, HANDLERS[name])
        return handler(**args)  # handlers already return the {ok, data} envelope
    except WafError as e:
        return {"ok": False, "error": e.error, "hint": e.hint}
    except TypeError as e:
        return {"ok": False, "error": f"bad arguments for {name}: {e}",
                "hint": _schema_hint(name)}
    except KeyError as e:
        return {"ok": False, "error": f"missing required argument {e}",
                "hint": _schema_hint(name)}


def register(config: dict | None = None) -> dict[str, Callable]:
    """Register the waf group: returns {tool_name: handler(args: dict) -> dict}.

    config keys (all optional): bridge — a pre-built BridgeClient; base / token /
    allow_direct — BridgeClient constructor overrides; anything else is ignored.
    """
    config = dict(config or {})
    if isinstance(config.get("bridge"), BridgeClient):
        core = WafCore(bridge=config["bridge"])
    else:
        kw = {k: config[k] for k in ("base", "token", "allow_direct") if k in config}
        core = WafCore(bridge=BridgeClient(**kw))
    handlers: dict[str, Callable] = {}
    for name in HANDLERS:
        def handler(args: dict, _core: WafCore = core, _name: str = name) -> dict:
            return _run(_core, _name, args)
        handlers[name] = handler
    return handlers
