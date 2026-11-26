"""registry.py — name→handler map for the 48-tool surface.

``dispatch(name, arguments)`` is the single choke point the MCP server, the
CLI and the tests all go through:

  * ``burp_bridge`` group → proxied to the Java extension via
    aobh.core.bridge.BridgeClient.call() (env-wired; a clean error envelope
    when the bridge is down so local work can continue first),
  * everything else → a local engine handler from the package registers.

Local handlers are built lazily and re-buildable (``reset()``) so tests can
point the engines at a fresh engagement dir via the environment. Handlers have
signature ``handler(args: dict) -> dict`` — one positional dict, the contract
every engine package registered against.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from aobh.core.bridge import BridgeClient, BridgeError
from aobh.core.config import get_config

MANIFEST_PATH = Path(__file__).resolve().parent / "tools.json"

_manifest: dict | None = None
_local: dict[str, Callable[[dict], dict]] | None = None
_bridge_client: BridgeClient | None = None


def manifest() -> dict:
    """Load and validate the 48-tool manifest (cached)."""
    global _manifest
    if _manifest is None:
        doc = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        names = [t["name"] for t in doc["tools"]]
        if doc["meta"].get("surface") != 48 or len(set(names)) != 48:
            raise SystemExit(f"manifest at {MANIFEST_PATH} does not carry the 48-tool surface")
        _manifest = doc
    return _manifest


def tool_group(name: str) -> str | None:
    for t in manifest()["tools"]:
        if t["name"] == name:
            return t["group"]
    return None


def bridge_client() -> BridgeClient:
    global _bridge_client
    if _bridge_client is None:
        _bridge_client = BridgeClient()
    return _bridge_client


def local_handlers() -> dict[str, Callable[[dict], dict]]:
    """All local (non-bridge) handlers, keyed by tool name. Built lazily from
    the engine packages' register() factories against the current environment."""
    global _local
    if _local is None:
        from aobh.orchestrator import tools as orchestrator_tools
        from aobh.rag import tools as rag_tools
        from aobh.atap import tools as atap_tools
        from aobh.waf import tools as waf_tools
        from aobh.recaptcha import tools as captcha_tools

        cfg = get_config()
        handlers: dict[str, Callable[[dict], dict]] = {}
        handlers.update(orchestrator_tools.register(str(cfg.engagement_dir)))
        handlers.update(rag_tools.register(None))
        handlers.update(atap_tools.register(None))
        handlers.update(waf_tools.register(None))
        handlers.update(captcha_tools.register(None))
        _local = handlers
    return _local


def reset() -> None:
    """Drop the cached registries (tests call this after changing the env)."""
    global _local, _bridge_client
    _local = None
    _bridge_client = None


def dispatch(name: str, arguments: dict | None) -> dict:
    """One tool call → response envelope. Never raises."""
    tool = None
    for t in manifest()["tools"]:
        if t["name"] == name:
            tool = t
            break
    if tool is None:
        return {"ok": False, "error": "unknown_tool",
                "hint": f"No tool named {name!r}; the 48-tool surface lives in aobh/tools/tools.json."}
    if tool["group"] == "burp_bridge":
        try:
            return bridge_client().call(name, dict(arguments or {}))
        except BridgeError as e:
            return {"ok": False, "error": e.error,
                    "hint": e.hint or "Is Burp running with the AI Agent Bridge extension? "
                                      "Set BURP_BRIDGE_URL and BURP_BRIDGE_TOKEN."}
        except Exception as e:  # never crash the server on one call
            return {"ok": False, "error": "bridge_error", "hint": f"{type(e).__name__}: {e}"[:300]}
    try:
        handler = local_handlers().get(name)
        if handler is None:
            return {"ok": False, "error": "unknown_tool",
                    "hint": f"Tool {name!r} is in the manifest but no local handler is registered."}
        return handler(dict(arguments or {}))
    except Exception as e:  # never crash the server on one call
        return {"ok": False, "error": f"tool_error in {name}",
                "hint": f"{type(e).__name__}: {e}"[:300]}
