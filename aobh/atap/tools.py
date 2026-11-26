#!/usr/bin/env python3
"""tools.py — the 8 atap_* tool handlers: registry, manifest cross-check, envelope dispatch.

Port of the atap dispatch that used to live in rag/server.py
(`_ATAP_HANDLERS` / `_atap_tool_schemas` / `_run_atap_tool`):

  * handlers are called with ONE positional dict (``handler(args: dict) -> dict``)
    and return the engine's {ok, data} envelope as-is;
  * AtapError -> {ok: false, error, hint}; AccountStoreError -> {ok: false,
    error, hint: "Check atap_list_accounts for valid ids."}; bad/missing
    arguments -> {ok: false, error, hint: <inputSchema>} — exactly like the
    old dispatcher;
  * required arguments are validated against the engine's ATAP_TOOLS schemas,
    which register() cross-checks against the shipped manifest
    (aobh/tools/tools.json, group "atap").
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable

from aobh.atap.manager import ATAP_TOOLS, AtapError, get_engine, reset_engine
from aobh.atap.store import AccountStoreError

# tool name -> engine method (identical to the old rag/server.py _ATAP_HANDLERS)
_HANDLERS: dict[str, str] = {
    "atap_policy_check":   "policy_check",
    "atap_create_account": "create_account",
    "atap_verify_account": "verify_account",
    "atap_login":          "login",
    "atap_get_session":    "get_session",
    "atap_account_health": "account_health",
    "atap_list_accounts":  "list_accounts",
    "atap_cleanup":        "cleanup",
}

# logical config keys -> ATAP_* env var (exact env-var names also pass through)
_ENV_ALIASES: dict[str, str] = {
    "engagement_dir": "ATAP_ENGAGEMENT_DIR",
    "bridge_url": "BURP_BRIDGE_URL",
    "bridge_token": "BURP_BRIDGE_TOKEN",
    "allow_direct": "ATAP_ALLOW_DIRECT",
    "vault_key": "ATAP_VAULT_KEY",
    "max_accounts": "ATAP_MAX_ACCOUNTS",
    "use_catcher": "ATAP_USE_CATCHER",
    "mailcatch_host": "ATAP_MAILCATCH_HOST",
    "mailcatch_port": "ATAP_MAILCATCH_PORT",
    "imap_host": "ATAP_IMAP_HOST",
    "imap_user": "ATAP_IMAP_USER",
    "imap_pass": "ATAP_IMAP_PASS",
    "imap_mailbox": "ATAP_IMAP_MAILBOX",
}

_MANIFEST_VERIFIED = False


def tool_schemas() -> list[dict]:
    """The 8 atap_* tool schemas (single source of truth: manager.ATAP_TOOLS,
    cross-checked against the tools.json manifest at register() time)."""
    return ATAP_TOOLS


def _manifest_path() -> Path:
    return Path(__file__).resolve().parent.parent / "tools" / "tools.json"


def _verify_manifest() -> None:
    """Cross-check required args + property names of ATAP_TOOLS against the
    shipped manifest (tools.json, group "atap"). Raises RuntimeError on drift.
    Idempotent; runs once per process (or again after reset)."""
    global _MANIFEST_VERIFIED
    if _MANIFEST_VERIFIED:
        return
    manifest = json.loads(_manifest_path().read_text(encoding="utf-8"))
    by_name = {t["name"]: t for t in manifest.get("tools", []) if t.get("group") == "atap"}
    engine_names = {t["name"] for t in ATAP_TOOLS}
    if set(by_name) != engine_names:
        raise RuntimeError(f"manifest drift: engine tools {sorted(engine_names)} != "
                           f"manifest tools {sorted(by_name)}")
    for t in ATAP_TOOLS:
        m = by_name[t["name"]]
        want_req = t["inputSchema"].get("required", [])
        got_req = m["inputSchema"].get("required", [])
        if want_req != got_req:
            raise RuntimeError(f"manifest drift for {t['name']}: required "
                               f"{want_req} != {got_req}")
        want_props = t["inputSchema"].get("properties", {})
        got_props = m["inputSchema"].get("properties", {})
        if set(want_props) != set(got_props):
            raise RuntimeError(f"manifest drift for {t['name']}: properties "
                               f"{sorted(want_props)} != {sorted(got_props)}")
        for prop, eschema in want_props.items():
            mschema = got_props[prop]
            for key in ("default", "enum"):
                if eschema.get(key) != mschema.get(key):
                    raise RuntimeError(f"manifest drift for {t['name']}.{prop}: "
                                       f"{key} {eschema.get(key)!r} != {mschema.get(key)!r}")
    _MANIFEST_VERIFIED = True


def _check_required(name: str, args: dict) -> None:
    """Raise KeyError for a missing required arg (the old dispatcher's
    `missing required argument` envelope path)."""
    schema = next(t["inputSchema"] for t in ATAP_TOOLS if t["name"] == name)
    for req in schema.get("required", []):
        if req not in args:
            raise KeyError(f"'{req}'")


def run_tool(name: str, args: dict) -> dict:
    """Dispatch one atap_* tool — the rag/server.py _run_atap_tool semantics,
    with required args cross-checked against the schema first."""
    try:
        _check_required(name, args or {})
        handler = getattr(get_engine(), _HANDLERS[name])
        return handler(**(args or {}))  # engine methods already return {ok, data}
    except AtapError as e:
        return {"ok": False, "error": e.error, "hint": e.hint}
    except AccountStoreError as e:
        return {"ok": False, "error": str(e), "hint": "Check atap_list_accounts for valid ids."}
    except TypeError as e:
        return {"ok": False, "error": f"bad arguments for {name}: {e}",
                "hint": f"Schema: {json.dumps([t['inputSchema'] for t in ATAP_TOOLS if t['name']==name])}"[:400]}
    except KeyError as e:
        return {"ok": False, "error": f"missing required argument {e}",
                "hint": f"Schema: {json.dumps([t['inputSchema'] for t in ATAP_TOOLS if t['name']==name])}"[:400]}


def _make_handler(name: str) -> Callable[[dict], dict]:
    def handler(args: dict) -> dict:
        return run_tool(name, args)
    handler.__name__ = name
    handler.__doc__ = next(t["description"] for t in ATAP_TOOLS if t["name"] == name)
    return handler


def _apply_config(config: dict) -> None:
    """Apply a config dict to the environment (explicit config wins over env).
    Accepts exact ATAP_* / BURP_* env-var names or the logical aliases above.
    Booleans normalize to '1'/'0' (ATAP_USE_CATCHER, ATAP_ALLOW_DIRECT, ...)."""
    for key, value in config.items():
        env = _ENV_ALIASES.get(key, key)
        if isinstance(value, bool):
            value = "1" if value else "0"
        os.environ[env] = str(value)


def register(config: dict | None = None) -> dict[str, Callable]:
    """Register the 8 atap_* tools; returns {tool_name: handler(args)->dict}.

    config (optional): applied to the environment BEFORE the engine singleton is
    (re)created — e.g. {'engagement_dir': ..., 'bridge_url': ..., 'use_catcher': True}.
    Existing environment variables are overridden by explicit config values.
    Raises RuntimeError if the engine schemas drift from tools.json.
    """
    if config:
        _apply_config(config)
        reset_engine()  # next get_engine() re-reads env
    _verify_manifest()
    return {name: _make_handler(name) for name in _HANDLERS}
