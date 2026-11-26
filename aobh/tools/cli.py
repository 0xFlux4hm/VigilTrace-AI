"""cli.py — the `aobh` command line.

Subcommands:
  serve        run the FastMCP stdio MCP server (loads an optional --env file first)
  list-tools   print the 48-tool surface (group<TAB>name)
  ingest       rebuild the RAG index from the bundled disclosed-reports CSV
  smoke        offline end-to-end smoke — no Burp needed (also scripts/smoke.py)
  doctor       config summary (secrets redacted) + bridge health (non-fatal)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path


def _cmd_list_tools() -> int:
    from aobh.tools.registry import manifest

    for t in manifest()["tools"]:
        print(f"{t['group']}\t{t['name']}")
    return 0


def _cmd_serve(env_file: str | None) -> int:
    if env_file:
        from aobh.core.config import load_env_file

        load_env_file(env_file)
    from aobh.tools.server import main as server_main

    return server_main([])


def _cmd_ingest(csv: str, index: str) -> int:
    from aobh.rag import ingest

    argv = [csv] + (["--index", index] if index else [])
    try:
        ingest.main(argv)
    except TypeError:
        old = sys.argv
        sys.argv = ["ingest"] + argv
        try:
            ingest.main()
        finally:
            sys.argv = old
    return 0


def _cmd_doctor() -> int:
    from aobh.core.bridge import BridgeClient, BridgeError
    from aobh.core.config import get_config

    cfg = get_config()
    print(json.dumps(cfg.redacted(), indent=2))
    try:
        health = BridgeClient().health()
        keep = ("instance", "tools", "requests_sent", "rejected_out_of_scope", "rejected_other")
        print("bridge: ok —", json.dumps({k: health[k] for k in keep if k in health}))
    except BridgeError as e:
        print(f"bridge: down — {e.error}")
        print("hint:", e.hint or "Start Burp with the AI Agent Bridge extension.")
    return 0


def run_smoke() -> int:
    """Offline end-to-end smoke: manifest parity, engine wiring, RAG retrieval,
    CAPTCHA detection, the authorization gate and clean bridge-down envelopes.
    No Burp needed; returns 0 only when every check passes."""
    checks: list[tuple[str, bool]] = []

    def check(label: str, cond: bool) -> None:
        checks.append((label, bool(cond)))
        print(("ok: " if cond else "FAIL: ") + label)

    tmp = tempfile.mkdtemp(prefix="aobh-smoke-")
    os.environ["ATAP_ENGAGEMENT_DIR"] = tmp
    os.environ["BURP_BRIDGE_URL"] = "http://127.0.0.1:8787"

    from aobh.core.authz import BridgeGuard, ScopeRegistry
    from aobh.tools import registry

    registry.reset()
    doc = registry.manifest()
    check("manifest surface == 48 tools", doc["meta"]["surface"] == 48 and len(doc["tools"]) == 48)

    handlers = registry.local_handlers()
    local_names = [t["name"] for t in doc["tools"] if t["group"] != "burp_bridge"]
    check("registry covers all 33 local tools", all(n in handlers for n in local_names))

    out = registry.dispatch("rag_query_reports", {"query": "idor", "limit": 3})
    check("rag_query_reports returns precedents", bool(out.get("ok")) and bool(out.get("data")))

    out = registry.dispatch("captcha_detect", {
        "url": "http://127.0.0.1:8080/x",
        "response": {"status": 403, "headers": [["content-type", "text/html"]],
                     "body": "<html>Attention Required! | Cloudflare</html>"}})
    check("captcha_detect classifies an inline challenge", bool(out.get("ok")))

    guard = BridgeGuard(registry.bridge_client(), ScopeRegistry(Path(tmp) / "scope.json"))
    try:
        guard.request("GET", "http://127.0.0.1:8080/")
        refused = False
    except Exception:
        refused = True
    check("authz gate refuses unauthorized sends", refused)

    os.environ["BURP_BRIDGE_URL"] = "http://127.0.0.1:1"
    registry.reset()
    out = registry.dispatch("get_scope", {})
    check("bridge tools fail with a clean envelope", out.get("ok") is False and bool(out.get("hint")))

    registry.reset()
    failed = [label for label, cond in checks if not cond]
    if failed:
        print(f"AOBH SMOKE FAILED — {len(failed)}/{len(checks)} checks failed: {failed}")
        return 1
    print(f"AOBH SMOKE PASSED — {len(checks)}/{len(checks)} checks")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="aobh",
        description="Autonomous Orchestrated Bug Hunter — AUTHORIZED SECURITY TESTING ONLY.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("serve", help="run the FastMCP stdio MCP server")
    sp.add_argument("--env", default=None, help="optional .env file to load first")
    sub.add_parser("list-tools", help="print the 48-tool surface (group<TAB>name)")
    ip = sub.add_parser("ingest", help="rebuild the RAG index from the disclosed-reports CSV")
    ip.add_argument("--csv", default=None)
    ip.add_argument("--index", default="")
    sub.add_parser("smoke", help="offline end-to-end smoke (no Burp needed)")
    sub.add_parser("doctor", help="config summary + bridge health")

    a = ap.parse_args(argv)
    if a.cmd == "serve":
        return _cmd_serve(a.env)
    if a.cmd == "list-tools":
        return _cmd_list_tools()
    if a.cmd == "ingest":
        default_csv = Path(__file__).resolve().parents[2] / "aobh" / "rag" / "data" / "hackerone_reports.csv"
        return _cmd_ingest(a.csv or str(default_csv), a.index)
    if a.cmd == "smoke":
        return run_smoke()
    return _cmd_doctor()


if __name__ == "__main__":
    sys.exit(main())
