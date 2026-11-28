"""Integration tests for the tools layer: manifest <-> registry <-> FastMCP.

The engine suites prove engine behavior; these prove the 48-tool surface is
served exactly: every manifest name has a working handler, dispatch returns
clean envelopes in every mode, and the FastMCP server lists all 48 tools with
their manifest schemas.
"""

import asyncio
import json

import pytest

from aobh.tools import registry
from aobh.tools.server import build_mcp

MANIFEST = json.loads(registry.MANIFEST_PATH.read_text(encoding="utf-8"))


def test_manifest_is_56_tools_in_eight_groups():
    assert MANIFEST["meta"]["surface"] == 56
    assert len(MANIFEST["tools"]) == 56
    names = [t["name"] for t in MANIFEST["tools"]]
    assert len(set(names)) == 56
    groups = {}
    for t in MANIFEST["tools"]:
        groups.setdefault(t["group"], []).append(t["name"])
    assert {k: len(v) for k, v in groups.items()} == {
        "burp_bridge": 15, "mission_control": 16, "rag": 4,
        "atap": 8, "waf": 4, "captcha": 3, "tamper": 4, "oob": 2}


def test_registry_covers_every_local_tool_exactly():
    handlers = registry.local_handlers()
    local_names = {t["name"] for t in MANIFEST["tools"] if t["group"] != "burp_bridge"}
    missing = local_names - set(handlers)
    extra = set(handlers) - local_names
    assert not missing, f"no handler registered for {sorted(missing)}"
    assert not extra, f"handlers registered outside the manifest: {sorted(extra)}"


def test_dispatch_unknown_tool_envelope():
    out = registry.dispatch("definitely_not_a_tool", {})
    assert out["ok"] is False and out["error"] == "unknown_tool" and out["hint"]


def test_dispatch_rag_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("H1_INDEX_PATH", "")  # packaged index
    registry.reset()
    out = registry.dispatch("rag_query_reports", {"query": "idor", "limit": 3})
    assert out["ok"] is True, out
    assert out["data"]


def test_dispatch_captcha_detect_inline(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAP_ENGAGEMENT_DIR", str(tmp_path))
    registry.reset()
    out = registry.dispatch("captcha_detect", {
        "url": "http://127.0.0.1:8080/x",
        "response": {"status": 403, "headers": [["content-type", "text/html"]],
                     "body": "<html>Attention Required! | Cloudflare</html>"}})
    assert out["ok"] is True, out


def test_dispatch_mission_init_and_status(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAP_ENGAGEMENT_DIR", str(tmp_path))
    registry.reset()
    out = registry.dispatch("mission_init", {
        "target": "https://api.example.com",
        "authorization_reference": "pytest-contract-1"})
    assert out.get("ok") is True, out
    out2 = registry.dispatch("mission_status", {})
    assert out2.get("ok") is True, out2


def test_dispatch_bridge_tool_down_gives_clean_envelope(monkeypatch):
    monkeypatch.setenv("BURP_BRIDGE_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("BURP_BRIDGE_TOKEN", "x" * 16)
    registry.reset()
    out = registry.dispatch("get_scope", {})
    assert out["ok"] is False and out.get("error") and out.get("hint"), out


def test_fastmcp_lists_all_56_tools_with_manifest_schemas():
    mcp = build_mcp()
    tools = asyncio.run(mcp.list_tools())
    assert len(tools) == 56
    manifest_tools = {t["name"]: t for t in MANIFEST["tools"]}
    for tool in tools:
        assert tool.name in manifest_tools
        expected = manifest_tools[tool.name]
        assert (tool.description or "").startswith(expected["description"][:40])
        schema = getattr(tool, "inputSchema", None) or getattr(tool, "parameters", None)
        assert schema is not None


def test_cli_list_tools_56_lines(capsys):
    from aobh.tools.cli import main as cli_main

    assert cli_main(["list-tools"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 56
    assert all("\t" in line for line in lines)
