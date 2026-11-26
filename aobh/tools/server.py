"""server.py — FastMCP stdio server exposing the 48-tool surface of tools.json.

Every tool is registered programmatically from the manifest (names, groups,
descriptions and JSON Schemas come from tools.json — no per-tool Python glue),
and every call funnels through aobh.tools.registry.dispatch, which returns the
standard envelope as a JSON string:

    {"ok": true, "data": ...} | {"ok": false, "error": "<code>", "hint": "..."}

Run:
    python3 -m aobh.tools.server                # stdio; register as "aobh"
    python3 -m aobh.tools.server --list-tools   # print the surface and exit

If the FastMCP Tool API of the installed SDK differs, the server falls back to
the equivalent low-level Server wiring (same manifest, same dispatch).
"""
from __future__ import annotations

import json
import sys

from aobh.tools.registry import dispatch, manifest


def _override_schema(mcp, name: str, schema: dict) -> bool:
    """add_tool derives the schema from type hints (loose object); the manifest
    schema is authoritative — overwrite the stored Tool's parameters. The
    manager's storage attribute name varies across SDK versions, so find it
    defensively."""
    manager = getattr(mcp, "_tool_manager", None)
    if manager is None:
        return False
    for attr in vars(manager).values():
        if isinstance(attr, dict):
            tool = attr.get(name)
            if tool is not None and hasattr(tool, "parameters"):
                tool.parameters = schema
                return True
    return False


def _register_one(mcp, name: str, description: str, schema: dict) -> None:
    """Register one manifest tool: a kwargs-only closure dispatching through the
    registry (schemas get overridden with the manifest's right after), since
    the SDK derives schemas from signatures and forbids underscore params."""
    def _fn(**kwargs):
        return json.dumps(dispatch(name, kwargs), ensure_ascii=False)

    _fn.__name__ = name
    _fn.__doc__ = description
    mcp.add_tool(_fn, name=name, description=description)
    _override_schema(mcp, name, schema)


def build_mcp():
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("aobh-agent")
    for t in manifest()["tools"]:
        _register_one(mcp, t["name"], t["description"], t["inputSchema"])
    return mcp


def _build_lowlevel_serve():
    import mcp.server.stdio
    import mcp.types as types
    from mcp.server.lowlevel import Server

    app = Server("aobh-agent")

    @app.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [types.Tool(name=t["name"], description=t["description"],
                           inputSchema=t["inputSchema"]) for t in manifest()["tools"]]

    @app.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
        result = dispatch(name, arguments)
        return [types.TextContent(type="text", text=json.dumps(result)[:100_000])]

    async def _serve():
        async with mcp.server.stdio.stdio_server() as (read, write):
            await app.run(read, write, app.create_initialization_options())

    return _serve


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--list-tools" in argv:
        for t in manifest()["tools"]:
            print(f"{t['group']}\t{t['name']}")
        return 0

    import asyncio

    try:
        mcp = build_mcp()
        tools = asyncio.run(mcp.list_tools())
        if len(tools) != 48:
            raise RuntimeError(f"FastMCP registered {len(tools)} tools, expected 48")
        mcp.run()  # stdio
        return 0
    except Exception:
        # SDK version drift: the low-level wiring is the verified fallback.
        import anyio

        anyio.run(_build_lowlevel_serve())
        return 0


if __name__ == "__main__":
    sys.exit(main())
