"""tools — the 48-tool surface: manifest, handler registry, FastMCP server, CLI.

  tools.json   the manifest (single source of truth: names, groups, schemas)
  registry.py  dispatch(name, arguments) -> envelope; the one choke point
  server.py    FastMCP stdio server (python3 -m aobh.tools.server)
  cli.py       aobh serve|list-tools|ingest|smoke|doctor
"""

from aobh.tools.registry import dispatch, local_handlers, manifest

__all__ = ["dispatch", "local_handlers", "manifest"]
