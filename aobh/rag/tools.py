"""tools.py — the "rag" tool group of the aobh tool registry.

Exposes exactly the four disclosed-report tools declared in the shipped
manifest aobh/tools/tools.json (group rag, 4 entries):

    rag_query_reports, rag_find_similar, rag_pattern_stats, rag_playbook

`register(config)` mirrors the proven MCP server
(autonomous-bug-hunter/rag/server.py::_run_rag_tool) exactly:

  * success            -> {"ok": True, "data": ...}
  * TypeError          -> {"ok": False, "error": "bad arguments for <name>: ...",
                          "hint": "Schema: [...]"} (sliced to 400 chars)
  * KeyError           -> {"ok": False, "error": "missing required argument ...",
                          "hint": "Schema: [...]"} (sliced to 400 chars)

`config` may be a plain dict or aobh.core.config.Config (None -> get_config()).
rag_index_path / rag_csv_path are honored; blank/None falls back to the
package-bundled data/ and index/ directories (env H1_INDEX_PATH / H1_CSV_PATH
still win via get_config / default_index_path).
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Callable

from aobh.rag import vectorstore
from aobh.rag.store import ReportCorpus, default_index_path

RAG_TOOL_NAMES = ("rag_query_reports", "rag_find_similar", "rag_pattern_stats", "rag_playbook")

_PACKAGE_DIR = Path(__file__).resolve().parent
_DEFAULT_CSV = _PACKAGE_DIR / "data" / "hackerone_reports.csv"
_MANIFEST = _PACKAGE_DIR.parent / "tools" / "tools.json"

_CORPUS_CACHE: dict[str, ReportCorpus] = {}


@lru_cache(maxsize=1)
def rag_tool_schemas() -> dict[str, dict]:
    """The 4 rag tool definitions from the shipped manifest (single source of truth)."""
    data = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    return {t["name"]: t for t in data["tools"] if t["name"] in RAG_TOOL_NAMES}


def _resolve_path(config: dict | None, key: str, env_var: str, default: Path) -> Path:
    """config value `key` (dict entry or Config attribute) -> Path; blank/None
    falls back to `env_var`, then to the package default."""
    if config is None:
        try:
            from aobh.core.config import get_config
            config = get_config()
        except Exception:
            config = {}
    if isinstance(config, dict):
        raw = str(config.get(key) or "")
    else:
        raw = str(getattr(config, key, None) or "")
    raw = raw.strip() or os.environ.get(env_var, "").strip()
    return Path(raw) if raw else default


def load_corpus(index_path: Path, csv_path: Path) -> ReportCorpus:
    """Load the JSONL index (cached per path); if missing, build it from the
    CSV once — the exact startup behavior of the proven server."""
    key = str(index_path)
    cached = _CORPUS_CACHE.get(key)
    if cached is not None:
        return cached
    if index_path.exists():
        corpus = ReportCorpus.from_jsonl(index_path)
    elif csv_path.exists():
        corpus = ReportCorpus.from_csv(csv_path)
        index_path.parent.mkdir(parents=True, exist_ok=True)
        vectorstore.save_jsonl(index_path, [r.to_dict() for r in corpus.reports])
    else:
        raise FileNotFoundError(
            f"No RAG index at {index_path} and no CSV at {csv_path} — run python -m aobh.rag.ingest"
        )
    _CORPUS_CACHE[key] = corpus
    return corpus


# --------------------------------------------------------------------------
# data producers — argument handling identical to server.py::_run_rag_tool
# --------------------------------------------------------------------------

def _run_query_reports(corpus: ReportCorpus, args: dict) -> dict:
    return {"results": corpus.query(
        args["query"], vuln_type=args.get("vuln_type"), program=args.get("program"),
        min_upvotes=int(args.get("min_upvotes") or 0),
        min_bounty=args.get("min_bounty"), limit=int(args.get("limit") or 8))}


def _run_find_similar(corpus: ReportCorpus, args: dict) -> dict:
    return {"results": corpus.find_similar(
        args["target_description"], vuln_type=args.get("vuln_type"),
        limit=int(args.get("limit") or 8))}


def _run_pattern_stats(corpus: ReportCorpus, args: dict) -> dict:
    return corpus.pattern_stats(
        keywords=args.get("keywords"), program=args.get("program"),
        top_n=int(args.get("top_n") or 15))


def _run_playbook(corpus: ReportCorpus, args: dict) -> dict:
    return corpus.playbook(
        args["hypothesis"], endpoint_context=args.get("endpoint_context"),
        limit=int(args.get("limit") or 6))


_RUNNERS: dict[str, Callable[[ReportCorpus, dict], object]] = {
    "rag_query_reports": _run_query_reports,
    "rag_find_similar": _run_find_similar,
    "rag_pattern_stats": _run_pattern_stats,
    "rag_playbook": _run_playbook,
}


def _wrap_handler(name: str, schema: dict,
                  run: Callable[[dict], object]) -> Callable[[dict], dict]:
    """Envelope wrapper, byte-for-byte the error contract of the proven server:
    TypeError -> "bad arguments", KeyError -> "missing required argument"."""

    def handler(args: dict) -> dict:
        try:
            return {"ok": True, "data": run(args)}
        except TypeError as e:
            return {"ok": False, "error": f"bad arguments for {name}: {e}",
                    "hint": f"Schema: {json.dumps([schema])}"[:400]}
        except KeyError as e:
            return {"ok": False, "error": f"missing required argument {e}",
                    "hint": f"Schema: {json.dumps([schema])}"[:400]}

    handler.__name__ = name
    handler.__doc__ = (f"{schema.get('description', name)}\n\n"
                       "Args: one positional dict (manifest inputSchema). "
                       "Returns the {ok, data}/{ok, error, hint} envelope.")
    return handler


def register(config: dict | None = None) -> dict[str, Callable]:
    """Register the rag tool group.

    config: a plain dict (e.g. {"rag_index_path": "/tmp/reports.jsonl"}) or a
    aobh.core.config.Config instance; None resolves via aobh.core.config.get_config().
    Blank/None rag_index_path -> package default (see store.default_index_path).

    Returns EXACTLY the four rag tool names, each mapped to a handler that
    takes ONE positional dict of arguments and returns the {ok, ...} envelope.
    """
    index_path = _resolve_path(config, "rag_index_path", "H1_INDEX_PATH", default_index_path())
    csv_path = _resolve_path(config, "rag_csv_path", "H1_CSV_PATH", _DEFAULT_CSV)
    corpus = load_corpus(index_path, csv_path)
    schemas = rag_tool_schemas()
    handlers: dict[str, Callable] = {}
    for name, runner in _RUNNERS.items():
        handlers[name] = _wrap_handler(name, schemas[name], lambda a, _r=runner, _c=corpus: _r(_c, a))
    return handlers
