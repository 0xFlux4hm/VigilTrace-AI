"""test_rag.py — smoke tests for the aobh.rag pipeline, ported 1:1 from the
proven scripts/smoke_rag.py against the real HackerOne corpus.

1. runs aobh.rag.ingest (CSV -> JSONL cache)
2. exercises all four retrieval surfaces with realistic agent queries
3. verifies the tool layer (aobh.rag.tools.register) exposes exactly the four
   manifest rag_* tools and dispatches them with the {ok, data} envelope
4. verifies default_index_path resolves inside the package and honors the
   H1_INDEX_PATH env override

Every assert carries a failure message (per-assert messages requirement).
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import aobh.rag  # noqa: E402
from aobh.rag import tools  # noqa: E402
from aobh.rag.store import ReportCorpus, default_index_path  # noqa: E402

RAG_DIR = REPO / "aobh" / "rag"
CSV_PATH = RAG_DIR / "data" / "hackerone_reports.csv"
JSONL_PATH = RAG_DIR / "index" / "reports.jsonl"


# --- 1. ingest --------------------------------------------------------------
def test_ingest_builds_jsonl_cache():
    assert CSV_PATH.exists(), f"missing corpus CSV at {CSV_PATH}"
    r = subprocess.run(
        [sys.executable, "-m", "aobh.rag.ingest", str(CSV_PATH), str(JSONL_PATH)],
        capture_output=True, text=True, cwd=REPO,
    )
    print(r.stdout.strip())
    assert r.returncode == 0, f"ingest failed (rc={r.returncode}): {r.stderr[-500:]}"
    assert JSONL_PATH.exists(), f"ingest did not produce the JSONL cache at {JSONL_PATH}"
    print(f"cache size: {JSONL_PATH.stat().st_size / 1e6:.1f} MB")


# --- 2. retrieval -----------------------------------------------------------
@pytest.fixture(scope="module")
def corpus() -> ReportCorpus:
    c = ReportCorpus.from_jsonl(JSONL_PATH)
    print(f"\ncorpus loaded: {len(c.reports)} reports")
    return c


def _show(label: str, rows: list[dict], n: int = 3) -> None:
    print(f"\n== {label} -> {len(rows)} hits")
    for h in rows[:n]:
        print(f"   [{h['upvotes']}up ${h['bounty']:,.0f}] ({h['vuln_type']}) {h['title'][:95]}")
        print(f"      {h['program']} | {h['link']}")


def test_query_reports_idor(corpus):
    q1 = corpus.query("idor order id parameter access control", min_upvotes=5)
    _show("query 'idor order id parameter'", q1)
    assert q1, "idor query returned no hits"
    assert any("Access Control" in h["vuln_type"] or "IDOR" in h["vuln_type"] for h in q1), \
        f"no Access Control/IDOR hit in top results: {[h['vuln_type'] for h in q1]}"


def test_query_reports_ssrf_min_bounty(corpus):
    q2 = corpus.query("ssrf webhook url parameter", min_bounty=500)
    _show("query 'ssrf webhook' min_bounty=500", q2)
    assert q2, "ssrf query with min_bounty=500 returned no hits"
    assert all(h["bounty"] >= 500 for h in q2), \
        f"min_bounty filter leaked: {[h['bounty'] for h in q2]}"


def test_find_similar_tech_stack(corpus):
    q3 = corpus.find_similar(
        "Laravel API with GraphQL endpoint, S3 file uploads, OAuth login, React admin panel")
    _show("find_similar laravel/graphql/s3/oauth", q3)
    assert q3, "find_similar returned no hits for a tech-stack description"


def test_pattern_stats_graphql(corpus):
    q4 = corpus.pattern_stats(keywords="graphql")
    print(f"\n== pattern_stats keywords='graphql' -> {q4['total_matching']} matching reports, top types:")
    for s in q4["vuln_types"][:5]:
        print(f"   {s['count']:4} | medUp {s['median_upvotes']} | paid {s['paid_share']:.0%} "
              f"| avg$ {s['avg_bounty_paid']:,.0f} | {s['vuln_type']}")
    assert q4["total_matching"] > 20, \
        f"pattern_stats('graphql') matched only {q4['total_matching']} reports"


def test_playbook_idor_orders(corpus):
    q5 = corpus.playbook("IDOR on /v2/orders via orderId path parameter",
                         endpoint_context="REST JSON API")
    _show("playbook IDOR /v2/orders", q5["matched_reports"], 2)
    print("   dominant types:", [d["type"] for d in q5["dominant_vuln_types"][:3]])
    print("   technique keywords:", q5["technique_keywords"])
    assert q5["matched_reports"], "playbook matched no precedent reports"
    assert q5["technique_keywords"], "playbook extracted no technique keywords"


# --- 3. tool layer (register + envelope dispatch) ---------------------------
def test_register_exposes_exactly_four_rag_tools():
    handlers = tools.register()
    names = set(handlers)
    expected = {"rag_query_reports", "rag_find_similar", "rag_pattern_stats", "rag_playbook"}
    print("\n== aobh.rag tools registered:", sorted(names))
    assert names == expected, f"registered tools mismatch: {sorted(names)} vs {sorted(expected)}"


def test_tool_handlers_dispatch_all_payloads():
    handlers = tools.register()
    payloads = {
        "rag_query_reports": {"query": "jwt authentication bypass"},
        "rag_find_similar": {"target_description": "wordpress plugin with file upload"},
        "rag_pattern_stats": {"keywords": "upload"},
        "rag_playbook": {"hypothesis": "SSRF via webhook url parameter"},
    }
    for name, args in payloads.items():
        res = handlers[name](args)
        assert res["ok"], f"{name} dispatch failed: {res}"
        assert "data" in res, f"{name} envelope missing data: {res}"
        blob = json.dumps(res["data"])[:120]
        print(f"   {name}: ok ({len(json.dumps(res['data']))} bytes) {blob[:100]}...")


# --- 4. default index path --------------------------------------------------
def test_default_index_path_resolves_inside_package(monkeypatch):
    monkeypatch.delenv("H1_INDEX_PATH", raising=False)
    p = default_index_path()
    pkg_dir = Path(aobh.rag.__file__).resolve().parent
    assert p == pkg_dir / "index" / "reports.jsonl", \
        f"default index path is not the bundled one: {p}"
    assert p.is_relative_to(pkg_dir), f"default index path escapes the package: {p}"
    assert p.exists(), f"bundled index missing on disk: {p}"


def test_default_index_path_env_override(tmp_path, monkeypatch):
    custom = tmp_path / "custom" / "reports.jsonl"
    monkeypatch.setenv("H1_INDEX_PATH", str(custom))
    assert default_index_path() == custom, \
        f"H1_INDEX_PATH override ignored: {default_index_path()} != {custom}"
    monkeypatch.delenv("H1_INDEX_PATH", raising=False)
    assert not default_index_path().is_relative_to(tmp_path), \
        "index path still overridden after H1_INDEX_PATH was removed"
