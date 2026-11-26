#!/usr/bin/env python3
"""bypass.py — the budgeted bypass tester and the shared per-host engagement
budget (waf_state.json), ported verbatim from the proven waf/waf_core.py.

Boundary (must hold): waf_test_bypass is a NORMAL traffic-volume activity
(Tier 1): <= 8 transforms per call, <= WAF_BYPASS_MAX (24) attempts per host
per engagement, every attempt annotated. An origin-reachable bypass is a
FINDING CANDIDATE and needs V-1 precedent calibration (impact = the underlying
vuln's reachability). This module NEVER rotates IPs, never mutates TLS
fingerprints, never defeats rate limits. The same budget helper is consumed by
waf_probe (core.py) for the WAF_PROBE_MAX cap.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.parse import urlparse

from aobh.core.bridge import BridgeClient
from aobh.waf.errors import WafError
from aobh.waf.fingerprint import classify_response
from aobh.waf.transforms import apply_transform

BYPASS_CAP_DEFAULT = 24


def _env(name, default=None):
    return os.environ.get(name, default)


def _budget_bump(host: str, n: int, cap: int, kind: str) -> dict:
    """Per-host, per-engagement counters in waf_state.json. Raises past cap."""
    path = Path(_env("ATAP_ENGAGEMENT_DIR") or Path.cwd() / "engagement") / "waf_state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    state = {"hosts": {}}
    if path.exists():
        try:
            state = json.loads(path.read_text())
        except Exception:
            pass
    used = state["hosts"].get(host, {}).get(kind, 0)
    if used + n > cap:
        raise WafError(
            f"{kind} budget exhausted for {host} ({used}/{cap} used)",
            f"The {kind} cap ({cap}) exists to keep WAF interaction low-volume. "
            "Report what is known, or ask the operator to raise the cap in scope.md.")
    state["hosts"].setdefault(host, {})[kind] = used + n
    state["hosts"][host]["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    path.write_text(json.dumps(state, indent=2))
    return {"used": used + n, "cap": cap}


# ---------------------------------------------------------------------------
# waf_test_bypass handler (was WafCore.waf_test_bypass)
# ---------------------------------------------------------------------------
def test_bypass(bridge: BridgeClient, request: dict, transform_ids: list[str],
                max_attempts: int = 8) -> dict:
    if not request or "url" not in request:
        raise WafError("request {method,url,headers,body} required", "Paste the blocked request.")
    ids = list(dict.fromkeys(transform_ids or []))[:max(1, min(int(max_attempts), 8))]
    if not ids:
        raise WafError("transform_ids required", "Pass ids from waf_adapt output (start with low-risk ones).")
    host = urlparse(request["url"]).netloc
    budget = _budget_bump(host, len(ids) + 1, int(_env("WAF_BYPASS_MAX", BYPASS_CAP_DEFAULT)), "bypass_attempts")

    base_resp = bridge.request(request.get("method", "GET"), request["url"],
                               headers=request.get("headers") or [], body=request.get("body"),
                               note=f"WAF bypass baseline {request['url']}")
    base_v = classify_response(base_resp)
    base_blocked = base_v["verdict"] in ("blocked", "challenge")

    results = []
    for tid in ids:
        try:
            new_req, why = apply_transform(request, tid)
        except WafError as e:
            results.append({"id": tid, "applied": False, "error": e.error})
            continue
        resp = bridge.request(new_req.get("method", "GET"), new_req["url"],
                              headers=new_req.get("headers") or [], body=new_req.get("body"),
                              note=f"WAF bypass test [{tid}] {request['url']}")
        v = classify_response(resp)
        reached = v["verdict"] not in ("blocked", "challenge")
        results.append({"id": tid, "applied": True, "status": resp.get("status"),
                        "verdict": v["verdict"], "origin_reached": reached,
                        "rationale": why,
                        "bridge_id": resp.get("id")})
    winners = [r for r in results if r.get("origin_reached")]
    return {"ok": True, "data": {
        "baseline": {"status": base_resp.get("status"), "verdict": base_v["verdict"]},
        "results": results, "budget": budget,
        "origin_reached": bool(winners),
        "finding_hint": ("If the origin response shows the endpoint's REAL behavior for the modified "
                         "request, you have a WAF-bypass finding candidate: re-validate once (§6), "
                         "calibrate with V-1, and write impact as the underlying vuln's reachability — "
                         "not 'WAF bypassed' alone.") if winners else None,
    }}
