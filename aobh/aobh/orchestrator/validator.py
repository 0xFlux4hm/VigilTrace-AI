#!/usr/bin/env python3
"""validator.py — Mission Control's adversarial validator + duplicate detection.

The validator is the FALSE-POSITIVE FILTER between "candidate" and "finding". It
does two things, honestly and locally (no target traffic of its own):

  1. KILL-TEST PLANNING — per vulnerability class, the specific cheap tests that
     most often kill a false positive (fresh-session retry, cache-buster, cold
     reproduction, param isolation, control check...). The agent executes them
     through the normal hunting tools (§6 gauntlet); the validator decides which
     are still outstanding for the evidence at hand.

  2. EVIDENCE SCORING + TRIAGE — a transparent 0-100 score over declared evidence
     (differential pair, OOB interaction, cold reproductions, server-side effect,
     attached pairs, mechanism clarity) minus classic false-positive penalties.
     Triage policy (skill §13.5):
         score >= 90  -> validated        (raise_issue is authorized)
         60..89       -> needs_more_validation (outstanding kill tests listed)
         < 60         -> watchlist        (keep, do not raise)

Duplicate detection cross-checks a candidate against (a) the local findings
registry, (b) Burp's existing scanner issues via the bridge (when reachable), and
(c) the disclosed-report corpus for precedent calibration — never for copying.
"""
from __future__ import annotations

from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Kill tests per vulnerability class. `applies(evidence)` decides which are
# already satisfied by the declared evidence; the rest are outstanding gaps.
# ---------------------------------------------------------------------------
KILL_TESTS = {
    "access_control": [
        {"id": "fresh-session", "test": "Re-run the unauthorized read with a freshly authenticated session (re-login once) — expired-session false positives die here."},
        {"id": "cold-repro-x2", "test": "Two reproductions from a cold sequence (not blind replays of the same request id), same observable result."},
        {"id": "both-directions", "test": "Prove the differential in both role directions (A reads B's object AND B reads A's) where feasible — rules out object-staleness."},
        {"id": "missing-vs-forbidden", "test": "Check semantics for a nonexistent id (404 vs 403) — confirms the endpoint processes the id at all."},
        {"id": "param-isolation", "test": "Confirm exactly one variable changed between baseline and variant (§5.2)."},
    ],
    "injection": [
        {"id": "error-stability", "test": "Re-send the payload twice fresh — the error signature must be deterministic, not a fluke."},
        {"id": "body-reflection", "test": "Confirm the marker appears in a response context that matters (body/execution), not a header echo or log line."},
        {"id": "param-isolation", "test": "Re-run with only the payload parameter changed — no other field touched."},
        {"id": "benign-control", "test": "Send a benign value in the same parameter — must NOT trigger the same response, proving the payload matters."},
    ],
    "ssrf_oob": [
        {"id": "interaction-latency", "test": "Interaction must arrive ≥60s after trigger and be attributable to YOUR payload id (poll_collaborator)."},
        {"id": "dns-vs-http", "test": "Classify DNS-only vs HTTP interaction — HTTP with request details is the strong signal; DNS-only stays a candidate."},
        {"id": "retrigger-once", "test": "Trigger once more after a delay — second interaction confirms reachability is not a one-off."},
        {"id": "param-isolation", "test": "Only the URL-like parameter changed between baseline and variant."},
    ],
    "auth_session": [
        {"id": "cold-client-replay", "test": "Replay the pre-logout / old token from a cold sequence — session-invalidation flaws survive fresh replay."},
        {"id": "own-token-only", "test": "Confirm every tampered token belongs to your own test account (never someone else's session)."},
        {"id": "repro-x2", "test": "Two independent reproductions (logout → reuse; password change → old session)."},
    ],
    "business_logic": [
        {"id": "full-flow", "test": "Capture the full flow (order → tamper → confirm) — not a single mutated request in isolation."},
        {"id": "math-recheck", "test": "Re-verify quantities/currency arithmetic in code (never in your head) before claiming a miscalculation."},
        {"id": "reversible", "test": "Revert the tampered state where possible and record the revert in the report."},
    ],
    "file_upload": [
        {"id": "landing-proof", "test": "Fetch the uploaded file's returned URL — prove where it landed and how it is served."},
        {"id": "served-content-type", "test": "Check the Content-Type the server uses when serving the file (execution context matters)."},
    ],
    "captcha_validation": [
        {"id": "all-variants", "test": "All four invalid variants attempted (omit / empty / dummy / replay), each response captured."},
        {"id": "control-accepted", "test": "A valid token (or the flow's normal path) is accepted — proves the endpoint works and the check is really absent."},
    ],
    "misconfig": [
        {"id": "stable-x2", "test": "Behavior stable across two fresh requests (CORS reflection, header oddities)."},
        {"id": "scanner-crosscheck", "test": "Cross-check get_scanner_issues — if Burp already reports it, reference it instead of re-raising."},
    ],
    "info_disclosure": [
        {"id": "stable-x2", "test": "Leak stable across two requests and not a cached/A-B artifact (add a cache-buster)."},
        {"id": "sensitivity-check", "test": "Confirm the exposed data is genuinely sensitive (stack trace, secret, internal URL) — not a generic banner."},
    ],
    "open_redirect": [
        {"id": "location-proof", "test": "Capture the 30x Location header (or JS/meta redirect) — the redirect must be verifiable offline via get_response."},
    ],
    "rate_limiting": [
        {"id": "within-scope", "test": "Confirm the program policy does not exclude rate-limit testing (scope.md excluded classes)."},
        {"id": "benign-only", "test": "Prove the burst used benign payloads on a non-auth endpoint within the fuzz budget."},
    ],
    "mass_assignment": [
        {"id": "own-account-only", "test": "Effect verified on your own account only; revert recorded if reversible."},
        {"id": "field-isolation", "test": "One added field per test — no batch-adding of privileged fields."},
    ],
}

# ---------------------------------------------------------------------------
# Evidence scoring. Each key: (points, label). Agent declares which apply.
# ---------------------------------------------------------------------------
POSITIVE_EVIDENCE = {
    "differential_pair":       (25, "baseline + single-variable variant with a clear, repeated difference"),
    "oob_interaction":         (25, "Collaborator interaction captured and attributed to your payload"),
    "deterministic_repro_x2":  (20, "two independent cold reproductions, same observable result"),
    "server_side_effect":      (15, "state change or cross-user data observed server-side (own accounts only)"),
    "evidence_pairs_attached": (10, "full request/response pair(s) attached (agent/proxy ids)"),
    "mechanism_understood":    (5,  "root cause articulable in one sentence"),
}
NEGATIVE_EVIDENCE = {
    "single_observation_only":   (-25, "one ambiguous signal, no reproduction"),
    "client_side_only":          (-15, "impact depends on browser/JS behavior you did not prove"),
    "environment_dependent":     (-15, "cache, A/B tests or app state could explain the difference"),
    "mechanism_unclear":         (-10, "no credible root cause yet"),
    "blocked_final_proof":       (-10, "rate limit / WAF / policy stopped the final proof"),
}
SCORE_FLOOR, SCORE_CEIL = 0, 100


def score_evidence(declared: list[str]) -> dict:
    """Score declared evidence keys (strings from POSITIVE/NEGATIVE tables)."""
    breakdown, score = [], 0
    unknown = []
    for key in declared:
        if key in POSITIVE_EVIDENCE:
            pts, label = POSITIVE_EVIDENCE[key]
            score += pts
            breakdown.append({"key": key, "points": pts, "label": label})
        elif key in NEGATIVE_EVIDENCE:
            pts, label = NEGATIVE_EVIDENCE[key]
            score += pts
            breakdown.append({"key": key, "points": pts, "label": label})
        else:
            unknown.append(key)
    score = max(SCORE_FLOOR, min(SCORE_CEIL, score))
    if score >= 90:
        triage, meaning = "validated", "evidence is raise-ready — provenance 'agent-validated'"
    elif score >= 60:
        triage, meaning = "needs_more_validation", "complete the outstanding kill tests, then re-run validate_finding"
    else:
        triage, meaning = "watchlist", "do not raise — keep on the watchlist and gather coverage"
    return {"score": score, "triage": triage, "meaning": meaning,
            "breakdown": breakdown, "unknown_keys": unknown}


def kill_test_plan(vuln_class: str) -> list[dict]:
    return [dict(t) for t in KILL_TESTS.get(vuln_class, KILL_TESTS["misconfig"])]


def outstanding_kill_tests(vuln_class: str, declared: list[str]) -> list[dict]:
    """Heuristic mapping: which kill tests the declared evidence already covers."""
    covered_by = {
        "deterministic_repro_x2": {"cold-repro-x2", "repro-x2", "error-stability", "stable-x2",
                                   "retrigger-once", "all-variants"},
        "differential_pair":      {"both-directions", "param-isolation", "benign-control",
                                   "field-isolation", "dns-vs-http"},
        "evidence_pairs_attached": {"landing-proof", "location-proof", "control-accepted",
                                    "full-flow", "interaction-latency"},
        "server_side_effect":     {"own-account-only", "sensitivity-check", "math-recheck"},
        "mechanism_understood":   set(),
    }
    covered: set[str] = set()
    for key in declared:
        covered |= covered_by.get(key, set())
    return [t for t in kill_test_plan(vuln_class) if t["id"] not in covered]


# ---------------------------------------------------------------------------
# Duplicate detection
# ---------------------------------------------------------------------------

def _norm_url(url: str) -> dict:
    sp = urlsplit(url if "://" in url else "https://" + url)
    path = sp.path.rstrip("/") or "/"
    return {"host": sp.netloc.lower(), "path": path}


def normalize_class(vuln_class: str) -> str:
    return (vuln_class or "unknown").strip().lower().replace("-", "_").replace(" ", "_")


def check_local_duplicates(candidate: dict, registry: list[dict]) -> dict:
    """candidate: {url, vuln_class, param?, title?}; registry: findings store list."""
    c_url, c_class = _norm_url(candidate.get("url", "")), normalize_class(candidate.get("vuln_class", ""))
    c_param = (candidate.get("param") or "").lower()
    hits = []
    for f in registry:
        if f.get("status") in ("killed", "duplicate"):
            continue
        f_url, f_class = _norm_url(f.get("url", "")), normalize_class(f.get("vuln_class", ""))
        f_param = (f.get("param") or "").lower()
        same_class = f_class == c_class
        same_path = f_url["path"] == c_url["path"]
        same_param = bool(c_param) and c_param == f_param
        if same_class and (same_path or same_param):
            reason = "same path + class" if same_path else "same param + class"
            hits.append({"finding_id": f["id"], "title": f.get("title", ""),
                         "status": f.get("status"), "match_reason": reason})
    verdict = "local_duplicate" if hits else "unique"
    return {"verdict": verdict, "matches": hits,
            "hint": ("merge evidence into the existing finding or differentiate it — do not raise twice"
                     if hits else "no local overlap in the findings registry")}


def precedent_query(candidate: dict) -> str:
    """BM25-friendly query string for precedent calibration (V-1/C-1)."""
    parts = [candidate.get("vuln_class", ""), candidate.get("param", ""),
             candidate.get("title", "")]
    return " ".join(p for p in parts if p).strip()
