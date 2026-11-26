#!/usr/bin/env python3
"""coverage.py — the CoverageMatrix: endpoints × vulnerability classes.

Split out of the proven mission_core.py unchanged. The matrix is what makes
the hunt self-directing:

  * coverage_update (engine) writes cells; this module owns the vocabulary
    and the read-side computations.
  * summary()  — per-class counts (tested, vulnerable, in_progress, na) and
    the percentage of each class covered; feeds mission_status.
  * gaps()     — ranked untested cells: class weight + endpoint weight
    (value flows and auth'd endpoints first, state-changing methods +1);
    feeds coverage_gaps and, with auto_seed, the task queue.

The matrix vocabulary mirrors skill §5.3 playbooks P1-P12 + C-2; weights feed
gap ranking.
"""
from __future__ import annotations

COVERAGE_STATES = ["untested", "in_progress", "tested_clean", "vulnerable", "na"]

COVERAGE_CLASSES = [
    ("access_control", 5), ("auth_session", 4), ("injection", 4), ("ssrf_oob", 4),
    ("business_logic", 4), ("xss", 3), ("file_upload", 3), ("mass_assignment", 3),
    ("captcha_validation", 3), ("info_disclosure", 2), ("misconfiguration", 2),
    ("open_redirect", 2), ("rate_limiting", 1),
]
CLASS_WEIGHTS = dict(COVERAGE_CLASSES)
CLASS_NAMES = [c for c, _ in COVERAGE_CLASSES]


class CoverageMatrix:
    """Read-side computations over the coverage document in the store.

    Owns no state of its own — the store is the single writer; coverage_update
    (engine.py) registers endpoints and writes cells through it.
    """

    def __init__(self, store):
        self.store = store

    def summary(self) -> dict:
        cov = self.store.coverage()
        keys = [e["key"] for e in cov["endpoints"]]
        per_class = {}
        for cls in CLASS_NAMES:
            counts: dict[str, int] = {}
            for key in keys:
                s = cov["matrix"].get(key, {}).get(cls, {}).get("state")
                if s:
                    counts[s] = counts.get(s, 0) + 1
            na = counts.get("na", 0)
            tested = counts.get("tested_clean", 0) + counts.get("vulnerable", 0)
            evaluated = max(len(keys) - na, 0)
            per_class[cls] = {"endpoints": len(keys), "tested": tested,
                              "vulnerable": counts.get("vulnerable", 0),
                              "in_progress": counts.get("in_progress", 0),
                              "not_applicable": na,
                              "pct_of_class_covered": round(100.0 * tested / evaluated, 1) if evaluated else 0.0}
        return {"endpoints_registered": len(keys), "classes": CLASS_NAMES, "per_class": per_class}

    def gaps(self, limit: int) -> list[dict]:
        """Ranked untested cells (class weight + endpoint weight), truncated to
        max(1, min(limit, 40)). Empty matrix is the caller's (engine's) error case."""
        cov = self.store.coverage()
        gaps = []
        for e in cov["endpoints"]:
            weight = (3 if (e.get("value_flow") or e.get("auth")) else 2 if e.get("auth") else 1)
            if e.get("method") in ("POST", "PUT", "DELETE", "PATCH"):
                weight += 1
            for cls, cw in COVERAGE_CLASSES:
                cell = cov["matrix"].get(e["key"], {}).get(cls)
                if cell is None or cell["state"] == "untested":
                    gaps.append({"endpoint": e["key"], "auth": e.get("auth", ""),
                                 "vuln_class": cls, "score": cw + weight,
                                 "state": cell["state"] if cell else "untested"})
        gaps.sort(key=lambda g: -g["score"])
        return gaps[:max(1, min(limit, 40))]
