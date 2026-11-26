#!/usr/bin/env python3
"""budget.py — the BudgetGovernor: request/time/call budgets with warn(80%)/exhausted gates.

Split out of the proven mission_core.py unchanged. The governor is a read-side
verdict over the mission document's budgets/counters, with bridge /health
counters taking precedence where they report higher usage:

    verdict  — ok | warn (any row ≥80%) | exhausted (any row ≥100%)
    rows     — per-budget {used, cap, pct, flag}
    pace     — observed requests/hour and projected minutes to the request cap
    rec      — the enforcement recommendation the engine follows

Exhausted budgets block NEW testing tasks in task_next; validation/report/
cleanup tasks still run so the engagement can close honestly
(ALLOWED_WHEN_EXHAUSTED). Caps are only raised by mission_control action=budget
WITH an operator_reference — the agent cannot silently extend its own authority.

Bridge /health counters are baselined per bridge ``instance``: on a restart
(instance change) the previous instance's last-reported counters are banked
into a carry-over, so cumulative spend survives counter resets — and the
engine notifies the operator once per restart.
"""
from __future__ import annotations

from datetime import datetime, timezone

# task types the queue still yields when the budget is exhausted (honest close-out)
ALLOWED_WHEN_EXHAUSTED = {"validate_step", "validate_finding", "report_section",
                          "atap_cleanup", "coverage_seed", "coverage_fill"}


def _iso_age_minutes(iso: str) -> float:
    if not iso:
        return 0.0
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return max(0.0, (datetime.now(timezone.utc) - dt).total_seconds() / 60.0)
    except ValueError:
        return 0.0


class BudgetGovernor:
    """Computes the budget verdict from the mission doc (+ optional bridge counters)."""

    def __init__(self, store):
        self.store = store

    def _bridge_sync(self) -> dict:
        """Persisted reconciliation state (the mission doc's bridge_sync section)."""
        bs = (self.store.mission() or {}).get("bridge_sync") or {}
        keys = ("requests_sent", "fuzz_requests")
        return {"instance": bs.get("instance"),
                "carryover": {k: int((bs.get("carryover") or {}).get(k, 0)) for k in keys},
                "last_seen": {k: int((bs.get("last_seen") or {}).get(k, 0)) for k in keys}}

    def _record_bridge_sync(self, instance: str, carryover: dict, last_seen: dict) -> None:
        try:
            self.store.update_mission(bridge_sync={"instance": instance,
                                                   "carryover": dict(carryover),
                                                   "last_seen": dict(last_seen)})
        except Exception:
            pass  # reconciliation state is advisory; never break the verdict on a store hiccup

    def verdict(self, bridge_counters: dict | None = None,
                bridge_instance: str | None = None) -> dict:
        doc = self.store.mission()
        b, c = doc["budgets"], doc["counters"]
        bc = dict(bridge_counters or {})
        restarted = False
        carry: dict = {}
        if bridge_instance is not None:
            bs = self._bridge_sync()
            if bs["instance"] == bridge_instance:
                carry = dict(bs["carryover"])
            elif bs["instance"]:
                # Burp restarted: bank what the previous instance last reported so
                # cumulative bridge spend survives the counter reset
                carry = {k: bs["carryover"].get(k, 0) + bs["last_seen"].get(k, 0)
                         for k in ("requests_sent", "fuzz_requests")}
                restarted = True
            else:
                carry = {k: 0 for k in ("requests_sent", "fuzz_requests")}
            seen = {k: int(bc.get(k, 0) or 0) for k in ("requests_sent", "fuzz_requests")}
            self._record_bridge_sync(bridge_instance, carry, seen)
            bc = {k: carry.get(k, 0) + seen[k] for k in ("requests_sent", "fuzz_requests")}
        used = {
            "requests": max(int(c.get("requests_sent", 0)), int(bc.get("requests_sent", 0) or 0)),
            "fuzz_requests": max(int(c.get("fuzz_requests", 0)), int(bc.get("fuzz_requests", 0) or 0)),
            "tool_calls": int(c.get("tool_calls", 0)),
            "session_minutes": round(_iso_age_minutes(c.get("session_started_at", "")), 1),
        }
        caps = {"requests": b["max_requests"], "fuzz_requests": b["max_fuzz_requests"],
                "tool_calls": b["max_tool_calls"], "session_minutes": b["max_session_minutes"]}
        rows = []
        for k, cap in caps.items():
            pct = round(100.0 * used[k] / cap, 1) if cap else 100.0
            rows.append({"budget": k, "used": used[k], "cap": cap, "pct": pct,
                         "flag": ("exhausted" if pct >= 100 else "warn" if pct >= 80 else "ok")})
        verdict = ("exhausted" if any(r["flag"] == "exhausted" for r in rows)
                   else "warn" if any(r["flag"] == "warn" for r in rows) else "ok")
        hours = max(used["session_minutes"], 0.1) / 60.0
        pace_per_hour = round(used["requests"] / hours, 1)
        remaining = caps["requests"] - used["requests"]
        projection = (round(remaining / pace_per_hour * 60.0, 1) if pace_per_hour > 0 and remaining > 0 else None)
        rec = {"ok": "continue — budget headroom",
               "warn": "≥80% spent — finish open loops, start validation/reporting (§13.6)",
               "exhausted": "budget exhausted — no new testing; validate + report + cleanup now"}[verdict]
        out = {"verdict": verdict, "rows": rows, "requests_per_hour": pace_per_hour,
               "projected_minutes_to_request_cap": projection, "recommendation": rec}
        if bridge_instance is not None:
            out["bridge"] = {"instance": bridge_instance, "restarted": restarted, "carryover": dict(carry)}
        return out
