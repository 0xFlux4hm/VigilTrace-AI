#!/usr/bin/env python3
"""approvals.py — the ApprovalGate: Tier-3 and risky actions hold until the operator approves.

Split out of the proven mission_core.py unchanged. Two halves share one idea —
the agent cannot promote its own authority:

  * pause reasons   — hard pauses (scope_drift / target_down) and soft pauses;
                      only mission_control resolve_pause with an operator_reference
                      lifts a hard pause
  * approval records — Tier-3 tasks are unclaimable without an APPROVED approval
                      record; task_next auto-creates the request and parks the
                      task in pending_approval

All persistence goes through the MissionStore (approvals.json, mission doc,
notifications.jsonl); this module decides, the store writes.
"""
from __future__ import annotations

from aobh.orchestrator.store import _now


class ApprovalGate:
    """Pause-reason bookkeeping + the Tier-3 approval gate (state in the store)."""

    def __init__(self, store):
        self.store = store

    # ---------------- pause machinery ----------------

    def add_pause_reason(self, doc: dict, ptype: str, detail: str, hard: bool) -> dict:
        reasons = doc.setdefault("pause_reasons", [])
        for r in reasons:
            if r["type"] == ptype and not r.get("resolved_at"):
                r["detail"], r["raised_at"] = detail, _now()
                return r
        r = {"id": f"P-{len(reasons) + 1:03d}", "type": ptype, "hard": hard,
             "detail": detail[:300], "raised_at": _now(), "resolved_at": None}
        reasons.append(r)
        return r

    def unresolved_hard(self, doc: dict) -> list[dict]:
        return [r for r in doc.get("pause_reasons", [])
                if r.get("hard") and not r.get("resolved_at")]

    # ---------------- approval gate ----------------

    def approval_for_task(self, task_id: str) -> dict | None:
        for a in self.store.approvals():
            if a["status"] == "approved" and a.get("block_task_id") == task_id:
                return a
        return None

    def auto_request_approval(self, task: dict) -> dict:
        apr = self.store.add_approval({
            "title": f"Tier-{task['tier']} task {task['id']}: {task['title']}",
            "action": task["type"], "risk_tier": task["tier"], "params": task.get("params", {}),
            "context": "auto-gated by task_next: Tier-3 tasks require operator approval (§13.7)",
            "block_task_id": task["id"],
        })
        self.store.append("notifications", {
            "level": "critical", "requires_ack": True,
            "subject": f"Approval needed: {apr['id']} ({task['type']})",
            "body": f"{task['title']} — approve/deny via mission_control action=approve|deny approval_id={apr['id']} with operator_reference.",
        })
        return apr
