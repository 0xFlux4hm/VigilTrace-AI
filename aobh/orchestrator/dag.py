#!/usr/bin/env python3
"""dag.py — the task queue machinery (TaskQueue): dependencies, recompute, prereq injection.

Split out of the proven mission_core.py unchanged. MissionCore owns the
task_* handlers and delegates the queue machinery here; every method name and
behavior is identical to the proven code (single writer, idempotent recompute).

Subsystems here:
  * recompute()      — status propagation: deps done -> ready; deps dead ->
                       blocked; failed with attempts left -> auto-requeue
  * queue_counts()   — status histogram over the task list
  * prereq_tasks()   — dependency injection: authenticated tasks need healthy
                       accounts; payload-bearing tasks need a WAF probe on
                       their host first (W-2)

External state readers (_waf_probed_hosts / _active_accounts_count) are
side-effect free and tolerant of absence: the account gate only reads the
vault when both accounts.json and .vault_key already exist, and never creates
vault material.
"""
from __future__ import annotations

import json
from pathlib import Path

# statuses the queue itself sets or propagates (task_update validates against this list)
TASK_STATUSES = ["queued", "ready", "blocked", "running", "done", "failed", "cancelled",
                 "pending_approval"]
PRIORITIES = {0: "critical", 1: "high", 2: "normal", 3: "low", 4: "backlog"}

# suggested tool sequence per task type (hints, not enforcement — skill §5/§10-§12 own the rules)
TASK_PLAYBOOKS = {
    "bootstrap_scope":   ["get_scope — reconcile with the authorization artifact", "add_to_scope / remove_from_scope", "write scope.md", "mission_control action=checkpoint"],
    "recon_inventory":   ["get_proxy_history", "get_site_map", "search_history", "coverage_update (register endpoints, state=untested)"],
    "waf_fingerprint":   ["waf_fingerprint (W-1)", "memory_save the vendor+verdict", "record in attack-surface.md"],
    "rag_briefing":      ["rag_find_similar (target stack)", "rag_pattern_stats (stack keywords)", "write known-weak patterns into attack-surface.md"],
    "coverage_seed":     ["coverage_update per endpoint (state=untested)", "coverage_gaps to rank what to test first"],
    "coverage_fill":     ["coverage_gaps auto_seed=true", "execute seeded test_hypothesis tasks"],
    "test_hypothesis":   ["rag_playbook (T-1)", "atap_account_health if authenticated (A-2)", "baseline -> single-variable variant -> compare -> third leg (§5.2)", "coverage_update", "task_update done + result"],
    "validate_step":     ["execute the kill test with the hunting tools", "re-run validate_finding with the new evidence"],
    "validate_finding":  ["validate_finding", "resolve needs_more_validation tasks", "raise_issue only after triage=validated"],
    "investigate_oob":   ["poll_collaborator (≥60s)", "classify DNS vs HTTP", "validate_finding with oob_interaction evidence"],
    "waf_bypass_eval":   ["waf_adapt", "waf_test_bypass (budgeted, 2-4 low-risk transforms)", "origin-reached -> validate_finding"],
    "captcha_handle":    ["captcha_detect (C-0)", "sanctioned path per §12 (human first)", "captcha_test_bypass once per flow (C-2)"],
    "atap_provision":    ["atap_policy_check (A-0) if undecided", "atap_create_account -> atap_verify_account -> atap_login (A-1)"],
    "atap_health":       ["atap_account_health (A-2)", "one re-login max", "mark expired if it fails"],
    "atap_cleanup":      ["atap_cleanup dry_run=true then real (A-3)", "paste disclosure_block into report.md"],
    "backoff_wait":      ["hold target traffic for params.minutes", "one benign re-probe", "emit event=target_up if recovered"],
    "report_section":    ["write the artifact section", "rag_query_reports for title calibration (C-1)"],
}


# ---------------------------------------------------------------------------
# External state readers (side-effect free, all tolerant of absence)
# ---------------------------------------------------------------------------

def _waf_probed_hosts(engagement_dir: str | Path) -> set[str]:
    path = Path(engagement_dir) / "waf_state.json"
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        return {h for h, v in state.get("hosts", {}).items() if v.get("probe", 0) > 0}
    except Exception:
        return set()


def _active_accounts_count(engagement_dir: str | Path) -> int:
    """Count ACTIVE atap accounts WITHOUT creating vault material: only read when
    both accounts.json and .vault_key already exist."""
    d = Path(engagement_dir)
    if not ((d / "accounts.json").exists() and (d / ".vault_key").exists()):
        return 0
    try:
        from aobh.atap.vault import Vault  # noqa: E402  (sibling engine, stdlib crypto)
        data = Vault.open(d).load()
        return sum(1 for a in data.get("accounts", []) if a.get("status") == "active")
    except Exception:
        return 0


class TaskQueue:
    """The priority queue with dependencies, auto-retry and prereq injection.

    Owns no state of its own — the MissionStore is the single writer; every
    read goes through it so a restarted process resumes from disk.
    """

    def __init__(self, store):
        self.store = store

    def recompute(self) -> list[dict]:
        """Status propagation: deps done -> ready; deps dead -> blocked; failed with
        attempts left -> auto-requeue. Single writer, idempotent."""
        tasks = self.store.tasks()
        by_id = {t["id"]: t for t in tasks}
        changed = False
        for t in tasks:
            dead_dep = None
            for d in t["deps"]:
                dep = by_id.get(d)
                if dep is None:
                    dead_dep = f"unknown dependency {d}"
                    break
                if dep["status"] == "cancelled" or (dep["status"] == "failed" and dep["attempts"] >= dep["max_attempts"]):
                    dead_dep = f"dependency {d} {dep['status']}"
                    break
            if dead_dep and t["status"] in ("queued", "ready"):
                t["status"], t["error"], changed = "blocked", dead_dep, True
                continue
            if t["status"] == "failed" and t["attempts"] < t["max_attempts"]:
                t["status"], changed = "queued", True   # auto-retry
                continue
            if t["status"] == "queued":
                if not t["deps"]:
                    t["status"], changed = "ready", True
                elif all(by_id[d]["status"] == "done" for d in t["deps"] if d in by_id):
                    t["status"], changed = "ready", True
        if changed:
            self.store._write("tasks", tasks)
        return tasks

    @staticmethod
    def queue_counts(tasks: list[dict]) -> dict[str, int]:
        c: dict[str, int] = {}
        for t in tasks:
            c[t["status"]] = c.get(t["status"], 0) + 1
        return c

    def prereq_tasks(self, task: dict) -> list[dict]:
        """Dependency injection: authenticated tasks need healthy accounts; payload-
        bearing tasks need a WAF probe on their host first (W-2)."""
        prereqs: list[dict] = []
        params = task.get("params", {})
        probed = _waf_probed_hosts(self.store.dir)
        host = params.get("host", "")
        if task.get("tier", 0) >= 2 and host and host not in probed and params.get("payload_bearing", True):
            prereqs.append({"type": "waf_probe", "title": f"WAF probe battery on {host} before payload work (W-2)",
                            "priority": 1, "tier": 1, "params": {"host": host},
                            "source": "prereq-injector"})
        if params.get("authenticated") and _active_accounts_count(self.store.dir) == 0:
            prereqs.append({"type": "atap_provision", "title": "Provision/verify test accounts before authenticated work (A-0/A-1)",
                            "priority": 1, "tier": 0, "params": {}, "source": "prereq-injector"})
        return prereqs
