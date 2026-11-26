#!/usr/bin/env python3
"""engine.py — MissionCore: the control loop that orchestrates the whole hunt.

Ported 1:1 from the proven autonomous-bug-hunter mission/mission_core.py; the
engine internals are split into sibling modules (dag, triggers, coverage,
budget, approvals, memory, phases) and every class/method name and behavior
is unchanged. `Orchestrator = MissionCore` is the package-facing alias.

This module turns the linear five-phase skill (§1) into a self-directing loop:

    event / coverage gap ──► PLANNER (task queue, priorities, dependencies)
                          ──► task_next ──► agent executes with the hunting tools
                          ──► results, evidence, coverage updates feed back
                          ──► budget governor, validator, approval gates supervise

Subsystems (all agent-side, stdlib only, state in the engagement dir):
  * TaskQueue (dag.py)           — priority queue with dependencies, auto-retry,
                                   prereq injection
  * TriggerEngine (triggers.py)  — built-in event → task/notification/pause reactions
  * CoverageMatrix (coverage.py) — endpoints × vulnerability classes; ranked gaps
  * TargetMemory (memory.py)     — durable quirks/intel/failures across sessions
  * BudgetGovernor (budget.py)   — request/time/call budgets with warn(80%)/exhausted gates
  * ApprovalGate (approvals.py)  — Tier-3 and risky actions hold until the operator approves
  * Validator (validator.py)     — adversarial kill-test planning + scoring + triage

Hard boundaries (enforced in code, restated in skill §13):
  * A PAUSED or HARD-PAUSED mission yields no new work from task_next — only the
    operator (mission_control resolve_pause with an operator_reference) lifts a
    hard pause raised by scope_drift / target_down events.
  * Tier-3 tasks are unclaimable without an APPROVED approval record.
  * Exhausted budgets block new testing tasks; validation/report/cleanup tasks
    still run so the engagement can close honestly.
  * Budget caps are only raised by mission_control action=budget WITH an
    operator_reference — the agent cannot silently extend its own authority.
  * Everything the engine does lands in run_log.jsonl / events.jsonl — the
    engagement transcript stays reconstructable from files alone.

Tool surface: 14 registered tools (tools.py / aobh.tools manifest, group
"mission_control"). The old 17-tool surface folded three tools:
task_list → mission_status (queue summary; the public method stays),
check_duplicates → validate_finding(dedup_only=true) (nothing written),
notify_operator → mission_control action="notify" (the public method stays).
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from aobh.core.config import get_config

from aobh.orchestrator.approvals import ApprovalGate
from aobh.orchestrator.budget import ALLOWED_WHEN_EXHAUSTED, BudgetGovernor, _iso_age_minutes
from aobh.orchestrator.coverage import (CLASS_NAMES, CLASS_WEIGHTS, COVERAGE_CLASSES,
                                        COVERAGE_STATES, CoverageMatrix)
from aobh.orchestrator.dag import PRIORITIES, TASK_PLAYBOOKS, TASK_STATUSES, TaskQueue
from aobh.orchestrator.memory import MEMORY_KINDS, TargetMemory
from aobh.orchestrator.phases import PHASES
from aobh.orchestrator.store import MissionStore, MissionStoreError, _now
import aobh.orchestrator.validator as validator
from aobh.orchestrator.triggers import TRIGGER_KNOWN, TriggerEngine

MISSION_DIR = Path(__file__).resolve().parent          # aobh/orchestrator
RAG_DIR = MISSION_DIR.parent / "rag"                   # aobh/rag (bundled corpus)

BRIDGE = os.environ.get("BURP_BRIDGE_URL", "http://127.0.0.1:8787")
BRIDGE_HDRS = {"Authorization": "Bearer " + os.environ.get("BURP_BRIDGE_TOKEN", "")}


class MissionError(Exception):
    def __init__(self, error: str, hint: str = ""):
        super().__init__(error)
        self.error, self.hint = error, hint


def _env(name: str, default=None):
    return os.environ.get(name, default)


class MissionCore:
    def __init__(self, engagement_dir: str | Path | None = None):
        self.store = MissionStore(engagement_dir or get_config().engagement_dir)
        # engine internals, split into sibling modules (names/behavior unchanged)
        self.queue = TaskQueue(self.store)
        self.triggers = TriggerEngine(self)
        self.coverage = CoverageMatrix(self.store)
        self.budget = BudgetGovernor(self.store)
        self.approvals = ApprovalGate(self.store)
        self.memory = TargetMemory(self.store)

    # ---------------- internal plumbing ----------------

    def _active(self) -> dict:
        doc = self.store.mission()
        if doc is None:
            raise MissionError("no mission initialized",
                               "Call mission_init with the target + authorization reference (skill §13.2).")
        return doc

    def _audit(self, tool: str, args: dict, ok: bool, started: float) -> None:
        """Every handler call: run_log entry + tool_calls counter."""
        self.store.append("run_log", {
            "tool": tool, "ok": bool(ok),
            "args_digest": json.dumps({k: (v if isinstance(v, (int, float, bool, str)) else "…")
                                       for k, v in list(args.items())[:6]}, ensure_ascii=False)[:400],
            "duration_ms": int((time.time() - started) * 1000),
        })
        try:
            self.store.bump("tool_calls")
        except MissionStoreError:
            pass  # no mission yet (mission_init itself)

    def _bridge_health(self) -> dict | None:
        try:
            req = urllib.request.Request(f"{BRIDGE}/health", headers=BRIDGE_HDRS, method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status < 400:  # requests' r.ok semantics
                    return json.loads(resp.read().decode())
        except Exception:
            pass
        return None

    def _scanner_issues(self, url_prefix: str, limit: int = 10) -> dict:
        try:
            req = urllib.request.Request(
                f"{BRIDGE}/tools/get_scanner_issues",
                data=json.dumps({"url_prefix": url_prefix, "limit": limit}).encode("utf-8"),
                headers={**BRIDGE_HDRS, "Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                env = json.loads(resp.read().decode())
            if env.get("ok"):
                return {"reachable": True, "issues": env["data"].get("issues", [])}
        except Exception:
            pass
        return {"reachable": False, "issues": [],
                "note": "bridge unreachable — run get_scanner_issues yourself when Burp is up"}

    _CORPUS = None

    def _corpus(self):
        if MissionCore._CORPUS is not None:
            return MissionCore._CORPUS
        index = Path(_env("H1_INDEX_PATH", RAG_DIR / "index" / "reports.jsonl"))
        if not index.exists():
            return None
        try:
            import aobh.rag.store as rag_store  # noqa: E402  (sibling engine, when present)
            MissionCore._CORPUS = rag_store.ReportCorpus.from_jsonl(index)
            return MissionCore._CORPUS
        except Exception:
            return None

    # ---------------- queue machinery (dag.py) ----------------

    def _recompute(self) -> list[dict]:
        return self.queue.recompute()

    @staticmethod
    def _queue_counts(tasks: list[dict]) -> dict[str, int]:
        return TaskQueue.queue_counts(tasks)

    def _prereq_tasks(self, task: dict) -> list[dict]:
        return self.queue.prereq_tasks(task)

    # ---------------- budget governor (budget.py) ----------------

    def _budget_verdict(self, bridge_counters: dict | None = None,
                        bridge_instance: str | None = None) -> dict:
        return self.budget.verdict(bridge_counters, bridge_instance=bridge_instance)

    def _reconcile_budget(self, health: dict | None) -> dict:
        """Instance-aware reconciliation: counters are baselined per bridge
        instance — a mid-mission Burp restart banks the previous instance's
        last-reported spend and notifies the operator exactly once."""
        verdict = self._budget_verdict((health.get("counters") if health else None),
                                       bridge_instance=(health or {}).get("instance"))
        if verdict.get("bridge", {}).get("restarted"):
            try:
                self.notify_operator("warn", "Burp/bridge restart detected",
                                     "Bridge instance changed mid-mission; counters were re-baselined "
                                     "and the previous instance's spend was banked into the carry-over.")
            except Exception:
                pass
        return verdict

    # ---------------- pause machinery (approvals.py) ----------------

    def _add_pause_reason(self, doc: dict, ptype: str, detail: str, hard: bool) -> dict:
        return self.approvals.add_pause_reason(doc, ptype, detail, hard)

    def _unresolved_hard(self, doc: dict) -> list[dict]:
        return self.approvals.unresolved_hard(doc)

    def _approval_for_task(self, task_id: str) -> dict | None:
        return self.approvals.approval_for_task(task_id)

    def _auto_request_approval(self, task: dict) -> dict:
        return self.approvals.auto_request_approval(task)

    # ---------------- coverage read-side (coverage.py) ----------------

    def _coverage_summary(self) -> dict:
        return self.coverage.summary()

    # =================================================================
    # 1-3. mission lifecycle
    # =================================================================

    def mission_init(self, target: str, authorization_reference: str, program_url: str = "",
                     phase: str = "0-bootstrap", budgets: dict | None = None,
                     seed_tasks: bool = True, note: str = "") -> dict:
        started = time.time()
        try:
            existing = self.store.mission()
            if existing and existing.get("status") in ("active", "paused"):
                self._audit("mission_init", {"target": target}, False, started)
                raise MissionError(
                    f"mission {existing['mission_id']} already exists ({existing['status']})",
                    "Continue it via mission_status (resume protocol, §13.8); delete "
                    "mission.json in the engagement dir only to abandon it deliberately.")
            if phase not in PHASES:
                raise MissionError(f"invalid phase {phase}", f"phases: {PHASES}")
            doc = self.store.init_mission(target, authorization_reference,
                                          program_url=program_url, phase=phase,
                                          budgets=budgets)
            seeded = []
            if seed_tasks:
                seeds = [
                    {"type": "bootstrap_scope", "title": "Reconcile Burp scope with the authorization artifact (Phase 0)",
                     "priority": 0, "tier": 0},
                    {"type": "recon_inventory", "title": "Harvest existing surface: proxy history, site map, history search (Phase 1)",
                     "priority": 1, "tier": 0, "deps": []},
                    {"type": "waf_fingerprint", "title": "Fingerprint the perimeter — one benign GET (W-1)",
                     "priority": 1, "tier": 1},
                    {"type": "rag_briefing", "title": "Corpus briefing: rag_find_similar + rag_pattern_stats for the stack (R-1)",
                     "priority": 2, "tier": 0},
                    {"type": "coverage_seed", "title": "Register discovered endpoints into the coverage matrix",
                     "priority": 2, "tier": 0},
                ]
                created = [self.store.add_task({**s, "source": "seed"}) for s in seeds]
                # the scope task gates everything; recon depends on it
                created[1]["deps"] = [created[0]["id"]]
                self.store._write("tasks", self.store.tasks())
                seeded = [t["id"] for t in created]
            self.store.append("notifications", {
                "level": "info", "requires_ack": False,
                "subject": f"Mission {doc['mission_id']} initialized",
                "body": f"target={target} auth={authorization_reference[:120]} budgets={doc['budgets']} note={note[:200]}",
            })
            self._recompute()
            self._audit("mission_init", {"target": target}, True, started)
            return {"ok": True, "data": {
                "mission": doc, "seeded_tasks": seeded,
                "next": "mission_status → task_next (claim=True) → execute → task_update",
                "note": "Budgets/caps can be adjusted only via mission_control action=budget with an operator_reference."}}
        except MissionError:
            raise
        except Exception as e:
            self._audit("mission_init", {"target": target}, False, started)
            raise MissionError(f"mission_init failed: {e}", "Check engagement dir permissions.")

    def mission_status(self, sections: list[str] | None = None) -> dict:
        started = time.time()
        doc = self._active()
        want = set(sections or ["queue", "budget", "coverage", "findings", "approvals",
                                "events", "notifications", "pause"])
        tasks = self._recompute()
        health = self._bridge_health()
        verdict = self._reconcile_budget(health)
        data: dict = {"mission": {k: doc[k] for k in ("mission_id", "target", "status", "phase",
                                                      "authorization_reference", "program_url",
                                                      "created_at", "updated_at")},
                      "budget": verdict, "bridge": {"reachable": bool(health),
                                                    "counters_synced": bool(health and health.get("counters"))}}
        if "pause" in want:
            data["pause_reasons"] = [r for r in doc.get("pause_reasons", []) if not r.get("resolved_at")]
        if "queue" in want:
            ready = sorted([t for t in tasks if t["status"] == "ready"],
                           key=lambda t: (t["priority"], t["created_at"]))
            data["queue"] = {"counts": self._queue_counts(tasks),
                             "ready_top": [{**{k: t[k] for k in ("id", "type", "title", "priority", "tier")},
                                            "playbook": TASK_PLAYBOOKS.get(t["type"], [])}
                                           for t in ready[:5]],
                             "orphans": [t["id"] for t in tasks if t["status"] == "running"
                                         and _iso_age_minutes(t["updated_at"]) > 30]}
        if "coverage" in want:
            data["coverage"] = self._coverage_summary()
        if "findings" in want:
            fs = self.store.findings()
            data["findings"] = {"count": len(fs),
                                "by_status": {s: sum(1 for f in fs if f.get("status") == s)
                                              for s in ("validated", "candidate", "watchlist",
                                                        "duplicate", "killed", "raised")},
                                "top": [{"id": f["id"], "title": f["title"], "score": f.get("validation", {}).get("score"),
                                         "triage": f.get("validation", {}).get("triage")} for f in fs[-5:]]}
        if "approvals" in want:
            data["approvals_pending"] = [a for a in self.store.approvals() if a["status"] == "pending"]
        if "events" in want:
            data["events_tail"] = self.store.read_jsonl("events")[-5:]
        if "notifications" in want:
            notes = self.store.read_jsonl("notifications")
            data["notifications"] = {"unread_critical": sum(1 for n in notes
                                                            if n.get("level") == "critical" and not n.get("read")),
                                     "tail": notes[-5:]}
        # recommendation
        if data.get("pause_reasons"):
            data["next_action"] = "PAUSED — resolve via mission_control (hard pauses need operator_reference)"
        elif verdict["verdict"] == "exhausted":
            data["next_action"] = "Wrap up: validate findings, write report, atap_cleanup (A-3)"
        elif data.get("queue", {}).get("ready_top"):
            data["next_action"] = f"task_next → {data['queue']['ready_top'][0]['id']}: {data['queue']['ready_top'][0]['title']}"
        else:
            data["next_action"] = "Queue empty — coverage_gaps(auto_seed=true) or enqueue follow-ups from new surface"
        self._audit("mission_status", {}, True, started)
        return {"ok": True, "data": data}

    def mission_control(self, action: str, reason: str = "", operator_reference: str = "",
                        budget: dict | None = None, phase: str = "", approval_id: str = "",
                        force: bool = False, note: str = "", level: str = "", subject: str = "",
                        body: str = "", requires_ack: bool = False) -> dict:
        started = time.time()
        doc = self._active()
        tasks = self._recompute()
        non_terminal = [t for t in tasks if t["status"] not in ("done", "failed", "cancelled")]
        out: dict = {"action": action}

        if action == "pause":
            r = self._add_pause_reason(doc, reason or "manual", reason or "paused by operator request", hard=False)
            doc = self.store.update_mission(status="paused")
            self.store.append("notifications", {"level": "warn", "requires_ack": False,
                                                "subject": f"Mission paused ({r['id']})", "body": r["detail"]})
            out.update({"status": "paused", "pause_reason": r})

        elif action == "resume":
            hard = self._unresolved_hard(doc)
            if hard:
                self._audit("mission_control", {"action": action}, False, started)
                raise MissionError(f"hard pause active: {[h['id'] + ':' + h['type'] for h in hard]}",
                                   "Hard pauses (scope_drift/target_down) lift ONLY via action=resolve_pause with operator_reference.")
            doc = self.store.update_mission(status="active")
            out.update({"status": "active"})

        elif action == "resolve_pause":
            if not operator_reference:
                self._audit("mission_control", {"action": action}, False, started)
                raise MissionError("resolve_pause requires operator_reference",
                                   "Cite the operator's statement (who confirmed scope/target, when).")
            resolved = []
            for r in doc.get("pause_reasons", []):
                if not r.get("resolved_at") and (not reason or r["id"] == reason or r["type"] == reason):
                    r["resolved_at"], r["resolved_by"] = _now(), operator_reference[:200]
                    resolved.append(r["id"])
            doc["pause_reasons"] = doc.get("pause_reasons", [])
            doc = self.store.update_mission(pause_reasons=doc["pause_reasons"],
                                            status="active" if not self._unresolved_hard(doc) else "paused")
            self.store.append("notifications", {"level": "info", "requires_ack": False,
                                                "subject": f"Pause resolved: {resolved}",
                                                "body": f"by {operator_reference[:150]} — {note[:200]}"})
            out.update({"resolved": resolved, "status": doc["status"]})

        elif action == "abort":
            for t in non_terminal:
                self.store.update_task(t["id"], status="cancelled", error=f"mission aborted: {reason[:200]}")
            doc = self.store.update_mission(status="aborted",
                                            end_summary={"reason": reason[:300], "at": _now(),
                                                         "tasks_cancelled": len(non_terminal)})
            self.store.append("notifications", {"level": "critical", "requires_ack": True,
                                                "subject": f"Mission {doc['mission_id']} ABORTED",
                                                "body": reason[:300] or "no reason given"})
            out.update({"status": "aborted", "tasks_cancelled": len(non_terminal)})

        elif action == "end":
            if non_terminal and not force:
                self._audit("mission_control", {"action": action}, False, started)
                raise MissionError(f"{len(non_terminal)} tasks still non-terminal",
                                   "Close them (task_update) or pass force=true to cancel them into the end summary.")
            if force:
                for t in non_terminal:
                    self.store.update_task(t["id"], status="cancelled", error="mission ended (force)")
            fs = self.store.findings()
            verdict = self._budget_verdict()
            summary = {"at": _now(), "reason": reason[:300], "note": note[:300],
                       "findings": {"total": len(fs),
                                    "validated": sum(1 for f in fs if f.get("status") == "validated")},
                       "budget_used": {r["budget"]: r["used"] for r in verdict["rows"]}}
            doc = self.store.update_mission(status="ended", end_summary=summary)
            self.store.append("notifications", {"level": "info", "requires_ack": False,
                                                "subject": f"Mission {doc['mission_id']} ended",
                                                "body": json.dumps(summary, ensure_ascii=False)[:400]})
            out.update({"status": "ended", "end_summary": summary})

        elif action == "checkpoint":
            cps = doc.setdefault("checkpoints", [])
            cp = {"id": f"C-{len(cps) + 1:03d}", "phase": doc["phase"], "note": note[:300], "at": _now()}
            cps.append(cp)
            doc = self.store.update_mission(checkpoints=cps)
            out.update({"checkpoint": cp})

        elif action == "phase":
            if phase not in PHASES:
                self._audit("mission_control", {"action": action}, False, started)
                raise MissionError(f"invalid phase {phase}", f"phases: {PHASES}")
            doc = self.store.update_mission(phase=phase)
            out.update({"phase": phase})

        elif action == "budget":
            if not operator_reference:
                self._audit("mission_control", {"action": action}, False, started)
                raise MissionError("budget changes require operator_reference",
                                   "Only the operator raises caps — cite their statement verbatim (§13.6).")
            budgets = dict(doc["budgets"])
            for k, v in (budget or {}).items():
                if k not in budgets:
                    self._audit("mission_control", {"action": action}, False, started)
                    raise MissionError(f"unknown budget key {k}", f"keys: {list(budgets)}")
                if not isinstance(v, (int, float)) or v <= 0:
                    self._audit("mission_control", {"action": action}, False, started)
                    raise MissionError(f"budget {k} must be a positive number", "")
                budgets[k] = v
            doc = self.store.update_mission(budgets=budgets)
            self.store.append("notifications", {"level": "info", "requires_ack": False,
                                                "subject": "Budget updated by operator",
                                                "body": f"{json.dumps(budget)} — ref: {operator_reference[:150]}"})
            out.update({"budgets": budgets})

        elif action == "approve":
            if not (approval_id and operator_reference):
                self._audit("mission_control", {"action": action}, False, started)
                raise MissionError("approve requires approval_id + operator_reference", "")
            apr = self.store.update_approval(approval_id, status="approved", decided_at=_now(),
                                             decided_by=operator_reference[:200], note=note[:300])
            if apr.get("block_task_id"):
                try:
                    self.store.update_task(apr["block_task_id"], status="queued")
                except MissionStoreError:
                    pass
            self._recompute()
            out.update({"approval": apr})

        elif action == "deny":
            if not (approval_id and operator_reference):
                self._audit("mission_control", {"action": action}, False, started)
                raise MissionError("deny requires approval_id + operator_reference", "")
            apr = self.store.update_approval(approval_id, status="denied", decided_at=_now(),
                                             decided_by=operator_reference[:200], note=note[:300])
            if apr.get("block_task_id"):
                try:
                    self.store.update_task(apr["block_task_id"], status="cancelled",
                                           error=f"approval {approval_id} denied")
                except MissionStoreError:
                    pass
            self._recompute()
            out.update({"approval": apr})

        elif action == "notify":
            # folded notify_operator — exactly what the public method does
            if level not in ("info", "warn", "critical"):
                self._audit("mission_control", {"action": action}, False, started)
                raise MissionError(f"invalid level {level}", "levels: info | warn | critical")
            rec = self.store.append("notifications", {"level": level, "requires_ack": bool(requires_ack),
                                                      "subject": subject[:200], "body": body[:1000]})
            out.update({"notification": rec,
                        "channel": "notifications.jsonl in the engagement dir + mission_status tail "
                                   "(wire an email/webhook forward here if the operator wants push)"})

        else:
            self._audit("mission_control", {"action": action}, False, started)
            raise MissionError(f"unknown action {action}",
                               "actions: pause | resume | resolve_pause | abort | end | checkpoint | "
                               "phase | budget | approve | deny | notify")

        self._audit("mission_control", {"action": action}, True, started)
        return {"ok": True, "data": out}

    # =================================================================
    # 4-7. task queue
    # =================================================================

    def task_enqueue(self, tasks: list[dict], auto_prereqs: bool = True) -> dict:
        started = time.time()
        self._active()
        if not isinstance(tasks, list) or not tasks:
            self._audit("task_enqueue", {}, False, started)
            raise MissionError("tasks must be a non-empty list",
                               "Each item: {type, title, priority?, deps?, tier?, params?, hypothesis?}.")
        created, injected = [], []
        for spec in tasks:
            if not spec.get("title"):
                self._audit("task_enqueue", {}, False, started)
                raise MissionError("every task needs a title", "")
            t = self.store.add_task({
                "type": spec.get("type", "generic"), "title": spec["title"],
                "priority": max(0, min(4, int(spec.get("priority", 2)))),
                "deps": spec.get("deps", []), "tier": max(0, min(3, int(spec.get("tier", 0)))),
                "params": spec.get("params", {}), "hypothesis": spec.get("hypothesis", ""),
                "source": spec.get("source", "agent"),
                "max_attempts": max(1, min(5, int(spec.get("max_attempts", 3)))),
            })
            created.append(t)
            if auto_prereqs:
                for p in self._prereq_tasks(t):
                    if any(c["type"] == p["type"] and c["title"] == p["title"] for c in created + injected):
                        continue  # dedupe identical prereqs within one batch
                    pr = self.store.add_task(p)
                    t["deps"] = t.get("deps", []) + [pr["id"]]
                    injected.append(pr)
        self.store._write("tasks", self.store.tasks())
        self._recompute()
        self._audit("task_enqueue", {"count": len(created)}, True, started)
        return {"ok": True, "data": {
            "tasks": [{k: t[k] for k in ("id", "type", "title", "priority", "status", "deps", "tier")}
                      for t in created],
            "injected_prereqs": [{k: p[k] for k in ("id", "type", "title", "status")} for p in injected],
            "queue_counts": self._queue_counts(self.store.tasks())}}

    def task_next(self, limit: int = 1, claim: bool = True) -> dict:
        started = time.time()
        doc = self._active()
        tasks = self._recompute()
        health = self._bridge_health()
        verdict = self._reconcile_budget(health)
        base = {"queue_counts": self._queue_counts(tasks), "budget": verdict,
                "orphans": [{"id": t["id"], "title": t["title"], "stale_for_min": round(_iso_age_minutes(t["updated_at"]), 1)}
                            for t in tasks if t["status"] == "running"
                            and _iso_age_minutes(t["updated_at"]) > 30]}
        if doc["status"] in ("paused", "ended", "aborted"):
            hard = self._unresolved_hard(doc)
            self._audit("task_next", {}, True, started)
            return {"ok": True, "data": {**base, "blocked": f"mission_{doc['status']}",
                    "hard_pauses": hard,
                    "hint": ("operator lifts hard pauses via mission_control action=resolve_pause "
                             "with operator_reference" if hard else
                             "mission_control action=resume when ready")}}
        claimable = [t for t in tasks if t["status"] == "ready"]
        # Tier-3 approval gate: unclaimable without an approved approval record
        gated = []
        for t in claimable:
            if t["tier"] >= 3 and not self._approval_for_task(t["id"]):
                apr = self._auto_request_approval(t)
                self.store.update_task(t["id"], status="pending_approval",
                                       params={**t.get("params", {}), "approval_id": apr["id"]})
                gated.append({"task": t["id"], "approval_id": apr["id"]})
        if gated:
            tasks = self._recompute()
            claimable = [t for t in tasks if t["status"] == "ready"]
        if verdict["verdict"] == "exhausted":
            allowed = [t for t in claimable if t["type"] in ALLOWED_WHEN_EXHAUSTED]
            blocked_testing = len(claimable) - len(allowed)
            if not allowed:
                self._audit("task_next", {}, True, started)
                return {"ok": True, "data": {**base, "blocked": "budget_exhausted",
                        "blocked_testing_tasks": blocked_testing,
                        "hint": "Validate findings, write the report, atap_cleanup (A-3) — "
                                "or the operator raises caps via mission_control action=budget."}}
            claimable = allowed
        claimable.sort(key=lambda t: (t["priority"], t["created_at"]))
        picked = claimable[:max(1, min(limit, 10))]
        out = []
        for t in picked:
            if claim:
                t = self.store.update_task(t["id"], status="running",
                                           attempts=t["attempts"] + 1)
            out.append({**{k: t[k] for k in ("id", "type", "title", "priority", "status",
                                             "tier", "params", "hypothesis", "deps", "attempts")},
                        "playbook": TASK_PLAYBOOKS.get(t["type"], []),
                        "priority_label": PRIORITIES.get(t["priority"], "normal")})
        self._audit("task_next", {"claim": claim, "limit": limit}, True, started)
        return {"ok": True, "data": {**base, "tasks": out,
                "hint": "Execute with the hunting tools, then task_update(done|failed) — "
                        "update test-plan.md/coverage as you go (§13.4)."}}

    def task_list(self, status: str = "", type: str = "", limit: int = 50) -> dict:
        """Public (folded out of the registered tools — mission_status summarizes
        the queue); kept for API parity with the proven engine."""
        started = time.time()
        self._active()
        tasks = self._recompute()
        rows = [t for t in tasks
                if (not status or t["status"] == status)
                and (not type or t["type"] == type)]
        rows.sort(key=lambda t: (t["priority"], t["created_at"]))
        self._audit("task_list", {"status": status}, True, started)
        return {"ok": True, "data": {"counts": self._queue_counts(tasks),
                "tasks": [{k: t[k] for k in ("id", "type", "title", "priority", "status",
                                             "deps", "tier", "attempts", "error")}
                          for t in rows[:max(1, min(limit, 200))]]}}

    def task_update(self, task_id: str, status: str | None = None, result: dict | None = None,
                    error: str = "", evidence_refs: list[str] | None = None, note: str = "") -> dict:
        started = time.time()
        self._active()
        if status is not None and status not in TASK_STATUSES:
            self._audit("task_update", {"task_id": task_id}, False, started)
            raise MissionError(f"invalid status {status}", f"statuses: {TASK_STATUSES}")
        t = self.store.get_task(task_id)
        fields: dict = {}
        if status:
            fields["status"] = status
        if result is not None:
            merged = dict(t.get("result", {}))
            merged.update(result)
            fields["result"] = merged
        if error:
            fields["error"] = error[:300]
        if evidence_refs:
            fields["evidence_refs"] = sorted(set(t.get("evidence_refs", [])) | set(evidence_refs))
        if note:
            fields["note"] = note[:500]
        t = self.store.update_task(task_id, **fields)
        if status == "failed" and t["attempts"] < t["max_attempts"]:
            self.store.append("notifications", {
                "level": "warn", "requires_ack": False,
                "subject": f"Task {task_id} failed (attempt {t['attempts']}/{t['max_attempts']})",
                "body": f"{t['title']} — {t.get('error', '')[:200]} — auto-requeued."})
        self._recompute()
        self._audit("task_update", {"task_id": task_id, "status": status}, True, started)
        return {"ok": True, "data": {"task": {k: t[k] for k in ("id", "status", "attempts",
                                                                "result", "error", "evidence_refs")},
                "queue_counts": self._queue_counts(self.store.tasks())}}

    # =================================================================
    # 8-9. coverage matrix
    # =================================================================

    def coverage_update(self, endpoint: dict, vuln_class: str, state: str,
                        evidence: str = "", note: str = "") -> dict:
        started = time.time()
        self._active()
        if vuln_class not in CLASS_NAMES:
            self._audit("coverage_update", {}, False, started)
            raise MissionError(f"unknown vuln_class {vuln_class}", f"classes: {CLASS_NAMES}")
        if state not in COVERAGE_STATES:
            self._audit("coverage_update", {}, False, started)
            raise MissionError(f"invalid state {state}", f"states: {COVERAGE_STATES}")
        url = endpoint.get("url", "")
        method = (endpoint.get("method") or "").upper()
        path = endpoint.get("path", "")
        if url and not (method and path):
            sp = urlsplit(url)
            method = method or "GET"
            path = sp.path or "/"
        if not (method and path):
            self._audit("coverage_update", {}, False, started)
            raise MissionError("endpoint needs url, or method + path",
                               "e.g. {\"url\": \"https://api.example.com/v2/orders/1042\"} or "
                               "{\"method\": \"POST\", \"path\": \"/v2/orders\"}.")
        key = f"{method} {path}"
        cov = self.store.coverage()
        if not any(e["key"] == key for e in cov["endpoints"]):
            cov["endpoints"].append({"key": key, "url": url or f"https://{endpoint.get('host', '')}{path}",
                                     "method": method, "path": path,
                                     "auth": endpoint.get("auth", ""), "roles": endpoint.get("roles", []),
                                     "value_flow": endpoint.get("value_flow", ""), "added_at": _now()})
        cell = {"state": state, "evidence": evidence[:200], "note": note[:200], "updated_at": _now()}
        cov["matrix"].setdefault(key, {})[vuln_class] = cell
        self.store.save_coverage(cov)
        if state == "vulnerable":
            self.store.append("notifications", {
                "level": "warn", "requires_ack": False,
                "subject": f"Coverage: {key} marked vulnerable ({vuln_class})",
                "body": evidence[:250] or "run validate_finding before raising"})
        self._audit("coverage_update", {"key": key, "class": vuln_class, "state": state}, True, started)
        return {"ok": True, "data": {"endpoint_key": key, "cell": {vuln_class: cell},
                "summary": self._coverage_summary()["per_class"][vuln_class]}}

    def coverage_gaps(self, limit: int = 10, auto_seed: bool = False, tier: int = 2) -> dict:
        started = time.time()
        doc = self._active()
        cov = self.store.coverage()
        if not cov["endpoints"]:
            self._audit("coverage_gaps", {}, False, started)
            raise MissionError("coverage matrix empty",
                               "Register endpoints via coverage_update (recon) or event_emit new_surface first.")
        gaps = self.coverage.gaps(limit)
        seeded = []
        if auto_seed:
            for g in gaps:
                t = self.store.add_task({
                    "type": "test_hypothesis",
                    "title": f"Test {g['vuln_class']} on {g['endpoint']} (coverage gap)",
                    "priority": 2, "tier": tier,
                    "params": {"endpoint": g["endpoint"], "vuln_class": g["vuln_class"],
                               "authenticated": bool(g["auth"])},
                    "hypothesis": f"{g['vuln_class']} on {g['endpoint']} — precedent check via rag_playbook (P-1/T-1)",
                    "source": "planner:coverage_gaps"})
                seeded.append(t["id"])
            self._recompute()
        self._audit("coverage_gaps", {"auto_seed": auto_seed}, True, started)
        return {"ok": True, "data": {"gaps": gaps, "seeded_tasks": seeded,
                "summary": self._coverage_summary()["per_class"]}}

    # =================================================================
    # 10-11. target memory
    # =================================================================

    def memory_save(self, kind: str, text: str, tags: list[str] | None = None,
                    refs: list[str] | None = None, endpoint: str = "") -> dict:
        started = time.time()
        self._active()
        if kind not in MEMORY_KINDS:
            self._audit("memory_save", {}, False, started)
            raise MissionError(f"invalid kind {kind}",
                               "kinds: quirk (target behaves oddly), intel (structure/stack), "
                               "failure (approach that did NOT work), decision (a call worth keeping), preference")
        item = self.memory.save(kind, text, tags=tags, refs=refs, endpoint=endpoint)
        self._audit("memory_save", {"kind": kind}, True, started)
        return {"ok": True, "data": {"memory": item}}

    def memory_search(self, query: str = "", kind: str = "", tag: str = "", limit: int = 10) -> dict:
        started = time.time()
        self._active()
        matches, total = self.memory.search(query=query, kind=kind, tag=tag, limit=limit)
        self._audit("memory_search", {"query": query[:80]}, True, started)
        return {"ok": True, "data": {"matches": matches,
                "total_memories": total}}

    # =================================================================
    # 12. event triggers
    # =================================================================

    def event_emit(self, type: str, payload: dict | None = None, source: str = "agent",
                   spawn_task: dict | None = None) -> dict:
        started = time.time()
        doc = self._active()
        p = payload or {}
        spawned: list[str] = []

        def _spawn(**spec) -> str:
            t = self.store.add_task({**spec, "source": f"trigger:{type}"})
            spawned.append(t["id"])
            return t["id"]

        effects = self.triggers.react(type, p, doc, _spawn)
        if spawn_task:
            if not spawn_task.get("title"):
                self._audit("event_emit", {"type": type}, False, started)
                raise MissionError("spawn_task needs a title", "")
            _spawn(**{**spawn_task, "tier": int(spawn_task.get("tier", 0))})
        self._recompute()
        rec = self.store.append("events", {"type": type, "payload": p, "source": source,
                                           "tasks_spawned": spawned, "effects": effects})
        self._audit("event_emit", {"type": type}, True, started)
        return {"ok": True, "data": {"event": rec, "tasks_spawned": spawned, "effects": effects,
                "mission_status_now": self.store.mission()["status"]}}

    # =================================================================
    # 13-14. validator + duplicates
    # =================================================================

    def validate_finding(self, finding: dict, spawn_validation_tasks: bool = True,
                         dedup_only: bool = False) -> dict:
        started = time.time()
        self._active()
        if dedup_only:
            # folded check_duplicates: the local duplicate verdict only, nothing written
            if not finding.get("url"):
                self._audit("validate_finding", {}, False, started)
                raise MissionError("finding.url is required", "")
            cls = validator.normalize_class(finding.get("vuln_class", ""))
            dup = validator.check_local_duplicates(
                {"url": finding["url"], "vuln_class": cls, "param": finding.get("param", "")},
                self.store.findings())
            self._audit("validate_finding", {"dedup_only": True, "url": finding["url"][:80]}, True, started)
            return {"ok": True, "data": {"dedup_only": True, "verdict": dup["verdict"],
                    "local_matches": dup["matches"], "local_hint": dup["hint"],
                    "next": ("merge with the existing finding (local_duplicate)" if dup["verdict"] == "local_duplicate"
                             else "unique locally — validate_finding when evidence is in hand")}}
        for req in ("title", "url", "vuln_class"):
            if not finding.get(req):
                self._audit("validate_finding", {}, False, started)
                raise MissionError(f"finding.{req} is required", "")
        cls = validator.normalize_class(finding["vuln_class"])
        if cls not in CLASS_NAMES:
            self._audit("validate_finding", {}, False, started)
            raise MissionError(f"unknown vuln_class {cls}", f"classes: {CLASS_NAMES}")
        declared = list(finding.get("evidence_keys", []))
        scoring = validator.score_evidence(declared)
        outstanding = validator.outstanding_kill_tests(cls, declared)
        dup = validator.check_local_duplicates(
            {"url": finding["url"], "vuln_class": cls, "param": finding.get("param", "")},
            self.store.findings())
        scanner = self._scanner_issues(finding["url"].split("?")[0])
        if dup["verdict"] == "local_duplicate":
            status, verdict = "duplicate", "duplicate of an existing finding — do not raise twice"
        elif scoring["triage"] == "validated":
            status, verdict = "validated", "evidence raise-ready — proceed to raise_issue (provenance agent-validated)"
        elif scoring["triage"] == "needs_more_validation":
            status, verdict = "candidate", "complete the outstanding kill tests, then re-run validate_finding"
        else:
            status, verdict = "watchlist", "below the raise bar — keep on watchlist, do not raise"
        f = self.store.add_finding({
            "title": finding["title"], "url": finding["url"], "vuln_class": cls,
            "param": finding.get("param", ""), "severity": finding.get("severity", ""),
            "confidence": finding.get("confidence", ""), "status": status,
            "evidence_keys": declared,
            "evidence_refs": finding.get("evidence_refs", []),
            "notes": finding.get("notes", "")[:500],
            "validation": {"score": scoring["score"], "triage": scoring["triage"],
                           "breakdown": scoring["breakdown"],
                           "outstanding_kill_tests": outstanding},
            "dup_check": dup, "scanner_crosscheck": {"reachable": scanner["reachable"],
                                                     "issues": scanner["issues"][:5]},
        })
        spawned = []
        if spawn_validation_tasks and status == "candidate" and outstanding:
            t = self.store.add_task({
                "type": "validate_step", "priority": 1, "tier": 2,
                "title": f"Kill tests for {f['id']} ({cls}): {len(outstanding)} outstanding",
                "params": {"finding_id": f["id"], "kill_tests": outstanding},
                "hypothesis": f["title"], "source": f"validator:{f['id']}"})
            spawned.append(t["id"])
        self._recompute()
        self._audit("validate_finding", {"finding": finding["title"][:60]}, True, started)
        return {"ok": True, "data": {"finding_id": f["id"], "score": scoring["score"],
                "triage": scoring["triage"], "meaning": scoring["meaning"],
                "breakdown": scoring["breakdown"], "unknown_keys": scoring["unknown_keys"],
                "outstanding_kill_tests": outstanding, "dup_check": dup,
                "scanner_crosscheck": scanner, "status": status, "verdict": verdict,
                "validation_task": spawned[0] if spawned else None}}

    # =================================================================
    # 15-17. budget, approvals, operator channel
    # =================================================================

    def budget_status(self, note_requests: int = 0, note_fuzz: int = 0) -> dict:
        started = time.time()
        self._active()
        if note_requests or note_fuzz:
            self.store.bump("requests_sent", max(0, int(note_requests)))
            self.store.bump("fuzz_requests", max(0, int(note_fuzz)))
        health = self._bridge_health()
        bc = health.get("counters") if health else None
        verdict = self._reconcile_budget(health)
        self._audit("budget_status", {"note_requests": note_requests}, True, started)
        return {"ok": True, "data": {**verdict,
                "bridge_sync": {"reachable": bool(health),
                                "note": ("bridge /health exposes 'counters' — authoritative values synced"
                                         if bc else "bridge exposes no counters yet — agent-reported numbers "
                                         "(note_requests/note_fuzz, fuzz results total_sent)")}}}

    def request_approval(self, title: str, action: str, params: dict | None = None,
                         risk_tier: int = 3, context: str = "", block_task_id: str = "") -> dict:
        started = time.time()
        self._active()
        apr = self.store.add_approval({
            "title": title[:200], "action": action[:100], "risk_tier": int(risk_tier),
            "params": params or {}, "context": context[:300], "block_task_id": block_task_id or None})
        if block_task_id:
            try:
                self.store.update_task(block_task_id, status="pending_approval",
                                       params={**self.store.get_task(block_task_id).get("params", {}),
                                               "approval_id": apr["id"]})
            except MissionStoreError:
                pass
        self.store.append("notifications", {
            "level": "critical", "requires_ack": True,
            "subject": f"Approval needed: {apr['id']} ({action})",
            "body": f"{title[:200]} — approve/deny via mission_control action=approve|deny "
                    f"approval_id={apr['id']} with operator_reference."})
        self._audit("request_approval", {"action": action}, True, started)
        return {"ok": True, "data": {"approval": apr,
                "rule": "The agent MUST NOT execute the gated action until mission_status shows this "
                        "approval approved — waiting is correct behavior, not an error."}}

    def notify_operator(self, level: str, subject: str, body: str,
                        requires_ack: bool = False) -> dict:
        """Public (folded out of the registered tools — mission_control action="notify"
        is the registered surface); kept for API parity with the proven engine."""
        started = time.time()
        self._active()
        if level not in ("info", "warn", "critical"):
            self._audit("notify_operator", {}, False, started)
            raise MissionError(f"invalid level {level}", "levels: info | warn | critical")
        rec = self.store.append("notifications", {"level": level, "requires_ack": bool(requires_ack),
                                                  "subject": subject[:200], "body": body[:1000]})
        self._audit("notify_operator", {"level": level}, True, started)
        return {"ok": True, "data": {"notification": rec,
                "channel": "notifications.jsonl in the engagement dir + mission_status tail "
                           "(wire an email/webhook forward here if the operator wants push)"}}


# Package-facing alias (aobh.orchestrator.Orchestrator).
Orchestrator = MissionCore
