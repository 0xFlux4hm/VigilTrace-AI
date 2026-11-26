#!/usr/bin/env python3
"""store.py — Mission Control persistence (aobh.orchestrator.store): the engagement's operational state.

Files (all inside the engagement dir, shared with ATAP/WAF/CAPTCHA state):

    mission.json        mission document: target, status, phase, budgets, counters,
                        pause reasons, checkpoints, end summary
    tasks.json          task queue (list) — the orchestrated work plan
    coverage.json       coverage matrix: endpoints x vulnerability classes
    memory.json         target memory: quirks, intel, failed approaches, decisions
    findings.json       finding registry with validation verdicts + dup checks
    approvals.json      human approval requests (Tier-3 / risky action gates)
    events.jsonl        append-only event log (trigger inputs + what they spawned)
    notifications.jsonl append-only operator inbox
    run_log.jsonl       append-only tool-call audit trail (every mission_* call)

All writes are atomic (tmp + os.replace). JSONL files are append-only audit trails;
JSON docs are read-modify-write under the store's single lock. The store is the
ONLY component that touches these files — handlers go through it, so the state on
disk is always the truth a fresh session resumes from (SKILL.md §13).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path


class MissionStoreError(Exception):
    pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"


JSON_DOCS = ("mission", "tasks", "coverage", "memory", "findings", "approvals")
JSONL_APPEND = ("events", "notifications", "run_log")

DEFAULT_MISSION = {
    "version": 1,
    "mission_id": "",
    "target": "",
    "authorization_reference": "",
    "program_url": "",
    "status": "active",           # active | paused | ended | aborted
    "phase": "0-bootstrap",       # 0-bootstrap .. 5-report (skill §1)
    "created_at": "",
    "updated_at": "",
    "budgets": {
        "max_requests": 600,       # target requests (skill §1.1)
        "max_fuzz_requests": 200,  # fuzz payloads per run_simple_fuzz envelope
        "max_session_minutes": 240,
        "max_tool_calls": 2000,
    },
    "counters": {
        "requests_sent": 0,        # agent-reported + bridge /health sync when available
        "fuzz_requests": 0,
        "tool_calls": 0,
        "session_started_at": "",
        "last_activity": "",
    },
    "pause_reasons": [],           # [{id, type, detail, hard, raised_at}]
    "checkpoints": [],             # [{id, phase, note, at}]
    "end_summary": None,
}


class MissionStore:
    def __init__(self, engagement_dir: str | Path):
        self.dir = Path(engagement_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, dict | list] = {}

    # ---------- paths / io ----------
    def _path(self, name: str) -> Path:
        return self.dir / f"{name}.json" if name in JSON_DOCS else self.dir / f"{name}.jsonl"

    def _read(self, name: str):
        p = self._path(name)
        if name in self._cache:
            return self._cache[name]
        if not p.exists():
            return {"tasks": [], "memory": [], "findings": [], "approvals": [],
                    "coverage": None, "mission": None}.get(name, [] if name in JSONL_APPEND else {})
        with p.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        self._cache[name] = data
        return data

    def _write(self, name: str, data) -> None:
        p = self._path(name)
        tmp = p.with_suffix(p.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, p)
        self._cache[name] = data

    # ---------- mission doc ----------
    def init_mission(self, target: str, authorization_reference: str,
                     program_url: str = "", phase: str = "0-bootstrap",
                     budgets: dict | None = None, mission_id: str = "") -> dict:
        doc = json.loads(json.dumps(DEFAULT_MISSION))  # deep copy
        doc.update({
            "mission_id": mission_id or f"M-{time.strftime('%Y%m%d')}-{os.urandom(2).hex().upper()}",
            "target": target, "authorization_reference": authorization_reference,
            "program_url": program_url, "phase": phase,
            "created_at": _now(), "updated_at": _now(),
            "counters": {**DEFAULT_MISSION["counters"], "session_started_at": _now()},
        })
        for k, v in (budgets or {}).items():
            if k in doc["budgets"] and isinstance(v, (int, float)) and v > 0:
                doc["budgets"][k] = v
        self._write("mission", doc)
        return doc

    def mission(self) -> dict | None:
        return self._read("mission")

    def update_mission(self, **fields) -> dict:
        doc = self.mission()
        if doc is None:
            raise MissionStoreError("no mission initialized — call mission_init first")
        for k, v in fields.items():
            if k in ("pause_reasons", "counters", "budgets", "checkpoints") and v is None:
                continue
            doc[k] = v
        doc["updated_at"] = _now()
        self._write("mission", doc)
        return doc

    def bump(self, counter: str, n: int = 1) -> dict:
        doc = self.mission()
        if doc is None:
            raise MissionStoreError("no mission initialized — call mission_init first")
        doc["counters"][counter] = int(doc["counters"].get(counter, 0)) + n
        doc["counters"]["last_activity"] = _now()
        doc["updated_at"] = _now()
        self._write("mission", doc)
        return doc

    # ---------- generic id allocation ----------
    @staticmethod
    def _next_id(items: list[dict], prefix: str) -> str:
        n = len(items) + 1
        return f"{prefix}-{n:03d}"

    # ---------- tasks ----------
    def tasks(self) -> list[dict]:
        return self._read("tasks")

    def add_task(self, task: dict) -> dict:
        items = self.tasks()
        task = {
            "id": self._next_id(items, "T"), "type": task.get("type", "generic"),
            "title": task["title"], "priority": int(task.get("priority", 2)),
            "status": task.get("status", "queued"),   # queued -> (auto) ready -> running -> done/failed
            "params": task.get("params", {}), "deps": list(task.get("deps", [])),
            "tier": int(task.get("tier", 0)), "hypothesis": task.get("hypothesis", ""),
            "source": task.get("source", "agent"), "result": task.get("result", {}),
            "evidence_refs": list(task.get("evidence_refs", [])),
            "attempts": int(task.get("attempts", 0)), "max_attempts": int(task.get("max_attempts", 3)),
            "error": task.get("error"), "created_at": _now(), "updated_at": _now(),
        }
        items.append(task)
        self._write("tasks", items)
        return task

    def update_task(self, task_id: str, **fields) -> dict:
        items = self.tasks()
        for t in items:
            if t["id"] == task_id:
                t.update({k: v for k, v in fields.items() if v is not None})
                t["updated_at"] = _now()
                self._write("tasks", items)
                return t
        raise MissionStoreError(f"unknown task id {task_id}")

    def get_task(self, task_id: str) -> dict:
        for t in self.tasks():
            if t["id"] == task_id:
                return t
        raise MissionStoreError(f"unknown task id {task_id}")

    # ---------- coverage ----------
    def coverage(self) -> dict:
        cov = self._read("coverage")
        if cov is None:
            cov = {"classes": [], "endpoints": [], "matrix": {}}
        return cov

    def save_coverage(self, cov: dict) -> None:
        self._write("coverage", cov)

    # ---------- memory ----------
    def memory(self) -> list[dict]:
        return self._read("memory")

    def add_memory(self, item: dict) -> dict:
        items = self.memory()
        item = {"id": self._next_id(items, "M"), "kind": item.get("kind", "intel"),
                "text": item["text"], "tags": list(item.get("tags", [])),
                "refs": list(item.get("refs", [])), "endpoint": item.get("endpoint", ""),
                "created_at": _now()}
        items.append(item)
        self._write("memory", items)
        return item

    # ---------- findings ----------
    def findings(self) -> list[dict]:
        return self._read("findings")

    def add_finding(self, finding: dict) -> dict:
        items = self.findings()
        finding = {**finding, "id": self._next_id(items, "F"), "created_at": _now(),
                   "updated_at": _now()}
        items.append(finding)
        self._write("findings", items)
        return finding

    def update_finding(self, finding_id: str, **fields) -> dict:
        items = self.findings()
        for f in items:
            if f["id"] == finding_id:
                f.update(fields)
                f["updated_at"] = _now()
                self._write("findings", items)
                return f
        raise MissionStoreError(f"unknown finding id {finding_id}")

    # ---------- approvals ----------
    def approvals(self) -> list[dict]:
        return self._read("approvals")

    def add_approval(self, approval: dict) -> dict:
        items = self.approvals()
        approval = {"id": self._next_id(items, "APR"), **approval,
                    "status": approval.get("status", "pending"), "requested_at": _now(),
                    "decided_at": None, "decided_by": None, "note": ""}
        items.append(approval)
        self._write("approvals", items)
        return approval

    def update_approval(self, approval_id: str, **fields) -> dict:
        items = self.approvals()
        for a in items:
            if a["id"] == approval_id:
                a.update(fields)
                self._write("approvals", items)
                return a
        raise MissionStoreError(f"unknown approval id {approval_id}")

    # ---------- append-only logs ----------
    def append(self, name: str, record: dict) -> dict:
        rec = {"id": None, "created_at": _now(), **record}
        if name == "events":
            rec["id"] = self._next_id(self.read_jsonl("events"), "E")
        elif name == "notifications":
            rec["id"] = self._next_id(self.read_jsonl("notifications"), "N")
        p = self._path(name)
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec

    def read_jsonl(self, name: str) -> list[dict]:
        p = self._path(name)
        if not p.exists():
            return []
        out = []
        with p.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out
