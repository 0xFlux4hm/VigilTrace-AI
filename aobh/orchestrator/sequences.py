"""sequences.py — Layer 11: the S0–S5 mission sequence gate + the closure gate.

``sequence_next`` is the state machine the orchestrator consults before every
step: it returns the mission's current phase, the next legal step, and the
gates (recon debt = 0 before progress claims, budget exhausted → validation
only, paused missions yield nothing). ``closure_check`` is the 7-condition
gate that makes ``no_findings_complete`` an earned conclusion, including the
skim-detection arithmetic. Both are pure readers of the MissionStore files —
they never mutate state.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable

PHASES = ("0-bootstrap", "1-recon", "2-triage", "3-testing", "4-validation", "5-report")

NEXT_STEP = {
    "0-bootstrap": "mission_init with target + authorization_reference (scope is law)",
    "1-recon": "map surface (proxy history first — get_proxy_history), register endpoints in coverage",
    "2-triage": "triage every registered endpoint (live/auth/params) — debt must reach 0",
    "3-testing": "work coverage_gaps top-down; tamper loop for identity/authz classes (skills/param_tampering.md)",
    "4-validation": "validate_finding every candidate; kill-test anything below score 90",
    "5-report": "raise_issue validated findings only; mission_control(action='end')",
}

SKIM_MIN_TOOL_CALLS_PER_CELL = 0.4
SKIM_MIN_PROBES_PER_PARAM = 6


def register_sequence_handlers(engagement_dir: str | None) -> dict[str, Callable]:
    """sequence_next + closure_check handlers (mission_control group members)."""
    dir_ = _config_dir(engagement_dir)

    def sequence_next(args: dict) -> dict:
        return sequence_next_core(dir_)

    def closure_check(args: dict) -> dict:
        return closure_check_core(dir_, asset=args.get("asset", ""),
                                  strict=bool(args.get("strict", False)))

    return {"sequence_next": sequence_next, "closure_check": closure_check}


def _load(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _config_dir(engagement_dir: str | None) -> Path:
    if engagement_dir:
        return Path(engagement_dir)
    from aobh.core.config import get_config
    return Path(str(get_config().engagement_dir))


def sequence_next_core(engagement_dir: Path) -> dict:
    mission = _load(engagement_dir / "mission.json", {}) or {}
    tasks = _load(engagement_dir / "tasks.json", {"tasks": []}) or {"tasks": []}
    cov = _load(engagement_dir / "coverage.json", None)
    task_list = tasks.get("tasks", []) if isinstance(tasks, dict) else (tasks or [])
    blockers: list[str] = []
    gates: dict[str, bool] = {}

    status = mission.get("status", "not_initialized")
    if status in ("not_initialized", ""):
        return {"ok": True, "data": {"phase": "0-bootstrap", "status": status,
                                     "next_step": NEXT_STEP["0-bootstrap"],
                                     "gates": {}, "blockers": ["mission not initialized"]}}
    if status in ("paused", "hard_paused", "ended", "aborted"):
        blockers.append(f"mission status={status} — paused/ended missions yield no work")

    # budget gate: exhausted testing budgets block testing, never validation/report
    counters = mission.get("counters", {})
    budgets = mission.get("budgets", {})
    req_sent = counters.get("requests_sent", 0)
    max_req = budgets.get("max_requests", 0)
    budget_exhausted = bool(max_req and req_sent >= max_req)

    phase = mission.get("phase", "0-bootstrap")
    if phase not in PHASES:
        phase = "0-bootstrap"
    idx = PHASES.index(phase)

    pending = [t for t in task_list if isinstance(t, dict) and t.get("status") not in ("done", "skipped", "failed", "cancelled")]
    triage_pending = [t for t in pending if "triage" in str(t.get("kind", "")) or "triage" in str(t.get("title", "")).lower()]

    gates = {
        "mission_active": not blockers,
        "recon_debt_zero": not triage_pending,
        "budget_remaining": not budget_exhausted,
        "coverage_registered": bool(cov and (cov.get("endpoints") or [])),
    }

    # phase progression advice (advisory — the operator lifts hard pauses only)
    if idx <= 1 and not gates["coverage_registered"]:
        advisory = NEXT_STEP["1-recon"]
    elif triage_pending:
        advisory = f"clear {len(triage_pending)} triage-debt task(s) before progress claims (Layer 10)"
    elif budget_exhausted and idx < 4:
        advisory = "budget exhausted — testing tasks blocked; move to validation/report or ask the operator for a budget change (mission_control action=budget)"
    elif pending:
        advisory = f"work the queue: {len(pending)} open task(s), next: {pending[0].get('title', pending[0].get('id', '?'))}"
    elif idx < 3 and gates["coverage_registered"]:
        gaps_cells = _untested_cells(cov)
        advisory = NEXT_STEP["3-testing"] + (f" — {gaps_cells} untested coverage cells" if gaps_cells else "")
    else:
        advisory = NEXT_STEP[phase]

    return {"ok": True, "data": {"phase": phase, "status": status, "gates": gates,
                                 "blockers": blockers, "open_tasks": len(pending),
                                 "triage_debt": len(triage_pending),
                                 "budget_exhausted": budget_exhausted,
                                 "next_step": advisory}}


def _untested_cells(cov: dict) -> int:
    n = 0
    matrix = cov.get("matrix", {})
    for _key, classes in matrix.items():
        for _cls, cell in (classes or {}).items():
            if (cell or {}).get("state") in (None, "untested"):
                n += 1
    return n


def closure_check_core(engagement_dir: Path, asset: str = "", strict: bool = False) -> dict:
    """The 7-condition closure gate. strict=True promotes warnings to failures."""
    mission = _load(engagement_dir / "mission.json", {}) or {}
    cov = _load(engagement_dir / "coverage.json", None) or {}
    tamper = _load(engagement_dir / "tamper.json", None)
    oob = _load(engagement_dir / "oob.json", None)
    findings = _load(engagement_dir / "findings.json", []) or []
    if isinstance(findings, dict):
        findings = findings.get("findings", [])
    conditions: list[dict] = []

    def cond(name: str, passed: bool, detail: str, warning: bool = False) -> None:
        conditions.append({"condition": name, "passed": passed or (warning and not strict),
                           "detail": detail, "warning": warning})

    # 1 — coverage: every class per endpoint is tested or n_a
    matrix = cov.get("matrix", {})
    if asset:
        matrix = {k: v for k, v in matrix.items() if asset in k}
    untested = {k: [c for c, cell in (cl or {}).items()
                    if (cell or {}).get("state") in (None, "untested")]
                for k, cl in matrix.items()}
    untested = {k: v for k, v in untested.items() if v}
    if matrix:
        cond("coverage_complete", not untested,
             f"{len(matrix)} endpoint(s) checked" + (f"; untested classes remain on {list(untested)[:3]}" if untested else ""),
             warning=True)  # coverage grows during the mission; closure is per-asset
    else:
        cond("coverage_registered", False, "no coverage matrix — register endpoints first")

    # 2 — tamper ladder completion for identity/authz classes
    if tamper and tamper.get("probes"):
        probes = [p for p in tamper["probes"] if not asset or asset in str(p)]
        exhausted = any(p.get("signal") in ("data_cross", "state_change") for p in probes) or len(probes) >= 8
        cond("tamper_ladder_complete", exhausted,
             f"{len(probes)} tamper probe(s) recorded" + ("" if exhausted else " — ladder incomplete"))
    else:
        has_access_class = any("access" in c.lower() or "idor" in c.lower() or "authz" in c.lower()
                               for cl in matrix.values() for c in (cl or {}))
        cond("tamper_ladder_complete", not has_access_class,
             "no tamper record" + (" but access-control classes are on the matrix — run param_tamper_run"
                                   if has_access_class else " and no access-control classes on the matrix"),
             warning=not has_access_class)

    # 3 — OOB registrations all observed or expired
    if oob and oob.get("registrations"):
        now = time.time()
        unobserved = []
        for r in oob["registrations"]:
            polls = r.get("polls") or []
            try:
                exp = time.mktime(time.strptime(r.get("expires_at", "1970-01-01T00:00:00Z"),
                                                "%Y-%m-%dT%H:%M:%SZ"))
            except (ValueError, TypeError):
                exp = 0
            if not polls and exp > now:
                unobserved.append(r.get("payload_id", "?"))
        cond("oob_final_poll", not unobserved,
             f"{len(oob['registrations'])} registration(s)" +
             (f"; unpolled live: {unobserved[:3]} — run oob_poll before closure" if unobserved else " — all observed/expired"))
    else:
        cond("oob_final_poll", True, "no OOB registrations (nothing outstanding)", warning=True)

    # 4 — auth contexts (≥2): encrypted vault → count check is advisory
    accounts = _load(engagement_dir / "accounts.json", None)
    if accounts is not None:
        cond("auth_contexts", True,
             "ATAP vault present — verify ≥2 active contexts via atap_list_accounts", warning=True)
    else:
        cond("auth_contexts", False,
             "no test accounts provisioned — differential (≥2 auth contexts) unproven", warning=True)

    # 5+6 — findings carry evidence + validator verdicts for high+
    bad_evidence = [f.get("id", "?") for f in findings
                    if not (f.get("evidence") or f.get("refs") or f.get("proxy_id") or f.get("burp_ref"))]
    unsigned = [f.get("id", "?") for f in findings
                if str(f.get("severity", "")).lower() in ("high", "critical")
                and f.get("validation") not in ("validated", "confirmed")]
    cond("evidence_refs", not bad_evidence,
         f"{len(findings)} finding(s)" + (f"; missing evidence: {bad_evidence[:3]}" if bad_evidence else ""))
    cond("validator_signoff", not unsigned,
         f"high+/critical findings without a validated verdict: {unsigned[:3]}" if unsigned
         else "all high+ findings validated (validator sign-off)")

    # 7 — skim detection: honest depth arithmetic (auto-reopen = hard blocker)
    counters = mission.get("counters", {})
    tool_calls = counters.get("tool_calls", 0)
    cells = sum(max(len(cl or {}), 1) for cl in matrix.values()) or 1
    cond("skim_depth", tool_calls >= SKIM_MIN_TOOL_CALLS_PER_CELL * cells,
         f"{tool_calls} tool calls / {cells} coverage cells (min {SKIM_MIN_TOOL_CALLS_PER_CELL}/cell)")
    if tamper and tamper.get("probes"):
        per_param: dict[str, int] = {}
        for p in tamper["probes"]:
            per_param[p.get("param", "?")] = per_param.get(p.get("param", "?"), 0) + 1
        shallow = [k for k, v in per_param.items() if v < SKIM_MIN_PROBES_PER_PARAM]
        cond("tamper_depth", not shallow,
             f"params under {SKIM_MIN_PROBES_PER_PARAM} probes: {shallow[:3]}" if shallow
             else "tamper probes meet depth floor")

    can_close = all(c["passed"] for c in conditions)
    return {"ok": True, "data": {"asset": asset or "(all endpoints)", "can_close": can_close,
                                 "conditions": conditions, "strict": strict,
                                 "verdict": "no_findings_complete" if can_close else "incomplete",
                                 "note": "a rejected closure is a decision, not an apology — list the missing probes and reopen"}}
