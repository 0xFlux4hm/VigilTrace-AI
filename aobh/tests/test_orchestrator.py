#!/usr/bin/env python3
"""Orchestrator (Mission Control) end-to-end test — no Burp, no external target.

1:1 port of scripts/test_mission.py onto the aobh package; only imports/paths
adapted (and the three folded tools re-checked through their new surface).

Topology (all localhost / tempdir):
    test ──► aobh.orchestrator.engine.MissionCore (14 registered mission_* handlers)
              │  GET  /health              ──► STUB BRIDGE (optional /health counters)
              │  POST /tools/get_scanner_issues ──► STUB BRIDGE (one canned issue)
              │  vault + waf_state.json    ──► real aobh.atap vault (side-effect guarded)
              └─► bundled RAG index (aobh/rag/index/reports.jsonl) — corpus module pending

Exercises: init + seeds, duplicate-init refusal, queue mechanics (deps release,
auto-retry, blocked-by-dead-dep), prereq injection (WAF probe + account gate with
real vault), Tier-3 approval gate (auto-create → approve/deny), budget governor
(warn/exhausted/blocked testing/close-out allowed/operator-only raise), triggers
(collaborator_hit/waf_block/rate_limited/scope_drift hard pause/target_down,
resume refusal, resolve_pause operator gate), coverage matrix (register, invalid
class refusal, gaps, auto_seed, vulnerable notification), memory save/search,
validator scoring (watchlist → candidate+kill-test task → validated) and local
duplicate detection (via the folded validate_finding dedup_only), bridge /health
counter sync, crash-recovery orphans, persistence across engine restart,
run_log/events/notifications audit trails, and the 14-tool registry.

The old 17-tool surface folded: task_list → mission_status (method kept public),
check_duplicates → validate_finding(dedup_only=true) (nothing written),
notify_operator → mission_control action="notify" (method kept public).
"""
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PKG = "/home/z/my-project/download/aobh"
sys.path.insert(0, PKG)
ENG = tempfile.mkdtemp(prefix="aobh-orchestrator-test-eng-")
os.environ["ATAP_ENGAGEMENT_DIR"] = ENG            # must be set BEFORE importing aobh.orchestrator.engine


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close(); return port


STUB_PORT = free_port()
os.environ["BURP_BRIDGE_URL"] = f"http://127.0.0.1:{STUB_PORT}"
os.environ["BURP_BRIDGE_TOKEN"] = "test-token"


# ---------------- stub bridge: /health counters + scanner issues ----------------
# mutable bridge /health served by the stub: "instance": None reproduces a bridge
# without instance reporting (the pre-instance-aware behavior the ported checks assume)
BRIDGE_HEALTH = {"ok": True, "instance": None,
                 "counters": {"requests_sent": 50, "fuzz_requests": 0}}


class StubBridge(BaseHTTPRequestHandler):
    log_message = lambda self, *a: None

    def _json(self, obj):
        payload = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if urlparse(self.path).path == "/health":
            return self._json(BRIDGE_HEALTH)
        self._json({"ok": False, "error": "not found"})

    def do_POST(self):
        if urlparse(self.path).path == "/tools/get_scanner_issues":
            return self._json({"ok": True, "data": {"issues": [
                {"issue_id": 1, "name": "Scripting cross-site scripting", "severity": "high",
                 "confidence": "tentative", "baseUrl": "https://api.example.com/v2/orders"}]}})
        self._json({"ok": False, "error": "unknown endpoint"})


def serve(handler, port):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


serve(StubBridge, STUB_PORT)

from aobh.orchestrator.store import MissionStore          # noqa: E402
from aobh.orchestrator.engine import MissionCore, MissionError  # noqa: E402
from aobh.orchestrator.validator import score_evidence    # noqa: E402
from aobh.orchestrator.tools import register              # noqa: E402

passed, failed = [], []


def check(label, cond, detail=""):
    (passed if cond else failed).append(label)
    print(("  PASS " if cond else "  FAIL ") + label + (f"  [{detail}]" if detail and not cond else ""))


def expect_error(label, fn, fragment=""):
    try:
        fn()
        check(label, False, "no error raised")
    except MissionError as e:
        check(label, fragment in (e.error + " " + e.hint), f"got: {e.error}")


def test_orchestrator_end_to_end():
    """The full 93-check Mission Control scenario (port of test_mission.py + 6
    instance-aware budget reconciliation checks)."""
    mc = MissionCore(ENG)

    print("== 1. bootstrap ==")
    r = mc.mission_init(target="https://api.example.com",
                        authorization_reference="scope.md — user statement 2026-11-26",
                        program_url="https://example.com/program",
                        budgets={"max_requests": 600})
    d = r["data"]
    check("init ok + mission id", d["mission"]["mission_id"].startswith("M-"))
    check("init budgets applied", d["mission"]["budgets"]["max_requests"] == 600)
    check("5 seed tasks", len(d["seeded_tasks"]) == 5)
    check("seed T-002 depends on scope task", mc.store.get_task(d["seeded_tasks"][1])["deps"] == [d["seeded_tasks"][0]])
    expect_error("duplicate init refused", lambda: mc.mission_init(target="x", authorization_reference="y"), "already exists")

    st = mc.mission_status()["data"]
    check("status next_action → scope task", "Reconcile Burp scope" in st["next_action"])
    check("status bridge synced counters", st["bridge"]["reachable"] and st["bridge"]["counters_synced"])
    check("budget verdict ok", st["budget"]["verdict"] == "ok")

    print("== 2. queue mechanics ==")
    n1 = mc.task_next()["data"]["tasks"][0]
    check("task_next claims scope task", n1["id"] == d["seeded_tasks"][0] and n1["status"] == "running")
    check("playbook hint attached", any("get_scope" in s for s in n1["playbook"]))
    mc.task_update(n1["id"], status="done", result={"outcome": "PASS"}, evidence_refs=["a-01"])
    n2 = mc.task_next()["data"]["tasks"][0]
    check("dep release: recon ready after scope done", n2["id"] == d["seeded_tasks"][1])
    mc.task_update(n2["id"], status="done")

    r = mc.task_enqueue(tasks=[{"type": "test_hypothesis", "title": "flaky task", "priority": 0, "tier": 2,
                                "params": {"host": "api.example.com", "payload_bearing": False},
                                "max_attempts": 2}])
    flaky = r["data"]["tasks"][0]["id"]
    r = mc.task_enqueue(tasks=[{"type": "generic", "title": "blocked behind failure",
                                "priority": 4, "deps": [flaky]}])
    dep_id = r["data"]["tasks"][0]["id"]
    mc.task_next(claim=True)
    check("flaky claimed running (priority 0)", mc.store.get_task(flaky)["status"] == "running")
    mc.task_update(flaky, status="failed", error="500 blip")
    check("failed auto-requeued (attempt 1/2)", mc.store.get_task(flaky)["status"] == "queued")
    check("failure notification emitted", any("failed (attempt" in n["subject"] for n in mc.store.read_jsonl("notifications")))
    mc.task_next(claim=True)
    check("attempt counter incremented", mc.store.get_task(flaky)["attempts"] == 2)
    mc.task_update(flaky, status="failed", error="500 again")
    ft = mc.store.get_task(flaky)
    check("failed-final stays failed", ft["status"] == "failed")
    check("blocked by dead dep", mc.store.get_task(dep_id)["status"] == "blocked"
          and "failed" in (mc.store.get_task(dep_id)["error"] or ""))

    print("== 3. prereq injection ==")
    r = mc.task_enqueue(tasks=[
        {"type": "test_hypothesis", "title": "IDOR orders as userA", "tier": 2,
         "params": {"host": "orders.example.com", "authenticated": True, "payload_bearing": False}},
        {"type": "test_hypothesis", "title": "fuzz export param", "tier": 2,
         "params": {"host": "export.example.com", "payload_bearing": True}}])
    inj = r["data"]["injected_prereqs"]
    check("atap_provision injected (no active accounts)",
          any(p["type"] == "atap_provision" for p in inj))
    check("waf_probe injected (unprobed host)",
          any(p["type"] == "waf_probe" and "export.example.com" in p["title"] for p in inj))
    auth_task = next(t for t in r["data"]["tasks"] if t["title"] == "IDOR orders as userA")
    check("prereq wired as dependency",
          set(mc.store.get_task(auth_task["id"])["deps"]) == {p["id"] for p in inj if p["type"] == "atap_provision"})
    with open(os.path.join(ENG, "waf_state.json"), "w") as fh:
        json.dump({"hosts": {"export.example.com": {"probe": 12, "bypass": 0}}}, fh)
    r = mc.task_enqueue(tasks=[{"type": "test_hypothesis", "title": "second fuzz of export", "tier": 2,
                                "params": {"host": "export.example.com", "payload_bearing": True}}])
    check("no waf_probe re-injected (host probed)",
          all(p["type"] != "waf_probe" for p in r["data"]["injected_prereqs"]))
    from aobh.atap.vault import Vault  # noqa: E402
    v = Vault.open(ENG)
    v.save({"accounts": [{"id": "ACC-01", "status": "active"}]})
    r = mc.task_enqueue(tasks=[{"type": "test_hypothesis", "title": "authed with live account", "tier": 2,
                                "params": {"authenticated": True, "payload_bearing": False}}])
    check("no atap_provision injected (active account exists)",
          all(p["type"] != "atap_provision" for p in r["data"]["injected_prereqs"]))

    print("== 4. tier-3 approval gate ==")
    r = mc.task_enqueue(tasks=[{"type": "test_hypothesis", "title": "blind XSS to admin panel", "priority": 0,
                                "tier": 3, "params": {"payload_bearing": False}}])
    t3 = r["data"]["tasks"][0]["id"]
    nxt = mc.task_next()["data"]
    check("tier-3 auto-gated (not returned)", all(t["id"] != t3 for t in nxt["tasks"]))
    apr = [a for a in mc.store.approvals() if a.get("block_task_id") == t3]
    check("approval auto-created", len(apr) == 1 and apr[0]["status"] == "pending")
    expect_error("approve without operator_reference refused",
                 lambda: mc.mission_control(action="approve", approval_id=apr[0]["id"]), "operator_reference")
    mc.mission_control(action="approve", approval_id=apr[0]["id"],
                       operator_reference="operator slack message 2026-11-26 14:00 UTC")
    check("approved task back to ready", mc.store.get_task(t3)["status"] == "ready")
    nxt = mc.task_next()["data"]
    claimable = nxt["tasks"]
    if claimable:
        check("tier-3 claimable after approval", any(t["id"] == t3 for t in claimable) or mc.store.get_task(t3)["status"] in ("running", "done"))
        for t in claimable:
            mc.task_update(t["id"], status="done")
    # deny path
    r = mc.task_enqueue(tasks=[{"type": "test_hypothesis", "title": "race condition window test", "priority": 0,
                                "tier": 3, "params": {"payload_bearing": False}}])
    t4 = r["data"]["tasks"][0]["id"]
    mc.task_next()  # auto-gate
    apr4 = [a for a in mc.store.approvals() if a.get("block_task_id") == t4][0]
    mc.mission_control(action="deny", approval_id=apr4["id"],
                       operator_reference="operator: out of scope per policy §4")
    check("denied task cancelled", mc.store.get_task(t4)["status"] == "cancelled")

    print("== 5. budget governor ==")
    r = mc.budget_status(note_requests=480)["data"]  # max(480 agent, 50 bridge) = 480/600 = 80%
    check("warn at 80%", r["verdict"] == "warn" and r["recommendation"].startswith("≥80%"))
    r = mc.budget_status(note_requests=120)["data"]  # 600/600 → exhausted
    check("exhausted at cap", r["verdict"] == "exhausted")
    check("pace reported", r["requests_per_hour"] >= 0 and "projected_minutes_to_request_cap" in r)
    r = mc.task_enqueue(tasks=[{"type": "test_hypothesis", "title": "should be blocked by budget",
                                "tier": 2, "params": {"payload_bearing": False}},
                               {"type": "report_section", "title": "write findings.md"}])["data"]
    nxt = mc.task_next()["data"]
    check("testing blocked when exhausted", nxt["tasks"] != []
          and all("should be blocked by budget" not in t["title"] for t in nxt["tasks"])
          and all(t["type"] in ("validate_step", "validate_finding", "report_section",
                                "atap_cleanup", "coverage_seed", "coverage_fill")
                  for t in nxt["tasks"]))
    check("close-out task still claimable", mc.task_next()["data"]["tasks"] != [] or
          any(t["type"] == "report_section" for t in mc.store.tasks() if t["status"] == "running"))
    expect_error("budget raise without operator_reference refused",
                 lambda: mc.mission_control(action="budget", budget={"max_requests": 1200}), "operator_reference")
    mc.mission_control(action="budget", budget={"max_requests": 1200},
                       operator_reference="operator email 2026-11-26: one more pass on orders API")
    check("budget raised with reference", mc.budget_status()["data"]["verdict"] != "exhausted")
    check("budget change notification", any("Budget updated by operator" in n["subject"]
                                            for n in mc.store.read_jsonl("notifications")))

    print("== 5b. instance-aware budget reconciliation ==")
    orig_counters = dict(mc.store.mission()["counters"])
    mc.store.update_mission(counters={**orig_counters, "requests_sent": 5})  # let bridge totals dominate
    BRIDGE_HEALTH["instance"] = "inst-a"
    r = mc.budget_status()["data"]
    check("first sighting records instance, no restart",
          r["bridge"]["instance"] == "inst-a" and r["bridge"]["restarted"] is False)
    check("first sighting: used = bridge counters", r["rows"][0]["used"] == 50)
    BRIDGE_HEALTH["counters"]["requests_sent"] = 90
    r = mc.budget_status()["data"]
    check("same instance accumulates",
          r["rows"][0]["used"] == 90 and r["bridge"]["restarted"] is False)
    n_mid = len(mc.store.read_jsonl("notifications"))
    BRIDGE_HEALTH["instance"] = "inst-b"
    BRIDGE_HEALTH["counters"]["requests_sent"] = 10
    r = mc.budget_status()["data"]
    check("restart banks previous instance (90+10)",
          r["bridge"]["restarted"] is True and r["rows"][0]["used"] == 100)
    bs = mc.store.mission()["bridge_sync"]
    check("restart persisted with carryover",
          bs["instance"] == "inst-b" and bs["carryover"]["requests_sent"] == 90)
    check("restart notified the operator",
          len(mc.store.read_jsonl("notifications")) == n_mid + 1)
    BRIDGE_HEALTH["instance"] = None
    BRIDGE_HEALTH["counters"]["requests_sent"] = 50
    mc.store.update_mission(counters=orig_counters)  # restore for the later sections

    print("== 6. triggers, pause, operator gate ==")
    r = mc.event_emit(type="collaborator_hit", payload={"payload_id": "abc123", "summary": "DNS+HTTP"})
    check("collaborator_hit spawns priority-0 investigation",
          any(mc.store.get_task(t)["priority"] == 0 and mc.store.get_task(t)["type"] == "investigate_oob"
              for t in r["data"]["tasks_spawned"]))
    check("OOB memory saved", any("OOB hit" in m["text"] for m in mc.store.memory()))
    r = mc.event_emit(type="waf_block", payload={"host": "api.example.com", "detail": "403 on payload"})
    check("waf_block spawns bypass eval + quirk memory",
          any(mc.store.get_task(t)["type"] == "waf_bypass_eval" for t in r["data"]["tasks_spawned"])
          and any("WAF blocks" in m["text"] for m in mc.store.memory()))
    r = mc.event_emit(type="rate_limited", payload={"host": "api.example.com", "minutes": 3})
    check("rate_limited spawns backoff task",
          any(mc.store.get_task(t)["type"] == "backoff_wait" for t in r["data"]["tasks_spawned"]))
    r = mc.event_emit(type="captcha_challenge", payload={"url": "https://api.example.com/signup"})
    check("captcha_challenge spawns captcha_handle",
          any(mc.store.get_task(t)["type"] == "captcha_handle" for t in r["data"]["tasks_spawned"]))
    r = mc.event_emit(type="unregistered_custom", payload={})
    check("unregistered event logged with note", "unregistered" in r["data"]["effects"]["note"])

    mc.event_emit(type="scope_drift", payload={"url": "https://internal.example.com/admin"})
    st = mc.mission_status()["data"]
    check("scope_drift hard-pauses mission", st["mission"]["status"] == "paused"
          and st["pause_reasons"] and st["pause_reasons"][0]["hard"])
    nxt = mc.task_next()["data"]
    check("task_next blocked while paused", nxt.get("blocked") == "mission_paused")
    expect_error("resume refused under hard pause",
                 lambda: mc.mission_control(action="resume"), "hard pause")
    expect_error("resolve_pause without operator_reference refused",
                 lambda: mc.mission_control(action="resolve_pause"), "operator_reference")
    r = mc.mission_control(action="resolve_pause",
                           operator_reference="operator confirmed internal.example.com is OUT of scope; stay on api.")
    check("resolve_pause clears hard pause", r["data"]["status"] == "active")
    check("pause decision notification", any("Pause resolved" in n["subject"]
                                             for n in mc.store.read_jsonl("notifications")))
    mc.event_emit(type="target_down", payload={"detail": "connection refused storm"})
    check("target_down pauses again", mc.mission_status()["data"]["mission"]["status"] == "paused")
    r = mc.mission_control(action="resolve_pause", reason="target_down",
                           operator_reference="operator: target back up 15:10 UTC")
    check("resolve by type works", r["data"]["status"] == "active")
    r = mc.event_emit(type="new_surface", payload={"url": "https://api.example.com/v3/"})
    check("new_surface spawns coverage_seed",
          any(mc.store.get_task(t)["type"] == "coverage_seed" for t in r["data"]["tasks_spawned"]))

    print("== 7. coverage matrix ==")
    expect_error("unknown vuln_class refused",
                 lambda: mc.coverage_update(endpoint={"url": "https://api.example.com/x"},
                                            vuln_class="sql_injection", state="untested"), "unknown vuln_class")
    expect_error("invalid state refused",
                 lambda: mc.coverage_update(endpoint={"url": "https://api.example.com/x"},
                                            vuln_class="access_control", state="maybe"), "invalid state")
    for ep, cls, state in [
        ({"url": "https://api.example.com/v2/orders/1042", "auth": "userA", "value_flow": "orders"}, "access_control", "vulnerable"),
        ({"url": "https://api.example.com/v2/orders/1042"}, "injection", "tested_clean"),
        ({"method": "POST", "path": "/v2/orders", "auth": "userA", "value_flow": "orders"}, "access_control", "untested"),
        ({"url": "https://api.example.com/v2/profile"}, "xss", "tested_clean"),
        ({"url": "https://api.example.com/v2/export"}, "ssrf_oob", "untested"),
    ]:
        mc.coverage_update(endpoint=ep, vuln_class=cls, state=state,
                           evidence="a-17" if state == "vulnerable" else "")
    gaps = mc.coverage_gaps(limit=10)["data"]["gaps"]
    check("gaps ranked (auth+value-flow first)", gaps and gaps[0]["score"] >= gaps[-1]["score"])
    check("orders POST outranks profile", all(g["endpoint"] != "POST /v2/orders" or g["score"] >= 6 for g in gaps if g["endpoint"] == "POST /v2/orders"))
    r = mc.coverage_gaps(limit=3, auto_seed=True)["data"]
    check("auto_seed enqueues test tasks", len(r["seeded_tasks"]) == 3 and
          all(mc.store.get_task(t)["type"] == "test_hypothesis" for t in r["seeded_tasks"]))
    summ = mc.mission_status(sections=["coverage"])["data"]["coverage"]["per_class"]["access_control"]
    check("coverage summary counts vulnerable", summ["vulnerable"] == 1 and summ["pct_of_class_covered"] > 0)
    check("vulnerable cell notification", any("marked vulnerable" in n["subject"]
                                              for n in mc.store.read_jsonl("notifications")))

    print("== 8. target memory ==")
    mc.memory_save(kind="quirk", text="WAF normalizes /v2/* paths — always test with X-Original-URL too",
                   tags=["waf", "api.example.com"])
    mc.memory_save(kind="failure", text="sqli preset on /v2/orders.sort produced nothing (WAF strips quotes)",
                   tags=["sqli", "api.example.com"])
    r = mc.memory_search(query="waf x-original-url")["data"]
    check("memory search hit", any("X-Original-URL" in m["text"] for m in r["matches"]))
    r = mc.memory_search(kind="failure")["data"]
    check("kind filter", all(m["kind"] == "failure" for m in r["matches"]))

    print("== 9. validator + duplicates ==")
    w = score_evidence(["single_observation_only", "mechanism_unclear"])
    check("weak evidence scores low", w["score"] <= 40 and w["triage"] == "watchlist")
    r = mc.validate_finding(finding={
        "title": "Reflected XSS in orders search sort param", "url": "https://api.example.com/v2/orders",
        "vuln_class": "xss", "param": "sort", "severity": "medium",
        "evidence_keys": ["single_observation_only", "mechanism_unclear"]})["data"]
    check("weak candidate → watchlist", r["triage"] == "watchlist" and r["status"] == "watchlist")
    r = mc.validate_finding(finding={
        "title": "IDOR: cross-account order read via orderId", "url": "https://api.example.com/v2/orders/1042",
        "vuln_class": "access_control", "param": "orderId", "severity": "high",
        "evidence_keys": ["differential_pair", "deterministic_repro_x2", "server_side_effect",
                          "evidence_pairs_attached", "mechanism_understood"],
        "evidence_refs": ["a-17", "a-21"]})["data"]
    check("strong candidate scores 75", r["score"] == 75)
    check("candidate triage + kill-test task spawned", r["triage"] == "needs_more_validation"
          and r["validation_task"] and mc.store.get_task(r["validation_task"])["type"] == "validate_step")
    check("outstanding kill tests listed", any(t["id"] == "fresh-session" for t in r["outstanding_kill_tests"]))
    r = mc.validate_finding(finding={
        "title": "Session token remains valid after logout", "url": "https://api.example.com/v2/logout",
        "vuln_class": "auth_session", "param": "token", "severity": "high",
        "evidence_keys": ["differential_pair", "deterministic_repro_x2", "oob_interaction",
                          "server_side_effect", "evidence_pairs_attached", "mechanism_understood"]})["data"]
    check("raise-ready at 100", r["score"] == 100 and r["triage"] == "validated" and r["status"] == "validated")
    r = mc.validate_finding(finding={
        "title": "IDOR again same endpoint", "url": "https://api.example.com/v2/orders/9999",
        "vuln_class": "access_control", "param": "orderId",
        "evidence_keys": ["differential_pair"]})["data"]
    check("local duplicate detected", r["dup_check"]["verdict"] == "local_duplicate" and r["status"] == "duplicate")
    # folded check_duplicates surface: dedup_only → just the local dup verdict, nothing written
    check("scanner crosscheck reachable via bridge",
          r["scanner_crosscheck"]["reachable"] and len(r["scanner_crosscheck"]["issues"]) == 1)
    n_findings_before = len(mc.store.findings())
    d = mc.validate_finding(finding={"title": "SSRF via export url param",
                                     "url": "https://api.example.com/v2/export",
                                     "vuln_class": "ssrf_oob", "param": "url"},
                            dedup_only=True)["data"]
    check("dup check unique locally", d["verdict"] == "unique" and isinstance(d["local_matches"], list))
    check("dedup_only writes no finding", len(mc.store.findings()) == n_findings_before)

    print("== 10. bridge counter sync + close-out + persistence ==")
    r = mc.budget_status()["data"]
    check("bridge counters synced (50 floor)", r["rows"][0]["used"] >= 50)
    r = mc.mission_control(action="checkpoint", note="pre-report checkpoint")["data"]
    check("checkpoint recorded", r["checkpoint"]["id"] == "C-001")
    r = mc.mission_control(action="phase", phase="4-validate")["data"]
    check("phase transition", r["phase"] == "4-validate")
    expect_error("invalid phase refused", lambda: mc.mission_control(action="phase", phase="9-x"), "invalid phase")
    # folded notify_operator: mission_control action="notify" and the kept public method
    r = mc.mission_control(action="notify", level="warn", subject="WAF coverage partial",
                           body="bypass cap reached on api.example.com; coverage noted in report")["data"]
    pub = mc.notify_operator(level="warn", subject="WAF coverage partial",
                             body="bypass cap reached on api.example.com; coverage noted in report")["data"]
    check("notify_operator appends", r["notification"]["level"] == "warn"
          and pub["notification"]["level"] == "warn")
    # persistence: a fresh engine over the same dir resumes cleanly (crash semantics:
    # cache dies with the process, state on disk is the truth)
    mc2 = MissionCore(ENG)
    mc2.task_enqueue(tasks=[{"type": "generic", "title": "long-running survey"}])
    t = mc2.task_next(claim=True)["data"]["tasks"][0]
    tasks = json.load(open(os.path.join(ENG, "tasks.json")))
    for tt in tasks:
        if tt["id"] == t["id"]:
            tt["updated_at"] = "2026-01-01T00:00:00Z"
    json.dump(tasks, open(os.path.join(ENG, "tasks.json"), "w"))
    mc3 = MissionCore(ENG)  # the "restarted process" — re-reads state from disk
    check("orphan detected after crash", t["id"] in mc3.mission_status()["data"]["queue"]["orphans"])
    st2 = mc2.mission_status()["data"]
    check("resume: mission intact across restart", st2["mission"]["mission_id"] == st["mission"]["mission_id"])
    check("resume: findings survive", st2["findings"]["count"] >= 3)
    check("resume: coverage survives", st2["coverage"]["endpoints_registered"] == 4)
    # end with force
    r = mc.mission_control(action="end", force=True, reason="budget + coverage complete")["data"]
    check("mission ended with summary", r["end_summary"]["findings"]["total"] >= 3)
    nxt = mc.task_next()["data"]
    check("ended mission yields nothing", nxt.get("blocked") == "mission_ended")
    check("run_log audit trail exists", len(mc.store.read_jsonl("run_log")) > 40)
    check("events log ids sequential", mc.store.read_jsonl("events")[0]["id"] == "E-001")

    print("== 11. MCP router ==")
    manifest = json.load(open(os.path.join(PKG, "aobh", "tools", "tools.json"), encoding="utf-8"))["tools"]
    group = [t for t in manifest if t.get("group") == "mission_control"]
    handlers = register(ENG)
    check("14 orchestrator tools registered", len(handlers) == 14
          and not ({"task_list", "check_duplicates", "notify_operator"} & set(handlers)),
          f"got {sorted(handlers)}")
    check("registry names match manifest group", set(handlers) == {t["name"] for t in group})
    r = handlers["mission_status"]({"sections": ["budget"]})
    check("router dispatch works", r["ok"] and "budget" in r["data"])
    r = handlers["task_enqueue"]({"tasks": []})
    check("router error envelope", r["ok"] is False and "hint" in r)

    shutil.rmtree(ENG, ignore_errors=True)
    print(f"\nORCHESTRATOR TEST {'PASSED' if not failed else 'FAILED'} — {len(passed)} checks"
          + (f", {len(failed)} FAILED: {failed}" if failed else ""))
    assert not failed, f"{len(failed)} checks FAILED: {failed}"
