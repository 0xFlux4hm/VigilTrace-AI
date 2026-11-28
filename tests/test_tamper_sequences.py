"""Layer 11/12 engine tests — pure units, no bridge: tamper matrix, one-variable
application, diff classification, the sequence gate and the closure gate.
"""
from __future__ import annotations

import json

import pytest

from aobh.tamper import core as tamper
from aobh.orchestrator import sequences

RAW = (
    "GET /api/v2/users/42?user_id=42&price=100&debug=0 HTTP/1.1\r\n"
    "Host: target.example.com\r\n"
    "Content-Type: application/json\r\n"
    "\r\n"
    '{"user_id": 42, "role": "user", "price": "100", "timestamp": "2026-01-01T00:00:00Z"}'
)


def _write(d, name, doc):
    (d / name).write_text(json.dumps(doc), encoding="utf-8")


# ---------- Layer 12: matrix + one-variable law ----------

def test_matrix_classifies_candidates():
    m = tamper.build_matrix(RAW)
    per_class = m["per_class"]
    assert "identity" in per_class and "user_id" in per_class["identity"]
    assert "value" in per_class and "price" in per_class["value"]
    assert m["candidates"] >= 3


def test_apply_param_changes_exactly_one_variable():
    q = "GET /api/x?id=7&flag=1 HTTP/1.1\r\nHost: h\r\n\r\n"
    out = tamper.apply_param(q, "id", "{PEER_ID}")
    assert "id=%7BPEER_ID%7D" in out or "id={PEER_ID}" in out
    assert "flag=1" in out  # untouched
    body_q = (
        "POST /api/x HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n"
        '{"is_admin": false, "keep": 1}'
    )
    out2 = tamper.apply_param(body_q, "is_admin", '{"role":"admin"}')
    obj = json.loads(out2.split("\r\n\r\n", 1)[1])
    assert obj["is_admin"] == {"role": "admin"}
    assert obj["keep"] == 1


def test_diff_classification_rules():
    base = {"status": 200, "body": json.dumps({"user_id": 42, "timestamp": "x", "nonce": 1})}
    # volatile-only changes -> noise
    noisy = {"status": 200, "body": json.dumps({"user_id": 42, "timestamp": "y", "nonce": 2})}
    assert tamper.diff_responses(base, noisy)["signal"] == "noise"
    # explicit denial -> rejected
    assert tamper.diff_responses(base, {"status": 403, "body": ""})["signal"] == "rejected"
    # another principal's identity fields appear -> data_cross
    cross = {"status": 200, "body": json.dumps({"user_id": 42, "email": "victim@example.com"})}
    assert tamper.diff_responses(base, cross)["signal"] == "data_cross"
    # authz flip honored -> state_change
    priv = {"status": 200, "body": json.dumps({"user_id": 42, "is_admin": True})}
    assert tamper.diff_responses(base, priv)["signal"] == "state_change"


def test_ladder_order_and_tamper_class_guard():
    ladder = tamper.ladder_for("identity")
    assert ladder[0]["variant"] == "{PEER_ID}"
    with pytest.raises(tamper.TamperError):
        tamper.ladder_for("nope")


# ---------- Layer 11: sequence gate + closure gate ----------

def test_sequence_gate_blocks_uninitialized_and_debt(tmp_path):
    out = sequences.sequence_next_core(tmp_path)
    assert out["data"]["phase"] == "0-bootstrap"
    assert "not initialized" in out["data"]["blockers"][0]
    _write(tmp_path, "mission.json", {"version": 1, "status": "active", "phase": "3-testing",
                                      "budgets": {"max_requests": 600},
                                      "counters": {"requests_sent": 10, "tool_calls": 50}})
    out2 = sequences.sequence_next_core(tmp_path)
    assert out2["data"]["gates"]["recon_debt_zero"] is True
    _write(tmp_path, "tasks.json", {"tasks": [{"id": "t1", "kind": "triage", "status": "pending"}]})
    out3 = sequences.sequence_next_core(tmp_path)
    assert out3["data"]["triage_debt"] == 1
    assert out3["data"]["gates"]["recon_debt_zero"] is False


def test_closure_gate_requires_evidence_and_validator(tmp_path):
    _write(tmp_path, "mission.json", {"version": 1, "status": "active", "phase": "5-report",
                                      "counters": {"tool_calls": 100, "requests_sent": 0}})
    _write(tmp_path, "coverage.json", {
        "endpoints": [{"key": "https://t/x", "auth": "anon"}],
        "matrix": {"https://t/x": {"sqli": {"state": "tested"}, "idor": {"state": "tested"}}},
        "classes": ["sqli", "idor"],
    })
    out = sequences.closure_check_core(tmp_path)
    conds = {c["condition"]: c for c in out["data"]["conditions"]}
    # unpolled live OOB + shallow tamper probes -> cannot close
    _write(tmp_path, "oob.json", {"registrations": [
        {"payload_id": "p1", "expires_at": "2099-01-01T00:00:00Z", "polls": [], "interactions": []}]})
    _write(tmp_path, "tamper.json", {"probes": [{"param": "user_id", "signal": "noise"}]})
    out2 = sequences.closure_check_core(tmp_path)
    conds2 = {c["condition"]: c for c in out2["data"]["conditions"]}
    assert conds2["oob_final_poll"]["passed"] is False
    assert conds2["tamper_depth"]["passed"] is False
    assert out2["data"]["can_close"] is False
    assert out2["data"]["verdict"] == "incomplete"
    # a clean ledger closes
    _write(tmp_path, "oob.json", {"registrations": [
        {"payload_id": "p1", "expires_at": "2020-01-01T00:00:00Z", "polls": ["x"], "interactions": []}]})
    # ladder exhaustion floor: >= 8 probes per param or a recorded hit
    _write(tmp_path, "tamper.json", {"probes": [{"param": "user_id", "signal": "noise"}] * 8})
    out3 = sequences.closure_check_core(tmp_path)
    assert out3["data"]["can_close"] is True
    assert out3["data"]["verdict"] == "no_findings_complete"


def test_sequence_and_closure_handlers_register(tmp_path):
    h = sequences.register_sequence_handlers(str(tmp_path))  # explicit dir: never touch shared config
    assert callable(h["sequence_next"]) and callable(h["closure_check"])
    out = h["sequence_next"]({})
    assert out["ok"] is True and "phase" in out["data"]
    out2 = h["closure_check"]({"strict": True})
    assert out2["ok"] is True and "can_close" in out2["data"]
