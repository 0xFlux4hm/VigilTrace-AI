#!/usr/bin/env python3
"""Integration test — the REAL Java BridgeServer serving HTTP while the REAL Python client talks to it.

The last untested seam: no stub, no mock on either side of the wire.

Topology (all localhost, nothing leaves the JVM):
    pytest ──► aobh.core.bridge.BridgeClient + aobh.tools.registry.dispatch (the real wire client)
            ──► aobh.orchestrator.engine.MissionCore._bridge_health (module BRIDGE/BRIDGE_HDRS)
                    │
                    ▼
            java -jar extension/build/burp-agent-bridge.jar --serve --port N --token T
                └─► dev.agent.burp.selftest.ServeMode: the SAME FakeBurpGateway + ToolRegistry +
                    BridgeServer wiring the Java self-test exercises, kept up until the process is
                    killed. Scripted for determinism: every send is answered with one fixed 200
                    text/html page carrying AOBH-SCRIPTED-MARKER, and raise_issue always fails with
                    error "scripted_tool_error". The scope registry starts empty, so the Python side
                    drives add_to_scope itself and the out_of_scope refusal can be observed first.

Skipped unless the built jar and a java binary exist, so the suite stays hermetic everywhere else.

Entry point note: the packaged jar's Main-Class is dev.agent.burp.standalone.StandaloneDemo, which now
delegates --serve to ServeMode (a few glue lines); `java -cp extension/build/classes
dev.agent.burp.selftest.SelfTest --serve …` reaches the same class directly. The test uses `java -jar`
so the exact packaged artifact is exercised.
"""
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))                      # parity with the other suites (run from any cwd)

JAR = PKG / "extension" / "build" / "burp-agent-bridge.jar"
JAVA = shutil.which("java") or "/usr/bin/java"

pytestmark = pytest.mark.skipif(
    not JAR.exists() or not Path(JAVA).exists(),
    reason=f"integration needs a java binary and {JAR} — build with: python3 extension/build.py")

MARKER = "AOBH-SCRIPTED-MARKER"                   # ServeMode.MARKER, asserted in every scripted body
SCRIPTED_ERROR = "scripted_tool_error"            # ServeMode.SCRIPTED_ERROR
READY_PREFIX = "BRIDGE SERVE MODE READY port="    # ServeMode's single stdout line, the readiness signal
TOKEN = "integration-token-0123456789abcdef"      # >= 16 chars, what BridgeServer would demand anyway
COUNTER_KEYS = ("requests_sent", "fuzz_requests", "redirect_following_requests", "send_errors",
                "tool_calls", "tool_errors", "rejected_out_of_scope", "rejected_other")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


TARGET = f"http://127.0.0.1:{free_port()}"        # the in-scope prefix the test authorizes via add_to_scope
NEVER_SCOPED = f"http://127.0.0.1:{free_port()}"  # a host nothing ever authorizes -> out_of_scope forever


@pytest.fixture(scope="module")
def serve():
    """The real Java bridge in serve mode: start `java -jar … --serve`, wait for the READY line, yield,
    terminate in finally. stdout/stderr are drained by daemon threads the whole time so the JVM can
    never block on a full pipe."""
    port = free_port()
    cmd = [JAVA, "-Djava.awt.headless=true", "-jar", str(JAR),
           "--serve", "--port", str(port), "--token", TOKEN]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out_lines, err_lines = [], []
    for stream, sink in ((proc.stdout, out_lines), (proc.stderr, err_lines)):
        threading.Thread(target=lambda s=stream, k=sink: [k.append(line.decode(errors="replace").rstrip())
                                                          for line in s], daemon=True).start()
    ready, deadline = None, time.monotonic() + 20.0
    while ready is None and time.monotonic() < deadline:
        if proc.poll() is not None:
            break                                  # died before it was ready
        ready = next((ln for ln in out_lines if ln.startswith(READY_PREFIX)), None)
        time.sleep(0.05)
    assert ready is not None, (
        f"serve mode never printed '{READY_PREFIX}<port>' within 20s "
        f"(exit={proc.poll()})\nstdout:\n" + "\n".join(out_lines) + "\nstderr:\n" + "\n".join(err_lines))
    try:
        yield {"proc": proc, "port": port, "base": f"http://127.0.0.1:{port}",
               "token": TOKEN, "ready": ready, "output": out_lines}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


@pytest.fixture(autouse=True)
def _wire_client_and_engine(serve, monkeypatch):
    """Point the REAL client stack at the serve port: the registry's BridgeClient is env-wired (so env +
    registry.reset()), while engine.BRIDGE/BRIDGE_HDRS are module-level constants read at import — patch
    those module attributes directly, NOT os.environ, because other suites already imported the module."""
    from aobh.tools import registry
    import aobh.orchestrator.engine as engine

    monkeypatch.setenv("BURP_BRIDGE_URL", serve["base"])
    monkeypatch.setenv("BURP_BRIDGE_TOKEN", serve["token"])
    monkeypatch.setattr(engine, "BRIDGE", serve["base"])
    monkeypatch.setattr(engine, "BRIDGE_HDRS", {"Authorization": "Bearer " + serve["token"]})
    registry.reset()
    yield
    registry.reset()


def health_counters():
    from aobh.core.bridge import BridgeClient
    return BridgeClient().health()["counters"]


def test_real_java_bridge_serve_seam(serve, tmp_path):
    """The whole seam in one run, in wire order: health → registry parity of intent → out-of-scope refusal
    → add_to_scope → counted in-scope send → scripted tool failure → budget reconciliation → instance
    awareness. Every assert speaks to the real Java process on the loopback socket."""
    from aobh.core.bridge import BridgeClient
    from aobh.tools import registry

    # ---- 1. BridgeClient().health(): ok + counters present, and the READY line named the real port
    env = BridgeClient().health()
    assert env.get("ok") is True, f"bridge /health did not report ok: {env}"
    cn = env.get("counters")
    assert isinstance(cn, dict) and all(k in cn for k in COUNTER_KEYS), \
        f"/health counters missing documented keys: {sorted(cn or {})}"
    assert str(env.get("instance", "")).startswith("br-") and env.get("mode") == "standalone", \
        f"unexpected instance/mode in /health: {env.get('instance')} / {env.get('mode')}"
    assert serve["ready"] == READY_PREFIX + str(serve["port"]), \
        f"READY line did not carry the actual port: {serve['ready']}"

    # ---- 2. registry.dispatch("get_scope", {}): a plain ok envelope, empty authorization registry
    scope = registry.dispatch("get_scope", {})
    assert scope.get("ok") is True, f"get_scope through registry.dispatch was not ok: {scope}"
    assert scope.get("data", {}).get("agent_registry") == [], \
        f"serve mode must start with an empty authorization registry: {scope.get('data')}"

    # ---- 3. a send to an out-of-scope URL FIRST (no add_to_scope happened yet): refused by the real
    #         ScopeGuard, and the real counters see the refusal
    before = health_counters()
    refused = registry.dispatch("send_http_request", {"url": NEVER_SCOPED + "/", "note": "integration out-of-scope"})
    assert refused.get("ok") is False and refused.get("error") == "out_of_scope", \
        f"out-of-scope send was not refused with out_of_scope: {refused}"
    assert refused.get("hint"), f"the out_of_scope refusal carries no hint: {refused}"
    after_refusal = health_counters()
    assert after_refusal["rejected_out_of_scope"] == before["rejected_out_of_scope"] + 1, \
        f"rejected_out_of_scope did not increment exactly once: {before} -> {after_refusal}"
    assert after_refusal["requests_sent"] == before["requests_sent"], \
        f"a refused request must not land in requests_sent: {before} -> {after_refusal}"

    # ---- 4. add_to_scope (provenance + bootstrap override), then exactly one in-scope send through
    #         registry.dispatch: passes, carries the scripted marker, counted in requests_sent exactly once
    added = registry.dispatch("add_to_scope", {"url_prefix": TARGET + "/",
                                               "added_from": "tests/test_integration.py",
                                               "bootstrap_override": True})
    assert added.get("ok") is True, f"add_to_scope failed: {added}"
    after_scope = health_counters()
    sent = registry.dispatch("send_http_request", {"url": TARGET + "/marker", "note": "integration scripted send"})
    assert sent.get("ok") is True, f"in-scope send failed after add_to_scope: {sent}"
    assert sent.get("data", {}).get("status_code") == 200 and MARKER in str(sent.get("data", {}).get("response_body")), \
        f"scripted 200 + marker missing from the send_http_request data: {str(sent.get('data'))[:300]}"
    after_send = health_counters()
    assert after_send["requests_sent"] == after_scope["requests_sent"] + 1, \
        f"requests_sent must increment by exactly 1 for one send: {after_scope} -> {after_send}"

    # ---- 5. the same seam through BridgeClient.request() (the engines' send path): the response really
    #         came back over the bridge wire, so the client stamps transport=bridge on it
    via_client = BridgeClient().request("GET", TARGET + "/transport", note="integration transport flag")
    assert via_client.get("transport") == "bridge", \
        f"transport flag missing/wrong on the bridge path: {via_client.get('transport')}"
    assert via_client.get("status_code") == 200 and MARKER in str(via_client.get("response_body")), \
        f"scripted 200 + marker missing via BridgeClient.request: {str(via_client)[:300]}"

    # ---- 6. the scripted-failure tool: raise_issue always fails with the stable code + hint; the client
    #         surfaces a tool-level ok:false envelope, not a transport error, not a raise
    failed = registry.dispatch("raise_issue", {"title": "T", "severity": "high", "confidence": "firm",
                                               "url": TARGET + "/", "description": "integration scripted failure"})
    assert failed.get("ok") is False and failed.get("error") == SCRIPTED_ERROR, \
        f"expected the scripted tool failure envelope, got: {failed}"
    assert isinstance(failed.get("hint"), str) and failed["hint"], \
        f"the scripted failure envelope carries no hint: {failed}"

    # ---- 7. MissionCore budget_status() (fresh MissionCore, tmp engagement dir): the mission's LOCAL
    #         request counter never moves, so the verdict rows must take used= from the REAL java
    #         /health counters — with max_requests=1 the real send drives the verdict to exhausted
    from aobh.orchestrator.engine import MissionCore
    mc = MissionCore(tmp_path)
    init = mc.mission_init(target=TARGET, authorization_reference="tests/test_integration.py",
                           budgets={"max_requests": 1})
    assert init.get("ok") is True, f"mission_init failed: {init}"
    assert mc.store.mission()["counters"]["requests_sent"] == 0, \
        "precondition: the mission's local request counter must still be zero"
    real = BridgeClient().health()["counters"]      # read before budget_status; no sends in between
    assert real["requests_sent"] >= 1, \
        f"precondition: at least one real send must have happened by now (requests_sent={real['requests_sent']})"
    budget = mc.budget_status()["data"]
    sync = budget.get("bridge_sync", {})
    assert sync.get("reachable") is True, f"budget_status does not see the bridge as reachable: {sync}"
    assert "counters" in sync.get("note", ""), \
        f"budget_status did not report the counters-synced note: {sync.get('note')}"
    assert budget.get("verdict") == "exhausted", \
        (f"with max_requests=1 and a real send the verdict must be exhausted: "
         f"{budget.get('verdict')} / {budget.get('rows')}")
    rows = {r["budget"]: r for r in budget["rows"]}
    assert rows["requests"]["cap"] == 1 and rows["requests"]["flag"] == "exhausted", \
        f"the requests row must carry the small cap and flag exhausted: {rows['requests']}"
    assert rows["requests"]["used"] == real["requests_sent"], \
        (f"budget row used ({rows['requests']['used']}) must equal the REAL java counter "
         f"({real['requests_sent']}) while the local counter is 0 — that is the reconciliation proof")
    assert mc.store.mission()["counters"]["requests_sent"] == 0, \
        "the local mission counter moved — then the verdict would not prove the bridge read"
    assert budget.get("bridge", {}).get("instance") == BridgeClient().health()["instance"], \
        f"budget verdict is not pinned to the real bridge instance: {budget.get('bridge')}"

    # ---- 8. mission_status() on a fresh MissionCore: instance-awareness reports the REAL bridge
    #         instance (br-<UTC start>-<random>), and the bridge block is reachable + counters synced
    mc2 = MissionCore(tmp_path / "second-engagement")
    init2 = mc2.mission_init(target=TARGET, authorization_reference="tests/test_integration.py",
                             budgets={"max_requests": 5000})
    assert init2.get("ok") is True, f"mission_init (second) failed: {init2}"
    instance = BridgeClient().health()["instance"]
    status = mc2.mission_status()["data"]
    assert status.get("bridge", {}).get("reachable") is True, \
        f"mission_status does not see the bridge as reachable: {status.get('bridge')}"
    assert status.get("bridge", {}).get("counters_synced") is True, \
        f"mission_status did not sync counters: {status.get('bridge')}"
    seen = status.get("budget", {}).get("bridge", {}).get("instance")   # the reconciled verdict carries it
    assert isinstance(seen, str) and seen == instance and len(seen) > 0, \
        f"mission_status must report the real bridge instance {instance}, got: {seen!r}"
