#!/usr/bin/env python3
"""WAF + CAPTCHA end-to-end test — no Burp, no external target, no real solver service.

Ported 1:1 from the proven scripts/test_waf_captcha.py (41 checks): harness and
stub servers kept, imports/paths adapted only — engines now come from the aobh
package (aobh.waf.core / aobh.recaptcha.core) and the MCP layer is exercised
through aobh.waf.tools.register() / aobh.recaptcha.tools.register() (the old
rag/server.py routers, envelope semantics reproduced exactly).

Topology (all localhost):
    test ──► waf core / recaptcha core (engines + BridgeClient)
               │  POST /tools/send_http_request
               ▼
            STUB BRIDGE ──► LAB APP with WAF middleware
               ▲                 │  UA + payload rules → Cloudflare-style block page
               │                 │  /search  /protected (mock reCAPTCHA)  /submit /submit-broken
               │                 └── X-Original-URL routing (naive-WAF blind spot)
               └── STUB SOLVER SERVICE (in.php/res.php shape)  [only captcha_solve goes here]

Exercises: fingerprint (inline + bridge), probe map + budget, adapt ranking,
bypass (SQL comment split + X-Original-URL), validation-bypass (broken vs secure
endpoint), human strategy, service gating (no key / no auth ref / cap), solver
round-trip into the protected form, replay detection, tool routing.
"""
import json
import os
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote_plus, urlsplit, quote as urlquote

REPO = str(Path(__file__).resolve().parents[1])  # the aobh repo root
if REPO not in sys.path:
    sys.path.insert(0, REPO)


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close(); return port


# ---------- lab app behind a mock WAF ----------
BLOCK_UA = ("python-requests", "curl/")
BLOCK_PATTERNS = ["<img", "onerror", "onmouseover", "onload=", "' or '1'='1",
                  "union select", "sleep(", "../", "${jndi"]
BLOCK_PAGE_BODY = ("Attention Required! | Cloudflare\n\nCloudflare Ray ID: 8a11f00d\n"
                   "Your IP address was blocked because this request looks automated.")


def waf_guard(headers: dict, path_qs: str, body: str) -> bool:
    """Mock WAF: inspects URL-decoded path+query+body and the UA (header blind spots intact)."""
    ua = (headers.get("User-Agent") or "").lower()
    if any(u in ua for u in BLOCK_UA):
        return True
    blob = unquote_plus(path_qs + " " + (body or "")).lower()
    return any(p in blob for p in BLOCK_PATTERNS)


class Lab(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, headers=None):
        self.send_response(code)
        for k, v in (headers or []):
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def _read(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n).decode() if n else ""

    def _route(self, path, query, form):
        """Origin routing, X-Original-URL aware (classic naive-WAF blind spot)."""
        xou = self.headers.get("X-Original-URL")
        if xou and path == "/":
            sp = urlsplit(xou)
            path, query = sp.path, (sp.query or query)
        q = {k: v[0] for k, v in parse_qs(query, keep_blank_values=True).items()}
        return path, q

    def do_GET(self):
        sp = urlsplit(self.path)
        headers = {k: v for k, v in self.headers.items()}
        if waf_guard(headers, self.path, ""):
            return self._send(403, BLOCK_PAGE_BODY,
                              [("Server", "cloudflare"), ("CF-Ray", "8a11f00dabc123"),
                               ("Set-Cookie", "__cf_bm=mock; Path=/")])
        path, q = self._route(sp.path, sp.query, {})
        if path == "/":
            return self._send(200, "hello origin")
        if path == "/search":
            return self._send(200, f"results for: {q.get('x', '')}")
        if path == "/protected":
            html = ('<html><head><script src="https://www.google.com/recaptcha/api.js">'
                    "</script></head><body><form action=\"/submit\" method=\"post\">"
                    '<div class="g-recaptcha" data-sitekey="6LeMockKey1234567890ab"></div>'
                    "<input name=\"username\"><button>go</button></form></body></html>")
            return self._send(200, html)
        return self._send(404, "no route")

    def do_POST(self):
        sp = urlsplit(self.path)
        body = self._read()
        headers = {k: v for k, v in self.headers.items()}
        if waf_guard(headers, self.path, body):
            return self._send(403, BLOCK_PAGE_BODY,
                              [("Server", "cloudflare"), ("CF-Ray", "8a11f00dabc123")])
        path, q = self._route(sp.path, sp.query, body)
        form = {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}
        if path == "/submit":
            tok = form.get("g-recaptcha-response", "")
            if tok.startswith("tok-valid"):
                return self._send(200, f"welcome {form.get('username', 'user')}")
            return self._send(400, "captcha invalid or missing — please verify you are human")
        if path == "/submit-broken":
            return self._send(200, f"welcome {form.get('username', 'user')}")
        return self._send(404, "no route")


class StubBridge(BaseHTTPRequestHandler):
    """Mimics the Burp bridge; adds a browser-like UA when none is set (as a real
    browser-driven origin session would)."""
    def log_message(self, *a): pass
    counter = 0

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        req = json.loads(self.rfile.read(n))
        if urlparse(self.path).path != "/tools/send_http_request":
            return self._json({"ok": False, "error": "unknown endpoint"})
        body = req.get("body")
        fwd = {h["name"]: h["value"] for h in req.get("headers", [])}
        fwd.setdefault("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/126")
        if req.get("note"):
            fwd["X-Bridge-Note"] = req["note"]
        import urllib.request, urllib.error
        r = urllib.request.Request(req["url"], data=body.encode() if body else None,
                                   headers=fwd, method=req.get("method", "GET"))
        try:
            resp = urllib.request.urlopen(r, timeout=15)
            code, raw, hdrs = resp.status, resp.read().decode(errors="replace"), resp.getheaders()
        except urllib.error.HTTPError as e:
            code, raw, hdrs = e.code, e.read().decode(errors="replace"), e.headers.items()
        except Exception as e:
            return self._json({"ok": False, "error": f"forward failed: {e}"})
        StubBridge.counter += 1
        return self._json({"ok": True, "data": {
            "id": f"s-{StubBridge.counter}", "status": code,
            "headers": [{"name": k, "value": v} for k, v in hdrs],
            "body": raw[:20000], "note": req.get("note", "")}})

    def _json(self, obj):
        payload = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class StubSolver(BaseHTTPRequestHandler):
    """in.php/res.php-shaped solver service (2captcha API shape) with instant-ish solves."""
    def log_message(self, *a): pass
    jobs, polls = {}, {}

    def do_GET(self):
        sp = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(sp.query).items()}
        if q.get("key") != "test-key":
            return self._json({"status": 0, "request": "ERROR_WRONG_USER_KEY"})
        if sp.path == "/in.php":
            if not q.get("googlekey") and not q.get("sitekey"):
                return self._json({"status": 0, "request": "ERROR_NO_SITEKEY"})
            jid = f"solve-{len(StubSolver.jobs) + 1}"
            StubSolver.jobs[jid] = q.get("googlekey") or q.get("sitekey")
            StubSolver.polls[jid] = 0
            return self._json({"status": 1, "request": jid})
        if sp.path == "/res.php" and q.get("action") == "get":
            jid = q.get("id", "")
            StubSolver.polls[jid] = StubSolver.polls.get(jid, 0) + 1
            if StubSolver.polls[jid] < 2:
                return self._json({"status": 0, "request": "CAPCHA_NOT_READY"})
            return self._json({"status": 1, "request": f"tok-valid-{jid}"})
        return self._json({"status": 0, "request": "ERROR_UNKNOWN"})

    def _json(self, obj):
        payload = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def serve(handler, port=0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_waf_captcha_end_to_end():
    LAB_PORT, STUB_PORT, SOLVER_PORT = free_port(), free_port(), free_port()
    LAB = f"http://127.0.0.1:{LAB_PORT}"

    serve(Lab, LAB_PORT)
    stub_srv = serve(StubBridge)
    STUB = f"http://127.0.0.1:{stub_srv.server_address[1]}"
    serve(StubSolver, SOLVER_PORT)

    # ---------- env BEFORE module imports (engagement dir + bridge + caps) ----------
    ENG = tempfile.mkdtemp(prefix="waf-captcha-test-")
    os.environ.update({
        "ATAP_ENGAGEMENT_DIR": ENG,
        "BURP_BRIDGE_URL": STUB,
        "BURP_BRIDGE_TOKEN": "test-token",
        "ATAP_ALLOW_DIRECT": "0",
        "WAF_PROBE_MAX": "16",
        "WAF_BYPASS_MAX": "24",
        "CAPTCHA_SERVICE_URL": f"http://127.0.0.1:{SOLVER_PORT}",
        "CAPTCHA_SERVICE_KEY": "test-key",
        "CAPTCHA_MAX_SOLVES": "2",
        "CAPTCHA_POLL_INTERVAL": "0.3",
    })

    from aobh.waf.core import WafCore, WafError          # noqa: E402
    from aobh.recaptcha.core import CaptchaCore, CaptchaError  # noqa: E402

    waf, cap = WafCore(), CaptchaCore()
    passed = []

    def check(label, cond, detail=""):
        assert cond, f"FAIL: {label} {detail}"
        passed.append(label)
        print(f"  ok: {label}" + (f" ({detail})" if detail else ""))

    # ---------- 1. fingerprint ----------
    print("== waf_fingerprint")
    inline_block = {"status": 403,
                    "headers": [{"name": "Server", "value": "cloudflare"},
                                {"name": "CF-Ray", "value": "8a11f00dabc123"}],
                    "body": BLOCK_PAGE_BODY}
    r = waf.waf_fingerprint(response=inline_block)["data"]
    check("inline: Cloudflare high confidence",
          r["classification"]["vendors"][0]["vendor"] == "Cloudflare"
          and r["classification"]["vendors"][0]["confidence"] == "high")
    check("inline: verdict blocked", r["classification"]["verdict"] == "blocked")
    r2 = waf.waf_fingerprint(url=f"{LAB}/")["data"]
    check("bridge: benign root normal", r2["classification"]["verdict"] == "normal"
          and "bridge" in r2["transport"])

    # ---------- 2. probe map + budget ----------
    print("== waf_probe")
    r = waf.waf_probe(target=LAB)["data"]
    blocked, passed_ids = set(r["blocked_patterns"]), set(r["passed_patterns"])
    check("payload classes blocked", {"xss-tag", "xss-event", "xss-svg", "sqli-quote",
          "sqli-union", "sqli-sleep", "path-trav", "log4j"} <= blocked, sorted(blocked))
    check("payload classes passed", {"sqli-comment", "cmd-inj", "ssti", "php-wrapper"} <= passed_ids,
          sorted(passed_ids))
    check("requests budgeted", r["requests_sent"] == 13 and r["budget"]["used"] == 13
          and r["budget"]["cap"] == 16, f"{r['budget']}")
    try:
        waf.waf_probe(target=LAB)
        raise AssertionError("probe budget not enforced")
    except WafError as e:
        check("probe budget exhausted -> refused", "budget exhausted" in e.error)

    # ---------- 3. adapt ----------
    print("== waf_adapt")
    blocked_req = {"method": "GET", "url": f"{LAB}/search?x=1%20UNION%20SELECT%20user", "headers": []}
    r = waf.waf_adapt(request=blocked_req)["data"]
    check("11 transforms ranked", len(r["transforms"]) == 11
          and r["transforms"][0]["id"] == "ua-normalize")
    check("low-risk first, payload-level later",
          r["transforms"][-1]["id"] == "content-type-json")

    # ---------- 4. bypass testing ----------
    print("== waf_test_bypass")
    r = waf.waf_test_bypass(request=blocked_req, transform_ids=["ua-normalize", "payload-comment"])["data"]
    res = {x["id"]: x for x in r["results"]}
    check("baseline blocked", r["baseline"]["verdict"] == "blocked")
    check("ua-normalize alone fails", res["ua-normalize"]["origin_reached"] is False)
    check("SQL comment split reaches origin", res["payload-comment"]["origin_reached"] is True,
          f"status={res['payload-comment']['status']}")
    check("finding hint present", r["origin_reached"] and "finding candidate" in r["finding_hint"].lower())
    xou_req = {"method": "GET", "url": f"{LAB}/search?x=UNION%20SELECT%20pass", "headers": []}
    r2 = waf.waf_test_bypass(request=xou_req, transform_ids=["x-original-url"])["data"]
    check("X-Original-URL reaches origin", r2["origin_reached"] is True,
          f"status={r2['results'][0]['status']}")
    check("bypass budget tracked", r2["budget"]["used"] == 3 + 2, json.dumps(r2["budget"]))

    # ---------- 5. captcha detection ----------
    print("== captcha_detect")
    r = cap.captcha_detect(url=f"{LAB}/protected")["data"]
    ch = r["challenge"]
    check("recaptcha_v2 detected", ch["type"] == "recaptcha_v2", ch["vendor"])
    check("sitekey extracted", ch["sitekey"] == "6LeMockKey1234567890ab")
    check("pageurl recorded", ch["pageurl"].endswith("/protected"))

    # ---------- 6. validation-bypass testing ----------
    print("== captcha_test_bypass")
    r = cap.captcha_test_bypass(url=f"{LAB}/submit-broken", form_fields={"username": "atap_probe"})["data"]
    check("broken endpoint accepts invalid tokens", r["validation_bypassed"] is True
          and all(x["accepted"] for x in r["results"]))
    check("finding hint on bypass", "FINDING CANDIDATE" in r["finding_hint"])
    r2 = cap.captcha_test_bypass(url=f"{LAB}/submit", form_fields={"username": "atap_probe"})["data"]
    check("secure endpoint rejects all variants", r2["validation_bypassed"] is False
          and not any(x["accepted"] for x in r2["results"]))
    check("negative-result hint", "negative result" in r2["finding_hint"])

    # ---------- 7. human strategy ----------
    print("== captcha_solve (human)")
    r = cap.captcha_solve(challenge=ch, strategy="human")["data"]
    check("human: instructions, no token", r["token"] is None and len(r["instructions"]) >= 2)

    # ---------- 8. service gating ----------
    print("== captcha_solve (service gates)")
    try:
        key_backup = os.environ.pop("CAPTCHA_SERVICE_KEY")
        cap.captcha_solve(challenge=ch, strategy="service", authorization_reference="x" * 20)
        raise AssertionError("solved without service key")
    except CaptchaError as e:
        check("no service key -> refused", "CAPTCHA_SERVICE_KEY" in e.error)
    finally:
        os.environ["CAPTCHA_SERVICE_KEY"] = key_backup
    try:
        cap.captcha_solve(challenge=ch, strategy="service")
        raise AssertionError("solved without authorization_reference")
    except CaptchaError as e:
        check("no authorization_reference -> refused", "authorization_reference" in e.error)

    # ---------- 9. service solve + round-trip + cap ----------
    print("== captcha_solve (service, authorized)")
    AUTH = ("scope.md #captcha — operator explicitly authorizes capped automated solving "
            "for the signup regression flow")
    r = cap.captcha_solve(challenge=ch, strategy="service", authorization_reference=AUTH)["data"]
    tok = r["token"]
    check("token obtained", tok.startswith("tok-valid-"), tok[:20])
    check("budget counted", r["budget"]["solves_used"] == 1 and r["budget"]["cap"] == 2)
    check("disclosure present", "disclose in report.md" in r["disclosure"])
    sess = waf.bridge.request("POST", f"{LAB}/submit",
                              headers=[{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
                              body=f"username=atap_user&g-recaptcha-response={urlquote(tok)}",
                              note="ATAP signup with sanctioned CAPTCHA token")
    check("token round-trip into protected form", sess["status"] == 200
          and "welcome" in (sess["body"] or ""), f"HTTP {sess['status']}")
    r2 = cap.captcha_solve(challenge=ch, strategy="service", authorization_reference=AUTH)["data"]
    check("second solve within cap", r2["budget"]["solves_used"] == 2)
    try:
        cap.captcha_solve(challenge=ch, strategy="service", authorization_reference=AUTH)
        raise AssertionError("cap not enforced")
    except CaptchaError as e:
        check("solver cap enforced", "cap reached" in e.error)

    # ---------- 10. replay detection ----------
    print("== captcha_test_bypass (replay)")
    r = cap.captcha_test_bypass(url=f"{LAB}/submit", form_fields={"username": "atap_probe"},
                                token_to_replay=tok)["data"]
    variants = {x["variant"]: x for x in r["results"]}
    check("replayed token accepted (server does not bind tokens)",
          variants["replay"]["accepted"] is True and r["validation_bypassed"] is True)
    check("omit/empty/dummy still rejected",
          not any(variants[v]["accepted"] for v in ("omit", "empty", "dummy")))

    # ---------- 11. state files ----------
    print("== state files")
    waf_state = json.load(open(os.path.join(ENG, "waf_state.json")))
    cap_state = json.load(open(os.path.join(ENG, "captcha_state.json")))
    check("waf budgets persisted", waf_state["hosts"][urlparse(LAB).netloc]["probe_requests"] == 13)
    check("solve log persisted", len(cap_state["solutions"]) == 2 and cap_state["solves_used"] == 2)

    # ---------- 12. tool layer (register() routers; schemas from the manifest) ----------
    print("== tool layer")
    from aobh.waf.tools import register as register_waf, tool_schemas as waf_tool_schemas  # noqa: E402
    from aobh.recaptcha.tools import register as register_captcha, tool_schemas as captcha_tool_schemas  # noqa: E402
    waf_tools, cap_tools = register_waf(), register_captcha()
    schemas = waf_tool_schemas() + captcha_tool_schemas()
    check("7 waf/captcha schemas served", len(schemas) == 7)
    names = {t["name"] for t in schemas}
    check("tool names complete", names == {"waf_fingerprint", "waf_probe", "waf_adapt", "waf_test_bypass",
          "captcha_detect", "captcha_solve", "captcha_test_bypass"}
          and set(waf_tools) | set(cap_tools) == names)
    r = waf_tools["waf_fingerprint"]({"response": inline_block})
    check("route waf_fingerprint", r["ok"] and r["data"]["classification"]["verdict"] == "blocked")
    r = cap_tools["captcha_solve"]({"challenge": ch, "strategy": "human"})
    check("route captcha_solve", r["ok"] and r["data"]["strategy"] == "human")
    r = waf_tools["waf_adapt"]({})
    check("route error path", r["ok"] is False and "hint" in r)
    r = cap_tools["captcha_solve"]({"challenge": {"type": "recaptcha_v2",
                                                  "sitekey": "6LeMockKey1234567890ab"},
                                    "strategy": "service",
                                    "authorization_reference": AUTH})
    check("cap error via router", r["ok"] is False and "cap" in r["error"])

    print(f"\nWAF+CAPTCHA END-TO-END TEST PASSED — {len(passed)} checks")
    print(f"engagement dir: {ENG}")
    assert len(passed) == 41, f"expected 41 checks, got {len(passed)}"
