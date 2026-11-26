"""core.py — CaptchaCore: the three public CAPTCHA tool methods (ported from
the proven captcha/captcha_core.py).

Traffic rules (unchanged): challenge pages are fetched through the Burp bridge
(aobh.core.bridge.BridgeClient) like all target traffic; ONLY the solver-service
calls go direct (operator infrastructure, service.py). Detection lives in
sitekey.py, sanctioned strategies in solvers.py; captcha_test_bypass probes the
TARGET's own server-side token validation — not a solver.
"""
from __future__ import annotations

from urllib.parse import quote as urlquote

from aobh.core.bridge import BridgeClient
from aobh.recaptcha.errors import CaptchaError
from aobh.recaptcha.sitekey import detect_challenge
from aobh.recaptcha.solvers import solve

__all__ = ["CaptchaCore", "CaptchaError"]


# ---------------------------------------------------------------------------
# MCP handlers
# ---------------------------------------------------------------------------
class CaptchaCore:
    def __init__(self, bridge: BridgeClient | None = None):
        self.bridge = bridge or BridgeClient()

    # ---- 1. captcha_detect ----
    def captcha_detect(self, url: str | None = None, response: dict | None = None) -> dict:
        if not response and not url:
            raise CaptchaError("provide url or response",
                               "url: one annotated GET via the bridge; response: inline {status,headers,body} (Tier 0).")
        if response:
            transport = "inline (no request sent)"
        else:
            response = self.bridge.request("GET", url, note=f"CAPTCHA detect GET {url}")
            transport = response.get("transport")
        ch = detect_challenge(response.get("body") or "")
        if not ch:
            return {"ok": True, "data": {"challenge": None, "transport": transport,
                                         "note": "No CAPTCHA markers in this response."}}
        ch["pageurl"] = url
        handling = {
            "recaptcha_v2": "human: open the page in a browser, complete it, copy g-recaptcha-response; service: only if explicitly authorized (§12)",
            "recaptcha_v3": "score-based — often passes without interaction; test validation bypass first (captcha_test_bypass)",
            "hcaptcha": "same paths as reCAPTCHA v2 (solver adapter supports it if the service does)",
            "turnstile": "managed challenge — try normal request first (may be JS-only); human fallback",
            "geetest": "human strategy recommended; no sanctioned service path",
            "custom": "human strategy; if the field is server-validated, captcha_test_bypass applies",
        }[ch["type"]]
        return {"ok": True, "data": {"challenge": ch, "transport": transport, "handling": handling}}

    # ---- 2. captcha_solve ----
    def captcha_solve(self, challenge: dict, strategy: str = "human",
                      authorization_reference: str | None = None, timeout: int = 120) -> dict:
        return solve(challenge, strategy=strategy,
                     authorization_reference=authorization_reference, timeout=timeout)

    # ---- 3. captcha_test_bypass ----
    def captcha_test_bypass(self, url: str, form_fields: dict | None = None,
                            captcha_field: str = "g-recaptcha-response",
                            token_to_replay: str | None = None, method: str = "POST") -> dict:
        """Tests the TARGET's server-side token validation — not a solver.
        Variants: field omitted / empty / dummy / replayed valid token."""
        form_fields = dict(form_fields or {})
        variants = [
            ("omit", {k: v for k, v in form_fields.items()}),
            ("empty", {**form_fields, captcha_field: ""}),
            ("dummy", {**form_fields, captcha_field: "test-bypass-probe"}),
        ]
        if token_to_replay:
            variants.append(("replay", {**form_fields, captcha_field: token_to_replay}))
        if len(variants) > 6:
            raise CaptchaError("variant cap exceeded", "Max 6 validation probes per call.")

        results = []
        for name, fields in variants:
            body = "&".join(f"{k}={urlquote(str(v), safe='')}" for k, v in fields.items())
            resp = self.bridge.request(method.upper(), url,
                                       headers=[{"name": "Content-Type",
                                                 "value": "application/x-www-form-urlencoded"}],
                                       body=body, note=f"CAPTCHA validation test [{name}] {url}")
            blob = (resp.get("body") or "").lower()
            status = resp.get("status")
            rejected = (status in (400, 403, 422)) or any(
                m in blob for m in ["captcha", "please verify", "not a robot", "invalid token",
                                    "verification failed", "missing captcha"])
            results.append({"variant": name, "status": status, "accepted": not rejected,
                            "evidence": (resp.get("body") or "")[:120], "bridge_id": resp.get("id")})
        bypassed = any(r["accepted"] for r in results)
        return {"ok": True, "data": {
            "results": results, "validation_bypassed": bypassed,
            "finding_hint": ("Server accepted at least one invalid token variant → FINDING CANDIDATE "
                             "'CAPTCHA not server-side-validated': re-validate once (§6), capture the exact "
                             "accepted request as evidence, calibrate with V-1. Impact: what the CAPTCHA "
                             "protects (signup spam, credential stuffing, rate-limit bypass).") if bypassed
            else "Server validates tokens correctly on all variants — record as a negative result (§7).",
        }}
