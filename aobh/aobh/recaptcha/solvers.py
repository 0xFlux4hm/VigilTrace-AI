"""solvers.py — sanctioned CAPTCHA solving strategies and the per-engagement
solve cap (captcha_state.json), ported verbatim from the proven
captcha/captcha_core.py.

Boundary (must hold): strategy=human is the DEFAULT and needs nothing — it
hands the challenge to the operator. strategy=service is gated by all four
checks below (operator-configured key, authorization_reference, supported
type, sitekey) and hard-capped per engagement (CAPTCHA_MAX_SOLVES, default 5);
every solve is counted and flagged for report disclosure. Tokens are single-use
and consumed for ONE flow — never for bulk actions. No CAPTCHA/anti-bot
circumvention beyond the operator-authorized service path.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from aobh.recaptcha.errors import CaptchaError
from aobh.recaptcha.service import _METHOD_FOR, _service_poll, _service_submit

SOLVE_CAP_DEFAULT = 5


def _env(name, default=None):
    return os.environ.get(name, default)


def _budget_bump(n: int, cap: int) -> dict:
    path = Path(_env("ATAP_ENGAGEMENT_DIR") or Path.cwd() / "engagement") / "captcha_state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    state = {"solves_used": 0, "solutions": []}
    if path.exists():
        try:
            state = json.loads(path.read_text())
        except Exception:
            pass
    used = state.get("solves_used", 0)
    if used + n > cap:
        raise CaptchaError(
            f"solver cap reached ({used}/{cap} used this engagement)",
            f"The cap (CAPTCHA_MAX_SOLVES={cap}) exists so automated solving stays a "
            "single-flow exception, never bulk capability. Finish with human strategy "
            "or ask the operator to raise the cap in scope.md — and disclose the count.")
    state["solves_used"] = used + n
    state["solutions"].append({"n": used + n, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    path.write_text(json.dumps(state, indent=2))
    return {"solves_used": state["solves_used"], "cap": cap}


def _field_name(challenge: dict) -> str:
    return {"recaptcha_v2": "g-recaptcha-response", "recaptcha_v3": "g-recaptcha-response",
            "hcaptcha": "h-captcha-response", "turnstile": "cf-turnstile-response"}.get(
        challenge.get("type"), "captcha_response")


# ---------------------------------------------------------------------------
# captcha_solve handler (was CaptchaCore.captcha_solve)
# ---------------------------------------------------------------------------
def solve(challenge: dict, strategy: str = "human",
          authorization_reference: str | None = None, timeout: int = 120) -> dict:
    if not challenge or not challenge.get("type"):
        raise CaptchaError("challenge {type,sitekey,pageurl} required",
                           "Get it from captcha_detect output.")
    if strategy not in ("human", "service"):
        raise CaptchaError("strategy must be 'human' or 'service'", "Default is human.")

    if strategy == "human":
        return {"ok": True, "data": {
            "strategy": "human", "token": None,
            "instructions": [
                f"Open {challenge.get('pageurl') or 'the challenge page'} in a browser.",
                "Complete the challenge (developer tools → the form field "
                f"('{_field_name(challenge)}') or copy the token from the callback).",
                "Pass it into the next request/flow yourself, or paste it here via "
                "captcha_solve(strategy='human') with challenge.complete_token — the flow continues.",
            ],
            "next": "Continue the flow with the token in the form fields (bridge, annotated).",
        }}

    # ---- service strategy: all four gates ----
    key = _env("CAPTCHA_SERVICE_KEY")
    if not key:
        raise CaptchaError("no solver service configured (CAPTCHA_SERVICE_KEY unset)",
                           "Automated solving stays OFF unless the operator configures a service key — "
                           "and the engagement explicitly allows it. Use strategy=human.")
    if not authorization_reference or len(authorization_reference) < 15:
        raise CaptchaError("authorization_reference required for service solving",
                           "Cite the engagement permission, e.g. 'scope.md #captcha: operator explicitly "
                           "authorizes capped automated solving for the signup regression flow'. "
                           "No reference — no solve.")
    if challenge["type"] not in _METHOD_FOR:
        raise CaptchaError(f"service solving not supported for '{challenge['type']}'",
                           "Supported: recaptcha_v2, recaptcha_v3, hcaptcha (if the service supports it). "
                           "Use strategy=human.")
    if not challenge.get("sitekey"):
        raise CaptchaError("challenge.sitekey missing", "Take it from captcha_detect output.")

    budget = _budget_bump(1, int(_env("CAPTCHA_MAX_SOLVES", SOLVE_CAP_DEFAULT)))
    base = _env("CAPTCHA_SERVICE_URL", "https://2captcha.com").rstrip("/")
    job_id = _service_submit(challenge, key, base)
    token = _service_poll(job_id, key, base, timeout)
    return {"ok": True, "data": {
        "strategy": "service", "token": token, "provider_job_id": job_id,
        "challenge_type": challenge["type"], "single_use": True,
        "budget": budget,
        "disclosure": f"CAPTCHA solved via authorized service ({budget['solves_used']}/{budget['cap']} "
                      "this engagement) — disclose in report.md §Scope & methodology.",
        "next": "Use the token ONCE in the flow's form fields (bridge, annotated 'ATAP/CAPTCHA solve "
                f"#{budget['solves_used']}'); tokens are single-use and this is not a bulk capability.",
    }}
