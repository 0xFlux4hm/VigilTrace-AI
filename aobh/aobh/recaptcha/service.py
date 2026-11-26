"""service.py — solver-service client (operator infrastructure, not the target).

Speaks the common "in.php/res.php" solver-service API shape (2captcha-style;
the base URL is configurable so other providers or a local mock can be dropped
in). ONLY these calls go direct — it is operator-configured infrastructure;
all target traffic goes through the bridge (core.py). Ported from the proven
captcha/captcha_core.py, converted to stdlib urllib (repo rule: stdlib only —
`requests.get(url, params=...)` became urlencode + urlopen; requests.utils.quote
is urllib.parse.quote, so encoded bytes are identical).
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request

from aobh.recaptcha.errors import CaptchaError

POLL_INTERVAL = float(os.environ.get("CAPTCHA_POLL_INTERVAL", "5"))


def _env(name, default=None):
    return os.environ.get(name, default)


_METHOD_FOR = {"recaptcha_v2": "userrecaptcha", "recaptcha_v3": "userrecaptcha", "hcaptcha": "hcaptcha"}


def _get_json(url: str, params: dict) -> dict:
    full = f"{url}?{urllib.parse.urlencode(params)}"
    with urllib.request.urlopen(full, timeout=30) as r:
        return json.loads(r.read().decode())


def _service_submit(challenge: dict, key: str, base: str) -> str:
    params = {"key": key, "json": "1", "pageurl": challenge.get("pageurl", "")}
    if challenge["type"] == "hcaptcha":
        params.update(method="hcaptcha", sitekey=challenge["sitekey"])
    else:
        params.update(method="userrecaptcha", googlekey=challenge["sitekey"])
    if challenge["type"] == "recaptcha_v3":
        params.update(version="v3", action=challenge.get("action", "verify"),
                      min_score=str(challenge.get("min_score", "0.7")))
    data = _get_json(f"{base}/in.php", params)
    if str(data.get("status")) != "1":
        raise CaptchaError(f"solver service rejected the job: {data.get('request')}",
                           "Check CAPTCHA_SERVICE_KEY, the sitekey/pageurl, and the service's balance.")
    return str(data["request"])


def _service_poll(job_id: str, key: str, base: str, timeout: int) -> str:
    deadline = time.time() + min(max(int(timeout), 10), 240)
    while time.time() < deadline:
        data = _get_json(f"{base}/res.php",
                         {"key": key, "action": "get", "id": job_id, "json": "1"})
        if str(data.get("status")) == "1":
            return str(data["request"])
        if "CAPCHA_NOT_READY" not in str(data.get("request", "")):
            raise CaptchaError(f"solver service error: {data.get('request')}",
                               "Transient provider error — the job id is logged; retry once or use human strategy.")
        time.sleep(POLL_INTERVAL)
    raise CaptchaError(f"solver did not return a token within {timeout}s",
                       "Use strategy=human, or retry once.")
