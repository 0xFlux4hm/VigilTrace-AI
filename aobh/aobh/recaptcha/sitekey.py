"""sitekey.py — CAPTCHA/challenge detection and sitekey extraction (ported
verbatim from the proven captcha/captcha_core.py detection section).

Pure computation (Tier 0): regex markers over a page body. One or more marker
matches classify the challenge type; the first capturing group yields the
sitekey where the vendor exposes one. Custom/image CAPTCHAs require two
markers to avoid false positives.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# detection
# ---------------------------------------------------------------------------
DETECTORS = [
    {"type": "recaptcha_v2", "vendor": "Google reCAPTCHA v2",
     "patterns": [r'data-sitekey="([0-9A-Za-z_\-]{20,})"', r'google\.com/recaptcha/(api|enterprise)\.js',
                  r'class="[^"]*g-recaptcha[^"]*"']},
    {"type": "recaptcha_v3", "vendor": "Google reCAPTCHA v3 (invisible, score-based)",
     "patterns": [r'grecaptcha\.execute\s*\(', r'render=([0-9A-Za-z_\-]{20,})']},
    {"type": "hcaptcha", "vendor": "hCaptcha",
     "patterns": [r'hcaptcha\.com/1/api\.js', r'class="[^"]*h-captcha[^"]*"',
                  r'data-sitekey="([0-9A-Za-z_\-]{20,})"']},
    {"type": "turnstile", "vendor": "Cloudflare Turnstile",
     "patterns": [r'challenges\.cloudflare\.com/turnstile', r'class="[^"]*cf-turnstile[^"]*"',
                  r'name="cf-turnstile-response"']},
    {"type": "geetest", "vendor": "GeeTest",
     "patterns": [r'gt\.js', r'api\.geetest\.com', r'geetest']},
    {"type": "custom", "vendor": "custom/image CAPTCHA",
     "patterns": [r'<input[^>]+name="[^"]*captcha[^"]*"', r'captcha[_\-]?(image|code|img)']},
]


def detect_challenge(body: str) -> dict | None:
    if not body:
        return None
    for det in DETECTORS:
        sitekey = None
        matched = 0
        for pat in det["patterns"]:
            m = re.search(pat, body, re.I)
            if m:
                matched += 1
                if m.groups() and not sitekey:
                    sitekey = m.group(1)
        if matched >= 1:
            if det["type"] == "recaptcha_v3" and 'g-recaptcha' in body and not re.search(r'grecaptcha\.execute', body, re.I):
                continue  # v2 checkbox page also carries g-recaptcha markers
            if det["type"] == "custom" and matched < 2:
                continue  # require two custom markers to avoid false positives
            return {"type": det["type"], "vendor": det["vendor"], "sitekey": sitekey,
                    "matched_markers": matched}
    return None
