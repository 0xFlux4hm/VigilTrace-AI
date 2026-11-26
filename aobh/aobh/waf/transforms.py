#!/usr/bin/env python3
"""transforms.py — the WAF-normalization transform engine and the waf_adapt
ranker (ported verbatim from the proven waf/waf_core.py).

Pure computation (Tier 0): given a blocked request, produce a RANKED list of
sanctioned transformations with rationale + risk per transform. These test
whether the WAF's payload inspection can be normalized past — a legitimate,
commonly-paid bug bounty class — within the waf_test_bypass budget (bypass.py).
No IP rotation, no TLS fingerprinting, no rate-limit evasion — ever.
"""
from __future__ import annotations

import copy
import json
import random
import re
from urllib.parse import parse_qsl, quote, urlencode, urlparse

from aobh.waf.errors import WafError
from aobh.waf.fingerprint import classify_response

BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/126.0.0.0 Safari/537.36")

SQL_KEYWORDS = re.compile(r"\b(union|select|insert|update|delete|sleep|benchmark|exec)\b", re.I)


def _set_header(headers: list[dict], name: str, value: str) -> list[dict]:
    out = [h for h in headers if h.get("name", "").lower() != name.lower()]
    out.append({"name": name, "value": value})
    return out


def _last_query_pair(url: str) -> str | None:
    qs = urlparse(url).query
    pairs = parse_qsl(qs, keep_blank_values=True)
    return pairs[-1][0] if pairs else None


def apply_transform(request: dict, tid: str) -> tuple[dict, str]:
    """Return (new_request, rationale). request: {method,url,headers,body}."""
    r = copy.deepcopy(request)
    url = r["url"]
    p = urlparse(url)
    headers = list(r.get("headers") or [])

    if tid == "ua-normalize":
        r["headers"] = _set_header(headers, "User-Agent", BROWSER_UA)
        return r, "default scanner UA (python-requests/curl) is heavily scored by WAFs; a common browser UA removes that signal"
    if tid == "referer-normalize":
        r["headers"] = _set_header(headers, "Referer", f"{p.scheme}://{p.netloc}/")
        return r, "some WAF rules flag cross-origin or missing Referer on state-changing requests"
    if tid == "xff-loopback":
        r["headers"] = _set_header(headers, "X-Forwarded-For", "127.0.0.1")
        r["headers"] = _set_header(r["headers"], "X-Custom-IP-Authorization", "127.0.0.1")
        return r, "misconfigured WAFs/origins trust client-supplied IP headers for allow-lists"
    if tid == "x-original-url":
        r["url"] = f"{p.scheme}://{p.netloc}/"
        r["headers"] = _set_header(headers, "X-Original-URL", p.path + ("?" + p.query if p.query else ""))
        return r, "proxies that route on X-Original-URL let the WAF inspect '/' while the origin serves the real path"
    if tid == "x-rewrite-url":
        r["url"] = f"{p.scheme}://{p.netloc}/"
        r["headers"] = _set_header(headers, "X-Rewrite-URL", p.path + ("?" + p.query if p.query else ""))
        return r, "same class as X-Original-URL (IIS/proxy rewrite headers)"
    if tid == "path-dot-segment":
        r["url"] = f"{p.scheme}://{p.netloc}/./{p.path.lstrip('/')}" + ("?" + p.query if p.query else "")
        return r, "/./ segment: WAF and origin may normalize differently"
    if tid == "case-toggle-path":
        rng = random.Random(url)
        r["url"] = f"{p.scheme}://{p.netloc}/" + "".join(
            c.upper() if rng.random() < 0.5 else c.lower() for c in p.path.lstrip('/')) + \
            ("?" + p.query if p.query else "")
        return r, "case-insensitive origins accept mixed-case paths some regex rules miss"
    if tid == "param-hpp":
        key = _last_query_pair(url)
        if not key:
            raise WafError("param-hpp needs a query parameter", "Add the payload as ?param=... first.")
        sep = "&" if p.query else "?"
        r["url"] = f"{url}{sep}{key}={quote('benign')}"
        return r, "HTTP parameter pollution: WAF may inspect the first occurrence while the origin takes another"
    if tid == "encode-double":
        pairs = parse_qsl(p.query, keep_blank_values=True) if p.query else []
        if not pairs:
            raise WafError("encode-double needs a query parameter", "Add the payload as ?param=... first.")
        enc = "&".join(f"{k}={quote(quote(v, safe=''), safe='')}" for k, v in pairs)
        r["url"] = f"{p.scheme}://{p.netloc}{p.path}?{enc}"
        return r, "double URL-encoding: WAF decodes once and inspects the still-encoded string"
    if tid == "payload-comment":
        key = _last_query_pair(url)
        if not key:
            raise WafError("payload-comment needs a query parameter", "Add the payload as ?param=... first.")
        pairs = parse_qsl(p.query, keep_blank_values=True)
        def split_comment(m):
            w = m.group(0)
            cut = max(2, len(w) // 2)
            return f"{w[:cut]}/**/{w[cut:]}"
        pairs = [(k, SQL_KEYWORDS.sub(split_comment, v) if k == key else v) for k, v in pairs]
        r["url"] = f"{p.scheme}://{p.netloc}{p.path}?" + urlencode(pairs)
        return r, "inline SQL comments split keywords; origin DB parsers usually ignore /**/ inside identifiers"
    if tid == "content-type-json":
        if not r.get("body"):
            raise WafError("content-type-json needs a body", "Only applies to requests with a body.")
        ctype = (_hdr_value(headers, "Content-Type") or "")
        if "application/x-www-form-urlencoded" in ctype:
            pairs = parse_qsl(r["body"], keep_blank_values=True)
            r["body"] = json.dumps(dict(pairs))
            r["headers"] = _set_header(headers, "Content-Type", "application/json")
            return r, "WAF body parsers are often tuned for form encoding; JSON re-encoding changes the parse tree"
        return r, "body kept as-is (not form-encoded)"
    raise WafError(f"unknown transform id '{tid}'", "Pick ids from atap-free waf_adapt output.")


def _hdr_value(headers, name):
    for h in headers or []:
        if h.get("name", "").lower() == name.lower():
            return h.get("value")
    return None


TRANSFORM_ORDER = [
    ("ua-normalize", "headers", "low risk"), ("referer-normalize", "headers", "low risk"),
    ("xff-loopback", "headers", "low risk — origin may ignore"),
    ("x-original-url", "headers", "medium risk — changes routing semantics"),
    ("x-rewrite-url", "headers", "medium risk — changes routing semantics"),
    ("param-hpp", "query", "low risk"), ("encode-double", "query", "low risk"),
    ("payload-comment", "query", "medium risk — payload mutation"),
    ("path-dot-segment", "path", "medium risk — origin may 404"),
    ("case-toggle-path", "path", "low risk — only for case-insensitive origins"),
    ("content-type-json", "body", "medium risk — origin parser must accept JSON"),
]


# ---------------------------------------------------------------------------
# waf_adapt handler (was WafCore.waf_adapt)
# ---------------------------------------------------------------------------
def adapt(request: dict, block_response: dict | None = None) -> dict:
    if not request or "url" not in request:
        raise WafError("request {method,url,headers,body} required",
                       "Paste the blocked request (from bridge history / send_http_request output).")
    ctx = classify_response(block_response) if block_response else None
    ranked = []
    for tid, cls, risk in TRANSFORM_ORDER:
        try:
            _, rationale = apply_transform(request, tid)
        except WafError as e:
            rationale = f"(prerequisite missing: {e.error})"
        ranked.append({"id": tid, "class": cls, "risk": risk, "rationale": rationale})
    return {"ok": True, "data": {
        "transforms": ranked,
        "block_context": {"vendors": [v["vendor"] for v in ctx["vendors"]]} if ctx else None,
        "next": "waf_test_bypass with 2-4 candidate ids (start low-risk); origin-reachable bypass = finding candidate (V-1 calibration required)",
    }}
