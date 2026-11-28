"""core.py — Layer 12 tamper engine (pure logic; the bridge is injected).

Everything here is deterministic and unit-testable without a bridge:
request parsing, param classification, ladder generation, one-variable
application, response normalization and signal classification. The bridge
(sender/fetcher callables) is passed in by tools.py, so tests drive real
flows against fake senders.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# --------------------------------------------------------------------------
# vocabulary (skills/param_tampering.md §2 — the tamper matrix)
# --------------------------------------------------------------------------
TAMPER_CLASSES = ("identity", "authz", "value", "state", "type_confusion", "hidden")

IDENTITY_KEYS = ("id", "user_id", "userid", "account_id", "acct", "uuid", "guid",
                 "order_id", "doc_id", "document", "email", "username", "user",
                 "profile_id", "customer", "invoice", "message_id", "file", "object")
AUTHZ_KEYS = ("role", "is_admin", "admin", "level", "permissions", "groups",
              "verified", "email_verified", "account_type", "premium", "staff",
              "superuser", "is_staff")
VALUE_KEYS = ("price", "amount", "quantity", "qty", "discount", "total", "balance",
              "cost", "fee", "limit", "count", "credit")
STATE_KEYS = ("status", "state", "approved", "active", "locked", "paid",
              "enabled", "published", "is_active", "is_verified")
# volatile fields normalized out before any diff (tamper_policy.normalize_volatile_fields)
VOLATILE_KEYS = ("timestamp", "ts", "time", "nonce", "csrf", "csrf_token", "xsrf",
                 "request_id", "trace_id", "tracking", "session", "session_id",
                 "token", "created_at", "updated_at", "random", "seed", "elapsed")

SIGNALS = ("data_cross", "state_change", "behavior_change", "rejected", "noise", "no_signal")
SIGNAL_MAP = {"data_cross": "confirmed_candidate", "state_change": "confirmed_candidate",
              "behavior_change": "suspected", "rejected": "guardrail_mapped",
              "noise": "ignore", "no_signal": "ignore"}


class TamperError(ValueError):
    pass


# --------------------------------------------------------------------------
# request parsing / classification
# --------------------------------------------------------------------------
def parse_request(raw: str) -> dict:
    """Parse a raw HTTP/1.1 request into {method, target, headers, body}."""
    if not raw or not raw.strip():
        raise TamperError("empty request")
    head, _, body = raw.partition("\r\n\r\n")
    if "\r\n\r\n" not in raw:  # tolerate \n\n
        head, _, body = raw.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n")
    parts = lines[0].split()
    if len(parts) < 2:
        raise TamperError(f"malformed request line: {lines[0]!r}")
    method, target = parts[0].upper(), parts[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {"method": method, "target": target, "headers": headers, "body": body}


def classify_param(name: str) -> str | None:
    """Map a parameter/header name to its tamper class (None = not a candidate)."""
    n = name.lower()
    if any(k in n for k in AUTHZ_KEYS):
        return "authz"
    if any(k in n for k in IDENTITY_KEYS):
        return "identity"
    if any(k in n for k in VALUE_KEYS):
        return "value"
    if any(k in n for k in STATE_KEYS):
        return "state"
    return None


def build_matrix(raw: str) -> dict:
    """Classify every parameter in the request → the per-class probe matrix."""
    req = parse_request(raw)
    params: list[dict] = []
    # query params
    q = urlsplit(req["target"]).query
    for name, value in parse_qsl(q, keep_blank_values=True):
        params.append({"name": name, "value": value, "where": "query",
                       "class": classify_param(name)})
    # JSON body keys
    body = req["body"]
    ctype = req["headers"].get("content-type", "")
    if body and "json" in ctype:
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    params.append({"name": k, "value": v if isinstance(v, str) else json.dumps(v),
                                   "where": "body_json", "class": classify_param(k)})
        except json.JSONDecodeError:
            pass
    elif body and "=" in body:
        for name, value in parse_qsl(body, keep_blank_values=True):
            params.append({"name": name, "value": value, "where": "body_form",
                           "class": classify_param(name)})
    # identity/authorization headers
    for hname, hvalue in req["headers"].items():
        if hname.startswith("x-") and classify_param(hname.lstrip("x-")):
            params.append({"name": hname, "value": hvalue, "where": "header",
                           "class": classify_param(hname.lstrip("x-"))})
    per_class = {c: [p["name"] for p in params if p["class"] == c] for c in TAMPER_CLASSES}
    candidates = [p for p in params if p["class"]]
    return {
        "params": params,
        "candidates": len(candidates),
        "per_class": {c: v for c, v in per_class.items() if v},
        "note": "one variable per probe; every probe needs a baseline (skills/param_tampering.md §3)",
    }


# --------------------------------------------------------------------------
# ladder generation + one-variable application
# --------------------------------------------------------------------------
def ladder_for(tclass: str, baseline: str = "", peer: str = "{PEER_ID}") -> list[dict]:
    """Ordered variants for one tamper class (identity→authz→value→state→type)."""
    b = baseline or "1"
    ladders = {
        "identity": [
            (peer, "substitute canary peer identifier — IDOR candidate"),
            ("1", "low sequential id"),
            ("0", "zero id"), ("-1", "negative id"), ("999999999", "high id"),
            (f"{b}{b}", "concatenation artifact"),
        ],
        "authz": [
            ('{"role":"admin"}', "mass assignment: role=admin"),
            ('{"is_admin":true}', "mass assignment: is_admin"),
            ('{"permissions":["*"]}', "mass assignment: wildcard permissions"),
            ("10", "level escalation"), ("1", "boolean flip"),
        ],
        "value": [("-1", "negative"), ("0", "zero"), ("0.0000001", "sub-unit"),
                  ("2147483647", "int max"), ("1e12", "overflow")],
        "state": [('"approved"', "state flip: approved"), ('"paid"', "state flip: paid"),
                  ("true", "boolean flip"), ("false", "backward flip maps guardrails")],
        "type_confusion": [(f"[{b}]", "scalar→list"), ('{"$ne":null}', "operator injection"),
                           ("null", "null"), ("true", "bool")],
        "hidden": [("true", "hidden param flip"), ("1", "hidden param enable")],
    }
    if tclass not in ladders:
        raise TamperError(f"unknown tamper class {tclass!r}; use one of {TAMPER_CLASSES}")
    return [{"variant": v, "note": n} for v, n in ladders[tclass]]


def apply_param(raw: str, name: str, variant: str, where: str = "auto") -> str:
    """Set exactly ONE parameter to the variant (one-variable-per-probe law)."""
    req = parse_request(raw)
    if where == "auto":
        where = "query" if f"{name}=" in urlsplit(req["target"]).query else (
            "body" if req["body"] else "query")
    if where in ("query", "header"):
        parts = urlsplit(req["target"])
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        hit = False
        pairs = [(k, variant if k == name else v) for k, v in pairs]
        if where == "query" and not any(k == name for k, _ in pairs):
            pairs.append((name, variant))
            hit = True
        new_q = urlencode(pairs)
        if where == "header":
            req["headers"][name.lower()] = variant
        else:
            req["target"] = urlunsplit(parts._replace(query=new_q))
        if not hit and where != "header":
            req["target"] = urlunsplit(urlsplit(req["target"])._replace(query=new_q))
    else:  # body (json or form)
        if req["body"].strip().startswith("{"):
            try:
                obj = json.loads(req["body"])
                obj[name] = _coerce(variant)
                req["body"] = json.dumps(obj)
            except json.JSONDecodeError as e:
                raise TamperError(f"json body unparsable: {e}") from e
        else:
            pairs = parse_qsl(req["body"], keep_blank_values=True)
            pairs = [(k, variant if k == name else v) for k, v in pairs]
            if not any(k == name for k, _ in pairs):
                pairs.append((name, variant))
            req["body"] = urlencode(pairs)
    lines = [f"{req['method']} {req['target']} HTTP/1.1"]
    lines += [f"{k}: {v}" for k, v in req["headers"].items()]
    if req["body"]:
        lines += ["", req["body"]]
    return "\r\n".join(lines)


def _coerce(variant: str):
    """JSON-typed variants ('{"is_admin":true}' → dict; 'null' → None; ...)."""
    v = variant.strip()
    if v.startswith(("{", "[")):
        try:
            return json.loads(v)
        except json.JSONDecodeError:
            return variant
    if v == "null":
        return None
    if v in ("true", "false"):
        return v == "true"
    return variant


# --------------------------------------------------------------------------
# observation: normalization + signal classification
# --------------------------------------------------------------------------
def _strip_volatile(obj):
    if isinstance(obj, dict):
        return {k: ("<volatile>" if k.lower() in VOLATILE_KEYS else _strip_volatile(v))
                for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        items = [_strip_volatile(v) for v in obj]
        return sorted(items, key=lambda x: json.dumps(x, sort_keys=True, default=str))
    return obj


def normalize_body(text: str):
    """Parse + normalize a response body for diffing (None if not JSON)."""
    try:
        return _strip_volatile(json.loads(text))
    except (json.JSONDecodeError, TypeError):
        return None


def _flatten(obj, prefix=""):
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:20]):
            out.update(_flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix] = obj
    return out


IDENTITY_FIELD_RE = re.compile(
    r"(email|user|owner|account|order|doc|profile|customer|invoice|message|file|balance)", re.I)


def diff_responses(a: dict, b: dict) -> dict:
    """Normalized field-level diff of two responses → {signal, attribution, ...}.

    a/b: {"status": int, "body": str}. a = baseline, b = tampered.
    """
    sa, sb = int(a.get("status", 0)), int(b.get("status", 0))
    na, nb = normalize_body(a.get("body", "")), normalize_body(b.get("body", ""))
    out: dict = {"status_a": sa, "status_b": sb, "signal": "no_signal",
                 "attribution": "", "confidence": "low",
                 "verdict_hint": SIGNAL_MAP["no_signal"], "field_deltas": []}
    if sa != sb:
        if sb in (401, 403):
            out.update(signal="rejected", confidence="high",
                       attribution=f"status {sa}→{sb}",
                       verdict_hint=SIGNAL_MAP["rejected"])
            return out
        out.update(signal="behavior_change", confidence="medium",
                   attribution=f"status {sa}→{sb}",
                   verdict_hint=SIGNAL_MAP["behavior_change"])
        if not (na and nb):
            return out
    if na is None or nb is None:
        la, lb = len(a.get("body", "") or ""), len(b.get("body", "") or "")
        delta = (lb - la) / max(la, 1)
        sig = "behavior_change" if abs(delta) > 0.2 else "noise"
        out.update(signal=sig, attribution=f"non-json body length {la}→{lb}",
                   confidence="low" if sig == "noise" else "medium",
                   verdict_hint=SIGNAL_MAP[sig])
        return out
    fa, fb = _flatten(na), _flatten(nb)
    added = {k: v for k, v in fb.items() if k not in fa}
    removed = {k: v for k, v in fa.items() if k not in fb}
    changed = {k: (fa[k], fb[k]) for k in fb if k in fa and fa[k] != fb[k]}
    out["field_deltas"] = [{"field": k, "change": "added", "to": v} for k, v in added.items()]
    out["field_deltas"] += [{"field": k, "change": "removed", "from": v} for k, v in removed.items()]
    out["field_deltas"] += [{"field": k, "change": "changed", "from": f, "to": t}
                            for k, (f, t) in changed.items()]
    if not (added or removed or changed):
        out.update(signal="noise", attribution="volatile fields only",
                   confidence="high", verdict_hint=SIGNAL_MAP["noise"])
        return out
    cross = [k for k in list(added) + list(changed) if IDENTITY_FIELD_RE.search(k)]
    if cross:
        out.update(signal="data_cross", attribution=f"principal fields {cross[:3]}",
                   confidence="medium", verdict_hint=SIGNAL_MAP["data_cross"])
        return out
    authz = [k for k in list(added) + list(changed)
             if any(a in k.lower() for a in AUTHZ_KEYS)]
    if authz:
        out.update(signal="state_change", attribution=f"authz fields {authz[:3]}",
                   confidence="medium", verdict_hint=SIGNAL_MAP["state_change"])
        return out
    out.update(signal="behavior_change",
               attribution=f"{len(added)} added / {len(changed)} changed fields",
               confidence="medium", verdict_hint=SIGNAL_MAP["behavior_change"])
    return out


# --------------------------------------------------------------------------
# tamper state (engagement dir; atomic writes like the MissionStore)
# --------------------------------------------------------------------------
def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"


def load_state(engagement_dir: str | Path) -> dict:
    p = Path(engagement_dir) / "tamper.json"
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"version": 1, "probes": [], "baselines": {}, "counters": {"probes": 0}}


def save_state(engagement_dir: str | Path, state: dict) -> None:
    p = Path(engagement_dir) / "tamper.json"
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, p)


def record_probe(engagement_dir: str | Path, probe: dict) -> dict:
    state = load_state(engagement_dir)
    probe["at"] = _now()
    state["probes"].append(probe)
    state["counters"]["probes"] += 1
    save_state(engagement_dir, state)
    return state
