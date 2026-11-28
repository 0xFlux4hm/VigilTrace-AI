"""tools.py — the four tamper handlers (aobh.tamper.tools.register).

Follows the repo contract: one positional args dict → response envelope.
The bridge client is imported lazily inside handlers (registry imports this
package, so a module-level import would be circular). All target-facing
HTTP goes through bridge send tools with an audit note — never direct.
"""
from __future__ import annotations

from typing import Callable

from aobh.tamper import core
from aobh.tamper.core import TamperError


def _bridge():
    """Lazy bridge import (registry → this package → registry would cycle)."""
    from aobh.tools.registry import bridge_client
    return bridge_client()


def _config_dir(engagement_dir: str | None) -> str:
    if engagement_dir:
        return engagement_dir
    from aobh.core.config import get_config
    return str(get_config().engagement_dir)


def _raw_from_source(args: dict) -> str:
    raw = args.get("raw_request")
    if raw:
        return raw
    source = args.get("source")
    if not source:
        raise TamperError("need raw_request or source (proxy id / agent id / sitemap / raw)")
    data = _bridge().call("get_response", {"source": source, "part": "request",
                                           "include_headers": True})
    if not data.get("ok"):
        raise TamperError(f"could not read request for source: {data.get('error')}")
    d = data.get("data", {})
    text = d.get("request") or d.get("raw") or d.get("body") or ""
    if not text:
        raise TamperError("bridge returned no request text; pass raw_request instead")
    return text


def _extract_response(data: dict) -> dict:
    d = data.get("data", {}) if isinstance(data, dict) else {}
    body = d.get("response") or d.get("body") or d.get("text") or ""
    status = d.get("status") or d.get("status_code") or 0
    return {"status": status, "body": body}


def _send_raw(raw: str, note: str) -> dict:
    """Send one tampered/baseline request through the bridge (audit note kept)."""
    data = _bridge().call("send_http_request", {"raw_request": raw, "note": note,
                                                "follow_redirects": "never"})
    if not data.get("ok"):
        raise TamperError(f"bridge refused send: {data.get('error')} — {data.get('hint', '')}")
    return _extract_response(data)


def _fetch_response(args: dict) -> dict:
    source = args.get("source_a") or args.get("source_b") or args.get("source")
    if not source:
        raise TamperError("res_diff needs source_a and source_b (source convention)")
    data = _bridge().call("get_response", {"source": source,
                                           "part": args.get("part", "all")})
    if not data.get("ok"):
        raise TamperError(f"could not read source: {data.get('error')}")
    return _extract_response(data)


def register(engagement_dir: str | None) -> dict[str, Callable]:
    """Build the 4-tamper-tool handler map over `engagement_dir`."""
    dir_ = _config_dir(engagement_dir)

    def tamper_matrix_build(args: dict) -> dict:
        raw = _raw_from_source(args)
        matrix = core.build_matrix(raw)
        state = core.load_state(dir_)
        matrix["probes_spent"] = state["counters"]["probes"]
        return {"ok": True, "data": matrix}

    def param_tamper_run(args: dict) -> dict:
        note = args.get("note") or "tamper probe"
        raw = _raw_from_source(args)
        matrix = core.build_matrix(raw)
        tclass = args.get("tamper_class")
        param = args.get("param")
        if not param:
            first = matrix["params"]
            if not first:
                return {"ok": False, "error": "no_params",
                        "hint": "request has no parameters to tamper; run tamper_matrix_build first"}
            param, tclass = first[0]["name"], first[0]["class"] or "type_confusion"
        tclass = tclass or core.classify_param(param) or "type_confusion"
        baseline = args.get("baseline_value") or ""
        # baseline-first law: capture the untouched response before any probe
        baseline_resp = _send_raw(raw, f"{note} [baseline]")
        probes = []
        budget = int(args.get("budget", 20))
        for step in core.ladder_for(tclass, baseline):
            if len(probes) >= budget:
                break
            tampered = core.apply_param(raw, param, step["variant"])
            resp = _send_raw(tampered, f"{note} [tamper {tclass}/{param}={step['variant'][:40]}]")
            diff = core.diff_responses(baseline_resp, resp)
            probe = {"param": param, "class": tclass, "variant": step["variant"],
                     "note": step["note"], "signal": diff["signal"],
                     "verdict_hint": diff["verdict_hint"], "attribution": diff["attribution"],
                     "confidence": diff["confidence"], "baseline_status": diff["status_a"],
                     "tampered_status": diff["status_b"], "field_deltas": diff["field_deltas"][:10]}
            # repeat-once rule: hits and deterministic rejects get one confirmation probe
            if diff["signal"] in ("data_cross", "state_change", "rejected") and len(probes) + 2 <= budget:
                resp2 = _send_raw(tampered, f"{note} [confirm {param}={step['variant'][:40]}]")
                diff2 = core.diff_responses(baseline_resp, resp2)
                probe["confirmed"] = diff2["signal"] == diff["signal"]
                probe["confidence"] = "high" if probe["confirmed"] else "low"
            probes.append(probe)
            core.record_probe(dir_, probe)
        signals = {}
        for p in probes:
            signals[p["signal"]] = signals.get(p["signal"], 0) + 1
        return {"ok": True, "data": {"param": param, "tamper_class": tclass,
                                     "probes": probes, "signals": signals,
                                     "note": "data_cross/state_change → canary confirm "
                                             "(atap accounts) then validate_finding"}}

    def res_diff(args: dict) -> dict:
        a = _fetch_response({"source": args.get("source_a"), "part": args.get("part", "all")})
        b = _fetch_response({"source": args.get("source_b"), "part": args.get("part", "all")})
        diff = core.diff_responses(a, b)
        return {"ok": True, "data": diff}

    def param_discover(args: dict) -> dict:
        note = args.get("note") or "param discovery"
        raw = _raw_from_source(args)
        candidates = args.get("params") or ["debug", "verbose", "admin", "internal",
                                            "test", "source", "format", "redirect",
                                            "url", "path", "callback", "next"]
        canary = args.get("canary_value") or "vtrace-canary"
        baseline = _send_raw(raw, f"{note} [baseline]")
        hits = []
        for name in candidates[:int(args.get("max", 12))]:
            tampered = core.apply_param(raw, name, canary)
            resp = _send_raw(tampered, f"{note} [discover {name}]")
            diff = core.diff_responses(baseline, resp)
            reflected = canary in (resp.get("body") or "")
            if diff["signal"] not in ("noise", "no_signal") or reflected:
                hits.append({"param": name, "signal": diff["signal"],
                             "reflected": reflected, "attribution": diff["attribution"]})
        return {"ok": True, "data": {"tested": len(candidates[:int(args.get("max", 12))]),
                                     "hits": hits,
                                     "note": "feed hits into tamper_matrix_build as candidates"}}

    return {"tamper_matrix_build": tamper_matrix_build,
            "param_tamper_run": param_tamper_run,
            "res_diff": res_diff,
            "param_discover": param_discover}
