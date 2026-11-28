"""oob_tools.py — oob_register / oob_poll over the bridge's Collaborator tools.

The out-of-band channel rides Burp Collaborator (the extension exposes
get_collaborator_payload / poll_collaborator); this module adds the Layer-11
bookkeeping the raw tools lack: TTLs, poll-before-claim discipline, and the
registration ledger (oob.json) the closure gate reads. A self-hosted
interactsh backend can replace the bridge later without changing the tool
surface (docs/IMPLEMENTATION.md §3).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Callable

from aobh.orchestrator.sequences import _config_dir, _load


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"


def _save_oob(engagement_dir: Path, doc: dict) -> None:
    p = engagement_dir / "oob.json"
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, p)


def register_oob_handlers(engagement_dir: str | None) -> dict[str, Callable]:
    dir_ = _config_dir(engagement_dir)

    def _bridge():
        from aobh.tools.registry import bridge_client
        return bridge_client()

    def oob_register(args: dict) -> dict:
        count = int(args.get("count", 1))
        ttl = int(args.get("ttl_minutes", 60))
        note = args.get("note") or "oob registration"
        data = _bridge().call("get_collaborator_payload", {"count": count, "note": note})
        if not data.get("ok"):
            return {"ok": False, "error": "bridge_error",
                    "hint": f"collaborator payload unavailable: {data.get('error')} — {data.get('hint', '')}"}
        d = data.get("data", {})
        payloads = d.get("payloads") if isinstance(d.get("payloads"), list) else [d]
        doc = _load(dir_ / "oob.json", {"version": 1, "registrations": []}) or {"registrations": []}
        doc.setdefault("registrations", [])
        now = time.time()
        registered = []
        for p in payloads:
            pid = p.get("payload_id") or p.get("id") or ""
            if not pid:
                continue
            rec = {"payload_id": pid,
                   "location": p.get("location") or p.get("url") or p.get("payload") or "",
                   "note": note, "registered_at": _now(),
                   "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + ttl * 60)),
                   "ttl_minutes": ttl, "polls": [], "interactions": []}
            doc["registrations"].append(rec)
            registered.append(rec)
        _save_oob(dir_, doc)
        return {"ok": True, "data": {"registered": len(registered), "ttl_minutes": ttl,
                                     "payloads": [{k: r[k] for k in ("payload_id", "location", "expires_at")}
                                                  for r in registered],
                                     "rule": "register BEFORE the first payload of any OOB-capable "
                                             "class; poll before claiming; final poll before closure"}}

    def oob_poll(args: dict) -> dict:
        payload_id = args.get("payload_id")
        doc = _load(dir_ / "oob.json", {"registrations": []}) or {"registrations": []}
        recs = [r for r in doc.get("registrations", []) if not payload_id or r["payload_id"] == payload_id]
        if payload_id and not recs:
            return {"ok": False, "error": "unknown_payload",
                    "hint": f"no registration for {payload_id!r}; run oob_register first"}
        results = []
        for rec in recs:
            data = _bridge().call("poll_collaborator",
                                  {"payload_id": rec["payload_id"],
                                   "wait_seconds": int(args.get("wait_seconds", 0)),
                                   "interaction_type": args.get("interaction_type", "dns"),
                                   "since": args.get("since", "")})
            interactions = []
            if data.get("ok"):
                d = data.get("data", {})
                raw_list = d.get("interactions") if isinstance(d.get("interactions"), list) else (
                    [d] if d.get("interaction_type") or d.get("client") else [])
                interactions = raw_list
            rec["polls"] = (rec.get("polls") or []) + [_now()]
            rec["interactions"] = (rec.get("interactions") or []) + interactions
            results.append({"payload_id": rec["payload_id"],
                            "new_interactions": len(interactions),
                            "total_interactions": len(rec["interactions"]),
                            "note": "claim a blind finding only with a correlated callback"})
        _save_oob(dir_, doc)
        return {"ok": True, "data": {"polled": len(results), "results": results}}

    return {"oob_register": oob_register, "oob_poll": oob_poll}
