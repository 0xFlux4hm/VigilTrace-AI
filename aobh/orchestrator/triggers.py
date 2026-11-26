#!/usr/bin/env python3
"""triggers.py — the TriggerEngine: built-in event → task/notification/pause reactions.

Split out of the proven mission_core.py unchanged. This is how findings push
work instead of the agent polling:

    collaborator_hit  → priority-0 investigate_oob task + OOB intel memory
    new_surface       → coverage_seed task
    waf_block         → quirk memory + budgeted waf_bypass_eval task
    rate_limited      → backoff_wait task + quirk memory
    scope_drift /     → HARD PAUSE (only the operator lifts it via
    target_down         mission_control resolve_pause with operator_reference)
    captcha_challenge → captcha_handle task
    account_state     → expired account → atap_health task
    target_up         → note only (resume is a deliberate operator/engine act)

Anything unregistered is logged with a note; custom one-off work travels as
the event's spawn_task. The engine (MissionCore.event_emit) supplies the spawn
closure and the mission document and persists the event record — this module
only decides the reactions.
"""
from __future__ import annotations

import json

TRIGGER_KNOWN = ["collaborator_hit", "new_surface", "waf_block", "rate_limited",
                 "scope_drift", "target_down", "captcha_challenge", "account_state",
                 "budget_warning", "target_up"]


class TriggerEngine:
    """Reacts to an emitted event by spawning tasks, saving memory, pausing.

    Holds a reference to the engine (MissionCore) for the store and the pause
    machinery; no state of its own.
    """

    def __init__(self, core):
        self.core = core

    def react(self, type: str, payload: dict, doc: dict, spawn) -> dict:
        """Apply the built-in reactions for `type`.

        doc     — the active mission document (pause reasons are added to it)
        spawn   — callable(**task_spec) -> task id, provided by event_emit
                  (it tags spawned tasks source="trigger:<type>")
        returns the effects dict for the event record.
        """
        p = payload
        effects: dict = {}

        if type == "collaborator_hit":
            spawn(type="investigate_oob", priority=0, tier=2,
                  title=f"Investigate Collaborator interaction: {str(p.get('payload_id', ''))[:60]}",
                  params={"payload_id": p.get("payload_id", ""), "interaction": p.get("summary", ""),
                          "payload_bearing": False},
                  hypothesis="OOB interaction — classify DNS vs HTTP, attribute to payload, validate_finding")
            self.core.store.add_memory({"kind": "intel", "text": f"OOB hit: {json.dumps(p, ensure_ascii=False)[:250]}",
                                        "tags": ["oob", "collaborator"]})
        elif type == "new_surface":
            spawn(type="coverage_seed", priority=2, tier=0,
                  title=f"Register + rank new surface: {str(p.get('url', p.get('urls', '')))[:80]}",
                  params={"url": p.get("url", "")})
        elif type == "waf_block":
            host = p.get("host", "")
            self.core.store.add_memory({"kind": "quirk",
                                        "text": f"WAF blocks on {host}: {str(p.get('detail', ''))[:200]}",
                                        "tags": ["waf", host]})
            spawn(type="waf_bypass_eval", priority=1, tier=1,
                  title=f"WAF adapt + budgeted bypass eval on {host} (W-3)",
                  params={"host": host, "request": p.get("request", {}), "payload_bearing": False})
        elif type == "rate_limited":
            mins = int(p.get("minutes", 5))
            host = p.get("host", "target")
            spawn(type="backoff_wait", priority=1, tier=0,
                  title=f"Back off {host} for {mins}m (rate limit hit)",
                  params={"minutes": mins, "host": host})
            self.core.store.add_memory({"kind": "quirk", "text": f"Rate limit hit: {json.dumps(p, ensure_ascii=False)[:200]}",
                                        "tags": ["rate-limit", p.get("host", "")]})
        elif type in ("scope_drift", "target_down"):
            self.core._add_pause_reason(doc, type, str(p.get("url", p.get("detail", "")))[:250], hard=True)
            self.core.store.update_mission(status="paused", pause_reasons=doc.get("pause_reasons"))
            effects["paused"] = type
            self.core.store.append("notifications", {
                "level": "critical", "requires_ack": True,
                "subject": f"HARD PAUSE: {type}",
                "body": f"{json.dumps(p, ensure_ascii=False)[:300]} — mission paused; operator must resolve "
                        f"via mission_control action=resolve_pause with operator_reference."})
        elif type == "captcha_challenge":
            spawn(type="captcha_handle", priority=1, tier=1,
                  title=f"Captcha on {str(p.get('url', ''))[:70]} (C-0 detect → sanctioned path)",
                  params={"url": p.get("url", ""), "payload_bearing": False})
        elif type == "account_state":
            if p.get("state") == "expired":
                spawn(type="atap_health", priority=1, tier=0,
                      title=f"Account {p.get('account_id', '?')} expired — health check / re-login once (A-2)",
                      params={"account_id": p.get("account_id", ""), "payload_bearing": False})
        elif type == "target_up":
            effects["note"] = "target_up — consider mission_control action=resume if a target_down pause is active"
        else:
            effects["note"] = (f"unregistered event type '{type}' — logged only. "
                               f"Known: {TRIGGER_KNOWN}; custom work via spawn_task.")
        return effects
