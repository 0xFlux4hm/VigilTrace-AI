#!/usr/bin/env python3
"""registrar.py — thin re-export slice of the AtapCore engine: create_account vocabulary.

The full engine (and the other 7 tool handlers) lives in aobh.atap.manager;
this slice exists so provisioning-focused callers can import just the
account-creation surface. Same name, same signature, same {ok, data} envelope
as ``AtapCore.create_account`` — it delegates to the shared engine singleton
(``aobh.atap.manager.get_engine``).
"""
from __future__ import annotations

from aobh.atap.manager import AtapCore, AtapError, get_engine  # noqa: F401 (re-exported)


def create_account(*args, **kwargs) -> dict:
    """atap_create_account — provision a test account (see AtapCore.create_account).

    Creates credentials (username, strong random password, strategy-appropriate
    email), submits the signup form through the Burp bridge, stores everything in
    the encrypted vault and detects bot-walls (human_assisted, never bypassed).
    Requires an authorization_reference citing where permission comes from.
    """
    return get_engine().create_account(*args, **kwargs)
