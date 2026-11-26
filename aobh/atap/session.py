#!/usr/bin/env python3
"""session.py — thin re-export slice of the AtapCore engine: get_session vocabulary.

The full engine (and the other 7 tool handlers) lives in aobh.atap.manager;
this slice exists so session-focused callers can import just the
ready-to-use-session surface. Same name, same signature, same {ok, data}
envelope as ``AtapCore.get_session`` — it delegates to the shared engine
singleton (``aobh.atap.manager.get_engine``).
"""
from __future__ import annotations

from aobh.atap.manager import AtapCore, AtapError, get_engine  # noqa: F401 (re-exported)


def get_session(*args, **kwargs) -> dict:
    """atap_get_session — session material for an account (see AtapCore.get_session).

    Returns the Cookie header string and Authorization bearer so hunting tools
    can act as that role. Passwords are NOT included unless include_password=True;
    sessions stay in the encrypted vault.
    """
    return get_engine().get_session(*args, **kwargs)
