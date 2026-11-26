#!/usr/bin/env python3
"""verifier.py — thin re-export slice of the AtapCore engine: verify_account vocabulary.

The full engine (and the other 7 tool handlers) lives in aobh.atap.manager;
this slice exists so verification-focused callers can import just the
email-verification surface. Same name, same signature, same {ok, data}
envelope as ``AtapCore.verify_account`` — it delegates to the shared engine
singleton (``aobh.atap.manager.get_engine``).
"""
from __future__ import annotations

from aobh.atap.manager import AtapCore, AtapError, get_engine  # noqa: F401 (re-exported)


def verify_account(*args, **kwargs) -> dict:
    """atap_verify_account — complete email verification (see AtapCore.verify_account).

    Waits for the confirmation mail (catcher or IMAP strategy), extracts the
    verification link, clicks it through the Burp bridge and confirms success.
    Manual fallback: pass verification_link collected by the operator.
    """
    return get_engine().verify_account(*args, **kwargs)
