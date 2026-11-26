#!/usr/bin/env python3
"""aobh.atap — Autonomous Test Account Provisioning (engine for the 8 atap_* tools).

Ported 1:1 from the proven atap stack (autonomous-bug-hunter/atap):

  vault      encrypted credential store (atap-vault-v1: scrypt + HMAC-SHA256-CTR
             + integrity tag; ATAP_VAULT_KEY env or per-engagement .vault_key)
  mailcatch  verification-mail acquisition: SMTP catcher (asyncio, 127.0.0.1),
             IMAP polling, or manual link paste
  store      AccountStore — account lifecycle, audit trail, redaction (vault-backed)
  manager    the AtapCore engine + BridgeClient (via aobh.core.bridge) +
             ATAP_TOOLS schemas; env-at-import (ATAP_ENGAGEMENT_DIR)
  registrar  thin re-export slice: create_account vocabulary
  verifier   thin re-export slice: verify_account vocabulary
  session    thin re-export slice: get_session vocabulary
  tools      register() -> the 8 atap_* handlers ({ok,data}/{ok,error,hint} envelopes)

NOTE: manager.py reads ATAP_* environment variables at import time, so this
package __init__ deliberately does NOT import it eagerly. Set the environment
first (as tests/test_atap.py does), then ``import aobh.atap.manager`` — or use
the lazy attribute access below, which imports on first use.
"""
from __future__ import annotations

from aobh.atap.mailcatch import MailCatcher, extract_links, imap_fetch_links
from aobh.atap.store import AccountStore, AccountStoreError
from aobh.atap.vault import Vault, VaultError, generate_password

__all__ = [
    # env-safe modules (no env reads at import)
    "MailCatcher", "extract_links", "imap_fetch_links",
    "AccountStore", "AccountStoreError",
    "Vault", "VaultError", "generate_password",
    # lazy (env-at-import) symbols resolved in __getattr__
    "AtapCore", "AtapError", "ATAP_TOOLS", "get_engine", "reset_engine",
    "register", "run_tool", "tool_schemas",
]

_LAZY_MANAGER = ("AtapCore", "AtapError", "ATAP_TOOLS", "get_engine", "reset_engine")
_LAZY_TOOLS = ("register", "run_tool", "tool_schemas")


def __getattr__(name: str):
    """PEP 562 lazy re-exports: manager (and tools) read ATAP_* env at import."""
    if name in _LAZY_MANAGER:
        from aobh.atap import manager
        return getattr(manager, name)
    if name in _LAZY_TOOLS:
        from aobh.atap import tools
        return getattr(tools, name)
    raise AttributeError(f"module 'aobh.atap' has no attribute {name!r}")
