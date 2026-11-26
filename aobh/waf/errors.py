"""errors.py — engine exceptions for the waf group.

Envelope contract (mirrors aobh.core.utils and the old atap stack): handlers
return {"ok": True, "data": ...} or {"ok": False, "error", "hint"}. Every
WafError carries both an operator-facing error string and a hint.
"""
from __future__ import annotations


class WafError(Exception):
    def __init__(self, error: str, hint: str = ""):
        super().__init__(error)
        self.error, self.hint = error, hint
