#!/usr/bin/env python3
"""store.py — ATAP account registry: lifecycle, audit trail, redaction.

Status machine:
    planned -> created -> awaiting_verification -> verified -> active
                                       |                |
                                       v                v
                              human_assisted         expired --(re-login)--> active
                                       |                |
                                       +--> locked <----+            locked -> human_assisted
    active/deleted -> cleaned_up | deleted (cleanup phase)

Every transition appends an audit event {ts, account, event, detail} — the
engagement transcript stays reconstructable from accounts.json alone.
Persisted via vault.Vault (encrypted at rest: passwords, sessions).
"""
from __future__ import annotations

import time
from pathlib import Path

from aobh.atap.vault import Vault

STATUSES = ["planned", "created", "awaiting_verification", "verified", "active",
            "expired", "locked", "human_assisted", "cleaned_up", "deleted"]

# account fields that must never appear in tool output unless explicitly requested
SECRET_FIELDS = {"password", "session_cookies", "session_token"}


class AccountStoreError(Exception):
    pass


class AccountStore:
    def __init__(self, engagement_dir: str | Path):
        self.vault = Vault.open(engagement_dir)
        self.data = self.vault.load()

    # ---------- audit ----------
    def _audit(self, account_id: str, event: str, detail: str = "") -> None:
        self.data.setdefault("audit", []).append({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
            "account": account_id, "event": event, "detail": detail[:500],
        })

    def save(self) -> None:
        self.vault.save(self.data)

    # ---------- CRUD ----------
    def next_id(self) -> str:
        return f"ACC-{len(self.data.get('accounts', [])) + 1:02d}"

    def create(self, account: dict) -> dict:
        account.setdefault("id", self.next_id())
        account["status"] = account.get("status") or "planned"
        account["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.data.setdefault("accounts", []).append(account)
        self._audit(account["id"], "created", account.get("target", ""))
        self.save()
        return account

    def get(self, account_id: str) -> dict:
        for a in self.data.get("accounts", []):
            if a["id"] == account_id:
                return a
        raise AccountStoreError(f"unknown account id {account_id}")

    def update(self, account_id: str, **fields) -> dict:
        a = self.get(account_id)
        event = fields.pop("event", None)
        for k, v in fields.items():
            a[k] = v
        if event:
            self._audit(account_id, event, "; ".join(f"{k}={fields[k]}" for k in fields)[:400])
        self.save()
        return a

    def set_status(self, account_id: str, status: str, detail: str = "") -> dict:
        if status not in STATUSES:
            raise AccountStoreError(f"invalid status {status}")
        a = self.update(account_id, status=status, event=f"status->{status}", detail=detail)
        if status == "verified":
            a["verified_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if status == "active":
            a["last_active_at"] = a.get("verified_at") or a["created_at"]
        self.save()
        return a

    # ---------- views ----------
    @staticmethod
    def redact(account: dict, include_password: bool = False) -> dict:
        out = {k: v for k, v in account.items() if k not in SECRET_FIELDS}
        if include_password and "password" in account:
            out["password"] = account["password"]
        return out

    def list(self, redact: bool = True) -> list[dict]:
        rows = [a if not redact else self.redact(a) for a in self.data.get("accounts", [])]
        for r in rows:
            r.pop("audit", None)
        return rows

    def audit_tail(self, n: int = 50) -> list[dict]:
        return self.data.get("audit", [])[-n:]

    def count_by_status(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for a in self.data.get("accounts", []):
            c[a["status"]] = c.get(a["status"], 0) + 1
        return c
