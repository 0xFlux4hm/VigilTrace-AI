#!/usr/bin/env python3
"""manager.py — Autonomous Test Account Provisioning: the AtapCore engine for the 8 atap_* tools.

Lifecycle: policy_check → create_account → verify_account → login → get_session /
account_health (maintenance) → cleanup. All target-facing HTTP goes through the
Burp bridge (`send_http_request`), so account provisioning stays inside the same
enforcement perimeter as the hunting traffic: scope gate, rate limit, audit log,
notes — visible in Burp's history. A direct-HTTP fallback exists only for local
labs (ATAP_ALLOW_DIRECT=1) and is flagged in every result.

Hard boundaries (enforced here, restated in SKILL.md §11):
  * NO CAPTCHA / anti-bot circumvention — if the signup or login flow is gated,
    the account is marked human_assisted and the flow stops.
  * NO SMS/phone automation — same fallback: human_assisted.
  * NO bulk creation — handlers cap total accounts per target (default 3).
  * Credentials live only in the encrypted vault; tool output is redacted.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from aobh.core.bridge import BridgeClient as _CoreBridgeClient, BridgeError

from aobh.atap.store import AccountStore, AccountStoreError
from aobh.atap.mailcatch import MailCatcher, imap_fetch_links
from aobh.atap.vault import generate_password

ENGAGEMENT_DIR = Path(os.environ.get("ATAP_ENGAGEMENT_DIR", Path.cwd() / "engagement"))
CAPTCHA_MARKERS = ["captcha", "recaptcha", "hcaptcha", "turnstile", "are you human",
                   "robot check", "challenge-platform", "cf-chl", "just a moment"]
ANTIABOT_MARKERS = ["cloudflare", "incapsula", "akamai", "datadome", "perimeterx", "px-captcha"]
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+")


class AtapError(Exception):
    def __init__(self, error: str, hint: str = ""):
        super().__init__(error)
        self.error, self.hint = error, hint


def _env(name: str, default=None):
    return os.environ.get(name, default)


# ---------------------------------------------------------------------------
# Bridge client — ALL target traffic flows through Burp
# ---------------------------------------------------------------------------

class BridgeClient(_CoreBridgeClient):
    """ATAP's bridge client — the identical send_http_request wire API, reused
    from aobh.core.bridge. Only difference: transport failures surface as
    AtapError (the old atap_core.BridgeClient contract that the tool dispatch
    maps to {ok: false, error, hint}). The engine uses request() only."""

    def request(self, method: str, url: str, headers: list[dict] | None = None,
                body: str | None = None, note: str = "", timeout: int = 60) -> dict:
        try:
            return super().request(method, url, headers=headers, body=body,
                                   note=note, timeout=timeout)
        except BridgeError as e:
            raise AtapError(e.error, e.hint) from e


def _header_value(resp: dict, name: str) -> str | None:
    for h in resp.get("headers", []):
        if h.get("name", "").lower() == name.lower():
            return h.get("value")
    return None


def _cookie_pairs(resp: dict) -> list[tuple[str, str]]:
    pairs = []
    for h in resp.get("headers", []):
        if h.get("name", "").lower() != "set-cookie":
            continue
        first = h.get("value", "").split(";")[0]
        if "=" in first:
            k, v = first.split("=", 1)
            pairs.append((k.strip(), v.strip()))
    return pairs


def _looks_like_botwall(resp: dict) -> str | None:
    blob = (str(resp.get("status")) + " " + (resp.get("body") or "")[:3000]).lower()
    for m in CAPTCHA_MARKERS:
        if m in blob:
            return f"captcha/anti-bot marker '{m}' in response"
    for m in ANTIABOT_MARKERS:
        if m in blob and resp.get("status") in (403, 429, 503):
            return f"anti-bot service marker '{m}' with status {resp.get('status')}"
    return None


def _extract_token(body: str) -> str | None:
    m = re.search(r'"(?:access_token|token|jwt|session_token|sessionId)"\s*:\s*"([^"\s]{8,})"', body or "")
    return m.group(1) if m else None


def _mail() -> MailCatcher:
    global _MAILCATCHER
    if _MAILCATCHER is None:
        _MAILCATCHER = MailCatcher(_env("ATAP_MAILCATCH_HOST", "127.0.0.1"),
                                   int(_env("ATAP_MAILCATCH_PORT", "8025")),
                                   mail_dir=ENGAGEMENT_DIR / "mail")
    return _MAILCATCHER


def _ensure_catcher() -> dict:
    """Start the local SMTP catcher on demand (idempotent)."""
    global _CATCHER_STARTED
    m = _mail()
    if not _CATCHER_STARTED:
        m.start_in_thread()
        _CATCHER_STARTED = True
        time.sleep(0.3)  # give the loop a beat to bind
    return {"host": m.host, "port": m.port}


_MAILCATCHER: MailCatcher | None = None
_CATCHER_STARTED = False


# ---------------------------------------------------------------------------
# Handlers — one per MCP tool
# ---------------------------------------------------------------------------

class AtapCore:
    def __init__(self, bridge: BridgeClient | None = None):
        self.bridge = bridge or BridgeClient()

    def _store(self) -> AccountStore:
        return AccountStore(ENGAGEMENT_DIR)

    # ---- 1. policy_check ----
    def policy_check(self, policy_text: str = "", program_url: str = "",
                     accounts_needed: int = 3) -> dict:
        text = (policy_text or "").lower()
        allow = any(k in text for k in ["multiple test accounts", "test accounts", "dedicated testing accounts",
                                        "create an account", "accounts for testing", "trial accounts allowed"])
        deny = any(k in text for k in ["do not create accounts", "no multiple accounts", "one account per",
                                       "do not register", "prohibited from creating"])
        verdict = ("explicit-allow" if allow and not deny else
                   "explicit-deny" if deny else "unknown")
        return {"ok": True, "data": {
            "verdict": verdict,
            "meaning": {
                "explicit-allow": "policy permits test accounts — proceed, cite the policy phrase",
                "explicit-deny": "policy forbids creating accounts — use only accounts the program hands you",
                "unknown": "policy silent — ask the operator ONCE (bootstrap is the only question window) or use provided accounts",
            }[verdict],
            "accounts_needed": accounts_needed,
            "strategy_defaults": {
                "imap": "preferred for real targets (dedicated test inbox, plus-addressing)",
                "catcher": "local labs only (SMTP catcher on 127.0.0.1)",
                "manual": "fallback when mail automation is impossible",
            },
            "boundaries": [
                "max 3 accounts per target; create only what differential testing requires",
                "no CAPTCHA/anti-bot/SMS circumvention — ever (marked human_assisted instead)",
                "dedicated test mailbox with generated identity; zero real-person PII",
                "every account is disclosed in the final report and cleaned up at close-out",
            ],
            "program_url": program_url,
        }}

    # ---- 2. create_account ----
    def create_account(self, target: str, authorization_reference: str, role_tag: str = "A",
                       signup_endpoint: str | None = None, email_strategy: str = "auto",
                       email: str | None = None, username: str | None = None,
                       fields: dict | None = None, content_type: str = "form") -> dict:
        if not authorization_reference or len(authorization_reference) < 10:
            raise AtapError("authorization_reference required",
                            "Cite where permission comes from (e.g. 'scope.md #accounts: program policy "
                            "explicitly allows multiple test accounts'). No reference — no account.")
        store = self._store()
        same_target = [a for a in store.list() if a.get("target") == target
                       and a["status"] not in ("deleted", "cleaned_up")]
        if len(same_target) >= int(_env("ATAP_MAX_ACCOUNTS", "3")):
            raise AtapError(f"account cap reached for {target}",
                            "Differential testing needs 2-3 accounts, not more. Use the existing ones "
                            "(atap_list_accounts) or justify a higher cap to the operator.")

        account_id = store.next_id()
        uname = username or f"atap_{role_tag.lower()}_{account_id.lower().replace('acc-', '')}"
        pwd = generate_password()
        strategy = email_strategy
        if strategy == "auto":
            strategy = "imap" if _env("ATAP_IMAP_HOST") else "catcher" if _env("ATAP_USE_CATCHER", "0") == "1" else "manual"

        acct_email = email
        if not acct_email:
            if strategy == "catcher":
                acct_email = f"{uname}@catcher.local"
            elif strategy == "imap" and _env("ATAP_IMAP_USER"):
                base = _env("ATAP_IMAP_USER")
                acct_email = base.split("@")[0] + f"+{uname}@" + base.split("@")[1]
            else:
                acct = store.create({
                    "id": account_id, "target": target, "role_tag": role_tag,
                    "username": uname, "email": None, "password": pwd, "strategy": "manual",
                    "status": "human_assisted", "notes": "email required — provide one manually"})
                raise AtapError(f"{account_id}: no email available for strategy '{strategy}'",
                                "Set ATAP_IMAP_HOST/ATAP_IMAP_USER (+PASSWORD), enable ATAP_USE_CATCHER=1, "
                                "or pass email=/email_strategy='manual' with your own test address. "
                                f"Record created as {account_id} (human_assisted).")

        signup_url = signup_endpoint or f"{target.rstrip('/')}/signup"
        if strategy == "catcher":
            _ensure_catcher()
        form = dict(fields or {})
        form.update({"username": uname, "email": acct_email, "password": pwd,
                     "password_confirmation": form.get("password_confirmation", pwd)})
        body = json.dumps(form) if content_type == "json" else "&".join(
            f"{k}={_form_quote(v)}" for k, v in form.items())
        note = f"ATAP signup {account_id} ({role_tag}) for {target}"
        resp = self.bridge.request("POST", signup_url,
                                   headers=[{"name": "Content-Type",
                                             "value": "application/json" if content_type == "json"
                                             else "application/x-www-form-urlencoded"}],
                                   body=body, note=note)
        botwall = _looks_like_botwall(resp)
        record = {
            "id": account_id, "target": target, "role_tag": role_tag,
            "username": uname, "email": acct_email, "password": pwd, "strategy": strategy,
            "signup_endpoint": signup_url, "login_endpoint": None, "cleanup_endpoint": None,
            "session_cookies": None, "session_token": None, "notes": "",
        }
        if botwall:
            record.update(status="human_assisted", notes=f"blocked: {botwall}")
            acct = store.create(record)
            return {"ok": True, "data": {"account": store.redact(acct), "signup_status": resp.get("status"),
                                         "blocked_reason": botwall,
                                         "next": "Complete this signup manually (or with the program's help); "
                                                 "then atap_verify_account / atap_login. NO bypass attempts."}}
        blob = (resp.get("body") or "").lower()
        if resp.get("status") in (200, 201, 302):
            mail_hint = any(k in blob for k in ["verify", "confirmation", "activate", "check your email"])
            record["status"] = "awaiting_verification" if mail_hint else "created"
        else:
            record["status"] = "created"
            record["notes"] = f"signup returned HTTP {resp.get('status')} — inspect before proceeding"
        acct = store.create(record)
        return {"ok": True, "data": {"account": store.redact(acct), "signup_status": resp.get("status"),
                                     "bridge_id": resp.get("id"), "transport": resp.get("transport"),
                                     "next": ("atap_verify_account (confirmation email expected)"
                                              if record["status"] == "awaiting_verification"
                                              else "atap_login")} if record["status"] != "human_assisted"
                            else {"next": "manual completion required"}}

    # ---- 3. verify_account ----
    def verify_account(self, account_id: str, wait_seconds: int = 90,
                       verification_link: str | None = None) -> dict:
        store, acct = self._store(), None
        acct = store.get(account_id)
        if acct["status"] in ("verified", "active"):
            return {"ok": True, "data": {"account": store.redact(acct), "already": True}}
        link = verification_link
        source_info = {}
        if not link:
            if acct["strategy"] == "catcher":
                msg = _mail().wait_for_message(recipient_contains=acct["email"], timeout=wait_seconds)
                if not msg:
                    raise AtapError(f"no mail caught for {acct['email']} in {wait_seconds}s",
                                    "Is the catcher reachable at the address the target sends to? "
                                    "Fallback: atap_verify_account(verification_link=...) after manual pickup.")
                link = _pick_link(msg.get("links", []), acct["target"])
                source_info = {"mail_id": msg["id"], "subject": msg["subject"]}
            elif acct["strategy"] == "imap":
                res = imap_fetch_links(_env("ATAP_IMAP_HOST"), _env("ATAP_IMAP_USER"), _env("ATAP_IMAP_PASS") or "",
                                       _env("ATAP_IMAP_MAILBOX", "INBOX"),
                                       recipient_contains=acct["email"])
                cands = [l for m in res["messages"] for l in m["links"]]
                link = _pick_link(cands, acct["target"])
                source_info = {"messages_seen": len(res["messages"])}
                if not link:
                    raise AtapError("no verification link found in IMAP mailbox",
                                    "Check ATAP_IMAP_* config; fallback: manual link.")
            else:
                raise AtapError("strategy is 'manual' — pass verification_link",
                                "Ask the operator to open the test inbox and paste the verification URL.")
        if not link:
            raise AtapError("no verification link identified",
                            "Pass it manually: atap_verify_account(verification_link='https://...').")
        resp = self.bridge.request("GET", link, note=f"ATAP verify {account_id}")
        blob = (resp.get("body") or "").lower()
        ok = resp.get("status") == 200 and not any(k in blob for k in ["invalid", "expired", "already used", "error"])
        acct = store.set_status(account_id, "verified" if ok else "created",
                                f"verify via {link[:120]} {'OK' if ok else 'UNRESOLVED'}")
        acct = store.update(account_id, verification_link=link)
        return {"ok": True, "data": {"account": store.redact(acct), "link_source": source_info or {"manual": True},
                                     "verify_status": resp.get("status"), "verified": ok,
                                     "next": "atap_login"}}

    # ---- 4. login ----
    def login(self, account_id: str, login_endpoint: str | None = None,
              field_map: dict | None = None, content_type: str = "form") -> dict:
        store = self._store()
        acct = store.get(account_id)
        url = login_endpoint or acct.get("login_endpoint") or f"{acct['target'].rstrip('/')}/login"
        fmap = field_map or {"username_field": "username", "password_field": "password"}
        form = {fmap.get("username_field", "username"): acct["username"],
                fmap.get("password_field", "password"): acct["password"]}
        form.update(field_map.get("extra", {}) if isinstance(field_map, dict) else {})
        body = json.dumps(form) if content_type == "json" else "&".join(
            f"{k}={_form_quote(v)}" for k, v in form.items())
        resp = self.bridge.request("POST", url,
                                   headers=[{"name": "Content-Type",
                                             "value": "application/json" if content_type == "json"
                                             else "application/x-www-form-urlencoded"}],
                                   body=body, note=f"ATAP login {account_id} ({acct['role_tag']})")
        botwall = _looks_like_botwall(resp)
        if botwall:
            store.set_status(account_id, "human_assisted", f"login blocked: {botwall}")
            raise AtapError(f"login blocked ({botwall})",
                            "No circumvention. Complete authentication manually, then store the session "
                            "via the operator — or use the program-provided credentials.")
        cookies = _cookie_pairs(resp)
        token = _extract_token(resp.get("body") or "")
        blob = (resp.get("body") or "").lower()
        success = resp.get("status") in (200, 302) and (
            cookies or token or any(k in blob for k in ["welcome", "dashboard", "logout", "sign out", "my account"]))
        if not success:
            store.set_status(account_id, "created", f"login failed HTTP {resp.get('status')}")
            raise AtapError(f"login did not produce a session (HTTP {resp.get('status')})",
                            "Check field names via the bridge history; wrong-password lockout risk — retry max once.")
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies) if cookies else None
        acct = store.update(account_id, login_endpoint=url, session_cookies=cookie_header,
                            session_token=token, event="login-ok")
        acct = store.set_status(account_id, "active")
        mask = (token[:6] + "…" + token[-4:]) if token else None
        return {"ok": True, "data": {"account": store.redact(acct), "cookies_captured": len(cookies),
                                     "token_masked": mask, "bridge_id": resp.get("id"),
                                     "next": "atap_get_session to use in send_http_request headers"}}

    # ---- 5. get_session ----
    def get_session(self, account_id: str, include_password: bool = False) -> dict:
        acct = self._store().get(account_id)
        if acct["status"] not in ("active", "verified") and not acct.get("session_cookies"):
            raise AtapError(f"{account_id} has no usable session (status: {acct['status']})",
                            "Run atap_login first.")
        return {"ok": True, "data": {
            "account_id": account_id, "status": acct["status"],
            "cookie_header": acct.get("session_cookies"),
            "authorization": f"Bearer {acct['session_token']}" if acct.get("session_token") else None,
            "username": acct["username"], "email": acct["email"], "role_tag": acct["role_tag"],
            "password": acct["password"] if include_password else None,
            "usage": "Pass cookie_header as a Cookie header (and authorization as an Authorization header) "
                     "into send_http_request / modify_and_resend_request. Sessions stay in the vault.",
        }}

    # ---- 6. account_health ----
    def account_health(self, account_id: str, check_endpoint: str | None = None,
                       auto_relogin: bool = True) -> dict:
        store, acct = self._store(), None
        acct = store.get(account_id)
        sess = self.get_session(account_id)
        hdrs = []
        if sess["data"]["cookie_header"]:
            hdrs.append({"name": "Cookie", "value": sess["data"]["cookie_header"]})
        if sess["data"]["authorization"]:
            hdrs.append({"name": "Authorization", "value": sess["data"]["authorization"]})
        url = check_endpoint or acct["target"].rstrip("/") + "/"
        resp = self.bridge.request("GET", url, headers=hdrs, note=f"ATAP health {account_id}")
        status = resp.get("status")
        if status in (401, 403):
            if auto_relogin and acct.get("login_endpoint"):
                try:
                    self.login(account_id)
                    return self.account_health(account_id, check_endpoint, auto_relogin=False)
                except AtapError as e:
                    store.set_status(account_id, "expired", f"re-login failed: {e.error}")
                    return {"ok": True, "data": {"account_id": account_id, "healthy": False,
                                                 "status_code": status, "action": "relogin_failed",
                                                 "detail": e.error}}
            store.set_status(account_id, "expired", f"health check HTTP {status}")
            return {"ok": True, "data": {"account_id": account_id, "healthy": False, "status_code": status,
                                         "action": "marked_expired", "next": "atap_login or manual re-auth"}}
        healthy = status and 200 <= status < 400
        store.update(account_id, last_health=f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} HTTP {status}",
                     event="health-check")
        return {"ok": True, "data": {"account_id": account_id, "healthy": bool(healthy),
                                     "status_code": status, "transport": resp.get("transport")}}

    # ---- 7. list_accounts ----
    def list_accounts(self, include_audit: bool = False) -> dict:
        store = self._store()
        rows = store.list(redact=True)
        out: dict = {"accounts": rows, "counts_by_status": store.count_by_status()}
        if include_audit:
            out["audit_tail"] = store.audit_tail(30)
        return {"ok": True, "data": out}

    # ---- 8. cleanup ----
    def cleanup(self, account_ids: list[str] | None = None, dry_run: bool = False) -> dict:
        store = self._store()
        targets = [a for a in store.list(redact=False)
                   if (not account_ids or a["id"] in account_ids)
                   and a["status"] not in ("deleted", "cleaned_up")]
        results = []
        for acct in targets:
            entry = {"account_id": acct["id"], "target": acct["target"], "action": "none"}
            endpoint = acct.get("cleanup_endpoint") or acct.get("settings_endpoint")
            if endpoint and not dry_run:
                hdrs = []
                if acct.get("session_cookies"):
                    hdrs.append({"name": "Cookie", "value": acct["session_cookies"]})
                if acct.get("session_token"):
                    hdrs.append({"name": "Authorization", "value": f"Bearer {acct['session_token']}"})
                try:
                    resp = self.bridge.request("DELETE", endpoint, headers=hdrs,
                                               note=f"ATAP cleanup {acct['id']}")
                    ok = resp.get("status") in (200, 202, 204)
                    store.set_status(acct["id"], "deleted" if ok else "human_assisted",
                                     f"cleanup DELETE {endpoint} -> HTTP {resp.get('status')}")
                    entry.update(action="delete_attempted", http_status=resp.get("status"),
                                 result="deleted" if ok else "manual_required")
                except AtapError as e:
                    store.set_status(acct["id"], "human_assisted", f"cleanup error: {e.error}")
                    entry.update(action="delete_attempted", result=f"error: {e.error}")
            else:
                if not dry_run:
                    store.set_status(acct["id"], "human_assisted",
                                     "cleanup: no self-service endpoint recorded")
                entry.update(action="manual_required" if not dry_run else "dry_run",
                             result="no cleanup endpoint known — record in report for operator")
            results.append(entry)
        remaining = [a for a in store.list() if a["status"] not in ("deleted", "cleaned_up")]
        return {"ok": True, "data": {
            "cleanup_results": results,
            "disclosure_block": _disclosure(store),
            "outstanding": [a["id"] for a in remaining],
            "note": "Disclose the disclosure_block in report.md §Scope & methodology and clean up "
                    "outstanding accounts per program policy at close-out.",
        }}


# ---------------------------------------------------------------------------
# engine singleton (the rag/server.py `atap()` pattern)
# ---------------------------------------------------------------------------

_ENGINE: AtapCore | None = None


def get_engine() -> AtapCore:
    """Process-wide AtapCore singleton — shared by the tool registry and the
    registrar/verifier/session slices. State is the vault-backed store, so
    separately constructed AtapCore() instances stay equivalent."""
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = AtapCore()
    return _ENGINE


def reset_engine() -> AtapCore:
    """Drop the singleton so the next get_engine() re-reads env/config."""
    global _ENGINE
    _ENGINE = None
    return get_engine()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _form_quote(v: str) -> str:
    from urllib.parse import quote
    return quote(str(v), safe="")


def _pick_link(links: list[str], target: str) -> str | None:
    host = target.split("//")[-1].split("/")[0].lower()
    kw = ["verify", "confirm", "activate", "token", "validate"]
    same_host_kw = [l for l in links if host in l.lower() and any(k in l.lower() for k in kw)]
    keyword = [l for l in links if any(k in l.lower() for k in kw)]
    same_host = [l for l in links if host in l.lower()]
    for pool in (same_host_kw, keyword, same_host, links):
        if pool:
            return pool[0]
    return None


def _disclosure(store: AccountStore) -> dict:
    rows = []
    for a in store.list():
        rows.append({"id": a["id"], "target": a["target"], "username": a["username"],
                     "email": a["email"], "role_tag": a["role_tag"], "status": a["status"],
                     "created": a.get("created_at")})
    return {"accounts_created": rows, "policy_reference": "see scope.md #accounts",
            "note": "test identities only — generated usernames/emails, no real-person PII"}


# ---------------------------------------------------------------------------
# MCP tool schemas (single source of truth, served by rag/server.py)
# ---------------------------------------------------------------------------

ATAP_TOOLS = [
    {
        "name": "atap_policy_check",
        "description": "Determine whether autonomous test-account provisioning is permitted for the target. "
                       "Parse the policy text collected at bootstrap (§2) and return a verdict (explicit-allow / "
                       "explicit-deny / unknown), the required boundaries (max 3 accounts, no CAPTCHA/anti-bot/SMS "
                       "circumvention, dedicated test mailbox, disclosure + cleanup) and the mail-strategy defaults. "
                       "MANDATORY before atap_create_account (checkpoint A-0). Tier 0 — no target traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "policy_text": {"type": "string", "description": "The program-policy excerpt about accounts, collected at bootstrap."},
                "program_url": {"type": "string", "description": "Program/policy URL for the audit trail."},
                "accounts_needed": {"type": "integer", "default": 3, "description": "How many accounts differential testing requires (2-3)."}
            }
        },
        "example": {"name": "atap_policy_check", "arguments": {"policy_text": "Researchers may create multiple test accounts for verification purposes", "accounts_needed": 2}},
        "returns": "verdict + meaning + boundaries + strategy defaults."
    },
    {
        "name": "atap_create_account",
        "description": "Create a test account on an in-scope target: generates credentials (username, strong "
                       "random password, strategy-appropriate email), submits the signup form through the Burp "
                       "bridge (scoped, rate-limited, annotated 'ATAP signup ACC-nn'), stores everything in the "
                       "encrypted vault, and detects bot-walls. If the flow is gated by CAPTCHA/anti-bot or needs "
                       "SMS, the account is marked human_assisted — NO circumvention is attempted. Requires an "
                       "authorization_reference citing where permission comes from. Cap: 3 accounts per target.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "In-scope base URL, e.g. https://app.example.com"},
                "authorization_reference": {"type": "string", "description": "Required. Where permission comes from, e.g. 'scope.md #accounts — program policy explicitly allows multiple test accounts'."},
                "role_tag": {"type": "string", "default": "A", "description": "Role label for differential testing (A/B/admin-candidate...)."},
                "signup_endpoint": {"type": "string", "description": "Full signup URL; default {target}/signup."},
                "email_strategy": {"type": "string", "enum": ["auto", "imap", "catcher", "manual"], "default": "auto", "description": "auto: IMAP if configured, catcher if enabled, else manual."},
                "email": {"type": "string", "description": "Explicit test email (manual strategy or override)."},
                "username": {"type": "string", "description": "Override generated username (atap_a_acc01 style by default)."},
                "fields": {"type": "object", "description": "Extra signup form fields (e.g. terms checkbox, invite code)."},
                "content_type": {"type": "string", "enum": ["form", "json"], "default": "form"}
            },
            "required": ["target", "authorization_reference"]
        },
        "example": {"name": "atap_create_account", "arguments": {"target": "https://app.example.com", "authorization_reference": "scope.md #accounts: policy allows multiple test accounts", "role_tag": "A"}},
        "returns": "account record (redacted), signup HTTP status, blocked_reason if bot-walled, next step."
    },
    {
        "name": "atap_verify_account",
        "description": "Complete email verification for a provisioned account: waits for the confirmation mail "
                       "(catcher or IMAP strategy), extracts the verification link, clicks it through the Burp "
                       "bridge, and confirms success. For the manual strategy (or any fallback), pass "
                       "verification_link collected by the operator. Never bypasses mail-flow checks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string", "description": "e.g. ACC-01"},
                "wait_seconds": {"type": "integer", "default": 90, "maximum": 600, "description": "How long to wait for the mail."},
                "verification_link": {"type": "string", "description": "Manual fallback: the URL from the verification email."}
            },
            "required": ["account_id"]
        },
        "example": {"name": "atap_verify_account", "arguments": {"account_id": "ACC-01"}},
        "returns": "account status (verified), link source, verify HTTP status, next step."
    },
    {
        "name": "atap_login",
        "description": "Authenticate a provisioned account through the Burp bridge and capture the session "
                       "(Set-Cookie pairs and/or bearer/JWT token from the response) into the encrypted vault. "
                       "Marks the account active. Bot-walled logins are refused without circumvention "
                       "(human_assisted). Max one retry — avoid lockout games.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string"},
                "login_endpoint": {"type": "string", "description": "Default {target}/login or stored endpoint."},
                "field_map": {"type": "object", "description": "Field-name overrides, e.g. {\"username_field\":\"email\",\"extra\":{\"otp\":\"123456\"}} (only from your own test device)."},
                "content_type": {"type": "string", "enum": ["form", "json"], "default": "form"}
            },
            "required": ["account_id"]
        },
        "example": {"name": "atap_login", "arguments": {"account_id": "ACC-01"}},
        "returns": "redacted account, cookies captured, masked token, next step."
    },
    {
        "name": "atap_get_session",
        "description": "Return ready-to-use session material for an account (Cookie header string, Authorization "
                       "bearer) so hunting tools (send_http_request / modify_and_resend_request / run_simple_fuzz) "
                       "can act as that role. Passwords are NOT included unless include_password=true. Sessions "
                       "stay in the vault; tool output is what the audit trail shows.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string"},
                "include_password": {"type": "boolean", "default": False, "description": "Reveal the generated password (e.g. to hand the account to the human)."}
            },
            "required": ["account_id"]
        },
        "example": {"name": "atap_get_session", "arguments": {"account_id": "ACC-01"}},
        "returns": "cookie_header, authorization, identity, usage note."
    },
    {
        "name": "atap_account_health",
        "description": "Maintenance: validate an account's session still works (authenticated GET through the "
                       "bridge); on 401/403 optionally re-login once and re-check (checkpoint A-2 — run before "
                       "each authenticated hunting batch). Marks the account expired when re-auth fails.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string"},
                "check_endpoint": {"type": "string", "description": "Cheap authenticated endpoint; default {target}/."},
                "auto_relogin": {"type": "boolean", "default": True}
            }
        },
        "example": {"name": "atap_account_health", "arguments": {"account_id": "ACC-02"}},
        "returns": "healthy, status_code, action taken (relogin/mark_expired/none)."
    },
    {
        "name": "atap_list_accounts",
        "description": "List every provisioned test account with lifecycle status (planned → created → "
                       "awaiting_verification → verified → active → expired → locked → cleaned_up/deleted), "
                       "counts by status, and optionally the audit tail. Redacted — no passwords/sessions.",
        "inputSchema": {
            "type": "object",
            "properties": {"include_audit": {"type": "boolean", "default": False}}
        },
        "example": {"name": "atap_list_accounts", "arguments": {}},
        "returns": "accounts[] + counts_by_status (+audit_tail)."
    },
    {
        "name": "atap_cleanup",
        "description": "End-of-engagement lifecycle management (checkpoint A-3): attempt self-service deletion/"
                       "deactivation for each account through the bridge, mark accounts that need manual "
                       "cleanup, and return a report-ready disclosure block (every account created, its identity "
                       "and final status). Run at close-out; paste disclosure_block into report.md §Scope & "
                       "methodology. dry_run=true previews without state changes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_ids": {"type": "array", "items": {"type": "string"}, "description": "Subset; default all non-cleaned accounts."},
                "dry_run": {"type": "boolean", "default": False}
            }
        },
        "example": {"name": "atap_cleanup", "arguments": {"dry_run": True}},
        "returns": "cleanup_results[], disclosure_block, outstanding ids, note."
    },
]
