"""bridge.py — the only way target-facing HTTP leaves this codebase.

All target traffic goes through the Burp "AI Agent Bridge" Montoya extension
(../extension), where the enforcement perimeter lives: scope gate, rate
limiter, traffic counters, audit notes. This client speaks the bridge's wire
contract (docs/bridge-protocol.md):

    GET  {base}/health          timeout 3s    -> {"ok": true, ...}
    GET  {base}/tools           timeout 5s    -> {"tools": [...]}
    POST {base}/tools/{name}    timeout 300s  -> {"ok": true, "data": ...}
                                               | {"ok": false, "error", "hint"}

Auth on every endpoint: ``Authorization: Bearer $BURP_BRIDGE_TOKEN``. The
bridge refuses any request carrying an ``Origin`` header or a non-local
``Host`` (no browser page may drive it) and never sends CORS headers; this
client is a plain API client and sends neither. POST envelopes with
``ok: false`` are returned as-is (the agent must read the hint); only
transport/auth/protocol problems raise :class:`BridgeError`.

``ATAP_ALLOW_DIRECT=1`` enables a direct-HTTP fallback for LOCAL LABS ONLY —
results are flagged ``transport=direct`` so nothing slips into a report as if
it had gone through Burp. Never enable it against a real engagement.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

HEALTH_TIMEOUT = 3.0
TOOLS_TIMEOUT = 5.0
CALL_TIMEOUT = 300.0


class BridgeError(Exception):
    """Transport, auth or protocol failure talking to the bridge."""

    def __init__(self, error: str, hint: str = ""):
        super().__init__(error)
        self.error = error
        self.hint = hint

    def __str__(self) -> str:
        return f"{self.error}: {self.hint}" if self.hint else self.error


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Direct-fallback parity with the bridge path (allow_redirects=False)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


class BridgeClient:
    """HTTP client for the Burp bridge (stdlib only, so every engine can use it).

    Args:
        base: bridge base URL; default env BURP_BRIDGE_URL.
        token: bearer token; default env BURP_BRIDGE_TOKEN.
        allow_direct: enable the lab-only direct fallback; default env
            ATAP_ALLOW_DIRECT=1.
    """

    def __init__(self, base: str | None = None, token: str | None = None,
                 allow_direct: bool | None = None):
        self.base = base if base is not None else os.environ.get("BURP_BRIDGE_URL", "http://127.0.0.1:8787")
        self.token = token if token is not None else os.environ.get("BURP_BRIDGE_TOKEN", "")
        self.allow_direct = (_env_flag("ATAP_ALLOW_DIRECT")) if allow_direct is None else bool(allow_direct)

    # ------------------------------------------------------------- wire

    def _headers(self, extra: dict | None = None) -> dict:
        hdrs = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"}
        hdrs.update(extra or {})
        return hdrs

    def _post(self, path: str, payload: dict, timeout: float) -> dict:
        req = urllib.request.Request(
            f"{self.base}{path}",
            data=json.dumps(payload).encode(),
            headers=self._headers(),
            method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())

    def _get(self, path: str, timeout: float) -> dict:
        req = urllib.request.Request(f"{self.base}{path}", headers=self._headers(), method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())

    # ------------------------------------------------------------- API

    def request(self, method: str, url: str, headers: list[dict] | None = None,
                body: str | None = None, note: str = "", timeout: int = 60) -> dict:
        """Send one HTTP request to a TARGET through Burp (send_http_request).
        Returns the bridge data dict with ``transport`` added."""
        payload = {"url": url, "method": method.upper(), "note": note,
                   "headers": headers or [], "timeout_seconds": max(5, min(timeout, 120))}
        if body is not None:
            payload["body"] = body
        try:
            env = self._post("/tools/send_http_request", payload, timeout + 10)
            if not env.get("ok"):
                raise BridgeError(f"bridge rejected request: {env.get('error')}",
                                  env.get("hint", "Check scope and bridge health."))
            out = env["data"]
            out["transport"] = "bridge"
            return out
        except BridgeError:
            raise
        except Exception as e:
            if not self.allow_direct:
                raise BridgeError(
                    f"Burp bridge unreachable ({e})",
                    "Start Burp with the AI Agent Bridge extension, or set ATAP_ALLOW_DIRECT=1 "
                    "for local labs only (direct HTTP, flagged in results).") from e
            return self._direct(method, url, headers, body, timeout)

    def get(self, url: str, **kw) -> dict:
        return self.request("GET", url, **kw)

    def post(self, url: str, body: str | None = None, **kw) -> dict:
        return self.request("POST", url, body=body, **kw)

    def call(self, name: str, arguments: dict | None = None, timeout: float = CALL_TIMEOUT) -> dict:
        """Generic bridge tool call: POST /tools/{name} with the arguments as
        payload. Returns the envelope as-is — a tool-level ``ok: false`` is
        returned, not raised (the agent must read the hint). Raises
        BridgeError only on transport/auth/protocol problems."""
        try:
            return self._post(f"/tools/{name}", dict(arguments or {}), timeout)
        except Exception as e:
            raise BridgeError(f"bridge unreachable ({e})",
                              "Is Burp running with the AI Agent Bridge extension? "
                              "Set BURP_BRIDGE_URL and BURP_BRIDGE_TOKEN.") from e

    def health(self) -> dict:
        """Bridge health + traffic counters (3s timeout)."""
        try:
            env = self._get("/health", HEALTH_TIMEOUT)
        except Exception as e:
            raise BridgeError(f"bridge unreachable ({e})",
                              "Is Burp running with the AI Agent Bridge extension?") from e
        if not env.get("ok"):
            raise BridgeError("bridge health check failed", str(env)[:200])
        return env

    def list_tools(self) -> list:
        """The bridge's served tool definitions (5s timeout)."""
        try:
            return self._get("/tools", TOOLS_TIMEOUT).get("tools", [])
        except Exception as e:
            raise BridgeError(f"bridge unreachable ({e})",
                              "Is Burp running with the AI Agent Bridge extension?") from e

    # ------------------------------------------------------- lab fallback

    def _direct(self, method: str, url: str, headers: list[dict] | None,
                body: str | None, timeout: int) -> dict:
        """LOCAL LABS ONLY: direct HTTP, bypassing Burp. Flagged transport=direct."""
        hdrs = {h.get("name", h.get("key", "")): h.get("value", "") for h in (headers or [])}
        req = urllib.request.Request(url, data=body.encode() if body is not None else None,
                                     headers=hdrs or {}, method=method.upper())
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(req, timeout=max(5, min(timeout, 120))) as resp:
                return {"status": resp.status, "headers": [(k, v) for k, v in resp.headers.items()],
                        "body": resp.read().decode(errors="replace")[:2_000_000], "transport": "direct"}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "headers": [(k, v) for k, v in e.headers.items()],
                    "body": e.read().decode(errors="replace")[:2_000_000], "transport": "direct"}
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise BridgeError(f"direct request failed ({e})",
                              "The lab fallback could not reach the target; "
                              "disable ATAP_ALLOW_DIRECT to go through Burp.") from e


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "0") == "1"


def default_bridge(**overrides) -> BridgeClient:
    """A BridgeClient wired from the environment (engines' default)."""
    return BridgeClient(**overrides)
