"""config.py — environment-first configuration for AOBH.

Every module of the previous stack read its own env vars; all of those names
keep working unchanged (tests and operator scripts rely on them). This module
is the documented map plus typed accessors for new code (CLI, server, authz).

An optional .env file (AOBH_ENV or ./.env) is loaded once via load_env_file();
existing environment variables always win over the file. Values are secrets
(bridge token, vault key, IMAP password) and are never logged anywhere.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_ENV_KEYS = {
    "engagement_dir": ("ATAP_ENGAGEMENT_DIR", "./engagement"),
    "bridge_url": ("BURP_BRIDGE_URL", "http://127.0.0.1:8787"),
    "bridge_token": ("BURP_BRIDGE_TOKEN", ""),
    "allow_direct": ("ATAP_ALLOW_DIRECT", "0"),
    "vault_key": ("ATAP_VAULT_KEY", ""),
    "imap_host": ("ATAP_IMAP_HOST", ""),
    "imap_port": ("ATAP_IMAP_PORT", ""),
    "imap_user": ("ATAP_IMAP_USER", ""),
    "imap_pass": ("ATAP_IMAP_PASS", ""),
    "imap_mailbox": ("ATAP_IMAP_MAILBOX", ""),
    "mailcatch_port": ("ATAP_MAILCATCH_PORT", "8025"),
    "rag_index_path": ("H1_INDEX_PATH", ""),
    "rag_csv_path": ("H1_CSV_PATH", ""),
    "waf_probe_max": ("WAF_PROBE_MAX", "16"),
    "waf_bypass_max": ("WAF_BYPASS_MAX", "24"),
    "captcha_service_url": ("CAPTCHA_SERVICE_URL", "https://2captcha.com"),
    "captcha_service_key": ("CAPTCHA_SERVICE_KEY", ""),
    "captcha_max_solves": ("CAPTCHA_MAX_SOLVES", "5"),
}


@dataclass
class Config:
    engagement_dir: Path
    bridge_url: str
    bridge_token: str
    allow_direct: bool
    vault_key: str
    imap_host: str
    imap_port: str
    imap_user: str
    imap_pass: str
    imap_mailbox: str
    mailcatch_port: int
    rag_index_path: Path
    rag_csv_path: Path
    waf_probe_max: int
    waf_bypass_max: int
    captcha_service_url: str
    captcha_service_key: str
    captcha_max_solves: int

    def redacted(self) -> dict:
        """Safe view for doctor/logs: secrets replaced by presence markers."""
        return {
            "engagement_dir": str(self.engagement_dir),
            "bridge_url": self.bridge_url,
            "bridge_token": "set" if self.bridge_token else "UNSET (bridge stays off)",
            "allow_direct": self.allow_direct,
            "vault_key": "set" if self.vault_key else "unset (.vault_key file will be used)",
            "imap_host": self.imap_host or "unset",
            "mailcatch_port": self.mailcatch_port,
            "rag_index_path": str(self.rag_index_path) if self.rag_index_path else "bundled default",
            "waf_probe_max": self.waf_probe_max,
            "waf_bypass_max": self.waf_bypass_max,
            "captcha_service_url": self.captcha_service_url,
            "captcha_service_key": "set (automated solving enabled)" if self.captcha_service_key else "UNSET (human strategies only)",
            "captcha_max_solves": self.captcha_max_solves,
        }


def load_env_file(path: str | os.PathLike | None = None) -> int:
    """Load KEY=VALUE lines into os.environ (existing vars win). Returns the
    number of variables applied. No quoting expansion, no shell interpolation."""
    if path is None:
        path = os.environ.get("AOBH_ENV", "") or Path.cwd() / ".env"
    p = Path(path)
    if not p.exists():
        return 0
    applied = 0
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key and key not in os.environ:
            os.environ[key] = value
            applied += 1
    return applied


def get_config() -> Config:
    def _int(key: str) -> int:
        try:
            return int(os.environ.get(_ENV_KEYS[key][0], "") or _ENV_KEYS[key][1])
        except ValueError:
            return int(_ENV_KEYS[key][1])

    def _path(key: str) -> Path:
        raw = os.environ.get(_ENV_KEYS[key][0], "") or _ENV_KEYS[key][1]
        return Path(raw) if raw else None  # type: ignore[return-value]

    return Config(
        engagement_dir=Path(_env("ATAP_ENGAGEMENT_DIR", "") or Path.cwd() / "engagement"),
        bridge_url=_env("BURP_BRIDGE_URL", "http://127.0.0.1:8787"),
        bridge_token=_env("BURP_BRIDGE_TOKEN", ""),
        allow_direct=_env("ATAP_ALLOW_DIRECT", "0") == "1",
        vault_key=_env("ATAP_VAULT_KEY", ""),
        imap_host=_env("ATAP_IMAP_HOST", ""),
        imap_port=_env("ATAP_IMAP_PORT", ""),
        imap_user=_env("ATAP_IMAP_USER", ""),
        imap_pass=_env("ATAP_IMAP_PASS", ""),
        imap_mailbox=_env("ATAP_IMAP_MAILBOX", ""),
        mailcatch_port=_int("mailcatch_port"),
        rag_index_path=_path("rag_index_path"),
        rag_csv_path=_path("rag_csv_path"),
        waf_probe_max=_int("waf_probe_max"),
        waf_bypass_max=_int("waf_bypass_max"),
        captcha_service_url=_env("CAPTCHA_SERVICE_URL", "https://2captcha.com"),
        captcha_service_key=_env("CAPTCHA_SERVICE_KEY", ""),
        captcha_max_solves=_int("captcha_max_solves"),
    )


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)
