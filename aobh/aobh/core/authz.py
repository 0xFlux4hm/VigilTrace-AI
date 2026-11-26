"""authz.py — the agent-side authorization gate (defense in depth).

The Java bridge is the ENFORCEMENT point for scope (ScopeGuard refuses
out-of-scope sends and counts refusals). This module is the agent-side gate
that runs BEFORE anything is sent, plus the registry bookkeeping the
`add_to_scope` / `remove_from_scope` / `get_scope` tools surface:

  * ScopeRegistry — authorized prefixes with provenance (who authorized, when),
    persisted to the engagement dir, plus explicit exclusions.
  * covers() — prefix matching with scheme/host normalization; no wildcard
    magic: a registry entry covers exactly its literal prefix.
  * BridgeGuard — wraps BridgeClient.request and refuses anything the
    registry doesn't cover. The bridge re-checks: fail closed twice.
  * tier gating — tier 3 (invasive) actions must reference an APPROVED
    request_approval record; the orchestrator's approval gate is authoritative,
    this is the second line.

Everything here fails closed: an empty registry authorizes nothing.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

TIERS = {
    0: "passive / read-only",
    1: "active, non-invasive",
    2: "active, may create test data",
    3: "invasive — requires an APPROVED request_approval record",
}


class AuthorizationError(Exception):
    """Raised by the gate; carries an envelope-style error + hint."""

    def __init__(self, error: str, hint: str = ""):
        super().__init__(error)
        self.error = error
        self.hint = hint


@dataclass
class ScopeEntry:
    prefix: str                 # normalized: scheme://host[:port]/path-prefix
    added_from: str             # provenance: "scope.md line 3", "operator", ...
    enabled: bool = True
    added_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


def _normalize_prefix(prefix: str) -> str:
    p = prefix.strip().rstrip("/")
    if "://" not in p:
        p = "https://" + p
    parts = urlsplit(p)
    host = (parts.hostname or "").lower()
    if not host:
        raise AuthorizationError("bad_scope_prefix", f"cannot parse prefix {prefix!r}")
    port = parts.port
    if port is not None and not ((parts.scheme == "http" and port == 80) or (parts.scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    return f"{parts.scheme}://{host}{parts.path.rstrip('/')}"


def _normalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    port = parts.port
    if port is not None and not ((parts.scheme == "http" and port == 80) or (parts.scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    return f"{parts.scheme}://{host}{parts.path or '/'}"


class ScopeRegistry:
    """Persisted registry of authorized prefixes + exclusions (JSON document)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.entries: list[ScopeEntry] = []
        self.exclusions: list[str] = []
        if self.path.exists():
            try:
                doc = json.loads(self.path.read_text(encoding="utf-8"))
                self.entries = [ScopeEntry(**e) for e in doc.get("entries", [])]
                self.exclusions = list(doc.get("exclusions", []))
            except (json.JSONDecodeError, TypeError):
                # a corrupt registry authorizes nothing (fail closed)
                self.entries, self.exclusions = [], []

    # ------------------------------------------------------------ state

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        doc = {"entries": [asdict(e) for e in self.entries], "exclusions": self.exclusions}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        tmp.replace(self.path)

    # ------------------------------------------------------------ ops

    def add(self, prefix: str, added_from: str, enabled: bool = True) -> ScopeEntry:
        norm = _normalize_prefix(prefix)
        for e in self.entries:
            if e.prefix == norm:
                e.added_from = added_from or e.added_from
                e.enabled = enabled
                return e
        entry = ScopeEntry(prefix=norm, added_from=added_from or "unspecified", enabled=enabled)
        self.entries.append(entry)
        return entry

    def remove(self, prefix: str, drop_from_registry: bool = False) -> dict:
        """Exclude a prefix from authorization. The registry entry is kept as
        provenance by default (drop_from_registry=false — 'only if it was never
        authorized'); exclusions are checked BEFORE coverage, so removal always
        stops authorization regardless."""
        norm = _normalize_prefix(prefix)
        if norm not in self.exclusions:
            self.exclusions.append(norm)
        size_before = len(self.entries)
        if drop_from_registry:
            self.entries = [e for e in self.entries if e.prefix != norm]
        return {"excluded": norm, "registry_size_before": size_before,
                "registry_size": len(self.entries)}

    def covers(self, url: str) -> bool:
        """True iff some enabled entry's prefix covers url and url is not
        excluded. Exclusions win over coverage."""
        target = _normalize_url(url)
        if any(target.startswith(_normalize_prefix(x)) or target == _normalize_prefix(x) for x in self.exclusions):
            return False
        for e in self.entries:
            if not e.enabled:
                continue
            if target.startswith(e.prefix + "/") or target == e.prefix or target.startswith(e.prefix + "?"):
                return True
        return False

    def assert_authorized(self, url: str, action: str = "send") -> None:
        if not self.covers(url):
            raise AuthorizationError(
                "out_of_scope",
                f"{action} to {url} is not covered by the engagement authorization. "
                "add_to_scope(url_prefix, added_from=<provenance>) first, or correct the URL.")

    def summary(self) -> dict:
        return {"entries": [asdict(e) for e in self.entries],
                "exclusions": list(self.exclusions),
                "covers_anything": bool(self.entries)}


def parse_scope_md(path: str | Path) -> list[dict]:
    """Parse an operator scope file (see examples/scope.md): lines under the
    'in scope' heading are authorized prefixes with the line number as
    provenance; commented lines and the 'out of scope' section are ignored."""
    entries: list[dict] = []
    in_scope = False
    for lineno, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        lowered = line.lower()
        if re.match(r"^#{1,6}\s.*(in scope)", lowered):
            in_scope = True
            continue
        if re.match(r"^#{1,6}\s.*(out of scope|out-of-scope)", lowered):
            in_scope = False
            continue
        if line.startswith("#") or line.startswith(";"):
            continue
        if in_scope:
            prefix = line.split()[0]
            try:
                entries.append({"prefix": _normalize_prefix(prefix), "added_from": f"scope.md line {lineno}"})
            except AuthorizationError:
                continue  # unparseable lines never authorize anything
    return entries


class BridgeGuard:
    """Wraps a BridgeClient and refuses to send anything the registry doesn't
    cover. The bridge re-checks on its side — defense in depth, not trust."""

    def __init__(self, client, registry: ScopeRegistry):
        self.client = client
        self.registry = registry

    def request(self, method: str, url: str, **kw) -> dict:
        self.registry.assert_authorized(url, action=f"{method.upper()} {url}")
        return self.client.request(method, url, **kw)

    def __getattr__(self, name):  # delegate the rest (health, list_tools, ...)
        return getattr(self.client, name)
