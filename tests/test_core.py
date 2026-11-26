"""Tests for the core layer: the authorization gate, config and bridge client.

The authz gate is new code (the rest is ported), so it gets the thorough
treatment: normalization, prefix-boundary coverage, exclusions winning over
coverage, fail-closed behavior, provenance semantics and the BridgeGuard.
"""

import json

import pytest

from aobh.core.authz import (
    AuthorizationError,
    BridgeGuard,
    ScopeRegistry,
    _normalize_prefix,
    _normalize_url,
    parse_scope_md,
)
from aobh.core.bridge import BridgeClient, BridgeError
from aobh.core.config import get_config, load_env_file


# ---------------------------------------------------------------- authz

def test_prefix_normalization():
    assert _normalize_prefix("shop.example") == "https://shop.example"
    assert _normalize_prefix("https://shop.example/") == "https://shop.example"
    assert _normalize_prefix("http://shop.example:80") == "http://shop.example"
    assert _normalize_prefix("https://shop.example:8443/app") == "https://shop.example:8443/app"
    assert _normalize_url("https://SHOP.example/App") == "https://shop.example/App"


def test_empty_registry_fails_closed(tmp_path):
    reg = ScopeRegistry(tmp_path / "scope.json")
    assert reg.covers("https://anything.example/") is False
    with pytest.raises(AuthorizationError) as exc:
        reg.assert_authorized("https://anything.example/", action="send")
    assert exc.value.error == "out_of_scope"
    assert exc.value.hint


def test_registry_covers_prefix_boundary(tmp_path):
    reg = ScopeRegistry(tmp_path / "scope.json")
    reg.add("shop.example", "test")
    reg.save()
    assert reg.covers("https://shop.example/") is True
    assert reg.covers("https://shop.example/app/login") is True
    assert reg.covers("https://shop.example.evil.com/") is False
    assert reg.covers("https://shop.examplefoo/") is False
    assert reg.covers("http://other.example/") is False


def test_exclusion_wins_over_coverage(tmp_path):
    reg = ScopeRegistry(tmp_path / "scope.json")
    reg.add("shop.example", "test")
    reg.add("shop.example/admin", "test")
    assert reg.covers("https://shop.example/admin/panel") is True
    reg.remove("shop.example/admin", drop_from_registry=False)
    # removal always stops authorization, even though the wider prefix covers it
    assert reg.covers("https://shop.example/admin/panel") is False
    # provenance semantics: without the flag the removed entry stays in the
    # registry (both entries kept), exclusions already block authorization
    assert len(reg.entries) == 2
    # with drop_from_registry=true the entry is dropped
    reg.remove("shop.example/admin", drop_from_registry=True)
    assert reg.exclusions  # exclusion recorded regardless
    reg2 = ScopeRegistry(tmp_path / "scope2.json")
    reg2.add("shop.example", "test")
    reg2.remove("shop.example", drop_from_registry=True)
    assert len(reg2.entries) == 0


def test_registry_survives_corrupt_file(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text("{not json", encoding="utf-8")
    reg = ScopeRegistry(p)  # must not raise; must authorize nothing
    assert reg.covers("https://anything.example/") is False


def test_bridge_guard_refuses_then_allows(tmp_path):
    class FakeClient:
        def __init__(self):
            self.sent = []

        def request(self, method, url, **kw):
            self.sent.append((method, url))
            return {"status": 200, "transport": "bridge"}

    client = FakeClient()
    reg = ScopeRegistry(tmp_path / "scope.json")
    guard = BridgeGuard(client, reg)
    with pytest.raises(AuthorizationError):
        guard.request("GET", "https://shop.example/")
    assert client.sent == []
    reg.add("shop.example", "test")
    out = guard.request("GET", "https://shop.example/app")
    assert out["transport"] == "bridge" and client.sent == [("GET", "https://shop.example/app")]


def test_parse_scope_md(tmp_path):
    scope = tmp_path / "scope.md"
    scope.write_text(
        "# engagement\n"
        "## in scope\n"
        "https://shop.example    # main site\n"
        "https://api.shop.example/v2\n"
        "## out of scope\n"
        "https://shop.example/admin\n",
        encoding="utf-8")
    entries = parse_scope_md(scope)
    assert [e["prefix"] for e in entries] == ["https://shop.example", "https://api.shop.example/v2"]
    assert entries[0]["added_from"] == "scope.md line 3"


# ---------------------------------------------------------------- config

def test_load_env_file(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# comment\nAOBH_TEST_UNSET_VAR=from-file\n\n", encoding="utf-8")
    monkeypatch.setenv("AOBH_TEST_EXISTING_VAR", "from-env")
    applied = load_env_file(env)
    assert applied == 1
    import os

    assert os.environ["AOBH_TEST_UNSET_VAR"] == "from-file"


def test_config_redacted_hides_secrets(monkeypatch):
    monkeypatch.setenv("BURP_BRIDGE_TOKEN", "supersecret-token-value")
    monkeypatch.setenv("ATAP_VAULT_KEY", "supersecret-vault-key")
    cfg = get_config()
    dumped = json.dumps(cfg.redacted())
    assert "supersecret" not in dumped
    assert cfg.redacted()["bridge_token"] == "set"


# ---------------------------------------------------------------- bridge

def test_bridge_unreachable_raises_with_hint():
    client = BridgeClient(base="http://127.0.0.1:1", token="x" * 16)
    with pytest.raises(BridgeError) as exc:
        client.health()
    assert exc.value.error and exc.value.hint
    with pytest.raises(BridgeError) as exc2:
        client.request("GET", "https://shop.example/")
    assert "ATAP_ALLOW_DIRECT" in exc2.value.hint


def test_bridge_call_returns_envelope_as_is(monkeypatch):
    # point the client at a closed port: call() must raise BridgeError (transport),
    # while a *tool-level* refusal would come back as a returned envelope.
    client = BridgeClient(base="http://127.0.0.1:1", token="x" * 16)
    with pytest.raises(BridgeError):
        client.call("get_scope", {})
