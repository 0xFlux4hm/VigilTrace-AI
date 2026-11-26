"""core — configuration, the Burp bridge client, the authorization gate, utils.

Every engine imports from here instead of re-implementing plumbing:

  config.get_config()  env-first configuration (all legacy env names keep working)
  bridge.BridgeClient  the ONLY way target-facing HTTP leaves this codebase
  authz.ScopeRegistry  agent-side scope registry + BridgeGuard (defense in depth;
                       the Java bridge is the enforcement point)
  utils                ids, timestamps, response envelopes, atomic JSON writes
"""

from aobh.core.bridge import BridgeClient, BridgeError, default_bridge
from aobh.core.config import Config, get_config, load_env_file
from aobh.core.utils import append_jsonl, atomic_write_json, canonical_json, err, new_id, ok, truncate, utcnow_iso

__all__ = [
    "BridgeClient",
    "BridgeError",
    "Config",
    "default_bridge",
    "append_jsonl",
    "atomic_write_json",
    "canonical_json",
    "err",
    "get_config",
    "load_env_file",
    "new_id",
    "ok",
    "truncate",
    "utcnow_iso",
]
