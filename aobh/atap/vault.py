#!/usr/bin/env python3
"""vault.py — encrypted credential store for ATAP (Autonomous Test Account Provisioning).

Threat model: protect test-account passwords/sessions at rest on the operator's
disk (engagement directory), with a key that is NOT in the same file. Zero
third-party dependencies: key derivation via hashlib.scrypt, encryption via an
HMAC-SHA256-CTR keystream (nonce || counter), integrity via HMAC-SHA256 tag.

File format (one line):  atap-vault-v1:<salt_b64>:<nonce_b64>:<ct_b64>:<tag_b64>
Keys are re-derived per record from (key material + format tag) and the stored
salt, so rotating the master key simply re-saves the store.

Key material resolution (first match wins):
  1. ATAP_VAULT_KEY environment variable
  2. `<engagement dir>/.vault_key` keyfile (auto-created, chmod 0600)

Upgrade path: if `cryptography` is installed, Fernet may be substituted without
changing the Vault API (see IMPLEMENTATION.md §10).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
from pathlib import Path

_FORMAT = b"atap-vault-v1"
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


class VaultError(Exception):
    pass


def _keystream_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """HMAC-SHA256-CTR keystream XOR (nonce || 64-bit counter blocks)."""
    out = bytearray(len(data))
    for counter, off in enumerate(range(0, len(data), 32)):
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        chunk = data[off:off + 32]
        for i, b in enumerate(chunk):
            out[off + i] = b ^ block[i]
    return bytes(out)


def generate_password(length: int = 16) -> str:
    """Generated password with guaranteed class coverage (no look-alike chars)."""
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)):
            return pw


class Vault:
    def __init__(self, path: str | Path, key_material: bytes):
        self.path = Path(path)
        self._key_material = bytes(key_material)

    # ---------- key resolution ----------
    @classmethod
    def open(cls, engagement_dir: str | Path) -> "Vault":
        d = Path(engagement_dir)
        d.mkdir(parents=True, exist_ok=True)
        env = os.environ.get("ATAP_VAULT_KEY")
        if env:
            return cls(d / "accounts.json", env.encode())
        keyfile = d / ".vault_key"
        if keyfile.exists():
            return cls(d / "accounts.json", keyfile.read_bytes().strip())
        key = secrets.token_hex(32).encode()
        keyfile.write_bytes(key)
        keyfile.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
        return cls(d / "accounts.json", key)

    # ---------- crypto ----------
    def _derive(self, salt: bytes) -> tuple[bytes, bytes]:
        derived = hashlib.scrypt(self._key_material + _FORMAT, salt=salt,
                                 n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=64)
        return derived[:32], derived[32:]

    def encrypt_json(self, obj: dict) -> str:
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(16)
        k_enc, k_mac = self._derive(salt)
        pt = json.dumps(obj, ensure_ascii=False).encode()
        ct = _keystream_xor(k_enc, nonce, pt)
        tag = hmac.new(k_mac, _FORMAT + salt + nonce + ct, hashlib.sha256).digest()
        return ":".join([_FORMAT.decode(),
                         base64.b64encode(salt).decode(), base64.b64encode(nonce).decode(),
                         base64.b64encode(ct).decode(), base64.b64encode(tag).decode()])

    def decrypt_json(self, blob: str) -> dict:
        try:
            parts = blob.strip().split(":")
            if len(parts) != 5 or parts[0] != _FORMAT.decode():
                raise VaultError("unknown vault format")
            salt, nonce, ct, tag = (base64.b64decode(x) for x in parts[1:])
        except VaultError:
            raise
        except Exception as e:
            raise VaultError(f"vault blob malformed: {e}") from e
        k_enc, k_mac = self._derive(salt)
        good = hmac.new(k_mac, _FORMAT + salt + nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(good, tag):
            raise VaultError("vault integrity check failed (wrong key or tampered file)")
        try:
            return json.loads(_keystream_xor(k_enc, nonce, ct))
        except Exception as e:
            raise VaultError(f"vault decrypt failed: {e}") from e

    # ---------- load/save ----------
    def load(self) -> dict:
        if not self.path.exists():
            return {"accounts": [], "audit": []}
        return self.decrypt_json(self.path.read_text(encoding="utf-8"))

    def save(self, data: dict) -> None:
        self.path.write_text(self.encrypt_json(data), encoding="utf-8")
        self.path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
