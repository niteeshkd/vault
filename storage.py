"""Vault directory layout and index helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .crypto import (
    KDF_IDS,
    KDF_NAMES,
    SALT_LEN,
    default_cost,
    derive_master_key,
    encrypt_canary,
    verify_canary,
)
from .errors import VaultAlreadyExists, VaultNotInitialized, WrongPassword

META_NAME = "meta.json"
SALT_NAME = "salt.bin"
CANARY_NAME = "canary.enc"
INDEX_NAME = "index.json"
ENTRIES_DIR = "entries"


def atomic_write(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` via a temp file + rename (crash-safe)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def load_index(vault_dir: Path) -> dict:
    """Load ``index.json`` (name → entry metadata). Empty dict if missing."""
    index_path = vault_dir / INDEX_NAME
    if not index_path.exists():
        return {}
    return json.loads(index_path.read_text())


def save_index(vault_dir: Path, index: dict) -> None:
    """Atomically persist the vault entry index."""
    atomic_write(vault_dir / INDEX_NAME, json.dumps(index, indent=2).encode())


def load_meta(vault_dir: Path) -> dict:
    """Load vault metadata (format version, KDF id/cost)."""
    meta_path = vault_dir / META_NAME
    if not meta_path.exists():
        raise VaultNotInitialized(f"no vault found at {vault_dir}")
    return json.loads(meta_path.read_text())


def save_meta(vault_dir: Path, meta: dict) -> None:
    """Atomically persist vault metadata."""
    atomic_write(vault_dir / META_NAME, json.dumps(meta, indent=2).encode())


def require_vault(vault_dir: Path) -> None:
    """Raise VaultNotInitialized unless salt.bin and meta.json exist."""
    if not (vault_dir / SALT_NAME).exists() or not (vault_dir / META_NAME).exists():
        raise VaultNotInitialized(
            f"no vault found at {vault_dir} — run 'python -m vault init' first"
        )


def init_vault(vault_dir: Path, password: str, kdf_name: str = "argon2id") -> str:
    """Create a new vault: salt, canary, meta, empty index, and entries/."""
    if (vault_dir / SALT_NAME).exists():
        raise VaultAlreadyExists(f"a vault already exists at {vault_dir}")

    if kdf_name not in KDF_NAMES:
        raise ValueError(f"unknown kdf: {kdf_name}")
    kdf_id = KDF_NAMES[kdf_name]
    cost = default_cost(kdf_id)

    vault_dir.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(SALT_LEN)  # 16-byte vault salt for the master-key KDF
    master_key = derive_master_key(password, salt, kdf_id, cost)
    canary = encrypt_canary(master_key)

    atomic_write(vault_dir / SALT_NAME, salt)
    atomic_write(vault_dir / CANARY_NAME, canary)
    save_meta(
        vault_dir,
        {
            "version": 1,
            "kdf": kdf_name,
            "kdf_id": kdf_id,
            "kdf_cost": cost,
        },
    )
    save_index(vault_dir, {})
    (vault_dir / ENTRIES_DIR).mkdir(exist_ok=True)
    return f"Vault initialized at {vault_dir} (kdf={kdf_name})"


def unlock(vault_dir: Path, password: str) -> bytes:
    """Derive and verify the master key from the password; return it on success."""
    require_vault(vault_dir)
    meta = load_meta(vault_dir)
    kdf_id = int(meta["kdf_id"])
    cost = int(meta["kdf_cost"])
    if kdf_id not in KDF_IDS:
        raise WrongPassword(f"unsupported kdf id in meta: {kdf_id}")

    salt = (vault_dir / SALT_NAME).read_bytes()
    master_key = derive_master_key(password, salt, kdf_id, cost)
    canary = (vault_dir / CANARY_NAME).read_bytes()
    verify_canary(master_key, canary)
    return master_key


def entry_path(vault_dir: Path, filename: str) -> Path:
    """Return the full path to an encrypted blob under ``entries/``."""
    return vault_dir / ENTRIES_DIR / filename
