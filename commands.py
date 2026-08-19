"""High-level vault operations."""

from __future__ import annotations

import datetime
import uuid
from pathlib import Path

from . import crypto
from .errors import EntryAlreadyExists, EntryNotFound, VaultError
from .storage import (
    ENTRIES_DIR,
    atomic_write,
    entry_path,
    init_vault,
    load_index,
    require_vault,
    save_index,
    unlock,
)


def cmd_init(vault_dir: Path, password: str, kdf: str = "argon2id") -> str:
    """Create a new vault directory with salt, canary, meta, and empty index."""
    return init_vault(vault_dir, password, kdf_name=kdf)


def cmd_list(vault_dir: Path) -> None:
    """Print vault entries as name, type, size, and created_at."""
    require_vault(vault_dir)
    index = load_index(vault_dir)
    if not index:
        print("(empty)")
        return
    for name, meta in sorted(index.items()):
        kind = meta.get("type", "?")
        size = meta.get("size", "?")
        created = meta.get("created_at", "?")
        print(f"{name}\t{kind}\t{size}\t{created}")


def cmd_add_note(
    vault_dir: Path,
    password: str,
    name: str,
    content: bytes,
    force: bool = False,
) -> str:
    """Encrypt ``content`` as a whole-blob note and register it under ``name``."""
    master_key = unlock(vault_dir, password)
    index = load_index(vault_dir)
    if name in index and not force:
        raise EntryAlreadyExists(
            f"entry '{name}' already exists (use --force to overwrite)"
        )

    if name in index:
        old = entry_path(vault_dir, index[name]["file"])
        old.unlink(missing_ok=True)

    blob = crypto.encrypt_whole(master_key, content, entry_type=crypto.TYPE_NOTE)
    filename = f"{uuid.uuid4().hex}.enc"
    atomic_write(vault_dir / ENTRIES_DIR / filename, blob)
    index[name] = {
        "file": filename,
        "type": "note",
        "mode": "whole",
        "size": len(content),
        "created_at": datetime.datetime.now().isoformat(timespec="seconds"),
    }
    save_index(vault_dir, index)
    return f"added note '{name}' ({len(content)} bytes)"


def cmd_add_file(
    vault_dir: Path,
    password: str,
    name: str,
    input_path: Path,
    force: bool = False,
) -> str:
    """Stream-encrypt a file into the vault under ``name`` (chunked entry)."""
    if not input_path.is_file():
        raise VaultError(f"input file not found: {input_path}")

    master_key = unlock(vault_dir, password)
    index = load_index(vault_dir)
    if name in index and not force:
        raise EntryAlreadyExists(
            f"entry '{name}' already exists (use --force to overwrite)"
        )

    if name in index:
        old = entry_path(vault_dir, index[name]["file"])
        old.unlink(missing_ok=True)

    filename = f"{uuid.uuid4().hex}.enc"
    out_path = vault_dir / ENTRIES_DIR / filename
    tmp_path = out_path.with_suffix(out_path.suffix + ".tmp")

    with input_path.open("rb") as src, tmp_path.open("wb") as dst:
        size = crypto.encrypt_stream(
            master_key, src, dst, entry_type=crypto.TYPE_FILE
        )
    tmp_path.replace(out_path)

    index[name] = {
        "file": filename,
        "type": "file",
        "mode": "chunked",
        "size": size,
        "source_name": input_path.name,
        "created_at": datetime.datetime.now().isoformat(timespec="seconds"),
    }
    save_index(vault_dir, index)
    return f"added file '{name}' ({size} bytes)"


def cmd_get_note(vault_dir: Path, password: str, name: str) -> bytes:
    """Unlock and decrypt a note entry; returns plaintext bytes."""
    master_key = unlock(vault_dir, password)
    index = load_index(vault_dir)
    if name not in index:
        raise EntryNotFound(f"no entry named '{name}'")
    meta = index[name]
    if meta.get("type") != "note":
        raise VaultError(
            f"'{name}' is a file entry — use get-file instead"
        )
    blob = entry_path(vault_dir, meta["file"]).read_bytes()
    entry_type, plaintext = crypto.decrypt_whole(master_key, blob)
    if entry_type != crypto.TYPE_NOTE:
        raise VaultError(f"'{name}' is not a note on disk")
    return plaintext


def cmd_get_file(
    vault_dir: Path,
    password: str,
    name: str,
    output_path: Path,
    force: bool = False,
) -> str:
    """Stream-decrypt a file entry to ``output_path``."""
    if output_path.exists() and not force:
        raise VaultError(
            f"output already exists: {output_path} (use --force to overwrite)"
        )

    master_key = unlock(vault_dir, password)
    index = load_index(vault_dir)
    if name not in index:
        raise EntryNotFound(f"no entry named '{name}'")
    meta = index[name]
    if meta.get("type") != "file":
        raise VaultError(
            f"'{name}' is a note entry — use get-note instead"
        )

    in_path = entry_path(vault_dir, meta["file"])
    tmp_path = output_path.with_suffix(output_path.suffix + ".tmp")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with in_path.open("rb") as src, tmp_path.open("wb") as dst:
        size = crypto.decrypt_stream(master_key, src, dst)
    tmp_path.replace(output_path)
    return f"wrote '{name}' -> {output_path} ({size} bytes)"


def cmd_rm(vault_dir: Path, password: str, name: str) -> str:
    """Require the master password, then delete an entry from disk and index."""
    unlock(vault_dir, password)  # require password to delete
    index = load_index(vault_dir)
    if name not in index:
        raise EntryNotFound(f"no entry named '{name}'")
    path = entry_path(vault_dir, index[name]["file"])
    path.unlink(missing_ok=True)
    del index[name]
    save_index(vault_dir, index)
    return f"removed '{name}'"
