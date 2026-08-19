"""Unit tests for the unified vault."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

# Repo root is the `vault` package; its parent must be on sys.path for imports.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_PARENT = _REPO_ROOT.parent
if str(_PARENT) not in sys.path:
    sys.path.insert(0, str(_PARENT))

from vault import commands, crypto, storage  # noqa: E402
from vault.errors import (  # noqa: E402
    CorruptEntry,
    EntryAlreadyExists,
    EntryNotFound,
    VaultAlreadyExists,
    VaultError,
    VaultNotInitialized,
    WrongPassword,
)

PASSWORD = "test-password"
WRONG_PASSWORD = "wrong-password"


@pytest.fixture
def fast_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    """Speed up KDFs so vault init/unlock stay practical in unit tests."""

    def _fast_cost(kdf_id: int) -> int:
        if kdf_id == crypto.KDF_PBKDF2HMAC:
            return 1
        if kdf_id == crypto.KDF_SCRYPT:
            return 2  # n = 2**2
        if kdf_id == crypto.KDF_ARGON2ID:
            return 1
        raise ValueError(f"unknown kdf id: {kdf_id}")

    monkeypatch.setattr(storage, "default_cost", _fast_cost)
    monkeypatch.setattr(crypto, "default_cost", _fast_cost)
    # Argon2 requires memory_cost >= 8 * lanes (lanes=4 → min 32 KiB).
    monkeypatch.setattr(crypto, "ARGON2_MEMORY_KIB", 32)


@pytest.fixture
def vault_dir(tmp_path: Path, fast_kdf: None) -> Path:
    """Initialized vault directory using a fast KDF."""
    path = tmp_path / "vault"
    storage.init_vault(path, PASSWORD, kdf_name="pbkdf2hmac")
    return path


# ---------------------------------------------------------------------------
# crypto
# ---------------------------------------------------------------------------


class TestDefaultCost:
    def test_known_kdfs(self) -> None:
        assert crypto.default_cost(crypto.KDF_PBKDF2HMAC) == crypto.PBKDF2_ITERATIONS_DEFAULT
        assert crypto.default_cost(crypto.KDF_SCRYPT) == crypto.SCRYPT_N_DEFAULT
        assert crypto.default_cost(crypto.KDF_ARGON2ID) == crypto.ARGON2_ITERATIONS_DEFAULT

    def test_unknown_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown kdf id"):
            crypto.default_cost(99)


class TestDeriveMasterKey:
    def test_pbkdf2_deterministic(self) -> None:
        salt = b"\x01" * crypto.SALT_LEN
        a = crypto.derive_master_key(PASSWORD, salt, crypto.KDF_PBKDF2HMAC, cost=1)
        b = crypto.derive_master_key(PASSWORD, salt, crypto.KDF_PBKDF2HMAC, cost=1)
        assert a == b
        assert len(a) == crypto.KEY_LEN

    def test_accepts_bytes_password(self) -> None:
        salt = b"\x02" * crypto.SALT_LEN
        from_str = crypto.derive_master_key(PASSWORD, salt, crypto.KDF_PBKDF2HMAC, cost=1)
        from_bytes = crypto.derive_master_key(
            PASSWORD.encode(), salt, crypto.KDF_PBKDF2HMAC, cost=1
        )
        assert from_str == from_bytes

    def test_different_password_different_key(self) -> None:
        salt = b"\x03" * crypto.SALT_LEN
        a = crypto.derive_master_key(PASSWORD, salt, crypto.KDF_PBKDF2HMAC, cost=1)
        b = crypto.derive_master_key(WRONG_PASSWORD, salt, crypto.KDF_PBKDF2HMAC, cost=1)
        assert a != b

    def test_scrypt(self) -> None:
        salt = b"\x04" * crypto.SALT_LEN
        key = crypto.derive_master_key(PASSWORD, salt, crypto.KDF_SCRYPT, cost=2)
        assert len(key) == crypto.KEY_LEN

    def test_argon2id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(crypto, "ARGON2_MEMORY_KIB", 32)
        salt = b"\x05" * crypto.SALT_LEN
        key = crypto.derive_master_key(PASSWORD, salt, crypto.KDF_ARGON2ID, cost=1)
        assert len(key) == crypto.KEY_LEN

    def test_unknown_kdf_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown kdf id"):
            crypto.derive_master_key(PASSWORD, b"\x00" * crypto.SALT_LEN, 99, cost=1)


class TestCanary:
    def test_encrypt_and_verify(self) -> None:
        master_key = b"\xab" * crypto.KEY_LEN
        blob = crypto.encrypt_canary(master_key)
        crypto.verify_canary(master_key, blob)

    def test_wrong_key_raises(self) -> None:
        master_key = b"\xab" * crypto.KEY_LEN
        blob = crypto.encrypt_canary(master_key)
        with pytest.raises(WrongPassword):
            crypto.verify_canary(b"\xcd" * crypto.KEY_LEN, blob)

    def test_truncated_blob_raises(self) -> None:
        with pytest.raises(WrongPassword):
            crypto.verify_canary(b"\x00" * crypto.KEY_LEN, b"short")


class TestWrapCek:
    def test_wrap_unwrap_roundtrip(self) -> None:
        master_key = b"\x11" * crypto.KEY_LEN
        cek = b"\x22" * crypto.KEY_LEN
        aad = b"test-aad"
        nonce, wrapped = crypto.wrap_cek(master_key, cek, aad)
        assert crypto.unwrap_cek(master_key, nonce, wrapped, aad) == cek

    def test_wrong_aad_raises(self) -> None:
        master_key = b"\x11" * crypto.KEY_LEN
        cek = b"\x22" * crypto.KEY_LEN
        nonce, wrapped = crypto.wrap_cek(master_key, cek, aad=b"aad-a")
        with pytest.raises(WrongPassword):
            crypto.unwrap_cek(master_key, nonce, wrapped, aad=b"aad-b")


class TestWholeBlob:
    def test_encrypt_decrypt_roundtrip(self) -> None:
        master_key = b"\x33" * crypto.KEY_LEN
        plaintext = b"secret note content"
        blob = crypto.encrypt_whole(master_key, plaintext, entry_type=crypto.TYPE_NOTE)
        entry_type, out = crypto.decrypt_whole(master_key, blob)
        assert entry_type == crypto.TYPE_NOTE
        assert out == plaintext

    def test_wrong_master_key_raises(self) -> None:
        master_key = b"\x33" * crypto.KEY_LEN
        blob = crypto.encrypt_whole(master_key, b"data")
        with pytest.raises(WrongPassword):
            crypto.decrypt_whole(b"\x44" * crypto.KEY_LEN, blob)

    def test_truncated_raises(self) -> None:
        with pytest.raises(CorruptEntry, match="truncated"):
            crypto.decrypt_whole(b"\x00" * crypto.KEY_LEN, b"nope")

    def test_bad_magic_raises(self) -> None:
        master_key = b"\x33" * crypto.KEY_LEN
        blob = bytearray(crypto.encrypt_whole(master_key, b"data"))
        blob[0:4] = b"XXXX"
        with pytest.raises(CorruptEntry, match="bad magic"):
            crypto.decrypt_whole(master_key, bytes(blob))


class TestStream:
    def test_encrypt_decrypt_roundtrip(self) -> None:
        master_key = b"\x55" * crypto.KEY_LEN
        plaintext = b"chunk-a" * 100 + b"chunk-b" * 50
        src = io.BytesIO(plaintext)
        enc = io.BytesIO()
        written = crypto.encrypt_stream(
            master_key, src, enc, entry_type=crypto.TYPE_FILE, chunk_size=64
        )
        assert written == len(plaintext)

        enc.seek(0)
        out = io.BytesIO()
        read = crypto.decrypt_stream(master_key, enc, out)
        assert read == len(plaintext)
        assert out.getvalue() == plaintext

    def test_empty_stream(self) -> None:
        master_key = b"\x55" * crypto.KEY_LEN
        enc = io.BytesIO()
        written = crypto.encrypt_stream(
            master_key, io.BytesIO(b""), enc, chunk_size=32
        )
        assert written == 0
        enc.seek(0)
        out = io.BytesIO()
        assert crypto.decrypt_stream(master_key, enc, out) == 0
        assert out.getvalue() == b""

    def test_wrong_key_raises(self) -> None:
        master_key = b"\x55" * crypto.KEY_LEN
        enc = io.BytesIO()
        crypto.encrypt_stream(master_key, io.BytesIO(b"payload"), enc, chunk_size=16)
        enc.seek(0)
        with pytest.raises(WrongPassword):
            crypto.decrypt_stream(b"\x66" * crypto.KEY_LEN, enc, io.BytesIO())


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------


class TestStorage:
    def test_init_creates_layout(self, vault_dir: Path) -> None:
        assert (vault_dir / storage.SALT_NAME).is_file()
        assert (vault_dir / storage.CANARY_NAME).is_file()
        assert (vault_dir / storage.META_NAME).is_file()
        assert (vault_dir / storage.INDEX_NAME).is_file()
        assert (vault_dir / storage.ENTRIES_DIR).is_dir()

        meta = storage.load_meta(vault_dir)
        assert meta["kdf"] == "pbkdf2hmac"
        assert meta["version"] == 1
        assert storage.load_index(vault_dir) == {}

    def test_init_already_exists(self, vault_dir: Path) -> None:
        with pytest.raises(VaultAlreadyExists):
            storage.init_vault(vault_dir, PASSWORD, kdf_name="pbkdf2hmac")

    def test_init_unknown_kdf(self, tmp_path: Path, fast_kdf: None) -> None:
        with pytest.raises(ValueError, match="unknown kdf"):
            storage.init_vault(tmp_path / "v", PASSWORD, kdf_name="not-a-kdf")

    def test_unlock_success(self, vault_dir: Path) -> None:
        key = storage.unlock(vault_dir, PASSWORD)
        assert len(key) == crypto.KEY_LEN

    def test_unlock_wrong_password(self, vault_dir: Path) -> None:
        with pytest.raises(WrongPassword):
            storage.unlock(vault_dir, WRONG_PASSWORD)

    def test_require_vault_missing(self, tmp_path: Path) -> None:
        with pytest.raises(VaultNotInitialized):
            storage.require_vault(tmp_path / "missing")

    def test_atomic_write_and_index(self, tmp_path: Path) -> None:
        path = tmp_path / "data.bin"
        storage.atomic_write(path, b"hello")
        assert path.read_bytes() == b"hello"
        assert not path.with_suffix(".bin.tmp").exists()

        vault = tmp_path / "v"
        vault.mkdir()
        storage.save_index(vault, {"n": {"type": "note"}})
        assert storage.load_index(vault) == {"n": {"type": "note"}}
        assert storage.load_index(tmp_path / "empty") == {}

    def test_entry_path(self, vault_dir: Path) -> None:
        assert storage.entry_path(vault_dir, "abc.enc") == vault_dir / "entries" / "abc.enc"


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


class TestCommands:
    def test_init_wrapper(self, tmp_path: Path, fast_kdf: None) -> None:
        path = tmp_path / "v"
        msg = commands.cmd_init(path, PASSWORD, kdf="pbkdf2hmac")
        assert "initialized" in msg.lower()
        storage.require_vault(path)

    def test_add_and_get_note(self, vault_dir: Path) -> None:
        content = b"my secret note"
        msg = commands.cmd_add_note(vault_dir, PASSWORD, "secrets", content)
        assert "secrets" in msg
        assert commands.cmd_get_note(vault_dir, PASSWORD, "secrets") == content

        index = storage.load_index(vault_dir)
        assert index["secrets"]["type"] == "note"
        assert index["secrets"]["size"] == len(content)
        assert (vault_dir / "entries" / index["secrets"]["file"]).is_file()

    def test_add_note_duplicate_without_force(self, vault_dir: Path) -> None:
        commands.cmd_add_note(vault_dir, PASSWORD, "dup", b"one")
        with pytest.raises(EntryAlreadyExists):
            commands.cmd_add_note(vault_dir, PASSWORD, "dup", b"two")

    def test_add_note_force_overwrites(self, vault_dir: Path) -> None:
        commands.cmd_add_note(vault_dir, PASSWORD, "dup", b"one")
        old_file = storage.load_index(vault_dir)["dup"]["file"]
        commands.cmd_add_note(vault_dir, PASSWORD, "dup", b"two", force=True)
        assert commands.cmd_get_note(vault_dir, PASSWORD, "dup") == b"two"
        assert not (vault_dir / "entries" / old_file).exists()

    def test_get_note_missing(self, vault_dir: Path) -> None:
        with pytest.raises(EntryNotFound):
            commands.cmd_get_note(vault_dir, PASSWORD, "nope")

    def test_add_and_get_file(self, vault_dir: Path, tmp_path: Path) -> None:
        src = tmp_path / "plain.bin"
        src.write_bytes(b"file-bytes-" * 200)
        msg = commands.cmd_add_file(vault_dir, PASSWORD, "backup", src)
        assert "backup" in msg

        out = tmp_path / "out.bin"
        msg = commands.cmd_get_file(vault_dir, PASSWORD, "backup", out)
        assert out.read_bytes() == src.read_bytes()
        assert "wrote" in msg.lower()

        index = storage.load_index(vault_dir)
        assert index["backup"]["type"] == "file"
        assert index["backup"]["mode"] == "chunked"

    def test_add_file_missing_input(self, vault_dir: Path, tmp_path: Path) -> None:
        with pytest.raises(VaultError, match="input file not found"):
            commands.cmd_add_file(vault_dir, PASSWORD, "x", tmp_path / "missing.bin")

    def test_get_file_refuses_existing_without_force(
        self, vault_dir: Path, tmp_path: Path
    ) -> None:
        src = tmp_path / "plain.bin"
        src.write_bytes(b"data")
        commands.cmd_add_file(vault_dir, PASSWORD, "f", src)
        out = tmp_path / "out.bin"
        out.write_bytes(b"existing")
        with pytest.raises(VaultError, match="output already exists"):
            commands.cmd_get_file(vault_dir, PASSWORD, "f", out)
        commands.cmd_get_file(vault_dir, PASSWORD, "f", out, force=True)
        assert out.read_bytes() == b"data"

    def test_get_note_on_file_entry_raises(self, vault_dir: Path, tmp_path: Path) -> None:
        src = tmp_path / "plain.bin"
        src.write_bytes(b"data")
        commands.cmd_add_file(vault_dir, PASSWORD, "f", src)
        with pytest.raises(VaultError, match="file entry"):
            commands.cmd_get_note(vault_dir, PASSWORD, "f")

    def test_get_file_on_note_entry_raises(self, vault_dir: Path, tmp_path: Path) -> None:
        commands.cmd_add_note(vault_dir, PASSWORD, "n", b"note")
        with pytest.raises(VaultError, match="note entry"):
            commands.cmd_get_file(vault_dir, PASSWORD, "n", tmp_path / "out")

    def test_list_empty(self, vault_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
        commands.cmd_list(vault_dir)
        assert capsys.readouterr().out.strip() == "(empty)"

    def test_list_entries(self, vault_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
        commands.cmd_add_note(vault_dir, PASSWORD, "alpha", b"a")
        commands.cmd_add_note(vault_dir, PASSWORD, "beta", b"bb")
        commands.cmd_list(vault_dir)
        out = capsys.readouterr().out
        assert "alpha" in out
        assert "beta" in out

    def test_rm(self, vault_dir: Path) -> None:
        commands.cmd_add_note(vault_dir, PASSWORD, "temp", b"gone")
        filename = storage.load_index(vault_dir)["temp"]["file"]
        msg = commands.cmd_rm(vault_dir, PASSWORD, "temp")
        assert "removed" in msg.lower()
        assert "temp" not in storage.load_index(vault_dir)
        assert not (vault_dir / "entries" / filename).exists()

    def test_rm_missing(self, vault_dir: Path) -> None:
        with pytest.raises(EntryNotFound):
            commands.cmd_rm(vault_dir, PASSWORD, "missing")

    def test_rm_wrong_password(self, vault_dir: Path) -> None:
        commands.cmd_add_note(vault_dir, PASSWORD, "temp", b"x")
        with pytest.raises(WrongPassword):
            commands.cmd_rm(vault_dir, WRONG_PASSWORD, "temp")
        assert "temp" in storage.load_index(vault_dir)

    def test_wrong_password_cannot_read_note(self, vault_dir: Path) -> None:
        commands.cmd_add_note(vault_dir, PASSWORD, "secrets", b"top-secret")
        with pytest.raises(WrongPassword):
            commands.cmd_get_note(vault_dir, WRONG_PASSWORD, "secrets")
