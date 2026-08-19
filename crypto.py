"""Crypto primitives: KDF, master/CEK wrap, AES-GCM, streaming."""

from __future__ import annotations

import os
import struct
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import CorruptEntry, WrongPassword

# On-disk entry format
MAGIC = b"UVLT"
VERSION = 1
TYPE_NOTE = 1
TYPE_FILE = 2
MODE_WHOLE = 0
MODE_CHUNKED = 1
ENTRY_RESERVED = 0  # reserved header byte; unused, for future flags

SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
GCM_TAG_LEN = 16  # AES-GCM authentication tag (also min ciphertext length)
CHUNK_SIZE = 1 << 20  # 1 MiB
CANARY_VALUE = b"vault-canary-v1"

KDF_PBKDF2HMAC = 1
KDF_SCRYPT = 2
KDF_ARGON2ID = 3

KDF_NAMES = {
    "pbkdf2hmac": KDF_PBKDF2HMAC,
    "scrypt": KDF_SCRYPT,
    "argon2id": KDF_ARGON2ID,
}
KDF_IDS = {v: k for k, v in KDF_NAMES.items()}

PBKDF2_ITERATIONS_DEFAULT = 310_000
SCRYPT_N_DEFAULT = 15  # cost = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
ARGON2_ITERATIONS_DEFAULT = 3
ARGON2_LANES = 4
ARGON2_MEMORY_KIB = 64 * 1024  # 64 MiB

# magic(4) version(1) type(1) mode(1) reserved(1)
ENTRY_HDR = struct.Struct(">4sBBBB")
WRAP_CEK_LEN = KEY_LEN + GCM_TAG_LEN  # wrapped CEK ciphertext


def default_cost(kdf_id: int) -> int:
    """Return the default KDF cost parameter for the given KDF id."""
    if kdf_id == KDF_PBKDF2HMAC:
        return PBKDF2_ITERATIONS_DEFAULT
    if kdf_id == KDF_SCRYPT:
        return SCRYPT_N_DEFAULT
    if kdf_id == KDF_ARGON2ID:
        return ARGON2_ITERATIONS_DEFAULT
    raise ValueError(f"unknown kdf id: {kdf_id}")


def derive_master_key(
    password: str | bytes,
    salt: bytes,
    kdf_id: int,
    cost: int,
) -> bytes:
    """Derive the vault master key from password + salt using the chosen KDF."""
    pw = password.encode("utf-8") if isinstance(password, str) else password
    if kdf_id == KDF_PBKDF2HMAC:
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LEN,
            salt=salt,
            iterations=cost,
        ).derive(pw)
    if kdf_id == KDF_SCRYPT:
        return Scrypt(
            salt=salt,
            length=KEY_LEN,
            n=2**cost,
            r=SCRYPT_R,
            p=SCRYPT_P,
        ).derive(pw)
    if kdf_id == KDF_ARGON2ID:
        return Argon2id(
            salt=salt,
            length=KEY_LEN,
            iterations=cost,
            lanes=ARGON2_LANES,
            memory_cost=ARGON2_MEMORY_KIB,
        ).derive(pw)
    raise ValueError(f"unknown kdf id: {kdf_id}")


def _gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-GCM encrypt; returns ciphertext with the 16-byte tag appended."""
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def _gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """AES-GCM decrypt; maps InvalidTag to WrongPassword."""
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise WrongPassword(
            "incorrect password or corrupted/tampered data"
        ) from exc


def encrypt_canary(master_key: bytes) -> bytes:
    """Encrypt the vault canary under the master key (nonce || ciphertext)."""
    nonce = os.urandom(NONCE_LEN)
    ct = _gcm_encrypt(master_key, nonce, CANARY_VALUE, aad=b"canary")
    return nonce + ct


def verify_canary(master_key: bytes, blob: bytes) -> None:
    """Decrypt and check the canary; raises WrongPassword on failure."""
    if len(blob) < NONCE_LEN + GCM_TAG_LEN:
        raise WrongPassword("incorrect password or corrupted vault")
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    plain = _gcm_decrypt(master_key, nonce, ct, aad=b"canary")
    if plain != CANARY_VALUE:
        raise WrongPassword("incorrect password")


def wrap_cek(master_key: bytes, cek: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt a content key with the master key. Returns (wrap_nonce, wrapped_cek)."""
    nonce = os.urandom(NONCE_LEN)
    return nonce, _gcm_encrypt(master_key, nonce, cek, aad)


def unwrap_cek(
    master_key: bytes, wrap_nonce: bytes, wrapped: bytes, aad: bytes
) -> bytes:
    """Decrypt a wrapped content key with the master key."""
    return _gcm_decrypt(master_key, wrap_nonce, wrapped, aad)


def _entry_header(entry_type: int, mode: int) -> bytes:
    """Pack the fixed entry header used as AAD for that entry's ciphertext."""
    return ENTRY_HDR.pack(MAGIC, VERSION, entry_type, mode, ENTRY_RESERVED)


def encrypt_whole(
    master_key: bytes, plaintext: bytes, entry_type: int = TYPE_NOTE
) -> bytes:
    """Encrypt a small payload as one blob (header || wrapped CEK || data)."""
    header = _entry_header(entry_type, MODE_WHOLE)
    cek = os.urandom(KEY_LEN)
    wrap_nonce, wrapped = wrap_cek(master_key, cek, aad=header)
    data_nonce = os.urandom(NONCE_LEN)
    ciphertext = _gcm_encrypt(cek, data_nonce, plaintext, aad=header)
    return header + wrap_nonce + wrapped + data_nonce + ciphertext


def decrypt_whole(master_key: bytes, blob: bytes) -> tuple[int, bytes]:
    """Decrypt a whole-blob entry. Returns (entry_type, plaintext)."""
    header, wrap_nonce, wrapped, rest = _parse_prefix(blob)
    _magic, version, entry_type, mode, _ = ENTRY_HDR.unpack(header)
    if mode != MODE_WHOLE:
        raise CorruptEntry("entry is not whole-blob mode")
    cek = unwrap_cek(master_key, wrap_nonce, wrapped, aad=header)
    if len(rest) < NONCE_LEN:
        raise CorruptEntry("truncated entry")
    data_nonce, ciphertext = rest[:NONCE_LEN], rest[NONCE_LEN:]
    plaintext = _gcm_decrypt(cek, data_nonce, ciphertext, aad=header)
    return entry_type, plaintext


def encrypt_stream(
    master_key: bytes,
    src: BinaryIO,
    dst: BinaryIO,
    entry_type: int = TYPE_FILE,
    chunk_size: int = CHUNK_SIZE,
) -> int:
    """Stream-encrypt a large file without loading it all into memory.

    Reads plaintext from ``src`` in ``chunk_size`` pieces, encrypts each chunk
    with a fresh random CEK (wrapped under ``master_key``), and writes the
    vault entry format to ``dst``. Suitable for multi-GB inputs where
    ``encrypt_whole`` would OOM. Returns the total plaintext byte count.
    """
    header = _entry_header(entry_type, MODE_CHUNKED)
    cek = os.urandom(KEY_LEN)
    wrap_nonce, wrapped = wrap_cek(master_key, cek, aad=header)

    dst.write(header)
    dst.write(wrap_nonce)
    dst.write(wrapped)
    dst.write(struct.pack(">I", chunk_size))

    total = 0
    aes = AESGCM(cek)
    while True:
        chunk = src.read(chunk_size)
        if not chunk:
            break
        nonce = os.urandom(NONCE_LEN)
        ct = aes.encrypt(nonce, chunk, associated_data=header)
        dst.write(nonce)
        dst.write(struct.pack(">I", len(ct)))
        dst.write(ct)
        total += len(chunk)
    # Sentinel: zero-length ciphertext marks end of stream.
    dst.write(b"\x00" * NONCE_LEN)
    dst.write(struct.pack(">I", 0))
    return total


def decrypt_stream(master_key: bytes, src: BinaryIO, dst: BinaryIO) -> int:
    """Decrypt a chunked entry from src → dst. Returns plaintext byte count."""
    header = src.read(ENTRY_HDR.size)
    if len(header) != ENTRY_HDR.size:
        raise CorruptEntry("truncated entry header")
    magic, version, _entry_type, mode, _ = ENTRY_HDR.unpack(header)
    if magic != MAGIC:
        raise CorruptEntry("bad magic")
    if version != VERSION:
        raise CorruptEntry(f"unsupported entry version: {version}")
    if mode != MODE_CHUNKED:
        raise CorruptEntry("entry is not chunked mode")

    wrap_nonce = src.read(NONCE_LEN)
    wrapped = src.read(WRAP_CEK_LEN)
    if len(wrap_nonce) != NONCE_LEN or len(wrapped) != WRAP_CEK_LEN:
        raise CorruptEntry("truncated wrapped CEK")
    cek = unwrap_cek(master_key, wrap_nonce, wrapped, aad=header)

    chunk_size_raw = src.read(4)
    if len(chunk_size_raw) != 4:
        raise CorruptEntry("missing chunk size")
    struct.unpack(">I", chunk_size_raw)  # present for format completeness

    aes = AESGCM(cek)
    total = 0
    while True:
        nonce = src.read(NONCE_LEN)
        len_raw = src.read(4)
        if len(nonce) != NONCE_LEN or len(len_raw) != 4:
            raise CorruptEntry("truncated chunk")
        (ct_len,) = struct.unpack(">I", len_raw)
        if ct_len == 0:
            break
        ct = src.read(ct_len)
        if len(ct) != ct_len:
            raise CorruptEntry("truncated chunk ciphertext")
        try:
            plain = aes.decrypt(nonce, ct, associated_data=header)
        except InvalidTag as exc:
            raise WrongPassword(
                "incorrect password or corrupted/tampered data"
            ) from exc
        dst.write(plain)
        total += len(plain)
    return total


def _parse_prefix(blob: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Split an entry blob into (header, wrap_nonce, wrapped_cek, remainder)."""
    need = ENTRY_HDR.size + NONCE_LEN + WRAP_CEK_LEN
    if len(blob) < need:
        raise CorruptEntry("truncated entry")
    header = blob[: ENTRY_HDR.size]
    magic, version, _entry_type, _mode, _ = ENTRY_HDR.unpack(header)
    if magic != MAGIC:
        raise CorruptEntry("bad magic")
    if version != VERSION:
        raise CorruptEntry(f"unsupported entry version: {version}")
    offset = ENTRY_HDR.size
    wrap_nonce = blob[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    wrapped = blob[offset : offset + WRAP_CEK_LEN]
    offset += WRAP_CEK_LEN
    return header, wrap_nonce, wrapped, blob[offset:]
