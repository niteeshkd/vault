# Vault — Design Document

## Overview

Unified CLI password vault for small encrypted **notes** and large encrypted **files**. One master password unlocks the vault; each entry uses its own random content-encryption key (CEK). Encryption is AES-256-GCM via the `cryptography` library.

## Goals

- Store notes and large files in one vault
- Never keep the master password; derive a master key with a KDF
- Authenticated encryption (tamper detection via GCM tags)
- Stream large files so multi-GB inputs do not need to fit in memory
- Simple on-disk layout (plain directory + JSON index)

## Architecture

```
__main__.py   CLI (argparse, password prompts)
commands.py   High-level ops: init, add/get note|file, list, rm
storage.py    Vault directory layout, meta/index, unlock
crypto.py     KDF, canary, CEK wrap, AES-GCM whole + chunked
errors.py     VaultError hierarchy
```

Call flow for a typical write:

1. `unlock` → load salt/meta → KDF(password) → verify canary → master key  
2. Generate random CEK → encrypt payload with CEK → wrap CEK under master key  
3. Write blob under `entries/` and update `index.json`

## Cryptography

| Piece | Choice |
|--------|--------|
| Master key | KDF from password + 16-byte salt (default **Argon2id**; also scrypt, PBKDF2-HMAC-SHA256) |
| Password check | Encrypted canary (`canary.enc`); wrong password → decrypt/tag failure |
| Payload cipher | AES-256-GCM (12-byte nonce, 16-byte tag) |
| Per-entry key | 32-byte random CEK, wrapped under the master key (GCM) |
| AAD | Entry header bytes bind ciphertext to type/mode |

**Notes** use whole-blob mode (one CEK, one ciphertext).  
**Files** use chunked streaming (1 MiB chunks by default, each with its own nonce; zero-length sentinel ends the stream).

## On-disk layout

Default vault directory: `.vault/`

```
.vault/
  salt.bin        # vault salt for the KDF
  canary.enc      # nonce || GCM(canary) under master key
  meta.json       # version, kdf name/id/cost
  index.json      # name → {file, type, mode, size, created_at, ...}
  entries/
    <uuid>.enc    # encrypted note or file blob
```

Entry blob prefix (both modes):

```
magic "UVLT" | version | type | mode | reserved | wrap_nonce | wrapped_CEK | …
```

- Whole mode: `data_nonce || ciphertext`
- Chunked mode: `chunk_size || (nonce || ct_len || ct)* || sentinel(ct_len=0)`

`index.json` is metadata only (names, sizes, paths). Ciphertext authenticity comes from GCM, not from the index.

## Module responsibilities

- **`crypto`**: pure crypto primitives; no filesystem policy beyond byte formats  
- **`storage`**: create/load vault files; `atomic_write` via temp + rename  
- **`commands`**: user-facing operations and index updates  
- **`__main__`**: CLI wiring; prompts for passwords; maps args → commands  

## How to use

### Setup

```bash
cd /path/to/github   # parent of the vault package directory
python3 -m venv vault/.venv
source vault/.venv/bin/activate
pip install -r vault/requirements.txt
```

Run the CLI as a module (package name is the `vault` directory):

```bash
python -m vault --help
```

### Initialize a vault

```bash
python -m vault init
# optional: --kdf argon2id|scrypt|pbkdf2hmac
# optional: --vault-dir /path/to/myvault
```

You will be prompted for a new master password (with confirmation).

### Notes

```bash
# from stdin
echo 'api token xyz' | python -m vault add-note secrets

# from a file
python -m vault add-note secrets --file note.txt

# overwrite existing name
python -m vault add-note secrets --file note.txt --force

# decrypt to stdout
python -m vault get-note secrets
```

### Files (streaming)

```bash
python -m vault add-file backup -i large.bin
python -m vault get-file backup -o restored.bin
python -m vault get-file backup -o restored.bin --force   # overwrite output
```

### List and remove

```bash
python -m vault list
python -m vault rm secrets
```

Removal still requires the master password.

### Custom vault path

```bash
python -m vault --vault-dir ~/secure/myvault init
python -m vault --vault-dir ~/secure/myvault list
```

## Testing

```bash
pip install -r requirements.txt
python -m pytest tests/test_vault.py -v
```

Unit tests use a fast KDF cost so init/unlock stay quick. They cover crypto round-trips, vault lifecycle, and command-level note/file flows.

## Threat model (brief)

**Protects against:** casual disk inspection; offline ciphertext without the password; undetected tampering of entry blobs (GCM).

**Does not protect against:** malware on a machine that already has the unlocked password typed; attackers who obtain the password; metadata leakage in `index.json` (entry names, sizes, timestamps); secure deletion of overwritten plaintext files outside the vault.

Keep `.vault/` out of version control (see `.gitignore`). The master password is never written to disk.
