"""CLI for the unified vault."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from . import commands
from .crypto import KDF_NAMES
from .errors import VaultError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault",
        description=(
            "Unified password vault for encrypted notes and large files "
            "(AES-256-GCM, master key + per-entry content keys)."
        ),
    )
    parser.add_argument(
        "--vault-dir",
        default=".vault",
        help="vault directory (default: .vault)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create a new vault")
    p_init.add_argument(
        "--kdf",
        choices=sorted(KDF_NAMES),
        default="argon2id",
        help="key derivation function (default: argon2id)",
    )

    p_add_note = sub.add_parser("add-note", help="add an encrypted note")
    p_add_note.add_argument("name")
    p_add_note.add_argument(
        "--file",
        help="read note content from this file instead of stdin",
    )
    p_add_note.add_argument(
        "--force",
        action="store_true",
        help="overwrite if the name exists",
    )

    p_add_file = sub.add_parser(
        "add-file", help="add a large file (streamed, chunked encryption)"
    )
    p_add_file.add_argument("name")
    p_add_file.add_argument(
        "--input", "-i", required=True, help="path to plaintext file"
    )
    p_add_file.add_argument(
        "--force",
        action="store_true",
        help="overwrite if the name exists",
    )

    sub.add_parser("list", help="list vault entries")

    p_get_note = sub.add_parser("get-note", help="decrypt a note to stdout")
    p_get_note.add_argument("name")

    p_get_file = sub.add_parser("get-file", help="decrypt a file to a path")
    p_get_file.add_argument("name")
    p_get_file.add_argument(
        "--output", "-o", required=True, help="destination path"
    )
    p_get_file.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="overwrite output if it exists",
    )

    p_rm = sub.add_parser("rm", help="remove an entry")
    p_rm.add_argument("name")

    return parser


def _prompt_new_password() -> str:
    password = getpass.getpass("Enter new master password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        raise VaultError("passwords did not match")
    if not password:
        raise VaultError("password must not be empty")
    return password


def _prompt_password() -> str:
    password = getpass.getpass("Master password: ")
    if not password:
        raise VaultError("password must not be empty")
    return password


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    vault_dir = Path(args.vault_dir)

    try:
        if args.command == "init":
            password = _prompt_new_password()
            print(commands.cmd_init(vault_dir, password, kdf=args.kdf))

        elif args.command == "add-note":
            if args.file:
                content = Path(args.file).read_bytes()
            else:
                content = sys.stdin.buffer.read()
            password = _prompt_password()
            print(
                commands.cmd_add_note(
                    vault_dir, password, args.name, content, force=args.force
                )
            )

        elif args.command == "add-file":
            password = _prompt_password()
            print(
                commands.cmd_add_file(
                    vault_dir,
                    password,
                    args.name,
                    Path(args.input),
                    force=args.force,
                )
            )

        elif args.command == "list":
            commands.cmd_list(vault_dir)

        elif args.command == "get-note":
            password = _prompt_password()
            sys.stdout.buffer.write(
                commands.cmd_get_note(vault_dir, password, args.name)
            )

        elif args.command == "get-file":
            password = _prompt_password()
            print(
                commands.cmd_get_file(
                    vault_dir,
                    password,
                    args.name,
                    Path(args.output),
                    force=args.force,
                )
            )

        elif args.command == "rm":
            password = _prompt_password()
            print(commands.cmd_rm(vault_dir, password, args.name))

    except VaultError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
