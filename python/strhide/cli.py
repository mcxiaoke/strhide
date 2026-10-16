"""Command-line interface for strhide."""

from __future__ import annotations

import argparse
import base64
import codecs
import getpass
import json
import os
import sys
from typing import Optional

from strhide.core.engine import (
    inspect_carrier,
    read_carrier,
    remove_carrier,
    verify_carrier,
    write_carrier,
)
from strhide.core.router import find_adapter, list_all_strategies
from strhide.errors import StrHideError


def prompt_password(confirm: bool = False) -> str:
    """Prompt for password interactively without echo."""
    pwd = getpass.getpass("Enter password: ")
    if not pwd:
        raise ValueError("Password cannot be empty")
    if confirm:
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd != pwd2:
            raise ValueError("Passwords do not match")
    return pwd


def resolve_password(args: argparse.Namespace, confirm: bool = False) -> Optional[str]:
    """Resolve password from CLI arg, password file, environment variable, or interactive prompt."""
    if getattr(args, "password", None):
        return args.password
    if getattr(args, "password_file", None):
        with open(args.password_file, "r", encoding="utf-8") as f:
            return f.read().strip("\r\n")
    if os.environ.get("STRHIDE_PASSWORD"):
        return os.environ.get("STRHIDE_PASSWORD")
    if getattr(args, "encrypt", False):
        return prompt_password(confirm=confirm)
    return None


def cmd_write(args: argparse.Namespace) -> int:
    password = resolve_password(args, confirm=True)

    strategy = args.strategy
    if strategy == "ask":
        with open(args.carrier, "rb") as f:
            strats = list_all_strategies(f)
        print(f"Available strategies for '{args.carrier}':")
        for idx, s in enumerate(strats, 1):
            print(f"  [{idx}] {s}")
        choice = input(f"Select strategy [1-{len(strats)}] (default 1): ").strip()
        if choice and choice.isdigit() and 1 <= int(choice) <= len(strats):
            strategy = strats[int(choice) - 1]
        else:
            strategy = strats[0]

    # Resolve text data safely from args, file, base64, or environment variable
    text_data = args.text
    if getattr(args, "text_file", None):
        with open(args.text_file, "r", encoding="utf-8") as tf:
            text_data = tf.read()
    elif getattr(args, "text_base64", None):
        text_data = base64.b64decode(args.text_base64).decode("utf-8")
    elif not text_data and not args.data and not getattr(args, "stdin", False) and os.environ.get("STRHIDE_TEXT"):
        text_data = os.environ.get("STRHIDE_TEXT")

    if text_data and getattr(args, "unescape", False):
        try:
            text_data = codecs.decode(text_data.encode("utf-8"), "unicode_escape")
        except Exception:
            pass

    try:
        res = write_carrier(
            carrier_path=args.carrier,
            data_file=args.data,
            data_text=text_data,
            data_stdin=getattr(args, "stdin", False),
            output_path=args.output,
            password=password,
            strategy=strategy,
            stealth=args.stealth,
            preserve_time=args.preserve_time,
            backup=getattr(args, "backup", True),
        )
        print(f"[OK] Successfully embedded into '{res['carrier']}' using strategy '{res['strategy']}'.")
        print(f"     Payload: {res['raw_size']} bytes -> UBE: {res['ube_size']} bytes.")
        if res.get("backup_file"):
            print(f"     [BACKUP] Original carrier backed up to '{res['backup_file']}'.")
        if res.get("warning"):
            print(f"[WARNING] {res['warning']}", file=sys.stderr)
        return 0
    except StrHideError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


def cmd_read(args: argparse.Namespace) -> int:
    password = resolve_password(args, confirm=False)
    try:
        res = read_carrier(
            carrier_path=args.carrier,
            output_path=args.output,
            password=password,
        )
    except Exception as e:
        if "Password required" in str(e) and not password:
            password = prompt_password(confirm=False)
            try:
                res = read_carrier(
                    carrier_path=args.carrier,
                    output_path=args.output,
                    password=password,
                )
            except StrHideError as err:
                print(f"[ERROR] {err}", file=sys.stderr)
                return 1
        else:
            print(f"[ERROR] {e}", file=sys.stderr)
            return 1

    if res.get("written_file"):
        print(f"[OK] Extracted payload to '{res['written_file']}' ({res['raw_size']} bytes).")
    elif args.stdout or not res.get("is_file"):
        try:
            print(res["data"].decode("utf-8"))
        except UnicodeDecodeError:
            sys.stdout.buffer.write(res["data"])
    else:
        # Default filename in current dir
        fn = res.get("filename") or "extracted.bin"
        with open(fn, "wb") as f:
            f.write(res["data"])
        print(f"[OK] Extracted payload to '{fn}' ({res['raw_size']} bytes).")

    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    password = resolve_password(args, confirm=False)
    try:
        res = remove_carrier(
            carrier_path=args.carrier,
            output_path=args.output,
            password=password,
            backup=getattr(args, "backup", True),
        )
        print(f"[OK] Successfully stripped hidden data from '{res['carrier']}'.")
        print(f"     Restored size: {res['restored_size']} bytes.")
        print(f"     SHA-256: {res['restored_sha256']} (100% verified identical to original).")
        if res.get("backup_file"):
            print(f"     [BACKUP] Prior carrier backed up to '{res['backup_file']}'.")
        return 0
    except StrHideError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


def cmd_inspect(args: argparse.Namespace) -> int:
    password = resolve_password(args, confirm=False)
    try:
        res = inspect_carrier(carrier_path=args.carrier, password=password)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Carrier: {res['carrier']}")
            print(f"Format:  {res['format']}")
            print(f"Has Hidden Data: {res['has_hidden_data']}")
            if res.get("has_hidden_data"):
                print(f"Strategy:        {res['strategy']}")
                print(f"UBE Offset:      {res['ube_offset']}")
                print(f"UBE Total Size:  {res['ube_total_size']} bytes")
                print(f"Encrypted:       {res['is_encrypted']}")
                print(f"Stealth Mode:    {res['is_stealth']}")
                print(f"Original Size:   {res['orig_host_size']} bytes")
                print(f"Original SHA256: {res['orig_host_sha256']}")
                if res.get("metadata"):
                    print(f"Metadata:        {json.dumps(res['metadata'])}")
        return 0
    except StrHideError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    password = resolve_password(args, confirm=False)
    try:
        res = verify_carrier(carrier_path=args.carrier, password=password)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Carrier: {res['carrier']} ({res['format']})")
            print(f"  Level 1 (Host Structure):    {'[PASS]' if res['level1_host']['ok'] else '[FAIL]'} {res['level1_host']['detail']}")
            print(f"  Level 2 (Envelope Boundary): {'[PASS]' if res['level2_envelope']['ok'] else '[FAIL]'} {res['level2_envelope']['detail']}")
            print(f"  Level 3 (Crypto & Payload):  {'[PASS]' if res['level3_crypto']['ok'] else '[WARN]'} {res['level3_crypto']['detail']}")
        return 0 if (res["level1_host"]["ok"] and res["level2_envelope"]["ok"]) else 1
    except StrHideError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


def cmd_list_strategies(args: argparse.Namespace) -> int:
    try:
        with open(args.carrier, "rb") as f:
            adapter = find_adapter(f)
            strats = adapter.supported_strategies()
        print(f"Format: {adapter.format_name()}")
        print("Supported strategies:")
        for s in strats:
            print(f"  - {s}")
        return 0
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="strhide",
        description="Smart format-preserving lossless data hiding CLI tool.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # write
    p_write = subparsers.add_parser("write", help="Hide data inside a carrier file")
    p_write.add_argument("-c", "--carrier", required=True, help="Host carrier file")
    p_write.add_argument("-d", "--data", help="Secret file to hide")
    p_write.add_argument("-t", "--text", help="Secret text string to hide")
    p_write.add_argument("--text-file", help="Read secret text from UTF-8 file (avoids shell escaping/encoding issues)")
    p_write.add_argument("--text-base64", help="Secret text as Base64 string (immune to shell special characters)")
    p_write.add_argument("--unescape", action="store_true", help="Decode escape sequences in --text (e.g. \\n, \\t)")
    p_write.add_argument("--stdin", action="store_true", help="Read secret binary data stream from stdin")
    p_write.add_argument("-o", "--output", help="Output carrier file path (default: in-place)")
    p_write.add_argument("-p", "--password", help="Password for encryption")
    p_write.add_argument("--password-file", help="Read password from UTF-8 file")
    p_write.add_argument("-e", "--encrypt", action="store_true", help="Prompt password for encryption")
    p_write.add_argument("-s", "--strategy", default="auto", help="Hiding strategy (auto|ask|<name>)")
    p_write.add_argument("--stealth", action="store_true", help="Stealth mode (strip static signatures)")
    p_write.add_argument("--no-preserve-time", dest="preserve_time", action="store_false", help="Do not preserve original file timestamps")
    p_write.add_argument("--no-backup", dest="backup", action="store_false", help="Do not create .bak backup in in-place mode")
    p_write.set_defaults(func=cmd_write, preserve_time=True, backup=True)

    # read
    p_read = subparsers.add_parser("read", help="Extract hidden data from a carrier file")
    p_read.add_argument("-c", "--carrier", required=True, help="Host carrier file")
    p_read.add_argument("-o", "--output", help="Output file or directory")
    p_read.add_argument("-p", "--password", help="Password for decryption")
    p_read.add_argument("--password-file", help="Read password from UTF-8 file")
    p_read.add_argument("--stdout", action="store_true", help="Force output to stdout")
    p_read.set_defaults(func=cmd_read)

    # remove
    p_remove = subparsers.add_parser("remove", aliases=["strip"], help="100%% loss-free restore and stripping")
    p_remove.add_argument("-c", "--carrier", required=True, help="Host carrier file")
    p_remove.add_argument("-o", "--output", help="Output file path (default: in-place)")
    p_remove.add_argument("-p", "--password", help="Password for stealth mode removal")
    p_remove.add_argument("--password-file", help="Read password from UTF-8 file")
    p_remove.add_argument("--no-backup", dest="backup", action="store_false", help="Do not create .bak backup in in-place mode")
    p_remove.set_defaults(func=cmd_remove, backup=True)

    # inspect
    p_inspect = subparsers.add_parser("inspect", help="Inspect carrier structure and hidden metadata")
    p_inspect.add_argument("-c", "--carrier", required=True, help="Host carrier file")
    p_inspect.add_argument("-p", "--password", help="Password to decrypt metadata")
    p_inspect.add_argument("--password-file", help="Read password from UTF-8 file")
    p_inspect.add_argument("--json", action="store_true", help="Output in JSON format")
    p_inspect.set_defaults(func=cmd_inspect)

    # verify
    p_verify = subparsers.add_parser("verify", help="Diagnose host integrity and envelope health")
    p_verify.add_argument("-c", "--carrier", required=True, help="Host carrier file")
    p_verify.add_argument("-p", "--password", help="Password for level 3 payload check")
    p_verify.add_argument("--password-file", help="Read password from UTF-8 file")
    p_verify.add_argument("--json", action="store_true", help="Output in JSON format")
    p_verify.set_defaults(func=cmd_verify)

    # list-strategies
    p_list = subparsers.add_parser("list-strategies", help="List available strategies for a carrier")
    p_list.add_argument("-c", "--carrier", required=True, help="Host carrier file")
    p_list.set_defaults(func=cmd_list_strategies)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
