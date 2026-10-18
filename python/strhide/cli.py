"""Command-line interface for strhide."""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
from typing import Optional

from strhide.adapters import ADAPTERS
from strhide.config import FileConfig, load_config
from strhide.core.engine import (
    inspect_carrier,
    read_carrier,
    remove_carrier,
    sanitize_filename,
    verify_carrier,
    write_carrier,
)
from strhide.core.router import find_adapter_or_reject
from strhide.errors import PasswordError, StrHideError


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


def resolve_password(
    args: argparse.Namespace, confirm: bool = False, cfg: Optional[FileConfig] = None
) -> Optional[str]:
    """Resolve password from CLI arg, password file, environment variable,
    config file, or interactive prompt (in that order)."""
    cfg = cfg or FileConfig()
    if getattr(args, "password", None):
        return args.password
    if getattr(args, "password_file", None):
        with open(args.password_file, "r", encoding="utf-8") as f:
            return f.read().strip("\r\n")
    if os.environ.get("STRHIDE_PASSWORD"):
        return os.environ.get("STRHIDE_PASSWORD")
    # Config file sources come after CLI args and the environment variable.
    if cfg.password:
        return cfg.password
    if cfg.password_file:
        with open(cfg.password_file, "r", encoding="utf-8") as f:
            return f.read().strip("\r\n")
    if getattr(args, "encrypt", False):
        # Only prompt when a terminal is actually attached. Both stdin and
        # stdout must be TTYs: some environments (e.g. Git Bash with
        # `< /dev/null`) report stdin as a TTY while no console exists, which
        # would make getpass block forever.
        if sys.stdin.isatty() and sys.stdout.isatty():
            return prompt_password(confirm=confirm)
        raise StrHideError(
            "Password required but no interactive terminal is available. "
            "Use -p/--password, --password-file, or STRHIDE_PASSWORD."
        )
    return None


def unescape_string(s: str) -> str:
    """Decode C-style escape sequences, mirroring the Rust implementation
    character for character.

    Supported: ``\\n \\r \\t \\a \\b \\f \\v \\\\ \\' \\"``, octal ``\\ooo``
    (1-3 digits, up to U+01FF), ``\\xHH`` (exactly 2 hex digits), ``\\uHHHH``
    (exactly 4, surrogate pairs combined, lone surrogates become U+FFFD),
    ``\\UHHHHHHHH`` (8 hex digits). Malformed or unknown escapes are preserved
    verbatim. Non-ASCII input is kept as text (the previous ``unicode_escape``
    path re-decoded it through latin-1 and mangled it).
    """
    chars = list(s)
    n = len(chars)
    out: list[str] = []

    def read_hex(start: int, count: int) -> Optional[int]:
        if start + count > n:
            return None
        value = 0
        for k in range(count):
            d = chars[start + k]
            if d not in "0123456789abcdefABCDEF":
                return None
            value = value * 16 + int(d, 16)
        return value

    simple = {
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "a": "\a",
        "b": "\b",
        "f": "\f",
        "v": "\v",
        "\\": "\\",
        "'": "'",
        '"': '"',
    }

    i = 0
    while i < n:
        c = chars[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        esc = chars[i + 1]
        if esc in simple:
            out.append(simple[esc])
            i += 2
        elif esc in "01234567":
            value = 0
            consumed = 0
            while consumed < 3:
                idx = i + 1 + consumed
                if idx < n and chars[idx] in "01234567":
                    value = value * 8 + int(chars[idx], 8)
                    consumed += 1
                else:
                    break
            out.append(chr(value))
            i += 1 + consumed
        elif esc == "x":
            v = read_hex(i + 2, 2)
            if v is None:
                out.append("\\")
                i += 1
            else:
                out.append(chr(v))
                i += 4
        elif esc == "u":
            v = read_hex(i + 2, 4)
            if v is None:
                out.append("\\")
                i += 1
                continue
            consumed = 4
            # Combine a UTF-16 surrogate pair written as two \u escapes.
            # `consumed` counts characters after the leading "\u": the second
            # escape adds its own 6 characters ("\u" + 4 digits). Its digits
            # start at i + 8.
            if 0xD800 <= v <= 0xDBFF:
                low = read_hex(i + 8, 4)
                if low is not None and 0xDC00 <= low <= 0xDFFF:
                    v = 0x10000 + ((v - 0xD800) << 10) + (low - 0xDC00)
                    consumed = 10
            if 0xD800 <= v <= 0xDFFF:
                out.append("\ufffd")
            else:
                out.append(chr(v))
            i += 2 + consumed
        elif esc == "U":
            v = read_hex(i + 2, 8)
            if v is None:
                out.append("\\")
                i += 1
            else:
                try:
                    out.append(chr(v))
                except ValueError:
                    out.append("\ufffd")
                i += 10
        else:
            out.append("\\")
            out.append(esc)
            i += 2
    return "".join(out)


def _apply_config_defaults(args: argparse.Namespace, cfg: FileConfig) -> None:
    """Merge config file values into parsed args as defaults.

    Explicit CLI flags already parsed into ``args`` always win; config values
    only fill in where argparse left its built-in default untouched. Note:
    a ``true`` value in the config for a store_true-style flag cannot be
    disabled from the command line (remove it from the config instead).
    """
    # write-only keys
    if getattr(args, "strategy", None) is None:
        args.strategy = cfg.strategy or "auto"
    for flag in ("stealth", "encrypt", "unescape"):
        if hasattr(args, flag) and not getattr(args, flag) and getattr(cfg, flag):
            setattr(args, flag, True)
    if getattr(args, "preserve_time", True) and cfg.preserve_time is False:
        args.preserve_time = False
    if getattr(args, "backup", True) and cfg.backup is False:
        args.backup = False
    if getattr(args, "hint", None) is None and cfg.hint:
        args.hint = cfg.hint


def cmd_write(args: argparse.Namespace, cfg: FileConfig) -> int:
    # --stealth implies encryption (its magics are password-derived); prompt
    # for a password when neither -p nor a password source was supplied.
    args.encrypt = bool(getattr(args, "encrypt", False)) or bool(getattr(args, "stealth", False))
    password = resolve_password(args, confirm=True, cfg=cfg)

    strategy = args.strategy
    if strategy == "ask":
        with open(args.carrier, "rb") as f:
            adapter = find_adapter_or_reject(f, args.carrier)
            strats = adapter.supported_strategies()
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
        text_data = unescape_string(text_data)

    try:
        res = write_carrier(
            carrier_path=args.carrier,
            data_file=args.data,
            data_text=text_data,
            data_stdin=getattr(args, "stdin", False),
            output_path=args.output,
            password=password,
            password_hint=getattr(args, "hint", None),
            strategy=strategy,
            stealth=args.stealth,
            preserve_time=args.preserve_time,
            backup=getattr(args, "backup", True),
        )
        print(f"[OK] Successfully embedded into '{res['carrier']}' using strategy '{res['strategy']}'.")
        print(f"     Payload: {res['raw_size']} bytes -> UBE: {res['ube_size']} bytes.")
        if res.get("strategy_note"):
            print(f"     [STRATEGY] {res['strategy_note']}")
        if res.get("password_hint"):
            print(f"     Password Hint: '{res['password_hint']}'.")
        if res.get("backup_file"):
            print(f"     [BACKUP] Original carrier backed up to '{res['backup_file']}'.")
        if res.get("warning"):
            print(f"[WARNING] {res['warning']}", file=sys.stderr)
        return 0
    except StrHideError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


def cmd_read(args: argparse.Namespace, cfg: FileConfig) -> int:
    password = resolve_password(args, confirm=False, cfg=cfg)
    try:
        res = read_carrier(
            carrier_path=args.carrier,
            output_path=args.output,
            password=password,
        )
    except PasswordError as e:
        # Discriminate by exception type, not by message text.
        if password:
            print(f"[ERROR] {e}", file=sys.stderr)
            return 1
        err_msg = str(e)
        if "Hint: '" in err_msg:
            try:
                hint_part = err_msg.split("Hint: '", 1)[1].rsplit("'", 1)[0]
                print(f"[INFO] Password hint: {hint_part}")
            except Exception:
                pass
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            print(
                "[ERROR] Password required but no interactive terminal is available. "
                "Use -p/--password, --password-file, or STRHIDE_PASSWORD.",
                file=sys.stderr,
            )
            return 1
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
    except StrHideError as e:
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
        # Default filename in current dir; the metadata filename is untrusted
        # input, so sanitize it to a bare name (no traversal, no absolute path).
        fn = sanitize_filename(res.get("filename") or "extracted.bin")
        with open(fn, "wb") as f:
            f.write(res["data"])
        print(f"[OK] Extracted payload to '{fn}' ({res['raw_size']} bytes).")

    return 0


def cmd_remove(args: argparse.Namespace, cfg: FileConfig) -> int:
    password = resolve_password(args, confirm=False, cfg=cfg)
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


def cmd_inspect(args: argparse.Namespace, cfg: FileConfig) -> int:
    password = resolve_password(args, confirm=False, cfg=cfg)
    try:
        res = inspect_carrier(carrier_path=args.carrier, password=password)
        if args.json:
            print(json.dumps(res, indent=2, ensure_ascii=False))
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
                if res.get("password_hint"):
                    print(f"Password Hint:   {res['password_hint']}")
                print(f"Original Size:   {res['orig_host_size']} bytes")
                print(f"Original SHA256: {res['orig_host_sha256']}")
                if res.get("metadata"):
                    print(f"Metadata:        {json.dumps(res['metadata'], ensure_ascii=False)}")

            # Capacity report (available whether or not an envelope exists).
            # The first available strategy is what `-s auto` would pick for a
            # payload that fits.
            strategies = res.get("strategies", [])
            auto_idx = next(
                (i for i, c in enumerate(strategies) if c.get("available")), None
            )
            print("Strategy capacities (max payload size):")
            for idx, c in enumerate(strategies):
                auto = " [auto preference]" if idx == auto_idx else ""
                state = "" if c.get("available") else " (unavailable)"
                detail = c.get("note") or ""
                line = f"  - {c['strategy']}{auto}{state}: {c['limit']}"
                if detail:
                    line += f" — {detail}"
                print(line)
        return 0
    except StrHideError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


def cmd_verify(args: argparse.Namespace, cfg: FileConfig) -> int:
    password = resolve_password(args, confirm=False, cfg=cfg)
    try:
        res = verify_carrier(carrier_path=args.carrier, password=password)
        if args.json:
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print(f"Carrier: {res['carrier']} ({res['format']})")
            print(f"  Level 1 (Host Structure):    {'[PASS]' if res['level1_host']['ok'] else '[FAIL]'} {res['level1_host']['detail']}")
            print(f"  Level 2 (Envelope Boundary): {'[PASS]' if res['level2_envelope']['ok'] else '[FAIL]'} {res['level2_envelope']['detail']}")
            print(f"  Level 3 (Crypto & Payload):  {'[PASS]' if res['level3_crypto']['ok'] else '[WARN]'} {res['level3_crypto']['detail']}")
        return 0 if (res["level1_host"]["ok"] and res["level2_envelope"]["ok"]) else 1
    except StrHideError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


def cmd_list_strategies(args: argparse.Namespace, cfg: FileConfig) -> int:
    # Static reference table: constants come from the adapters themselves, so
    # the table cannot drift from the code. Carrier-specific limits are
    # answered by `strhide inspect -c <carrier>`.
    print(f"{'Format':<8} {'Strategy':<15} Limit")
    print(f"{'-' * 8} {'-' * 15} {'-' * 48}")
    for adapter in ADAPTERS:
        for cap in adapter.strategy_capacities(None):
            print(f"{adapter.format_name():<8} {cap.strategy:<15} {cap.limit}")
    print()
    print("Carrier-dependent limits are measured by `strhide inspect -c <carrier>`.")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    config_parent = argparse.ArgumentParser(add_help=False)
    # SUPPRESS keeps a subcommand that omits --config from clobbering a value
    # given before the subcommand (subparser results overwrite the namespace).
    config_parent.add_argument(
        "--config",
        default=argparse.SUPPRESS,
        help="Path to TOML config file (default: ./strhide.toml, then ~/.strhide/config.toml)",
    )
    parser = argparse.ArgumentParser(
        prog="strhide",
        description="Smart format-preserving lossless data hiding CLI tool.",
        parents=[config_parent],
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # write
    p_write = subparsers.add_parser(
        "write", parents=[config_parent], help="Hide data inside a carrier file"
    )
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
    p_write.add_argument("-H", "--hint", "--password-hint", dest="hint", help="Optional password hint (displayed if password is required/forgotten)")
    p_write.add_argument("-e", "--encrypt", action="store_true", help="Prompt password for encryption")
    p_write.add_argument(
        "-s", "--strategy", default=None,
        help="Hiding strategy (auto|ask|<name>; default: auto or config file)",
    )
    p_write.add_argument("--stealth", action="store_true", help="Stealth mode (strip static signatures)")
    p_write.add_argument("--no-preserve-time", dest="preserve_time", action="store_false", help="Do not preserve original file timestamps")
    p_write.add_argument("--no-backup", dest="backup", action="store_false", help="Do not create .bak backup in in-place mode")
    p_write.set_defaults(func=cmd_write, preserve_time=True, backup=True)

    # read
    p_read = subparsers.add_parser(
        "read", parents=[config_parent], help="Extract hidden data from a carrier file"
    )
    p_read.add_argument("-c", "--carrier", required=True, help="Host carrier file")
    p_read.add_argument("-o", "--output", help="Output file or directory")
    p_read.add_argument("-p", "--password", help="Password for decryption")
    p_read.add_argument("--password-file", help="Read password from UTF-8 file")
    p_read.add_argument("--stdout", action="store_true", help="Force output to stdout")
    p_read.set_defaults(func=cmd_read)

    # remove
    p_remove = subparsers.add_parser(
        "remove", aliases=["strip"], parents=[config_parent], help="100%% loss-free restore and stripping"
    )
    p_remove.add_argument("-c", "--carrier", required=True, help="Host carrier file")
    p_remove.add_argument("-o", "--output", help="Output file path (default: in-place)")
    p_remove.add_argument("-p", "--password", help="Password for stealth mode removal")
    p_remove.add_argument("--password-file", help="Read password from UTF-8 file")
    p_remove.add_argument("--no-backup", dest="backup", action="store_false", help="Do not create .bak backup in in-place mode")
    p_remove.set_defaults(func=cmd_remove, backup=True)

    # inspect
    p_inspect = subparsers.add_parser(
        "inspect", parents=[config_parent], help="Inspect carrier structure and hidden metadata"
    )
    p_inspect.add_argument("-c", "--carrier", required=True, help="Host carrier file")
    p_inspect.add_argument("-p", "--password", help="Password to decrypt metadata")
    p_inspect.add_argument("--password-file", help="Read password from UTF-8 file")
    p_inspect.add_argument("--json", action="store_true", help="Output in JSON format")
    p_inspect.set_defaults(func=cmd_inspect)

    # verify
    p_verify = subparsers.add_parser(
        "verify", parents=[config_parent], help="Diagnose host integrity and envelope health"
    )
    p_verify.add_argument("-c", "--carrier", required=True, help="Host carrier file")
    p_verify.add_argument("-p", "--password", help="Password for level 3 payload check")
    p_verify.add_argument("--password-file", help="Read password from UTF-8 file")
    p_verify.add_argument("--json", action="store_true", help="Output in JSON format")
    p_verify.set_defaults(func=cmd_verify)

    # list-strategies
    p_list = subparsers.add_parser(
        "list-strategies",
        parents=[config_parent],
        help="List all supported formats, strategies, and their capacity limits",
    )
    p_list.set_defaults(func=cmd_list_strategies)

    args = parser.parse_args(argv)
    try:
        cfg = load_config(getattr(args, "config", None))
    except StrHideError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
    _apply_config_defaults(args, cfg)
    return args.func(args, cfg)


if __name__ == "__main__":
    sys.exit(main())
