"""Regression tests for P2 CLI/security alignment (2026-10-17), batch 3.

- #15: ``verify`` must exit non-zero when Level 1 or Level 2 fails (parity
  with the Rust CLI; Level 3 crypto failures are reported only).
- #16: the read password retry must discriminate on the exception type, not
  message text; reading a stealth envelope without its password must produce
  actionable guidance instead of a bare "not found".
- #18: the JAR signature guard must be content-based so a signed archive
  renamed to ``.zip`` cannot bypass it.
- #19: ``--unescape`` must support the full escape set (\\xHH, \\uXXXX,
  \\UXXXXXXXX, octal, \\a\\b\\f\\v) identically in both implementations, and must
  no longer mangle non-ASCII input.
"""

import io
import os
import struct
import subprocess
import sys
import zipfile

import pytest

from strhide.cli import unescape_string
from strhide.core.engine import read_carrier, write_carrier
from strhide.errors import (
    NoHiddenDataError,
    PasswordError,
    RejectionError,
)

# --------------------------------------------------------------------------- helpers


def make_png() -> bytes:
    magic = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr = (
        struct.pack(">I4s", len(ihdr_data), b"IHDR")
        + ihdr_data
        + struct.pack(">I", __import__("zlib").crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    )
    return magic + ihdr + b"\x00\x00\x00\x00IEND\xaeB`\x82"


def make_zip_with_entries(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def cli_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
    return env


# --------------------------------------------------------------------------- #18 JAR signature guard decoupled from extension


def test_signed_zip_renamed_to_zip_is_rejected(tmp_path):
    carrier = str(tmp_path / "signed_archive.zip")
    with open(carrier, "wb") as f:
        f.write(
            make_zip_with_entries(
                [
                    ("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n"),
                    ("META-INF/SIGNER.SF", "Signature-Version: 1.0\r\n"),
                    ("classes/Dummy.class", b"\xca\xfe\xba\xbe"),
                ]
            )
        )

    with pytest.raises(RejectionError) as exc:
        write_carrier(carrier, data_text="payload", output_path=str(tmp_path / "o.zip"))
    msg = str(exc.value)
    assert "digital signature" in msg and "META-INF" in msg, msg


def test_clean_zip_is_still_accepted(tmp_path):
    carrier = str(tmp_path / "clean.zip")
    with open(carrier, "wb") as f:
        f.write(make_zip_with_entries([("hello.txt", b"hello world")]))

    out = str(tmp_path / "o.zip")
    res = write_carrier(carrier, data_text="payload", output_path=out)
    assert res["strategy"] == "pre_cd_inject"
    assert read_carrier(out)["data"] == b"payload"


# --------------------------------------------------------------------------- #19 unescape escape set


def test_unescape_string_full_escape_set():
    assert unescape_string(r"A\x42C\u4E2D\101\tD\U0001F680E\q\a") == (
        "ABC中A\tD🚀E\\q\a"
    )
    # Octal above 0xFF becomes the corresponding code point (CPython's
    # unicode_escape semantics: \777 -> U+01FF).
    assert unescape_string(r"\777") == "\u01ff"
    # Octal NUL
    assert unescape_string(r"\0") == "\0"
    # Surrogate pair written as two \u escapes
    assert unescape_string(r"\uD83D\uDE80") == "🚀"
    # Lone surrogate -> U+FFFD (it cannot be represented in valid UTF-8 text)
    assert unescape_string(r"\uD83D") == "\ufffd"
    # \x takes exactly two hex digits, so "\x4bad" is 0x4B ('K') + "ad".
    assert unescape_string(r"ok\x4bad") == "okKad"
    # Malformed escapes are preserved verbatim instead of aborting the whole
    # unescape (Python previously kept the entire original string).
    assert unescape_string(r"ok\xzbad") == "ok\\xzbad"
    assert unescape_string(r"ok\uZZZZ") == "ok\\uZZZZ"
    # Non-ASCII input survives unmangled (the previous unicode_escape path
    # re-decoded it through latin-1).
    assert unescape_string("中文\\n行") == "中文\n行"
    # Trailing lone backslash
    assert unescape_string("tail\\") == "tail\\"


def test_unescape_cli_end_to_end(tmp_path):
    carrier = str(tmp_path / "c.png")
    out = str(tmp_path / "o.png")
    with open(carrier, "wb") as f:
        f.write(make_png())

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "strhide.cli",
            "write",
            "-c",
            carrier,
            "-t",
            r"A\x42C\u4E2D\101\tD\U0001F680E\q\a",
            "--unescape",
            "-o",
            out,
            "--no-backup",
        ],
        env=cli_env(),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert read_carrier(out)["data"] == "ABC中A\tD🚀E\\q\a".encode("utf-8")


# --------------------------------------------------------------------------- #16 error variants + stealth guidance


def test_read_encrypted_without_password_raises_password_error(tmp_path):
    carrier = str(tmp_path / "c.png")
    out = str(tmp_path / "o.png")
    with open(carrier, "wb") as f:
        f.write(make_png())
    write_carrier(
        carrier,
        data_text="encrypted secret",
        output_path=out,
        password="pw12345",
        password_hint="the hint",
    )

    with pytest.raises(PasswordError) as exc:
        read_carrier(out)
    assert "the hint" in str(exc.value)


def test_stealth_without_password_reports_guidance(tmp_path):
    carrier = str(tmp_path / "c.png")
    out = str(tmp_path / "o.png")
    with open(carrier, "wb") as f:
        f.write(make_png())
    write_carrier(
        carrier,
        data_text="stealth secret",
        output_path=out,
        password="pw12345",
        stealth=True,
    )

    with pytest.raises(NoHiddenDataError) as exc:
        read_carrier(out)
    msg = str(exc.value)
    assert "stealth envelope" in msg, msg
    assert "prIv" in msg, msg

    # A wrong password keeps plausible deniability but still explains the
    # structural evidence.
    with pytest.raises(NoHiddenDataError) as exc:
        read_carrier(out, password="wrong-password")
    assert "different password" in str(exc.value)


def test_clean_file_without_envelope_raises_plain_no_hidden_data(tmp_path):
    carrier = str(tmp_path / "c.png")
    with open(carrier, "wb") as f:
        f.write(make_png())

    with pytest.raises(NoHiddenDataError) as exc:
        read_carrier(carrier)
    assert "No hidden strhide data found" in str(exc.value)
    # No envelope-shaped structures -> no stealth guidance appended.
    assert "stealth envelope" not in str(exc.value)


def test_stealth_read_without_password_cli_reports_guidance(tmp_path):
    carrier = str(tmp_path / "c.png")
    out = str(tmp_path / "o.png")
    with open(carrier, "wb") as f:
        f.write(make_png())
    write_carrier(
        carrier,
        data_text="stealth secret",
        output_path=out,
        password="pw12345",
        stealth=True,
    )

    # Non-TTY run must fail fast (never hang on a password prompt) and print
    # the guidance.
    proc = subprocess.run(
        [sys.executable, "-m", "strhide.cli", "read", "-c", out, "--stdout"],
        env=cli_env(),
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "stealth envelope" in proc.stderr.lower()


# --------------------------------------------------------------------------- #15 verify exit code parity


def test_verify_exit_code_nonzero_when_envelope_invalid(tmp_path):
    carrier = str(tmp_path / "c.bin")
    out = str(tmp_path / "o.bin")
    with open(carrier, "wb") as f:
        f.write(b"generic host file contents for eof strategy")
    write_carrier(carrier, data_text="x", output_path=out, strategy="eof")

    # Patch the version byte (header offset 8) to an unsupported value.
    with open(out, "r+b") as f:
        f.seek(os.path.getsize(carrier) + 8)
        f.write(bytes([0x09]))

    proc = subprocess.run(
        [sys.executable, "-m", "strhide.cli", "verify", "-c", out],
        env=cli_env(),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[FAIL]" in proc.stdout


def test_verify_exit_code_zero_for_valid_carrier(tmp_path):
    carrier = str(tmp_path / "c.png")
    out = str(tmp_path / "o.png")
    with open(carrier, "wb") as f:
        f.write(make_png())
    write_carrier(carrier, data_text="payload", output_path=out)

    proc = subprocess.run(
        [sys.executable, "-m", "strhide.cli", "verify", "-c", out],
        env=cli_env(),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


# --------------------------------------------------------------------------- #20 .bak collision protection


def test_backup_collision_uses_timestamped_name(tmp_path):
    from strhide.core.engine import remove_carrier

    carrier = str(tmp_path / "c.png")
    with open(carrier, "wb") as f:
        f.write(make_png())
    with open(carrier, "rb") as f:
        original = f.read()

    # First in-place write creates the plain .bak
    w1 = write_carrier(carrier, data_text="first")
    bak1 = w1["backup_file"]
    assert bak1.endswith(".bak"), bak1
    with open(bak1, "rb") as f:
        assert f.read() == original

    # Removing in place would previously overwrite that .bak, destroying the
    # only pre-write copy of the carrier.
    r1 = remove_carrier(carrier)
    bak2 = r1["backup_file"]
    assert bak1 != bak2, "backup path was reused"
    assert ".bak-" in bak2, bak2
    assert os.path.exists(bak1), "first backup must be preserved"
    assert os.path.exists(bak2), "second backup must exist"
