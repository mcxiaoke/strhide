"""Unit and integration tests for password hint functionality."""

import json
import os
import subprocess
import sys
import tempfile
import pytest

from strhide.core.crypto import compute_file_sha256
from strhide.core.engine import inspect_carrier, read_carrier, remove_carrier, write_carrier
from strhide.errors import PasswordError, StrHideError


def make_dummy_png(path: str) -> None:
    """Create a minimal valid PNG file."""
    import struct
    import zlib

    magic = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
    ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)

    idat_data = zlib.compress(b"\x00\xff\x00\x00" + os.urandom(2000))
    idat_crc = zlib.crc32(b"IDAT" + idat_data)
    idat_chunk = struct.pack(">I", len(idat_data)) + b"IDAT" + idat_data + struct.pack(">I", idat_crc)

    iend_crc = zlib.crc32(b"IEND")
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

    with open(path, "wb") as f:
        f.write(magic + ihdr_chunk + idat_chunk + iend_chunk)


def test_password_hint_lifecycle():
    """Verify write with hint, inspect showing hint, read error showing hint, and 100% restore."""
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "test.png")
        make_dummy_png(carrier)
        orig_sha = compute_file_sha256(carrier).hex()

        hint_text = "高中班级号+母亲生日年份（如：3班1975）"
        pwd = "MySecretPassword_2026!"
        secret = "This is a very top secret message."

        # 1. Write with password and hint
        res_w = write_carrier(
            carrier,
            data_text=secret,
            password=pwd,
            password_hint=hint_text,
            backup=False,
        )
        assert res_w["password_hint"] == hint_text
        assert res_w["is_encrypted"] is True

        # 2. Inspect carrier without password: hint must be visible!
        res_insp = inspect_carrier(carrier)
        assert res_insp["is_encrypted"] is True
        assert res_insp["password_hint"] == hint_text

        # 3. Read carrier without password: must raise PasswordError with hint text!
        with pytest.raises(PasswordError) as exc_info:
            read_carrier(carrier)
        assert hint_text in str(exc_info.value)

        # 4. Read carrier with correct password: must extract successfully!
        res_r = read_carrier(carrier, password=pwd)
        assert res_r["data"].decode("utf-8") == secret
        assert res_r["password_hint"] == hint_text

        # 5. Remove carrier: 100% loss-free restore
        res_rm = remove_carrier(carrier, password=pwd, backup=False)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier).hex() == orig_sha


def test_stealth_mode_rejects_hint():
    """Verify stealth mode strictly rejects hint (stealth requires password to locate)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "test.png")
        make_dummy_png(carrier)

        with pytest.raises(StrHideError) as exc_info:
            write_carrier(
                carrier,
                data_text="secret",
                password="pwd",
                password_hint="some hint",
                stealth=True,
                backup=False,
            )
        assert "not supported in --stealth mode" in str(exc_info.value)


def test_no_hint_behavior():
    """Verify behavior when no hint is provided."""
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "test.png")
        make_dummy_png(carrier)

        write_carrier(carrier, data_text="secret", password="pwd", backup=False)

        res_insp = inspect_carrier(carrier)
        assert res_insp["password_hint"] is None

        with pytest.raises(PasswordError) as exc_info:
            read_carrier(carrier)
        assert "Password hint" not in str(exc_info.value)


def test_unicode_and_emoji_hint():
    """Verify hint supporting Chinese, Unicode, and Emoji with NFC normalization."""
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "test.png")
        make_dummy_png(carrier)

        hint = "🔑高考考场🎯+手机尾号📱_2026"
        write_carrier(carrier, data_text="secret", password="pwd", password_hint=hint, backup=False)

        res_insp = inspect_carrier(carrier)
        assert res_insp["password_hint"] == hint


def test_password_hint_cli_integration():
    """Test CLI write --hint and inspect."""
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "test.png")
        make_dummy_png(carrier)

        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

        # CLI write with --hint
        hint = "CLI密码提示：大学寝室号"
        cmd_w = [
            sys.executable, "-m", "strhide.cli", "write",
            "-c", carrier,
            "-t", "hello world",
            "-p", "pass123",
            "--hint", hint,
            "--no-backup",
        ]
        cp_w = subprocess.run(cmd_w, env=env, capture_output=True, text=True, check=True)
        assert "[OK]" in cp_w.stdout
        assert hint in cp_w.stdout

        # CLI inspect
        cmd_insp = [
            sys.executable, "-m", "strhide.cli", "inspect",
            "-c", carrier,
        ]
        cp_insp = subprocess.run(cmd_insp, env=env, capture_output=True, text=True, check=True)
        assert f"Password Hint:   {hint}" in cp_insp.stdout

        # CLI inspect JSON
        cmd_json = [
            sys.executable, "-m", "strhide.cli", "inspect",
            "-c", carrier,
            "--json",
        ]
        cp_json = subprocess.run(cmd_json, env=env, capture_output=True, text=True, check=True)
        data = json.loads(cp_json.stdout)
        assert data["password_hint"] == hint
