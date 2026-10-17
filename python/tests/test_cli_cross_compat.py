"""Test cross-platform, cross-shell compatibility:
1. Unicode normalization (macOS NFD vs Windows/Linux NFC).
2. Password from environment variable (STRHIDE_PASSWORD).
3. Password from UTF-8 file (--password-file).
4. Binary stdin streaming (--stdin).
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import pytest

from strhide.core.crypto import compute_file_sha256, derive_keys
from strhide.core.engine import read_carrier, remove_carrier, write_carrier

TESTFILES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "temp", "testfiles"))


def test_unicode_nfc_nfd_password_compatibility():
    """Verify that passwords typed on macOS (NFD) and Windows/Linux (NFC) decrypt each other."""
    # Base text with accented characters and Chinese
    base_text = "café_naïve_résumé_密码_2026"
    pwd_nfc = unicodedata.normalize("NFC", base_text)
    pwd_nfd = unicodedata.normalize("NFD", base_text)

    # Prove that the raw bytes of NFC and NFD strings are actually DIFFERENT without normalization
    assert pwd_nfc.encode("utf-8") != pwd_nfd.encode("utf-8")

    # In strhide, both MUST derive the exact same payload key and meta key!
    salt = os.urandom(16)
    k_payload_nfc, k_meta_nfc = derive_keys(pwd_nfc, salt)
    k_payload_nfd, k_meta_nfd = derive_keys(pwd_nfd, salt)

    assert k_payload_nfc == k_payload_nfd
    assert k_meta_nfc == k_meta_nfd

    # Test full write with NFD and read with NFC
    carrier_src = os.path.join(TESTFILES_DIR, "file-09.png")
    if not os.path.exists(carrier_src):
        pytest.skip("file-09.png not found")

    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "nfc_nfd_test.png")
        shutil.copy2(carrier_src, carrier)
        orig_sha = compute_file_sha256(carrier)

        # Write with NFD password (typical from macOS terminal/bash)
        write_carrier(carrier, data_text="Secret NFD data", password=pwd_nfd)

        # Read with NFC password (typical from Windows PowerShell / Linux)
        res_r = read_carrier(carrier, password=pwd_nfc)
        assert res_r["data"].decode("utf-8") == "Secret NFD data"

        # Remove with NFC password
        remove_carrier(carrier, password=pwd_nfc)
        assert compute_file_sha256(carrier) == orig_sha


def test_cli_env_var_password_and_password_file():
    """Test CLI invoking with STRHIDE_PASSWORD env var and --password-file."""
    carrier_src = os.path.join(TESTFILES_DIR, "file-06.jpg")
    if not os.path.exists(carrier_src):
        pytest.skip("file-06.jpg not found")

    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "cli_test.jpg")
        shutil.copy2(carrier_src, carrier)
        orig_sha = compute_file_sha256(carrier)

        # 1. Test password via environment variable (useful for Node.js / Go / Rust exec)
        env = os.environ.copy()
        env["STRHIDE_PASSWORD"] = "EnvSecretPassword!2026_环境变量密码"
        env["PYTHONPATH"] = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

        # Write using env var password
        cmd_w = [sys.executable, "-m", "strhide", "write", "-c", carrier, "-t", "Env Secret Message"]
        proc = subprocess.run(cmd_w, env=env, capture_output=True, text=True)
        assert proc.returncode == 0, f"Write failed: {proc.stderr}"

        # 2. Test reading using --password-file
        pwd_file = os.path.join(tmpdir, "pass.txt")
        with open(pwd_file, "w", encoding="utf-8") as f:
            f.write("EnvSecretPassword!2026_环境变量密码\n")

        cmd_r = [sys.executable, "-m", "strhide", "read", "-c", carrier, "--password-file", pwd_file, "--stdout"]
        proc_r = subprocess.run(cmd_r, env=env, capture_output=True, text=True, encoding="utf-8")
        assert proc_r.returncode == 0, f"Read failed: {proc_r.stderr}"
        assert "Env Secret Message" in proc_r.stdout

        # 3. Test remove using --password-file
        cmd_rm = [sys.executable, "-m", "strhide", "remove", "-c", carrier, "--password-file", pwd_file]
        proc_rm = subprocess.run(cmd_rm, env=env, capture_output=True, text=True)
        assert proc_rm.returncode == 0, f"Remove failed: {proc_rm.stderr}"
        assert compute_file_sha256(carrier) == orig_sha


def test_cli_stdin_binary_pipeline():
    """Test feeding raw arbitrary binary data via standard input pipeline (--stdin)."""
    carrier_src = os.path.join(TESTFILES_DIR, "file-17.zip")
    if not os.path.exists(carrier_src):
        pytest.skip("file-17.zip not found")

    raw_binary_input = bytes(range(256)) * 8  # 2048 bytes with all 0x00..0xFF
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "stdin_test.zip")
        shutil.copy2(carrier_src, carrier)
        orig_sha = compute_file_sha256(carrier)

        # Pipe raw binary bytes into stdin
        cmd_w = [sys.executable, "-m", "strhide", "write", "-c", carrier, "--stdin", "-p", "PipePass2026"]
        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

        proc = subprocess.run(cmd_w, input=raw_binary_input, env=env, capture_output=True)
        assert proc.returncode == 0, f"Stdin write failed: {proc.stderr.decode('utf-8', errors='ignore')}"

        # Read back using python API
        res_r = read_carrier(carrier, password="PipePass2026")
        assert res_r["data"] == raw_binary_input

        # Remove & check 100% SHA256 restoration
        remove_carrier(carrier)
        assert compute_file_sha256(carrier) == orig_sha
