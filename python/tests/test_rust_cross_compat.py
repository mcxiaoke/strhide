"""Cross-compatibility tests between Python and Rust implementations of strhide."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import pytest

# Determine paths
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RUST_BIN = os.path.join(ROOT_DIR, "rust", "target", "debug", "strhide.exe")
TESTFILES_DIR = os.path.join(ROOT_DIR, "temp", "testfiles")
PYTHON_CLI = [sys.executable, "-m", "strhide.cli"]

env = os.environ.copy()
env["PYTHONPATH"] = os.path.abspath(os.path.join(ROOT_DIR, "python"))


def run_rust(*args) -> subprocess.CompletedProcess:
    assert os.path.exists(RUST_BIN), f"Rust binary not found at {RUST_BIN}"
    return subprocess.run([RUST_BIN, *args], capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)


def run_python(*args) -> subprocess.CompletedProcess:
    return subprocess.run([*PYTHON_CLI, *args], capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


@pytest.fixture
def tmp_workspace():
    with tempfile.TemporaryDirectory() as td:
        yield td


def test_rust_binary_exists():
    assert os.path.exists(RUST_BIN)
    res = run_rust("--help")
    assert res.returncode == 0
    assert "Smart multi-format lossless container data hiding tool" in res.stdout


def test_roundtrip_rust_write_python_read_plain(tmp_workspace):
    """Rust writes plaintext -> Python reads, verifies, and removes."""
    orig_src = os.path.join(TESTFILES_DIR, "file-02.png")
    if not os.path.exists(orig_src):
        pytest.skip(f"Sample {orig_src} not found")

    carrier = os.path.join(tmp_workspace, "carrier.png")
    shutil.copy2(orig_src, carrier)
    orig_sha = sha256_file(carrier)

    secret_text = "Hello from Rust to Python! Interop verified."

    # 1. Rust writes
    res = run_rust("write", "-c", carrier, "-t", secret_text, "--strategy", "chunk")
    assert res.returncode == 0, res.stderr
    assert "[OK]" in res.stdout

    # 2. Python verifies
    res = run_python("verify", "-c", carrier, "--json")
    assert res.returncode == 0, res.stderr
    v = json.loads(res.stdout)
    assert v["level1_host"]["ok"] is True
    assert v["level2_envelope"]["ok"] is True
    assert v["level3_crypto"]["ok"] is True

    # 3. Python reads
    res = run_python("read", "-c", carrier, "--stdout")
    assert res.returncode == 0, res.stderr
    assert secret_text in res.stdout

    # 4. Python removes
    res = run_python("remove", "-c", carrier, "--no-backup")
    assert res.returncode == 0, res.stderr
    assert sha256_file(carrier) == orig_sha


def test_roundtrip_python_write_rust_read_encrypted_hint(tmp_workspace):
    """Python writes with password and hint -> Rust reads with password and hint, verifies, removes."""
    orig_src = os.path.join(TESTFILES_DIR, "file-06.jpg")
    if not os.path.exists(orig_src):
        pytest.skip(f"Sample {orig_src} not found")

    carrier = os.path.join(tmp_workspace, "carrier.jpg")
    shutil.copy2(orig_src, carrier)
    orig_sha = sha256_file(carrier)

    secret_text = "Encrypted secret message with CJK & Accents: 密码-Pässwörd-123456!"
    password = "MyComplexPassword@2026"
    hint = "Year 2026 password"

    # 1. Python writes
    res = run_python(
        "write", "-c", carrier, "-t", secret_text, "-p", password, "-H", hint, "--strategy", "app_segment"
    )
    assert res.returncode == 0, res.stderr

    # 2. Rust inspects
    res = run_rust("inspect", "-c", carrier, "--json")
    assert res.returncode == 0, res.stderr
    info = json.loads(res.stdout)
    assert info["has_hidden_data"] is True
    assert info["strategy"] == "app_segment"
    assert info["is_encrypted"] is True
    assert info["password_hint"] == hint

    # 3. Rust verifies
    res = run_rust("verify", "-c", carrier, "-p", password, "--json")
    assert res.returncode == 0, res.stderr
    v = json.loads(res.stdout)
    assert v["level1_host"]["ok"] is True
    assert v["level2_envelope"]["ok"] is True
    assert v["level3_crypto"]["ok"] is True

    # 4. Rust reads
    res = run_rust("read", "-c", carrier, "-p", password, "--stdout")
    assert res.returncode == 0, res.stderr
    assert secret_text in res.stdout

    # 5. Rust removes
    res = run_rust("remove", "-c", carrier, "-p", password, "--no-backup")
    assert res.returncode == 0, res.stderr
    assert sha256_file(carrier) == orig_sha


def test_roundtrip_rust_write_stealth_python_read(tmp_workspace):
    """Rust writes in --stealth mode -> Python reads in stealth mode."""
    orig_src = os.path.join(TESTFILES_DIR, "file-00.mp4")
    if not os.path.exists(orig_src):
        pytest.skip(f"Sample {orig_src} not found")

    carrier = os.path.join(tmp_workspace, "carrier.mp4")
    shutil.copy2(orig_src, carrier)
    orig_sha = sha256_file(carrier)

    secret_text = "Stealth MP4 payload: completely deniable container data."
    password = "StealthKey#99"

    # 1. Rust writes stealth
    res = run_rust("write", "-c", carrier, "-t", secret_text, "-p", password, "--stealth")
    assert res.returncode == 0, res.stderr

    # 2. Python inspects without password -> should report no hidden data (plausible deniability)
    res = run_python("inspect", "-c", carrier, "--json")
    assert res.returncode == 0, res.stderr
    info = json.loads(res.stdout)
    assert info["has_hidden_data"] is False

    # 3. Python reads with password
    res = run_python("read", "-c", carrier, "-p", password, "--stdout")
    assert res.returncode == 0, res.stderr
    assert secret_text in res.stdout

    # 4. Python removes
    res = run_python("remove", "-c", carrier, "-p", password, "--no-backup")
    assert res.returncode == 0, res.stderr
    assert sha256_file(carrier) == orig_sha


@pytest.mark.parametrize(
    "sample_file,strategy",
    [
        ("file-02.png", "chunk"),
        ("file-02.png", "eof"),
        ("file-06.jpg", "app_segment"),
        ("file-06.jpg", "eof"),
        ("file-00.mp4", "box_uuid"),
        ("file-00.mp4", "eof"),
        ("file-17.zip", "pre_cd_inject"),
        ("file-17.zip", "eof"),
        ("file-11.pdf", "incremental"),
        ("file-11.pdf", "eof"),
        ("caffeine64.exe", "pe_overlay"),
        ("caffeine64.exe", "eof"),
    ],
)
def test_all_strategies_bidirectional_interop(tmp_workspace, sample_file, strategy):
    """Test every supported strategy bidirectionally:
    1. Python writes -> Rust reads and removes (100% SHA256 match)
    2. Rust writes -> Python reads and removes (100% SHA256 match)
    """
    orig_src = os.path.join(TESTFILES_DIR, sample_file)
    if not os.path.exists(orig_src):
        pytest.skip(f"Sample {orig_src} not found")

    secret_text = f"Bi-directional interop test for {sample_file} with strategy {strategy}."
    password = "CrossTestPassword123"

    # --- Direction 1: Python writes -> Rust reads/removes ---
    carrier1 = os.path.join(tmp_workspace, f"py_{sample_file}")
    shutil.copy2(orig_src, carrier1)
    orig_sha1 = sha256_file(carrier1)

    res = run_python("write", "-c", carrier1, "-t", secret_text, "-p", password, "--strategy", strategy)
    assert res.returncode == 0, res.stderr

    res = run_rust("read", "-c", carrier1, "-p", password, "--stdout")
    assert res.returncode == 0, res.stderr
    assert secret_text in res.stdout

    res = run_rust("remove", "-c", carrier1, "-p", password, "--no-backup")
    assert res.returncode == 0, res.stderr
    assert sha256_file(carrier1) == orig_sha1

    # --- Direction 2: Rust writes -> Python reads/removes ---
    carrier2 = os.path.join(tmp_workspace, f"rs_{sample_file}")
    shutil.copy2(orig_src, carrier2)
    orig_sha2 = sha256_file(carrier2)

    res = run_rust("write", "-c", carrier2, "-t", secret_text, "-p", password, "--strategy", strategy)
    assert res.returncode == 0, res.stderr

    res = run_python("read", "-c", carrier2, "-p", password, "--stdout")
    assert res.returncode == 0, res.stderr
    assert secret_text in res.stdout

    res = run_python("remove", "-c", carrier2, "-p", password, "--no-backup")
    assert res.returncode == 0, res.stderr
    assert sha256_file(carrier2) == orig_sha2


def test_rust_rejection_security(tmp_workspace):
    """Verify Rust CLI enforces security rejections."""
    # 1. Standalone signature file
    sig_file = os.path.join(tmp_workspace, "test.sig")
    with open(sig_file, "w") as f:
        f.write("dummy signature")
    res = run_rust("write", "-c", sig_file, "-t", "secret")
    assert res.returncode != 0
    assert "standalone digital signature" in res.stderr

    # 2. APK file
    apk_file = os.path.join(TESTFILES_DIR, "file-07.apk")
    if os.path.exists(apk_file):
        res = run_rust("write", "-c", apk_file, "-t", "secret")
        assert res.returncode != 0
        assert "APK 格式不在支持列表中" in res.stderr
