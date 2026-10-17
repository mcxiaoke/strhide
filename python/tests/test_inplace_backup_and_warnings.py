"""Unit and integration tests for in-place backups, 50% size warnings, and text safety options."""

import base64
import os
import shutil
import subprocess
import sys
import tempfile
import unicodedata

from strhide.core.crypto import compute_file_sha256
from strhide.core.engine import read_carrier, remove_carrier, write_carrier


def make_dummy_png(path: str, extra_bytes: int = 1000) -> None:
    """Create a valid minimal PNG file with padded IDAT."""
    import struct
    import zlib

    magic = b"\x89PNG\r\n\x1a\n"
    # IHDR
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
    ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)

    # IDAT with padding (use random bytes so zlib doesn't compress to trivial size)
    raw_pixel = b"\x00\xff\x00\x00" + os.urandom(extra_bytes)
    idat_data = zlib.compress(raw_pixel)
    idat_crc = zlib.crc32(b"IDAT" + idat_data)
    idat_chunk = struct.pack(">I", len(idat_data)) + b"IDAT" + idat_data + struct.pack(">I", idat_crc)

    # IEND
    iend_crc = zlib.crc32(b"IEND")
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

    with open(path, "wb") as f:
        f.write(magic + ihdr_chunk + idat_chunk + iend_chunk)


def test_inplace_backup_creation_and_content():
    """Verify in-place write and remove create .bak copies of original files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier_path = os.path.join(tmpdir, "image.png")
        make_dummy_png(carrier_path, extra_bytes=5000)
        orig_sha256 = compute_file_sha256(carrier_path).hex()

        # 1. In-place write with default backup=True
        res = write_carrier(carrier_path, data_text="Secret message 2026", password="pass")
        write_bak = res["backup_file"]
        assert write_bak == carrier_path + ".bak"
        assert os.path.exists(write_bak)

        # The backup file must match the original carrier SHA-256
        bak_sha256 = compute_file_sha256(write_bak).hex()
        assert bak_sha256 == orig_sha256

        # 2. In-place remove with backup=True
        # Carrier currently contains hidden data
        modified_sha256 = compute_file_sha256(carrier_path).hex()
        res_rm = remove_carrier(carrier_path, password="pass")
        remove_bak = res_rm["backup_file"]
        # The plain .bak already exists, so the restore backup must NOT
        # overwrite it (that would destroy the only pre-write copy); it gets a
        # UTC timestamp suffix instead.
        assert remove_bak != write_bak
        assert remove_bak.startswith(carrier_path + ".bak-")

        # Carrier is now restored to original
        assert compute_file_sha256(carrier_path).hex() == orig_sha256
        # The first .bak still holds the pristine original...
        assert compute_file_sha256(write_bak).hex() == orig_sha256
        # ...while the timestamped backup holds the pre-restoration carrier.
        assert compute_file_sha256(remove_bak).hex() == modified_sha256


def test_inplace_no_backup_flag():
    """Verify backup=False disables .bak creation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier_path = os.path.join(tmpdir, "image.png")
        make_dummy_png(carrier_path, extra_bytes=2000)

        res = write_carrier(carrier_path, data_text="Hello", password="123", backup=False)
        assert res.get("backup_file") is None
        assert not os.path.exists(carrier_path + ".bak")


def test_payload_size_inflation_warning():
    """Verify warning is emitted if UBE length exceeds 50% of original carrier file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a small carrier (~1.1 KB)
        carrier_small = os.path.join(tmpdir, "small.png")
        make_dummy_png(carrier_small, extra_bytes=1000)
        small_size = os.path.getsize(carrier_small)

        # Inject 1 KB payload (UBE > 1 KB, which is > 50% of 1.1 KB)
        res_warn = write_carrier(
            carrier_small,
            data_bytes=os.urandom(1000),
            password="pass",
            output_path=os.path.join(tmpdir, "out_warn.png")
        )
        assert res_warn["warning"] is not None
        assert "exceeds 50.0% of carrier file size" in res_warn["warning"]
        assert "Noticeable file size inflation may compromise stealthiness!" in res_warn["warning"]

        # Create a large carrier (~100 KB)
        carrier_large = os.path.join(tmpdir, "large.png")
        make_dummy_png(carrier_large, extra_bytes=100_000)

        # Inject 50 bytes payload (UBE << 50% of 100 KB)
        res_ok = write_carrier(
            carrier_large,
            data_text="Small payload",
            password="pass",
            output_path=os.path.join(tmpdir, "out_ok.png")
        )
        assert res_ok["warning"] is None


def test_cli_text_safety_options():
    """Test CLI options for text safety: --text-file, --text-base64, --unescape, STRHIDE_TEXT."""
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "carrier.png")
        make_dummy_png(carrier, extra_bytes=20_000)

        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

        # 1. Test --text-file
        secret_file = os.path.join(tmpdir, "secret_text.txt")
        complex_content = "多行文本：第一行\n第二行 带特殊符号：$ & \" ' ! 🚀\n第三行\n"
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write(complex_content)

        out_tf = os.path.join(tmpdir, "out_tf.png")
        cmd_tf = [
            sys.executable, "-m", "strhide.cli", "write",
            "-c", carrier,
            "--text-file", secret_file,
            "-p", "password123",
            "-o", out_tf
        ]
        cp = subprocess.run(cmd_tf, env=env, capture_output=True, text=True, check=True)
        assert "[OK]" in cp.stdout

        res_read = read_carrier(out_tf, password="password123")
        assert res_read["data"].decode("utf-8") == unicodedata.normalize("NFC", complex_content)

        # 2. Test --text-base64
        raw_msg = "Base64传递的秘密信息：无视任何引号与转义！🔥"
        b64_msg = base64.b64encode(raw_msg.encode("utf-8")).decode("ascii")

        out_b64 = os.path.join(tmpdir, "out_b64.png")
        cmd_b64 = [
            sys.executable, "-m", "strhide.cli", "write",
            "-c", carrier,
            "--text-base64", b64_msg,
            "-p", "password123",
            "-o", out_b64
        ]
        cp = subprocess.run(cmd_b64, env=env, capture_output=True, text=True, check=True)
        assert "[OK]" in cp.stdout

        res_read_b64 = read_carrier(out_b64, password="password123")
        assert res_read_b64["data"].decode("utf-8") == raw_msg

        # 3. Test --unescape
        out_unescape = os.path.join(tmpdir, "out_unescape.png")
        cmd_unescape = [
            sys.executable, "-m", "strhide.cli", "write",
            "-c", carrier,
            "-t", "LineA\\nLineB\\tTabbed",
            "--unescape",
            "-p", "password123",
            "-o", out_unescape
        ]
        cp = subprocess.run(cmd_unescape, env=env, capture_output=True, text=True, check=True)
        assert "[OK]" in cp.stdout

        res_read_unescape = read_carrier(out_unescape, password="password123")
        assert res_read_unescape["data"].decode("utf-8") == "LineA\nLineB\tTabbed"

        # 4. Test STRHIDE_TEXT environment variable
        out_env = os.path.join(tmpdir, "out_env.png")
        env_with_text = env.copy()
        env_with_text["STRHIDE_TEXT"] = "这是来自环境变量的机密文本！🔐"
        cmd_env = [
            sys.executable, "-m", "strhide.cli", "write",
            "-c", carrier,
            "-p", "password123",
            "-o", out_env
        ]
        cp = subprocess.run(cmd_env, env=env_with_text, capture_output=True, text=True, check=True)
        assert "[OK]" in cp.stdout

        res_read_env = read_carrier(out_env, password="password123")
        assert res_read_env["data"].decode("utf-8") == "这是来自环境变量的机密文本！🔐"
