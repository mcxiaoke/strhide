"""Tests for Unicode text, binary payloads of various sizes, and Unicode/Chinese passwords."""

import os
import shutil
import tempfile
import pytest

from strhide.core.crypto import compute_file_sha256, compute_stream_sha256
from strhide.core.engine import (
    inspect_carrier,
    read_carrier,
    remove_carrier,
    verify_carrier,
    write_carrier,
)
from strhide.errors import PasswordError

TESTFILES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "temp", "testfiles"))


def test_chinese_and_emoji_text_with_chinese_password():
    """Test embedding Chinese & Emoji text with a Chinese & Emoji password."""
    carrier_src = os.path.join(TESTFILES_DIR, "file-02.png")
    if not os.path.exists(carrier_src):
        pytest.skip("file-02.png not found")

    chinese_text = (
        "【机密文件】\n"
        "赵客缦胡缨，吴钩霜雪明。银鞍照白马，飒沓如流星。\n"
        "十步杀一人，千里不留行。事了拂衣去，深藏身与名。\n"
        "特殊字符与表情符号：🎯 🚀 👨‍👩‍👧‍👦 \u200b\ufeff\n"
        "日文与韩文：こんにちは 世界！ 안녕하세요 세계!"
    )
    chinese_password = "芝麻开门！🔑🔒测试密码_2026年"

    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "test_chinese.png")
        shutil.copy2(carrier_src, carrier)
        orig_sha = compute_file_sha256(carrier)

        # 1. Write
        res_w = write_carrier(carrier, data_text=chinese_text, password=chinese_password)
        assert res_w["is_encrypted"] is True

        # 2. Inspect with correct Chinese password
        res_i = inspect_carrier(carrier, password=chinese_password)
        assert res_i["has_hidden_data"] is True
        assert res_i["is_encrypted"] is True

        # 3. Verify
        res_v = verify_carrier(carrier, password=chinese_password)
        assert res_v["level1_host"]["ok"] is True
        assert res_v["level2_envelope"]["ok"] is True
        assert res_v["level3_crypto"]["ok"] is True

        # 4. Wrong password test
        with pytest.raises(PasswordError):
            read_carrier(carrier, password="错误的密码_2026")

        # 5. Read and check 100% exact byte and string match
        res_r = read_carrier(carrier, password=chinese_password)
        extracted_text = res_r["data"].decode("utf-8")
        assert extracted_text == chinese_text
        assert res_r["data"] == chinese_text.encode("utf-8")

        # 6. Remove and check 100% bit-for-bit restoration
        res_rm = remove_carrier(carrier)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha


def test_arbitrary_binary_payload_with_all_bytes():
    """Test embedding raw binary payload containing all possible byte values 0x00..0xFF."""
    carrier_src = os.path.join(TESTFILES_DIR, "file-06.jpg")
    if not os.path.exists(carrier_src):
        pytest.skip("file-06.jpg not found")

    # Generate binary data covering all 256 bytes plus random sequences
    raw_binary = bytes(range(256)) * 64 + os.urandom(16384)
    unicode_password = "P@ss_Пароль_مرحبا_🔐"

    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "test_binary.jpg")
        shutil.copy2(carrier_src, carrier)
        orig_sha = compute_file_sha256(carrier)

        # Write binary
        res_w = write_carrier(carrier, data_bytes=raw_binary, password=unicode_password)
        assert res_w["raw_size"] == len(raw_binary)

        # Read binary
        res_r = read_carrier(carrier, password=unicode_password)
        # Byte-for-byte exact equality check
        assert res_r["data"] == raw_binary
        assert len(res_r["data"]) == len(raw_binary)

        # Remove & check exact SHA-256 match
        res_rm = remove_carrier(carrier)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha


def test_large_binary_file_crossing_chunks():
    """Test embedding a 5.5MB high-entropy binary file crossing multiple 2MB AEAD chunks."""
    carrier_src = os.path.join(TESTFILES_DIR, "file-00.mp4")
    if not os.path.exists(carrier_src):
        pytest.skip("file-00.mp4 not found")

    large_size = int(5.5 * 1024 * 1024)  # 5.5 MB
    large_payload = os.urandom(large_size)
    complex_password = "复杂中文字符串🔑+Special#Chars@!~"

    with tempfile.TemporaryDirectory() as tmpdir:
        payload_file = os.path.join(tmpdir, "机密数据_backup.bin")
        with open(payload_file, "wb") as pf:
            pf.write(large_payload)
        payload_sha = compute_file_sha256(payload_file)

        carrier = os.path.join(tmpdir, "test_large.mp4")
        shutil.copy2(carrier_src, carrier)
        orig_carrier_sha = compute_file_sha256(carrier)

        # 1. Write large file
        res_w = write_carrier(carrier, data_file=payload_file, password=complex_password)
        assert res_w["raw_size"] == large_size

        # 2. Verify level 1, 2, 3
        res_v = verify_carrier(carrier, password=complex_password)
        assert res_v["level1_host"]["ok"] is True
        assert res_v["level2_envelope"]["ok"] is True
        assert res_v["level3_crypto"]["ok"] is True

        # 3. Read out to file
        extract_dir = os.path.join(tmpdir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        res_r = read_carrier(carrier, output_path=extract_dir, password=complex_password)
        extracted_file = res_r["written_file"]
        assert os.path.exists(extracted_file)
        assert os.path.basename(extracted_file) == "机密数据_backup.bin"

        # Byte-for-byte SHA256 equality check
        extracted_sha = compute_file_sha256(extracted_file)
        assert extracted_sha == payload_sha
        assert os.path.getsize(extracted_file) == large_size

        # Also compare raw memory bytes
        with open(extracted_file, "rb") as ef:
            assert ef.read() == large_payload

        # 4. Remove & check carrier 100% restored
        res_rm = remove_carrier(carrier)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_carrier_sha


def test_chinese_filename_and_unicode_stealth_mode():
    """Test Chinese filename and Unicode stealth mode on ZIP container."""
    carrier_src = os.path.join(TESTFILES_DIR, "file-18.zip")
    if not os.path.exists(carrier_src):
        pytest.skip("file-18.zip not found")

    stealth_password = "绝密_Stealth_密码_👻"
    secret_bytes = ("绝密协议内容：" + "A" * 1024 + "🌟" * 128).encode("utf-8")

    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "test_stealth.zip")
        shutil.copy2(carrier_src, carrier)
        orig_sha = compute_file_sha256(carrier)

        # 1. Write in stealth mode
        res_w = write_carrier(
            carrier,
            data_bytes=secret_bytes,
            password=stealth_password,
            stealth=True,
        )
        assert res_w["is_stealth"] is True

        # 2. Inspect with password
        res_i = inspect_carrier(carrier, password=stealth_password)
        assert res_i["has_hidden_data"] is True
        assert res_i["is_stealth"] is True

        # 3. Read in stealth mode
        res_r = read_carrier(carrier, password=stealth_password)
        assert res_r["data"] == secret_bytes

        # 4. Remove in stealth mode
        res_rm = remove_carrier(carrier, password=stealth_password)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha


def test_tiny_and_empty_payloads():
    """Test edge cases: 1-byte payload and empty text."""
    carrier_src = os.path.join(TESTFILES_DIR, "xxhsum.exe")
    if not os.path.exists(carrier_src):
        pytest.skip("xxhsum.exe not found")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Test 1 byte
        carrier1 = os.path.join(tmpdir, "tiny1.exe")
        shutil.copy2(carrier_src, carrier1)
        orig_sha1 = compute_file_sha256(carrier1)

        write_carrier(carrier1, data_bytes=b"X", password="密_1")
        res1 = read_carrier(carrier1, password="密_1")
        assert res1["data"] == b"X"
        remove_carrier(carrier1)
        assert compute_file_sha256(carrier1) == orig_sha1

        # Test empty string
        carrier2 = os.path.join(tmpdir, "empty.exe")
        shutil.copy2(carrier_src, carrier2)
        orig_sha2 = compute_file_sha256(carrier2)

        write_carrier(carrier2, data_text="", password="密_2")
        res2 = read_carrier(carrier2, password="密_2")
        assert res2["data"] == b""
        remove_carrier(carrier2)
        assert compute_file_sha256(carrier2) == orig_sha2
