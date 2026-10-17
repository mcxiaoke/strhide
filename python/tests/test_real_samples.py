"""Integration tests using real-world files from the host system."""

import os
import shutil
import tempfile
import zipfile
import pytest

from strhide.core.crypto import compute_file_sha256
from strhide.core.engine import (
    inspect_carrier,
    read_carrier,
    remove_carrier,
    verify_carrier,
    write_carrier,
)
from strhide.errors import RejectionError

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "temp", "real_samples"))


@pytest.mark.skipif(not os.path.exists(SAMPLES_DIR), reason="real_samples directory not found")
def test_real_apk_rejection():
    apk_file = os.path.join(SAMPLES_DIR, "sample.apk")
    if not os.path.exists(apk_file):
        pytest.skip("sample.apk not available")

    with tempfile.TemporaryDirectory() as tmpdir:
        test_carrier = os.path.join(tmpdir, "test.apk")
        shutil.copy2(apk_file, test_carrier)

        with pytest.raises(RejectionError) as exc_info:
            write_carrier(test_carrier, data_text="Secret to APK", password="pwd")
        assert "APK" in str(exc_info.value)


@pytest.mark.skipif(not os.path.exists(SAMPLES_DIR), reason="real_samples directory not found")
def test_real_signed_pe_rejection():
    exe_file = os.path.join(SAMPLES_DIR, "signed_sample.exe")
    if not os.path.exists(exe_file):
        pytest.skip("signed_sample.exe not available")

    with tempfile.TemporaryDirectory() as tmpdir:
        test_carrier = os.path.join(tmpdir, "signed_test.exe")
        shutil.copy2(exe_file, test_carrier)

        with pytest.raises(RejectionError) as exc_info:
            write_carrier(test_carrier, data_text="Secret to signed EXE", password="pwd")
        assert "Authenticode" in str(exc_info.value)


@pytest.mark.skipif(not os.path.exists(SAMPLES_DIR), reason="real_samples directory not found")
def test_real_png_full_lifecycle():
    png_file = os.path.join(SAMPLES_DIR, "sample.png")
    if not os.path.exists(png_file):
        pytest.skip("sample.png not available")

    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "sample.png")
        shutil.copy2(png_file, carrier)
        orig_sha = compute_file_sha256(carrier)
        secret = "Real PNG Secret Content 2026! 🚀"

        # 1. Write
        res_w = write_carrier(carrier, data_text=secret, password="RealPass!PNG")
        assert res_w["format"] == "PNG"
        assert res_w["strategy"] == "chunk"

        # 2. Inspect
        res_i = inspect_carrier(carrier, password="RealPass!PNG")
        assert res_i["has_hidden_data"] is True
        assert res_i["format"] == "PNG"

        # 3. Verify
        res_v = verify_carrier(carrier, password="RealPass!PNG")
        assert res_v["level1_host"]["ok"] is True
        assert res_v["level2_envelope"]["ok"] is True
        assert res_v["level3_crypto"]["ok"] is True

        # 4. Read
        res_r = read_carrier(carrier, password="RealPass!PNG")
        assert res_r["data"].decode("utf-8") == secret

        # 5. Remove & verify 100% exact bit match
        res_rm = remove_carrier(carrier)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha


@pytest.mark.skipif(not os.path.exists(SAMPLES_DIR), reason="real_samples directory not found")
def test_real_jpg_full_lifecycle():
    jpg_file = os.path.join(SAMPLES_DIR, "sample.jpg")
    if not os.path.exists(jpg_file):
        pytest.skip("sample.jpg not available")

    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "sample.jpg")
        shutil.copy2(jpg_file, carrier)
        orig_sha = compute_file_sha256(carrier)
        secret = "Real JPEG Secret Payload 2026!"

        # 1. Write
        res_w = write_carrier(carrier, data_text=secret, password="RealPass!JPG")
        assert res_w["format"] == "JPEG"

        # 2. Verify
        res_v = verify_carrier(carrier, password="RealPass!JPG")
        assert res_v["level1_host"]["ok"] is True
        assert res_v["level2_envelope"]["ok"] is True
        assert res_v["level3_crypto"]["ok"] is True

        # 3. Read
        res_r = read_carrier(carrier, password="RealPass!JPG")
        assert res_r["data"].decode("utf-8") == secret

        # 4. Remove & check 100% bit match
        res_rm = remove_carrier(carrier)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha


@pytest.mark.skipif(not os.path.exists(SAMPLES_DIR), reason="real_samples directory not found")
def test_real_mp4_full_lifecycle():
    mp4_file = os.path.join(SAMPLES_DIR, "sample.mp4")
    if not os.path.exists(mp4_file):
        pytest.skip("sample.mp4 not available")

    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "sample.mp4")
        shutil.copy2(mp4_file, carrier)
        orig_sha = compute_file_sha256(carrier)
        secret = "Real MP4 Secret Audio/Video Key!"

        # 1. Write
        res_w = write_carrier(carrier, data_text=secret, password="RealPass!MP4")
        assert res_w["format"] == "MP4"
        assert res_w["strategy"] == "box_uuid"

        # 2. Verify
        res_v = verify_carrier(carrier, password="RealPass!MP4")
        assert res_v["level1_host"]["ok"] is True
        assert res_v["level2_envelope"]["ok"] is True
        assert res_v["level3_crypto"]["ok"] is True

        # 3. Read
        res_r = read_carrier(carrier, password="RealPass!MP4")
        assert res_r["data"].decode("utf-8") == secret

        # 4. Remove & check 100% bit match
        res_rm = remove_carrier(carrier)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha


@pytest.mark.skipif(not os.path.exists(SAMPLES_DIR), reason="real_samples directory not found")
def test_real_zip_full_lifecycle():
    zip_file = os.path.join(SAMPLES_DIR, "sample.zip")
    if not os.path.exists(zip_file):
        pytest.skip("sample.zip not available")

    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "sample.zip")
        shutil.copy2(zip_file, carrier)
        orig_sha = compute_file_sha256(carrier)
        secret = "Real ZIP Archive Hidden Data in Central Directory!"

        # Check entries before
        with zipfile.ZipFile(carrier, "r") as zf:
            orig_namelist = zf.namelist()

        # 1. Write
        res_w = write_carrier(carrier, data_text=secret, password="RealPass!ZIP")
        assert res_w["format"] == "ZIP"
        assert res_w["strategy"] == "pre_cd_inject"

        # 2. Verify zipfile still reads all original entries perfectly!
        with zipfile.ZipFile(carrier, "r") as zf:
            assert zf.namelist() == orig_namelist

        # 3. Verify
        res_v = verify_carrier(carrier, password="RealPass!ZIP")
        assert res_v["level1_host"]["ok"] is True
        assert res_v["level2_envelope"]["ok"] is True
        assert res_v["level3_crypto"]["ok"] is True

        # 4. Read
        res_r = read_carrier(carrier, password="RealPass!ZIP")
        assert res_r["data"].decode("utf-8") == secret

        # 5. Remove & check 100% bit match
        res_rm = remove_carrier(carrier)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha


@pytest.mark.skipif(not os.path.exists(SAMPLES_DIR), reason="real_samples directory not found")
def test_real_pdf_full_lifecycle():
    pdf_file = os.path.join(SAMPLES_DIR, "sample.pdf")
    if not os.path.exists(pdf_file):
        pytest.skip("sample.pdf not available")

    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "sample.pdf")
        shutil.copy2(pdf_file, carrier)
        orig_sha = compute_file_sha256(carrier)
        secret = "Secret hidden inside real PDF document!"

        # 1. Write
        res_w = write_carrier(carrier, data_text=secret, password="RealPass!PDF")
        assert res_w["format"] == "PDF"
        assert res_w["strategy"] == "incremental"
        # 2. Verify
        res_v = verify_carrier(carrier, password="RealPass!PDF")
        assert res_v["level1_host"]["ok"] is True
        assert res_v["level2_envelope"]["ok"] is True
        assert res_v["level3_crypto"]["ok"] is True

        # 3. Read
        res_r = read_carrier(carrier, password="RealPass!PDF")
        assert res_r["data"].decode("utf-8") == secret

        # 4. Remove & check 100% bit match
        res_rm = remove_carrier(carrier)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha
