"""Synthetic lifecycle tests for all supported adapters."""

import os
import struct
import tempfile
import zipfile
import zlib
import pytest

from strhide.core.crypto import compute_file_sha256
from strhide.core.engine import (
    inspect_carrier,
    read_carrier,
    remove_carrier,
    verify_carrier,
    write_carrier,
)


def create_minimal_png() -> bytes:
    """Create a valid 1x1 PNG image with standard chunks."""
    magic = b"\x89PNG\r\n\x1a\n"
    # IHDR: width=1, height=1, bit_depth=8, color_type=2 (RGB), def=0, filter=0, interlace=0
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF
    ihdr = struct.pack(">I4s", len(ihdr_data), b"IHDR") + ihdr_data + struct.pack(">I", ihdr_crc)

    # IDAT: compressed raw scanline (filter byte 0 + RGB 255, 0, 0)
    raw_scanline = b"\x00\xff\x00\x00"
    idat_data = zlib.compress(raw_scanline)
    idat_crc = zlib.crc32(b"IDAT" + idat_data) & 0xFFFFFFFF
    idat = struct.pack(">I4s", len(idat_data), b"IDAT") + idat_data + struct.pack(">I", idat_crc)

    # IEND
    iend = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    return magic + ihdr + idat + iend


def create_minimal_mp4() -> bytes:
    """Create a minimal valid ISO BMFF MP4 with ftyp and mdat boxes."""
    # ftyp box: size 24, 'ftyp', major_brand='isom', minor_version=512, compatible_brands=['isom', 'iso2']
    ftyp_data = b"isom" + struct.pack(">I", 512) + b"isom" + b"iso2"
    ftyp_box = struct.pack(">I4s", 8 + len(ftyp_data), b"ftyp") + ftyp_data

    # mdat box: size 16, 'mdat', 8 bytes payload
    mdat_payload = b"DUMMYVID"
    mdat_box = struct.pack(">I4s", 8 + len(mdat_payload), b"mdat") + mdat_payload

    return ftyp_box + mdat_box


def create_minimal_jpeg() -> bytes:
    """Create a minimal valid JPEG file with SOI, APP0, SOF0, SOS, and EOI."""
    soi = b"\xff\xd8"
    # APP0 (JFIF)
    app0_data = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    app0 = b"\xff\xe0" + struct.pack(">H", 2 + len(app0_data)) + app0_data
    # DQT
    dqt_data = b"\x00" + (b"\x10" * 64)
    dqt = b"\xff\xdb" + struct.pack(">H", 2 + len(dqt_data)) + dqt_data
    # SOF0
    sof0_data = b"\x08\x00\x01\x00\x01\x01\x01\x11\x00"
    sof0 = b"\xff\xc0" + struct.pack(">H", 2 + len(sof0_data)) + sof0_data
    # DHT
    dht_data = b"\x00" + (b"\x00" * 16)
    dht = b"\xff\xc4" + struct.pack(">H", 2 + len(dht_data)) + dht_data
    # SOS
    sos_data = b"\x01\x01\x00\x00\x3f\x00"
    sos = b"\xff\xda" + struct.pack(">H", 2 + len(sos_data)) + sos_data
    # Scan data + EOI
    scan_data = b"\x00\xff\x00\x55"  # with byte-stuffing
    eoi = b"\xff\xd9"
    return soi + app0 + dqt + sof0 + dht + sos + scan_data + eoi


def test_png_lifecycle():
    png_bytes = create_minimal_png()
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "test.png")
        with open(carrier, "wb") as f:
            f.write(png_bytes)

        orig_sha = compute_file_sha256(carrier)
        secret_text = "Hidden secret in PNG image!"

        # 1. Write encrypted
        res_w = write_carrier(carrier, data_text=secret_text, password="Pass123!PNG")
        assert res_w["format"] == "PNG"
        assert res_w["strategy"] == "chunk"

        # 2. Inspect
        res_i = inspect_carrier(carrier, password="Pass123!PNG")
        assert res_i["has_hidden_data"] is True
        assert res_i["strategy"] == "chunk"

        # 3. Verify
        res_v = verify_carrier(carrier, password="Pass123!PNG")
        assert res_v["level1_host"]["ok"] is True
        assert res_v["level2_envelope"]["ok"] is True
        assert res_v["level3_crypto"]["ok"] is True

        # 4. Read
        res_r = read_carrier(carrier, password="Pass123!PNG")
        assert res_r["data"].decode("utf-8") == secret_text

        # 5. Remove & verify 100% exact bit match
        res_rm = remove_carrier(carrier)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha


def test_mp4_lifecycle():
    mp4_bytes = create_minimal_mp4()
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "test.mp4")
        with open(carrier, "wb") as f:
            f.write(mp4_bytes)

        orig_sha = compute_file_sha256(carrier)
        secret_text = "Secret payload in MP4 movie!"

        # 1. Write
        res_w = write_carrier(carrier, data_text=secret_text, password="Pass123!MP4")
        assert res_w["format"] == "MP4"
        assert res_w["strategy"] == "box_uuid"

        # 2. Verify
        res_v = verify_carrier(carrier, password="Pass123!MP4")
        assert res_v["level1_host"]["ok"] is True
        assert res_v["level2_envelope"]["ok"] is True
        assert res_v["level3_crypto"]["ok"] is True

        # 3. Read
        res_r = read_carrier(carrier, password="Pass123!MP4")
        assert res_r["data"].decode("utf-8") == secret_text

        # 4. Remove & check bit match
        res_rm = remove_carrier(carrier)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha


def test_zip_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "test.zip")
        with zipfile.ZipFile(carrier, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("file1.txt", "Hello in zip entry 1")
            zf.writestr("file2.txt", "Hello in zip entry 2")

        orig_sha = compute_file_sha256(carrier)
        secret_text = "Top Secret in ZIP pre-cd!"

        # 1. Write
        res_w = write_carrier(carrier, data_text=secret_text, password="Pass123!ZIP")
        assert res_w["format"] == "ZIP"
        assert res_w["strategy"] == "pre_cd_inject"

        # 2. Verify standard zip reading is still completely functional!
        with zipfile.ZipFile(carrier, "r") as zf:
            assert zf.read("file1.txt") == b"Hello in zip entry 1"
            assert zf.read("file2.txt") == b"Hello in zip entry 2"

        # 3. Verify with strhide
        res_v = verify_carrier(carrier, password="Pass123!ZIP")
        assert res_v["level1_host"]["ok"] is True
        assert res_v["level2_envelope"]["ok"] is True
        assert res_v["level3_crypto"]["ok"] is True

        # 4. Read secret
        res_r = read_carrier(carrier, password="Pass123!ZIP")
        assert res_r["data"].decode("utf-8") == secret_text

        # 5. Remove & check 100% bit match
        res_rm = remove_carrier(carrier)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha


def test_jpeg_lifecycle():
    jpeg_bytes = create_minimal_jpeg()
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "test.jpg")
        with open(carrier, "wb") as f:
            f.write(jpeg_bytes)

        orig_sha = compute_file_sha256(carrier)
        secret_text = "Hidden in JPEG EOI trail!"

        # 1. Write (auto selects app_segment for small data)
        res_w = write_carrier(carrier, data_text=secret_text, password="Pass123!JPEG")
        assert res_w["format"] == "JPEG"
        assert res_w["strategy"] == "app_segment"

        # 2. Verify structure
        res_v = verify_carrier(carrier, password="Pass123!JPEG")
        assert res_v["level1_host"]["ok"] is True
        assert res_v["level2_envelope"]["ok"] is True
        assert res_v["level3_crypto"]["ok"] is True

        # 3. Read
        res_r = read_carrier(carrier, password="Pass123!JPEG")
        assert res_r["data"].decode("utf-8") == secret_text

        # 4. Remove & check bit match
        res_rm = remove_carrier(carrier)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha

        # 5. Explicit eof strategy test
        res_w2 = write_carrier(carrier, data_text=secret_text, password="Pass123!JPEG", strategy="eof")
        assert res_w2["strategy"] == "eof"
        res_r2 = read_carrier(carrier, password="Pass123!JPEG")
        assert res_r2["data"].decode("utf-8") == secret_text
        res_rm2 = remove_carrier(carrier)
        assert res_rm2["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha


def test_generic_eof_lifecycle():
    random_bytes = b"MY-CUSTOM-BINARY-FILE-HEADER" + os.urandom(2048)
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "test.bin")
        with open(carrier, "wb") as f:
            f.write(random_bytes)

        orig_sha = compute_file_sha256(carrier)
        secret_text = "Secret in EOF binary!"

        res_w = write_carrier(carrier, data_text=secret_text, password="Pass123!EOF")
        assert res_w["format"] == "GENERIC"
        assert res_w["strategy"] == "eof"

        res_r = read_carrier(carrier, password="Pass123!EOF")
        assert res_r["data"].decode("utf-8") == secret_text

        res_rm = remove_carrier(carrier)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha


def create_minimal_pe() -> bytes:
    """Create a minimal valid unsigned PE32+ (x64) executable."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 64)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x0022)
    opt_std = struct.pack("<HBBIIIII", 0x20B, 1, 0, 512, 0, 0, 0x1000, 0x1000)
    opt_win = struct.pack(
        "<QIIHHHHHHIIIIHHQQQQII",
        0x140000000,
        4096,
        512,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        8192,
        512,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    data_dirs = b"\x00" * 128
    opt = opt_std + opt_win + data_dirs
    sec = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 64, 0x1000, 512, 512, 0, 0, 0, 0, 0x60000020)
    headers = bytes(dos) + pe_sig + coff + opt + sec
    pad = b"\x00" * (512 - len(headers))
    headers_padded = headers + pad
    raw_data = b"\x90" * 64 + b"\x00" * (512 - 64)
    return headers_padded + raw_data


def test_pe_lifecycle():
    pe_bytes = create_minimal_pe()
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier = os.path.join(tmpdir, "test.exe")
        with open(carrier, "wb") as f:
            f.write(pe_bytes)

        orig_sha = compute_file_sha256(carrier)
        secret_text = "Top Secret inside Windows PE overlay!"

        # 1. Write (auto selects pe_overlay)
        res_w = write_carrier(carrier, data_text=secret_text, password="Pass123!PE")
        assert res_w["format"] == "PE"
        assert res_w["strategy"] == "pe_overlay"
        assert "PE image overlay" in res_w["strategy_note"]

        # 2. Inspect
        res_i = inspect_carrier(carrier, password="Pass123!PE")
        assert res_i["has_hidden_data"] is True
        assert res_i["format"] == "PE"

        # 3. Verify
        res_v = verify_carrier(carrier, password="Pass123!PE")
        assert res_v["level1_host"]["ok"] is True
        assert res_v["level2_envelope"]["ok"] is True
        assert res_v["level3_crypto"]["ok"] is True

        # 4. Read
        res_r = read_carrier(carrier, password="Pass123!PE")
        assert res_r["data"].decode("utf-8") == secret_text

        # 5. Remove & verify 100% bit match
        res_rm = remove_carrier(carrier)
        assert res_rm["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha

        # 6. Explicit eof strategy test
        res_w2 = write_carrier(carrier, data_text=secret_text, password="Pass123!PE", strategy="eof")
        assert res_w2["strategy"] == "eof"
        res_r2 = read_carrier(carrier, password="Pass123!PE")
        assert res_r2["data"].decode("utf-8") == secret_text
        res_rm2 = remove_carrier(carrier)
        assert res_rm2["verified_identical"] is True
        assert compute_file_sha256(carrier) == orig_sha

