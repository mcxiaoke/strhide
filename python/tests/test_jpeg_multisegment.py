import os
import hashlib
from pathlib import Path
import pytest
from strhide.core.engine import (
    write_carrier,
    read_carrier,
    verify_carrier,
    remove_carrier,
    inspect_carrier,
)
from strhide.errors import StrHideError
from strhide.adapters.jpeg import partition_jpeg_payload_lengths


def make_jpeg() -> bytes:
    # SOI, APP0 (JFIF), DQT, SOF0, SOS, scan data, EOI
    return (
        b"\xFF\xD8"
        b"\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xFF\xDB\x00\x43\x00" + b"\x01" * 64 +
        b"\xFF\xC0\x00\x0B\x08\x00\x01\x00\x01\x01\x01\x11\x00"
        b"\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00"
        b"\x12\x34\x56\x78"
        b"\xFF\xD9"
    )


def test_partition_jpeg_payload_lengths_borrowing():
    # 65534 = 65533 + 1. Remainder 1 < 24 -> borrows from first chunk
    lens = partition_jpeg_payload_lengths(65534)
    assert sum(lens) == 65534
    assert len(lens) == 2
    assert lens[0] <= 65533
    assert lens[1] >= 24

    # Single segment
    lens1 = partition_jpeg_payload_lengths(500)
    assert lens1 == [500]


def test_jpeg_multisegment_roundtrip_and_lossless_restore(tmp_path):
    carrier = tmp_path / "carrier.jpg"
    orig_bytes = make_jpeg()
    carrier.write_bytes(orig_bytes)
    orig_sha256 = hashlib.sha256(orig_bytes).hexdigest()

    # 70KB incompressible payload -> requires 2 segments
    payload_data = os.urandom(70 * 1024)
    payload_path = tmp_path / "payload.bin"
    payload_path.write_bytes(payload_data)

    stego = tmp_path / "stego.jpg"
    res = write_carrier(
        str(carrier),
        data_file=str(payload_path),
        password="test_multiseg_pw",
        output_path=str(stego),
    )
    assert res["strategy"] == "app_segment"
    assert res["ube_size"] > 65533

    # Inspect
    info = inspect_carrier(str(stego), password="test_multiseg_pw")
    assert info["format"].lower() == "jpeg"
    assert info["strategy"] == "app_segment"
    assert info["has_hidden_data"] is True

    # Verify
    v = verify_carrier(str(stego), password="test_multiseg_pw")
    assert v["level1_host"]["ok"]
    assert v["level2_envelope"]["ok"]
    assert v["level3_crypto"]["ok"]

    # Read
    out = read_carrier(str(stego), password="test_multiseg_pw")
    assert out["data"] == payload_data

    # Remove (lossless restore)
    restored = tmp_path / "restored.jpg"
    remove_carrier(str(stego), output_path=str(restored), password="test_multiseg_pw")
    restored_bytes = restored.read_bytes()
    assert hashlib.sha256(restored_bytes).hexdigest() == orig_sha256
    assert restored_bytes == orig_bytes


def test_jpeg_boundary_65534_borrowing(tmp_path):
    carrier = tmp_path / "carrier.jpg"
    orig_bytes = make_jpeg()
    carrier.write_bytes(orig_bytes)

    from test_security_fixes import _exact_ube_size_for_payload
    target = 65534
    payload_len = next(
        L for L in range(65000, 65600) if _exact_ube_size_for_payload(L) == target
    )
    payload_data = os.urandom(payload_len)
    payload_path = tmp_path / "payload.bin"
    payload_path.write_bytes(payload_data)

    stego = tmp_path / "stego.jpg"
    res = write_carrier(
        str(carrier),
        data_file=str(payload_path),
        password="test_borrowing_pw",
        output_path=str(stego),
    )
    assert res["strategy"] == "app_segment"
    assert res["ube_size"] == target

    # Read back and remove
    out = read_carrier(str(stego), password="test_borrowing_pw")
    assert out["data"] == payload_data

    restored = tmp_path / "restored.jpg"
    remove_carrier(str(stego), output_path=str(restored), password="test_borrowing_pw")
    assert restored.read_bytes() == orig_bytes
