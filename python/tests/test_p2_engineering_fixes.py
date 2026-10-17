"""Regression tests for P2 engineering-quality fixes (2026-10-17).

Batch 1:
- #23: MP4/PNG ``verify_structure`` must walk the full container (box tree /
  all chunks with CRC verification), not just the first box or the tail IEND.
  Mirrors the Rust adapter behavior.

Batch 1 additionally hardened Rust adapter inject against silently swallowed
I/O errors (#10); that path has no Python equivalent (the Python adapters
already propagate read errors), so only the structure-depth parity is tested
here.
"""

import struct
import zlib

import pytest

from strhide.core.engine import verify_carrier, write_carrier


# --------------------------------------------------------------------------- helpers


def make_png() -> bytes:
    magic = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr = (
        struct.pack(">I4s", len(ihdr_data), b"IHDR")
        + ihdr_data
        + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    )
    return magic + ihdr + b"\x00\x00\x00\x00IEND\xaeB`\x82"


def make_mp4() -> bytes:
    ftyp_body = b"isom\x00\x00\x02\x00isom"
    ftyp = struct.pack(">I4s", 8 + len(ftyp_body), b"ftyp") + ftyp_body
    free = struct.pack(">I4s", 8, b"free")
    return ftyp + free


# --------------------------------------------------------------------------- #23: PNG verify depth


def test_png_verify_detects_corrupted_chunk_crc(tmp_path):
    carrier = str(tmp_path / "c.png")
    png = bytearray(make_png())
    # Flip a byte inside the IHDR chunk data (data starts at offset 16).
    png[16] ^= 0xFF
    with open(carrier, "wb") as f:
        f.write(png)

    res = verify_carrier(carrier)
    assert res["level1_host"]["ok"] is False
    assert "CRC32 mismatch" in res["level1_host"]["detail"]


def test_png_verify_detects_missing_iend(tmp_path):
    carrier = str(tmp_path / "c.png")
    # Magic + IHDR chunk, no IEND.
    png = make_png()[: -len(b"\x00\x00\x00\x00IEND\xaeB`\x82")]
    with open(carrier, "wb") as f:
        f.write(png)

    res = verify_carrier(carrier)
    assert res["level1_host"]["ok"] is False


def test_png_verify_accepts_valid_carrier_with_envelope(tmp_path):
    carrier = str(tmp_path / "c.png")
    out = str(tmp_path / "o.png")
    with open(carrier, "wb") as f:
        f.write(make_png())
    write_carrier(carrier, data_text="batch1 png", output_path=out)

    res = verify_carrier(out)
    assert res["level1_host"]["ok"] is True, res["level1_host"]["detail"]
    assert "private chunk 'prIv'" in res["level1_host"]["detail"]


# --------------------------------------------------------------------------- #23: MP4 verify depth


def test_mp4_verify_detects_invalid_box_size(tmp_path):
    carrier = str(tmp_path / "c.mp4")
    # ftyp box declaring size 2 (< the 8-byte header).
    data = struct.pack(">I4s", 2, b"ftyp") + b"\x00" * 16
    with open(carrier, "wb") as f:
        f.write(data)

    res = verify_carrier(carrier)
    assert res["level1_host"]["ok"] is False
    assert "Invalid box size" in res["level1_host"]["detail"]


def test_mp4_verify_detects_box_past_eof(tmp_path):
    carrier = str(tmp_path / "c.mp4")
    mp4 = bytearray(make_mp4())
    # Inflate the ftyp box size far beyond the file length.
    mp4[0:4] = struct.pack(">I", 0x10000)
    with open(carrier, "wb") as f:
        f.write(mp4)

    res = verify_carrier(carrier)
    assert res["level1_host"]["ok"] is False
    assert "past end of file" in res["level1_host"]["detail"]


def test_mp4_verify_detects_missing_ftyp(tmp_path):
    carrier = str(tmp_path / "c.mp4")
    # First box is moov (still detected as ISO BMFF, but not a valid file).
    data = struct.pack(">I4s", 8, b"moov") + struct.pack(">I4s", 8, b"free")
    with open(carrier, "wb") as f:
        f.write(data)

    res = verify_carrier(carrier)
    assert res["level1_host"]["ok"] is False
    assert "missing ftyp" in res["level1_host"]["detail"]


def test_mp4_verify_accepts_valid_carrier_with_envelope(tmp_path):
    carrier = str(tmp_path / "c.mp4")
    out = str(tmp_path / "o.mp4")
    with open(carrier, "wb") as f:
        f.write(make_mp4())
    write_carrier(carrier, data_text="batch1 mp4", output_path=out)

    res = verify_carrier(out)
    assert res["level1_host"]["ok"] is True, res["level1_host"]["detail"]
    assert "top-level boxes" in res["level1_host"]["detail"]
