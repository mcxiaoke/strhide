"""Regression tests for P2 engineering-quality fixes (2026-10-17).

Batch 1:
- #23: MP4/PNG ``verify_structure`` must walk the full container (box tree /
  all chunks with CRC verification), not just the first box or the tail IEND.
  Mirrors the Rust adapter behavior.

Batch 2:
- #11: ``verify_carrier`` Level 2 must validate the envelope header (version /
  hint_len / meta_len consistency) instead of only checking the trailer.
- #14: xref-stream PDFs (no ``trailer`` keyword) must derive the next object
  number from the tail's ``N G obj`` definitions instead of a hardcoded 9999,
  must recover ``/Root`` from the tail, and must be refused when no ``/Root``
  exists at all. The Rust and Python parsers must agree byte-for-byte.

Batch 1 additionally hardened Rust adapter inject against silently swallowed
I/O errors (#10); that path has no Python equivalent (the Python adapters
already propagate read errors), so only the structure-depth parity is tested
here.
"""

import io
import os
import struct
import zlib

import pytest

from strhide.adapters.pdf import parse_pdf_trailer_info
from strhide.core.engine import (
    read_carrier,
    remove_carrier,
    verify_carrier,
    write_carrier,
)
from strhide.errors import CorruptedDataError, UnsupportedFormatError


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


# --------------------------------------------------------------------------- #14: PDF object number derivation


def make_xref_stream_pdf() -> bytes:
    """xref-stream PDF (PDF 1.5+): no ``trailer`` keyword; the trailer dict
    lives inside the XRef stream object. Highest object number is 4, so the
    next free number is 5, and ``/Root 1 0 R`` is only recoverable from the
    tail."""
    return (
        b"%PDF-1.5\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Type /XRef /Root 1 0 R /Size 5 /Length 20 >>\nstream\n"
        + bytes(range(20))
        + b"\nendstream\nendobj\nstartxref\n170\n%%EOF\n"
    )


def make_pdf_without_root() -> bytes:
    """PDF with neither a ``trailer`` keyword nor any ``/Root`` reference."""
    return b"%PDF-1.5\n1 0 obj\n<< /Type /Foo >>\nendobj\nstartxref\n9\n%%EOF\n"


def test_pdf_xref_stream_object_number_from_tail():
    eof_offset, prev_sx, new_obj_num, root_ref, info_ref = parse_pdf_trailer_info(
        io.BytesIO(make_xref_stream_pdf())
    )
    assert new_obj_num == 5, "next object number must be max(N)+1"
    assert root_ref == "1 0 R"


def test_pdf_xref_stream_incremental_write_roundtrip(tmp_path):
    carrier = str(tmp_path / "c.pdf")
    out = str(tmp_path / "o.pdf")
    with open(carrier, "wb") as f:
        f.write(make_xref_stream_pdf())

    # auto must still select incremental (trailer info is recoverable)
    res = write_carrier(carrier, data_text="xref stream secret", output_path=out)
    assert res["strategy"] == "incremental"

    # The injected object must use the derived number 5, not 9999, and the
    # incremental trailer must carry the recovered /Root.
    with open(out, "rb") as f:
        stego = f.read()
    assert b"\n5 0 obj\n" in stego, "injected object number not derived from tail scan"
    assert b"/Root 1 0 R" in stego, "incremental trailer missing recovered /Root"

    # Full lossless lifecycle still holds.
    read = read_carrier(out)
    assert read["data"] == b"xref stream secret"
    remove_carrier(out)
    with open(out, "rb") as f:
        assert f.read() == make_xref_stream_pdf()


def test_pdf_without_root_is_rejected_for_incremental(tmp_path):
    with pytest.raises(CorruptedDataError):
        parse_pdf_trailer_info(io.BytesIO(make_pdf_without_root()))

    carrier = str(tmp_path / "c.pdf")
    out = str(tmp_path / "o.pdf")
    with open(carrier, "wb") as f:
        f.write(make_pdf_without_root())

    # auto falls back to the lossless EOF overlay
    res = write_carrier(carrier, data_text="noroot", output_path=out)
    assert res["strategy"] == "eof"

    # explicit incremental fails with a clear message
    with pytest.raises(UnsupportedFormatError, match="/Root"):
        write_carrier(carrier, data_text="noroot", output_path=out, strategy="incremental")


# --------------------------------------------------------------------------- #11: verify L2 header validation


def _write_eof_envelope(tmp_path, name: str):
    carrier = str(tmp_path / f"{name}.png")
    out = str(tmp_path / f"{name}.out")
    with open(carrier, "wb") as f:
        f.write(make_png())
    write_carrier(carrier, data_text="x", output_path=out, strategy="eof")

    # EOF strategy appends at the end of the host, so the envelope starts at
    # the original carrier size.
    return out, os.path.getsize(carrier)


def _patch_header_field(out: str, ube_offset: int, field_offset: int, payload: bytes):
    with open(out, "r+b") as f:
        f.seek(ube_offset + field_offset)
        f.write(payload)


def test_verify_detects_unsupported_envelope_version(tmp_path):
    out, ube_offset = _write_eof_envelope(tmp_path, "v")

    # version field sits at header offset 8
    _patch_header_field(out, ube_offset, 8, bytes([0x09]))

    res = verify_carrier(out)
    assert res["level2_envelope"]["ok"] is False
    assert "version" in res["level2_envelope"]["detail"]


def test_verify_detects_inconsistent_meta_len(tmp_path):
    out, ube_offset = _write_eof_envelope(tmp_path, "m")

    # meta_len field sits at header offset 104; claim far more than the
    # envelope carries so hint+meta+136 exceeds the total size.
    _patch_header_field(out, ube_offset, 104, struct.pack("<I", 0xFFFFFFF0))

    res = verify_carrier(out)
    assert res["level2_envelope"]["ok"] is False
    assert "inconsistent" in res["level2_envelope"]["detail"]


def test_verify_accepts_untampered_carrier(tmp_path):
    out, _ = _write_eof_envelope(tmp_path, "ok")

    res = verify_carrier(out)
    assert res["level1_host"]["ok"] is True
    assert res["level2_envelope"]["ok"] is True
    assert res["level3_crypto"]["ok"] is True
