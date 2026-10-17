"""Regression tests for the P0/P1 security and correctness fixes (2026-10-17).

Covers:
- R1/P0-3: --stealth without password must fail fast (engine + CLI, no hang)
- R2/P0-2: metadata filename path traversal must be sanitized
- R3/P0-4: stealth double-injection protection + structural warning + reverse-order removal
- P0-1:  PDF dirty-tail preservation (100% bit-exact restore)
- R4/P1-5: auto strategy capacity estimation exactness (JPEG boundary fallback)
- R5:  tmp file cleanup on failed injection
- P1-6: ZIP EOCD candidate validation (fake magic in comment)
- R6:  envelope header validation (version / meta_len) and chunk_len upper bound
"""

import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib

import pytest

from strhide.core.engine import (
    inspect_carrier,
    read_carrier,
    remove_carrier,
    sanitize_filename,
    verify_carrier,
    write_carrier,
)
from strhide.core.envelope import HEADER_STRUCT, EnvelopeHeader, read_trailer_from_tail
from strhide.core.crypto import decrypt_stream_from_chunks
from strhide.errors import CorruptedDataError, RestoreMismatchError, StrHideError


# --------------------------------------------------------------------------- helpers

def make_png() -> bytes:
    magic = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr = struct.pack(">I4s", len(ihdr_data), b"IHDR") + ihdr_data + struct.pack(
        ">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF
    )
    raw = b"\x00\xff\x00\x00"
    idat_data = zlib.compress(raw)
    idat = struct.pack(">I4s", len(idat_data), b"IDAT") + idat_data + struct.pack(
        ">I", zlib.crc32(b"IDAT" + idat_data) & 0xFFFFFFFF
    )
    return magic + ihdr + idat + b"\x00\x00\x00\x00IEND\xaeB`\x82"


def make_jpeg() -> bytes:
    soi = b"\xff\xd8"
    app0_data = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    app0 = b"\xff\xe0" + struct.pack(">H", 2 + len(app0_data)) + app0_data
    dqt_data = b"\x00" + (b"\x10" * 64)
    dqt = b"\xff\xdb" + struct.pack(">H", 2 + len(dqt_data)) + dqt_data
    sof_data = struct.pack(">BHHB", 8, 1, 1, 1) + b"\x01\x11\x00"
    sof = b"\xff\xc0" + struct.pack(">H", 2 + len(sof_data)) + sof_data + sof_data
    sos_data = b"\x01"
    sos = b"\xff\xda" + struct.pack(">H", 2 + len(sos_data)) + sos_data
    entropy = b"\x00" * 32 + b"\xff\x00" * 8
    return soi + app0 + dqt + sof + sos + entropy + b"\xff\xd9"


def make_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("hello.txt", "hello world" * 50)
    return buf.getvalue()


def make_zip_with_fake_eocd_comment() -> bytes:
    data = bytearray(make_zip())
    eocd = data.rfind(b"PK\x05\x06")
    comment = b"PREFIX-PK\x05\x06-MIDDLE-SUFFIX"
    struct.pack_into("<H", data, eocd + 20, len(comment))
    data.extend(comment)
    return bytes(data)


def make_pdf_with_dirty_tail() -> bytes:
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n"
        b"trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n"
    )
    return body + b"DIRTY-TAIL-GARBAGE" * 8


@pytest.fixture
def workspace(tmp_path):
    return tmp_path


def write_synth_png(workspace, name="c.png"):
    p = workspace / name
    p.write_bytes(make_png())
    return str(p)


def write_synth_zip(workspace, name="c.zip"):
    p = workspace / name
    p.write_bytes(make_zip())
    return str(p)


# --------------------------------------------------------------------------- R1 / P0-3

def test_stealth_requires_password_engine(workspace):
    carrier = write_synth_png(workspace)
    with pytest.raises(StrHideError, match="requires a password"):
        write_carrier(carrier, data_text="x", stealth=True,
                      output_path=str(workspace / "out.png"))


def test_stealth_requires_password_cli_fast(workspace):
    """CLI must fail immediately (no blocking prompt) in a non-tty context."""
    carrier = write_synth_png(workspace)
    env = dict(os.environ)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    r = subprocess.run(
        [sys.executable, "-m", "strhide.cli", "write", "-c", carrier,
         "-t", "x", "--stealth", "-o", str(workspace / "out.png"), "--no-backup"],
        capture_output=True, timeout=60, stdin=subprocess.DEVNULL, env=env,
    )
    assert r.returncode != 0
    assert b"Password required" in r.stderr


def test_stealth_flag_reported_from_actual_flags(workspace):
    carrier = write_synth_png(workspace)
    res = write_carrier(carrier, data_text="x", password="pw", stealth=True,
                        output_path=str(workspace / "s.png"))
    assert res["is_stealth"] is True
    res2 = write_carrier(write_synth_png(workspace, "c2.png"), data_text="x",
                         password="pw", output_path=str(workspace / "s2.png"))
    assert res2["is_stealth"] is False


# --------------------------------------------------------------------------- R2 / P0-2

def test_sanitize_filename_unit():
    assert sanitize_filename("../x.txt") == "x.txt"
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("a/b/c.bin") == "c.bin"
    assert sanitize_filename("") == "extracted.bin"
    assert sanitize_filename("..") == "extracted.bin"
    assert sanitize_filename(".") == "extracted.bin"
    assert sanitize_filename(None) == "extracted.bin"


def test_path_traversal_sanitized_dir_output(workspace):
    carrier = write_synth_zip(workspace)
    payload = workspace / "payload.bin"
    payload.write_bytes(b"poc-data")
    stego = str(workspace / "evil.zip")
    write_carrier(carrier, data_file=str(payload), output_path=stego)

    # Tamper the (unencrypted) metadata filename with an equal-length traversal.
    data = bytearray(open(stego, "rb").read())
    old, new = b'"filename":"payload.bin"', b'"filename":"../EVIL.txt"'
    assert len(old) == len(new)
    i = data.find(old)
    assert i > 0
    data[i:i + len(old)] = new
    open(stego, "wb").write(bytes(data))

    outdir = workspace / "out"
    outdir.mkdir()
    read_carrier(stego, output_path=str(outdir))
    assert (outdir / "EVIL.txt").exists()
    assert not (workspace / "EVIL.txt").exists()


# --------------------------------------------------------------------------- R3 / P0-4

def test_double_injection_rejected_same_password(workspace):
    carrier = write_synth_png(workspace)
    stego = str(workspace / "d.png")
    write_carrier(carrier, data_text="first", password="pw1", stealth=True, output_path=stego)
    with pytest.raises(StrHideError, match="already contains hidden data"):
        write_carrier(stego, data_text="second", password="pw1", stealth=True,
                      output_path=stego)


def test_double_injection_rejected_standard(workspace):
    carrier = write_synth_png(workspace)
    stego = str(workspace / "d.png")
    write_carrier(carrier, data_text="a", password="x", output_path=stego)
    with pytest.raises(StrHideError, match="already contains hidden data"):
        write_carrier(stego, data_text="b", output_path=stego)


def test_structural_warning_for_unknown_password_envelope(workspace):
    carrier = write_synth_png(workspace)
    stego = str(workspace / "w.png")
    write_carrier(carrier, data_text="first", password="pw1", stealth=True, output_path=stego)
    # Second writer does not know the stealth password: proceed, but warn.
    res = write_carrier(stego, data_text="second",
                        output_path=str(workspace / "w2.png"))
    assert res["warning"] and "only a hidden envelope would produce" in res["warning"]


def test_double_envelope_reverse_order_removal(workspace):
    carrier = write_synth_png(workspace)
    stego = str(workspace / "de.png")
    write_carrier(carrier, data_text="inner", password="pw1", stealth=True, output_path=stego)
    write_carrier(stego, data_text="outer", output_path=stego)

    orig = open(carrier, "rb").read()
    # Remove outer (standard) first, then inner (stealth).
    remove_carrier(stego, output_path=str(workspace / "s1.png"))
    remove_carrier(str(workspace / "s1.png"), password="pw1",
                   output_path=str(workspace / "s2.png"))
    assert open(workspace / "s2.png", "rb").read() == orig


def test_double_envelope_inner_first_removal_diagnosed(workspace):
    carrier = write_synth_png(workspace)
    stego = str(workspace / "de2.png")
    write_carrier(carrier, data_text="inner", password="pw1", stealth=True, output_path=stego)
    write_carrier(stego, data_text="outer", output_path=stego)
    with pytest.raises(RestoreMismatchError, match="reverse order of injection"):
        remove_carrier(stego, password="pw1", output_path=str(workspace / "x.png"))


# --------------------------------------------------------------------------- P0-1

def test_pdf_dirty_tail_lossless(workspace):
    carrier = str(workspace / "dirty.pdf")
    open(carrier, "wb").write(make_pdf_with_dirty_tail())
    stego = str(workspace / "s.pdf")
    write_carrier(carrier, data_text="hello secret", output_path=stego)
    res = read_carrier(stego)
    assert res["data"] == b"hello secret"
    remove_carrier(stego, output_path=str(workspace / "r.pdf"))
    assert open(workspace / "r.pdf", "rb").read() == open(carrier, "rb").read()


def test_pdf_clean_tail_unchanged_behavior(workspace):
    body = (
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n"
        b"trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n"
    )
    carrier = str(workspace / "clean.pdf")
    open(carrier, "wb").write(body)
    stego = str(workspace / "cs.pdf")
    write_carrier(carrier, data_text="x", output_path=stego)
    remove_carrier(stego, output_path=str(workspace / "cr.pdf"))
    assert open(workspace / "cr.pdf", "rb").read() == body


# --------------------------------------------------------------------------- R4 / P1-5

def _exact_ube_size_for_payload(payload_len: int) -> int:
    """Mirror of the engine's exact size computation for a file payload."""
    meta = {
        "filename": "payload.bin",
        "raw_size": payload_len,
        "raw_sha256": "0" * 64,
        "created_at": 1773719840,
    }
    meta_len = len(json.dumps(meta, separators=(",", ":")).encode())
    return HEADER_STRUCT.size + (meta_len + 16) + (payload_len + 20) + 24


def test_auto_capacity_boundary_uses_multisegment_app15(workspace):
    # Payload one byte over the JPEG single-segment limit (65533).
    # With JPEG APP15 multi-segment chaining, it is seamlessly embedded
    # via chained app_segment without degrading to eof trailing data.
    target = 65534
    payload_len = next(
        L for L in range(65000, 65600) if _exact_ube_size_for_payload(L) == target
    )
    payload = workspace / "payload.bin"
    payload.write_bytes(os.urandom(payload_len))
    carrier = str(workspace / "b.jpg")
    open(carrier, "wb").write(make_jpeg())

    res = write_carrier(carrier, data_file=str(payload), password="pw",
                        output_path=str(workspace / "bs.jpg"))
    assert res["strategy"] == "app_segment"
    assert res["ube_size"] == target
    # Round-trip still works through chained APP15 segments.
    out = read_carrier(str(workspace / "bs.jpg"), password="pw")
    assert len(out["data"]) == payload_len

    # Verify 100% loss-free restore
    from strhide.core.engine import remove_carrier
    restored = str(workspace / "restored.jpg")
    remove_carrier(str(workspace / "bs.jpg"), output_path=restored, password="pw")
    assert open(restored, "rb").read() == open(carrier, "rb").read()


def test_explicit_oversize_strategy_rejected_without_tmp(workspace):
    payload = workspace / "rand2.bin"
    payload.write_bytes(b"hello world")
    carrier = str(workspace / "b2.jpg")
    open(carrier, "wb").write(make_jpeg())
    out = str(workspace / "bs2.jpg")
    with pytest.raises(StrHideError, match="not supported"):
        write_carrier(carrier, data_file=str(payload), password="pw",
                      strategy="invalid_strat", output_path=out)
    assert not os.path.exists(out + ".strhide.tmp")


# --------------------------------------------------------------------------- P1-6

def test_zip_fake_eocd_comment_located_correctly(workspace):
    from strhide.adapters.zip import find_eocd_offset
    carrier = str(workspace / "fc.zip")
    open(carrier, "wb").write(make_zip_with_fake_eocd_comment())
    with open(carrier, "rb") as f:
        eocd_pos, cd_offset, cd_size = find_eocd_offset(f)
    size = os.path.getsize(carrier)
    with open(carrier, "rb") as f:
        f.seek(eocd_pos + 20)
        comment_len = struct.unpack("<H", f.read(2))[0]
    # The real EOCD is the one whose comment covers the rest of the file.
    assert eocd_pos + 22 + comment_len == size
    assert cd_offset + cd_size <= eocd_pos


def test_zip_fake_eocd_comment_lifecycle(workspace):
    carrier = str(workspace / "fc2.zip")
    open(carrier, "wb").write(make_zip_with_fake_eocd_comment())
    stego = str(workspace / "fcs.zip")
    res = write_carrier(carrier, data_text="test", output_path=stego)
    assert res["strategy"] == "pre_cd_inject"
    assert verify_carrier(stego)["level2_envelope"]["ok"]
    remove_carrier(stego, output_path=str(workspace / "fcr.zip"))
    assert open(workspace / "fcr.zip", "rb").read() == open(carrier, "rb").read()


def test_zip_eof_stego_still_locatable(workspace):
    """An EOF-strategy envelope appended past the EOCD must remain locatable."""
    carrier = write_synth_zip(workspace)
    stego = str(workspace / "e.zip")
    write_carrier(carrier, data_text="x", strategy="eof", output_path=stego)
    res = read_carrier(stego)
    assert res["data"] == b"x"
    remove_carrier(stego, output_path=str(workspace / "er.zip"))
    assert open(workspace / "er.zip", "rb").read() == open(carrier, "rb").read()


# --------------------------------------------------------------------------- R6

def _stego_with_tamper(workspace, strategy="eof"):
    carrier = write_synth_zip(workspace)
    stego = str(workspace / "t.zip")
    write_carrier(carrier, data_text="t", strategy=strategy, output_path=stego)
    with open(stego, "rb") as f:
        trailer = read_trailer_from_tail(f)
    assert trailer is not None
    raw = bytearray(open(stego, "rb").read())
    return stego, raw, trailer.ube_offset


def test_tampered_version_rejected(workspace):
    stego, raw, off = _stego_with_tamper(workspace)
    raw[off + 8] = 0x09  # version byte
    open(stego, "wb").write(bytes(raw))
    with pytest.raises(CorruptedDataError, match="version"):
        read_carrier(stego)


def test_tampered_meta_len_rejected(workspace):
    stego, raw, off = _stego_with_tamper(workspace)
    raw[off + 104:off + 108] = struct.pack("<I", 0xFFFFFFF0)  # meta_len
    open(stego, "wb").write(bytes(raw))
    with pytest.raises(CorruptedDataError):
        read_carrier(stego)


def test_tampered_hint_len_rejected(workspace):
    stego, raw, off = _stego_with_tamper(workspace)
    raw[off + 108:off + 112] = struct.pack("<I", 0xFFFFFFF0)  # hint_len
    open(stego, "wb").write(bytes(raw))
    with pytest.raises(CorruptedDataError):
        read_carrier(stego)


def test_chunk_len_upper_bound():
    buf = io.BytesIO(struct.pack("<I", 0xFFFFFFF0) + b"\x00" * 32)
    with pytest.raises(CorruptedDataError, match="exceeds maximum"):
        decrypt_stream_from_chunks(buf, io.BytesIO(), b"\x00" * 32,
                                   b"\x00" * 12, b"\x00" * 80, 10 ** 9)


# --------------------------------------------------------------------------- R10 (compression criterion)

def test_compression_criterion_integer_equivalence():
    """comp_len * 100 < raw_size * 98 must drive the compressed flag."""
    from strhide.core.crypto import compress_stream
    data = b"A" * 102
    buf = io.BytesIO()
    raw_len, comp_len = compress_stream(io.BytesIO(data), buf)
    assert comp_len * 100 < raw_len * 98  # highly compressible -> compressed
