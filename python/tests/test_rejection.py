"""Unit tests for security rejection checks."""

import io
import struct
import pytest

from strhide.core.rejection import (
    check_unsupported_apk,
    check_jar_signature,
    check_pe_authenticode,
    check_pdf_signature,
    check_signature_file,
    run_all_rejection_checks,
)


def test_signature_file_extension():
    assert check_signature_file("test.sig") is not None
    assert check_signature_file("test.asc") is not None
    assert check_signature_file("test.png") is None


def test_apk_rejection():
    assert check_unsupported_apk(filename="app.apk") is not None
    assert check_unsupported_apk(filename="app.zip") is None


def test_pdf_signed_rejection():
    # Unsigned PDF
    clean_pdf = io.BytesIO(b"%PDF-1.4\n1 0 obj\n<< /Title (Test) >>\nendobj\n%%EOF")
    assert check_pdf_signature(clean_pdf) is None

    # Signed PDF
    signed_pdf = io.BytesIO(b"%PDF-1.4\n/ByteRange [0 100 200 300]\n/Type /Sig\n%%EOF")
    assert check_pdf_signature(signed_pdf) is not None


def test_pe_authenticode_rejection():
    # Synthetic PE with Authenticode
    # MZ at 0, e_lfanew at 0x3C
    buf = bytearray(512)
    buf[0:2] = b"MZ"
    e_lfanew = 0x80
    buf[0x3C:0x40] = struct.pack("<I", e_lfanew)
    
    # PE Header at 0x80
    buf[e_lfanew:e_lfanew+4] = b"PE\x00\x00"
    # COFF File Header (20B)
    buf[e_lfanew+4+16:e_lfanew+4+18] = struct.pack("<H", 224) # SizeOfOptionalHeader
    
    # Optional Header at e_lfanew + 24
    opt_offset = e_lfanew + 24
    buf[opt_offset:opt_offset+2] = struct.pack("<H", 0x20B) # PE32+ (64-bit)
    
    # For PE32+, Security directory is at opt_offset + 144
    sec_offset = opt_offset + 144
    buf[sec_offset:sec_offset+8] = struct.pack("<II", 0x1000, 0x200) # VirtAddr, Size
    
    stream = io.BytesIO(bytes(buf))
    assert check_pe_authenticode(stream) is not None

    # Zero out security dir -> should pass
    buf[sec_offset:sec_offset+8] = struct.pack("<II", 0, 0)
    stream_clean = io.BytesIO(bytes(buf))
    assert check_pe_authenticode(stream_clean) is None
