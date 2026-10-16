"""Security pre-check and rejection rules for strhide.

Strictly rejects files with digital signatures or integrity checks (Fail-Safe by Default).
"""

from __future__ import annotations

import os
import struct
import zipfile
from typing import BinaryIO, Optional


def check_pe_authenticode(stream: BinaryIO) -> Optional[str]:
    """Check if Windows PE executable has an Authenticode digital signature."""
    start_pos = stream.tell()
    try:
        stream.seek(0)
        mz = stream.read(2)
        if mz != b"MZ":
            return None

        stream.seek(0x3C)
        e_lfanew_bytes = stream.read(4)
        if len(e_lfanew_bytes) < 4:
            return None
        e_lfanew = struct.unpack("<I", e_lfanew_bytes)[0]

        stream.seek(e_lfanew)
        pe_sig = stream.read(4)
        if pe_sig != b"PE\x00\x00":
            return None

        # COFF File Header (20 bytes)
        coff_header = stream.read(20)
        if len(coff_header) < 20:
            return None
        size_of_optional_header = struct.unpack("<H", coff_header[16:18])[0]
        if size_of_optional_header == 0:
            return None

        # Optional Header Magic (2 bytes)
        opt_magic_bytes = stream.read(2)
        if len(opt_magic_bytes) < 2:
            return None
        opt_magic = struct.unpack("<H", opt_magic_bytes)[0]

        # Directory entry 4: IMAGE_DIRECTORY_ENTRY_SECURITY (Certificate Table)
        # PE32 (0x10b): offset 96 from OptionalHeader start -> 96 + 4*8 = 128
        # PE32+ (0x20b): offset 112 from OptionalHeader start -> 112 + 4*8 = 144
        if opt_magic == 0x10B:
            sec_dir_offset = e_lfanew + 24 + 128
        elif opt_magic == 0x20B:
            sec_dir_offset = e_lfanew + 24 + 144
        else:
            return None

        stream.seek(sec_dir_offset)
        sec_dir_bytes = stream.read(8)
        if len(sec_dir_bytes) < 8:
            return None
        virt_addr, size = struct.unpack("<II", sec_dir_bytes)

        if virt_addr != 0 and size != 0:
            return "Windows PE contains an Authenticode digital signature. Modification will invalidate the signature."
        return None
    except Exception:
        return None
    finally:
        stream.seek(start_pos)


def check_unsupported_apk(filename: Optional[str] = None) -> Optional[str]:
    """Check if the file is an Android APK (APK is strictly not supported)."""
    if filename and filename.lower().endswith(".apk"):
        return "APK 格式不在支持列表中（不支持作为载体文件进行修改）。"
    return None


def check_pdf_signature(stream: BinaryIO) -> Optional[str]:
    """Check if PDF document contains digital signatures (/ByteRange and /Type /Sig)."""
    start_pos = stream.tell()
    try:
        stream.seek(0)
        header = stream.read(1024)
        if not header.startswith(b"%PDF-"):
            return None

        # Quick scan stream in chunks for ByteRange and /Sig
        stream.seek(0)
        content = stream.read(1024 * 1024)  # 1MB sample
        if b"/ByteRange" in content and (b"/Sig" in content or b"/Type /Sig" in content or b"/Type/Sig" in content):
            return "PDF document contains a cryptographic digital signature. Modifying it will invalidate the signature."
        return None
    except Exception:
        return None
    finally:
        stream.seek(start_pos)


def check_jar_signature(stream: BinaryIO, filename: Optional[str] = None) -> Optional[str]:
    """Check if JAR contains META-INF signature files (*.SF, *.RSA, *.DSA)."""
    if filename and not filename.lower().endswith((".jar", ".war", ".ear")):
        return None

    start_pos = stream.tell()
    try:
        stream.seek(0)
        with zipfile.ZipFile(stream, "r") as zf:
            for name in zf.namelist():
                upper = name.upper()
                if upper.startswith("META-INF/") and (upper.endswith(".SF") or upper.endswith(".RSA") or upper.endswith(".DSA")):
                    return f"JAR archive contains digital signature file ({name}). Modifying it will break JVM verification."
        return None
    except Exception:
        return None
    finally:
        stream.seek(start_pos)


def check_signature_file(filename: Optional[str] = None) -> Optional[str]:
    """Check if the carrier file itself is a detached signature."""
    if not filename:
        return None
    lower = filename.lower()
    if lower.endswith((".sig", ".asc", ".p7s", ".p7b")):
        return f"File '{filename}' is a standalone digital signature file and cannot be used as a carrier."
    return None


def run_all_rejection_checks(stream: BinaryIO, filepath: Optional[str] = None) -> Optional[str]:
    """Run all security checks against the target carrier. Returns error reason if rejected, else None."""
    filename = os.path.basename(filepath) if filepath else None

    # Check write permission if filepath is provided
    if filepath and os.path.exists(filepath):
        if not os.access(filepath, os.W_OK):
            return f"No write permission on target file '{filepath}'."
        parent_dir = os.path.dirname(os.path.abspath(filepath)) or "."
        if not os.access(parent_dir, os.W_OK):
            return f"No write permission on parent directory '{parent_dir}'."

    # Check signature file extensions
    sig_err = check_signature_file(filename)
    if sig_err:
        return sig_err

    # Check unsupported APK
    apk_err = check_unsupported_apk(filename)
    if apk_err:
        return apk_err

    # Check PE Authenticode
    pe_err = check_pe_authenticode(stream)
    if pe_err:
        return pe_err

    # Check PDF Digital Signature
    pdf_err = check_pdf_signature(stream)
    if pdf_err:
        return pdf_err

    # Check JAR Signatures
    jar_err = check_jar_signature(stream, filename)
    if jar_err:
        return jar_err

    return None
