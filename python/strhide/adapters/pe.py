"""Windows Portable Executable (PE) adapter for strhide.

Handles Windows .exe, .dll, .sys, .scr files.
Supports:
- Format sniffing (MZ + PE signature validation, 32-bit & 64-bit COFF header).
- Security checks: Prevents modifying PE files with Authenticode digital signatures.
- Strategies:
  - 'pe_overlay': Appends compliant UBE envelope to the PE Overlay region.
    Preserves all section headers, imports, exports, resources, code and existing overlays.
  - 'eof': Standard EOF overlay alias.
- 100% bit-exact removal and restoration.
"""

from __future__ import annotations

import shutil
import struct
from typing import BinaryIO, List, Optional, Tuple

from strhide.adapters.base import HostAdapter
from strhide.core.envelope import EnvelopeHeader, read_trailer_from_tail
from strhide.errors import UnsupportedFormatError

PE_DOS_MAGIC = b"MZ"
PE_NT_MAGIC = b"PE\x00\x00"


def parse_pe_headers(stream: BinaryIO) -> Tuple[str, int, int, int, bool]:
    """Parse PE headers and return structural information.

    Returns:
        (arch, num_sections, pe_image_end, host_size, has_authenticode)
    """
    start_pos = stream.tell()
    try:
        stream.seek(0, 2)
        host_size = stream.tell()
        if host_size < 0x40:
            raise UnsupportedFormatError("File too small to be a PE executable")

        stream.seek(0)
        if stream.read(2) != PE_DOS_MAGIC:
            raise UnsupportedFormatError("Not a valid DOS/PE executable (missing 'MZ')")

        stream.seek(0x3C)
        e_lfanew_bytes = stream.read(4)
        if len(e_lfanew_bytes) < 4:
            raise UnsupportedFormatError("Truncated DOS header (missing e_lfanew)")
        e_lfanew = struct.unpack("<I", e_lfanew_bytes)[0]
        if e_lfanew < 0x40 or e_lfanew + 24 > host_size:
            raise UnsupportedFormatError(f"Invalid e_lfanew offset (0x{e_lfanew:X})")

        stream.seek(e_lfanew)
        if stream.read(4) != PE_NT_MAGIC:
            raise UnsupportedFormatError("Not a valid PE executable (missing 'PE\\0\\0')")

        coff_header = stream.read(20)
        if len(coff_header) < 20:
            raise UnsupportedFormatError("Truncated COFF file header")

        num_sections = struct.unpack("<H", coff_header[2:4])[0]
        size_of_opt_header = struct.unpack("<H", coff_header[16:18])[0]

        opt_magic = 0
        has_authenticode = False
        if size_of_opt_header >= 2:
            opt_pos = stream.tell()
            opt_magic = struct.unpack("<H", stream.read(2))[0]
            # Check Authenticode Certificate Table directory entry:
            # PE32 (0x10B): offset 128 from Optional Header start
            # PE32+ (0x20B): offset 144 from Optional Header start
            sec_dir_offset = 128 if opt_magic == 0x10B else (144 if opt_magic == 0x20B else None)
            if sec_dir_offset and size_of_opt_header >= sec_dir_offset + 8:
                stream.seek(opt_pos + sec_dir_offset)
                sec_bytes = stream.read(8)
                if len(sec_bytes) == 8:
                    sec_va, sec_sz = struct.unpack("<II", sec_bytes)
                    if sec_va != 0 and sec_sz != 0:
                        has_authenticode = True

        arch = "PE32+" if opt_magic == 0x20B else ("PE32" if opt_magic == 0x10B else "Unknown")

        # Read sections to determine pe_image_end (highest raw end)
        sec_table_offset = e_lfanew + 24 + size_of_opt_header
        stream.seek(sec_table_offset)
        pe_image_end = sec_table_offset
        for _ in range(num_sections):
            sec_header = stream.read(40)
            if len(sec_header) < 40:
                break
            # SizeOfRawData at offset 16, PointerToRawData at offset 20
            raw_size = struct.unpack("<I", sec_header[16:20])[0]
            raw_ptr = struct.unpack("<I", sec_header[20:24])[0]
            sec_end = raw_ptr + raw_size
            if sec_end > pe_image_end:
                pe_image_end = sec_end

        return arch, num_sections, pe_image_end, host_size, has_authenticode
    finally:
        stream.seek(start_pos)


class PeAdapter(HostAdapter):
    """Windows Portable Executable (PE) adapter.

    Appends compliant UBE envelope to the PE Overlay region.
    Preserves all PE sections and headers; code remains 100% executable.
    """

    def format_name(self) -> str:
        return "PE"

    def detect(self, stream: BinaryIO) -> bool:
        start_pos = stream.tell()
        try:
            stream.seek(0)
            if stream.read(2) != PE_DOS_MAGIC:
                return False
            stream.seek(0x3C)
            lfanew_bytes = stream.read(4)
            if len(lfanew_bytes) < 4:
                return False
            e_lfanew = struct.unpack("<I", lfanew_bytes)[0]
            if e_lfanew < 0x40 or e_lfanew > 0x1000:
                return False
            stream.seek(e_lfanew)
            return stream.read(4) == PE_NT_MAGIC
        except Exception:
            return False
        finally:
            stream.seek(start_pos)

    def supported_strategies(self) -> List[str]:
        return ["pe_overlay", "eof"]

    def choose_auto_strategy(self, stream: BinaryIO, ube_size: int) -> str:
        return "pe_overlay"

    def inject(
        self,
        host_in: BinaryIO,
        ube_in: BinaryIO,
        out: BinaryIO,
        strategy: str,
    ) -> Tuple[int, int, int, int]:
        if strategy not in ("pe_overlay", "eof"):
            raise UnsupportedFormatError(
                f"Strategy '{strategy}' not supported by PE adapter. Supported strategies: pe_overlay, eof"
            )

        arch, num_sections, pe_image_end, host_size, has_authenticode = parse_pe_headers(host_in)

        if has_authenticode:
            raise UnsupportedFormatError(
                "Cannot inject into Windows PE: Executable contains an Authenticode digital signature. "
                "Modifying it will invalidate the digital signature."
            )

        if host_size < pe_image_end:
            raise UnsupportedFormatError(
                f"Corrupted PE executable: file size ({host_size:,} bytes) is smaller than PE section headers dictate ({pe_image_end:,} bytes)."
            )

        ube_in.seek(0, 2)
        ube_size = ube_in.tell()
        ube_in.seek(0)

        # Copy original PE host completely
        host_in.seek(0)
        shutil.copyfileobj(host_in, out)
        inject_offset = out.tell()

        # Append UBE data
        shutil.copyfileobj(ube_in, out)
        inject_size = out.tell() - inject_offset

        return inject_offset, inject_size, 0, 0

    def locate(
        self,
        stego_in: BinaryIO,
        expected_trailer_magic: Optional[bytes] = None,
    ) -> Optional[Tuple[int, int, str]]:
        trailer = read_trailer_from_tail(stego_in, expected_magic=expected_trailer_magic)
        if not trailer:
            return None
        stego_in.seek(0, 2)
        total_size = stego_in.tell()
        if trailer.ube_offset + trailer.ube_total_size == total_size:
            return trailer.ube_offset, trailer.ube_total_size, "pe_overlay"
        return None

    def strip(
        self,
        stego_in: BinaryIO,
        out: BinaryIO,
        header: EnvelopeHeader,
    ) -> None:
        stego_in.seek(0)
        remaining = header.orig_host_size
        while remaining > 0:
            chunk = stego_in.read(min(64 * 1024, remaining))
            if not chunk:
                break
            out.write(chunk)
            remaining -= len(chunk)

    def verify_structure(self, stego_in: BinaryIO) -> Tuple[bool, str]:
        stego_in.seek(0, 2)
        total_size = stego_in.tell()
        trailer = read_trailer_from_tail(stego_in)
        if not trailer:
            return False, "Locator trailer not found at end of file"
        if trailer.ube_offset + trailer.ube_total_size != total_size:
            return (
                False,
                f"Trailer boundary mismatch: offset({trailer.ube_offset}) + size({trailer.ube_total_size}) != total({total_size})",
            )
        return True, "PE overlay envelope structure verified successfully"

    def suspicious_structures(self, stego_in: BinaryIO) -> list[str]:
        # Data appended beyond the PE image boundary is an overlay; anything
        # past the minimum envelope size is a probable hidden envelope.
        min_envelope = 112 + 24
        found: list[str] = []
        try:
            arch, num_sections, pe_image_end, host_size, has_authenticode = parse_pe_headers(stego_in)
            if host_size > pe_image_end + min_envelope:
                found.append(
                    f"overlay of {host_size - pe_image_end} bytes beyond PE image boundary "
                    f"(minimum envelope size is {min_envelope})"
                )
        except Exception:
            pass
        return found
