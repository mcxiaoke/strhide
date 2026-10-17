"""MP4 / MOV ISO BMFF container adapter for strhide with neutral 64-bit uuid Box."""

from __future__ import annotations

import shutil
import struct
from typing import BinaryIO, List, Optional, Tuple

from strhide.adapters.base import HostAdapter
from strhide.core.envelope import EnvelopeHeader, read_trailer_from_tail
from strhide.errors import CorruptedDataError, UnsupportedFormatError

# Neutral RFC 4122 UUID namespace (avoids leaking STRHIDE in WinHex ASCII view)
MP4_UUID_NEUTRAL = b"\xd4\x1a\x8e\x9c\x4f\x21\x4e\x87\x9a\x33\x5b\x6d\x12\x84\xef\x70"
LEGACY_UUID_NAMESPACE = b"\x89STRHIDE\x00\x00\x00\x00\x00\x00\x00\x01"


class Mp4Adapter(HostAdapter):
    """Adapter for MP4/MOV containers appending 64-bit uuid Box at end of stream."""

    def format_name(self) -> str:
        return "MP4"

    def detect(self, stream: BinaryIO) -> bool:
        start_pos = stream.tell()
        try:
            stream.seek(0)
            prefix = stream.read(8)
            if len(prefix) < 8:
                return False
            return prefix[4:8] in (b"ftyp", b"moov", b"mdat", b"wide", b"skip")
        finally:
            stream.seek(start_pos)

    def supported_strategies(self) -> List[str]:
        return ["box_uuid", "eof"]

    def choose_auto_strategy(self, stream: BinaryIO, ube_size: int) -> str:
        return "box_uuid"

    def calc_prefix_len(self, ube_size: int) -> int:
        """Calculate box header prefix length: 24 bytes for standard 32-bit box, 32 bytes for 64-bit box."""
        if 24 + ube_size < 0xFFFFFFFF:
            return 24
        return 32

    def inject(
        self,
        host_in: BinaryIO,
        ube_in: BinaryIO,
        out: BinaryIO,
        strategy: str,
    ) -> Tuple[int, int, int, int]:
        if strategy not in ("box_uuid", "eof"):
            raise UnsupportedFormatError(f"Strategy '{strategy}' not supported by MP4 adapter")

        host_in.seek(0)
        shutil.copyfileobj(host_in, out)
        inject_offset = out.tell()

        ube_in.seek(0, 2)
        ube_size = ube_in.tell()
        ube_in.seek(0)

        if strategy == "box_uuid":
            if 24 + ube_size < 0xFFFFFFFF:
                # Standard 32-bit Box format (ISO/IEC 14496-12 compliant for < 4GB):
                # [Size (4B)] + [Type = 'uuid' (4B)] + [UUID (16B)] + [UBE]
                total_box_size = 24 + ube_size
                box_header = struct.pack(">I4s16s", total_box_size, b"uuid", MP4_UUID_NEUTRAL)
            else:
                # 64-bit Large Box format (ISO/IEC 14496-12 for >= 4GB):
                # [Size = 1 (4B)] + [Type = 'uuid' (4B)] + [LargeSize = 32 + ube_size (8B)] + [UUID (16B)] + [UBE]
                largesize = 32 + ube_size
                box_header = struct.pack(">I4sQ16s", 1, b"uuid", largesize, MP4_UUID_NEUTRAL)

            out.write(box_header)
            shutil.copyfileobj(ube_in, out)
            inject_size = len(box_header) + ube_size
        else:
            shutil.copyfileobj(ube_in, out)
            inject_size = ube_size

        return inject_offset, inject_size, 0, 0

    def locate(
        self,
        stego_in: BinaryIO,
        expected_trailer_magic: Optional[bytes] = None,
    ) -> Optional[Tuple[int, int, str]]:
        trailer = read_trailer_from_tail(stego_in, expected_magic=expected_trailer_magic)
        if not trailer:
            return None

        # Determine if it's box_uuid or eof
        # 1. Check standard 32-bit uuid box (24-byte header before trailer.ube_offset)
        if trailer.ube_offset >= 24:
            stego_in.seek(trailer.ube_offset - 24)
            hdr24 = stego_in.read(24)
            if len(hdr24) == 24:
                size, box_type, uuid_ns = struct.unpack(">I4s16s", hdr24)
                if size != 1 and box_type == b"uuid" and (
                    size == 24 + trailer.ube_total_size
                    or uuid_ns in (MP4_UUID_NEUTRAL, LEGACY_UUID_NAMESPACE)
                ):
                    return trailer.ube_offset, trailer.ube_total_size, "box_uuid"

        # 2. Check 64-bit large uuid box (32-byte header before trailer.ube_offset, for >=4GB & backward compat)
        if trailer.ube_offset >= 32:
            stego_in.seek(trailer.ube_offset - 32)
            hdr32 = stego_in.read(32)
            if len(hdr32) == 32:
                size, box_type, largesize, uuid_ns = struct.unpack(">I4sQ16s", hdr32)
                if size == 1 and box_type == b"uuid" and (
                    largesize == 32 + trailer.ube_total_size
                    or uuid_ns in (MP4_UUID_NEUTRAL, LEGACY_UUID_NAMESPACE)
                ):
                    return trailer.ube_offset, trailer.ube_total_size, "box_uuid"

        return trailer.ube_offset, trailer.ube_total_size, "eof"

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
        stego_in.seek(0)

        # Walk top-level boxes
        offset = 0
        box_count = 0
        has_ftyp = False
        while offset < total_size:
            hdr = stego_in.read(8)
            if len(hdr) < 8:
                break
            size, box_type = struct.unpack(">I4s", hdr)
            if box_type == b"ftyp":
                has_ftyp = True

            if size == 1:
                large_bytes = stego_in.read(8)
                if len(large_bytes) < 8:
                    return False, f"Truncated 64-bit size for box {box_type}"
                size = struct.unpack(">Q", large_bytes)[0]
                read_header = 16
            elif size == 0:
                # Box extends to end of file
                size = total_size - offset
                read_header = 8
            else:
                read_header = 8

            if size < read_header:
                return False, f"Invalid box size {size} for box {box_type}"

            offset += size
            box_count += 1
            stego_in.seek(offset)

        if not has_ftyp:
            return False, "MP4 missing ftyp box"
        return True, f"MP4 box tree valid ({box_count} top-level boxes)"

    def suspicious_structures(self, stego_in: BinaryIO) -> list[str]:
        # A trailing top-level uuid box using the strhide namespaces can only
        # be a hidden envelope (checked without the magic, so stealth
        # envelopes with an unknown password are still detected structurally).
        import zlib

        found: list[str] = []
        stego_in.seek(0, 2)
        file_size = stego_in.tell()
        if file_size < 24:
            return found
        stego_in.seek(file_size - 24)
        tail = stego_in.read(24)
        if len(tail) < 24:
            return found
        ube_offset, ube_total_size, crc = struct.unpack_from("<QQI", tail, 0)
        if (zlib.crc32(tail[:16]) & 0xFFFFFFFF) != crc:
            return found
        if ube_offset + ube_total_size != file_size:
            return found
        if ube_offset >= 24:
            stego_in.seek(ube_offset - 24)
            hdr = stego_in.read(24)
            if len(hdr) == 24:
                _, box_type, uuid_ns = struct.unpack(">I4s16s", hdr)
                if box_type == b"uuid" and uuid_ns in (MP4_UUID_NEUTRAL, LEGACY_UUID_NAMESPACE):
                    found.append(
                        f"trailing uuid box at offset {ube_offset - 24} carries {ube_total_size} bytes"
                    )
        return found
