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
            # 64-bit Large Box format:
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
        # For box_uuid: 32 bytes before trailer.ube_offset should be the box header
        if trailer.ube_offset >= 32:
            stego_in.seek(trailer.ube_offset - 32)
            hdr = stego_in.read(32)
            if len(hdr) == 32:
                size, box_type, largesize, uuid_ns = struct.unpack(">I4sQ16s", hdr)
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
