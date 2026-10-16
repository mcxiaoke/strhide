"""PNG format adapter for strhide with ancillary chunk and dirty-tail tolerance."""

from __future__ import annotations

import struct
import zlib
from typing import BinaryIO, List, Optional, Tuple

from strhide.adapters.base import HostAdapter
from strhide.core.envelope import EnvelopeHeader, read_trailer_from_tail
from strhide.errors import CorruptedDataError, UnsupportedFormatError

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
IEND_FULL = b"\x00\x00\x00\x00IEND\xaeB`\x82"
CHUNK_STEG = b"stEg"


def find_iend_offset(stream: BinaryIO) -> Tuple[int, int]:
    """Find the offset of IEND chunk from tail, tolerating trailing garbage bytes.
    
    Returns (iend_offset, total_size).
    """
    stream.seek(0, 2)
    total_size = stream.tell()
    scan_len = min(total_size, 64 * 1024)
    stream.seek(total_size - scan_len)
    tail = stream.read(scan_len)

    idx = tail.rfind(IEND_FULL)
    if idx == -1:
        raise CorruptedDataError("Valid PNG IEND chunk not found within tail scan window")

    iend_offset = (total_size - scan_len) + idx
    return iend_offset, total_size


class PngAdapter(HostAdapter):
    """Adapter for PNG images injecting private ancillary 'stEg' chunk."""

    def format_name(self) -> str:
        return "PNG"

    def detect(self, stream: BinaryIO) -> bool:
        start_pos = stream.tell()
        try:
            stream.seek(0)
            magic = stream.read(8)
            return magic == PNG_MAGIC
        finally:
            stream.seek(start_pos)

    def supported_strategies(self) -> List[str]:
        return ["chunk", "eof"]

    def choose_auto_strategy(self, stream: BinaryIO, ube_size: int) -> str:
        return "chunk"

    def inject(
        self,
        host_in: BinaryIO,
        ube_in: BinaryIO,
        out: BinaryIO,
        strategy: str,
    ) -> Tuple[int, int, int, int]:
        if strategy == "eof":
            from strhide.adapters.eof import EofAdapter
            return EofAdapter().inject(host_in, ube_in, out, strategy)

        if strategy != "chunk":
            raise UnsupportedFormatError(f"Strategy '{strategy}' not supported by PNG adapter")

        iend_offset, total_size = find_iend_offset(host_in)

        # 1. Write everything before IEND
        host_in.seek(0)
        remaining = iend_offset
        while remaining > 0:
            buf = host_in.read(min(64 * 1024, remaining))
            out.write(buf)
            remaining -= len(buf)

        inject_offset = out.tell()

        # 2. Prepare stEg chunk
        ube_in.seek(0, 2)
        ube_size = ube_in.tell()
        ube_in.seek(0)

        # Calculate CRC over chunk_type + chunk_data
        crc_val = zlib.crc32(CHUNK_STEG)
        while True:
            chunk = ube_in.read(64 * 1024)
            if not chunk:
                break
            crc_val = zlib.crc32(chunk, crc_val)
        crc_val &= 0xFFFFFFFF

        # Write chunk length and type
        out.write(struct.pack(">I4s", ube_size, CHUNK_STEG))
        # Write chunk data (UBE)
        ube_in.seek(0)
        while True:
            chunk = ube_in.read(64 * 1024)
            if not chunk:
                break
            out.write(chunk)
        # Write CRC
        out.write(struct.pack(">I", crc_val))

        inject_size = out.tell() - inject_offset

        # 3. Write IEND chunk and any trailing garbage
        host_in.seek(iend_offset)
        while True:
            buf = host_in.read(64 * 1024)
            if not buf:
                break
            out.write(buf)

        return inject_offset, inject_size, 0, 0

    def locate(
        self,
        stego_in: BinaryIO,
        expected_trailer_magic: Optional[bytes] = None,
    ) -> Optional[Tuple[int, int, str]]:
        stego_in.seek(0)
        magic = stego_in.read(8)
        if magic != PNG_MAGIC:
            return None

        # Check chunk strategy first
        while True:
            hdr = stego_in.read(8)
            if len(hdr) < 8:
                break
            length, chunk_type = struct.unpack(">I4s", hdr)
            chunk_data_offset = stego_in.tell()

            if chunk_type == CHUNK_STEG:
                return chunk_data_offset, length, "chunk"

            if chunk_type == b"IEND":
                break

            # Skip chunk data + 4 bytes CRC
            stego_in.seek(chunk_data_offset + length + 4)

        # Fallback to EOF trailer if not found as chunk
        trailer = read_trailer_from_tail(stego_in, expected_magic=expected_trailer_magic)
        if trailer:
            return trailer.ube_offset, trailer.ube_total_size, "eof"

        return None

    def strip(
        self,
        stego_in: BinaryIO,
        out: BinaryIO,
        header: EnvelopeHeader,
    ) -> None:
        if header.strategy_id == 1:  # EOF
            from strhide.adapters.eof import EofAdapter
            return EofAdapter().strip(stego_in, out, header)

        # Strip intermediate chunk: write [0 : inject_offset], skip inject_size, write rest
        stego_in.seek(0)
        remaining = header.inject_offset
        while remaining > 0:
            buf = stego_in.read(min(64 * 1024, remaining))
            out.write(buf)
            remaining -= len(buf)

        stego_in.seek(header.inject_offset + header.inject_size)
        while True:
            buf = stego_in.read(64 * 1024)
            if not buf:
                break
            out.write(buf)

    def verify_structure(self, stego_in: BinaryIO) -> Tuple[bool, str]:
        stego_in.seek(0)
        if stego_in.read(8) != PNG_MAGIC:
            return False, "Not a valid PNG file"

        has_steg = False
        has_iend = False
        while True:
            hdr = stego_in.read(8)
            if len(hdr) < 8:
                break
            length, chunk_type = struct.unpack(">I4s", hdr)
            data_start = stego_in.tell()

            if chunk_type == CHUNK_STEG:
                has_steg = True

            stego_in.seek(data_start + length)
            crc_bytes = stego_in.read(4)
            if len(crc_bytes) < 4:
                return False, f"Truncated CRC for chunk {chunk_type.decode('ascii', errors='ignore')}"

            if chunk_type == b"IEND":
                has_iend = True
                break

        if not has_iend:
            return False, "PNG missing IEND chunk"
        return True, f"PNG structure valid (stEg chunk present: {has_steg})"
