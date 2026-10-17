"""PNG format adapter for strhide with neutral ancillary chunk and dirty-tail tolerance."""

from __future__ import annotations

import struct
import zlib
from typing import BinaryIO, List, Optional, Tuple

from strhide.adapters.base import HostAdapter
from strhide.core.envelope import EnvelopeHeader, read_trailer_from_tail
from strhide.errors import CorruptedDataError, UnsupportedFormatError

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
IEND_FULL = b"\x00\x00\x00\x00IEND\xaeB`\x82"
CHUNK_PRIV = b"prIv"  # Standard-compliant neutral private ancillary chunk
SUPPORTED_CHUNKS = (b"prIv", b"stEg")  # Supports both new prIv and legacy stEg
PNG_MAX_CHUNK_LEN = 0x7FFFFFFF  # 2GB


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
    """Adapter for PNG images injecting private ancillary 'prIv' (or legacy 'stEg') chunk."""

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
        # Best-effort: use chunk for <= 2GB, fallback to eof if exceeded
        if ube_size > PNG_MAX_CHUNK_LEN:
            return "eof"
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

        ube_in.seek(0, 2)
        ube_size = ube_in.tell()
        ube_in.seek(0)

        if ube_size > PNG_MAX_CHUNK_LEN:
            raise UnsupportedFormatError(
                f"Payload size ({ube_size:,} bytes) exceeds PNG chunk maximum capacity (2GB). "
                f"Please specify --strategy eof."
            )

        iend_offset, total_size = find_iend_offset(host_in)

        # 1. Write everything before IEND
        host_in.seek(0)
        remaining = iend_offset
        while remaining > 0:
            buf = host_in.read(min(64 * 1024, remaining))
            out.write(buf)
            remaining -= len(buf)

        inject_offset = out.tell()

        # 2. Prepare prIv chunk
        crc_val = zlib.crc32(CHUNK_PRIV)
        while True:
            chunk = ube_in.read(64 * 1024)
            if not chunk:
                break
            crc_val = zlib.crc32(chunk, crc_val)
        crc_val &= 0xFFFFFFFF

        # Write chunk length and type (prIv)
        out.write(struct.pack(">I4s", ube_size, CHUNK_PRIV))
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

        # Check chunk strategy first (supporting both prIv and legacy stEg)
        while True:
            hdr = stego_in.read(8)
            if len(hdr) < 8:
                break
            length, chunk_type = struct.unpack(">I4s", hdr)
            chunk_data_offset = stego_in.tell()

            if chunk_type in SUPPORTED_CHUNKS:
                if length >= 112 + 24:
                    trailer_offset = chunk_data_offset + length - 24
                    stego_in.seek(trailer_offset)
                    trailer_bytes = stego_in.read(24)
                    try:
                        from strhide.core.envelope import EnvelopeTrailer, STANDARD_TRAILER_MAGIC
                        trailer = EnvelopeTrailer.unpack(trailer_bytes, expected_magic=expected_trailer_magic)
                        if expected_trailer_magic is None and trailer.trailer_magic != STANDARD_TRAILER_MAGIC:
                            return None
                        return chunk_data_offset, length, "chunk"
                    except Exception:
                        pass

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

        found_chunk = None
        has_iend = False
        while True:
            hdr = stego_in.read(8)
            if len(hdr) < 8:
                break
            length, chunk_type = struct.unpack(">I4s", hdr)
            data_start = stego_in.tell()

            if chunk_type in SUPPORTED_CHUNKS:
                found_chunk = chunk_type.decode("latin-1", errors="replace")

            stego_in.seek(data_start + length)
            crc_bytes = stego_in.read(4)
            if len(crc_bytes) < 4:
                return False, f"Truncated CRC for chunk {chunk_type.decode('ascii', errors='ignore')}"

            if chunk_type == b"IEND":
                has_iend = True
                break

        if not has_iend:
            return False, "PNG missing IEND chunk"

        detail = f"private chunk '{found_chunk}' present" if found_chunk else "clean standard chunks"
        return True, f"PNG structure valid ({detail})"

    def suspicious_structures(self, stego_in: BinaryIO) -> list[str]:
        # A prIv/stEg chunk carrying >= 136 bytes (minimum envelope size) can
        # only realistically be a hidden envelope.
        min_envelope = 112 + 24
        found: list[str] = []
        stego_in.seek(0)
        if stego_in.read(8) != PNG_MAGIC:
            return found

        while True:
            hdr = stego_in.read(8)
            if len(hdr) < 8:
                break
            length, chunk_type = struct.unpack(">I4s", hdr)
            chunk_offset = stego_in.tell() - 8

            if chunk_type in SUPPORTED_CHUNKS and length >= min_envelope:
                found.append(
                    f"private chunk '{chunk_type.decode('latin-1', errors='replace')}' at offset "
                    f"{chunk_offset} carries {length} bytes (minimum envelope size is {min_envelope})"
                )

            if chunk_type == b"IEND":
                break

            stego_in.seek(stego_in.tell() + length + 4)

        return found
