"""JPEG format adapter for strhide with precise EOI boundary scanning."""

from __future__ import annotations

import struct
from typing import BinaryIO, List, Optional, Tuple

from strhide.adapters.base import HostAdapter
from strhide.core.envelope import EnvelopeHeader, read_trailer_from_tail
from strhide.errors import CorruptedDataError, UnsupportedFormatError

JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"
JPEG_SOS = b"\xff\xda"


def find_jpeg_eoi_offset(stream: BinaryIO) -> int:
    """Scan JPEG marker chain past SOS to find authentic EOI (0xFF 0xD9) offset.
    
    Returns the byte offset immediately following EOI (where data can be safely appended).
    """
    stream.seek(0)
    soi = stream.read(2)
    if soi != JPEG_SOI:
        raise CorruptedDataError("Invalid JPEG SOI marker")

    # Step through markers until SOS
    while True:
        marker_lead = stream.read(1)
        if not marker_lead:
            break
        if marker_lead != b"\xff":
            continue

        marker_code = stream.read(1)
        if not marker_code:
            break

        # Standalone markers without length
        if marker_code in (b"\xd8", b"\xd9"):  # SOI, EOI
            continue
        if 0xD0 <= marker_code[0] <= 0xD7:  # RSTm
            continue

        if marker_code == b"\xda":  # SOS (Start of Scan)
            # Read SOS length and skip header
            sos_len_bytes = stream.read(2)
            if len(sos_len_bytes) < 2:
                raise CorruptedDataError("Truncated SOS segment header")
            sos_len = struct.unpack(">H", sos_len_bytes)[0]
            stream.seek(stream.tell() + sos_len - 2)
            break

        # Normal segment: read 16-bit BE length
        seg_len_bytes = stream.read(2)
        if len(seg_len_bytes) < 2:
            break
        seg_len = struct.unpack(">H", seg_len_bytes)[0]
        stream.seek(stream.tell() + seg_len - 2)

    # Now in scan entropy data, search for authentic FF D9
    while True:
        buf = stream.read(64 * 1024)
        if not buf:
            break

        i = 0
        while i < len(buf):
            ff_idx = buf.find(b"\xff", i)
            if ff_idx == -1:
                break
            if ff_idx + 1 < len(buf):
                next_byte = buf[ff_idx + 1]
                if next_byte == 0xD9:  # EOI found!
                    abs_pos = stream.tell() - len(buf) + ff_idx + 2
                    return abs_pos
                elif next_byte == 0x00 or (0xD0 <= next_byte <= 0xD7):
                    i = ff_idx + 2
                else:
                    i = ff_idx + 1
            else:
                # 0xFF is at end of buffer, seek back 1 byte to check next
                stream.seek(stream.tell() - 1)
                break

    # If stream ended without finding EOI, check tail 4KB fallback
    stream.seek(0, 2)
    total = stream.tell()
    scan_tail = min(total, 4096)
    stream.seek(total - scan_tail)
    tail_buf = stream.read(scan_tail)
    eoi_idx = tail_buf.rfind(JPEG_EOI)
    if eoi_idx != -1:
        return (total - scan_tail) + eoi_idx + 2

    raise CorruptedDataError("Authentic JPEG EOI marker not found")


class JpegAdapter(HostAdapter):
    """Adapter for JPEG images injecting after EOI boundary."""

    def format_name(self) -> str:
        return "JPEG"

    def detect(self, stream: BinaryIO) -> bool:
        start_pos = stream.tell()
        try:
            stream.seek(0)
            prefix = stream.read(3)
            return len(prefix) >= 3 and prefix[:2] == JPEG_SOI and prefix[2] == 0xFF
        finally:
            stream.seek(start_pos)

    def supported_strategies(self) -> List[str]:
        return ["eof"]

    def choose_auto_strategy(self, stream: BinaryIO, ube_size: int) -> str:
        return "eof"

    def inject(
        self,
        host_in: BinaryIO,
        ube_in: BinaryIO,
        out: BinaryIO,
        strategy: str,
    ) -> Tuple[int, int, int, int]:
        if strategy != "eof":
            raise UnsupportedFormatError(f"Strategy '{strategy}' not supported by JPEG adapter")

        eoi_end_offset = find_jpeg_eoi_offset(host_in)

        # 1. Write host up to EOI marker
        host_in.seek(0)
        remaining = eoi_end_offset
        while remaining > 0:
            buf = host_in.read(min(64 * 1024, remaining))
            out.write(buf)
            remaining -= len(buf)

        inject_offset = out.tell()

        # 2. Append UBE
        ube_in.seek(0)
        while True:
            buf = ube_in.read(64 * 1024)
            if not buf:
                break
            out.write(buf)

        inject_size = out.tell() - inject_offset

        # 3. Copy any trailing bytes after original EOI
        host_in.seek(eoi_end_offset)
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
        stego_in.seek(0)
        remaining = header.orig_host_size
        while remaining > 0:
            chunk = stego_in.read(min(64 * 1024, remaining))
            if not chunk:
                break
            out.write(chunk)
            remaining -= len(chunk)

    def verify_structure(self, stego_in: BinaryIO) -> Tuple[bool, str]:
        try:
            eoi_pos = find_jpeg_eoi_offset(stego_in)
            return True, f"JPEG structure verified (EOI marker found at {eoi_pos})"
        except CorruptedDataError as e:
            return False, str(e)
