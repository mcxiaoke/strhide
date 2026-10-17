"""JPEG format adapter for strhide with APP15/COM segment multi-chain hiding."""

from __future__ import annotations

import struct
from typing import BinaryIO, List, Optional, Tuple

from strhide.adapters.base import HostAdapter, SubStream
from strhide.core.envelope import EnvelopeHeader, EnvelopeTrailer, read_trailer_from_tail
from strhide.errors import CorruptedDataError, UnsupportedFormatError

JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"
JPEG_SOS = b"\xff\xda"
JPEG_APP15 = b"\xff\xef"
JPEG_COM = b"\xff\xfe"
JPEG_MAX_SEG_PAYLOAD = 65533  # 65535 - 2 bytes length
JPEG_MAX_TOTAL_CAPACITY = 64 * 1024 * 1024  # 64MB


def find_jpeg_sos_offset(stream: BinaryIO) -> int:
    """Scan JPEG markers from SOI until SOS (0xFF 0xDA).
    
    Returns the byte offset immediately preceding SOS marker where APPn/COM segments can be inserted.
    """
    stream.seek(0)
    soi = stream.read(2)
    if soi != JPEG_SOI:
        raise CorruptedDataError("Invalid JPEG SOI marker")

    while True:
        marker_start = stream.tell()
        lead = stream.read(1)
        if not lead:
            break
        if lead != b"\xff":
            continue

        code = stream.read(1)
        while code == b"\xff":  # Handle multiple 0xFF padding bytes
            code = stream.read(1)
        if not code:
            break

        b = code[0]
        # Standalone markers without length: SOI, EOI, RSTm, TEM
        if b in (0xD8, 0xD9, 0x01) or (0xD0 <= b <= 0xD7):
            continue

        if b == 0xDA:  # SOS (Start of Scan)
            return marker_start

        len_bytes = stream.read(2)
        if len(len_bytes) < 2:
            break
        seg_len = struct.unpack(">H", len_bytes)[0]
        if seg_len < 2:
            raise CorruptedDataError(f"Invalid JPEG segment length: {seg_len}")
        stream.seek(stream.tell() + seg_len - 2)

    raise CorruptedDataError("JPEG SOS (Start of Scan) marker not found")


def find_jpeg_eoi_offset(stream: BinaryIO) -> int:
    """Scan JPEG marker chain past SOS to find authentic EOI (0xFF 0xD9) offset."""
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

        if marker_code in (b"\xd8", b"\xd9"):  # SOI, EOI
            continue
        if 0xD0 <= marker_code[0] <= 0xD7:  # RSTm
            continue

        if marker_code == b"\xda":  # SOS (Start of Scan)
            sos_len_bytes = stream.read(2)
            if len(sos_len_bytes) < 2:
                raise CorruptedDataError("Truncated SOS segment header")
            sos_len = struct.unpack(">H", sos_len_bytes)[0]
            stream.seek(stream.tell() + sos_len - 2)
            break

        seg_len_bytes = stream.read(2)
        if len(seg_len_bytes) < 2:
            break
        seg_len = struct.unpack(">H", seg_len_bytes)[0]
        stream.seek(stream.tell() + seg_len - 2)

    # In scan entropy data, search for authentic FF D9
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
                stream.seek(stream.tell() - 1)
                break

    stream.seek(0, 2)
    total = stream.tell()
    scan_tail = min(total, 4096)
    stream.seek(total - scan_tail)
    tail_buf = stream.read(scan_tail)
    eoi_idx = tail_buf.rfind(JPEG_EOI)
    if eoi_idx != -1:
        return (total - scan_tail) + eoi_idx + 2

    raise CorruptedDataError("Authentic JPEG EOI marker not found")


def partition_jpeg_payload_lengths(total_size: int) -> list[int]:
    """Compute segment payload lengths such that each segment <= 65533 bytes
    and the final segment is always >= 24 bytes (to safely contain EnvelopeTrailer).
    """
    if total_size <= JPEG_MAX_SEG_PAYLOAD:
        return [total_size]
    lengths: list[int] = []
    rem_total = total_size
    while rem_total > 0:
        if rem_total <= JPEG_MAX_SEG_PAYLOAD:
            lengths.append(rem_total)
            break
        rem = rem_total - JPEG_MAX_SEG_PAYLOAD
        if rem < 24:
            borrow = min(1024, JPEG_MAX_SEG_PAYLOAD - 24)
            lengths.append(JPEG_MAX_SEG_PAYLOAD - borrow)
            lengths.append(rem + borrow)
            break
        else:
            lengths.append(JPEG_MAX_SEG_PAYLOAD)
            rem_total -= JPEG_MAX_SEG_PAYLOAD
    return lengths


class JpegChainedSegmentStream:
    """A SeekRead stream bridging across a chained sequence of JPEG segment bodies."""

    def __init__(self, inner: BinaryIO, segments: list[tuple[int, int]], total_size: int) -> None:
        self.inner = inner
        self.segments = segments  # [(payload_offset, payload_len), ...]
        self.total_size = total_size
        self.logical_pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if self.logical_pos >= self.total_size or size == 0:
            return b""
        total_remaining = self.total_size - self.logical_pos
        to_read_total = total_remaining if size < 0 else min(size, total_remaining)

        out_chunks: list[bytes] = []
        bytes_read = 0

        while bytes_read < to_read_total:
            # Find current segment
            rem = self.logical_pos
            target_seg = None
            for seg_start, seg_len in self.segments:
                if rem < seg_len:
                    target_seg = (seg_start, seg_len, rem)
                    break
                rem -= seg_len

            if not target_seg:
                break

            seg_start, seg_len, offset_in_seg = target_seg
            seg_rem = seg_len - offset_in_seg
            chunk_to_read = min(to_read_total - bytes_read, seg_rem)

            self.inner.seek(seg_start + offset_in_seg)
            chunk = self.inner.read(chunk_to_read)
            if not chunk:
                break
            out_chunks.append(chunk)
            bytes_read += len(chunk)
            self.logical_pos += len(chunk)

        return b"".join(out_chunks)

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            new_pos = offset
        elif whence == 1:
            new_pos = self.logical_pos + offset
        elif whence == 2:
            new_pos = self.total_size + offset
        else:
            raise ValueError(f"Invalid whence: {whence}")
        if new_pos < 0:
            raise ValueError("Invalid seek to negative position")
        self.logical_pos = new_pos
        return self.logical_pos

    def tell(self) -> int:
        return self.logical_pos


class JpegAdapter(HostAdapter):
    """Adapter for JPEG images supporting APP15/COM multi-segment chains and EOF fallback."""

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
        return ["app_segment", "eof"]

    def choose_auto_strategy(self, stream: BinaryIO, ube_size: int) -> str:
        if ube_size <= JPEG_MAX_TOTAL_CAPACITY:
            return "app_segment"
        return "eof"

    def inject(
        self,
        host_in: BinaryIO,
        ube_in: BinaryIO,
        out: BinaryIO,
        strategy: str,
    ) -> Tuple[int, int, int, int]:
        if strategy == "app_segment":
            ube_in.seek(0, 2)
            ube_size = ube_in.tell()
            ube_in.seek(0)
            if ube_size > JPEG_MAX_TOTAL_CAPACITY:
                raise UnsupportedFormatError(
                    f"Payload envelope size ({ube_size} bytes) exceeds JPEG chain capacity "
                    f"({JPEG_MAX_TOTAL_CAPACITY} bytes). Please specify --strategy eof."
                )

            sos_offset = find_jpeg_sos_offset(host_in)

            # 1. Write host up to SOS offset
            host_in.seek(0)
            remaining = sos_offset
            while remaining > 0:
                buf = host_in.read(min(64 * 1024, remaining))
                out.write(buf)
                remaining -= len(buf)

            inject_offset = out.tell()

            # 2. Write multi-segment APP15 chain using safe length partitioning
            seg_lengths = partition_jpeg_payload_lengths(ube_size)
            inject_size = 0

            for seg_payload_len in seg_lengths:
                seg_hdr = JPEG_APP15 + struct.pack(">H", 2 + seg_payload_len)
                out.write(seg_hdr)
                inject_size += 4 + seg_payload_len

                seg_remaining = seg_payload_len
                while seg_remaining > 0:
                    buf = ube_in.read(min(64 * 1024, seg_remaining))
                    if not buf:
                        raise CorruptedDataError("Unexpected end of UBE input stream")
                    out.write(buf)
                    seg_remaining -= len(buf)

            # 3. Write rest of host (from SOS onwards through EOI)
            host_in.seek(sos_offset)
            while True:
                buf = host_in.read(64 * 1024)
                if not buf:
                    break
                out.write(buf)

            return inject_offset, inject_size, 0, 0

        elif strategy == "eof":
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

        else:
            raise UnsupportedFormatError(f"Strategy '{strategy}' not supported by JPEG adapter")

    def locate(
        self,
        stego_in: BinaryIO,
        expected_trailer_magic: Optional[bytes] = None,
    ) -> Optional[Tuple[int, int, str]]:
        stego_in.seek(0)
        soi = stego_in.read(2)
        if soi != JPEG_SOI:
            return None

        # 1. Scan markers before SOS, collecting candidate segments for APP15 and COM
        app15_segments: list[tuple[int, int]] = []
        com_segments: list[tuple[int, int]] = []

        while True:
            lead = stego_in.read(1)
            if not lead:
                break
            if lead != b"\xff":
                continue

            code = stego_in.read(1)
            while code == b"\xff":
                code = stego_in.read(1)
            if not code:
                break

            b = code[0]
            if b in (0xD8, 0xD9, 0x01) or (0xD0 <= b <= 0xD7):
                continue
            if b == 0xDA:  # Reached SOS
                break

            len_bytes = stego_in.read(2)
            if len(len_bytes) < 2:
                break
            seg_len = struct.unpack(">H", len_bytes)[0]
            if seg_len < 2:
                break

            payload_len = seg_len - 2
            payload_offset = stego_in.tell()

            if b == 0xEF:
                app15_segments.append((payload_offset, payload_len))
            elif b == 0xFE:
                com_segments.append((payload_offset, payload_len))

            stego_in.seek(payload_offset + payload_len)

        # Helper to check a chain of candidate segments
        def try_locate_chain(segments: list[tuple[int, int]]) -> Optional[Tuple[int, int, str]]:
            for k in range(len(segments) - 1, -1, -1):
                seg_payload_offset, seg_payload_len = segments[k]
                if seg_payload_len < 24:
                    continue
                trailer_offset = seg_payload_offset + seg_payload_len - 24
                stego_in.seek(trailer_offset)
                trailer_bytes = stego_in.read(24)
                try:
                    trailer = EnvelopeTrailer.unpack(trailer_bytes, expected_magic=expected_trailer_magic)
                    if expected_trailer_magic is None:
                        from strhide.core.envelope import STANDARD_TRAILER_MAGIC
                        if trailer.trailer_magic != STANDARD_TRAILER_MAGIC:
                            continue
                except Exception:
                    continue

                # Single segment match
                if trailer.ube_offset == seg_payload_offset and trailer.ube_total_size == seg_payload_len:
                    return trailer.ube_offset, trailer.ube_total_size, "app_segment"

                # Multi-segment chain match: trace backwards from segment k
                if trailer.ube_total_size > seg_payload_len:
                    accum_len = 0
                    start_idx = None
                    for m in range(k, -1, -1):
                        curr_off, curr_len = segments[m]
                        if m < k:
                            next_off, _ = segments[m + 1]
                            if curr_off + curr_len != next_off - 4:
                                break
                        accum_len += curr_len
                        if accum_len == trailer.ube_total_size:
                            if curr_off == trailer.ube_offset:
                                start_idx = m
                            break
                        elif accum_len > trailer.ube_total_size:
                            break

                    if start_idx is not None:
                        return trailer.ube_offset, trailer.ube_total_size, "app_segment"

            return None

        # 2. Priority check: APP15 multi-segment chain
        loc = try_locate_chain(app15_segments)
        if loc:
            return loc

        # 3. Fallback check: Legacy COM segment chain
        loc = try_locate_chain(com_segments)
        if loc:
            return loc

        # 4. Fallback check: EOF trailer
        trailer = read_trailer_from_tail(stego_in, expected_magic=expected_trailer_magic)
        if trailer:
            return trailer.ube_offset, trailer.ube_total_size, "eof"

        return None

    def open_ube_stream(
        self,
        carrier: BinaryIO,
        ube_offset: int,
        ube_total_size: int,
        strategy: str,
    ) -> BinaryIO:
        if strategy == "eof" or ube_total_size <= JPEG_MAX_SEG_PAYLOAD:
            return SubStream(carrier, ube_offset, ube_total_size)

        seg_lengths = partition_jpeg_payload_lengths(ube_total_size)
        segments: list[tuple[int, int]] = []
        curr_offset = ube_offset

        for seg_len in seg_lengths:
            segments.append((curr_offset, seg_len))
            curr_offset += seg_len + 4

        return JpegChainedSegmentStream(carrier, segments, ube_total_size)

    def strip(
        self,
        stego_in: BinaryIO,
        out: BinaryIO,
        header: EnvelopeHeader,
    ) -> None:
        if header.strategy_id == 1:  # EOF
            stego_in.seek(0)
            remaining = header.orig_host_size
            while remaining > 0:
                chunk = stego_in.read(min(64 * 1024, remaining))
                if not chunk:
                    break
                out.write(chunk)
                remaining -= len(chunk)
            return

        # Strategy 5 (app_segment) or other intermediate insertion:
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
        try:
            sos_pos = find_jpeg_sos_offset(stego_in)
            return True, f"Valid JPEG image (SOS marker at offset {sos_pos})"
        except CorruptedDataError as e:
            return False, str(e)

    def suspicious_structures(self, stego_in: BinaryIO) -> list[str]:
        min_envelope = 112 + 24
        found: list[str] = []
        stego_in.seek(0)
        soi = stego_in.read(2)
        if soi != JPEG_SOI:
            return found

        while True:
            lead = stego_in.read(1)
            if not lead:
                break
            if lead != b"\xff":
                continue

            code = stego_in.read(1)
            while code == b"\xff":
                code = stego_in.read(1)
            if not code:
                break

            b = code[0]
            if b in (0xD8, 0xD9, 0x01) or (0xD0 <= b <= 0xD7):
                continue
            if b == 0xDA:  # Reached SOS
                break

            len_bytes = stego_in.read(2)
            if len(len_bytes) < 2:
                break
            seg_len = struct.unpack(">H", len_bytes)[0]
            if seg_len < 2:
                break

            payload_offset = stego_in.tell()
            payload_len = seg_len - 2

            if (b == 0xEF or b == 0xFE) and payload_len >= min_envelope:
                seg_name = "APP15" if b == 0xEF else "COM"
                found.append(
                    f"{seg_name} segment at offset {payload_offset} carries {payload_len} bytes "
                    f"(minimum envelope size is {min_envelope})"
                )

            stego_in.seek(payload_offset + payload_len)

        return found
