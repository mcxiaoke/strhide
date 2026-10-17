"""ZIP format adapter for strhide using pre-CD injection and EOCD CD Offset adjustment."""

from __future__ import annotations

import shutil
import struct
from typing import BinaryIO, List, Optional, Tuple

from strhide.adapters.base import HostAdapter
from strhide.core.envelope import EnvelopeHeader, EnvelopeTrailer, read_trailer_from_tail
from strhide.errors import CorruptedDataError, UnsupportedFormatError

ZIP_LOCAL_MAGIC = b"PK\x03\x04"
ZIP_EOCD_MAGIC = b"PK\x05\x06"
ZIP_SPAN_MAGIC = b"PK\x07\x08"
ZIP_KNOWN_MAGICS = (ZIP_LOCAL_MAGIC, ZIP_EOCD_MAGIC, ZIP_SPAN_MAGIC)
EOCD_SIGNATURE = 0x06054B50


def find_eocd_offset(stream: BinaryIO) -> Tuple[int, int, int]:
    """Find EOCD in stream by searching backward from EOF.

    Walks EOCD magic candidates from the end backwards in two passes and
    accepts the first self-consistent record (exact-EOF shape preferred,
    fits-inside shape as fallback). A naive rfind() can be fooled by comment
    bytes that happen to contain "PK\x05\x06", which would misplace the
    injection point and corrupt the archive.

    Returns (eocd_pos, cd_offset, cd_size).
    """
    stream.seek(0, 2)
    file_size = stream.tell()
    scan_len = min(file_size, 65536 + 22)
    stream.seek(file_size - scan_len)
    tail = stream.read(scan_len)

    # Walk EOCD magic candidates from the end backwards. A naive rfind() can
    # be fooled by comment bytes that happen to contain "PK\x05\x06", which
    # would misplace the injection point and corrupt the archive.
    # Two passes: first require the record to end exactly at EOF (the shape of
    # a clean archive); if none qualifies, accept a record that merely fits
    # inside the file (the shape left by an EOF-strategy envelope appended
    # past the EOCD). Both passes additionally require the declared central
    # directory to lie before the record.
    for require_exact_eof in (True, False):
        search_end = len(tail)
        while search_end >= 4:
            idx = tail.rfind(ZIP_EOCD_MAGIC, 0, search_end)
            if idx == -1:
                break
            eocd_pos = (file_size - scan_len) + idx

            if idx + 22 <= len(tail):
                comment_len = struct.unpack_from("<H", tail, idx + 20)[0]
                record_end = eocd_pos + 22 + comment_len
                fits = (record_end == file_size) if require_exact_eof else (record_end <= file_size)
                if fits:
                    # Central directory must lie before the EOCD record.
                    cd_size, cd_offset = struct.unpack_from("<II", tail, idx + 12)
                    if cd_offset + cd_size <= eocd_pos or (cd_offset == 0 and cd_size == 0):
                        return eocd_pos, cd_offset, cd_size
            search_end = idx

    raise CorruptedDataError("Valid ZIP EOCD (End of Central Directory) record not found")


class ZipAdapter(HostAdapter):
    """Adapter for ZIP archives injecting UBE before Central Directory and adjusting EOCD."""

    def format_name(self) -> str:
        return "ZIP"

    def detect(self, stream: BinaryIO) -> bool:
        start_pos = stream.tell()
        try:
            stream.seek(0)
            prefix = stream.read(4)
            return prefix in ZIP_KNOWN_MAGICS
        finally:
            stream.seek(start_pos)

    def supported_strategies(self) -> List[str]:
        return ["pre_cd_inject", "eof"]

    def choose_auto_strategy(self, stream: BinaryIO, ube_size: int) -> str:
        # Best-effort: check if EOCD is valid and 32-bit CD offset won't overflow
        try:
            eocd_pos, cd_offset, _ = find_eocd_offset(stream)
            # The EOCD cd_offset field AND the patch position
            # (eocd_pos + 16, shifted by ube_size) must both stay inside
            # the 32-bit range, otherwise removal would restore a
            # truncated offset.
            patch_limit = max(cd_offset, eocd_pos + 16)
            if patch_limit + ube_size >= 0xFFFFFFFF:
                return "eof"
            return "pre_cd_inject"
        except Exception:
            return "eof"

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

        if strategy != "pre_cd_inject":
            raise UnsupportedFormatError(f"Strategy '{strategy}' not supported by ZIP adapter")

        try:
            eocd_pos, cd_offset, cd_size = find_eocd_offset(host_in)
        except Exception as e:
            raise UnsupportedFormatError(
                f"Cannot use 'pre_cd_inject' strategy: {e}. Please use --strategy eof."
            )

        ube_in.seek(0, 2)
        ube_size = ube_in.tell()
        ube_in.seek(0)

        # Both the adjusted cd_offset and the patch position
        # (eocd_pos + 16 + ube_size) must fit in uint32.
        patch_limit = max(cd_offset, eocd_pos + 16)
        if patch_limit + ube_size >= 0xFFFFFFFF:
            raise UnsupportedFormatError(
                f"Central directory or EOCD patch offset overflow (>4GB) for standard ZIP. "
                f"Please use --strategy eof."
            )

        # 1. Write everything before Central Directory [0 : cd_offset]
        host_in.seek(0)
        remaining = cd_offset
        while remaining > 0:
            buf = host_in.read(min(64 * 1024, remaining))
            out.write(buf)
            remaining -= len(buf)

        inject_offset = out.tell()

        # 2. Write UBE envelope
        shutil.copyfileobj(ube_in, out)
        inject_size = out.tell() - inject_offset

        # 3. Write Central Directory [cd_offset : eocd_pos]
        host_in.seek(cd_offset)
        remaining = eocd_pos - cd_offset
        while remaining > 0:
            buf = host_in.read(min(64 * 1024, remaining))
            out.write(buf)
            remaining -= len(buf)

        # 4. Write EOCD with adjusted cd_offset
        new_eocd_pos = out.tell()
        host_in.seek(eocd_pos)
        eocd_prefix = host_in.read(16)  # up to cd_offset field
        out.write(eocd_prefix)

        patch_offset = out.tell()
        orig_patch_val = cd_offset
        new_cd_offset = cd_offset + inject_size
        out.write(struct.pack("<I", new_cd_offset))

        # Skip cd_offset in host_in and copy comment length + comment
        host_in.seek(eocd_pos + 20)
        shutil.copyfileobj(host_in, out)

        return inject_offset, inject_size, patch_offset, orig_patch_val

    def locate(
        self,
        stego_in: BinaryIO,
        expected_trailer_magic: Optional[bytes] = None,
    ) -> Optional[Tuple[int, int, str]]:
        try:
            eocd_pos, cd_offset, cd_size = find_eocd_offset(stego_in)
        except CorruptedDataError:
            eocd_pos = cd_offset = cd_size = None

        # In pre_cd_inject, UBE is located immediately before Central Directory.
        # So the last 24 bytes of UBE are at [cd_offset - 24 : cd_offset].
        if cd_offset is not None and cd_offset >= 24:
            stego_in.seek(cd_offset - 24)
            tail_bytes = stego_in.read(24)
            try:
                trailer = EnvelopeTrailer.unpack(tail_bytes, expected_magic=expected_trailer_magic)
                if trailer.ube_offset + trailer.ube_total_size == cd_offset:
                    return trailer.ube_offset, trailer.ube_total_size, "pre_cd_inject"
            except CorruptedDataError:
                pass

        # Fallback to EOF trailer
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

        # Cut out [inject_offset : inject_offset + inject_size]
        stego_in.seek(0)
        remaining = header.inject_offset
        while remaining > 0:
            buf = stego_in.read(min(64 * 1024, remaining))
            out.write(buf)
            remaining -= len(buf)

        # Copy Central Directory and EOCD up to patch_offset
        # Note: In the restored stream, the patch field will be at:
        # header.patch_offset - header.inject_size
        stego_in.seek(header.inject_offset + header.inject_size)
        bytes_before_patch = header.patch_offset - (header.inject_offset + header.inject_size)
        while bytes_before_patch > 0:
            buf = stego_in.read(min(64 * 1024, bytes_before_patch))
            out.write(buf)
            bytes_before_patch -= len(buf)

        # Write original patch value (original cd_offset)
        out.write(struct.pack("<I", header.orig_patch_val))

        # Skip the modified patch field in stego_in (4 bytes)
        stego_in.seek(header.patch_offset + 4)
        # Copy remaining EOCD bytes (comment len + comment)
        while True:
            buf = stego_in.read(64 * 1024)
            if not buf:
                break
            out.write(buf)

    def verify_structure(self, stego_in: BinaryIO) -> Tuple[bool, str]:
        try:
            eocd_pos, cd_offset, cd_size = find_eocd_offset(stego_in)
        except CorruptedDataError as e:
            return False, str(e)

        stego_in.seek(cd_offset)
        cd_sig = stego_in.read(4)
        if cd_sig != b"PK\x01\x02":
            return False, f"Invalid Central Directory signature at offset {cd_offset}: {cd_sig!r}"

        return True, f"ZIP archive structure valid (Central Directory verified at {cd_offset})"
