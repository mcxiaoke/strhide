"""Generic EOF append adapter for strhide."""

from __future__ import annotations

import shutil
from typing import BinaryIO, List, Optional, Tuple

from strhide.adapters.base import HostAdapter
from strhide.core.envelope import EnvelopeHeader, read_trailer_from_tail
from strhide.errors import UnsupportedFormatError


class EofAdapter(HostAdapter):
    """Generic fallback adapter that appends UBE to the end of the file."""

    def format_name(self) -> str:
        return "GENERIC"

    def detect(self, stream: BinaryIO) -> bool:
        # Fallback adapter, always returns True if no other matches
        return True

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
            raise UnsupportedFormatError(f"Strategy '{strategy}' not supported by EOF adapter")

        host_in.seek(0)
        shutil.copyfileobj(host_in, out)
        inject_offset = out.tell()

        ube_in.seek(0)
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
        stego_in.seek(0, 2)
        total_size = stego_in.tell()
        trailer = read_trailer_from_tail(stego_in)
        if not trailer:
            return False, "Locator trailer not found at end of file"
        if trailer.ube_offset + trailer.ube_total_size != total_size:
            return False, f"Trailer boundary mismatch: offset({trailer.ube_offset}) + size({trailer.ube_total_size}) != total({total_size})"
        return True, "EOF envelope structure verified successfully"
