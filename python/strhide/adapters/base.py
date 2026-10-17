"""Abstract base class for all file format host adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import BinaryIO, List, Optional, Tuple

from strhide.core.envelope import EnvelopeHeader


class HostAdapter(ABC):
    """Abstract interface for format-specific structural hiding adapters."""

    @abstractmethod
    def format_name(self) -> str:
        """Name of the format (e.g. 'PNG', 'MP4', 'ZIP', 'JPEG', 'GENERIC')."""
        pass

    @abstractmethod
    def detect(self, stream: BinaryIO) -> bool:
        """Detect whether stream matches this format."""
        pass

    @abstractmethod
    def supported_strategies(self) -> List[str]:
        """List of supported strategy identifiers for this format."""
        pass

    @abstractmethod
    def choose_auto_strategy(self, stream: BinaryIO, ube_size: int) -> str:
        """Choose the optimal strategy based on host features and payload size."""
        pass

    @abstractmethod
    def inject(
        self,
        host_in: BinaryIO,
        ube_in: BinaryIO,
        out: BinaryIO,
        strategy: str,
    ) -> Tuple[int, int, int, int]:
        """Inject UBE stream into host stream.
        
        Returns:
            (inject_offset, inject_size, patch_offset, orig_patch_val)
        """
        pass

    @abstractmethod
    def locate(
        self,
        stego_in: BinaryIO,
        expected_trailer_magic: Optional[bytes] = None,
    ) -> Optional[Tuple[int, int, str]]:
        """Locate UBE envelope within carrier stream.
        
        Returns:
            (ube_offset, ube_total_size, strategy_name) or None if not found.
        """
        pass

    @abstractmethod
    def strip(
        self,
        stego_in: BinaryIO,
        out: BinaryIO,
        header: EnvelopeHeader,
    ) -> None:
        """Remove injected data and restore host to 100% original binary state."""
        pass

    @abstractmethod
    def verify_structure(self, stego_in: BinaryIO) -> Tuple[bool, str]:
        """Verify host structure integrity after injection."""
        pass

    def suspicious_structures(self, stego_in: BinaryIO) -> list[str]:
        """Password-independent structural scan for containers that only a
        strhide envelope would produce (oversized private chunks, COM
        segments, uuid boxes, PE overlays). Stealth envelopes written with an
        unknown password are invisible to magic-based ``locate``; this
        heuristic lets the engine warn about a probable pre-existing envelope
        before a second injection stacks another one on top. Default: no
        opinion.
        """
        return []

    def open_ube_stream(
        self,
        carrier: BinaryIO,
        ube_offset: int,
        ube_total_size: int,
        strategy: str,
    ) -> BinaryIO:
        """Open a virtual SeekRead stream over the embedded UBE envelope data.
        
        For standard contiguous envelopes (PNG, ZIP, PDF, MP4, PE, EOF), this
        is simply a bounded slice starting at `ube_offset` of `ube_total_size` bytes.
        Format adapters with fragmented/chained segments (e.g. JPEG APPn/COM
        multi-segment chains) override this to provide a continuous virtual UBE
        stream that transparently bridges across segment boundaries.
        """
        return SubStream(carrier, ube_offset, ube_total_size)


class SubStream:
    """A zero-copy bounded slice of a binary stream implementing read/seek/tell."""

    def __init__(self, inner: BinaryIO, base_offset: int, total_size: int) -> None:
        self.inner = inner
        self.base_offset = base_offset
        self.total_size = total_size
        self.pos = 0
        inner.seek(base_offset)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if self.pos >= self.total_size or size == 0:
            return b""
        remaining = self.total_size - self.pos
        to_read = remaining if size < 0 else min(size, remaining)
        self.inner.seek(self.base_offset + self.pos)
        chunk = self.inner.read(to_read)
        self.pos += len(chunk)
        return chunk

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            new_pos = offset
        elif whence == 1:
            new_pos = self.pos + offset
        elif whence == 2:
            new_pos = self.total_size + offset
        else:
            raise ValueError(f"Invalid whence: {whence}")
        if new_pos < 0:
            raise ValueError("Invalid seek to negative position")
        self.pos = new_pos
        return self.pos

    def tell(self) -> int:
        return self.pos
