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
