"""Host adapters package for strhide."""

from strhide.adapters.base import HostAdapter
from strhide.adapters.eof import EofAdapter
from strhide.adapters.jpeg import JpegAdapter
from strhide.adapters.mp4 import Mp4Adapter
from strhide.adapters.pdf import PdfAdapter
from strhide.adapters.pe import PeAdapter
from strhide.adapters.png import PngAdapter
from strhide.adapters.zip import ZipAdapter

# Specific adapters checked before generic fallback
ADAPTERS: list[HostAdapter] = [
    PngAdapter(),
    JpegAdapter(),
    Mp4Adapter(),
    ZipAdapter(),
    PdfAdapter(),
    PeAdapter(),
    EofAdapter(),
]

__all__ = [
    "HostAdapter",
    "PngAdapter",
    "JpegAdapter",
    "Mp4Adapter",
    "ZipAdapter",
    "PdfAdapter",
    "PeAdapter",
    "EofAdapter",
    "ADAPTERS",
]

