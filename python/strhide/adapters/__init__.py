"""Host adapters package for strhide."""

from strhide.adapters.base import HostAdapter
from strhide.adapters.eof import EofAdapter
from strhide.adapters.jpeg import JpegAdapter
from strhide.adapters.mp4 import Mp4Adapter
from strhide.adapters.pdf import PdfAdapter
from strhide.adapters.pe import PeAdapter
from strhide.adapters.png import PngAdapter
from strhide.adapters.zip import ZipAdapter

# Supported carrier formats, checked in order. EofAdapter is deliberately NOT
# registered: it remains the strategy provider that the format adapters use for
# their `eof` strategy, but it is no longer a format catch-all. Unrecognized
# files are rejected instead of being silently appended to, because appending
# an envelope to an arbitrary file can corrupt it.
ADAPTERS: list[HostAdapter] = [
    PngAdapter(),
    JpegAdapter(),
    Mp4Adapter(),
    ZipAdapter(),
    PdfAdapter(),
    PeAdapter(),
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

