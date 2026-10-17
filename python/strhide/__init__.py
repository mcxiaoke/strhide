"""strhide: Smart format-preserving lossless data hiding package.

Hide text or files inside ordinary host files (PNG, JPEG, MP4, ZIP, PDF,
Windows PE, or any file) without changing the host's visible format, and
restore the original host bit-for-bit afterwards. Fully cross-compatible
with the Rust implementation.

Typical usage::

    from strhide import write_carrier, read_carrier, inspect_carrier

    write_carrier("carrier.png", data_text="hello", password="pw")
    result = read_carrier("carrier.png", output_path="out.txt", password="pw")
    meta = inspect_carrier("carrier.png", password="pw")

All functions return a result dict and raise :class:`StrHideError`
subclasses on failure. See ``strhide.core.engine`` for the full keyword
reference of each function.
"""

from strhide.core.engine import (
    inspect_carrier,
    read_carrier,
    remove_carrier,
    sanitize_filename,
    verify_carrier,
    write_carrier,
)
from strhide.core.router import find_adapter, list_all_strategies
from strhide.errors import (
    CorruptedDataError,
    NoHiddenDataError,
    PasswordError,
    RejectionError,
    RestoreMismatchError,
    StrHideError,
    UnsupportedFormatError,
)

__version__ = "0.1.0"

__all__ = [
    # Engine operations
    "write_carrier",
    "read_carrier",
    "remove_carrier",
    "inspect_carrier",
    "verify_carrier",
    "sanitize_filename",
    # Routing helpers
    "find_adapter",
    "list_all_strategies",
    # Exceptions
    "StrHideError",
    "RejectionError",
    "CorruptedDataError",
    "PasswordError",
    "UnsupportedFormatError",
    "RestoreMismatchError",
    "NoHiddenDataError",
    "__version__",
]
