"""Format sniffing and strategy routing module."""

from __future__ import annotations

from typing import BinaryIO, List, Optional

from strhide.adapters import ADAPTERS, HostAdapter
from strhide.errors import UnsupportedFormatError

STRATEGY_MAP = {
    "eof": 1,
    "chunk": 2,
    "box_uuid": 3,
    "pre_cd_inject": 4,
    "app_segment": 5,
    "incremental": 6,
    "pe_overlay": 7,
    "pe_codebits": 8,
}

REVERSE_STRATEGY_MAP = {v: k for k, v in STRATEGY_MAP.items()}


def strategy_to_id(strategy: str) -> int:
    return STRATEGY_MAP.get(strategy, 1)


def id_to_strategy(strat_id: int) -> str:
    return REVERSE_STRATEGY_MAP.get(strat_id, "eof")


def find_adapter(stream: BinaryIO) -> Optional[HostAdapter]:
    """Detect carrier format and return the matching HostAdapter.

    Returns ``None`` when the stream is not a supported format. There is no
    generic fallback: appending an envelope to an arbitrary file can corrupt
    it (trailing checksums, embedded offsets, signed containers, ...).
    """
    start_pos = stream.tell()
    try:
        for adapter in ADAPTERS:
            if adapter.detect(stream):
                return adapter
        return None
    finally:
        stream.seek(start_pos)


def find_adapter_or_reject(stream: BinaryIO, carrier_display: str) -> HostAdapter:
    """Like :func:`find_adapter`, but raises for unrecognized files.

    ``carrier_display`` is only used in the error message.
    """
    adapter = find_adapter(stream)
    if adapter is not None:
        return adapter

    # Best-effort magic hint: the first bytes make "why was my file rejected?"
    # answerable without a hex editor.
    start = stream.tell()
    hint = ""
    try:
        stream.seek(0)
        magic = stream.read(4)
        if len(magic) == 4:
            hint = " (file starts with " + " ".join(f"{b:02X}" for b in magic) + ")"
    except OSError:
        pass
    finally:
        stream.seek(start)

    supported = ", ".join(a.format_name() for a in ADAPTERS)
    raise UnsupportedFormatError(
        f"'{carrier_display}' is not a supported carrier format{hint}. Supported formats: "
        f"{supported}. strhide only modifies explicitly supported formats and refuses to "
        "alter unrecognized files."
    )


def list_all_strategies(stream: BinaryIO) -> List[str]:
    """Return list of supported strategies for the carrier stream.

    Kept for API compatibility; raises ``UnsupportedFormatError`` for an
    unrecognized carrier (previously it silently returned ``["eof"]`` via the
    generic fallback adapter).
    """
    adapter = find_adapter_or_reject(stream, "<stream>")
    return adapter.supported_strategies()
