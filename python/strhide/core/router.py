"""Format sniffing and strategy routing module."""

from __future__ import annotations

from typing import BinaryIO, List

from strhide.adapters import ADAPTERS, HostAdapter

STRATEGY_MAP = {
    "eof": 1,
    "chunk": 2,
    "box_uuid": 3,
    "pre_cd_inject": 4,
    "app_segment": 5,
    "incremental": 6,
}

REVERSE_STRATEGY_MAP = {v: k for k, v in STRATEGY_MAP.items()}


def strategy_to_id(strategy: str) -> int:
    return STRATEGY_MAP.get(strategy, 1)


def id_to_strategy(strat_id: int) -> str:
    return REVERSE_STRATEGY_MAP.get(strat_id, "eof")


def find_adapter(stream: BinaryIO) -> HostAdapter:
    """Detect carrier format and return the matching HostAdapter."""
    start_pos = stream.tell()
    try:
        for adapter in ADAPTERS:
            if adapter.detect(stream):
                return adapter
        # Fallback to EofAdapter if none matches
        return ADAPTERS[-1]
    finally:
        stream.seek(start_pos)


def list_all_strategies(stream: BinaryIO) -> List[str]:
    """Return list of supported strategies for the carrier stream."""
    adapter = find_adapter(stream)
    return adapter.supported_strategies()
