"""Unit tests for UBE envelope header and trailer serialization."""

import os
import pytest

from strhide.core.envelope import (
    STANDARD_HEADER_MAGIC,
    STANDARD_TRAILER_MAGIC,
    EnvelopeHeader,
    EnvelopeTrailer,
)
from strhide.errors import CorruptedDataError


def test_header_pack_unpack():
    hdr = EnvelopeHeader(
        magic_header=STANDARD_HEADER_MAGIC,
        version=2,
        flags=0x07,
        strategy_id=3,
        salt=os.urandom(16),
        base_nonce=os.urandom(12),
        orig_host_size=123456789,
        orig_host_sha256=os.urandom(32),
        inject_offset=98765,
        inject_size=54321,
        patch_offset=100,
        orig_patch_val=200,
        meta_len=512,
        hint_len=42,
    )
    packed = hdr.pack()
    assert len(packed) == 112

    restored = EnvelopeHeader.unpack(packed)
    assert restored.magic_header == hdr.magic_header
    assert restored.version == 2
    assert restored.flags == 0x07
    assert restored.strategy_id == 3
    assert restored.salt == hdr.salt
    assert restored.base_nonce == hdr.base_nonce
    assert restored.orig_host_size == 123456789
    assert restored.orig_host_sha256 == hdr.orig_host_sha256
    assert restored.inject_offset == 98765
    assert restored.inject_size == 54321
    assert restored.patch_offset == 100
    assert restored.orig_patch_val == 200
    assert restored.meta_len == 512
    assert restored.hint_len == 42


def test_trailer_pack_unpack():
    trailer = EnvelopeTrailer.create(ube_offset=1024, ube_total_size=8192)
    packed = trailer.pack()
    assert len(packed) == 24

    restored = EnvelopeTrailer.unpack(packed)
    assert restored.ube_offset == 1024
    assert restored.ube_total_size == 8192
    assert restored.trailer_magic == STANDARD_TRAILER_MAGIC


def test_trailer_crc_tamper_detection():
    trailer = EnvelopeTrailer.create(ube_offset=1024, ube_total_size=8192)
    packed = bytearray(trailer.pack())

    # Corrupt a byte in offset
    packed[0] ^= 0xFF
    with pytest.raises(CorruptedDataError):
        EnvelopeTrailer.unpack(bytes(packed))
