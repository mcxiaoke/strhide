"""Binary envelope structures and serialization for strhide UBE v2.1.

Fixed Header (108 Bytes) + Metadata Block + Payload Stream + Locator Trailer (24 Bytes).
The first 80 bytes of Fixed Header serve as the immutable AAD for AES-256-GCM.
"""

from __future__ import annotations

import dataclasses
import struct
import zlib
from typing import BinaryIO, Optional, Tuple

from strhide.errors import CorruptedDataError

STANDARD_HEADER_MAGIC = b"\x89STRHIDE"
STANDARD_TRAILER_MAGIC = b"STH!"
CURRENT_VERSION = 0x02

# Flags bitmasks
FLAG_ENCRYPTED = 0x01
FLAG_COMPRESSED = 0x02
FLAG_IS_FILE = 0x04
FLAG_STEALTH = 0x08
FLAG_HAS_HINT = 0x10

# AAD is the first 80 bytes of the fixed header
AAD_STRUCT = struct.Struct("<8sBBBB16s12sQ32s")
HEADER_STRUCT = struct.Struct("<8sBBBB16s12sQ32sQQIIII")
TRAILER_STRUCT = struct.Struct("<QQI4s")

assert AAD_STRUCT.size == 80, f"AAD size mismatch: {AAD_STRUCT.size} != 80"
assert HEADER_STRUCT.size == 112, f"Header size mismatch: {HEADER_STRUCT.size} != 112"
assert TRAILER_STRUCT.size == 24, f"Trailer size mismatch: {TRAILER_STRUCT.size} != 24"


@dataclasses.dataclass
class EnvelopeHeader:
    """Fixed 112-byte UBE v2.2 Header."""
    magic_header: bytes = STANDARD_HEADER_MAGIC
    version: int = CURRENT_VERSION
    flags: int = 0
    strategy_id: int = 1
    reserved: int = 0
    salt: bytes = b"\x00" * 16
    base_nonce: bytes = b"\x00" * 12
    orig_host_size: int = 0
    orig_host_sha256: bytes = b"\x00" * 32
    inject_offset: int = 0
    inject_size: int = 0
    patch_offset: int = 0
    orig_patch_val: int = 0
    meta_len: int = 0
    hint_len: int = 0

    @property
    def is_encrypted(self) -> bool:
        return bool(self.flags & FLAG_ENCRYPTED)

    @property
    def is_compressed(self) -> bool:
        return bool(self.flags & FLAG_COMPRESSED)

    @property
    def is_file(self) -> bool:
        return bool(self.flags & FLAG_IS_FILE)

    @property
    def is_stealth(self) -> bool:
        return bool(self.flags & FLAG_STEALTH)

    @property
    def has_hint(self) -> bool:
        return bool(self.flags & FLAG_HAS_HINT)

    def get_aad(self) -> bytes:
        """Return the immutable 80-byte AAD binding header fields for AEAD."""
        return AAD_STRUCT.pack(
            self.magic_header,
            self.version,
            self.flags,
            self.strategy_id,
            self.reserved,
            self.salt,
            self.base_nonce,
            self.orig_host_size,
            self.orig_host_sha256,
        )

    def pack(self) -> bytes:
        """Pack fixed header into 112 bytes."""
        return HEADER_STRUCT.pack(
            self.magic_header,
            self.version,
            self.flags,
            self.strategy_id,
            self.reserved,
            self.salt,
            self.base_nonce,
            self.orig_host_size,
            self.orig_host_sha256,
            self.inject_offset,
            self.inject_size,
            self.patch_offset,
            self.orig_patch_val,
            self.meta_len,
            self.hint_len,
        )

    @classmethod
    def unpack(cls, data: bytes) -> EnvelopeHeader:
        """Unpack 112-byte fixed header."""
        if len(data) < HEADER_STRUCT.size:
            raise CorruptedDataError(f"Insufficient bytes for header: {len(data)} < {HEADER_STRUCT.size}")
        unpacked = HEADER_STRUCT.unpack(data[:HEADER_STRUCT.size])
        return cls(
            magic_header=unpacked[0],
            version=unpacked[1],
            flags=unpacked[2],
            strategy_id=unpacked[3],
            reserved=unpacked[4],
            salt=unpacked[5],
            base_nonce=unpacked[6],
            orig_host_size=unpacked[7],
            orig_host_sha256=unpacked[8],
            inject_offset=unpacked[9],
            inject_size=unpacked[10],
            patch_offset=unpacked[11],
            orig_patch_val=unpacked[12],
            meta_len=unpacked[13],
            hint_len=unpacked[14],
        )


@dataclasses.dataclass
class EnvelopeTrailer:
    """Fixed 24-byte Universal Locator Trailer."""
    ube_offset: int
    ube_total_size: int
    trailer_crc32: int
    trailer_magic: bytes = STANDARD_TRAILER_MAGIC

    @classmethod
    def create(cls, ube_offset: int, ube_total_size: int, trailer_magic: bytes = STANDARD_TRAILER_MAGIC) -> EnvelopeTrailer:
        """Create a new trailer with calculated CRC32."""
        raw_prefix = struct.pack("<QQ", ube_offset, ube_total_size)
        crc = zlib.crc32(raw_prefix) & 0xFFFFFFFF
        return cls(
            ube_offset=ube_offset,
            ube_total_size=ube_total_size,
            trailer_crc32=crc,
            trailer_magic=trailer_magic,
        )

    def pack(self) -> bytes:
        """Pack trailer into 24 bytes."""
        return TRAILER_STRUCT.pack(
            self.ube_offset,
            self.ube_total_size,
            self.trailer_crc32,
            self.trailer_magic,
        )

    @classmethod
    def unpack(cls, data: bytes, expected_magic: Optional[bytes] = None) -> EnvelopeTrailer:
        """Unpack and verify trailer CRC32."""
        if len(data) < TRAILER_STRUCT.size:
            raise CorruptedDataError(f"Insufficient bytes for trailer: {len(data)} < {TRAILER_STRUCT.size}")
        unpacked = TRAILER_STRUCT.unpack(data[:TRAILER_STRUCT.size])
        ube_offset, ube_total_size, trailer_crc32, trailer_magic = unpacked

        if expected_magic is not None and trailer_magic != expected_magic:
            raise CorruptedDataError(f"Trailer magic mismatch: {trailer_magic} != {expected_magic}")
        elif expected_magic is None and trailer_magic != STANDARD_TRAILER_MAGIC:
            raise CorruptedDataError(f"Trailer magic mismatch: {trailer_magic} != {STANDARD_TRAILER_MAGIC}")

        raw_prefix = struct.pack("<QQ", ube_offset, ube_total_size)
        expected_crc = zlib.crc32(raw_prefix) & 0xFFFFFFFF
        if trailer_crc32 != expected_crc:
            raise CorruptedDataError(f"Trailer CRC32 mismatch: {trailer_crc32:#x} != {expected_crc:#x}")

        return cls(
            ube_offset=ube_offset,
            ube_total_size=ube_total_size,
            trailer_crc32=trailer_crc32,
            trailer_magic=trailer_magic,
        )


def read_trailer_from_tail(stream: BinaryIO, expected_magic: Optional[bytes] = None) -> Optional[EnvelopeTrailer]:
    """Seek to the last 24 bytes of stream and attempt to parse Universal Locator Trailer."""
    stream.seek(0, 2)
    file_size = stream.tell()
    if file_size < TRAILER_STRUCT.size:
        return None

    stream.seek(file_size - TRAILER_STRUCT.size)
    tail_bytes = stream.read(TRAILER_STRUCT.size)
    try:
        return EnvelopeTrailer.unpack(tail_bytes, expected_magic=expected_magic)
    except CorruptedDataError:
        return None
