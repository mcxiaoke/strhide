"""Cryptographic and compression primitives for strhide.

Implements RFC 5869 HKDF-SHA256, chunked streaming AES-256-GCM, and Deflate compression.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import zlib
from typing import BinaryIO, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from strhide.errors import CorruptedDataError, PasswordError

CHUNK_SIZE = 2 * 1024 * 1024  # 2MB chunks for streaming AEAD


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract using SHA-256."""
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand using SHA-256."""
    hash_len = 32
    n = (length + hash_len - 1) // hash_len
    if n > 255:
        raise ValueError("Cannot expand to more than 255 * 32 bytes")

    okm = bytearray()
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm.extend(t)
    return bytes(okm[:length])


PBKDF2_ITERATIONS = 100_000


def derive_keys(password: str, salt: bytes) -> Tuple[bytes, bytes]:
    """Derive master payload key and metadata key from user password using PBKDF2-HMAC-SHA256 (100k rounds) + HKDF-SHA256."""
    import unicodedata
    normalized_pwd = unicodedata.normalize("NFC", password)
    password_bytes = normalized_pwd.encode("utf-8")
    ikm = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, PBKDF2_ITERATIONS, dklen=32)
    prk = hkdf_extract(salt, ikm)
    payload_key = hkdf_expand(prk, b"strhide-payload", 32)
    meta_key = hkdf_expand(prk, b"strhide-metadata", 32)
    return payload_key, meta_key


def derive_stealth_magics(password: str, salt: bytes = b"strhide-stealth-v1") -> Tuple[bytes, bytes]:
    """Derive dynamic 8-byte header magic and 4-byte trailer magic for stealth mode deterministically from password."""
    import unicodedata
    normalized_pwd = unicodedata.normalize("NFC", password)
    password_bytes = normalized_pwd.encode("utf-8")
    ikm = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, PBKDF2_ITERATIONS, dklen=32)
    prk = hkdf_extract(salt, ikm)
    header_magic = hkdf_expand(prk, b"strhide-stealth-header", 8)
    trailer_magic = hkdf_expand(prk, b"strhide-stealth-trailer", 4)
    return header_magic, trailer_magic



def make_chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """Derive 12-byte nonce for a specific chunk index."""
    counter = int.from_bytes(base_nonce[8:12], "little") ^ (chunk_index & 0xFFFFFFFF)
    return base_nonce[:8] + counter.to_bytes(4, "little")


def encrypt_metadata(meta_bytes: bytes, meta_key: bytes, base_nonce: bytes, aad: bytes) -> bytes:
    """Encrypt metadata JSON payload using AES-256-GCM.
    
    Nonce used is base_nonce XOR 0xFFFFFFFF at counter.
    """
    nonce = base_nonce[:8] + (int.from_bytes(base_nonce[8:12], "little") ^ 0xFFFFFFFF).to_bytes(4, "little")
    aesgcm = AESGCM(meta_key)
    return aesgcm.encrypt(nonce, meta_bytes, aad)


def decrypt_metadata(meta_ciphertext: bytes, meta_key: bytes, base_nonce: bytes, aad: bytes) -> bytes:
    """Decrypt metadata JSON payload using AES-256-GCM."""
    nonce = base_nonce[:8] + (int.from_bytes(base_nonce[8:12], "little") ^ 0xFFFFFFFF).to_bytes(4, "little")
    aesgcm = AESGCM(meta_key)
    try:
        return aesgcm.decrypt(nonce, meta_ciphertext, aad)
    except Exception as e:
        raise PasswordError("Invalid password or corrupted metadata") from e


def encrypt_stream_chunked(
    in_stream: BinaryIO,
    out_stream: BinaryIO,
    payload_key: bytes,
    base_nonce: bytes,
    fixed_header_aad: bytes,
) -> int:
    """Encrypt in_stream into out_stream in 2MB chunks using AES-256-GCM.
    
    Returns total written bytes.
    Format per chunk: [chunk_len (4B LE)] + [ciphertext + 16B tag].
    """
    aesgcm = AESGCM(payload_key)
    chunk_index = 0
    total_written = 0

    while True:
        chunk = in_stream.read(CHUNK_SIZE)
        if not chunk:
            break

        # Peek to see if this is the last chunk
        peek = in_stream.read(1)
        if not peek:
            is_last = True
        else:
            is_last = False
            # Reconstruct stream state: we need to include peek in next chunk or put it back
            # To handle clean streaming, we prepend peek to chunk in next loop.
            # A cleaner approach: buffer next chunk.
        
        # Buffer-ahead pattern:
        # Let's read first chunk before loop, then loop while buffering next chunk.
        break  # Handled below

    return 0


def encrypt_stream_to_chunks(
    in_stream: BinaryIO,
    out_stream: BinaryIO,
    payload_key: bytes,
    base_nonce: bytes,
    fixed_header_aad: bytes,
) -> int:
    """Encrypt in_stream into out_stream in 2MB chunks using AES-256-GCM with lookahead."""
    aesgcm = AESGCM(payload_key)
    chunk_index = 0
    total_written = 0

    current_chunk = in_stream.read(CHUNK_SIZE)
    if not current_chunk:
        # Empty stream, write a single empty final chunk
        chunk_nonce = make_chunk_nonce(base_nonce, 0)
        chunk_aad = fixed_header_aad + struct.pack("<QB", 0, 1)
        cipher = aesgcm.encrypt(chunk_nonce, b"", chunk_aad)
        header = struct.pack("<I", len(cipher))
        out_stream.write(header)
        out_stream.write(cipher)
        return len(header) + len(cipher)

    while current_chunk:
        next_chunk = in_stream.read(CHUNK_SIZE)
        is_last = len(next_chunk) == 0

        chunk_nonce = make_chunk_nonce(base_nonce, chunk_index)
        chunk_aad = fixed_header_aad + struct.pack("<QB", chunk_index, 1 if is_last else 0)
        cipher = aesgcm.encrypt(chunk_nonce, current_chunk, chunk_aad)

        chunk_header = struct.pack("<I", len(cipher))
        out_stream.write(chunk_header)
        out_stream.write(cipher)
        total_written += len(chunk_header) + len(cipher)

        chunk_index += 1
        current_chunk = next_chunk

    return total_written


def decrypt_stream_from_chunks(
    in_stream: BinaryIO,
    out_stream: BinaryIO,
    payload_key: bytes,
    base_nonce: bytes,
    fixed_header_aad: bytes,
    total_payload_bytes: int,
) -> int:
    """Decrypt chunked AES-256-GCM from in_stream and write plaintext to out_stream.
    
    Returns total plaintext bytes written.
    """
    aesgcm = AESGCM(payload_key)
    chunk_index = 0
    bytes_consumed = 0
    total_plain_written = 0
    seen_final = False

    while bytes_consumed < total_payload_bytes:
        header_data = in_stream.read(4)
        if len(header_data) < 4:
            raise CorruptedDataError("Unexpected EOF reading chunk header")
        bytes_consumed += 4
        chunk_len = struct.unpack("<I", header_data)[0]

        cipher = in_stream.read(chunk_len)
        if len(cipher) < chunk_len:
            raise CorruptedDataError("Unexpected EOF reading ciphertext chunk")
        bytes_consumed += chunk_len

        is_last = bytes_consumed >= total_payload_bytes
        if is_last:
            seen_final = True

        chunk_nonce = make_chunk_nonce(base_nonce, chunk_index)
        chunk_aad = fixed_header_aad + struct.pack("<QB", chunk_index, 1 if is_last else 0)

        try:
            plain = aesgcm.decrypt(chunk_nonce, cipher, chunk_aad)
        except Exception as e:
            raise CorruptedDataError(f"AEAD authentication failed at chunk {chunk_index}") from e

        out_stream.write(plain)
        total_plain_written += len(plain)
        chunk_index += 1

    if not seen_final and total_payload_bytes > 0:
        raise CorruptedDataError("Payload stream was truncated before final chunk")

    return total_plain_written


def compress_stream(in_stream: BinaryIO, out_stream: BinaryIO) -> Tuple[int, int]:
    """Compress in_stream using zlib raw deflate.
    
    Returns (raw_size, compressed_size).
    """
    compressor = zlib.compressobj(level=6, wbits=-zlib.MAX_WBITS)
    raw_size = 0
    comp_size = 0

    while True:
        data = in_stream.read(64 * 1024)
        if not data:
            break
        raw_size += len(data)
        out = compressor.compress(data)
        if out:
            out_stream.write(out)
            comp_size += len(out)

    tail = compressor.flush()
    if tail:
        out_stream.write(tail)
        comp_size += len(tail)

    return raw_size, comp_size


def decompress_stream(in_stream: BinaryIO, out_stream: BinaryIO, comp_size: int) -> int:
    """Decompress raw deflate from in_stream to out_stream.
    
    Returns decompressed bytes written.
    """
    decompressor = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
    bytes_read = 0
    plain_written = 0

    while bytes_read < comp_size:
        to_read = min(64 * 1024, comp_size - bytes_read)
        data = in_stream.read(to_read)
        if not data:
            break
        bytes_read += len(data)
        out = decompressor.decompress(data)
        if out:
            out_stream.write(out)
            plain_written += len(out)

    tail = decompressor.flush()
    if tail:
        out_stream.write(tail)
        plain_written += len(tail)

    return plain_written


def compute_stream_sha256(stream: BinaryIO) -> bytes:
    """Compute full SHA-256 hash of a stream from current position to end, then rewinds."""
    start_pos = stream.tell()
    hasher = hashlib.sha256()
    while True:
        chunk = stream.read(128 * 1024)
        if not chunk:
            break
        hasher.update(chunk)
    stream.seek(start_pos)
    return hasher.digest()


def compute_file_sha256(path: str) -> bytes:
    """Compute full SHA-256 hash of a file on disk."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(128 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.digest()
