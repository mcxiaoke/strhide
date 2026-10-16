"""Unit tests for cryptographic primitives."""

import io
import os
import pytest

from strhide.core.crypto import (
    compress_stream,
    decompress_stream,
    decrypt_metadata,
    decrypt_stream_from_chunks,
    derive_keys,
    derive_stealth_magics,
    encrypt_metadata,
    encrypt_stream_to_chunks,
    hkdf_expand,
    hkdf_extract,
)
from strhide.errors import CorruptedDataError, PasswordError


def test_hkdf_rfc5869():
    salt = b"test-salt-12345"
    ikm = b"super-secret-password"
    prk = hkdf_extract(salt, ikm)
    assert len(prk) == 32

    okm1 = hkdf_expand(prk, b"info1", 32)
    okm2 = hkdf_expand(prk, b"info2", 32)
    assert len(okm1) == 32
    assert len(okm2) == 32
    assert okm1 != okm2


def test_derive_keys():
    password = "MyPassword2026!"
    salt = os.urandom(16)
    k1, k2 = derive_keys(password, salt)
    assert len(k1) == 32
    assert len(k2) == 32
    assert k1 != k2


def test_metadata_encryption():
    password = "SafePassword"
    salt = os.urandom(16)
    nonce = os.urandom(12)
    _, meta_key = derive_keys(password, salt)
    aad = b"fixed-108-bytes-header-aad"

    plain = b'{"filename":"test.txt","raw_size":42}'
    cipher = encrypt_metadata(plain, meta_key, nonce, aad)
    assert cipher != plain
    assert len(cipher) == len(plain) + 16  # 16-byte Poly/GCM tag

    # Successful decryption
    decrypted = decrypt_metadata(cipher, meta_key, nonce, aad)
    assert decrypted == plain

    # Failed decryption with wrong password
    _, wrong_meta_key = derive_keys("WrongPassword", salt)
    with pytest.raises(PasswordError):
        decrypt_metadata(cipher, wrong_meta_key, nonce, aad)

    # Failed decryption with tampered AAD
    with pytest.raises(PasswordError):
        decrypt_metadata(cipher, meta_key, nonce, b"tampered-aad")


def test_chunked_stream_roundtrip():
    password = "StreamPassword"
    salt = os.urandom(16)
    base_nonce = os.urandom(12)
    payload_key, _ = derive_keys(password, salt)
    aad = b"sample-aad-fixed-header"

    # Test with 5MB data across multiple 2MB chunks
    original_data = os.urandom(5 * 1024 * 1024 + 12345)
    in_stream = io.BytesIO(original_data)
    cipher_stream = io.BytesIO()

    total_cipher_len = encrypt_stream_to_chunks(
        in_stream, cipher_stream, payload_key, base_nonce, aad
    )
    assert total_cipher_len == cipher_stream.tell()
    assert total_cipher_len > len(original_data)

    # Decrypt
    cipher_stream.seek(0)
    plain_stream = io.BytesIO()
    total_plain_len = decrypt_stream_from_chunks(
        cipher_stream, plain_stream, payload_key, base_nonce, aad, total_cipher_len
    )
    assert total_plain_len == len(original_data)
    assert plain_stream.getvalue() == original_data


def test_deflate_compression_roundtrip():
    data = b"Hello world! This is repetitive text. " * 1000
    in_stream = io.BytesIO(data)
    comp_stream = io.BytesIO()

    raw_len, comp_len = compress_stream(in_stream, comp_stream)
    assert raw_len == len(data)
    assert comp_len < raw_len

    comp_stream.seek(0)
    decomp_stream = io.BytesIO()
    decompress_stream(comp_stream, decomp_stream, comp_len)
    assert decomp_stream.getvalue() == data
