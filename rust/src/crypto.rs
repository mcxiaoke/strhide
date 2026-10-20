//! Cryptographic and compression primitives for strhide.
//!
//! This module is the single source of truth for the envelope's crypto
//! contract: key derivation, AEAD encryption, chunk framing, and the
//! decompression bomb bound. It is **not** a general-purpose crypto library —
//! every function assumes it is being driven by [`crate::engine`] and the wire
//! format in [`crate::envelope`].
//!
//! # Cryptographic layout
//!
//! - **KDF**: PBKDF2-HMAC-SHA256 with a 16-byte random salt,
//!   [`PBKDF2_ITERATIONS`] iterations, followed by HKDF-SHA256-Expand into
//!   separate subkeys: `strhide-payload` (payload key), `strhide-metadata`
//!   (metadata key), and `strhide-stealth-*` (stealth magics / header mask).
//! - **AEAD**: AES-256-GCM. The 80-byte immutable header fields are the AAD;
//!   per-chunk nonces are derived from a single random 12-byte base nonce by
//!   XOR-ing the chunk index into the low 32 bits (see [`make_chunk_nonce`]).
//! - **Framing**: payload is encrypted in [`CHUNK_SIZE`]-byte chunks, each
//!   prefixed by a little-endian u32 length. The final chunk carries
//!   `is_last = 1` in its AAD.
//! - **Compression**: raw deflate (no zlib header). The writer keeps the
//!   compressed form only when it saves at least 2%; the reader enforces the
//!   AEAD-protected `raw_size` as a hard decompression bound.
//!
//! # Stealth mode
//!
//! When a password is supplied with `stealth = true`, the header/trailer
//! magics are derived from the password ([`derive_stealth_magics`]), the
//! header's sensitive fields are masked with a keystream from
//! [`derive_header_mask`], and the trailer CRC is XOR-masked via
//! [`derive_trailer_crc_mask`]. Without the password, the envelope looks like
//! high-entropy random data.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use unicode_normalization::UnicodeNormalization;

use crate::envelope::AAD_SIZE;
use crate::errors::StrHideError;

/// Plaintext payload chunk size. Each chunk is independently sealed with
/// AES-256-GCM and prefixed by its own u32 length on the wire.
pub const CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2MB

/// PBKDF2-HMAC-SHA256 iteration count. Raising this invalidates envelopes
/// written with older versions, so it is treated as a wire-format constant.
pub const PBKDF2_ITERATIONS: u32 = 100_000;

/// Default internal secret used when the user does not specify a password.
/// All envelopes are uniformly encrypted with AES-256-GCM and Deflate-compressed,
/// eliminating plaintext leakage (no plaintext payload, metadata, or host SHA-256 in hex view).
pub const BUILTIN_DEFAULT_KEY: &str = "strhide::envelope::v2::default::builtin::public::secret";

/// NFC-normalize a user-supplied string (password, hint, filename).
///
/// Passwords typed on macOS / iOS may arrive as NFD decomposed form; deriving
/// keys from the raw bytes would silently produce different envelopes on
/// different platforms. All password-bearing call sites funnel through here.
pub fn normalize_nfc(s: &str) -> String {
    s.nfc().collect::<String>()
}

/// Derive the 32-byte payload and metadata keys from a password and salt.
///
/// The password is NFC-normalized, run through PBKDF2, then HKDF-Expand'd
/// twice with distinct info labels so the two keys are independent.
pub fn derive_keys(password: &str, salt: &[u8]) -> Result<([u8; 32], [u8; 32]), StrHideError> {
    let norm_pwd = normalize_nfc(password);
    let mut ikm = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(norm_pwd.as_bytes(), salt, PBKDF2_ITERATIONS, &mut ikm);

    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut payload_key = [0u8; 32];
    let mut meta_key = [0u8; 32];

    hk.expand(b"strhide-payload", &mut payload_key)
        .map_err(|e| StrHideError::General(format!("HKDF expand payload error: {e}")))?;
    hk.expand(b"strhide-metadata", &mut meta_key)
        .map_err(|e| StrHideError::General(format!("HKDF expand metadata error: {e}")))?;

    Ok((payload_key, meta_key))
}

/// Derive the 8-byte header magic and 4-byte trailer magic used in stealth
/// mode.
///
/// Without the password these bytes look like random data, so a forensic scan
/// for the standard ASCII/binary magics finds nothing.
pub fn derive_stealth_magics(
    password: &str,
    salt: &[u8],
) -> Result<([u8; 8], [u8; 4]), StrHideError> {
    let norm_pwd = normalize_nfc(password);
    let mut ikm = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(norm_pwd.as_bytes(), salt, PBKDF2_ITERATIONS, &mut ikm);

    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut header_magic = [0u8; 8];
    let mut trailer_magic = [0u8; 4];

    hk.expand(b"strhide-stealth-header", &mut header_magic)
        .map_err(|e| StrHideError::General(format!("HKDF expand stealth header error: {e}")))?;
    hk.expand(b"strhide-stealth-trailer", &mut trailer_magic)
        .map_err(|e| StrHideError::General(format!("HKDF expand stealth trailer error: {e}")))?;

    Ok((header_magic, trailer_magic))
}

/// Derive a 76-byte deterministic keystream from password and salt to mask
/// the sensitive fields of EnvelopeHeader in stealth mode.
pub fn derive_header_mask(password: &str, salt: &[u8]) -> Result<[u8; 76], StrHideError> {
    let norm_pwd = normalize_nfc(password);
    let mut ikm = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(norm_pwd.as_bytes(), salt, PBKDF2_ITERATIONS, &mut ikm);

    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut mask = [0u8; 76];
    hk.expand(b"strhide-header-mask-v1", &mut mask)
        .map_err(|e| StrHideError::General(format!("HKDF expand header mask error: {e}")))?;
    Ok(mask)
}

/// Derive a 4-byte CRC mask from trailer magic in stealth mode.
/// This prevents public IEEE 802.3 CRC32 scanning from detecting the trailer
/// without knowledge of the password.
pub fn derive_trailer_crc_mask(trailer_magic: &[u8; 4]) -> u32 {
    crc32fast::hash(&[
        trailer_magic[0],
        trailer_magic[1],
        trailer_magic[2],
        trailer_magic[3],
        0x53,
        0x54,
        0x45,
        0x41, // b"STEA"
    ])
}

/// Derive a 10-byte deterministic keystream from the 4-byte channel magic to mask
/// the remaining fields of ChannelHeader (version, flags, ube_len, slack_off).
/// This eliminates raw version numbers and zero-filled padding integers in PE codebits.
pub fn derive_channel_header_mask(magic: &[u8; 4]) -> [u8; 10] {
    let hk = hkdf::Hkdf::<Sha256>::new(None, magic);
    let mut mask = [0u8; 10];
    hk.expand(b"strhide-pe-channel-mask-v1", &mut mask)
        .expect("HKDF-Expand for 10-byte channel mask never fails");
    mask
}

/// Per-chunk nonce: the 8-byte prefix of `base_nonce` is preserved, and the
/// low 4 bytes are XOR-ed with `chunk_index`. Reusing `base_nonce` across
/// chunks is safe because every resulting nonce is distinct.
pub fn make_chunk_nonce(base_nonce: &[u8; 12], chunk_index: usize) -> [u8; 12] {
    let counter_bytes: [u8; 4] = base_nonce[8..12].try_into().unwrap();
    let counter = u32::from_le_bytes(counter_bytes) ^ (chunk_index as u32);
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&base_nonce[0..8]);
    nonce[8..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Metadata nonce: same scheme as [`make_chunk_nonce`] but XOR-ed with
/// `0xFFFF_FFFF` so the metadata seal never shares a nonce with chunk 0.
pub fn make_meta_nonce(base_nonce: &[u8; 12]) -> [u8; 12] {
    let counter_bytes: [u8; 4] = base_nonce[8..12].try_into().unwrap();
    let counter = u32::from_le_bytes(counter_bytes) ^ 0xFFFFFFFF;
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&base_nonce[0..8]);
    nonce[8..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Seal the (compact or JSON) metadata block with the metadata subkey.
/// The 80-byte header fields are bound as AAD so any later tamper of the
/// header that survives this decrypt also breaks the metadata tag.
pub fn encrypt_metadata(
    meta_bytes: &[u8],
    meta_key: &[u8; 32],
    base_nonce: &[u8; 12],
    aad: &[u8; AAD_SIZE],
) -> Result<Vec<u8>, StrHideError> {
    let nonce = make_meta_nonce(base_nonce);
    let cipher = Aes256Gcm::new_from_slice(meta_key)
        .map_err(|e| StrHideError::General(format!("Invalid key for AES-GCM: {e}")))?;
    let payload = Payload {
        msg: meta_bytes,
        aad,
    };
    cipher
        .encrypt(&Nonce::from(nonce), payload)
        .map_err(|e| StrHideError::General(format!("Metadata encryption failed: {e}")))
}

/// Open the metadata block. A failed tag is reported as
/// [`StrHideError::CorruptedData`]; callers that want to distinguish "wrong
/// password" from "corrupted" must match on this at the engine layer.
pub fn decrypt_metadata(
    meta_ciphertext: &[u8],
    meta_key: &[u8; 32],
    base_nonce: &[u8; 12],
    aad: &[u8; AAD_SIZE],
) -> Result<Vec<u8>, StrHideError> {
    let nonce = make_meta_nonce(base_nonce);
    let cipher = Aes256Gcm::new_from_slice(meta_key)
        .map_err(|e| StrHideError::General(format!("Invalid key for AES-GCM: {e}")))?;
    let payload = Payload {
        msg: meta_ciphertext,
        aad,
    };
    cipher
        .decrypt(&Nonce::from(nonce), payload)
        .map_err(|_| StrHideError::CorruptedData("Metadata authentication failed".into()))
}

/// Read `reader` to EOF, seal it in [`CHUNK_SIZE`]-byte AES-256-GCM chunks,
/// and write the length-prefixed chunk stream to `writer`.
///
/// Returns the total number of ciphertext bytes written (chunk lengths +
/// ciphertext + GCM tags). An empty input still produces one empty final
/// chunk so the reader can distinguish "no payload" from "truncated stream".
pub fn encrypt_stream_to_chunks<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    payload_key: &[u8; 32],
    base_nonce: &[u8; 12],
    fixed_header_aad: &[u8; AAD_SIZE],
) -> Result<u64, StrHideError> {
    let cipher = Aes256Gcm::new_from_slice(payload_key)
        .map_err(|e| StrHideError::General(format!("Invalid key for AES-GCM: {e}")))?;

    let mut current_chunk = Vec::with_capacity(CHUNK_SIZE);
    let mut buf = [0u8; 64 * 1024];

    // Read first chunk
    while current_chunk.len() < CHUNK_SIZE {
        let to_read = std::cmp::min(CHUNK_SIZE - current_chunk.len(), buf.len());
        let n = reader.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        current_chunk.extend_from_slice(&buf[..n]);
    }

    let mut chunk_index: usize = 0;
    let mut total_written: u64 = 0;

    if current_chunk.is_empty() {
        // Empty stream, write a single empty final chunk
        let chunk_nonce = make_chunk_nonce(base_nonce, 0);
        let mut chunk_aad = Vec::with_capacity(AAD_SIZE + 9);
        chunk_aad.extend_from_slice(fixed_header_aad);
        chunk_aad.extend_from_slice(&(0u64).to_le_bytes());
        chunk_aad.push(1u8); // is_last = 1

        let encrypted = cipher
            .encrypt(
                &Nonce::from(chunk_nonce),
                Payload {
                    msg: &[],
                    aad: &chunk_aad,
                },
            )
            .map_err(|e| StrHideError::General(format!("AEAD encryption failed: {e}")))?;

        let chunk_len = encrypted.len() as u32;
        writer.write_all(&chunk_len.to_le_bytes())?;
        writer.write_all(&encrypted)?;
        return Ok(4 + encrypted.len() as u64);
    }

    let mut next_chunk = Vec::with_capacity(CHUNK_SIZE);

    loop {
        // Read next chunk to determine if current_chunk is last
        next_chunk.clear();
        while next_chunk.len() < CHUNK_SIZE {
            let to_read = std::cmp::min(CHUNK_SIZE - next_chunk.len(), buf.len());
            let n = reader.read(&mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            next_chunk.extend_from_slice(&buf[..n]);
        }

        let is_last = next_chunk.is_empty();
        let chunk_nonce = make_chunk_nonce(base_nonce, chunk_index);

        let mut chunk_aad = Vec::with_capacity(AAD_SIZE + 9);
        chunk_aad.extend_from_slice(fixed_header_aad);
        chunk_aad.extend_from_slice(&(chunk_index as u64).to_le_bytes());
        chunk_aad.push(if is_last { 1u8 } else { 0u8 });

        let encrypted = cipher
            .encrypt(
                &Nonce::from(chunk_nonce),
                Payload {
                    msg: &current_chunk,
                    aad: &chunk_aad,
                },
            )
            .map_err(|e| StrHideError::General(format!("AEAD encryption failed: {e}")))?;

        let chunk_len = encrypted.len() as u32;
        writer.write_all(&chunk_len.to_le_bytes())?;
        writer.write_all(&encrypted)?;
        total_written += 4 + encrypted.len() as u64;

        if is_last {
            break;
        }

        chunk_index += 1;
        std::mem::swap(&mut current_chunk, &mut next_chunk);
    }

    Ok(total_written)
}

/// Reverse of [`encrypt_stream_to_chunks`]: read exactly
/// `total_payload_bytes` of framed ciphertext from `reader`, decrypt and
/// verify each chunk, and write the plaintext to `writer`.
///
/// `total_payload_bytes` comes from the AEAD-protected header, so it is
/// trusted; individual chunk lengths are still capped at
/// `CHUNK_SIZE + 16` to reject a forged envelope that asks for a giant
/// allocation.
pub fn decrypt_stream_from_chunks<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    payload_key: &[u8; 32],
    base_nonce: &[u8; 12],
    fixed_header_aad: &[u8; AAD_SIZE],
    total_payload_bytes: u64,
) -> Result<u64, StrHideError> {
    let cipher = Aes256Gcm::new_from_slice(payload_key)
        .map_err(|e| StrHideError::General(format!("Invalid key for AES-GCM: {e}")))?;

    let mut chunk_index: usize = 0;
    let mut bytes_consumed: u64 = 0;
    let mut total_plain_written: u64 = 0;
    let mut seen_final = false;

    while bytes_consumed < total_payload_bytes {
        let mut header_data = [0u8; 4];
        reader.read_exact(&mut header_data).map_err(|_| {
            StrHideError::CorruptedData("Unexpected EOF reading chunk header".into())
        })?;
        bytes_consumed += 4;
        let chunk_len = u32::from_le_bytes(header_data) as usize;

        // Upper bound: a legit chunk holds at most CHUNK_SIZE plaintext bytes
        // plus the 16-byte GCM tag. Anything larger means corruption or a
        // crafted envelope; reject before allocating.
        if chunk_len > CHUNK_SIZE + 16 {
            return Err(StrHideError::CorruptedData(format!(
                "Chunk length {chunk_len} exceeds maximum {} at chunk {chunk_index}",
                CHUNK_SIZE + 16
            )));
        }

        let mut cipher_chunk = vec![0u8; chunk_len];
        reader.read_exact(&mut cipher_chunk).map_err(|_| {
            StrHideError::CorruptedData("Unexpected EOF reading ciphertext chunk".into())
        })?;
        bytes_consumed += chunk_len as u64;

        let is_last = bytes_consumed >= total_payload_bytes;
        if is_last {
            seen_final = true;
        }

        let chunk_nonce = make_chunk_nonce(base_nonce, chunk_index);
        let mut chunk_aad = Vec::with_capacity(AAD_SIZE + 9);
        chunk_aad.extend_from_slice(fixed_header_aad);
        chunk_aad.extend_from_slice(&(chunk_index as u64).to_le_bytes());
        chunk_aad.push(if is_last { 1u8 } else { 0u8 });

        let plain = cipher
            .decrypt(
                &Nonce::from(chunk_nonce),
                Payload {
                    msg: &cipher_chunk,
                    aad: &chunk_aad,
                },
            )
            .map_err(|_| {
                StrHideError::CorruptedData(format!(
                    "AEAD authentication failed at chunk {chunk_index}"
                ))
            })?;

        writer.write_all(&plain)?;
        total_plain_written += plain.len() as u64;
        chunk_index += 1;
    }

    if !seen_final && total_payload_bytes > 0 {
        return Err(StrHideError::CorruptedData(
            "Payload stream was truncated before final chunk".into(),
        ));
    }

    Ok(total_plain_written)
}

/// Compress in_stream using raw deflate.
/// Returns (raw_size, compressed_size).
pub fn compress_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(u64, u64), StrHideError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(6));
    let mut buf = [0u8; 64 * 1024];
    let mut raw_size: u64 = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        raw_size += n as u64;
        encoder.write_all(&buf[..n])?;
    }

    let compressed = encoder.finish()?;
    let comp_size = compressed.len() as u64;
    writer.write_all(&compressed)?;

    Ok((raw_size, comp_size))
}

/// Decompress in_stream using raw deflate.
///
/// `limit` bounds the decompressed size: the declared `raw_size` from the
/// (AEAD-protected) metadata. A crafted carrier could otherwise expand a few
/// kilobytes into gigabytes — an 8 MiB run of zeros compresses to ~8 KiB —
/// and make `read` allocate far more memory than the carrier size suggests.
/// Returns total decompressed size.
pub fn decompress_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    limit: u64,
) -> Result<u64, StrHideError> {
    let mut decoder = DeflateDecoder::new(reader);
    let mut buf = [0u8; 64 * 1024];
    let mut total_decompressed: u64 = 0;

    loop {
        let n = decoder.read(&mut buf).map_err(|e| {
            StrHideError::CorruptedData(format!("Deflate decompression error: {e}"))
        })?;
        if n == 0 {
            break;
        }
        let next_total = total_decompressed.saturating_add(n as u64);
        if next_total > limit {
            return Err(StrHideError::CorruptedData(format!(
                "Decompressed payload exceeds the declared size ({limit} bytes); refusing to expand further"
            )));
        }
        writer.write_all(&buf[..n])?;
        total_decompressed = next_total;
    }

    Ok(total_decompressed)
}

/// One-shot SHA-256 of an in-memory buffer.
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Streamed SHA-256: reads `reader` to EOF in 64 KiB blocks, never
/// materializing the whole input. Used for hashing large carriers.
pub fn compute_stream_sha256<R: Read>(reader: &mut R) -> Result<[u8; 32], StrHideError> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Streamed SHA-256 of a file on disk.
pub fn compute_file_sha256(path: &std::path::Path) -> Result<[u8; 32], StrHideError> {
    let mut file = std::fs::File::open(path)?;
    compute_stream_sha256(&mut file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_crypto_vector_compatibility() {
        let salt = b"1234567890123456";
        let (pk, mk) = derive_keys("test_password", salt).unwrap();
        let (hm, tm) = derive_stealth_magics("test_password", b"strhide-stealth-v1").unwrap();

        // Check against Python computed hex strings
        let expected_pk = "2834274fef93d55fc5a3cb070c09c08eedecd8910b9a601fd67b703c8e078674";
        let expected_mk = "5406a23d873a956bcf01781771ea5f96857b61bda4f15ef53d40d87f07477c68";
        let expected_hm = "3858efa8820a029b";
        let expected_tm = "3a97756c";

        assert_eq!(
            pk.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            expected_pk
        );
        assert_eq!(
            mk.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            expected_mk
        );
        assert_eq!(
            hm.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            expected_hm
        );
        assert_eq!(
            tm.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            expected_tm
        );
    }

    #[test]
    fn test_deflate_compatibility() {
        let data = b"Hello World! This is a test of raw deflate compression.";
        let mut comp = Vec::new();
        let (raw_len, comp_len) = compress_stream(&mut &data[..], &mut comp).unwrap();
        assert_eq!(raw_len, data.len() as u64);
        assert_eq!(comp_len, comp.len() as u64);

        let mut decomp = Vec::new();
        let decomp_len = decompress_stream(&mut &comp[..], &mut decomp, data.len() as u64).unwrap();
        assert_eq!(decomp_len, data.len() as u64);
        assert_eq!(decomp, data);
    }

    #[test]
    fn test_metadata_encryption_roundtrip_and_tamper() {
        let salt = b"1234567890123456";
        let base_nonce = [7u8; 12];
        let (_, meta_key) = derive_keys("SafePassword", salt).unwrap();
        let aad = [0x55u8; AAD_SIZE];
        let plain = b"{\"filename\":\"test.txt\",\"raw_size\":42}";

        // Encrypt
        let cipher = encrypt_metadata(plain, &meta_key, &base_nonce, &aad).unwrap();
        assert_ne!(cipher, plain);
        assert_eq!(cipher.len(), plain.len() + 16); // 16-byte Poly/GCM tag

        // Decrypt successfully
        let decrypted = decrypt_metadata(&cipher, &meta_key, &base_nonce, &aad).unwrap();
        assert_eq!(decrypted, plain);

        // Wrong password / key
        let (_, wrong_meta_key) = derive_keys("WrongPassword", salt).unwrap();
        assert!(matches!(
            decrypt_metadata(&cipher, &wrong_meta_key, &base_nonce, &aad),
            Err(StrHideError::CorruptedData(_))
        ));

        // Tampered AAD
        let mut tampered_aad = aad;
        tampered_aad[0] ^= 0xFF;
        assert!(matches!(
            decrypt_metadata(&cipher, &meta_key, &base_nonce, &tampered_aad),
            Err(StrHideError::CorruptedData(_))
        ));
    }

    #[test]
    fn test_chunked_stream_roundtrip_multi_megabytes() {
        let salt = b"salt_for_stream!";
        let base_nonce = [3u8; 12];
        let (payload_key, _) = derive_keys("StreamPassword", salt).unwrap();
        let aad = [0xAAu8; AAD_SIZE];

        // 5MB data across multiple 2MB chunks
        let orig_size = 5 * 1024 * 1024 + 12345;
        let mut original_data = Vec::with_capacity(orig_size);
        for i in 0..orig_size {
            original_data.push(((i * 61 + 17) & 0xFF) as u8);
        }

        let mut in_stream = std::io::Cursor::new(&original_data);
        let mut cipher_stream = std::io::Cursor::new(Vec::new());

        let total_cipher_len = encrypt_stream_to_chunks(
            &mut in_stream,
            &mut cipher_stream,
            &payload_key,
            &base_nonce,
            &aad,
        )
        .unwrap();

        assert!(total_cipher_len > orig_size as u64);

        // Decrypt
        cipher_stream.set_position(0);
        let mut plain_stream = std::io::Cursor::new(Vec::new());
        let total_plain_len = decrypt_stream_from_chunks(
            &mut cipher_stream,
            &mut plain_stream,
            &payload_key,
            &base_nonce,
            &aad,
            total_cipher_len,
        )
        .unwrap();

        assert_eq!(total_plain_len, orig_size as u64);
        assert_eq!(plain_stream.into_inner(), original_data);
    }
}
