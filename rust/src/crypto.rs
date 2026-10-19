//! Cryptographic and compression primitives for strhide.

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

pub const CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2MB
pub const PBKDF2_ITERATIONS: u32 = 100_000;

/// Default internal secret used when the user does not specify a password.
/// All envelopes are uniformly encrypted with AES-256-GCM and Deflate-compressed,
/// eliminating plaintext leakage (no plaintext payload, metadata, or host SHA-256 in hex view).
pub const BUILTIN_DEFAULT_KEY: &str = "strhide::envelope::v2::default::builtin::public::secret";

pub fn normalize_nfc(s: &str) -> String {
    s.nfc().collect::<String>()
}

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

pub fn make_chunk_nonce(base_nonce: &[u8; 12], chunk_index: usize) -> [u8; 12] {
    let counter_bytes: [u8; 4] = base_nonce[8..12].try_into().unwrap();
    let counter = u32::from_le_bytes(counter_bytes) ^ (chunk_index as u32);
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&base_nonce[0..8]);
    nonce[8..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

pub fn make_meta_nonce(base_nonce: &[u8; 12]) -> [u8; 12] {
    let counter_bytes: [u8; 4] = base_nonce[8..12].try_into().unwrap();
    let counter = u32::from_le_bytes(counter_bytes) ^ 0xFFFFFFFF;
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&base_nonce[0..8]);
    nonce[8..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

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
        .map_err(|_| StrHideError::Password("Invalid password or corrupted metadata".into()))
}

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
/// Returns total decompressed size.
pub fn decompress_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
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
        writer.write_all(&buf[..n])?;
        total_decompressed += n as u64;
    }

    Ok(total_decompressed)
}

pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

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
        let decomp_len = decompress_stream(&mut &comp[..], &mut decomp).unwrap();
        assert_eq!(decomp_len, data.len() as u64);
        assert_eq!(decomp, data);
    }
}
