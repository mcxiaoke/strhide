//! Stealth micro-envelope for content-domain steganography.
//!
//! Inside the AEAD ciphertext:
//!
//! ```text
//! [4-byte big-endian uncompressed length][1-byte flags][payload bytes]
//! ```
//!
//! There are no magic bytes, no plaintext markers and no field that is not
//! covered by the tag: a carrier without the password is indistinguishable from
//! an untouched image.
//!
//! # Where salt and nonce live
//!
//! They no longer travel inside the envelope buffer: the carrier's own header
//! carries them (a 44-byte superblock for JPEG, a 32-byte header for the spatial
//! codec), and the *whole header* is the AEAD's associated data. That is a
//! deliberate change from the previous `salt || nonce` AAD:
//!
//! * any header field the decoder acts on (trellis height, group size, suite id,
//!   extension length) is authenticated, so tampering fails the tag instead of
//!   producing a different-but-plausible decode;
//! * the caller no longer concatenates `[salt | nonce]` and the ciphertext into
//!   a fresh `Vec` on the extract path.
//!
//! The pieces are therefore split into three steps: [`build_plaintext`],
//! [`encrypt_with_aad`] and [`unpack_envelope_parts`].

use std::io::{Read, Write};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use hkdf::Hkdf;
use rand::RngExt;
use sha2::Sha256;

use crate::crypto::normalize_nfc;
use crate::errors::StrHideError;
use crate::stego::format::{Aead as SuiteAead, CipherSuite};

/// Official public fallback secret.
///
/// Used only when neither a user password nor a private
/// [`StegoProfile::default_secret`](crate::params::StegoProfile::default_secret)
/// is supplied. The value is public by design: it keeps payloads off
/// plaintext-on-disk, but it gives **no** confidentiality against anyone who
/// has this source tree -- they can reproduce the exact key derivation and
/// read every no-password envelope (both the AEAD key and the header slot
/// permutation become known).
///
/// Replace it with a private value through
/// [`Profile::with_stego_secret`](crate::params::Profile::with_stego_secret)
/// (CLI: `--stego-secret`, config: `stego_secret`). Note the parameter class: it
/// must be identical on embed and extract, otherwise the carrier reads back as
/// `NoHiddenData`.
pub const PUBLIC_DEFAULT_SECRET: &str = "strhide-default-content-stego-key-2026";

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const HEADER_OVERHEAD: usize = SALT_LEN + NONCE_LEN; // 28 bytes
pub const MIN_ENVELOPE_LEN: usize = HEADER_OVERHEAD + 4 + 1 + TAG_LEN; // 49 bytes

/// Bytes the **ciphertext** spends on things that are not payload:
/// `[4-byte original length][1-byte flags]` inside the plaintext plus the
/// 16-byte AEAD tag.
///
/// The 28-byte salt/nonce is deliberately NOT part of this number: it is
/// carried by the carrier header, not by the body slots. Capacity probes must
/// subtract this from the body ciphertext budget, otherwise they under-report by
/// 28 bytes (they used to subtract `MIN_ENVELOPE_LEN`).
pub const BODY_OVERHEAD: usize = 4 + 1 + TAG_LEN; // 21 bytes

/// Largest payload a decoded envelope may expand to (matches the header's
/// 26-bit length field).
pub const MAX_PLAINTEXT_LEN: usize = 1 << 26;

/// Flag bit 0: the payload is compressed.
const FLAG_COMPRESSED: u8 = 0x01;

/// Bits 1..3 hold the compression algorithm id.
const COMPRESSION_SHIFT: u32 = 1;
const COMPRESSION_MASK: u8 = 0x07;

/// Compression algorithm id 0: Deflate (the only one implemented).
const COMPRESSION_DEFLATE: u8 = 0;

/// Derive a subkey from `ikm` when a custom `domain` is specified, applying
/// NFC normalization and an 8-byte big-endian length prefix to prevent collision.
///
/// If `domain` is `None` or empty, returns `None`, indicating that caller should use `ikm` directly.
pub fn derive_domain_subkey(ikm: &[u8], domain: Option<&str>) -> Option<[u8; 32]> {
    let d = domain.filter(|s| !s.is_empty())?;
    let norm_d = normalize_nfc(d);
    let len_bytes = (norm_d.len() as u64).to_be_bytes();
    let mut info = Vec::with_capacity(23 + 8 + norm_d.len());
    info.extend_from_slice(b"strhide-stego-domain-v1");
    info.extend_from_slice(&len_bytes);
    info.extend_from_slice(norm_d.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut subkey = [0u8; 32];
    hk.expand(&info, &mut subkey)
        .expect("HKDF expand domain subkey");
    Some(subkey)
}

/// Derive header permutation seed from password (or default builtin key) WITHOUT salt,
/// optionally isolated by domain.
///
/// Used by the spatial codec, whose header position must be resolvable before
/// the header (and therefore its salt) can be read. The JPEG codec does not use
/// this: its header seed comes from the suite KDF over the cover digest, so an
/// attacker cannot trial a password without paying a full KDF.
pub fn derive_header_perm_seed(password: Option<&str>, domain: Option<&str>) -> [u8; 32] {
    let pw = password.unwrap_or(PUBLIC_DEFAULT_SECRET);
    let norm_pw = normalize_nfc(pw);
    let subkey_buf;
    let effective_ikm: &[u8] = match derive_domain_subkey(norm_pw.as_bytes(), domain) {
        Some(subkey) => {
            subkey_buf = subkey;
            &subkey_buf
        }
        None => norm_pw.as_bytes(),
    };
    let mut header_seed = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(b"strhide-stego-hpos-salt-v2"), effective_ikm);
    hk.expand(b"strhide-stego-hpos-v2", &mut header_seed)
        .expect("HKDF expand header perm seed");
    header_seed
}

/// Derive the STC trellis seed from the body permutation seed.
///
/// Kept for the spatial codec; the JPEG codec uses
/// [`crate::stego::format::stc_seed`] so the label and salt layering follow the
/// format profile.
pub fn derive_stc_seed(perm_seed: &[u8; 32], salt: &[u8]) -> u64 {
    let hk = Hkdf::<Sha256>::new(Some(salt), perm_seed);
    let mut out = [0u8; 8];
    hk.expand(b"strhide-stc-trellis-v1", &mut out)
        .expect("HKDF expand stc trellis seed");
    u64::from_be_bytes(out)
}

/// Random salt for the payload-key layering.
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill(&mut salt);
    salt
}

/// Random AEAD nonce.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill(&mut nonce);
    nonce
}

/// Compress (when profitable) and frame the payload as AEAD plaintext.
///
/// `[4B original length][1B flags][body]`. The length is known before
/// encryption, which is what lets the caller size the header field first and
/// only then encrypt with the finished header as associated data.
pub fn build_plaintext(payload: &[u8]) -> Result<Vec<u8>, StrHideError> {
    if payload.len() > MAX_PLAINTEXT_LEN {
        return Err(StrHideError::General(format!(
            "Payload of {} bytes exceeds the {MAX_PLAINTEXT_LEN}-byte envelope limit",
            payload.len()
        )));
    }
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(payload)?;
    let compressed = encoder.finish()?;

    let (body, flags) = if compressed.len() < payload.len() {
        (
            compressed,
            FLAG_COMPRESSED | (COMPRESSION_DEFLATE << COMPRESSION_SHIFT),
        )
    } else {
        (payload.to_vec(), 0u8)
    };

    let mut plaintext = Vec::with_capacity(5 + body.len());
    plaintext.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    plaintext.push(flags);
    plaintext.extend_from_slice(&body);
    Ok(plaintext)
}

/// Encrypt the framed plaintext, authenticating `aad` (the carrier header).
pub fn encrypt_with_aad(
    suite: &CipherSuite,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, StrHideError> {
    match suite.aead {
        SuiteAead::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| StrHideError::Password(format!("Cipher init failed: {e}")))?;
            let nonce = Nonce::from(*nonce);
            cipher
                .encrypt(
                    &nonce,
                    aes_gcm::aead::Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| StrHideError::Password(format!("Encryption failed: {e}")))
        }
    }
}

/// Decrypt and unframe a ciphertext, without building a combined envelope
/// buffer. A tag failure is reported as `NoHiddenData`, identical to "there is
/// nothing here", so the two cases cannot be told apart.
pub fn unpack_envelope_parts(
    suite: &CipherSuite,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, StrHideError> {
    if ciphertext.len() < 5 + suite.tag_len() {
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }

    let plaintext = match suite.aead {
        SuiteAead::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;
            let nonce = Nonce::from(*nonce);
            cipher
                .decrypt(
                    &nonce,
                    aes_gcm::aead::Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| {
                    StrHideError::NoHiddenData(
                        "No valid payload found or incorrect password".into(),
                    )
                })? // Oracle resistance
        }
    };

    if plaintext.len() < 5 {
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }
    let orig_len =
        u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]) as usize;
    let flags = plaintext[4];
    let body = &plaintext[5..];

    if flags & !(FLAG_COMPRESSED | (COMPRESSION_MASK << COMPRESSION_SHIFT)) != 0 {
        return Err(StrHideError::CorruptedData(format!(
            "Envelope flags {flags:#04x} use reserved bits"
        )));
    }
    let algorithm = (flags >> COMPRESSION_SHIFT) & COMPRESSION_MASK;
    if flags & FLAG_COMPRESSED == 0 {
        if algorithm != 0 {
            return Err(StrHideError::CorruptedData(format!(
                "Envelope declares compression algorithm {algorithm} but is not compressed"
            )));
        }
        if body.len() != orig_len {
            return Err(StrHideError::NoHiddenData(
                "Plaintext length mismatch".into(),
            ));
        }
        return Ok(body.to_vec());
    }

    if algorithm != COMPRESSION_DEFLATE {
        return Err(StrHideError::UnsupportedVersion(format!(
            "Envelope uses unsupported compression algorithm {algorithm}"
        )));
    }
    if orig_len > MAX_PLAINTEXT_LEN {
        return Err(StrHideError::CorruptedData(format!(
            "Envelope claims a {orig_len}-byte payload, above the {MAX_PLAINTEXT_LEN}-byte limit"
        )));
    }

    let mut decoder = DeflateDecoder::new(body);
    let mut decompressed = Vec::with_capacity(orig_len);
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|_| StrHideError::NoHiddenData("Decompression failed".into()))?;
    if decompressed.len() != orig_len {
        return Err(StrHideError::NoHiddenData(
            "Decompressed length mismatch".into(),
        ));
    }
    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::format::{DEFAULT_FORMAT, SUITE_PBKDF2_200K, body_keys, derive_master};

    fn keys(password: &str, salt: &[u8]) -> [u8; 32] {
        let master = derive_master(&SUITE_PBKDF2_200K, password, salt).unwrap();
        let (enc_key, _) = body_keys(&DEFAULT_FORMAT, &master, salt, None);
        enc_key
    }

    #[test]
    fn roundtrip_with_and_without_compression() {
        let salt = [42u8; SALT_LEN];
        let key = keys("password", &salt);
        let nonce = [7u8; NONCE_LEN];
        let aad = b"header bytes";

        // Compressible payload takes the Deflate path.
        let repetitive = vec![0x21u8; 4096];
        let plaintext = build_plaintext(&repetitive).unwrap();
        assert_eq!(plaintext[4] & FLAG_COMPRESSED, FLAG_COMPRESSED);
        let ct = encrypt_with_aad(&SUITE_PBKDF2_200K, &key, &nonce, aad, &plaintext).unwrap();
        let out = unpack_envelope_parts(&SUITE_PBKDF2_200K, &key, &nonce, aad, &ct).unwrap();
        assert_eq!(out, repetitive);

        // Incompressible payload stays raw.
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let random: Vec<u8> = (0..512)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        let plaintext = build_plaintext(&random).unwrap();
        assert_eq!(plaintext[4] & FLAG_COMPRESSED, 0);
        let ct = encrypt_with_aad(&SUITE_PBKDF2_200K, &key, &nonce, aad, &plaintext).unwrap();
        let out = unpack_envelope_parts(&SUITE_PBKDF2_200K, &key, &nonce, aad, &ct).unwrap();
        assert_eq!(out, random);
    }

    #[test]
    fn aad_and_nonce_and_key_are_all_bound() {
        let salt = [1u8; SALT_LEN];
        let key = keys("password", &salt);
        let nonce = [2u8; NONCE_LEN];
        let plaintext = build_plaintext(b"bound payload").unwrap();
        let ct =
            encrypt_with_aad(&SUITE_PBKDF2_200K, &key, &nonce, b"header-a", &plaintext).unwrap();

        assert!(matches!(
            unpack_envelope_parts(&SUITE_PBKDF2_200K, &key, &nonce, b"header-b", &ct),
            Err(StrHideError::NoHiddenData(_))
        ));
        let wrong_nonce = [3u8; NONCE_LEN];
        assert!(
            unpack_envelope_parts(&SUITE_PBKDF2_200K, &key, &wrong_nonce, b"header-a", &ct)
                .is_err()
        );
        let wrong_key = keys("password2", &salt);
        assert!(
            unpack_envelope_parts(&SUITE_PBKDF2_200K, &wrong_key, &nonce, b"header-a", &ct)
                .is_err()
        );
    }

    #[test]
    fn reserved_flag_bits_and_unknown_algorithms_are_rejected() {
        let salt = [9u8; SALT_LEN];
        let key = keys("pw", &salt);
        let nonce = [4u8; NONCE_LEN];

        // Hand-build a plaintext with reserved bits set.
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&3u32.to_be_bytes());
        plaintext.push(0x80);
        plaintext.extend_from_slice(b"abc");
        let ct = encrypt_with_aad(&SUITE_PBKDF2_200K, &key, &nonce, b"aad", &plaintext).unwrap();
        assert!(matches!(
            unpack_envelope_parts(&SUITE_PBKDF2_200K, &key, &nonce, b"aad", &ct),
            Err(StrHideError::CorruptedData(_))
        ));

        // Compressed flag with an unknown algorithm id.
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&3u32.to_be_bytes());
        plaintext.push(FLAG_COMPRESSED | (2 << COMPRESSION_SHIFT));
        plaintext.extend_from_slice(b"abc");
        let ct = encrypt_with_aad(&SUITE_PBKDF2_200K, &key, &nonce, b"aad", &plaintext).unwrap();
        let err = unpack_envelope_parts(&SUITE_PBKDF2_200K, &key, &nonce, b"aad", &ct).unwrap_err();
        assert!(
            matches!(err, StrHideError::UnsupportedVersion(_)),
            "{err:?}"
        );
        assert!(err.to_string().contains("compression algorithm"), "{err}");
    }

    #[test]
    fn empty_and_oversized_payloads_are_handled() {
        let salt = [5u8; SALT_LEN];
        let key = keys("pw", &salt);
        let nonce = [6u8; NONCE_LEN];
        let plaintext = build_plaintext(b"").unwrap();
        let ct = encrypt_with_aad(&SUITE_PBKDF2_200K, &key, &nonce, b"aad", &plaintext).unwrap();
        assert_eq!(
            unpack_envelope_parts(&SUITE_PBKDF2_200K, &key, &nonce, b"aad", &ct).unwrap(),
            Vec::<u8>::new()
        );

        // A ciphertext shorter than the tag cannot be a valid envelope.
        assert!(unpack_envelope_parts(&SUITE_PBKDF2_200K, &key, &nonce, b"aad", &ct[..4]).is_err());
    }
}
