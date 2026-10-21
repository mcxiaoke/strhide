//! Stealth micro-envelope for content-domain steganography.
//!
//! Unlike structure-domain UBE envelopes which have structured headers, the content-domain
//! envelope is strictly minimal and pseudo-random:
//!
//! `[16-byte random Salt][12-byte random Nonce][AEAD ciphertext + 16-byte Tag]`
//!
//! Inside the ciphertext:
//! `[4-byte big-endian uncompressed length][1-byte flags (compression)][compressed payload]`
//!
//! Without the password, every single bit resembles high-entropy physical sensor noise or
//! PRNG output; there are no static magic bytes, headers, or plaintext markers.

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

/// Bytes the **ciphertext body** spends on things that are not payload:
/// `[4-byte original length][1-byte flags]` inside the plaintext plus the
/// 16-byte AEAD tag.
///
/// The 28-byte salt/nonce is deliberately NOT part of this number: it is
/// carried by the 256 header slots, not by the body slots. Capacity probes must
/// subtract this from the body ciphertext budget, otherwise they under-report by
/// 28 bytes (they used to subtract `MIN_ENVELOPE_LEN`).
pub const BODY_OVERHEAD: usize = 4 + 1 + TAG_LEN; // 21 bytes

/// Flag bit indicating Deflate compression.
const FLAG_COMPRESSED: u8 = 0x01;

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

/// Derive AES-256-GCM key and PRNG seed from password and salt, optionally isolated by domain.
pub fn derive_keys(password: &str, salt: &[u8], domain: Option<&str>) -> ([u8; 32], [u8; 32]) {
    let norm_pwd = normalize_nfc(password);
    // PBKDF2-HMAC-SHA256 with 100,000 iterations
    let mut pbkdf2_key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(norm_pwd.as_bytes(), salt, 100_000, &mut pbkdf2_key);

    let effective_ikm = match derive_domain_subkey(&pbkdf2_key, domain) {
        Some(subkey) => subkey,
        None => pbkdf2_key,
    };

    // HKDF expand into encryption key (32 bytes) and permutation seed (32 bytes)
    let hk = Hkdf::<Sha256>::new(Some(salt), &effective_ikm);
    let mut enc_key_bytes = [0u8; 32];
    let mut perm_seed = [0u8; 32];
    hk.expand(b"strhide-stego-enc-v1", &mut enc_key_bytes)
        .expect("HKDF expand enc key");
    hk.expand(b"strhide-stego-perm-v1", &mut perm_seed)
        .expect("HKDF expand perm seed");

    (enc_key_bytes, perm_seed)
}

/// Derive header permutation seed from password (or default builtin key) WITHOUT salt,
/// optionally isolated by domain.
/// This breaks the circular dependency ("chicken-and-egg") so the header location
/// can be pseudo-randomized across the carrier without knowing the salt upfront.
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
/// Takes the already-derived `perm_seed` instead of the password so the caller
/// does not pay a second 100k-iteration PBKDF2 per embed: both ends call
/// [`derive_keys`] exactly once and domain-separate from it here.
///
/// The trellis (`ĥ`, i.e. the parity-check matrix) must stay as secret as the
/// payload key -- a public `H` lets an attacker compute the syndrome of any
/// candidate change set, which is exactly the detector we are trying to deny.
pub fn derive_stc_seed(perm_seed: &[u8; 32], salt: &[u8]) -> u64 {
    let hk = Hkdf::<Sha256>::new(Some(salt), perm_seed);
    let mut out = [0u8; 8];
    hk.expand(b"strhide-stc-trellis-v1", &mut out)
        .expect("HKDF expand stc trellis seed");
    u64::from_be_bytes(out)
}

/// Fallback built-in key when no password is provided.
fn default_builtin_key(salt: &[u8], domain: Option<&str>) -> ([u8; 32], [u8; 32]) {
    derive_keys(PUBLIC_DEFAULT_SECRET, salt, domain)
}

/// Pack and encrypt payload into micro-envelope byte stream, also returning the derived `perm_seed`.
pub fn pack_envelope_ext(
    payload: &[u8],
    password: Option<&str>,
    domain: Option<&str>,
) -> Result<(Vec<u8>, [u8; 32]), StrHideError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    let mut rng = rand::rng();
    rng.fill(&mut salt);
    rng.fill(&mut nonce_bytes);

    let (key_bytes, perm_seed) = match password {
        Some(p) => derive_keys(p, &salt, domain),
        None => default_builtin_key(&salt, domain),
    };

    // Compress payload with Deflate
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(payload)?;
    let compressed = encoder.finish()?;

    let (payload_bytes, flags) = if compressed.len() < payload.len() {
        (compressed, FLAG_COMPRESSED)
    } else {
        (payload.to_vec(), 0u8)
    };

    // Plaintext format: [4B original len][1B flags][payload bytes]
    let mut plaintext = Vec::with_capacity(5 + payload_bytes.len());
    plaintext.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    plaintext.push(flags);
    plaintext.extend_from_slice(&payload_bytes);

    // AES-256-GCM encryption with Salt+Nonce as AAD
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| StrHideError::Password(format!("Cipher init failed: {e}")))?;
    let nonce = Nonce::from(nonce_bytes);
    let mut aad = Vec::with_capacity(HEADER_OVERHEAD);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| StrHideError::Password(format!("Encryption failed: {e}")))?;

    let mut out = Vec::with_capacity(HEADER_OVERHEAD + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    Ok((out, perm_seed))
}

/// Pack and encrypt payload into micro-envelope byte stream.
pub fn pack_envelope(
    payload: &[u8],
    password: Option<&str>,
    domain: Option<&str>,
) -> Result<Vec<u8>, StrHideError> {
    pack_envelope_ext(payload, password, domain).map(|(env, _)| env)
}

/// Unpack and decrypt micro-envelope from raw extracted bytes using a pre-derived AES key.
pub fn unpack_envelope_with_key(
    data: &[u8],
    key_bytes: &[u8; 32],
) -> Result<Vec<u8>, StrHideError> {
    if data.len() < MIN_ENVELOPE_LEN {
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }

    let salt = &data[..SALT_LEN];
    let nonce_bytes = &data[SALT_LEN..HEADER_OVERHEAD];
    let ciphertext = &data[HEADER_OVERHEAD..];

    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;
    let nonce = Nonce::try_from(nonce_bytes)
        .map_err(|_| StrHideError::NoHiddenData("Invalid nonce size".into()))?;
    let mut aad = Vec::with_capacity(HEADER_OVERHEAD);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| {
            StrHideError::NoHiddenData("No valid payload found or incorrect password".into())
        })?; // Oracle resistance

    if plaintext.len() < 5 {
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }

    let orig_len =
        u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]) as usize;
    let flags = plaintext[4];
    let body = &plaintext[5..];

    if flags & FLAG_COMPRESSED != 0 {
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
    } else {
        if body.len() != orig_len {
            return Err(StrHideError::NoHiddenData(
                "Plaintext length mismatch".into(),
            ));
        }
        Ok(body.to_vec())
    }
}

/// Unpack and decrypt micro-envelope from raw extracted bytes.
pub fn unpack_envelope(
    data: &[u8],
    password: Option<&str>,
    domain: Option<&str>,
) -> Result<Vec<u8>, StrHideError> {
    if data.len() < MIN_ENVELOPE_LEN {
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }

    let salt = &data[..SALT_LEN];
    let (key_bytes, _) = match password {
        Some(p) => derive_keys(p, salt, domain),
        None => default_builtin_key(salt, domain),
    };

    unpack_envelope_with_key(data, &key_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfc_normalization_produces_identical_keys_and_seeds() {
        // "café" in NFC (precomposed: \u{00E9}) vs NFD (decomposed: e + \u{0301})
        let pwd_nfc = "caf\u{00E9}";
        let pwd_nfd = "cafe\u{0301}";
        assert_ne!(pwd_nfc.as_bytes(), pwd_nfd.as_bytes());

        let salt = [42u8; 16];
        let (key_nfc, perm_nfc) = derive_keys(pwd_nfc, &salt, None);
        let (key_nfd, perm_nfd) = derive_keys(pwd_nfd, &salt, None);

        assert_eq!(key_nfc, key_nfd);
        assert_eq!(perm_nfc, perm_nfd);

        let hseed_nfc = derive_header_perm_seed(Some(pwd_nfc), None);
        let hseed_nfd = derive_header_perm_seed(Some(pwd_nfd), None);
        assert_eq!(hseed_nfc, hseed_nfd);

        // Cross pack/unpack
        let payload = b"secret stego message";
        let packed = pack_envelope(payload, Some(pwd_nfd), None).expect("pack with NFD password");
        let unpacked =
            unpack_envelope(&packed, Some(pwd_nfc), None).expect("unpack with NFC password");
        assert_eq!(unpacked, payload);
    }

    #[test]
    fn domain_isolation_keys_and_seeds() {
        let salt = [17u8; 16];
        let pwd = "MyStrongPassword123";

        let (key_default, perm_default) = derive_keys(pwd, &salt, None);
        let (key_a, perm_a) = derive_keys(pwd, &salt, Some("org.corp.alpha"));
        let (key_b, perm_b) = derive_keys(pwd, &salt, Some("org.corp.beta"));

        assert_ne!(key_default, key_a);
        assert_ne!(key_a, key_b);
        assert_ne!(perm_default, perm_a);
        assert_ne!(perm_a, perm_b);

        let hseed_default = derive_header_perm_seed(Some(pwd), None);
        let hseed_a = derive_header_perm_seed(Some(pwd), Some("org.corp.alpha"));
        let hseed_b = derive_header_perm_seed(Some(pwd), Some("org.corp.beta"));

        assert_ne!(hseed_default, hseed_a);
        assert_ne!(hseed_a, hseed_b);

        // Default builtin key also isolates by domain
        let (dkey_default, _) = derive_keys(PUBLIC_DEFAULT_SECRET, &salt, None);
        let (dkey_a, _) = derive_keys(PUBLIC_DEFAULT_SECRET, &salt, Some("org.corp.alpha"));
        assert_ne!(dkey_default, dkey_a);
    }

    #[test]
    fn domain_nfc_normalization_and_empty_equivalence() {
        let salt = [77u8; 16];
        let pwd = "password";

        // NFC vs NFD domain tag
        let domain_nfc = "resum\u{00E9}.vault";
        let domain_nfd = "resume\u{0301}.vault";
        assert_ne!(domain_nfc.as_bytes(), domain_nfd.as_bytes());

        let (key_nfc, perm_nfc) = derive_keys(pwd, &salt, Some(domain_nfc));
        let (key_nfd, perm_nfd) = derive_keys(pwd, &salt, Some(domain_nfd));
        assert_eq!(key_nfc, key_nfd);
        assert_eq!(perm_nfc, perm_nfd);

        let hseed_nfc = derive_header_perm_seed(Some(pwd), Some(domain_nfc));
        let hseed_nfd = derive_header_perm_seed(Some(pwd), Some(domain_nfd));
        assert_eq!(hseed_nfc, hseed_nfd);

        // Empty domain is equivalent to None
        let (key_empty, perm_empty) = derive_keys(pwd, &salt, Some(""));
        let (key_none, perm_none) = derive_keys(pwd, &salt, None);
        assert_eq!(key_empty, key_none);
        assert_eq!(perm_empty, perm_none);

        let hseed_empty = derive_header_perm_seed(Some(pwd), Some(""));
        let hseed_none = derive_header_perm_seed(Some(pwd), None);
        assert_eq!(hseed_empty, hseed_none);

        // Cross-domain unpack failure
        let payload = b"classified corporate data";
        let packed = pack_envelope(payload, Some(pwd), Some("domain-A")).expect("pack domain-A");
        let err = unpack_envelope(&packed, Some(pwd), Some("domain-B"));
        assert!(err.is_err(), "unpacking with mismatched domain must fail");
    }
}
