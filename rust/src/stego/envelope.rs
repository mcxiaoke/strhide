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
//! [`encrypt_v4_with_aad`] and [`unpack_v4_envelope_parts`].

use std::io::{Read, Write};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use hkdf::Hkdf;
use rand::RngExt;
use sha2::Sha256;

use crate::core::payload::{Payload, PayloadKind};
use crate::crypto::CipherSuiteId;
use crate::crypto::normalize_nfc;
use crate::errors::StrHideError;
use crate::stego::params::ExtractParams;

/// Official public fallback secret.
///
/// Used only when neither a user password nor a private
/// [`StegoProfile::default_secret`](crate::stego::params::StegoProfile::default_secret)
/// is supplied. The value is public by design: it keeps payloads off
/// plaintext-on-disk, but it gives **no** confidentiality against anyone who
/// has this source tree -- they can reproduce the exact key derivation and
/// read every no-password envelope (both the AEAD key and the header slot
/// permutation become known).
///
/// Replace it with a private value through
/// [`Dialect::with_default_secret`](crate::facade::Dialect::with_default_secret) in
/// a custom build (compile-time dialect; there is deliberately no CLI flag for
/// it). Note the parameter class: it must be identical on embed and extract,
/// otherwise the carrier reads back as `NoHiddenData`.
pub const PUBLIC_DEFAULT_SECRET: &str = "strhide-default-content-stego-key-2026";

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Micro-header tag for plain text or raw bytes without filename.
pub const MICRO_TAG_TEXT_OR_RAW: u8 = 0x00;

/// Micro-header tag for a file payload preserving its filename.
pub const MICRO_TAG_FILE: u8 = 0x01;

/// Minimal micro-header overhead: 1 byte (`0x00`) for text/raw payload.
pub const MICRO_OVERHEAD_MIN: usize = 1;

/// Bytes the **ciphertext** spends on things that are not raw payload:
/// `[4-byte original length][1-byte flags]` plus the 1-byte minimal micro-header
/// inside the plaintext, plus the 16-byte AEAD tag.
///
/// Note: this constant reflects minimal overhead for raw/text payloads without
/// a filename. When a payload carries a filename, the micro-header spends an additional
/// `1 + name_len` bytes. Capacity reports (`max_raw_payload_bytes`) reflect this minimal baseline.
pub const BODY_OVERHEAD: usize = 4 + 1 + MICRO_OVERHEAD_MIN + TAG_LEN; // 22 bytes

/// Largest payload a decoded envelope may expand to (matches the header's
/// 26-bit length field, minus the minimal framing overhead and AEAD tag).
pub const MAX_PLAINTEXT_LEN: usize =
    (crate::stego::header::HEADER_LEN_MAX as usize).saturating_sub(BODY_OVERHEAD);

/// Domain separator of the V4 associated data.
const V4_AAD_PREFIX: &[u8] = b"strhide-content-envelope-v4\0";

/// Build the V4 AEAD associated data.
///
/// `AAD = prefix || format_id || base_header || extension` authenticates the
/// carrier format, every decoded header field and the whole extension area in
/// one tag; a bit flip anywhere fails decryption rather than yielding a
/// plausible-but-different decode.
pub fn build_v4_aad(format_id: u8, base_header: &[u8], extension: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(V4_AAD_PREFIX.len() + 1 + base_header.len() + extension.len());
    aad.extend_from_slice(V4_AAD_PREFIX);
    aad.push(format_id);
    aad.extend_from_slice(base_header);
    aad.extend_from_slice(extension);
    aad
}

/// Flag bit 0: the payload is compressed.
const FLAG_COMPRESSED: u8 = 0x01;

/// Bits 1..3 hold the compression algorithm id.
const COMPRESSION_SHIFT: u32 = 1;
const COMPRESSION_MASK: u8 = 0x07;

/// Compression algorithm id 0: Deflate (the only one implemented).
const COMPRESSION_DEFLATE: u8 = 0;

/// Derive a domain subkey using an explicit domain separation label.
pub fn derive_domain_subkey_with_label(
    ikm: &[u8],
    domain: Option<&str>,
    label: &[u8],
) -> Option<[u8; 32]> {
    let d = domain.filter(|s| !s.is_empty())?;
    let norm_d = normalize_nfc(d);
    let len_bytes = (norm_d.len() as u64).to_be_bytes();
    let mut info = Vec::with_capacity(label.len() + 8 + norm_d.len());
    info.extend_from_slice(label);
    info.extend_from_slice(&len_bytes);
    info.extend_from_slice(norm_d.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut subkey = [0u8; 32];
    hk.expand(&info, &mut subkey)
        .expect("HKDF expand domain subkey");
    Some(subkey)
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

/// Where one embedding gets its salt and nonce.
///
/// [`Freshness::Random`] is the production path and draws fresh bytes from the
/// OS. [`Freshness::Seeded`] derives both from a caller-supplied seed **plus a
/// binding context** (see [`Freshness::seeded_binding`]), so the same carrier,
/// payload, password and seed produce byte-identical stego files -- and two
/// *different* inputs can never collide on the same salt or nonce.
///
/// The binding matters because the AEAD key is derived from
/// `(password, salt)` and the PNG engine uses the salt as the KDF salt
/// directly: without a payload/cover binding, the same password and seed on
/// two inputs would reuse the whole `(key, nonce)` pair, and AES-GCM under a
/// repeated pair with different plaintexts is a two-time pad
/// (review 2026-10-25, M1).
///
/// Reproducibility holds for a fixed `git` revision and target triple. Two
/// things narrow it further:
///
/// * the DCT cost maps accumulate in `f32`, so a build with AVX2/FMA enabled
///   rounds differently from a scalar one; seeded runs therefore force the
///   scalar kernel (see `JpegParams::deterministic`);
/// * compression goes through `flate2`, whose output is stable for a pinned
///   version but not across backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Freshness {
    /// Fresh randomness per embedding.
    #[default]
    Random,
    /// Deterministic sequence derived from `seed` and the binding context.
    Seeded([u8; 32]),
}

impl Freshness {
    /// `true` when the caller asked for a reproducible run.
    pub fn is_seeded(&self) -> bool {
        matches!(self, Self::Seeded(_))
    }

    /// Binding context for seeded salt/nonce derivation:
    /// `SHA-256(carrier) || SHA-256(payload) || u8(format_id) || u8(major) ||
    /// u8(minor) || encoded_extension`.
    ///
    /// Salt and nonce live in the carrier header and are read back on
    /// extraction, so binding them to the inputs costs the reader nothing --
    /// but it guarantees that a seeded run replayed on different inputs can
    /// never reproduce an earlier `(key, nonce)` pair. The format id, envelope
    /// version and extension area are part of the binding so that the same
    /// cover/payload under the same seed still yields a different salt for a
    /// different wire format, format version or TLV set (plan §3.5).
    pub fn seeded_binding(
        carrier: &[u8],
        payload: &[u8],
        format_id: u8,
        extension: &[u8],
    ) -> Vec<u8> {
        use sha2::Digest as _;
        let version = crate::stego::header::CONTENT_ENVELOPE_VERSION;
        let mut out = Vec::with_capacity(64 + 3 + extension.len());
        out.extend_from_slice(&sha2::Sha256::digest(carrier));
        out.extend_from_slice(&sha2::Sha256::digest(payload));
        out.push(format_id);
        out.push(version >> 4);
        out.push(version & 0x0F);
        out.extend_from_slice(extension);
        out
    }

    /// Salt for embedding attempt `attempt` (0-based).
    ///
    /// An embedding retries up to [`EMBED_ATTEMPTS`](crate::stego::jpeg) times
    /// when a Huffman-limited block cannot be encoded, and each retry has to
    /// draw a *different* salt or a seeded run would repeat the same failure
    /// forever. Folding the attempt index into the derivation keeps the whole
    /// retry sequence reproducible. `binding` comes from
    /// [`Freshness::seeded_binding`] and is ignored by [`Freshness::Random`].
    pub fn salt(&self, attempt: u32, binding: &[u8]) -> [u8; SALT_LEN] {
        match self {
            Self::Random => random_salt(),
            Self::Seeded(seed) => derive_seeded(seed, b"salt", attempt, binding),
        }
    }

    /// AEAD nonce for embedding attempt `attempt` (0-based). See [`Self::salt`].
    pub fn nonce(&self, attempt: u32, binding: &[u8]) -> [u8; NONCE_LEN] {
        match self {
            Self::Random => random_nonce(),
            Self::Seeded(seed) => derive_seeded(seed, b"nonce", attempt, binding),
        }
    }
}

/// `HKDF-SHA256(seed, info = label || attempt || binding)`, with a domain
/// separator so a salt can never collide with a nonce derived from the same
/// seed.
fn derive_seeded<const N: usize>(
    seed: &[u8; 32],
    label: &[u8],
    attempt: u32,
    binding: &[u8],
) -> [u8; N] {
    let hk = Hkdf::<Sha256>::new(Some(b"strhide-reproducible-v2"), seed);
    let mut info = Vec::with_capacity(label.len() + 4 + binding.len());
    info.extend_from_slice(label);
    info.extend_from_slice(&attempt.to_be_bytes());
    info.extend_from_slice(binding);
    let mut out = [0u8; N];
    hk.expand(&info, &mut out)
        .expect("HKDF output for a salt/nonce is far below the 8160-byte limit");
    out
}

/// Sanitize a filename to prevent path traversal and ensure it fits in a u8 length byte (<= 255 bytes).
pub fn sanitize_filename(name: &str) -> Option<String> {
    let norm = normalize_nfc(name);
    let trimmed = norm.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return None;
    }
    // One implementation for both domains: `Path::file_name` treats `\` as an
    // ordinary character on Unix, so a Windows-style traversal name read on
    // Linux used to survive verbatim, and control bytes / reserved devices
    // were never filtered. `core::fs` handles separators on every platform.
    let clean = crate::core::fs::sanitize_filename(trimmed);
    if clean == crate::core::fs::FALLBACK_NAME && trimmed != crate::core::fs::FALLBACK_NAME {
        // The name sanitised down to the fallback, i.e. nothing usable was
        // left. Store no name at all instead of inventing "extracted.bin".
        return None;
    }
    // Truncate at UTF-8 boundary to at most 255 bytes
    let mut byte_limit = 255.min(clean.len());
    while !clean.is_char_boundary(byte_limit) {
        byte_limit -= 1;
    }
    let safe = &clean[..byte_limit];
    if safe.is_empty() {
        None
    } else {
        Some(safe.to_string())
    }
}

/// Encode `Payload` with the stealth micro-header into raw uncompressed bytes.
///
/// Format:
/// - `[0x00][data]` for text, raw bytes, or when filename is omitted.
/// - `[0x01][name_len: u8][name_bytes (UTF-8)][data]` for file payload with name.
pub fn encode_micro_header(payload: &Payload<'_>) -> Vec<u8> {
    if payload.kind() == PayloadKind::File
        && let Some(raw_name) = payload.name()
        && let Some(safe_name) = sanitize_filename(raw_name)
    {
        let name_bytes = safe_name.as_bytes();
        let mut out = Vec::with_capacity(2 + name_bytes.len() + payload.len());
        out.push(MICRO_TAG_FILE);
        out.push(name_bytes.len() as u8);
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(payload.as_bytes());
        return out;
    }
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(MICRO_TAG_TEXT_OR_RAW);
    out.extend_from_slice(payload.as_bytes());
    out
}

/// Decode a decompressed plain buffer into a [`Payload`], unpacking the micro-header.
pub fn decode_micro_header(plain: &[u8]) -> Result<Payload<'static>, StrHideError> {
    if plain.is_empty() {
        return Err(StrHideError::CorruptedData(
            "Empty micro-envelope plaintext".into(),
        ));
    }
    match plain[0] {
        MICRO_TAG_TEXT_OR_RAW => Ok(Payload::owned(plain[1..].to_vec())),
        MICRO_TAG_FILE => {
            if plain.len() < 2 {
                return Err(StrHideError::CorruptedData(
                    "Truncated file micro-header".into(),
                ));
            }
            let name_len = plain[1] as usize;
            if plain.len() < 2 + name_len {
                return Err(StrHideError::CorruptedData(
                    "Truncated filename in micro-header".into(),
                ));
            }
            let name_str = std::str::from_utf8(&plain[2..2 + name_len]).map_err(|_| {
                StrHideError::CorruptedData("Filename in micro-header is not valid UTF-8".into())
            })?;
            let safe_name =
                sanitize_filename(name_str).unwrap_or_else(|| "extracted.bin".to_string());
            let data = plain[2 + name_len..].to_vec();
            Ok(Payload::file(safe_name, &data).into_owned())
        }
        tag => Err(StrHideError::CorruptedData(format!(
            "Unknown micro-header tag {tag:#04x}"
        ))),
    }
}

/// Compress (when profitable) and frame the payload with stealth micro-header as AEAD plaintext.
///
/// `[4B original length][1B flags][micro-header][payload bytes]`. The length is known before
/// encryption, which is what lets the caller size the header field first and
/// only then encrypt with the finished header as associated data.
pub fn build_plaintext(payload: &Payload<'_>) -> Result<Vec<u8>, StrHideError> {
    let uncompressed = encode_micro_header(payload);
    if uncompressed.len() > MAX_PLAINTEXT_LEN {
        return Err(StrHideError::General(format!(
            "Payload of {} bytes (with micro-header) exceeds the {MAX_PLAINTEXT_LEN}-byte envelope limit",
            uncompressed.len()
        )));
    }
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&uncompressed)?;
    let compressed = encoder.finish()?;

    let (body, flags) = if compressed.len() < uncompressed.len() {
        (
            compressed,
            FLAG_COMPRESSED | (COMPRESSION_DEFLATE << COMPRESSION_SHIFT),
        )
    } else {
        (uncompressed.clone(), 0u8)
    };

    let mut plaintext = Vec::with_capacity(5 + body.len());
    plaintext.extend_from_slice(&(uncompressed.len() as u32).to_be_bytes());
    plaintext.push(flags);
    plaintext.extend_from_slice(&body);
    Ok(plaintext)
}

/// Helper to build framed plaintext directly from raw bytes (no filename, text/raw tag).
pub fn build_plaintext_bytes(bytes: &[u8]) -> Result<Vec<u8>, StrHideError> {
    build_plaintext(&Payload::bytes(bytes))
}

/// V4 encryption: the suite id alone selects the AEAD; KDF parameters live in
/// the L1/L2/L3 derivation, never in the suite.
pub fn encrypt_v4_with_aad(
    suite: CipherSuiteId,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, StrHideError> {
    match suite {
        CipherSuiteId::Aes256Gcm => {
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
        CipherSuiteId::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| StrHideError::Password(format!("Cipher init failed: {e}")))?;
            let nonce = chacha20poly1305::Nonce::from(*nonce);
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

/// V4 decryption and unframing, enforcing [`ExtractParams`] before allocation.
///
/// Authentication failure and every structural failure collapse to
/// `NoHiddenData`, so a wrong password is indistinguishable from an untouched
/// carrier.
pub fn unpack_v4_envelope_parts(
    suite: CipherSuiteId,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    limits: &ExtractParams,
) -> Result<Payload<'static>, StrHideError> {
    let no_hidden = || StrHideError::NoHiddenData("No valid payload found".into());
    if ciphertext.len() < 5 + suite.tag_len() {
        return Err(no_hidden());
    }

    let plaintext = match suite {
        CipherSuiteId::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| no_hidden())?;
            let nonce = Nonce::from(*nonce);
            cipher
                .decrypt(
                    &nonce,
                    aes_gcm::aead::Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| no_hidden())?
        }
        CipherSuiteId::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| no_hidden())?;
            let nonce = chacha20poly1305::Nonce::from(*nonce);
            cipher
                .decrypt(
                    &nonce,
                    aes_gcm::aead::Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| no_hidden())?
        }
    };

    if plaintext.len() < 5 {
        return Err(no_hidden());
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
            return Err(StrHideError::CorruptedData(
                "Plaintext length mismatch".into(),
            ));
        }
        if orig_len > limits.max_payload_bytes {
            return Err(StrHideError::CorruptedData(format!(
                "Envelope claims a {orig_len}-byte payload, above the {}-byte limit",
                limits.max_payload_bytes
            )));
        }
        return decode_micro_header(body);
    }

    if algorithm != COMPRESSION_DEFLATE {
        return Err(StrHideError::UnsupportedVersion(format!(
            "Envelope uses unsupported compression algorithm {algorithm}"
        )));
    }
    if orig_len > limits.max_payload_bytes {
        return Err(StrHideError::CorruptedData(format!(
            "Envelope claims a {orig_len}-byte payload, above the {}-byte limit",
            limits.max_payload_bytes
        )));
    }

    let mut decoder = DeflateDecoder::new(body).take(orig_len as u64 + 1);
    let mut decompressed = Vec::with_capacity(orig_len.min(1 << 20));
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|_| StrHideError::CorruptedData("Decompression failed".into()))?;
    if decompressed.len() != orig_len {
        return Err(StrHideError::CorruptedData(
            "Decompressed length mismatch".into(),
        ));
    }
    decode_micro_header(&decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AES: CipherSuiteId = CipherSuiteId::Aes256Gcm;
    const CHACHA: CipherSuiteId = CipherSuiteId::ChaCha20Poly1305;

    fn key() -> [u8; 32] {
        [0x42; 32]
    }

    fn encrypt(
        suite: CipherSuiteId,
        key: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        encrypt_v4_with_aad(suite, key, nonce, aad, plaintext).expect("encrypt")
    }

    fn unpack(
        suite: CipherSuiteId,
        key: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Payload<'static>, StrHideError> {
        unpack_v4_envelope_parts(
            suite,
            key,
            nonce,
            aad,
            ciphertext,
            &ExtractParams::default(),
        )
    }

    /// Seeded derivations must reproduce for identical inputs and must move
    /// with either half of the (cover, payload) binding: the PNG engine uses
    /// the salt directly as the KDF salt, so an unbound seeded salt/nonce
    /// replayed on different inputs would reuse an AEAD (key, nonce) pair
    /// (review 2026-10-25, M1).
    #[test]
    fn seeded_derivations_bind_to_cover_and_payload() {
        let f = Freshness::Seeded([9u8; 32]);
        let a = Freshness::seeded_binding(b"cover-1", b"payload", 1, &[]);
        let other_cover = Freshness::seeded_binding(b"cover-2", b"payload", 1, &[]);
        let other_payload = Freshness::seeded_binding(b"cover-1", b"other-payload", 1, &[]);
        let other_format = Freshness::seeded_binding(b"cover-1", b"payload", 4, &[]);
        let other_ext = Freshness::seeded_binding(b"cover-1", b"payload", 1, &[0x02, 0x01, 0xAA]);

        assert_eq!(
            f.salt(0, &a),
            f.salt(0, &a),
            "the same (cover, payload, seed) must reproduce exactly"
        );
        assert_ne!(f.salt(0, &a), f.salt(0, &other_cover));
        assert_ne!(f.salt(0, &a), f.salt(0, &other_payload));
        assert_ne!(
            f.salt(0, &a),
            f.salt(0, &other_format),
            "the wire format id must separate the binding"
        );
        assert_ne!(
            f.salt(0, &a),
            f.salt(0, &other_ext),
            "the extension area must separate the binding"
        );
        assert_ne!(f.nonce(0, &a), f.nonce(0, &other_cover));
        assert_ne!(f.nonce(0, &a), f.nonce(0, &other_payload));
        assert_ne!(
            f.salt(0, &a),
            f.salt(1, &a),
            "the retry attempt index must still vary the derivation"
        );
    }

    #[test]
    fn roundtrip_with_and_without_compression() {
        let key = key();
        let nonce = [7u8; NONCE_LEN];
        let aad = b"header bytes";

        // Compressible payload takes the Deflate path.
        let repetitive = vec![0x21u8; 4096];
        let plaintext = build_plaintext_bytes(&repetitive).unwrap();
        assert_eq!(plaintext[4] & FLAG_COMPRESSED, FLAG_COMPRESSED);
        let ct = encrypt(AES, &key, &nonce, aad, &plaintext);
        let out = unpack(AES, &key, &nonce, aad, &ct).unwrap();
        assert_eq!(out.as_bytes(), repetitive.as_slice());

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
        let plaintext = build_plaintext_bytes(&random).unwrap();
        assert_eq!(plaintext[4] & FLAG_COMPRESSED, 0);
        let ct = encrypt(AES, &key, &nonce, aad, &plaintext);
        let out = unpack(AES, &key, &nonce, aad, &ct).unwrap();
        assert_eq!(out.as_bytes(), random.as_slice());
    }

    #[test]
    fn aad_and_nonce_and_key_are_all_bound() {
        let key = key();
        let nonce = [2u8; NONCE_LEN];
        let plaintext = build_plaintext_bytes(b"bound payload").unwrap();
        let ct = encrypt(AES, &key, &nonce, b"header-a", &plaintext);

        assert!(matches!(
            unpack(AES, &key, &nonce, b"header-b", &ct),
            Err(StrHideError::NoHiddenData(_))
        ));
        let wrong_nonce = [3u8; NONCE_LEN];
        assert!(unpack(AES, &key, &wrong_nonce, b"header-a", &ct).is_err());
        let wrong_key = [0x43; 32];
        assert!(unpack(AES, &wrong_key, &nonce, b"header-a", &ct).is_err());
    }

    #[test]
    fn reserved_flag_bits_and_unknown_algorithms_are_rejected() {
        let key = key();
        let nonce = [4u8; NONCE_LEN];

        // Hand-build a plaintext with reserved bits set.
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&3u32.to_be_bytes());
        plaintext.push(0x80);
        plaintext.extend_from_slice(b"abc");
        let ct = encrypt(AES, &key, &nonce, b"aad", &plaintext);
        assert!(matches!(
            unpack(AES, &key, &nonce, b"aad", &ct),
            Err(StrHideError::CorruptedData(_))
        ));

        // Compressed flag with an unknown algorithm id.
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&3u32.to_be_bytes());
        plaintext.push(FLAG_COMPRESSED | (2 << COMPRESSION_SHIFT));
        plaintext.extend_from_slice(b"abc");
        let ct = encrypt(AES, &key, &nonce, b"aad", &plaintext);
        let err = unpack(AES, &key, &nonce, b"aad", &ct).unwrap_err();
        assert!(
            matches!(err, StrHideError::UnsupportedVersion(_)),
            "{err:?}"
        );
        assert!(err.to_string().contains("compression algorithm"), "{err}");
    }

    #[test]
    fn empty_and_oversized_payloads_are_handled() {
        let key = key();
        let nonce = [6u8; NONCE_LEN];
        let plaintext = build_plaintext_bytes(b"").unwrap();
        let ct = encrypt(AES, &key, &nonce, b"aad", &plaintext);
        assert_eq!(
            unpack(AES, &key, &nonce, b"aad", &ct).unwrap().as_bytes(),
            b""
        );

        // A ciphertext shorter than the tag cannot be a valid envelope.
        assert!(unpack(AES, &key, &nonce, b"aad", &ct[..4]).is_err());
    }

    #[test]
    fn micro_header_roundtrips_file_and_text() {
        let key = key();
        let nonce = [7u8; NONCE_LEN];
        let aad = b"header aad";

        // 1. Text / raw without filename
        let text_p = Payload::text("hello world");
        let pt = build_plaintext(&text_p).unwrap();
        let ct = encrypt(AES, &key, &nonce, aad, &pt);
        let out = unpack(AES, &key, &nonce, aad, &ct).unwrap();
        assert_eq!(out.as_bytes(), b"hello world");
        assert_eq!(out.name(), None);

        // 2. File with filename preserved
        let file_p = Payload::file("notes.txt", b"secret notes");
        let pt = build_plaintext(&file_p).unwrap();
        let ct = encrypt(AES, &key, &nonce, aad, &pt);
        let out = unpack(AES, &key, &nonce, aad, &ct).unwrap();
        assert_eq!(out.as_bytes(), b"secret notes");
        assert_eq!(out.name(), Some("notes.txt"));
        assert_eq!(out.kind(), PayloadKind::File);

        // 3. File with keep_filename = false (--no-filename)
        let anon_p = Payload::bytes(b"secret notes");
        let pt_anon = build_plaintext(&anon_p).unwrap();
        let ct_anon = encrypt(AES, &key, &nonce, aad, &pt_anon);
        let out_anon = unpack(AES, &key, &nonce, aad, &ct_anon).unwrap();
        assert_eq!(out_anon.as_bytes(), b"secret notes");
        assert_eq!(out_anon.name(), None);

        // 4. Path traversal prevention
        let dangerous_p = Payload::file("../../etc/shadow", b"secret data");
        let pt_dang = build_plaintext(&dangerous_p).unwrap();
        let ct_dang = encrypt(AES, &key, &nonce, aad, &pt_dang);
        let out_dang = unpack(AES, &key, &nonce, aad, &ct_dang).unwrap();
        assert_eq!(out_dang.name(), Some("shadow"));
    }

    /// Suite 2 is ChaCha20-Poly1305: a full round trip, AAD binding, ciphertext
    /// tamper and key tamper must behave exactly like suite 1.
    #[test]
    fn chacha_suite_roundtrip_and_tamper_rejected() {
        let key = key();
        let nonce = [0x5Au8; NONCE_LEN];
        let aad = b"v4 header";
        let plaintext = build_plaintext_bytes(b"chacha payload").unwrap();

        let ct = encrypt(CHACHA, &key, &nonce, aad, &plaintext);
        assert_eq!(ct.len(), plaintext.len() + TAG_LEN);
        let out = unpack(CHACHA, &key, &nonce, aad, &ct).unwrap();
        assert_eq!(out.as_bytes(), b"chacha payload");

        // Both directions: AES ciphertext is not a ChaCha envelope and vice versa.
        assert!(unpack(AES, &key, &nonce, aad, &ct).is_err());
        let aes_ct = encrypt(AES, &key, &nonce, aad, &plaintext);
        assert!(unpack(CHACHA, &key, &nonce, aad, &aes_ct).is_err());

        // Tampered ciphertext / AAD / key all collapse to NoHiddenData.
        let mut tampered = ct.clone();
        tampered[0] ^= 0x01;
        assert!(matches!(
            unpack(CHACHA, &key, &nonce, aad, &tampered),
            Err(StrHideError::NoHiddenData(_))
        ));
        assert!(matches!(
            unpack(CHACHA, &key, &nonce, b"other header", &ct),
            Err(StrHideError::NoHiddenData(_))
        ));
        assert!(matches!(
            unpack(CHACHA, &[0x43; 32], &nonce, aad, &ct),
            Err(StrHideError::NoHiddenData(_))
        ));
    }
}

#[cfg(test)]
mod v4_aad_tests {
    use super::*;

    #[test]
    fn aad_prefix_format_and_areas_are_all_covered() {
        let base = [0xAAu8; 64];
        let ext = [0xBBu8; 4];
        let png = build_v4_aad(1, &base, &ext);
        assert_eq!(png.len(), 28 + 1 + 64 + 4);
        assert_eq!(&png[..28], b"strhide-content-envelope-v4\0");
        assert_eq!(png[28], 1);
        assert_eq!(&png[29..93], &base);
        assert_eq!(&png[93..], &ext);

        let jpeg = build_v4_aad(4, &base[..44], &ext);
        assert_ne!(png, jpeg, "format id must separate the AAD");
        let no_ext = build_v4_aad(1, &base, &[]);
        assert_ne!(png, no_ext, "extension bytes must be authenticated");
    }
}
