//! Cryptographic and compression primitives for strhide.
//!
//! This module is the single source of truth for the envelope's crypto
//! contract: key derivation, AEAD encryption, chunk framing, and the
//! decompression bomb bound. It is **not** a general-purpose crypto library —
//! every function assumes it is being driven by [`crate::structure`] and the wire
//! format in [`crate::structure::envelope`].
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
use flate2::write::DeflateDecoder as WriteDeflateDecoder;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use unicode_normalization::UnicodeNormalization;
pub use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::errors::StrHideError;

/// Size of the fixed AAD prefix the structure envelope binds into every seal.
///
/// The associated data itself is variable length — the structure envelope
/// appends its two length fields and the hint body, the content domain builds
/// its own V4 AAD — so the sealing functions take a plain slice. This constant
/// only describes the fixed prefix, and is what the tests below exercise.
#[doc(hidden)]
pub const AAD_SIZE: usize = 80;

/// Length of an AES-GCM authentication tag.
pub const AEAD_TAG_LEN: usize = 16;

/// Wire overhead of one framed payload chunk: the 4-byte length prefix plus the
/// AES-GCM tag.
#[doc(hidden)]
pub const CHUNK_OVERHEAD: usize = 4 + AEAD_TAG_LEN;

/// Number of chunks `plain_len` bytes occupy at `chunk_size`.
///
/// At least one, even for an empty payload: [`encrypt_stream_to_chunks`] always
/// emits a final chunk so the reader can tell "no payload" from "truncated".
#[doc(hidden)]
pub fn chunk_count(plain_len: u64, chunk_size: usize) -> u64 {
    // `max(1)` on the *divisor*: this is a `pub fn`, and a caller outside the
    // crate can pass 0. `LocalParams::validate` rejects that, but relying on it
    // here made the function divide by zero (a panic, and with `panic = "abort"`
    // a process kill) instead of degrading gracefully.
    plain_len.div_ceil(chunk_size.max(1) as u64).max(1)
}

/// Ciphertext length of the framed payload for `plain_len` bytes of plaintext.
///
/// This is the single source of truth for the framing overhead. The engine
/// needs it *before* writing anything, to size the envelope and pick a strategy;
/// when it spelled the constants out itself, any change to the framing would
/// have made `auto` choose a strategy the injector then rejected.
#[doc(hidden)]
pub fn framed_len(plain_len: u64, chunk_size: usize) -> u64 {
    plain_len + chunk_count(plain_len, chunk_size) * CHUNK_OVERHEAD as u64
}

/// Default plaintext payload chunk size. Each chunk is independently sealed
/// with AES-256-GCM and prefixed by its own u32 length on the wire.
///
/// The reader never needs this value: chunk framing is self-describing, so
/// [`crate::params::LocalParams::chunk_size`] can pick anything up to
/// [`MAX_CHUNK_SIZE`] without making an envelope unreadable.
pub const CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2MB

/// Hard ceiling on a single plaintext chunk, enforced on both sides: the writer
/// refuses a larger `chunk_size` and the reader refuses a chunk length above
/// it, so a crafted envelope cannot request a 4 GiB allocation.
pub const MAX_CHUNK_SIZE: usize = 64 * 1024 * 1024; // 64MB

/// PBKDF2-HMAC-SHA256 iteration count. Raising this invalidates envelopes
/// written with older versions, so it is treated as a wire-format constant.
#[doc(hidden)]
pub const PBKDF2_ITERATIONS: u32 = 100_000;

/// Fixed L1 PBKDF2 cost of the content-domain V4 envelope.
///
/// The content envelope no longer has a per-suite KDF cost: `suite_id` only
/// selects the AEAD. One password run always pays this many iterations, so a
/// forged header cannot choose a cheaper (or hugely more expensive) KDF.
#[doc(hidden)]
pub const CONTENT_L1_PBKDF2_ITERATIONS: u32 = 200_000;

/// Credential supplied to the content-domain key schedule.
///
/// Deliberately does **not** implement `Debug`: a password or file key must
/// never end up in a log line. Options structs that hold one redact it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Credential<'a> {
    /// Human password or deployment string; NFC-normalized and run through
    /// PBKDF2 for [`CONTENT_L1_PBKDF2_ITERATIONS`] iterations.
    Password(&'a str),
    /// 32-byte high-entropy key; skips PBKDF2 and goes straight to HKDF.
    FileKey(&'a [u8; 32]),
}

/// Wire ids for the content-domain AEAD suite table (append-only).
#[non_exhaustive]
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuiteId {
    /// AES-256-GCM, 16-byte tag.
    Aes256Gcm = 1,
    /// ChaCha20-Poly1305, 16-byte tag.
    ChaCha20Poly1305 = 2,
}

impl CipherSuiteId {
    /// Map a wire `suite_id` to a known suite. `0` and unknown ids are invalid.
    pub const fn from_u16(id: u16) -> Option<Self> {
        match id {
            1 => Some(Self::Aes256Gcm),
            2 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// Authentication tag length in bytes (both suites use a 16-byte tag).
    pub const fn tag_len(self) -> usize {
        16
    }

    /// Stable human-readable name for diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }

    /// Wire value written into the header.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Default internal secret used when the user does not specify a password.
/// All envelopes are uniformly encrypted with AES-256-GCM and Deflate-compressed,
/// eliminating plaintext leakage (no plaintext payload, metadata, or host SHA-256 in hex view).
pub const BUILTIN_DEFAULT_KEY: &str =
    "strhide::structure::envelope::v2::default::builtin::public::secret";

/// NFC-normalize a user-supplied string (password, hint, filename).
///
/// Passwords typed on macOS / iOS may arrive as NFD decomposed form; deriving
/// keys from the raw bytes would silently produce different envelopes on
/// different platforms. All password-bearing call sites funnel through here.
#[doc(hidden)]
pub fn normalize_nfc(s: &str) -> String {
    s.nfc().collect::<String>()
}

// Test-only count of PBKDF2 runs, used to verify that operations do
// not redundantly re-derive keys for the same (password, salt) pair.
//
// Thread-local rather than global so parallel tests cannot pollute measurements.
#[cfg(test)]
thread_local! {
    static PBKDF2_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_pbkdf2_calls() {
    PBKDF2_CALLS.with(|c| c.set(0));
}

#[cfg(test)]
pub(crate) fn pbkdf2_calls() -> usize {
    PBKDF2_CALLS.with(std::cell::Cell::get)
}

/// PBKDF2 over the NFC-normalised password, followed by HKDF-SHA256 with the
/// salt as the HKDF salt.
///
/// This is the one expensive step of the whole envelope (100k HMAC-SHA256
/// iterations, 30–60 ms), and every consumer below shares the same
/// (password, salt) pair — so it is computed exactly once per pair.
fn derive_ikm(password: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    #[cfg(test)]
    PBKDF2_CALLS.with(|c| c.set(c.get() + 1));
    let norm_pwd = Zeroizing::new(normalize_nfc(password));
    let mut ikm = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(norm_pwd.as_bytes(), salt, PBKDF2_ITERATIONS, &mut *ikm);
    ikm
}

/// Everything one (password, salt) pair derives.
///
/// Payload key, metadata key and header mask are three HKDF expansions of the
/// *same* IKM, so they are produced together. Before this existed a single
/// `read` ran PBKDF2 four to five times over the same pair (twice for the
/// stealth magics, once for the keys, twice for the header mask), which is
/// 100–250 ms of pure waste per operation.
///
/// Deliberately not `Copy`: a `Copy` secret cannot carry a destructor, and
/// removing `Copy` after 1.0 would itself be a breaking change. Callers that
/// need a second owner ask for `clone()`.
#[derive(Clone)]
pub struct PasswordSecrets {
    /// AES-256-GCM key for the chunked payload.
    pub payload_key: [u8; 32],
    /// AES-256-GCM key for the metadata block.
    pub meta_key: [u8; 32],
    /// 76-byte keystream masking the sensitive header fields.
    pub header_mask: [u8; 76],
}

impl Drop for PasswordSecrets {
    /// Overwrite the key material when the last owner goes away.
    ///
    /// All three buffers are expansions of one PBKDF2 output, so a heap dump
    /// that still holds them hands over the entire hierarchy for that carrier.
    fn drop(&mut self) {
        self.payload_key.zeroize();
        self.meta_key.zeroize();
        self.header_mask.zeroize();
    }
}

/// Overwrite `buf` in place so the zeroing cannot be optimised away.
///
/// Backed by [`Zeroize::zeroize`], preventing compiler dead-store elimination.
pub(crate) fn zero_bytes(buf: &mut [u8]) {
    buf.zeroize();
}

/// Derive the 32-byte payload and metadata keys from a password and salt.
///
/// The password is NFC-normalized, run through PBKDF2, then HKDF-Expand'd
/// twice with distinct info labels so the two keys are independent.
pub fn derive_keys(password: &str, salt: &[u8]) -> Result<([u8; 32], [u8; 32]), StrHideError> {
    let ikm = derive_ikm(password, salt);
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), &ikm[..]);
    let mut payload_key = [0u8; 32];
    let mut meta_key = [0u8; 32];

    hk.expand(b"strhide-payload", &mut payload_key)
        .map_err(|e| StrHideError::CryptoError(format!("HKDF expand payload error: {e}")))?;
    hk.expand(b"strhide-metadata", &mut meta_key)
        .map_err(|e| StrHideError::CryptoError(format!("HKDF expand metadata error: {e}")))?;

    Ok((payload_key, meta_key))
}

/// Derive every secret one (password, salt) pair yields, with a single PBKDF2.
#[doc(hidden)]
pub fn derive_all(password: &str, salt: &[u8]) -> Result<PasswordSecrets, StrHideError> {
    let ikm = derive_ikm(password, salt);
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), &ikm[..]);
    let mut secrets = PasswordSecrets {
        payload_key: [0u8; 32],
        meta_key: [0u8; 32],
        header_mask: [0u8; 76],
    };

    hk.expand(b"strhide-payload", &mut secrets.payload_key)
        .map_err(|e| StrHideError::CryptoError(format!("HKDF expand payload error: {e}")))?;
    hk.expand(b"strhide-metadata", &mut secrets.meta_key)
        .map_err(|e| StrHideError::CryptoError(format!("HKDF expand metadata error: {e}")))?;
    hk.expand(b"strhide-header-mask-v1", &mut secrets.header_mask)
        .map_err(|e| StrHideError::CryptoError(format!("HKDF expand header mask error: {e}")))?;

    Ok(secrets)
}

/// Derive the 8-byte header magic and 4-byte trailer magic used in stealth
/// mode.
///
/// Without the password these bytes look like random data, so a forensic scan
/// for the standard ASCII/binary magics finds nothing.
///
/// Note the salt here is the profile's *domain*, not the envelope salt: the
/// magics have to be reproducible before any header (and therefore its salt)
/// has been read. That makes this a separate PBKDF2 run from
/// [`derive_all`], not a shared one.
pub fn derive_stealth_magics(
    password: &str,
    salt: &[u8],
) -> Result<([u8; 8], [u8; 4]), StrHideError> {
    let ikm = derive_ikm(password, salt);
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), &ikm[..]);
    let mut header_magic = [0u8; 8];
    let mut trailer_magic = [0u8; 4];

    hk.expand(b"strhide-stealth-header", &mut header_magic)
        .map_err(|e| StrHideError::CryptoError(format!("HKDF expand stealth header error: {e}")))?;
    hk.expand(b"strhide-stealth-trailer", &mut trailer_magic)
        .map_err(|e| {
            StrHideError::CryptoError(format!("HKDF expand stealth trailer error: {e}"))
        })?;

    Ok((header_magic, trailer_magic))
}

/// Derive a 76-byte deterministic keystream from password and salt to mask
/// the sensitive fields of EnvelopeHeader in stealth mode.
#[doc(hidden)]
pub fn derive_header_mask(password: &str, salt: &[u8]) -> Result<[u8; 76], StrHideError> {
    let ikm = derive_ikm(password, salt);
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), &ikm[..]);
    let mut mask = [0u8; 76];
    hk.expand(b"strhide-header-mask-v1", &mut mask)
        .map_err(|e| StrHideError::CryptoError(format!("HKDF expand header mask error: {e}")))?;
    Ok(mask)
}

/// Derive a 4-byte CRC mask from trailer magic in stealth mode.
/// This prevents public IEEE 802.3 CRC32 scanning from detecting the trailer
/// without knowledge of the password.
#[doc(hidden)]
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

/// Derive a 10-byte deterministic keystream from the **8-byte envelope header
/// magic** to mask the remaining fields of `ChannelHeader` (version, flags,
/// `ube_len`, `slack_off`).
///
/// Derived from the envelope header magic in the UBE header at channel positions
/// `112..176`. In stealth mode it is password-derived and distinct from the
/// visible 4-byte channel magic, preventing unauthenticated unmasking of lengths.
/// In standard mode it uses `STANDARD_HEADER_MAGIC` for format obfuscation.
pub fn derive_channel_header_mask(envelope_header_magic: &[u8; 8]) -> [u8; 10] {
    let hk = hkdf::Hkdf::<Sha256>::new(None, envelope_header_magic);
    let mut mask = [0u8; 10];
    hk.expand(b"strhide-pe-channel-mask-v2", &mut mask)
        .expect("HKDF-Expand for 10-byte channel mask never fails");
    mask
}

/// Per-chunk nonce: the 8-byte prefix of `base_nonce` is preserved, and the
/// low 4 bytes are XOR-ed with `chunk_index`. Reusing `base_nonce` across
/// chunks is safe because every resulting nonce is distinct.
#[doc(hidden)]
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
#[doc(hidden)]
pub fn make_meta_nonce(base_nonce: &[u8; 12]) -> [u8; 12] {
    let counter_bytes: [u8; 4] = base_nonce[8..12].try_into().unwrap();
    let counter = u32::from_le_bytes(counter_bytes) ^ 0xFFFFFFFF;
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&base_nonce[0..8]);
    nonce[8..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Seal the (compact or JSON) metadata block with the metadata subkey.
///
/// `aad` is the caller's associated data. The structure domain passes
/// `EnvelopeHeader::auth_aad` (header prefix + lengths + hint), so any later
/// tamper of those fields breaks this tag; the content domain passes its own
/// V4 AAD. The length is deliberately not fixed here: the authenticated set is
/// whatever the envelope layout says it is.
pub fn encrypt_metadata(
    meta_bytes: &[u8],
    meta_key: &[u8; 32],
    base_nonce: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, StrHideError> {
    let nonce = make_meta_nonce(base_nonce);
    let cipher = Aes256Gcm::new_from_slice(meta_key)
        .map_err(|e| StrHideError::CryptoError(format!("Invalid key for AES-GCM: {e}")))?;
    let payload = Payload {
        msg: meta_bytes,
        aad,
    };
    cipher
        .encrypt(&Nonce::from(nonce), payload)
        .map_err(|e| StrHideError::CryptoError(format!("Metadata encryption failed: {e}")))
}

/// Open the metadata block. The AEAD tag authenticates both the key and the
/// ciphertext, so a wrong password and tampered bytes are indistinguishable:
/// a failed tag is reported as
/// [`CorruptedData`](StrHideError::CorruptedData) with the message
/// "Wrong password or corrupted metadata", rather than pretending callers can
/// tell the two apart.
pub fn decrypt_metadata(
    meta_ciphertext: &[u8],
    meta_key: &[u8; 32],
    base_nonce: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, StrHideError> {
    let nonce = make_meta_nonce(base_nonce);
    let cipher = Aes256Gcm::new_from_slice(meta_key)
        .map_err(|e| StrHideError::CryptoError(format!("Invalid key for AES-GCM: {e}")))?;
    let payload = Payload {
        msg: meta_ciphertext,
        aad,
    };
    cipher
        .decrypt(&Nonce::from(nonce), payload)
        .map_err(|_| StrHideError::CorruptedData("Wrong password or corrupted metadata".into()))
}

/// Read `reader` to EOF, seal it in `chunk_size`-byte AES-256-GCM chunks,
/// and write the length-prefixed chunk stream to `writer`.
///
/// `chunk_size` is a writer-only knob ([`crate::params::LocalParams::chunk_size`]):
/// it never has to be communicated, because each chunk carries its own length
/// and the final chunk is identified by the byte budget recorded in the header
/// (see [`decrypt_stream_from_chunks`]).
///
/// Returns the total number of ciphertext bytes written (chunk lengths +
/// ciphertext + GCM tags). An empty input still produces one empty final
/// chunk so the reader can distinguish "no payload" from "truncated stream".
pub fn encrypt_stream_to_chunks<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    payload_key: &[u8; 32],
    base_nonce: &[u8; 12],
    fixed_header_aad: &[u8],
    chunk_size: usize,
) -> Result<u64, StrHideError> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        // A `debug_assert!` here was the only check: release builds silently
        // emitted one empty chunk for `chunk_size == 0` and wrote an unreadable
        // stream for an oversized one.
        return Err(StrHideError::InvalidArgument(format!(
            "chunk_size must be in 1..={MAX_CHUNK_SIZE} bytes, got {chunk_size}"
        )));
    }
    let cipher = Aes256Gcm::new_from_slice(payload_key)
        .map_err(|e| StrHideError::CryptoError(format!("Invalid key for AES-GCM: {e}")))?;

    let mut current_chunk = Vec::with_capacity(chunk_size);
    let mut buf = [0u8; 64 * 1024];

    // Read first chunk
    while current_chunk.len() < chunk_size {
        let to_read = std::cmp::min(chunk_size - current_chunk.len(), buf.len());
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
        let mut chunk_aad = Vec::with_capacity(fixed_header_aad.len() + 9);
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
            .map_err(|e| StrHideError::CryptoError(format!("AEAD encryption failed: {e}")))?;

        let chunk_len = encrypted.len() as u32;
        writer.write_all(&chunk_len.to_le_bytes())?;
        writer.write_all(&encrypted)?;
        return Ok(4 + encrypted.len() as u64);
    }

    let mut next_chunk = Vec::with_capacity(chunk_size);

    loop {
        // Read next chunk to determine if current_chunk is last
        next_chunk.clear();
        while next_chunk.len() < chunk_size {
            let to_read = std::cmp::min(chunk_size - next_chunk.len(), buf.len());
            let n = reader.read(&mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            next_chunk.extend_from_slice(&buf[..n]);
        }

        let is_last = next_chunk.is_empty();
        let chunk_nonce = make_chunk_nonce(base_nonce, chunk_index);

        let mut chunk_aad = Vec::with_capacity(fixed_header_aad.len() + 9);
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
            .map_err(|e| StrHideError::CryptoError(format!("AEAD encryption failed: {e}")))?;

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
/// trusted; individual chunk lengths are still capped at the remaining budget
/// (and at [`MAX_CHUNK_SIZE`]) to reject a forged envelope that asks for a
/// giant allocation.
///
/// **Read-side decoupling:** no chunk size is negotiated or assumed. The upper
/// bound is `min(bytes left in the payload region, MAX_CHUNK_SIZE)`, which
/// accepts any chunk size the writer chose and still bounds allocation by the
/// (authenticated) total size.
pub fn decrypt_stream_from_chunks<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    payload_key: &[u8; 32],
    base_nonce: &[u8; 12],
    fixed_header_aad: &[u8],
    total_payload_bytes: u64,
) -> Result<u64, StrHideError> {
    let cipher = Aes256Gcm::new_from_slice(payload_key)
        .map_err(|e| StrHideError::CryptoError(format!("Invalid key for AES-GCM: {e}")))?;

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

        // Upper bound: the declared payload region is authenticated, so whatever
        // is left in it is the true ceiling for this chunk (the last chunk ends
        // exactly at the region boundary). (MAX_CHUNK_SIZE + AEAD_TAG_LEN)
        // additionally bounds a single allocation. Compute *after* consuming
        // the 4-byte prefix, or a legitimate final chunk would look oversized.
        let remaining = total_payload_bytes.saturating_sub(bytes_consumed);
        let max_cipher_chunk = (MAX_CHUNK_SIZE + AEAD_TAG_LEN) as u64;
        let max_chunk = remaining.min(max_cipher_chunk) as usize;
        if chunk_len > max_chunk {
            return Err(StrHideError::CorruptedData(format!(
                "Chunk length {chunk_len} exceeds maximum {max_chunk} at chunk {chunk_index}"
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
        let mut chunk_aad = Vec::with_capacity(fixed_header_aad.len() + 9);
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

pub(crate) use super::compress::{COMPRESSION_PROBE_MIN_BYTES, probe_compressibility};
/// Compress in_stream using raw deflate at `level` (0..=9).
///
/// The level is writer-only: the decoder always inflates raw deflate and never
/// consults it, so envelopes produced at different levels are mutually
pub use super::compress::{compress_stream, decompress_stream};

/// One-shot SHA-256 of an in-memory buffer.
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Streamed SHA-256: reads `reader` to EOF in 64 KiB blocks, never
/// materializing the whole input. Used for hashing large carriers.
///
/// `R: ?Sized` so a `&mut dyn Read`/`&mut dyn SeekRead` can be passed straight
/// through (the in-memory engine hands it a trait object).
#[doc(hidden)]
pub fn compute_stream_sha256<R: Read + ?Sized>(reader: &mut R) -> Result<[u8; 32], StrHideError> {
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

/// Maximum payload size allowed during verification (1 GiB) to prevent OOM
/// and zip-bomb style resource exhaustion from untrusted/crafted carriers.
pub const MAX_VERIFY_PAYLOAD_SIZE: u64 = 1024 * 1024 * 1024;

struct VerifySha256Writer {
    hasher: Sha256,
    total_bytes: u64,
    limit: u64,
}

impl Write for VerifySha256Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.total_bytes = self.total_bytes.saturating_add(buf.len() as u64);
        if self.total_bytes > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Decompressed payload exceeds maximum verification limit ({} bytes)",
                    self.limit
                ),
            ));
        }
        self.hasher.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Streamingly decrypt and verify payload against `expected_sha256` and `expected_raw_size`,
/// enforcing a hard memory/byte limit of [`MAX_VERIFY_PAYLOAD_SIZE`] (1 GiB) without
/// allocating the full payload in memory.
#[allow(clippy::too_many_arguments)]
pub fn verify_payload_stream<R: Read>(
    reader: &mut R,
    payload_key: &[u8; 32],
    base_nonce: &[u8; 12],
    fixed_header_aad: &[u8],
    total_payload_bytes: u64,
    is_compressed: bool,
    expected_raw_size: u64,
    expected_sha256: &str,
    limit: u64,
) -> Result<u64, StrHideError> {
    if limit == 0 {
        return Err(StrHideError::InvalidArgument(
            "Verification limit must be greater than zero".into(),
        ));
    }
    let limit = limit.min(MAX_VERIFY_PAYLOAD_SIZE);
    if total_payload_bytes > limit || expected_raw_size > limit {
        return Err(StrHideError::InvalidArgument(format!(
            "Payload size (declared raw: {expected_raw_size}B, encrypted: {total_payload_bytes}B) exceeds verification limit ({limit}B)"
        )));
    }

    let sha_writer = VerifySha256Writer {
        hasher: Sha256::new(),
        total_bytes: 0,
        limit: if is_compressed {
            expected_raw_size.min(limit)
        } else {
            limit
        },
    };

    let final_writer = if is_compressed {
        let mut deflate_decoder = WriteDeflateDecoder::new(sha_writer);
        decrypt_stream_from_chunks(
            reader,
            &mut deflate_decoder,
            payload_key,
            base_nonce,
            fixed_header_aad,
            total_payload_bytes,
        )?;
        deflate_decoder
            .finish()
            .map_err(|e| StrHideError::CorruptedData(format!("Deflate decompression error: {e}")))?
    } else {
        let mut writer = sha_writer;
        decrypt_stream_from_chunks(
            reader,
            &mut writer,
            payload_key,
            base_nonce,
            fixed_header_aad,
            total_payload_bytes,
        )?;
        writer
    };

    if final_writer.total_bytes != expected_raw_size {
        return Err(StrHideError::CorruptedData(format!(
            "Payload size mismatch: recovered {} bytes, metadata declared {}",
            final_writer.total_bytes, expected_raw_size
        )));
    }

    let digest = final_writer.hasher.finalize();
    let actual_sha256 = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if actual_sha256 != expected_sha256 {
        return Err(StrHideError::CorruptedData(format!(
            "Payload SHA-256 mismatch: {actual_sha256} != {expected_sha256}"
        )));
    }

    Ok(final_writer.total_bytes)
}

/// Streamed SHA-256 of a file on disk.
pub fn compute_file_sha256(path: &std::path::Path) -> Result<[u8; 32], StrHideError> {
    let mut file = std::fs::File::open(path)?;
    compute_stream_sha256(&mut file)
}

#[cfg(test)]
#[path = "crypto_tests.rs"]
mod tests;
