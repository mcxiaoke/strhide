//! Binary envelope structures and serialization for strhide UBE v2.2.
//!
//! The "Universal Byte Envelope" (UBE) is the self-contained container strhide
//! injects into a carrier. It is laid out as:
//!
//! ```text
//! +----------------------+  HEADER_SIZE = 112 bytes
//! | magic (8)            |
//! | version/flags/...    |
//! | salt (16)            |
//! | base_nonce (12)      |
//! | orig_host_size (8)   |
//! | orig_host_sha256 (32)|
//! | inject offsets       |
//! +----------------------+
//! | password hint        |  hint_len bytes (optional)
//! +----------------------+
//! | encrypted metadata   |  meta_len bytes (AES-GCM sealed)
//! +----------------------+
//! | encrypted payload    |  chunk-framed AES-GCM stream
//! +----------------------+
//! | trailer (24)         |  TRAILER_SIZE = 24 bytes
//! +----------------------+
//! ```
//!
//! The header/trailer magics are either the standard high-entropy constants
//! ([`STANDARD_HEADER_MAGIC`] / [`STANDARD_TRAILER_MAGIC`]) or, in stealth
//! mode, password-derived values produced by
//! [`crate::crypto::derive_stealth_magics`]. Sensitive header fields are
//! XOR-masked with a keystream derived from the password (or, for the default
//! non-encrypted envelope, from the profile's default secret —
//! [`crate::crypto::BUILTIN_DEFAULT_KEY`] unless a private
//! [`Profile`] overrides it).
//!
//! Readers should prefer [`EnvelopeHeader::unpack_with_password`] (official
//! dialect) or [`EnvelopeHeader::unpack_with_profile`] (any dialect) and
//! [`EnvelopeTrailer::unpack`]; the bare `unpack` calls assume an already
//! de-masked header.

use crate::errors::StrHideError;
use crate::params::Profile;
use std::io::{Read, Seek, SeekFrom};

/// Standard high-entropy binary header magic (8 bytes): SHA-256("strhide-standard-header-v2")[..8]
/// Pure pseudorandom binary bytes: eliminates all static ASCII strings ("STRHIDE") from forensic scans.
pub const STANDARD_HEADER_MAGIC: [u8; 8] = [0xb7, 0x54, 0x2c, 0x82, 0x7e, 0x31, 0x1d, 0x6e];

/// Standard high-entropy binary trailer magic (4 bytes): SHA-256("strhide-standard-trailer-v2")[..4]
/// Pure pseudorandom binary bytes: eliminates all static ASCII strings ("STH!") from forensic scans.
pub const STANDARD_TRAILER_MAGIC: [u8; 4] = [0x78, 0xe6, 0x66, 0xd2];

/// Largest strategy ID in [`crate::router::STRATEGY_REGISTRY`].
///
/// Used in the unencrypted envelope de-mask heuristic to eliminate false
/// positives while allowing all valid registered strategy IDs. Derived from the
/// registry rather than hand-maintained: a strategy added without updating this
/// constant would make a *new* carrier fail the "is this an envelope at all?"
/// gate and read back as "no hidden data".
pub const MAX_KNOWN_STRATEGY_ID: u8 = crate::router::MAX_STRATEGY_ID;

/// Envelope version written and accepted by this build.
///
/// Only this value parses: the v0.2/v0.3 ASCII magics (`\x89STRHIDE` / `STH!`)
/// and their plaintext metadata layout were dropped on 2026-10-21, so a
/// pre-v2 carrier now reports "no hidden data" instead of being read.
pub const CURRENT_VERSION: u8 = 0x02;

pub const FLAG_ENCRYPTED: u8 = 0x01;
pub const FLAG_COMPRESSED: u8 = 0x02;
pub const FLAG_IS_FILE: u8 = 0x04;
pub const FLAG_STEALTH: u8 = 0x08;
pub const FLAG_HAS_HINT: u8 = 0x10;
/// Metadata block uses the compact binary layout instead of JSON. Readers must
/// branch on this flag; writers set it whenever the block is encodable, so the
/// envelope shrinks by ~93 bytes (the JSON form spends 64 bytes on the SHA-256
/// hex string alone). Older readers that predate this flag still parse the
/// JSON form (flag clear) and fail cleanly — never silently — on the compact
/// form.
pub const FLAG_COMPACT_META: u8 = 0x20;

pub const HEADER_SIZE: usize = 112;
pub const AAD_SIZE: usize = 80;
pub const TRAILER_SIZE: usize = 24;
pub const MAX_HINT_LEN: u32 = 1024;

/// Smallest envelope the writer can currently produce with compact metadata,
/// an empty filename and a 1-byte payload:
/// `header 112 + meta 41 + payload 1 + trailer 24`.
///
/// Used by capacity reporting (`pe_codebits`) so `inspect` stops advertising a
/// capacity that cannot hold even the smallest real envelope (`MIN_UBE_LEN` of
/// 136 only covers header + trailer, which no writer ever emits).
pub const MIN_UBE_PLAIN: u32 = 178;
/// Same, encrypted: `112 + (meta 41 + 16 tag) + (1 + 4 length + 16 tag) + 24`.
pub const MIN_UBE_ENCRYPTED: u32 = 214;

/// Fixed 112-byte envelope header, serialized little-endian.
///
/// The first 80 bytes are exactly the AAD ([`Self::get_aad`]) bound into the
/// AEAD seals of both the metadata block and every payload chunk — tampering
/// with any of them breaks authentication. The trailing 32 bytes
/// (`inject_offset` / `inject_size` / `patch_offset` / `orig_patch_val` /
/// `meta_len` / `hint_len`) are stored after injection because the injector
/// does not know the final offset until it has placed the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeHeader {
    pub magic_header: [u8; 8],
    pub version: u8,
    pub flags: u8,
    pub strategy_id: u8,
    pub reserved: u8,
    pub salt: [u8; 16],
    pub base_nonce: [u8; 12],
    pub orig_host_size: u64,
    pub orig_host_sha256: [u8; 32],
    pub inject_offset: u64,
    pub inject_size: u64,
    pub patch_offset: u32,
    pub orig_patch_val: u32,
    pub meta_len: u32,
    pub hint_len: u32,
}

impl Default for EnvelopeHeader {
    fn default() -> Self {
        Self {
            magic_header: STANDARD_HEADER_MAGIC,
            version: CURRENT_VERSION,
            flags: 0,
            strategy_id: 1,
            reserved: 0,
            salt: [0u8; 16],
            base_nonce: [0u8; 12],
            orig_host_size: 0,
            orig_host_sha256: [0u8; 32],
            inject_offset: 0,
            inject_size: 0,
            patch_offset: 0,
            orig_patch_val: 0,
            meta_len: 0,
            hint_len: 0,
        }
    }
}

impl EnvelopeHeader {
    /// True when the envelope was sealed with a user password (FLAG_ENCRYPTED).
    ///
    /// Note: even when this is false, the payload is still encrypted with the
    /// built-in public key — "encrypted" here means "a user password was
    /// required".
    pub fn is_encrypted(&self) -> bool {
        (self.flags & FLAG_ENCRYPTED) != 0
    }

    /// The 16-byte salt field of a raw (possibly masked) header.
    ///
    /// The mask only covers bytes 8..12 and 40..112, so the salt can be read
    /// *before* the header is unmasked — which is what lets a caller derive the
    /// mask (and the payload keys) once and hand them in, instead of every
    /// consumer running its own PBKDF2.
    pub fn salt_of(data: &[u8]) -> Option<[u8; 16]> {
        if data.len() < HEADER_SIZE {
            return None;
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&data[12..28]);
        Some(salt)
    }

    /// True when the payload was deflate-compressed before sealing.
    pub fn is_compressed(&self) -> bool {
        (self.flags & FLAG_COMPRESSED) != 0
    }

    /// True when the payload was a file (rather than inline bytes/text).
    pub fn is_file(&self) -> bool {
        (self.flags & FLAG_IS_FILE) != 0
    }

    /// True when stealth mode is on (password-derived magics + masked fields).
    pub fn is_stealth(&self) -> bool {
        (self.flags & FLAG_STEALTH) != 0
    }

    /// Metadata block is the compact binary layout rather than JSON.
    pub fn is_compact_meta(&self) -> bool {
        (self.flags & FLAG_COMPACT_META) != 0
    }

    /// Validate header field ranges against the known envelope total size.
    ///
    /// Envelope metadata is untrusted input: a corrupted or crafted header must
    /// never drive huge allocations or unsigned underflow downstream. Callers
    /// must invoke this before sizing any buffer from `hint_len` / `meta_len`.
    pub fn validate_against(&self, ube_total_size: u64) -> Result<(), StrHideError> {
        if self.version != CURRENT_VERSION {
            return Err(StrHideError::CorruptedData(format!(
                "Unsupported envelope version {:#04x} (expected {:#04x})",
                self.version, CURRENT_VERSION
            )));
        }
        if self.hint_len > MAX_HINT_LEN {
            return Err(StrHideError::CorruptedData(format!(
                "Password hint length {} exceeds maximum {}",
                self.hint_len, MAX_HINT_LEN
            )));
        }
        let fixed = HEADER_SIZE as u64 + 24; // header + trailer
        let variable = self.hint_len as u64 + self.meta_len as u64;
        if variable + fixed > ube_total_size {
            return Err(StrHideError::CorruptedData(format!(
                "Envelope field sizes inconsistent: hint({}) + meta({}) + {} exceed total size {}",
                self.hint_len, self.meta_len, fixed, ube_total_size
            )));
        }
        Ok(())
    }

    /// Return the immutable 80-byte AAD binding header fields for AEAD.
    pub fn get_aad(&self) -> [u8; AAD_SIZE] {
        let mut aad = [0u8; AAD_SIZE];
        aad[0..8].copy_from_slice(&self.magic_header);
        aad[8] = self.version;
        aad[9] = self.flags;
        aad[10] = self.strategy_id;
        aad[11] = self.reserved;
        aad[12..28].copy_from_slice(&self.salt);
        aad[28..40].copy_from_slice(&self.base_nonce);
        aad[40..48].copy_from_slice(&self.orig_host_size.to_le_bytes());
        aad[48..80].copy_from_slice(&self.orig_host_sha256);
        aad
    }

    /// Pack fixed header into 112 bytes.
    pub fn pack(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..80].copy_from_slice(&self.get_aad());
        buf[80..88].copy_from_slice(&self.inject_offset.to_le_bytes());
        buf[88..96].copy_from_slice(&self.inject_size.to_le_bytes());
        buf[96..100].copy_from_slice(&self.patch_offset.to_le_bytes());
        buf[100..104].copy_from_slice(&self.orig_patch_val.to_le_bytes());
        buf[104..108].copy_from_slice(&self.meta_len.to_le_bytes());
        buf[108..112].copy_from_slice(&self.hint_len.to_le_bytes());
        buf
    }

    /// Pack fixed header into 112 bytes with masking applied from a mask the
    /// caller already derived.
    ///
    /// `None` means "no masking" — the encrypted non-stealth case, where the
    /// AEAD authenticates the header instead.
    pub fn pack_masked(&self, mask: Option<&[u8; 76]>) -> [u8; HEADER_SIZE] {
        let mut buf = self.pack();
        if let Some(mask) = mask {
            for i in 0..4 {
                buf[8 + i] ^= mask[i];
            }
            for i in 0..72 {
                buf[40 + i] ^= mask[4 + i];
            }
        }
        buf
    }

    /// Pack fixed header into 112 bytes with masking applied:
    /// - In stealth mode: sensitive fields are masked with the user's password.
    /// - In default mode (no custom password): sensitive fields are masked with
    ///   the profile's default secret (`BUILTIN_DEFAULT_KEY` for the official
    ///   profile).
    ///
    /// The masking secret must match on both sides — this is the write half of
    /// the pair whose read half is [`Self::unpack_with_profile`]. A private
    /// `Profile::default_secret` therefore has to be supplied to both calls or
    /// the header becomes unreadable.
    ///
    /// Callers that already hold a [`crate::crypto::PasswordSecrets`] (the
    /// writer derives the payload keys from the same pair) should use
    /// [`Self::pack_masked`] instead, so the PBKDF2 runs once per write.
    pub fn pack_with_profile(
        &self,
        password: Option<&str>,
        profile: &Profile,
    ) -> Result<[u8; HEADER_SIZE], StrHideError> {
        let mask_secret = if self.is_stealth() {
            password
        } else if !self.is_encrypted() {
            Some(profile.secret())
        } else {
            None
        };
        let mask = match mask_secret {
            Some(pwd) => Some(crate::crypto::derive_header_mask(pwd, &self.salt)?),
            None => None,
        };
        Ok(self.pack_masked(mask.as_ref()))
    }

    /// Unpack 112-byte fixed header.
    pub fn unpack(data: &[u8]) -> Result<Self, StrHideError> {
        if data.len() < HEADER_SIZE {
            return Err(StrHideError::CorruptedData(format!(
                "Insufficient bytes for header: {} < {}",
                data.len(),
                HEADER_SIZE
            )));
        }

        let mut magic_header = [0u8; 8];
        magic_header.copy_from_slice(&data[0..8]);

        let version = data[8];
        let flags = data[9];
        let strategy_id = data[10];
        let reserved = data[11];

        let mut salt = [0u8; 16];
        salt.copy_from_slice(&data[12..28]);

        let mut base_nonce = [0u8; 12];
        base_nonce.copy_from_slice(&data[28..40]);

        let orig_host_size = u64::from_le_bytes(data[40..48].try_into().unwrap());

        let mut orig_host_sha256 = [0u8; 32];
        orig_host_sha256.copy_from_slice(&data[48..80]);

        let inject_offset = u64::from_le_bytes(data[80..88].try_into().unwrap());
        let inject_size = u64::from_le_bytes(data[88..96].try_into().unwrap());
        let patch_offset = u32::from_le_bytes(data[96..100].try_into().unwrap());
        let orig_patch_val = u32::from_le_bytes(data[100..104].try_into().unwrap());
        let meta_len = u32::from_le_bytes(data[104..108].try_into().unwrap());
        let hint_len = u32::from_le_bytes(data[108..112].try_into().unwrap());

        Ok(Self {
            magic_header,
            version,
            flags,
            strategy_id,
            reserved,
            salt,
            base_nonce,
            orig_host_size,
            orig_host_sha256,
            inject_offset,
            inject_size,
            patch_offset,
            orig_patch_val,
            meta_len,
            hint_len,
        })
    }

    /// Unpack 112-byte fixed header, handling stealth and default de-masking
    /// for the official dialect.
    ///
    /// Wrapper over [`Self::unpack_with_profile`] with `Profile::default()`.
    pub fn unpack_with_password(data: &[u8], password: Option<&str>) -> Result<Self, StrHideError> {
        Self::unpack_with_profile(data, password, &Profile::default())
    }

    /// Unpack 112-byte fixed header, handling stealth and default de-masking.
    ///
    /// Three-tier identification, in order:
    ///
    /// 1. **Stealth + password**: the header magic is itself derived from the
    ///    password, so a match authenticates the password before any masked
    ///    field is trusted.
    /// 2. **Default mode**: unmask with the profile's default secret and accept
    ///    only if the unmasked `version` / `flags` / `strategy_id` / `reserved`
    ///    bytes form a plausible header. This gate is what makes a wrong
    ///    profile fail deterministically instead of yielding garbage fields.
    /// 3. **Bare header**: an already-plain header (encrypted mode is *not*
    ///    masked at all — the AEAD authenticates it).
    pub fn unpack_with_profile(
        data: &[u8],
        password: Option<&str>,
        profile: &Profile,
    ) -> Result<Self, StrHideError> {
        Self::unpack_with_secrets(data, password, profile, &UnpackSecrets::default())
    }

    /// [`Self::unpack_with_profile`] with the expensive derivations already done.
    ///
    /// See [`UnpackSecrets`]: this exists so a single read does not pay for
    /// PBKDF2 once per consumer of the same (password, salt) pair.
    pub fn unpack_with_secrets(
        data: &[u8],
        password: Option<&str>,
        profile: &Profile,
        secrets: &UnpackSecrets,
    ) -> Result<Self, StrHideError> {
        if data.len() < HEADER_SIZE {
            return Err(StrHideError::CorruptedData(format!(
                "Insufficient bytes for header: {} < {}",
                data.len(),
                HEADER_SIZE
            )));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&data[12..28]);

        // 1. Stealth + password: the header magic is itself derived from the
        //    password, so a match authenticates the password before any masked
        //    field is trusted. `secrets.stealth_header_magic` is the magic the
        //    locator already derived; `None` means "not derived yet", in which
        //    case it is computed here (one PBKDF2).
        if let Some(pwd) = password {
            let magic_matches = match secrets.stealth_header_magic {
                Some(m) => data[..8] == m[..],
                None => crate::crypto::derive_stealth_magics(pwd, profile.domain())
                    .ok()
                    .is_none_or(|m| data[..8] == m.0[..]),
            };
            let mask = match &secrets.password {
                Some(s) => Some(s.header_mask),
                None if magic_matches => Some(crate::crypto::derive_header_mask(pwd, &salt)?),
                None => None,
            };
            if magic_matches && let Some(mask) = mask {
                let mut unmasked = [0u8; HEADER_SIZE];
                unmasked.copy_from_slice(&data[..HEADER_SIZE]);
                for i in 0..4 {
                    unmasked[8 + i] ^= mask[i];
                }
                for i in 0..72 {
                    unmasked[40 + i] ^= mask[4 + i];
                }
                if unmasked[8] == CURRENT_VERSION
                    && (unmasked[9] & FLAG_STEALTH) != 0
                    && let Ok(hdr) = Self::unpack(&unmasked)
                {
                    return Ok(hdr);
                }
            }
        }

        // 2. De-mask with the profile's default secret (the public built-in key
        //    for the official dialect).
        let default_mask = match &secrets.default {
            Some(s) => Some(s.header_mask),
            None => Some(crate::crypto::derive_header_mask(profile.secret(), &salt)?),
        };
        if let Some(mask) = default_mask {
            let mut unmasked = [0u8; HEADER_SIZE];
            unmasked.copy_from_slice(&data[..HEADER_SIZE]);
            for i in 0..4 {
                unmasked[8 + i] ^= mask[i];
            }
            for i in 0..72 {
                unmasked[40 + i] ^= mask[4 + i];
            }
            if unmasked[8] == CURRENT_VERSION
                && (unmasked[9] & FLAG_ENCRYPTED) == 0
                && unmasked[10] <= MAX_KNOWN_STRATEGY_ID
                && unmasked[11] == 0
            {
                return Self::unpack(&unmasked);
            }
        }

        // 3. Bare header: an already-plain header (encrypted mode is *not*
        //    masked at all — the AEAD authenticates it).
        Self::unpack(data)
    }
}

/// Key material pre-derived for one header, so a single read does not run
/// PBKDF2 once per consumer of the same (password, salt) pair.
///
/// `read_carrier` used to derive: the stealth magics (in `locate_envelope`),
/// the same magics again (inside `unpack_with_profile`), the header mask for
/// the password, the header mask for the profile default — which is derived
/// even when the password branch already matched — and the payload/metadata
/// keys. That is four to five PBKDF2 runs where one or two suffice.
#[derive(Clone, Copy, Default)]
pub struct UnpackSecrets {
    /// Material for the caller's password, when one was supplied.
    pub password: Option<crate::crypto::PasswordSecrets>,
    /// Material for the profile's default secret.
    pub default: Option<crate::crypto::PasswordSecrets>,
    /// Header magic derived from password + domain. The locator already
    /// computed it to find the envelope; passing it in avoids doing it twice.
    pub stealth_header_magic: Option<[u8; 8]>,
}

/// 24-byte trailer at the end of the envelope, giving readers a way to find
/// the envelope backwards from the carrier's EOF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeTrailer {
    pub ube_offset: u64,
    pub ube_total_size: u64,
    pub trailer_crc32: u32,
    pub trailer_magic: [u8; 4],
}

impl EnvelopeTrailer {
    /// Build a standard trailer. `trailer_magic` is normally
    /// [`STANDARD_TRAILER_MAGIC`], or the password-derived magic in stealth.
    pub fn create(ube_offset: u64, ube_total_size: u64, trailer_magic: [u8; 4]) -> Self {
        let mut prefix = [0u8; 16];
        prefix[0..8].copy_from_slice(&ube_offset.to_le_bytes());
        prefix[8..16].copy_from_slice(&ube_total_size.to_le_bytes());
        let crc = crc32fast::hash(&prefix);

        Self {
            ube_offset,
            ube_total_size,
            trailer_crc32: crc,
            trailer_magic,
        }
    }

    /// Create trailer with password-derived CRC mask in stealth mode.
    /// This prevents scanning for standard IEEE 802.3 CRC32 to find the trailer without the password.
    pub fn create_stealth(ube_offset: u64, ube_total_size: u64, trailer_magic: [u8; 4]) -> Self {
        let mut prefix = [0u8; 16];
        prefix[0..8].copy_from_slice(&ube_offset.to_le_bytes());
        prefix[8..16].copy_from_slice(&ube_total_size.to_le_bytes());
        let raw_crc = crc32fast::hash(&prefix);
        let mask = crate::crypto::derive_trailer_crc_mask(&trailer_magic);

        Self {
            ube_offset,
            ube_total_size,
            trailer_crc32: raw_crc ^ mask,
            trailer_magic,
        }
    }

    /// Serialize to the 24-byte on-disk form.
    pub fn pack(&self) -> [u8; TRAILER_SIZE] {
        let mut buf = [0u8; TRAILER_SIZE];
        buf[0..8].copy_from_slice(&self.ube_offset.to_le_bytes());
        buf[8..16].copy_from_slice(&self.ube_total_size.to_le_bytes());
        buf[16..20].copy_from_slice(&self.trailer_crc32.to_le_bytes());
        buf[20..24].copy_from_slice(&self.trailer_magic);
        buf
    }

    /// Parse a 24-byte trailer, optionally requiring a specific magic.
    ///
    /// When `expected_magic` is `None` (the official dialect) only
    /// [`STANDARD_TRAILER_MAGIC`] is accepted and the CRC is checked against
    /// the unmasked value. When it is `Some(..)` (stealth or a private
    /// dialect), the password-derived CRC mask is also accepted.
    pub fn unpack(data: &[u8], expected_magic: Option<&[u8; 4]>) -> Result<Self, StrHideError> {
        if data.len() < TRAILER_SIZE {
            return Err(StrHideError::CorruptedData(format!(
                "Insufficient bytes for trailer: {} < {}",
                data.len(),
                TRAILER_SIZE
            )));
        }

        let ube_offset = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let ube_total_size = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let trailer_crc32 = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let mut trailer_magic = [0u8; 4];
        trailer_magic.copy_from_slice(&data[20..24]);

        let is_valid_magic = match expected_magic {
            Some(target) => &trailer_magic == target,
            None => trailer_magic == STANDARD_TRAILER_MAGIC,
        };

        if !is_valid_magic {
            return Err(StrHideError::CorruptedData(format!(
                "Trailer magic mismatch: {:?} is not a recognized magic",
                trailer_magic
            )));
        }

        let mut prefix = [0u8; 16];
        prefix[0..8].copy_from_slice(&ube_offset.to_le_bytes());
        prefix[8..16].copy_from_slice(&ube_total_size.to_le_bytes());
        let expected_crc = crc32fast::hash(&prefix);

        let crc_matches = if trailer_crc32 == expected_crc {
            true
        } else if expected_magic.is_some() {
            let mask = crate::crypto::derive_trailer_crc_mask(&trailer_magic);
            (trailer_crc32 ^ mask) == expected_crc
        } else {
            false
        };

        if !crc_matches {
            return Err(StrHideError::CorruptedData(format!(
                "Trailer CRC32 mismatch: {:#x} != {:#x}",
                trailer_crc32, expected_crc
            )));
        }

        Ok(Self {
            ube_offset,
            ube_total_size,
            trailer_crc32,
            trailer_magic,
        })
    }

    /// Read and parse the last 24 bytes of `reader`. Returns `Ok(None)` when
    /// the file is too short or the trailing bytes do not form a valid
    /// trailer — this is the normal "no envelope here" outcome and is not an
    /// error.
    pub fn read_from_tail<R: Read + Seek + ?Sized>(
        reader: &mut R,
        expected_magic: Option<&[u8; 4]>,
    ) -> Result<Option<Self>, StrHideError> {
        let file_size = reader.seek(SeekFrom::End(0))?;
        if file_size < TRAILER_SIZE as u64 {
            return Ok(None);
        }

        reader.seek(SeekFrom::End(-(TRAILER_SIZE as i64)))?;
        let mut tail_bytes = [0u8; TRAILER_SIZE];
        reader.read_exact(&mut tail_bytes)?;

        match Self::unpack(&tail_bytes, expected_magic) {
            Ok(trailer) => Ok(Some(trailer)),
            Err(_) => Ok(None),
        }
    }
}
