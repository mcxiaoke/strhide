//! Binary envelope structures and serialization for strhide UBE v2.2.

use crate::errors::StrHideError;
use std::io::{Read, Seek, SeekFrom};

pub const STANDARD_HEADER_MAGIC: [u8; 8] = *b"\x89STRHIDE";
pub const STANDARD_TRAILER_MAGIC: [u8; 4] = *b"STH!";
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
    pub fn is_encrypted(&self) -> bool {
        (self.flags & FLAG_ENCRYPTED) != 0
    }

    pub fn is_compressed(&self) -> bool {
        (self.flags & FLAG_COMPRESSED) != 0
    }

    pub fn is_file(&self) -> bool {
        (self.flags & FLAG_IS_FILE) != 0
    }

    pub fn is_stealth(&self) -> bool {
        (self.flags & FLAG_STEALTH) != 0
    }

    pub fn has_hint(&self) -> bool {
        (self.flags & FLAG_HAS_HINT) != 0
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

    /// Pack fixed header into 112 bytes with stealth masking applied if stealth mode is enabled.
    /// In stealth mode, sensitive fields (version, flags, strategy_id, host SHA-256, sizes and offsets)
    /// Pack fixed header into 112 bytes with masking applied:
    /// - In stealth mode: sensitive fields are masked with user's password.
    /// - In default mode (no custom password): sensitive fields are masked with BUILTIN_DEFAULT_KEY.
    pub fn pack_with_stealth_mask(
        &self,
        password: Option<&str>,
    ) -> Result<[u8; HEADER_SIZE], StrHideError> {
        let mut buf = self.pack();
        let effective_pwd = if self.is_stealth() {
            password
        } else if !self.is_encrypted() {
            Some(crate::crypto::BUILTIN_DEFAULT_KEY)
        } else {
            None
        };

        if let Some(pwd) = effective_pwd {
            let mask = crate::crypto::derive_header_mask(pwd, &self.salt)?;
            for i in 0..4 {
                buf[8 + i] ^= mask[i];
            }
            for i in 0..72 {
                buf[40 + i] ^= mask[4 + i];
            }
        }
        Ok(buf)
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

    /// Unpack 112-byte fixed header, handling stealth and default de-masking when applicable.
    pub fn unpack_with_password(data: &[u8], password: Option<&str>) -> Result<Self, StrHideError> {
        if data.len() < HEADER_SIZE {
            return Err(StrHideError::CorruptedData(format!(
                "Insufficient bytes for header: {} < {}",
                data.len(),
                HEADER_SIZE
            )));
        }

        if let Some(pwd) = password {
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&data[12..28]);
            if let Ok(mask) = crate::crypto::derive_header_mask(pwd, &salt) {
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

        // Try de-masking with BUILTIN_DEFAULT_KEY for default mode
        {
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&data[12..28]);
            if let Ok(mask) =
                crate::crypto::derive_header_mask(crate::crypto::BUILTIN_DEFAULT_KEY, &salt)
            {
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
                    && unmasked[10] <= 10
                    && unmasked[11] == 0
                {
                    return Self::unpack(&unmasked);
                }
            }
        }

        Self::unpack(data)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeTrailer {
    pub ube_offset: u64,
    pub ube_total_size: u64,
    pub trailer_crc32: u32,
    pub trailer_magic: [u8; 4],
}

impl EnvelopeTrailer {
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

    pub fn pack(&self) -> [u8; TRAILER_SIZE] {
        let mut buf = [0u8; TRAILER_SIZE];
        buf[0..8].copy_from_slice(&self.ube_offset.to_le_bytes());
        buf[8..16].copy_from_slice(&self.ube_total_size.to_le_bytes());
        buf[16..20].copy_from_slice(&self.trailer_crc32.to_le_bytes());
        buf[20..24].copy_from_slice(&self.trailer_magic);
        buf
    }

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

        let target_magic = expected_magic.unwrap_or(&STANDARD_TRAILER_MAGIC);
        if &trailer_magic != target_magic {
            return Err(StrHideError::CorruptedData(format!(
                "Trailer magic mismatch: {:?} != {:?}",
                trailer_magic, target_magic
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
