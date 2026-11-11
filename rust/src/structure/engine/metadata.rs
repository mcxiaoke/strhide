//! Payload metadata carried inside the encrypted envelope.
//!
//! [`CarrierMetadata`] is the record that survives `read`: the original
//! filename, the uncompressed payload size, its SHA-256, and a write
//! timestamp. Its only wire layout is the compact binary form below; the JSON
//! form was removed together with the pre-v2 compatibility layer.

use serde::{Deserialize, Serialize};

use crate::errors::StrHideError;

/// Metadata about the payload being hidden, stored inside the encrypted
/// envelope metadata block.
///
/// This is the metadata that survives `read`: the original filename, the
/// uncompressed payload size, its SHA-256, and a write timestamp. On extract,
/// `raw_sha256` is re-computed over the decrypted payload and must match.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarrierMetadata {
    pub filename: String,
    pub raw_size: u64,
    pub raw_sha256: String,
    pub created_at: u64,
}

/// Inspection status of the envelope's encrypted metadata block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum MetadataInspection {
    Decrypted(CarrierMetadata),
    DecryptFailed { error: String },
}

impl std::fmt::Display for MetadataInspection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decrypted(meta) => {
                let json = serde_json::to_string(meta).map_err(|_| std::fmt::Error)?;
                write!(f, "{json}")
            }
            Self::DecryptFailed { error } => {
                write!(f, "{{\"error\":\"{error}\"}}")
            }
        }
    }
}

/// Version of the compact (binary) metadata block. The JSON form carries no
/// version; a reader only reaches this layout when `FLAG_COMPACT_META` is set.
const COMPACT_META_VERSION: u8 = 0x01;
/// Compact layout: `u8 version | u16 name_len | name | varint raw_size |
/// 32-byte digest | varint created_at`. The JSON form spends 64 bytes on the
/// SHA-256 hex string alone plus ~60 bytes of key names, so this shrinks a
/// 1-byte payload's metadata from 137 to ~46 bytes.
pub(super) const COMPACT_META_MAX_NAME: usize = u16::MAX as usize;

pub(super) fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

pub(super) fn take_varint(input: &[u8], pos: &mut usize) -> Result<u64, StrHideError> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for i in 0..10 {
        let byte = *input.get(*pos).ok_or_else(|| {
            StrHideError::CorruptedData("Corrupted compact metadata block: truncated varint".into())
        })?;
        *pos += 1;
        // A 10-byte u64 varint may only use bit 0 of its last byte; additional
        // bits would overflow bit 63, corrupting decoded fields.
        if i == 9 {
            if byte & 0x80 != 0 {
                return Err(StrHideError::CorruptedData(
                    "Corrupted compact metadata block: varint too long".into(),
                ));
            }
            if byte & 0x7e != 0 {
                return Err(StrHideError::CorruptedData(
                    "Corrupted compact metadata block: varint overflows u64".into(),
                ));
            }
        }
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(StrHideError::CorruptedData(
        "Corrupted compact metadata block: varint too long".into(),
    ))
}

fn hex_to_digest32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    // Explicit indexing over 64 known bytes: avoids `chunks_exact(2)`, which
    // newer clippy lints push towards `as_chunks` (an API newer than this
    // crate's minimum toolchain).
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        *slot = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

impl CarrierMetadata {
    /// Build a metadata record.
    ///
    /// All four fields are required: the digest is re-checked on read and the
    /// timestamp is part of the sealed metadata block, so there is no sensible
    /// partial default.
    pub fn new(
        filename: impl Into<String>,
        raw_size: u64,
        raw_sha256: impl Into<String>,
        created_at: u64,
    ) -> Self {
        Self {
            filename: filename.into(),
            raw_size,
            raw_sha256: raw_sha256.into(),
            created_at,
        }
    }

    /// Replace the recorded filename.
    pub fn with_filename(mut self, filename: impl Into<String>) -> Self {
        self.filename = filename.into();
        self
    }

    /// Replace the recorded size and digest together.
    ///
    /// They travel as a pair: a size that does not match the digest is exactly
    /// the corruption `read` refuses.
    pub fn with_content(mut self, raw_size: u64, raw_sha256: impl Into<String>) -> Self {
        self.raw_size = raw_size;
        self.raw_sha256 = raw_sha256.into();
        self
    }

    /// Replace the recorded write timestamp (seconds since the Unix epoch).
    pub fn with_created_at(mut self, created_at: u64) -> Self {
        self.created_at = created_at;
        self
    }

    /// Compact encoding, or `None` when this metadata cannot be represented
    /// (over-long filename, malformed digest). This is the only metadata
    /// layout in the wire format; a `None` is a writer-side error, not a
    /// reason to fall back to another encoding.
    pub fn encode_compact(&self) -> Option<Vec<u8>> {
        let name = self.filename.as_bytes();
        if name.len() > COMPACT_META_MAX_NAME {
            return None;
        }
        let digest = hex_to_digest32(&self.raw_sha256)?;
        let mut out = Vec::with_capacity(3 + name.len() + 1 + 32 + 1);
        out.push(COMPACT_META_VERSION);
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name);
        put_varint(&mut out, self.raw_size);
        out.extend_from_slice(&digest);
        put_varint(&mut out, self.created_at);
        Some(out)
    }

    pub fn decode_compact(bytes: &[u8]) -> Result<Self, StrHideError> {
        let bad = |msg: &str| {
            StrHideError::CorruptedData(format!("Corrupted compact metadata block: {msg}"))
        };
        if bytes.len() < 3 {
            return Err(bad("truncated header"));
        }
        if bytes[0] != COMPACT_META_VERSION {
            return Err(StrHideError::CorruptedData(format!(
                "Unsupported compact metadata version {:#04x} (expected {:#04x})",
                bytes[0], COMPACT_META_VERSION
            )));
        }
        let name_len = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
        let mut pos = 3usize;
        let name_end = pos
            .checked_add(name_len)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| bad("truncated filename"))?;
        let filename = String::from_utf8(bytes[pos..name_end].to_vec())
            .map_err(|_| bad("filename is not valid UTF-8"))?;
        pos = name_end;
        let raw_size = take_varint(bytes, &mut pos)?;
        let digest_end = pos
            .checked_add(32)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| bad("truncated SHA-256 digest"))?;
        let raw_sha256 = bytes[pos..digest_end]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        pos = digest_end;
        let created_at = take_varint(bytes, &mut pos)?;
        Ok(Self {
            filename,
            raw_size,
            raw_sha256,
            created_at,
        })
    }
}

/// Encode the metadata block (compact layout only).
///
/// The former JSON fallback was removed with the rest of the pre-v2 read
/// compatibility layer: a filename that does not fit the u16 length field, or
/// a digest that is not 64 hex characters, is a programming error at the
/// writer, so it fails loudly instead of silently switching layouts.
pub(super) fn encode_metadata(meta: &CarrierMetadata) -> Result<Vec<u8>, StrHideError> {
    meta.encode_compact().ok_or_else(|| {
        StrHideError::General(
            "Payload filename exceeds 65535 bytes or its SHA-256 is malformed; cannot encode envelope metadata"
                .into(),
        )
    })
}

/// Decode the metadata block. `compact` is the wire flag the writer set; any
/// other value is a pre-v2 JSON block this build no longer reads.
pub(super) fn decode_metadata(
    bytes: &[u8],
    compact: bool,
) -> Result<CarrierMetadata, StrHideError> {
    if compact {
        CarrierMetadata::decode_compact(bytes)
    } else {
        Err(StrHideError::CorruptedData(
            "Unsupported metadata layout: pre-v2 JSON metadata blocks are no longer readable"
                .into(),
        ))
    }
}
