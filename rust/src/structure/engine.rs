//! High-level engine: write, read, inspect, verify, and remove operations.
//!
//! This is the module library callers should use. The flow for each operation
//! is:
//!
//! 1. Run rejection checks ([`crate::structure::rejection`]).
//! 2. Snapshot the carrier's metadata (size, SHA-256, permissions, mtime/atime).
//! 3. Detect the carrier format via [`crate::structure::registry`] and locate any existing
//!    envelope.
//! 4. Build the UBE (header + optional hint + encrypted metadata + chunked
//!    encrypted payload + trailer) in a staging buffer.
//! 5. Inject it into a `<target>.strhide.tmp` file, patch the header/trailer
//!    back with the real offsets, and self-verify the written envelope.
//! 6. On success: optional in-place `.bak` backup, atomic rename, restore
//!    permissions/timestamps.
//!
//! [`remove_carrier`] performs the inverse: it locates the envelope, strips
//! the injected bytes, restores any patched fields, and then **verifies the
//! result against the SHA-256 recorded in the header** before committing. Any
//! mismatch leaves the original carrier untouched.

use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngExt;
use serde::{Deserialize, Serialize};

use crate::commit::{TmpGuard, temp_path_for};
use crate::structure::adapters::{
    FinalizeCtx, HostAdapter, SeekRead, SeekWrite, StrategyCapacity, TrailerCtx,
};

pub use crate::commit::same_file;

pub use crate::commit::commit_carrier_bytes;
use crate::crypto::{
    compress_stream, decompress_stream, decrypt_metadata, decrypt_stream_from_chunks, derive_all,
    derive_keys, derive_stealth_magics, encrypt_metadata, encrypt_stream_to_chunks, normalize_nfc,
};
use crate::errors::StrHideError;
use crate::formats::FileFormat;
use crate::params::LocalParams;
use crate::structure::envelope::{
    EnvelopeHeader, EnvelopeTrailer, FLAG_COMPACT_META, FLAG_COMPRESSED, FLAG_ENCRYPTED,
    FLAG_HAS_HINT, FLAG_IS_FILE, FLAG_STEALTH, HEADER_SIZE, TRAILER_SIZE, UnpackSecrets,
};
use crate::structure::options::{ReadOptions, RestoreOptions, WriteOptions};
use crate::structure::params::StructureProfile;
use crate::structure::registry::{
    StrategyId, find_adapter, find_adapter_or_reject, strategy_to_id,
};
use crate::structure::rejection::run_rejection_checks;

/// Metadata about the payload being hidden, stored inside the encrypted
/// envelope metadata block.
///
/// This is the metadata that survives `read`: the original filename, the
/// uncompressed payload size, its SHA-256, and a write timestamp. On extract,
/// `raw_sha256` is re-computed over the decrypted payload and must match.
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

/// Stealth mode password derivation domain separation string.
///
/// Re-exported from [`crate::params`] for the public API: the constant lives
/// next to [`StructureProfile::stealth_domain`], which is what actually drives
/// derivation.
pub use crate::params::STEALTH_DOMAIN;

/// Locate an envelope: password-derived stealth magic first, then the profile's
/// dialect magic.
///
/// The official profile passes `None` to `locate`, which lets adapters also
/// accept the legacy magics. A private dialect passes its own trailer magic and
/// deliberately does **not** fall back to the standard scan: an official
/// envelope must look like "no hidden data" to a private-profile reader (and
/// vice versa), otherwise the two dialects would silently cross-read.
fn locate_envelope(
    carrier: &mut dyn SeekRead,
    adapter: &dyn HostAdapter,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<Option<(u64, u64, String)>, StrHideError> {
    Ok(locate_envelope_with_magic(carrier, adapter, password, profile)?.location)
}

/// Outcome of a locate scan: where the envelope is, plus the stealth magics the
/// scan derived on the way (if a password was supplied).
struct Located {
    location: Option<(u64, u64, String)>,
    /// Header magic derived from password + profile domain.
    stealth_header_magic: Option<[u8; 8]>,
    /// Trailer magic derived from the same PBKDF2 run. Level 1 and Level 2
    /// both need it for stealth overlays; re-deriving it per consumer was
    /// several extra 100k-iteration PBKDF2 runs per `verify` (review P1-7).
    stealth_trailer_magic: Option<[u8; 4]>,
}

/// [`locate_envelope`], also returning the stealth magics it had to derive
/// on the way.
///
/// `unpack_with_secrets` needs exactly the header magic to decide whether the
/// header is a stealth one, and the trailer check needs its counterpart —
/// deriving them twice costs a full PBKDF2 (100k HMAC-SHA256 iterations) — so
/// the locator hands its result over instead of recomputing it.
fn locate_envelope_with_magic(
    carrier: &mut dyn SeekRead,
    adapter: &dyn HostAdapter,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<Located, StrHideError> {
    let mut stealth_header_magic = None;
    let mut stealth_trailer_magic = None;
    let found = if let Some(pwd) = password {
        let magics = derive_stealth_magics(pwd, profile.domain())?;
        // The derived magics are kept even when the stealth scan misses: the
        // header/trailer unpack need them to rule out the stealth branch, and
        // dropping them here would cost a second PBKDF2.
        stealth_header_magic = Some(magics.0);
        stealth_trailer_magic = Some(magics.1);
        match adapter.locate_with_hint(carrier, Some(&magics.1), Some(&magics.0))? {
            Some(location) => Some(location),
            None => adapter.locate_with_hint(
                carrier,
                profile.locator_magic(),
                Some(&profile.header_magic()),
            )?,
        }
    } else {
        adapter.locate_with_hint(
            carrier,
            profile.locator_magic(),
            Some(&profile.header_magic()),
        )?
    };

    Ok(Located {
        location: confine_location(carrier, found)?,
        stealth_header_magic,
        stealth_trailer_magic,
    })
}

/// Reject a located envelope that cannot physically fit inside the carrier.
///
/// Adapters only *propose* a location: they find it by trusting a 24-byte
/// trailer at the end of the file, whose `ube_offset` / `ube_total_size` are
/// protected by CRC-32 and nothing else — both fields are trivially forgeable,
/// and so is whatever container header precedes them. A forged
/// `ube_total_size` used to survive as far as `vec![0u8; meta_len]`, where the
/// metadata length could claim ~4 GiB: the allocation failure aborts the
/// process, so a few hundred forged bytes were a password-free denial of
/// service (review P0-2).
///
/// This is the single place that decides whether a carrier really contains the
/// envelope an adapter claims, and it runs before any buffer is sized from the
/// header. `<= file_len` (rather than `== file_len`) is what the strategies
/// need: only the EOF-appending ones end at the file end, while chunk, box and
/// padding strategies are followed by the rest of the container.
fn confine_location(
    carrier: &mut dyn SeekRead,
    location: Option<(u64, u64, String)>,
) -> Result<Option<(u64, u64, String)>, StrHideError> {
    let Some((ube_offset, ube_total_size, strategy)) = location else {
        return Ok(None);
    };
    let file_len = carrier.seek(SeekFrom::End(0))?;
    let min_envelope = (HEADER_SIZE + TRAILER_SIZE) as u64;
    let end = ube_offset.checked_add(ube_total_size);
    if ube_total_size < min_envelope || end.is_none_or(|end| end > file_len) {
        // Not an error: a trailer-shaped tail that points outside the file is
        // exactly what a carrier without a (readable) envelope looks like.
        return Ok(None);
    }
    Ok(Some((ube_offset, ube_total_size, strategy)))
}

/// Version of the compact (binary) metadata block. The JSON form carries no
/// version; a reader only reaches this layout when `FLAG_COMPACT_META` is set.
const COMPACT_META_VERSION: u8 = 0x01;
/// Compact layout: `u8 version | u16 name_len | name | varint raw_size |
/// 32-byte digest | varint created_at`. The JSON form spends 64 bytes on the
/// SHA-256 hex string alone plus ~60 bytes of key names, so this shrinks a
/// 1-byte payload's metadata from 137 to ~46 bytes.
const COMPACT_META_MAX_NAME: usize = u16::MAX as usize;

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn take_varint(input: &[u8], pos: &mut usize) -> Result<u64, StrHideError> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for i in 0..10 {
        let byte = *input.get(*pos).ok_or_else(|| {
            StrHideError::CorruptedData("Corrupted compact metadata block: truncated varint".into())
        })?;
        *pos += 1;
        // A 10-byte u64 varint may only use bit 0 of its last byte; the other
        // payload bits would be shifted past bit 63 and silently dropped (review
        // P2-6), producing a "valid but wrong" raw_size/created_at.
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
fn encode_metadata(meta: &CarrierMetadata) -> Result<Vec<u8>, StrHideError> {
    meta.encode_compact().ok_or_else(|| {
        StrHideError::General(
            "Payload filename exceeds 65535 bytes or its SHA-256 is malformed; cannot encode envelope metadata"
                .into(),
        )
    })
}

/// Decode the metadata block. `compact` is the wire flag the writer set; any
/// other value is a pre-v2 JSON block this build no longer reads.
fn decode_metadata(bytes: &[u8], compact: bool) -> Result<CarrierMetadata, StrHideError> {
    if compact {
        CarrierMetadata::decode_compact(bytes)
    } else {
        Err(StrHideError::CorruptedData(
            "Unsupported metadata layout: pre-v2 JSON metadata blocks are no longer readable"
                .into(),
        ))
    }
}

/// Where the payload to hide comes from.
pub enum PayloadSource<'a> {
    /// Raw bytes, stored as a file named `payload.bin`.
    Bytes(&'a [u8]),
    /// A file to read; its basename becomes the stored payload filename.
    File(&'a Path),
    /// Text, NFC-normalized before being stored as a text payload.
    Text(&'a str),
    /// Read to EOF from stdin. Only the first read yields data.
    Stdin,
    /// Already-materialized bytes plus the exact metadata another source would
    /// have produced, obtained from [`PayloadSource::into_buffered`]. Batched
    /// writes buffer the payload once and reuse it for every carrier.
    Buffered {
        data: &'a [u8],
        filename: &'a str,
        is_file: bool,
    },
}

impl<'a> PayloadSource<'a> {
    /// Materialize this source into `(bytes, stored filename, is_file)`.
    ///
    /// This is the single place where a source turns into bytes, so `Text`
    /// NFC normalization and `Stdin`'s read-once behavior cannot drift between
    /// the one-carrier and many-carrier paths. `Stdin` is consumed by the first
    /// call: buffer it once, then pass [`PayloadSource::Buffered`] per carrier.
    ///
    /// Already-materialized bytes are returned as [`Cow::Borrowed`]: the write
    /// path only reads them, so copying a multi-megabyte payload here used to
    /// double the peak for every carrier (review A P2-09).
    pub fn into_buffered(self) -> Result<(Cow<'a, [u8]>, String, bool), StrHideError> {
        Ok(match self {
            PayloadSource::Bytes(b) => (Cow::Borrowed(b), "payload.bin".to_string(), true),
            PayloadSource::File(p) => {
                let mut f = File::open(p)?;
                let mut b = Vec::new();
                f.read_to_end(&mut b)?;
                let name = p
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("payload.bin")
                    .to_string();
                (Cow::Owned(b), name, true)
            }
            PayloadSource::Text(t) => (
                Cow::Owned(normalize_nfc(t).into_bytes()),
                String::new(),
                false,
            ),
            PayloadSource::Stdin => {
                let mut b = Vec::new();
                std::io::stdin().read_to_end(&mut b)?;
                (Cow::Owned(b), String::new(), false)
            }
            PayloadSource::Buffered {
                data,
                filename,
                is_file,
            } => (Cow::Borrowed(data), filename.to_string(), is_file),
        })
    }
}

/// A non-fatal warning attached to a successful write.
///
/// Typed rather than a pre-rendered sentence so a front end can group, filter,
/// or localize it (plan §5.3). Every variant carries the numbers it talks
/// about, so no consumer has to parse them back out of prose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Warning {
    /// The envelope is more than half the size of the carrier, which is
    /// visible as file-size inflation and weakens stealth.
    SizeInflation {
        /// Size of the injected envelope in bytes.
        ube_size: u64,
        /// Size of the carrier before injection, in bytes.
        host_size: u64,
        /// `ube_size / host_size * 100`, rounded to one decimal.
        ratio_pct: f64,
    },
    /// The carrier already shows envelope-shaped structures, so injecting now
    /// would stack a second envelope on top (usually a stealth envelope written
    /// under a password we were not given).
    SuspiciousStructures {
        /// Structural hints reported by the adapter.
        hints: Vec<String>,
    },
}

impl Warning {
    /// The English sentence this warning used to be, kept for CLI rendering.
    pub fn message(&self) -> String {
        match self {
            Warning::SizeInflation {
                ube_size,
                host_size,
                ratio_pct,
            } => format!(
                "Hidden data envelope ({ube_size} bytes) is {ratio_pct:.1}% of the carrier file size ({host_size} bytes), above the 50% inflation warning threshold. Noticeable file size inflation may compromise stealthiness!"
            ),
            Warning::SuspiciousStructures { hints } => format!(
                "Carrier shows structures consistent with a hidden envelope ({}). It may already contain a stealth envelope written with a different password; injecting now would stack a second envelope on top.",
                hints.join("; ")
            ),
        }
    }
    /// Render the warning according to the given context language.
    pub fn render(&self, ctx: crate::core::i18n::RenderCtx) -> String {
        match ctx.lang {
            crate::core::i18n::Lang::En => self.message(),
            crate::core::i18n::Lang::Zh => match self {
                Warning::SizeInflation {
                    ube_size,
                    host_size,
                    ratio_pct,
                } => format!(
                    "隐藏数据信封 ({ube_size} 字节) 占载体大小 ({host_size} 字节) 的 {ratio_pct:.1}%，超出 50% 膨胀告警阈值。显著的文件体积膨胀可能会影响隐蔽性！"
                ),
                Warning::SuspiciousStructures { hints } => format!(
                    "载体呈现与隐藏信封一致的结构 ({})。它可能已包含使用其他密码写入的隐身信封；此时写入可能会堆叠第二个信封。",
                    hints.join("; ")
                ),
            },
        }
    }
}

impl std::fmt::Display for Warning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

/// Outcome of a successful [`write_carrier`]. Serialized to JSON by the CLI.
///
/// `Ok` already means success, so there is no `status` field; every field is
/// typed (format, strategy, paths) instead of being a pre-rendered string.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct WriteResult {
    /// Path the (possibly stego) carrier was written to, or `<memory>` for the
    /// byte-level entry points.
    pub carrier: PathBuf,
    /// Detected carrier format.
    pub format: FileFormat,
    /// Strategy actually chosen, with both its registry id and its name.
    pub strategy: StrategyId,
    /// Human-readable explanation of what the chosen strategy did, when
    /// non-trivial (e.g. automatic fallback to `eof`).
    pub strategy_note: Option<String>,
    /// Uncompressed payload size in bytes.
    pub raw_size: u64,
    /// On-disk size of the injected UBE envelope in bytes.
    pub ube_size: u64,
    /// True when a user password was supplied (FLAG_ENCRYPTED).
    pub is_encrypted: bool,
    /// True when stealth mode was enabled.
    pub is_stealth: bool,
    /// Echo of the password hint, when one was set.
    pub password_hint: Option<String>,
    /// Path of the `<carrier>.bak` file kept for an in-place write, if any.
    pub backup_file: Option<PathBuf>,
    /// Non-fatal warnings, in the order they were detected. Empty on a clean
    /// write (two warnings can co-occur, which is why this is a list).
    pub warnings: Vec<Warning>,
}

/// Outcome of a successful [`read_carrier`] / [`read_carrier_with_dialect`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ReadResult {
    /// Path the carrier was read from, or `<memory>` for the byte-level
    /// entry points.
    pub carrier: PathBuf,
    /// Decrypted, decompressed payload bytes.
    pub data: Vec<u8>,
    /// Whether the envelope declared the payload to be a file (vs inline text).
    pub is_file: bool,
    /// Whether the envelope was encrypted with a user password. False for
    /// no-password envelopes (which use the public built-in key), so the CLI
    /// can warn when a supplied password had no effect.
    pub is_encrypted: bool,
    pub filename: String,
    pub raw_size: u64,
    /// Where the payload was written, when an output path was given.
    pub written_file: Option<PathBuf>,
}

/// Lightweight IPC read outcome summary omitting raw payload bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ReadSummary {
    pub carrier: PathBuf,
    pub is_file: bool,
    pub is_encrypted: bool,
    pub filename: String,
    pub raw_size: u64,
    pub written_file: Option<PathBuf>,
    /// Only present when payload is UTF-8 readable and <= 64 KiB
    pub text_preview: Option<String>,
}

impl ReadSummary {
    /// A summary with no written file and no text preview.
    pub fn new(
        carrier: PathBuf,
        is_file: bool,
        is_encrypted: bool,
        filename: impl Into<String>,
        raw_size: u64,
    ) -> Self {
        Self {
            carrier,
            is_file,
            is_encrypted,
            filename: filename.into(),
            raw_size,
            written_file: None,
            text_preview: None,
        }
    }

    /// Set [`written_file`](Self::written_file).
    pub fn with_written_file(mut self, written_file: Option<PathBuf>) -> Self {
        self.written_file = written_file;
        self
    }

    /// Set [`text_preview`](Self::text_preview).
    pub fn with_text_preview(mut self, text_preview: Option<String>) -> Self {
        self.text_preview = text_preview;
        self
    }
}

impl ReadResult {
    /// Convert to a lightweight [`ReadSummary`] suitable for IPC transfer across WebView/IPC boundaries.
    pub fn summary(&self) -> ReadSummary {
        let text_preview = if self.data.len() <= 64 * 1024 {
            std::str::from_utf8(&self.data).ok().map(|s| s.to_string())
        } else {
            None
        };
        ReadSummary {
            carrier: self.carrier.clone(),
            is_file: self.is_file,
            is_encrypted: self.is_encrypted,
            filename: self.filename.clone(),
            raw_size: self.raw_size,
            written_file: self.written_file.clone(),
            text_preview,
        }
    }
}

/// Outcome of [`inspect_carrier`].
///
/// Every field is `Option`-wrapped so the same type can describe a carrier
/// with no envelope: `has_hidden_data == false`, and all envelope-derived
/// fields are `None`. `strategies` is always populated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InspectResult {
    /// Path inspected.
    pub carrier: PathBuf,
    /// Detected carrier format.
    pub format: FileFormat,
    /// Whether an envelope (standard, or stealth-with-the-supplied-password)
    /// was located.
    pub has_hidden_data: bool,
    /// Strategy the envelope was written with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<StrategyId>,
    /// File offset of the envelope start (virtual offset for scattered
    /// strategies).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ube_offset: Option<u64>,
    /// Total envelope size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ube_total_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_encrypted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_compressed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_stealth: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orig_host_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orig_host_sha256: Option<String>,
    /// Decrypted metadata (payload filename, size, sha256, created_at),
    /// when it could be decrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MetadataInspection>,
    /// Detected suspicious stealth envelope structure markers when has_hidden_data is false.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suspicious_hints: Vec<String>,
    /// Capacity of every supported strategy for this carrier, in recommended
    /// priority order. Always present (also when an envelope already exists,
    /// answering "how much more could fit").
    pub strategies: Vec<StrategyCapacity>,
}

impl InspectResult {
    /// Report for a content-only carrier: the structure domain has no adapter
    /// for `format`, so no envelope can be present and no strategy applies.
    pub fn not_applicable(carrier: &Path, format: FileFormat) -> Self {
        Self {
            carrier: carrier.to_path_buf(),
            format,
            has_hidden_data: false,
            strategy: None,
            ube_offset: None,
            ube_total_size: None,
            is_encrypted: None,
            is_compressed: None,
            is_stealth: None,
            password_hint: None,
            orig_host_size: None,
            orig_host_sha256: None,
            metadata: None,
            suspicious_hints: Vec::new(),
            strategies: Vec::new(),
        }
    }
}

/// Result of one verification level.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct LevelStatus {
    /// Whether the level passed.
    pub ok: bool,
    /// Human-readable detail.
    pub detail: String,
    /// Whether the level could not be attempted at all (for Level 3: a password
    /// is needed but none was supplied).
    ///
    /// A skipped level is **not** a pass, but it is not a failure either: the
    /// caller could not have known either way. [`verify_passed`]
    /// counts it as "not disproven", while a level that ran and failed counts
    /// as a failure.
    #[serde(default)]
    pub skipped: bool,
}

impl LevelStatus {
    /// Render status detail according to context.
    pub fn render(&self, _ctx: crate::core::i18n::RenderCtx) -> &str {
        &self.detail
    }

    /// A level that ran and passed.
    fn pass(detail: impl Into<String>) -> Self {
        Self {
            ok: true,
            detail: detail.into(),
            skipped: false,
        }
    }

    /// A level that ran and failed.
    fn fail(detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            detail: detail.into(),
            skipped: false,
        }
    }

    /// A level that could not be attempted.
    fn skipped(detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            detail: detail.into(),
            skipped: true,
        }
    }
}

/// Outcome of [`verify_carrier`]: three independent checks.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct VerifyResult {
    pub carrier: PathBuf,
    pub format: FileFormat,
    /// Level 1: host container structure still parses (e.g. PNG CRCs, ZIP
    /// central directory, PE headers).
    pub level1_host: LevelStatus,
    /// Level 2: envelope header/trailer found and internally consistent
    /// (version, lengths, CRC, offsets).
    pub level2_envelope: LevelStatus,
    /// Level 3: payload actually decrypts and its SHA-256 matches metadata.
    pub level3_crypto: LevelStatus,
}

impl VerifyResult {
    /// Verdict for a content-only carrier: every structure level is skipped
    /// because there is nothing to verify there.
    pub fn not_applicable(carrier: &Path, format: FileFormat) -> Self {
        let detail = format!(
            "structure domain does not support {} carriers",
            format.as_str()
        );
        Self {
            carrier: carrier.to_path_buf(),
            format,
            level1_host: LevelStatus::skipped(detail.clone()),
            level2_envelope: LevelStatus::skipped(detail.clone()),
            level3_crypto: LevelStatus::skipped(detail),
        }
    }
}

/// Outcome of a successful [`remove_carrier`].
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct RemoveResult {
    /// Path the restored carrier was written to.
    pub carrier: PathBuf,
    /// Size of the restored file (must equal `orig_host_size` recorded in the
    /// envelope).
    pub restored_size: u64,
    /// SHA-256 of the restored file, as a hex string.
    pub restored_sha256: String,
    /// Always `true` on the success path; kept so callers can assert on the
    /// struct rather than just on `Result::is_ok`.
    pub verified_identical: bool,
    /// Path of the backup kept for an in-place removal, if any.
    pub backup_file: Option<PathBuf>,
}

/// Sanitize an untrusted metadata filename down to a safe bare file name.
///
/// Re-exported from [`crate::core::fs`] so the structure-domain path keeps its
/// historical name and both domains share one implementation.
pub use crate::core::fs::sanitize_filename;

/// Typed format of an adapter, or an error when its name is unregistered.
///
/// `format_name()` stays a `&'static str` because adapters are the low-level
/// layer; the public result structs carry the enum, so the conversion happens
/// once, here, instead of at every construction site.
fn adapter_format(adapter: &dyn HostAdapter) -> Result<FileFormat, StrHideError> {
    FileFormat::from_adapter_name(adapter.format_name()).ok_or_else(|| {
        StrHideError::General(format!(
            "Adapter reports unknown format name '{}'",
            adapter.format_name()
        ))
    })
}

/// Build the "no hidden data" error for a carrier that `locate` could not
/// resolve. A stealth envelope written with a password we were not given is
/// invisible to magic-based location by design; `suspicious_structures` gives
/// a password-independent structural opinion, which turns the bare "not found"
/// message into actionable guidance instead of a dead end.
fn no_hidden_data_error(
    carrier: &mut dyn SeekRead,
    adapter: &'static dyn HostAdapter,
    label: &str,
    password_supplied: bool,
) -> StrHideError {
    let mut msg = format!("No hidden strhide data found in '{label}'");
    let hints = adapter.suspicious_structures(carrier);
    if !hints.is_empty() {
        if password_supplied {
            msg.push_str(&format!(
                ". Note: the carrier shows envelope-shaped structures ({}); a stealth envelope may exist under a different password.",
                hints.join("; ")
            ));
        } else {
            msg.push_str(&format!(
                ". Note: the carrier shows envelope-shaped structures ({}); it may contain a stealth envelope - provide the password used at write time with -p/--password to check.",
                hints.join("; ")
            ));
        }
    }
    StrHideError::NoHiddenData(msg)
}

/// Inject `source` into `carrier_path`, returning a [`WriteResult`].
///
/// # Parameters
///
/// - `carrier_path`: an existing supported carrier (PNG/JPEG/MP4/ZIP/PDF/PE).
/// - `source`: where the payload comes from (bytes, file, text, or stdin) —
///   see [`PayloadSource`].
/// - `options`: see [`WriteOptions`]. The defaults match the CLI defaults.
///
/// # Errors
///
/// Returns [`StrHideError::Rejection`] for pre-write safety failures
/// (signed carrier, read-only target), [`StrHideError::General`] for bad
/// arguments or an already-populated carrier, and [`StrHideError::Io`] for
/// filesystem problems. On any error the carrier is left untouched.
///
/// # Examples
///
/// ```no_run
/// use strhide::structure::{write_carrier, PayloadSource, WriteOptions};
/// # fn main() -> Result<(), strhide::errors::StrHideError> {
/// write_carrier(
///     std::path::Path::new("photo.png"),
///     PayloadSource::Text("secret"),
///     &WriteOptions::default().with_password("pw"),
/// )?;
/// # Ok(()) }
/// ```
pub fn write_carrier(
    carrier_path: &Path,
    source: PayloadSource,
    options: &WriteOptions<'_>,
) -> Result<WriteResult, StrHideError> {
    write_carrier_with(
        carrier_path,
        source,
        options,
        &LocalParams::default(),
        &StructureProfile::default(),
    )
}

/// Inject `source` into `carrier_path` with library-level tuning.
///
/// Same as [`write_carrier`], plus:
///
/// - `local`: writer-only knobs ([`LocalParams`]) that the reader never needs.
///   Passing different values than the reader uses is safe.
/// - `dialect`: the private dialect ([`StructureProfile`]). The reader must be
///   given the same dialect; `StructureProfile::default()` is the official one.
///
/// ```no_run
/// use strhide::structure::params::StructureProfile;
/// use strhide::structure::{PayloadSource, WriteOptions, write_carrier_with};
/// use strhide::params::{CompressionStrategy, LocalParams};
/// # fn main() -> Result<(), strhide::errors::StrHideError> {
/// // Both types are `#[non_exhaustive]`: build from `default()` with setters.
/// let dialect = StructureProfile::default().with_default_secret("my-private-dialect");
/// let local = LocalParams::default()
///     .with_chunk_size(64 * 1024)
///     .with_compression(CompressionStrategy::Never);
/// write_carrier_with(
///     std::path::Path::new("photo.png"),
///     PayloadSource::Text("secret"),
///     &WriteOptions::default(),
///     &local,
///     &dialect,
/// )?;
/// # Ok(()) }
/// ```
/// Everything a write produces that does not depend on a path.
struct WriteCoreResult {
    format: FileFormat,
    strategy: StrategyId,
    strategy_note: Option<String>,
    raw_size: u64,
    ube_size: u64,
    is_encrypted: bool,
    is_stealth: bool,
    warnings: Vec<Warning>,
}

/// Build and inject an envelope from `host` into `out`.
///
/// This is the whole protocol, with no filesystem opinions: no existence check,
/// no permission probe, no `.bak`, no atomic rename, no timestamp cloning, and
/// no rejection checks (the caller owns those, because two of them are
/// path-based). [`write_carrier_with`] and [`write_carrier_bytes`] differ only
/// in the I/O objects they hand in and the side effects they add around it.
///
/// `H`/`W` are sized generics rather than `&mut dyn ...`: the adapters take
/// `&mut dyn Write` / `&mut dyn SeekRead`, and passing a concrete type through
/// avoids relying on trait-object upcasting.
fn write_core<H, W>(
    host: &mut H,
    out: &mut W,
    source: PayloadSource,
    options: &WriteOptions<'_>,
    local: &LocalParams,
    profile: &StructureProfile,
    carrier_label: &str,
) -> Result<WriteCoreResult, StrHideError>
where
    H: Read + Seek,
    W: Read + Write + Seek,
{
    local.validate()?;
    // An empty string means "no password", matching the content domain: a
    // caller who passes `Some("")` must not get a stealth envelope derived from
    // an empty secret.
    let password = options.password.filter(|s| !s.is_empty());
    let password_hint = options.password_hint;
    let strategy = options.strategy;
    let stealth = options.stealth;

    if password_hint.is_some() && stealth {
        return Err(StrHideError::General(
            "Password hint is not supported in --stealth mode (stealth mode requires password to locate envelope).".into(),
        ));
    }

    // Stealth mode derives its magics from the password; without a password the
    // envelope would silently degrade to the standard (plaintext-magic) mode,
    // which contradicts the user's stealth expectation. Fail fast instead.
    if stealth && password.is_none() {
        return Err(StrHideError::General(
            "Stealth mode requires a password (provide -p/--password, --password-file, or STRHIDE_PASSWORD).".into(),
        ));
    }

    let hint_bytes = if let Some(hint) = password_hint {
        let norm_hint = normalize_nfc(hint.trim());
        let bytes = norm_hint.into_bytes();
        if bytes.len() > 1024 {
            return Err(StrHideError::General(
                "Password hint cannot exceed 1024 bytes".into(),
            ));
        }
        bytes
    } else {
        Vec::new()
    };

    // 2. Capture carrier facts that live in the envelope: size and full SHA-256.
    // The file variant cannot get these from fs::metadata alone (the hash needs
    // a read pass anyway), so both variants derive them from the stream.
    host.seek(SeekFrom::End(0))?;
    let orig_host_size = host.stream_position()?;
    host.seek(SeekFrom::Start(0))?;
    let orig_host_sha256 = crate::crypto::compute_stream_sha256(host)?;

    // 3. Detect adapter & check existing envelope
    host.seek(SeekFrom::Start(0))?;
    let adapter = find_adapter_or_reject(host, carrier_label)?;

    // 3a. Refuse malformed hosts before touching them. Detection is deliberately
    // cheap (a JPEG is "anything starting with FF D8"), so without this a
    // truncated or forged header followed by arbitrary bytes used to be turned
    // into a stego carrier by the `auto` -> `eof` fallback: strhide would report
    // success while the output was no longer a valid container. Only recognized
    // formats reach this point (unknown files are already rejected), and each
    // adapter's verifier accepts plain, un-stegoed carriers.
    // Derive once: the pre-write verifier needs the same magic the new
    // envelope will use, and the occupied scans below reuse the pair.
    let stealth_magics = match password {
        Some(pwd) => Some(derive_stealth_magics(pwd, profile.domain())?),
        None => None,
    };
    let write_trailer_magic = if stealth {
        stealth_magics.as_ref().map(|m| &m.1)
    } else {
        profile.locator_magic()
    };
    host.seek(SeekFrom::Start(0))?;
    let (structure_ok, detail) = adapter.verify_structure_with_magic(host, write_trailer_magic)?;
    if !structure_ok {
        return Err(StrHideError::CorruptedData(format!(
            "Refusing to write into a malformed {} carrier: {}",
            adapter.format_name(),
            detail
        )));
    }

    // Reject carriers that already contain an envelope. A standard-magic
    // scan catches plain/standard-encrypted envelopes; when a password is
    // available, a second scan with the derived stealth magic also catches
    // stealth envelopes (which are intentionally invisible without it).
    //
    // Under a private magic both scans matter: one for the dialect's own
    // envelopes, one for official ones (a second envelope would stack on
    // top regardless of dialect). With the official profile there is only
    // one scan, exactly as before.
    let mut occupied = {
        host.seek(SeekFrom::Start(0))?;
        adapter.locate(host, profile.locator_magic())?.is_some()
    };
    if !occupied && profile.locator_magic().is_some() {
        host.seek(SeekFrom::Start(0))?;
        occupied = adapter.locate(host, None)?.is_some();
    }
    if occupied {
        return Err(StrHideError::General(
            "Carrier already contains hidden data. Use remove first or specify another file."
                .into(),
        ));
    }
    if let Some((_, ref tr_magic)) = stealth_magics {
        host.seek(SeekFrom::Start(0))?;
        if adapter.locate(host, Some(tr_magic))?.is_some() {
            return Err(StrHideError::General(
                "Carrier already contains hidden data (stealth envelope). Use remove first or specify another file.".into(),
            ));
        }
    }

    // Neither magic scan matched. A stealth envelope written with an unknown
    // password is undetectable by magic; scan structurally and warn (not
    // refuse) when the carrier shows an envelope-shaped container, so the user
    // learns a second envelope would stack on top.
    let structural_warnings = {
        host.seek(SeekFrom::Start(0))?;
        adapter.suspicious_structures(host)
    };

    // 4. Prepare data payload stream
    let (payload_raw_bytes, filename, is_file) = source.into_buffered()?;

    let raw_size = payload_raw_bytes.len() as u64;
    // The reader rejects any declared `raw_size` above `structure_payload_limit`
    // before decrypting. Applying the same bound here (with the same function)
    // means a payload that would be unreadable forever is refused up front
    // instead of producing a carrier that `read` can never extract. The input
    // host is at most as large as the post-injection carrier, so its limit is
    // the stricter of the two and the read path is guaranteed to pass.
    let max_payload = structure_payload_limit(orig_host_size);
    if raw_size > max_payload {
        return Err(StrHideError::PayloadTooLarge(format!(
            "Payload ({} bytes) exceeds the maximum supported by this carrier ({} bytes for a {} byte host); use a larger carrier or a smaller payload",
            raw_size, max_payload, orig_host_size
        )));
    }
    let raw_sha256 = {
        let h = crate::crypto::compute_sha256(&payload_raw_bytes);
        h.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    // 5. Compress data with Deflate. `CompressionStrategy::Auto` keeps the
    // historical integer criterion (cross-language identical: keep compression
    // only when it saves at least 2%: comp_len * 100 < raw_size * 98). The
    // level and the decision are writer-only; the reader just inflates raw
    // deflate when FLAG_COMPRESSED is set.
    //
    // Large payloads are probed first: a full deflate pass over incompressible
    // data costs ~17 ms/MiB and is discarded, so a fixed 256 KiB stratified
    // sample decides whether the full pass is worth starting. The same
    // `should_compress` rule is applied to the sample, so the flag written
    // below always reflects the bytes actually kept.
    let (to_encrypt_bytes, is_compressed) = match local.compression {
        crate::params::CompressionStrategy::Never => (payload_raw_bytes, false),
        strategy => {
            let level = strategy.level();
            let worth_full_pass =
                if payload_raw_bytes.len() > crate::crypto::COMPRESSION_PROBE_MIN_BYTES {
                    let (sample_raw, sample_comp) =
                        crate::crypto::probe_compressibility(&payload_raw_bytes, level)?;
                    strategy.should_compress(sample_raw, sample_comp)
                } else {
                    true
                };

            if !worth_full_pass {
                (payload_raw_bytes, false)
            } else {
                let mut compressed_buf = Vec::new();
                let (_, comp_len) = compress_stream(
                    &mut Cursor::new(&payload_raw_bytes),
                    &mut compressed_buf,
                    level,
                )?;

                if strategy.should_compress(raw_size, comp_len) {
                    // Keep the compressed stream and release the raw payload buffer early.
                    drop(payload_raw_bytes);
                    (Cow::Owned(compressed_buf), true)
                } else {
                    // Keep the raw payload and release the compressed buffer early.
                    drop(compressed_buf);
                    (payload_raw_bytes, false)
                }
            }
        }
    };

    // 6. Keys and Magics
    // `FLAG_ENCRYPTED` means "a user password is required", not "the payload is
    // encrypted": with a private `default_secret` the payload is still sealed
    // (under that secret) but the flag stays clear, so the reader knows not to
    // demand a password and instead uses the profile's secret.
    let has_custom_password = password.is_some();
    let effective_password = password.unwrap_or(profile.secret());
    let mut flags: u8 = 0;
    if has_custom_password {
        flags |= FLAG_ENCRYPTED;
    }
    if is_compressed {
        flags |= FLAG_COMPRESSED;
    }
    if is_file {
        flags |= FLAG_IS_FILE;
    }
    if !hint_bytes.is_empty() {
        flags |= FLAG_HAS_HINT;
    }

    let mut salt = [0u8; 16];
    let mut base_nonce = [0u8; 12];
    rand::rng().fill(&mut salt);
    rand::rng().fill(&mut base_nonce);
    // Payload key, metadata key and header mask are three HKDF expansions of
    // one PBKDF2 output, so they are derived together: a write used to run
    // PBKDF2 twice for the same (password, salt) pair.
    let secrets = derive_all(effective_password, &salt)?;
    let (payload_key, meta_key) = (secrets.payload_key, secrets.meta_key);
    // The mask only applies when the keying secret is the profile default
    // (no user password) or when stealth mode uses the user password. A
    // non-stealth encrypted header stays readable on purpose: without that, a
    // reader given no password could not tell an encrypted envelope from a
    // corrupted file, and the password hint would be unreachable. Its integrity
    // does not depend on the mask -- `EnvelopeHeader::auth_aad` binds the
    // header prefix, the two lengths and the hint into every AEAD seal.
    let header_mask = if !has_custom_password || stealth {
        Some(secrets.header_mask)
    } else {
        None
    };

    let header_magic: [u8; 8];
    let trailer_magic: [u8; 4];

    if stealth && has_custom_password {
        flags |= FLAG_STEALTH;
        let magics = stealth_magics.expect("stealth requires password");
        header_magic = magics.0;
        trailer_magic = magics.1;
    } else {
        // The profile decides the dialect; `StructureProfile::default()` yields the
        // standard magics, byte-identical to every earlier release.
        header_magic = profile.header_magic();
        trailer_magic = profile.trailer_magic();
    }

    // 7. Metadata Block
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let meta_obj = CarrierMetadata {
        filename,
        raw_size,
        raw_sha256,
        created_at,
    };
    // The compact binary block is the only metadata layout; `FLAG_COMPACT_META`
    // is therefore always set and must be in place before the AAD is captured.
    let meta_raw = encode_metadata(&meta_obj)?;
    flags |= FLAG_COMPACT_META;

    // Exact UBE size, computed before any strategy decision. All components are
    // deterministic at this point:
    //   meta_len      = len(meta_raw) + (16 if encrypted else 0)
    //   payload_len   = to_encrypt_len + chunks * 20 if encrypted else to_encrypt_len
    //                    (each encrypted chunk is 4B length + ciphertext + 16B tag;
    //                     an empty payload still emits one empty final chunk)
    // This eliminates the previous under-estimate (4B per chunk) that made the
    // JPEG/PNG/ZIP `auto` capacity checks select a strategy the injector then
    // rejected instead of gracefully falling back to `eof`.
    let to_encrypt_len = to_encrypt_bytes.len() as u64;
    let exact_meta_len = meta_raw.len() as u64 + crate::crypto::AEAD_TAG_LEN as u64;
    // Must use the *configured* chunk size: `exact_ube_size` is cross-checked
    // against the real ciphertext length, so a mismatch here would fail-fast.
    let exact_payload_len = crate::crypto::framed_len(to_encrypt_len, local.chunk_size);
    let exact_ube_size = HEADER_SIZE as u64
        + hint_bytes.len() as u64
        + exact_meta_len
        + exact_payload_len
        + TRAILER_SIZE as u64;

    let selected_strategy: String = if strategy == "auto" {
        host.seek(SeekFrom::Start(0))?;
        adapter
            .choose_auto_strategy(host, exact_ube_size)
            .to_string()
    } else {
        if !adapter.supported_strategies().contains(&strategy) {
            return Err(StrHideError::General(format!(
                "Strategy '{strategy}' not supported by adapter '{}'",
                adapter.format_name()
            )));
        }
        strategy.to_string()
    };

    // 8. Populate Header structure
    let strat_id = strategy_to_id(&selected_strategy)?;
    // Where the envelope lands relative to the injection point. Strategies
    // that prepend a container header (PNG chunk, JPEG APP15 segment, ISO-BMFF
    // box, EBML Void, PDF object) shift it by 4..32 bytes. The shift only
    // depends on the strategy and the envelope size, both known here, so it is
    // computed *before* the header is sealed and therefore lands inside the
    // AAD — that is what makes it tamper-evident, and what lets `verify`
    // cross-check the header against the trailer instead of comparing a value
    // with itself (review R2 P1-9).
    let offset_delta = {
        host.seek(SeekFrom::Start(0))?;
        adapter.envelope_offset_delta(host, &selected_strategy, exact_ube_size)?
    };
    if offset_delta > crate::structure::envelope::MAX_OFFSET_DELTA as u64 {
        return Err(StrHideError::General(format!(
            "Strategy '{selected_strategy}' displaces the envelope by {offset_delta} bytes, which \
             exceeds the {} bytes the header can record",
            crate::structure::envelope::MAX_OFFSET_DELTA
        )));
    }
    let offset_delta_u8 = offset_delta as u8;
    let exact_meta_len_u32 = u32::try_from(exact_meta_len).map_err(|_| {
        StrHideError::General("Metadata block exceeds the 4 GiB envelope field".into())
    })?;
    let mut header = EnvelopeHeader {
        magic_header: header_magic,
        flags,
        strategy_id: strat_id,
        offset_delta: offset_delta_u8,
        salt,
        base_nonce,
        orig_host_size,
        orig_host_sha256,
        hint_len: hint_bytes.len() as u32,
        // The metadata ciphertext length is `plaintext + tag`, both known here,
        // so the field can be filled *before* the seal and take part in the AAD.
        meta_len: exact_meta_len_u32,
        ..Default::default()
    };

    // The authenticated set: header prefix, the two length fields and the hint
    // body. Everything in it is known before the first byte is sealed, and
    // everything a reader must trust before it can check a tag is in it.
    let aad = header.auth_aad(&hint_bytes);

    // Encrypt metadata
    let meta_block = encrypt_metadata(&meta_raw, &meta_key, &base_nonce, &aad)?;
    // `meta_len` was sealed into the AAD above, so a length that disagreed with
    // reality would emit an envelope whose header, metadata block and AAD no
    // longer line up. Fail loudly instead of trusting the pre-computation.
    if meta_block.len() as u64 != exact_meta_len {
        return Err(StrHideError::General(format!(
            "Internal metadata size mismatch: sealed {} bytes, header declares {exact_meta_len}",
            meta_block.len()
        )));
    }

    // Assemble the UBE prefix first, then append the ciphertext directly into
    // the same buffer. The old path encrypted into a second full-size Vec and
    // then copied it into the envelope, so plaintext, ciphertext and envelope
    // were all resident at once (~3x the payload).
    let mut tmp_ube = Vec::with_capacity(exact_ube_size as usize);
    tmp_ube.extend_from_slice(&header.pack_masked(header_mask.as_ref()));
    if !hint_bytes.is_empty() {
        tmp_ube.extend_from_slice(&hint_bytes);
    }
    tmp_ube.extend_from_slice(&meta_block);

    // Encrypt payload stream directly into the envelope buffer.
    let payload_written = encrypt_stream_to_chunks(
        &mut Cursor::new(&to_encrypt_bytes),
        &mut tmp_ube,
        &payload_key,
        &base_nonce,
        &aad,
        local.chunk_size,
    )?;
    // Release the plaintext before the injector reads the envelope: only the
    // ciphertext copy is needed from here on.
    drop(to_encrypt_bytes);

    let ube_total_size = HEADER_SIZE as u64
        + hint_bytes.len() as u64
        + header.meta_len as u64
        + payload_written
        + TRAILER_SIZE as u64;

    // Defensive cross-check: the exact pre-computation above must match reality.
    // A mismatch would indicate a protocol drift between crypto and engine.
    if ube_total_size != exact_ube_size {
        return Err(StrHideError::General(format!(
            "Internal envelope size mismatch: computed {ube_total_size}, expected {exact_ube_size}"
        )));
    }

    // Non-fatal warnings. Both can fire for one write, so they are collected
    // instead of being merged into one sentence.
    let mut warnings = Vec::new();
    if orig_host_size > 0 && ube_total_size > (orig_host_size / 2) {
        let ratio_pct = (ube_total_size as f64 / orig_host_size as f64) * 100.0;
        // State the measured ratio and refer to the threshold separately. The
        // old text hard-coded "exceeds 50.0%" next to the real percentage,
        // which read like a contradiction for tiny carriers (e.g. "50.0% ...
        // 319.4%").
        warnings.push(Warning::SizeInflation {
            ube_size: ube_total_size,
            host_size: orig_host_size,
            ratio_pct,
        });
    }
    // Probable pre-existing stealth envelope.
    if !structural_warnings.is_empty() {
        warnings.push(Warning::SuspiciousStructures {
            hints: structural_warnings.clone(),
        });
    }

    // Finish the envelope: the dummy trailer carries placeholder coordinates
    // that are patched into the written file after injection.
    let dummy_trailer = if stealth && has_custom_password {
        EnvelopeTrailer::create_stealth(0, ube_total_size, trailer_magic)
    } else {
        EnvelopeTrailer::create(0, ube_total_size, trailer_magic)
    };
    tmp_ube.extend_from_slice(&dummy_trailer.pack());

    // 9. Inject into `out`. Where that is (temp file vs memory buffer, and the
    // atomic-rename dance around it) is the caller's business.
    let (inject_offset, inject_size, patch_offset, orig_patch_val) = {
        host.seek(SeekFrom::Start(0))?;
        let mut ube_cursor = Cursor::new(&tmp_ube);
        adapter.inject(host, &mut ube_cursor, out, &selected_strategy)?
    };

    // 10. Update real ube_offset in Header and Trailer.
    //
    // The shift was computed before the header was sealed (it is part of the
    // AAD), so this only applies it. Recomputing it here would let the two
    // disagree silently; the debug assertion keeps the pre-computation honest.
    debug_assert_eq!(
        {
            host.seek(SeekFrom::Start(0))?;
            offset_delta
        },
        adapter
            .envelope_offset_delta(host, &selected_strategy, ube_total_size)
            .unwrap_or(u64::MAX),
        "envelope offset delta changed between pre-seal and post-inject"
    );
    let actual_ube_offset = inject_offset + offset_delta;

    header.inject_offset = inject_offset;
    header.inject_size = inject_size;
    header.patch_offset = patch_offset;
    header.orig_patch_val = orig_patch_val;

    let final_trailer = if stealth && has_custom_password {
        EnvelopeTrailer::create_stealth(actual_ube_offset, ube_total_size, trailer_magic)
    } else {
        EnvelopeTrailer::create(actual_ube_offset, ube_total_size, trailer_magic)
    };

    // Scattered strategies (pe_codebits) embed the final envelope bytes during
    // inject(): inject_offset/inject_size are 0 by definition and the trailer
    // was assembled with ube_offset = 0, so there is nothing to patch at file
    // offsets. Patching anyway would overwrite host bytes (offset 0 is the MZ
    // header of a PE).
    let scattered = adapter.is_scattered_strategy(&selected_strategy);
    if !scattered {
        // Patch header
        out.seek(SeekFrom::Start(actual_ube_offset))?;
        out.write_all(&header.pack_masked(header_mask.as_ref()))?;

        // Patch trailer at end of UBE
        let trailer_ctx = TrailerCtx {
            actual_ube_offset,
            ube_total_size,
            inject_offset,
            inject_size,
            strategy: &selected_strategy,
        };
        let trailer_pos = adapter.trailer_offset(&trailer_ctx);
        out.seek(SeekFrom::Start(trailer_pos))?;
        out.write_all(&final_trailer.pack())?;

        // Post-write finalization (e.g. recalculating chunk CRCs)
        let fin_ctx = FinalizeCtx {
            ube_offset: actual_ube_offset,
            ube_total_size,
            inject_offset,
            inject_size,
            strategy: &selected_strategy,
        };
        adapter.finalize(out, &fin_ctx)?;
    }

    // Post-write self-check (review §5.2): inject and locate must agree on
    // where the envelope landed, or the write reports success for data that
    // read/inspect/remove can never reach. Matching against the trailer magic
    // this write produced is exactly what the read path demands, so a fresh
    // output its own locate cannot find aborts here instead of orphaning the
    // envelope. Cost: one streaming locate pass over the output.
    out.flush()?;
    out.seek(SeekFrom::Start(0))?;
    let self_located = adapter.locate(out, Some(&trailer_magic))?;
    // `Some` alone is not enough: a second envelope with the same trailer magic
    // could satisfy `locate` while `read` / `remove` would then reach the *old*
    // one. Require the coordinates this very write sealed into the trailer.
    let located_at = self_located.as_ref().map(|(o, s, _)| (*o, *s));
    if located_at != Some((actual_ube_offset, ube_total_size)) {
        return Err(StrHideError::General(format!(
            "Post-write self-check failed: strategy '{}' wrote the envelope at {} ({} bytes), but locate returned {:?}; aborting so no unreadable stego is committed",
            selected_strategy, actual_ube_offset, ube_total_size, located_at
        )));
    }

    let strategy_note = adapter.strategy_note(&selected_strategy, strategy == "auto");

    Ok(WriteCoreResult {
        format: FileFormat::from_adapter_name(adapter.format_name())
            .expect("every registered adapter maps to a FileFormat"),
        strategy: StrategyId::from_name(&selected_strategy)
            .expect("the selected strategy comes from STRATEGY_REGISTRY"),
        strategy_note,
        raw_size,
        ube_size: ube_total_size,
        is_encrypted: has_custom_password,
        is_stealth: (flags & FLAG_STEALTH) != 0,
        warnings,
    })
}

/// Inject `source` into `carrier_path`, staging through a temp file and an
/// atomic rename.
///
/// Everything path-shaped lives here: rejection checks, permission probing, the
/// `.bak` backup, the rename, and timestamp cloning. The protocol itself is in
/// `write_core`, which is why [`write_carrier_bytes`] can offer the same
/// guarantees minus the filesystem ones.
pub fn write_carrier_with(
    carrier_path: &Path,
    source: PayloadSource,
    options: &WriteOptions<'_>,
    local: &LocalParams,
    profile: &StructureProfile,
) -> Result<WriteResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let target_path = options.output_path.unwrap_or(carrier_path);

    if !same_file(target_path, carrier_path) {
        crate::core::pipeline::check_overwrite(target_path, options.overwrite)?;
    }
    // Fail before the envelope work: a read-only target would otherwise fail
    // the final rename with a misleading `TargetBusy`.
    crate::commit::reject_read_only_target(target_path)?;
    // Held until the commit finishes: a concurrent writer to the same target
    // must fail instead of silently replacing this envelope.
    let _target_lock = crate::commit::TargetLock::acquire(target_path)?;

    // 1. Run security rejection checks (carrier policy + target permissions)
    run_rejection_checks(carrier_path, target_path, local.rejection)?;

    let meta = std::fs::metadata(carrier_path)?;
    let orig_permissions = meta.permissions();
    let orig_atime = filetime::FileTime::from_last_access_time(&meta);
    let orig_mtime = filetime::FileTime::from_last_modification_time(&meta);

    // Collision-free temp file guard prevents races under concurrent execution.
    // TmpGuard removes the half-written file on any early return unless `commit()`
    // runs after the rename succeeded.
    let tmp_target = temp_path_for(target_path);
    let mut tmp_guard = TmpGuard::new(tmp_target.clone());

    let core = {
        let mut host = File::open(carrier_path)?;
        // Read+write, not `File::create`: the patch/finalize step seeks back
        // into the staged output and adapter `finalize` implementations may
        // read what they just wrote (a write-only handle fails with
        // "access denied" on Windows).
        let mut out_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_target)
            .map_err(|e| {
                let dir = match target_path.parent() {
                    Some(p) if !p.as_os_str().is_empty() => p,
                    _ => Path::new("."),
                };
                let reason = match e.kind() {
                    std::io::ErrorKind::NotFound => "the output directory does not exist",
                    std::io::ErrorKind::PermissionDenied => "the output directory is not writable",
                    _ => "the output file could not be created",
                };
                StrHideError::General(format!(
                    "Cannot create '{}' in '{}': {reason} [{e}]",
                    target_path.display(),
                    dir.display()
                ))
            })?;
        let mut pw = crate::core::control::ProgressWriter::new(
            &mut out_file,
            options.control,
            crate::core::control::Stage::Write,
            meta.len(),
        );
        let carrier_label = carrier_path.display().to_string();
        let core = write_core(
            &mut host,
            &mut pw,
            source,
            options,
            local,
            profile,
            &carrier_label,
        )
        .map_err(|e| crate::core::control::map_io_cancel(&options.control, e))?;
        // Durability before the rename, the same contract `commit.rs` applies to
        // every payload write: renaming first and syncing later leaves a window
        // where the new name exists with an unwritten tail. `pw` borrows
        // `out_file`, and its last use is the `write_core` call above, so the
        // borrow is already over here.
        out_file.sync_all()?;
        core
    };

    // Strict cancellation check before .bak creation and atomic commit
    options.control.check()?;

    // 2. In-place backup (if applicable) & Atomic commit
    let is_inplace = same_file(target_path, carrier_path);
    let mut backup_file = None;
    if is_inplace && options.backup {
        backup_file = Some(crate::commit::create_carrier_backup(carrier_path)?);
    }

    crate::commit::rename_with_retry(&tmp_target, target_path)?;
    tmp_guard.commit();
    crate::commit::sync_parent_dir(target_path);

    // Timestamps first, permissions second: restoring the carrier's read-only
    // attribute first would make the timestamp update fail on Windows and be
    // dropped silently. Warn instead of swallowing the failure (the write
    // itself succeeded).
    if options.preserve_time
        && let Err(e) = filetime::set_file_times(target_path, orig_atime, orig_mtime)
    {
        log::warn!(
            "failed to preserve file timestamps for '{}': {e}",
            target_path.display()
        );
    }
    if let Err(e) = std::fs::set_permissions(target_path, orig_permissions) {
        log::warn!(
            "failed to restore file permissions for '{}': {e}",
            target_path.display()
        );
    }

    Ok(WriteResult {
        carrier: target_path.to_path_buf(),
        format: core.format,
        strategy: core.strategy,
        strategy_note: core.strategy_note,
        raw_size: core.raw_size,
        ube_size: core.ube_size,
        is_encrypted: core.is_encrypted,
        is_stealth: core.is_stealth,
        password_hint: options.password_hint.map(|s| s.to_string()),
        backup_file,
        warnings: core.warnings,
    })
}

/// Inject `source` into an in-memory carrier, returning the stego bytes.
///
/// Same protocol and same self-verification as [`write_carrier_with`], minus
/// everything that only makes sense for a file. Three capabilities are
/// deliberately *not* provided, and the absence is the reason this entry point
/// exists for services that have no writable filesystem:
///
/// - **no atomic commit** — the caller owns the buffer it gets back; there is no
///   half-written state to roll back because nothing is written until it
///   decides to;
/// - **no `<carrier>.bak`** — the original bytes are still in the caller's
///   hands (`options.backup` is ignored);
/// - **no timestamp cloning** — there is no inode to stamp
///   (`options.preserve_time` is ignored).
///
/// Rejection checks are content-only: the path-based ones (read-only carrier,
/// target-directory write probe, `.apk`/signature-file name checks) describe
/// the filesystem, not the carrier. [`crate::structure::rejection::check_content`] still
/// refuses Authenticode/PDF/JAR-signed carriers, which is the part that matters
/// for "do not break someone's signature".
///
/// `options.output_path` must be `None`: honouring it here would silently write
/// a file from a function whose contract is "give me bytes".
pub fn write_carrier_bytes(
    carrier: &[u8],
    source: PayloadSource,
    options: &WriteOptions<'_>,
    local: &LocalParams,
    profile: &StructureProfile,
) -> Result<(Vec<u8>, WriteResult), StrHideError> {
    if let Some(p) = options.output_path {
        return Err(StrHideError::General(format!(
            "write_carrier_bytes returns the stego bytes instead of writing a file; \
             output_path '{}' is not honoured (use write_carrier_with for file output)",
            p.display()
        )));
    }

    let mut host = Cursor::new(carrier);
    if local.rejection != crate::params::RejectionPolicy::Skip {
        host.seek(SeekFrom::Start(0))?;
        crate::structure::rejection::check_content(&mut host, None)?;
    }

    let mut out = Cursor::new(Vec::new());
    let core = write_core(
        &mut host, &mut out, source, options, local, profile, "<memory>",
    )?;
    let bytes = out.into_inner();

    let result = WriteResult {
        carrier: PathBuf::from("<memory>"),
        format: core.format,
        strategy: core.strategy,
        strategy_note: core.strategy_note,
        raw_size: core.raw_size,
        ube_size: core.ube_size,
        is_encrypted: core.is_encrypted,
        is_stealth: core.is_stealth,
        password_hint: options.password_hint.map(|s| s.to_string()),
        backup_file: None,
        warnings: core.warnings,
    };
    Ok((bytes, result))
}

/// Extract the payload of a carrier, in the official dialect.
///
/// [`ReadOptions`] carries the destination, the password, and the overwrite
/// decision. Without [`ReadOptions::overwrite`], an existing destination is an
/// error: silently truncating it would lose a user file, which contradicts the
/// tool's "lossless, restorable" contract.
///
/// Call [`read_carrier_with_dialect`] when a private
/// [`StructureProfile`] was used at write time.
pub fn read_carrier(
    carrier_path: &Path,
    options: &ReadOptions<'_>,
) -> Result<ReadResult, StrHideError> {
    read_carrier_with_dialect(carrier_path, options, &StructureProfile::default())
}

/// Everything a successful read produces before any file is written.
///
/// Deliberately I/O-free: the same core serves [`read_carrier_with_profile`]
/// (path in, path out) and [`read_carrier_bytes`] (bytes in, bytes out), so the
/// two can never drift apart on envelope parsing.
struct ReadCore {
    data: Vec<u8>,
    is_file: bool,
    is_encrypted: bool,
    filename: String,
    raw_size: u64,
}

struct AuthenticatedEnvelope<'a> {
    ube_stream: Box<dyn SeekRead + 'a>,
    header: EnvelopeHeader,
    meta_obj: CarrierMetadata,
    payload_key: [u8; 32],
    /// Authenticated associated data this envelope's seals were bound to:
    /// header prefix + the two length fields + the hint body.
    aad: Vec<u8>,
    total_payload_bytes: u64,
}

/// Locate, unpack and authenticate envelope metadata and derive crypto keys.
fn open_and_authenticate_envelope<'a>(
    host: &'a mut dyn SeekRead,
    label: &str,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<AuthenticatedEnvelope<'a>, StrHideError> {
    let password = password.filter(|s| !s.is_empty());
    let adapter = find_adapter_or_reject(host, label)?;

    let Located {
        location,
        stealth_header_magic,
        ..
    } = locate_envelope_with_magic(host, adapter, password, profile)?;

    let location = match location {
        Some(l) => l,
        None => {
            return Err(no_hidden_data_error(
                host,
                adapter,
                label,
                password.is_some(),
            ));
        }
    };

    open_authenticated_at(
        host,
        adapter,
        location,
        password,
        profile,
        stealth_header_magic,
        None,
    )
}

/// [`open_and_authenticate_envelope`] for an envelope the caller already
/// located.
///
/// `precomputed` lets `verify` hand over the `UnpackSecrets` it derived for
/// Level 2, so Level 3 does not repeat PBKDF2 over the same (password, salt)
/// pair (review P1-7).
fn open_authenticated_at<'a>(
    host: &'a mut dyn SeekRead,
    adapter: &dyn HostAdapter,
    location: (u64, u64, String),
    password: Option<&str>,
    profile: &StructureProfile,
    stealth_header_magic: Option<[u8; 8]>,
    precomputed: Option<&UnpackSecrets>,
) -> Result<AuthenticatedEnvelope<'a>, StrHideError> {
    let (ube_offset, ube_total_size, strategy_name) = location;

    // Captured before the envelope reader borrows `host`; the strip path needs
    // the physical carrier bound to reject out-of-range header coordinates.
    let host_len = host.seek(SeekFrom::End(0))?;

    let mut ube_stream =
        adapter.open_ube_reader(host, ube_offset, ube_total_size, &strategy_name)?;

    let mut header_bytes = [0u8; HEADER_SIZE];
    ube_stream.read_exact(&mut header_bytes)?;

    let secrets = match precomputed {
        Some(s) => *s,
        None => {
            let salt = EnvelopeHeader::salt_of(&header_bytes).unwrap_or([0u8; 16]);
            UnpackSecrets {
                password: match password {
                    Some(pwd) => Some(derive_all(pwd, &salt)?),
                    None => None,
                },
                default: if password.is_none() {
                    Some(derive_all(profile.secret(), &salt)?)
                } else {
                    None
                },
                stealth_header_magic,
            }
        }
    };
    let header = EnvelopeHeader::unpack_with_secrets(&header_bytes, password, profile, &secrets)?;
    header.validate_against(ube_total_size, host_len)?;

    // `hint_len` is capped at `MAX_HINT_LEN` by `validate_against`, so this
    // allocation is bounded. The raw bytes are kept: they are part of the AAD,
    // while `hint_str` exists only for display.
    let mut hint_bytes: Vec<u8> = Vec::new();
    if header.hint_len > 0 {
        hint_bytes = vec![0u8; header.hint_len as usize];
        ube_stream.read_exact(&mut hint_bytes)?;
    }
    let hint_str = if hint_bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&hint_bytes).to_string())
    };

    let aad = header.auth_aad(&hint_bytes);

    let (payload_key, meta_key) = if header.is_encrypted() {
        secrets.password.as_ref().map_or_else(
            || {
                let message = match &hint_str {
                    Some(h) => format!("Password required to extract hidden data. Hint: '{h}'."),
                    None => "Password required to extract hidden data".into(),
                };
                Err(StrHideError::PasswordWithHint {
                    message,
                    hint: hint_str.clone(),
                })
            },
            |s| Ok((s.payload_key, s.meta_key)),
        )?
    } else {
        match &secrets.default {
            Some(s) => (s.payload_key, s.meta_key),
            None => derive_keys(profile.secret(), &header.salt)?,
        }
    };

    // `validate_against` capped `meta_len` at `MAX_META_LEN`, so the buffer a
    // forged field can request is 256 KiB, not 4 GiB.
    let mut meta_bytes = vec![0u8; header.meta_len as usize];
    ube_stream.read_exact(&mut meta_bytes)?;

    let meta_obj = decrypt_metadata(&meta_bytes, &meta_key, &header.base_nonce, &aad)
        .map_err(|_| StrHideError::Password("Invalid password or corrupted metadata".into()))
        .and_then(|plain| decode_metadata(&plain, header.is_compact_meta()))?;

    let total_payload_bytes = ube_total_size
        - (HEADER_SIZE as u64
            + TRAILER_SIZE as u64
            + header.hint_len as u64
            + header.meta_len as u64);

    Ok(AuthenticatedEnvelope {
        ube_stream,
        header,
        meta_obj,
        payload_key,
        aad,
        total_payload_bytes,
    })
}

/// Upper bound on the payload a carrier of `carrier_len` bytes may declare.
///
/// `MAX_VERIFY_PAYLOAD_SIZE` (1 GiB) used to be the only check, and it ran *after*
/// the whole ciphertext had been decrypted into memory. A small carrier holding
/// a high-ratio compressed stream could therefore make the reader allocate up to
/// 1 GiB before rejecting anything. Scale the limit with the physical carrier
/// size instead, keep a 64 MiB floor for legitimate payloads in small carriers,
/// and keep the absolute cap as the ceiling.
fn structure_payload_limit(carrier_len: u64) -> u64 {
    const FLOOR: u64 = 64 * 1024 * 1024;
    carrier_len
        .saturating_mul(256)
        .clamp(FLOOR, crate::crypto::MAX_VERIFY_PAYLOAD_SIZE)
}

/// Clamp every advertised strategy capacity to the payload limit the engine
/// actually enforces for a host of `host_len` bytes.
///
/// A strategy whose native ceiling is lower than the engine limit keeps its
/// own value and text; an unbounded (`None`, "file grows") or higher ceiling
/// is rewritten to the effective limit so the report is the number the writer
/// accepts, not the theoretical container maximum.
fn apply_engine_payload_limit(
    strategies: &mut [crate::structure::adapters::StrategyCapacity],
    host_len: u64,
) {
    let engine_limit = structure_payload_limit(host_len);
    for cap in strategies.iter_mut() {
        let exceeds = match cap.capacity_bytes {
            Some(native) => native > engine_limit,
            None => true,
        };
        if exceeds {
            cap.capacity_bytes = Some(engine_limit);
            cap.limit = format!(
                "<= {} B (engine payload limit for this host)",
                crate::structure::adapters::format_bytes(engine_limit)
            );
        }
    }
}

/// Locate, authenticate and decrypt the envelope in `host`.
///
/// `label` only appears in error messages ("'photo.png'" vs "'<memory>'").
fn read_core(
    host: &mut dyn SeekRead,
    label: &str,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<ReadCore, StrHideError> {
    // Captured before the envelope reader borrows `host`; `open_and_authenticate`
    // seeks around while locating the envelope.
    let carrier_len = host.seek(SeekFrom::End(0))?;
    let mut env = open_and_authenticate_envelope(host, label, password, profile)?;

    // Bound the declared output size *before* decrypting: the chunk ciphertext
    // itself is already bounded by the carrier, but `raw_size` drives the
    // decompression buffer and is only protected by the (public-key) metadata
    // seal on non-password envelopes. One MiB of slack covers chunk framing for
    // a genuinely large uncompressed payload.
    let max_safe_size = structure_payload_limit(carrier_len);
    if env.meta_obj.raw_size > max_safe_size {
        return Err(StrHideError::General(format!(
            "Declared payload size ({} bytes) exceeds the safe decompression limit ({} bytes)",
            env.meta_obj.raw_size, max_safe_size
        )));
    }
    if env.total_payload_bytes > max_safe_size.saturating_add(1 << 20) {
        return Err(StrHideError::General(format!(
            "Envelope payload stream ({} bytes) exceeds the safe decompression limit ({} bytes)",
            env.total_payload_bytes, max_safe_size
        )));
    }

    let mut decrypted_payload = Vec::new();
    decrypt_stream_from_chunks(
        &mut env.ube_stream,
        &mut decrypted_payload,
        &env.payload_key,
        &env.header.base_nonce,
        &env.aad,
        env.total_payload_bytes,
    )?;

    let data = if env.header.is_compressed() {
        let mut decomp = Vec::with_capacity(env.meta_obj.raw_size.min(1024 * 1024) as usize);
        decompress_stream(
            &mut Cursor::new(&decrypted_payload),
            &mut decomp,
            env.meta_obj.raw_size,
        )?;
        decomp
    } else {
        decrypted_payload
    };

    let actual_sha256 = {
        let h = crate::crypto::compute_sha256(&data);
        h.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    if actual_sha256 != env.meta_obj.raw_sha256 {
        return Err(StrHideError::CorruptedData(format!(
            "Payload SHA-256 mismatch: {actual_sha256} != {}",
            env.meta_obj.raw_sha256
        )));
    }

    // The metadata filename is attacker-controlled input (unencrypted
    // envelopes especially), and every caller that writes the payload out
    // trusts it: sanitise once here so no consumer can turn it into a path.
    let filename = if env.meta_obj.filename.is_empty() {
        String::new()
    } else {
        sanitize_filename(&env.meta_obj.filename)
    };

    Ok(ReadCore {
        data,
        is_file: env.header.is_file(),
        is_encrypted: env.header.is_encrypted(),
        filename,
        raw_size: env.meta_obj.raw_size,
    })
}

/// Streamingly verify Level 3 payload decryption and SHA-256, enforcing a
/// 1 GiB limit and using minimal memory (~4 MiB chunk buffer).
fn verify_authenticated_payload(env: &mut AuthenticatedEnvelope<'_>) -> Result<u64, StrHideError> {
    crate::crypto::verify_payload_stream(
        &mut env.ube_stream,
        &env.payload_key,
        &env.header.base_nonce,
        &env.aad,
        env.total_payload_bytes,
        env.header.is_compressed(),
        env.meta_obj.raw_size,
        &env.meta_obj.raw_sha256,
        crate::crypto::MAX_VERIFY_PAYLOAD_SIZE,
    )
}

/// Write the recovered payload to `out_p`, returning the path actually used.
///
/// `out_p` may name a file or an existing directory; in the latter case the
/// untrusted metadata filename is sanitised down to a bare name so a crafted
/// carrier cannot write outside that directory.
fn write_payload_to(
    out_p: &Path,
    carrier_path: &Path,
    core: &ReadCore,
    overwrite: bool,
) -> Result<PathBuf, StrHideError> {
    let final_dest = if out_p.is_dir() {
        let fn_to_use = if core.filename.is_empty() {
            "extracted.bin".to_string()
        } else {
            sanitize_filename(&core.filename)
        };
        out_p.join(fn_to_use)
    } else {
        out_p.to_path_buf()
    };

    // Writing the payload over its own carrier truncates the file that still
    // holds the hidden data, so the extraction would destroy its own source.
    if same_file(&final_dest, carrier_path) {
        return Err(StrHideError::Rejection(format!(
            "Refusing to write the extracted payload over carrier '{}': choose a different output path",
            carrier_path.display()
        )));
    }

    // Never truncate an existing file by accident: extracting several
    // carriers that contain the same payload name (or reading into a busy
    // directory) used to replace user files silently.
    crate::core::pipeline::check_overwrite(&final_dest, overwrite)?;

    // Write through a sibling temp file and rename, exactly like every carrier
    // commit does. A plain `File::create` left a half-written payload behind
    // when the disk filled up or the process was killed, and it followed a
    // pre-existing symlink at the destination instead of replacing the name
    // (review R2 P0-7).
    crate::core::commit::write_bytes_atomic(&final_dest, &core.data).map_err(|err| {
        let reason = match &err {
            StrHideError::Io(e) => match e.kind() {
                std::io::ErrorKind::NotFound => "the output directory does not exist",
                std::io::ErrorKind::PermissionDenied => "the output directory is not writable",
                _ => "the output file could not be created",
            },
            _ => "the output file could not be created",
        };
        StrHideError::General(format!(
            "Cannot create '{}': {reason} [{err}]",
            final_dest.display()
        ))
    })?;
    Ok(final_dest)
}

/// Extract the payload of a carrier written under `dialect`.
///
/// The dialect must be the same one used at write time. For the official
/// dialect this is identical to [`read_carrier`]; for a private dialect a
/// mismatched profile cannot return payload bytes — the envelope is either not
/// found at all (stealth, or a custom trailer magic) or fails header/`AEAD`
/// validation (custom `default_secret` with the standard magics).
pub fn read_carrier_with_dialect(
    carrier_path: &Path,
    options: &ReadOptions<'_>,
    dialect: &StructureProfile,
) -> Result<ReadResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let label = carrier_path.display().to_string();
    options.control.stage(crate::core::control::Stage::Read);
    options.control.check()?;
    let mut f = File::open(carrier_path)?;
    let core = read_core(&mut f, &label, options.password, dialect)?;
    options.control.check()?;
    let written_file = match options.output_path {
        Some(out_p) => {
            options.control.stage(crate::core::control::Stage::Write);
            Some(write_payload_to(
                out_p,
                carrier_path,
                &core,
                options.overwrite,
            )?)
        }
        None => None,
    };

    Ok(ReadResult {
        carrier: carrier_path.to_path_buf(),
        data: core.data,
        is_file: core.is_file,
        is_encrypted: core.is_encrypted,
        filename: core.filename,
        raw_size: core.raw_size,
        written_file,
    })
}

/// Extract the payload of an in-memory carrier.
///
/// Identical validation to [`read_carrier_with_dialect`] (format detection,
/// AEAD authentication, SHA-256 check); `written_file` is always `None` because
/// nothing is written — the caller already has the bytes.
pub fn read_carrier_bytes(
    carrier: &[u8],
    password: Option<&str>,
    dialect: &StructureProfile,
) -> Result<ReadResult, StrHideError> {
    let mut host = Cursor::new(carrier);
    let core = read_core(&mut host, "<memory>", password, dialect)?;
    Ok(ReadResult {
        carrier: PathBuf::from("<memory>"),
        data: core.data,
        is_file: core.is_file,
        is_encrypted: core.is_encrypted,
        filename: core.filename,
        raw_size: core.raw_size,
        written_file: None,
    })
}

/// Strip the envelope from `carrier_path` and restore the original carrier
/// bit-for-bit, in the official dialect.
///
/// When [`RestoreOptions::output_path`] is `None` the carrier is rewritten in
/// place; otherwise the restored bytes are written there (the original carrier
/// is untouched).
///
/// The restored file is hashed and compared to the `orig_host_size` /
/// `orig_host_sha256` recorded in the envelope. On mismatch the new file is
/// discarded and [`StrHideError::RestoreMismatch`] is returned — usually
/// because a second envelope was layered on top and must be removed first.
///
/// A password is required when the envelope was written either encrypted or in
/// stealth mode: the metadata seal is authenticated before anything is stripped,
/// and that needs the derived key. A plaintext, non-stealth envelope still
/// restores without a password.
///
/// When [`RestoreOptions::backup`] is true and the write is in place, a
/// `<carrier>.bak` file is kept before overwriting.
pub fn remove_carrier(
    carrier_path: &Path,
    options: &RestoreOptions<'_>,
) -> Result<RemoveResult, StrHideError> {
    remove_carrier_with_dialect(carrier_path, options, &StructureProfile::default())
}

/// Strip the envelope from `host` into `out`, returning the envelope header.
///
/// I/O-free core shared by [`remove_carrier_with`] and
/// [`remove_carrier_bytes`]. Verification is a separate step
/// ([`verify_restored`]) because the caller owns the restored stream: the file
/// wrapper reopens the temp file, the in-memory wrapper rewinds its cursor.
fn remove_core(
    host: &mut dyn SeekRead,
    out: &mut dyn SeekWrite,
    label: &str,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<EnvelopeHeader, StrHideError> {
    let password = password.filter(|s| !s.is_empty());
    let host_len = host.seek(SeekFrom::End(0))?;
    let adapter = find_adapter_or_reject(host, label)?;
    let located = locate_envelope_with_magic(host, adapter, password, profile)?;
    let (ube_offset, ube_total_size, strategy_name) = match located.location {
        Some(l) => l,
        None => {
            return Err(no_hidden_data_error(
                host,
                adapter,
                label,
                password.is_some(),
            ));
        }
    };

    // Decrypt the metadata AEAD before trusting any coordinate from the header.
    // `patch_offset` and the injection geometry are not covered by the seal, and
    // the old remove path stripped straight from an unauthenticated header, so a
    // forged `patch_offset` could drive `strip` outside the carrier. This also
    // makes `verified_identical` truthful: a header whose metadata seal does not
    // open is rejected before anything is written.
    let header = {
        let env = open_authenticated_at(
            host,
            adapter,
            (ube_offset, ube_total_size, strategy_name.clone()),
            password,
            profile,
            located.stealth_header_magic,
            None,
        )?;
        env.header.clone()
    };

    let strip_header = strip_coordinates_for_location(&header, ube_offset, &strategy_name)?;
    // Bound the (possibly relocated) injected region against the physical
    // carrier. The post-injection coordinates are outside any AEAD, so this is
    // what stops a forged `inject_offset`/`inject_size` from driving `strip`
    // past EOF. `envelope_coordinates_agree` also accepts the legitimate shift
    // of a PNG `chunk` envelope moved by content re-compression.
    envelope_coordinates_agree(
        &header,
        &strategy_name,
        ube_offset,
        ube_total_size,
        host_len,
    )
    .map_err(StrHideError::CorruptedData)?;
    adapter.strip(host, out, &strip_header)?;
    Ok(header)
}

/// Return header coordinates translated to the *located* envelope position.
///
/// A PNG `chunk` or appended EOF envelope can move after it was written:
/// content-domain embedding re-compresses IDAT (or re-encodes the media), which
/// changes the length of the stream preceding the envelope and therefore its
/// physical offset. The envelope trailer is authenticated, but its `ube_offset`
/// is the coordinate from write time, so `strip` must be told where the envelope
/// really is. All other strategies are anchored at write time; a mismatch there
/// means corruption.
fn strip_coordinates_for_location(
    header: &EnvelopeHeader,
    ube_offset: u64,
    strategy: &str,
) -> Result<EnvelopeHeader, StrHideError> {
    let declared = header
        .inject_offset
        .checked_add(header.offset_delta as u64)
        .ok_or_else(|| StrHideError::CorruptedData("inject_offset overflow".into()))?;
    if declared == ube_offset {
        return Ok(header.clone());
    }
    if !matches!(strategy, "chunk" | "eof") {
        return Err(StrHideError::CorruptedData(format!(
            "envelope coordinates disagree: header declares {declared}, located at {ube_offset}"
        )));
    }
    let shift = i128::from(ube_offset) - i128::from(declared);
    let adjusted = i128::from(header.inject_offset) + shift;
    let adjusted: u64 = adjusted.try_into().map_err(|_| {
        StrHideError::CorruptedData(format!(
            "relocated envelope underflows inject_offset {}",
            header.inject_offset
        ))
    })?;
    let mut relocated = header.clone();
    relocated.inject_offset = adjusted;
    Ok(relocated)
}

/// Check the restored carrier against the hashes recorded in the envelope.
fn verify_restored(
    restored: &mut dyn SeekRead,
    header: &EnvelopeHeader,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<(u64, [u8; 32]), StrHideError> {
    restored.seek(SeekFrom::Start(0))?;
    let restored_size = restored.seek(SeekFrom::End(0))?;
    restored.seek(SeekFrom::Start(0))?;
    let restored_sha256 = crate::crypto::compute_stream_sha256(restored)?;

    if restored_size == header.orig_host_size && restored_sha256 == header.orig_host_sha256 {
        return Ok((restored_size, restored_sha256));
    }

    // Diagnose the common cause: the carrier carried a second envelope (e.g. a
    // stealth envelope underneath), so stripping this one cannot reproduce the
    // recorded original. Envelopes must be removed in reverse order of
    // injection.
    let mut residual_envelope = false;
    restored.seek(SeekFrom::Start(0))?;
    if let Some(r_adapter) = find_adapter(restored) {
        let remaining = r_adapter
            .locate(restored, profile.locator_magic())
            .ok()
            .flatten()
            .or_else(|| r_adapter.locate(restored, None).ok().flatten())
            .or_else(|| {
                password.and_then(|pwd| {
                    derive_stealth_magics(pwd, profile.domain())
                        .ok()
                        .and_then(|m| r_adapter.locate(restored, Some(&m.1)).ok().flatten())
                })
            });
        // Removing an inner envelope shifts an outer one backwards, so its
        // trailer no longer describes its own coordinates and `locate`
        // correctly refuses it. The container is still there, though, and it
        // is the real reason the hashes cannot match: fall back to the
        // format's envelope-shaped-structure scan for the diagnosis.
        let envelope_shaped = !r_adapter.suspicious_structures(restored).is_empty();
        if remaining.is_some() || envelope_shaped {
            residual_envelope = true;
        }
    }

    let res_sha = restored_sha256
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let exp_sha = header
        .orig_host_sha256
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    Err(StrHideError::RestoreMismatch {
        restored_size,
        expected_size: header.orig_host_size,
        restored_sha256: res_sha,
        expected_sha256: exp_sha,
        residual_envelope,
    })
}

/// Strip the envelope of a carrier written under `dialect`.
///
/// The dialect must be the one used at write time: it drives envelope location
/// (custom magic), the stealth domain, and the `default_secret` used to decode
/// a non-password envelope.
///
/// [`RestoreOptions::overwrite`] decides what happens when the output path
/// names a different file that already exists. It defaults to refusing, which
/// is the safe answer for a library call: restoring replaces the file with the
/// pre-envelope host, and `rename`-ing over a user's file loses it with no way
/// back. The CLI resolves the user's choice first and passes `true` only after
/// they have confirmed. In-place restoration — the default when no output path
/// is given — is the one case where overwriting is the whole point.
pub fn remove_carrier_with_dialect(
    carrier_path: &Path,
    options: &RestoreOptions<'_>,
    dialect: &StructureProfile,
) -> Result<RemoveResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let target_path = options.output_path.unwrap_or(carrier_path);
    let meta = std::fs::metadata(carrier_path)?;
    let orig_permissions = meta.permissions();
    let orig_atime = filetime::FileTime::from_last_access_time(&meta);
    let orig_mtime = filetime::FileTime::from_last_modification_time(&meta);

    if !same_file(target_path, carrier_path) {
        crate::core::pipeline::check_overwrite(target_path, options.overwrite)?;
    }
    crate::commit::reject_read_only_target(target_path)?;
    // Same contract as the write path: one writer per target at a time.
    let _target_lock = crate::commit::TargetLock::acquire(target_path)?;

    let label = carrier_path.display().to_string();
    let tmp_target = temp_path_for(target_path);
    let mut tmp_guard = TmpGuard::new(tmp_target.clone());

    let header = {
        let mut cf = File::open(carrier_path)?;
        let mut out_f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_target)?;
        let mut pw = crate::core::control::ProgressWriter::new(
            &mut out_f,
            options.control,
            crate::core::control::Stage::Write,
            meta.len(),
        );
        let header = remove_core(&mut cf, &mut pw, &label, options.password, dialect)
            .map_err(|e| crate::core::control::map_io_cancel(&options.control, e))?;
        // Same durability contract as the write path: the restored file is
        // fsynced before its temp name is renamed over the carrier.
        out_f.sync_all()?;
        header
    };

    // Verify restored file
    options.control.stage(crate::core::control::Stage::Verify);
    options.control.check()?;
    let (restored_size, restored_sha256) = {
        let mut rf = File::open(&tmp_target)?;
        verify_restored(&mut rf, &header, options.password, dialect)?
    };

    // Strict cancellation check before .bak creation and atomic commit
    options.control.check()?;

    let is_inplace = same_file(target_path, carrier_path);
    let mut backup_file = None;
    if is_inplace && options.backup {
        backup_file = Some(crate::commit::create_carrier_backup(carrier_path)?);
    }

    crate::commit::rename_with_retry(&tmp_target, target_path)?;
    tmp_guard.commit();
    crate::commit::sync_parent_dir(target_path);
    // Same order as the write path: stamp, then restore permissions.
    if let Err(e) = filetime::set_file_times(target_path, orig_atime, orig_mtime) {
        log::warn!(
            "failed to preserve file timestamps for '{}': {e}",
            target_path.display()
        );
    }
    if let Err(e) = std::fs::set_permissions(target_path, orig_permissions) {
        log::warn!(
            "failed to restore file permissions for '{}': {e}",
            target_path.display()
        );
    }

    Ok(RemoveResult {
        carrier: target_path.to_path_buf(),
        restored_size,
        restored_sha256: restored_sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        verified_identical: true,
        backup_file,
    })
}

/// Strip the envelope from an in-memory carrier, returning the restored bytes.
///
/// The restored buffer is checked against the `orig_host_size` /
/// `orig_host_sha256` recorded in the envelope exactly like the file variant,
/// so a carrier that actually held two stacked envelopes fails with
/// [`StrHideError::RestoreMismatch`] instead of returning half-restored bytes.
/// No backup is produced (`backup` only exists for in-place file writes).
pub fn remove_carrier_bytes(
    carrier: &[u8],
    password: Option<&str>,
    dialect: &StructureProfile,
) -> Result<(Vec<u8>, RemoveResult), StrHideError> {
    let mut host = Cursor::new(carrier);
    let mut out = Cursor::new(Vec::new());
    let header = remove_core(&mut host, &mut out, "<memory>", password, dialect)?;
    let bytes = out.into_inner();

    let (restored_size, restored_sha256) = {
        let mut restored = Cursor::new(&bytes);
        verify_restored(&mut restored, &header, password, dialect)?
    };

    let result = RemoveResult {
        carrier: PathBuf::from("<memory>"),
        restored_size,
        restored_sha256: restored_sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        verified_identical: true,
        backup_file: None,
    };
    Ok((bytes, result))
}

/// Inspect a carrier: report its format, any envelope found, decrypted
/// metadata, and the capacity of every available strategy.
///
/// This function never modifies the carrier. A carrier with no envelope
/// returns `Ok` with `has_hidden_data == false` rather than an error.
pub fn inspect_carrier(
    carrier_path: &Path,
    password: Option<&str>,
) -> Result<InspectResult, StrHideError> {
    inspect_carrier_with(carrier_path, password, &StructureProfile::default())
}

/// Inspect a carrier written under `profile`.
///
/// A carrier whose envelope belongs to a different dialect reports
/// `has_hidden_data == false`: a private dialect is meant to be invisible to
/// readers that do not know it.
pub fn inspect_carrier_with(
    carrier_path: &Path,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<InspectResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let mut cf = File::open(carrier_path)?;
    inspect_core(
        &mut cf,
        &carrier_path.display().to_string(),
        password,
        profile,
    )
}

/// Inspect an in-memory carrier, using the same dialect resolution as
/// [`inspect_carrier_with`].
pub fn inspect_carrier_bytes(
    carrier: &[u8],
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<InspectResult, StrHideError> {
    let mut host = Cursor::new(carrier);
    inspect_core(&mut host, "<memory>", password, profile)
}

/// Build the "no readable envelope" inspect result.
///
/// Shared by the genuinely-empty carrier and the carrier whose envelope cannot
/// be opened with the caller's profile: both are indistinguishable from the
/// outside, which is the point of a private dialect.
fn empty_inspect_result(
    host: &mut dyn SeekRead,
    adapter: &dyn HostAdapter,
    label: &str,
    strategies: Vec<StrategyCapacity>,
) -> Result<InspectResult, StrHideError> {
    let _ = host.seek(SeekFrom::Start(0));
    let suspicious_hints = adapter.suspicious_structures(host);
    Ok(InspectResult {
        carrier: PathBuf::from(label),
        format: adapter_format(adapter)?,
        has_hidden_data: false,
        strategy: None,
        ube_offset: None,
        ube_total_size: None,
        is_encrypted: None,
        is_compressed: None,
        is_stealth: None,
        password_hint: None,
        orig_host_size: None,
        orig_host_sha256: None,
        metadata: None,
        suspicious_hints,
        strategies,
    })
}

/// Shared inspect logic over any seekable reader (a `File` on the path path, a
/// `Cursor` on the bytes path).
fn inspect_core(
    host: &mut dyn SeekRead,
    label: &str,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<InspectResult, StrHideError> {
    host.seek(SeekFrom::Start(0))?;
    let adapter = find_adapter_or_reject(host, label)?;
    let host_len = host.seek(SeekFrom::End(0))?;

    // Measured strategy capacities (design: folds the former `check` command
    // into `inspect`). Adapters that can answer statically ignore the reader;
    // PE measures `.text` density and zero slack, ZIP measures the EOCD offset.
    let mut strategies = adapter.strategy_capacities(Some(host));
    // Adapter ceilings describe the *container* mechanism only; the engine
    // itself refuses payloads above `structure_payload_limit(host_len)` on both
    // the write and the read path. Clamp every advertised capacity to that
    // effective limit so `inspect` never promises a payload the writer would
    // reject (an "unlimited (file grows)" EOF strategy is still bounded by the
    // 256x-host / 64 MiB-floor / 1 GiB-ceiling rule).
    apply_engine_payload_limit(&mut strategies, host_len);

    let loc = locate_envelope(host, adapter, password, profile)?;

    let (ube_offset, ube_total_size, strategy_name) = match loc {
        Some(l) => l,
        None => return empty_inspect_result(host, adapter, label, strategies),
    };

    let mut ube_stream =
        adapter.open_ube_reader(host, ube_offset, ube_total_size, &strategy_name)?;

    let mut header_bytes = [0u8; HEADER_SIZE];
    ube_stream.read_exact(&mut header_bytes)?;
    // An envelope we can see but cannot open with this profile is a private
    // dialect, and a private dialect is supposed to be invisible to readers
    // that do not know it. Surfacing `CorruptedData` told an outsider that
    // something is hidden and crashed `inspect_any`/`smart_extract` instead of
    // letting the content domain answer (review B-06).
    let header = match EnvelopeHeader::unpack_with_profile(&header_bytes, password, profile) {
        Ok(h) => h,
        Err(e) => {
            // Staying invisible to a reader that does not hold the dialect is
            // the point (B-06), so the result must not change — but the reason
            // still belongs in the log.
            log::debug!(
                target: "structure::inspect",
                "envelope header does not open under this profile: {e}"
            );
            drop(ube_stream);
            return empty_inspect_result(host, adapter, label, strategies);
        }
    };
    // A header that fails the level-2 shape check is not a readable envelope;
    // treat it exactly like an unparseable one instead of propagating
    // `CorruptedData` out of `inspect` / `smart_extract` (review B-06). This
    // also stops a coincidental de-mask hit on a foreign-key envelope from
    // aborting the whole inspection.
    if let Err(e) = header.validate_against(ube_total_size, host_len) {
        log::debug!(
            target: "structure::inspect",
            "envelope header failed the level-2 shape check: {e}"
        );
        drop(ube_stream);
        return empty_inspect_result(host, adapter, label, strategies);
    }

    let mut hint_bytes: Vec<u8> = Vec::new();
    if header.hint_len > 0 {
        hint_bytes = vec![0u8; header.hint_len as usize];
        ube_stream.read_exact(&mut hint_bytes)?;
    }
    let hint_str = if hint_bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&hint_bytes).to_string())
    };
    // The same AAD the writer sealed: header prefix + lengths + hint.
    let aad = header.auth_aad(&hint_bytes);

    let mut meta_val = None;
    if !header.is_encrypted() {
        let mut meta_bytes = vec![0u8; header.meta_len as usize];
        if ube_stream.read_exact(&mut meta_bytes).is_ok() {
            let decoded = if let Ok((_, meta_key)) = derive_keys(profile.secret(), &header.salt)
                && let Ok(dec) = decrypt_metadata(&meta_bytes, &meta_key, &header.base_nonce, &aad)
            {
                decode_metadata(&dec, header.is_compact_meta()).ok()
            } else {
                None
            };
            if let Some(meta_obj) = decoded {
                meta_val = Some(MetadataInspection::Decrypted(meta_obj));
            } else {
                log::debug!(
                    target: "structure::inspect",
                    "metadata block ({} B) present but did not decrypt/decode",
                    header.meta_len
                );
            }
        } else {
            log::debug!(
                target: "structure::inspect",
                "metadata block ({} B) could not be read",
                header.meta_len
            );
        }
    } else if let Some(pwd) = password {
        let mut meta_bytes = vec![0u8; header.meta_len as usize];
        if ube_stream.read_exact(&mut meta_bytes).is_ok()
            && let Ok((_, meta_key)) = derive_keys(pwd, &header.salt)
        {
            if let Ok(dec) = decrypt_metadata(&meta_bytes, &meta_key, &header.base_nonce, &aad) {
                if let Ok(meta_obj) = decode_metadata(&dec, header.is_compact_meta()) {
                    meta_val = Some(MetadataInspection::Decrypted(meta_obj));
                } else {
                    log::debug!(
                        target: "structure::inspect",
                        "metadata block decrypted but did not decode"
                    );
                }
            } else {
                meta_val = Some(MetadataInspection::DecryptFailed {
                    error: "Invalid password".to_string(),
                });
            }
        } else {
            log::debug!(
                target: "structure::inspect",
                "metadata block ({} B) unreadable or key derivation failed",
                header.meta_len
            );
        }
    }

    let reported_strategy = if header.strategy_id > 0 {
        StrategyId::from_u8(header.strategy_id)
    } else {
        StrategyId::from_name(&strategy_name).unwrap_or(StrategyId::from_u8(0))
    };

    Ok(InspectResult {
        carrier: PathBuf::from(label),
        format: adapter_format(adapter)?,
        has_hidden_data: true,
        strategy: Some(reported_strategy),
        ube_offset: Some(ube_offset),
        ube_total_size: Some(ube_total_size),
        is_encrypted: Some(header.is_encrypted()),
        is_compressed: Some(header.is_compressed()),
        is_stealth: Some(header.is_stealth()),
        password_hint: hint_str,
        orig_host_size: Some(header.orig_host_size),
        orig_host_sha256: Some(
            header
                .orig_host_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        ),
        metadata: meta_val,
        suspicious_hints: Vec::new(),
        strategies,
    })
}

/// Run three independent checks against a carrier: host structure integrity,
/// envelope boundary/CRC validity, and payload decrypt + SHA-256 match.
///
/// Does not modify the carrier. The returned [`VerifyResult`] reports each
/// level separately so a caller can distinguish "the file is structurally
/// fine" from "the payload does not decrypt".
pub fn verify_carrier(
    carrier_path: &Path,
    password: Option<&str>,
) -> Result<VerifyResult, StrHideError> {
    verify_carrier_with(carrier_path, password, &StructureProfile::default())
}

/// Verify a carrier written under `profile`.
///
/// Level 1 (host structure) is dialect-independent; levels 2 and 3 need the
/// same profile used at write time.
pub fn verify_carrier_with(
    carrier_path: &Path,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<VerifyResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let mut cf = File::open(carrier_path)?;
    verify_core(
        &mut cf,
        &carrier_path.display().to_string(),
        password,
        profile,
    )
}

/// Verify an in-memory carrier, using the same dialect resolution as
/// [`verify_carrier_with`].
pub fn verify_carrier_bytes(
    carrier: &[u8],
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<VerifyResult, StrHideError> {
    let mut host = Cursor::new(carrier);
    verify_core(&mut host, "<memory>", password, profile)
}

/// Shared verify logic over any seekable reader (a `File` on the path path, a
/// `Cursor` on the bytes path).
/// Cross-check the header's injection coordinates against the located envelope.
///
/// Level 2 used to compare the trailer's `ube_offset`/`ube_total_size` with the
/// values `locate_envelope` had just read out of that same trailer — true by
/// construction. The header's own coordinates were never checked against
/// anything, so a carrier whose header disagreed with its body passed `verify`
/// and only failed later, during `remove` (review R2 P1-9).
///
/// These four fields are the only header bytes the AEAD cannot cover: they are
/// filled in after the injector has run, i.e. after the metadata block and every
/// payload chunk were sealed (see `EnvelopeHeader`). Nothing here is trusted on
/// its own, though: `offset_delta` *is* inside the AAD, the envelope end is
/// pinned to the physical file by `confine_location`, and a wrong answer here
/// makes `remove` reproduce a carrier whose SHA-256 mismatches the
/// authenticated `orig_host_sha256`.
///
/// Relationships used, all of which hold for every registered strategy:
/// the envelope starts `offset_delta` bytes after the injection point, the
/// injected region is at least as large as the envelope it wraps (strategies
/// add container headers), and the whole region lies inside the file.
fn envelope_coordinates_agree(
    header: &EnvelopeHeader,
    strategy: &str,
    ube_offset: u64,
    ube_total_size: u64,
    file_len: u64,
) -> Result<(), String> {
    // Scattered strategies (`pe_codebits`) record 0/0 by definition: the payload
    // is spread over instruction encodings and PE padding, so there is no
    // contiguous injected region to check. Test the *strategy*, not
    // `inject_size == 0`: the size field is inside the header but outside the
    // AEAD's AAD, so accepting a zero there let anyone flip it in a contiguous
    // strategy (`eof`, `chunk`, `box_uuid`) and skip Level 2 entirely.
    // Both the caller's strategy name and the header's id must name
    // `pe_codebits`: trusting only the header-derived id let a header claim the
    // exemption while the caller was verifying a contiguous strategy, skipping
    // the coordinate check entirely (review C-01).
    if cfg!(feature = "structure-pe")
        && strategy == "pe_codebits"
        && crate::structure::registry::id_to_strategy(header.strategy_id) == strategy
    {
        return Ok(());
    }
    let expected_offset = header
        .inject_offset
        .checked_add(header.offset_delta as u64)
        .ok_or_else(|| {
            format!(
                "Header injection offset {} overflows once its {}-byte displacement is applied",
                header.inject_offset, header.offset_delta
            )
        })?;
    // PNG `chunk` and appended EOF envelopes can be physically relocated by
    // content-domain embedding: re-compressing IDAT (or re-encoding the media)
    // changes the length of the stream before the envelope, so the trailer
    // still carries the write-time coordinate. The trailer and header are
    // authenticated, so accept a shift for those strategies and bound the
    // relocated region against EOF. Every other strategy is anchored at write
    // time and a mismatch is corruption.
    let relocated = expected_offset != ube_offset;
    if relocated && !matches!(strategy, "chunk" | "eof") {
        return Err(format!(
            "Header coordinates disagree with the envelope: inject_offset {} + delta {} = {}, \
             but the envelope sits at {}",
            header.inject_offset, header.offset_delta, expected_offset, ube_offset
        ));
    }
    if ube_total_size > header.inject_size {
        return Err(format!(
            "Envelope size {ube_total_size}B exceeds the injected region of {}B",
            header.inject_size
        ));
    }
    let injected_end = if relocated {
        let wrapped = header
            .inject_size
            .checked_sub(header.offset_delta as u64)
            .ok_or_else(|| "Header displacement exceeds injected region".to_string())?;
        ube_offset
            .checked_add(wrapped)
            .ok_or_else(|| "Relocated injection region overflows".to_string())?
    } else {
        header
            .inject_offset
            .checked_add(header.inject_size)
            .ok_or_else(|| "Header injection region overflows".to_string())?
    };
    if injected_end > file_len {
        return Err(format!(
            "Header places the injected region at [{}..{}], past the end of the {file_len}B file",
            header.inject_offset, injected_end
        ));
    }
    Ok(())
}

fn attempt_l1(
    host: &mut dyn SeekRead,
    adapter: &dyn HostAdapter,
    magic: Option<&[u8; 4]>,
) -> Result<(bool, String), StrHideError> {
    host.seek(SeekFrom::Start(0))?;
    adapter.verify_structure_with_magic(host, magic)
}

/// Level 1 with every dialect the caller could be verifying: the profile's
/// own magic, the standard magic, and — only when a password is available —
/// the password-derived stealth magic. EOF-overlay formats need the right
/// trailer magic to step over the envelope; trying them in order avoids a
/// false "corrupted host" for stealth/private carriers.
fn verify_structure_for_dialects(
    host: &mut dyn SeekRead,
    adapter: &dyn HostAdapter,
    password: Option<&str>,
    profile: &StructureProfile,
    known_stealth_trailer_magic: Option<[u8; 4]>,
) -> Result<(bool, String), StrHideError> {
    if let Some(magic) = profile.locator_magic() {
        let result = attempt_l1(host, adapter, Some(magic))?;
        if result.0 {
            return Ok(result);
        }
    }
    let mut last = attempt_l1(host, adapter, None)?;
    if last.0 {
        return Ok(last);
    }
    let stealth_trailer_magic = match known_stealth_trailer_magic {
        Some(magic) => Some(magic),
        None => match password {
            Some(pwd) => Some(derive_stealth_magics(pwd, profile.domain())?.1),
            None => None,
        },
    };
    if let Some(magic) = stealth_trailer_magic {
        let result = attempt_l1(host, adapter, Some(&magic))?;
        if result.0 {
            return Ok(result);
        }
        last = result;
    }
    Ok(last)
}

fn verify_core(
    host: &mut dyn SeekRead,
    label: &str,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<VerifyResult, StrHideError> {
    let password = password.filter(|s| !s.is_empty());
    host.seek(SeekFrom::Start(0))?;
    let adapter = find_adapter_or_reject(host, label)?;

    // Needed by Level 2 to bound the injection coordinates the header claims.
    // Captured before the envelope reader borrows `host`.
    let file_len = host.seek(SeekFrom::End(0))?;

    // A single locate scan feeds Level 1's stealth trailer magic, Level 2's
    // header unpack and its trailer check, and Level 3's authentication.
    // Deriving the magics once instead of per consumer removes several
    // 100k-iteration PBKDF2 runs from every `verify` (review P1-7).
    let Located {
        location,
        stealth_header_magic,
        stealth_trailer_magic,
    } = locate_envelope_with_magic(host, adapter, password, profile)?;

    // Level 1: Host format integrity
    let (l1_ok, l1_msg) =
        verify_structure_for_dialects(host, adapter, password, profile, stealth_trailer_magic)?;

    let (ube_offset, ube_total_size, strategy_name) = match location {
        Some(l) => l,
        None => {
            return Ok(VerifyResult {
                carrier: PathBuf::from(label),
                format: adapter_format(adapter)?,
                level1_host: LevelStatus {
                    ok: l1_ok,
                    detail: l1_msg,
                    skipped: false,
                },
                level2_envelope: LevelStatus::fail("No envelope found"),
                level3_crypto: LevelStatus::skipped("Skipped (no envelope)"),
            });
        }
    };

    let mut secrets: Option<UnpackSecrets> = None;
    let (l2_ok, l2_msg, is_encrypted) = {
        match adapter.open_ube_reader(host, ube_offset, ube_total_size, &strategy_name) {
            Err(e) => (false, format!("Cannot open envelope reader: {e}"), false),
            Ok(mut ube_stream) => {
                let mut header_bytes = [0u8; HEADER_SIZE];
                if ube_stream.read_exact(&mut header_bytes).is_err() {
                    (false, "Cannot read header".into(), false)
                } else {
                    // Derive once for Level 2 and hand the same material to
                    // Level 3; `open_authenticated_at` would otherwise repeat
                    // PBKDF2 over the identical (password, salt) pair.
                    let salt = EnvelopeHeader::salt_of(&header_bytes).unwrap_or([0u8; 16]);
                    let built = UnpackSecrets {
                        password: match password {
                            Some(pwd) => Some(derive_all(pwd, &salt)?),
                            None => None,
                        },
                        default: if password.is_none() {
                            Some(derive_all(profile.secret(), &salt)?)
                        } else {
                            None
                        },
                        stealth_header_magic,
                    };
                    secrets = Some(built);

                    match EnvelopeHeader::unpack_with_secrets(
                        &header_bytes,
                        password,
                        profile,
                        &built,
                    ) {
                        Err(e) => {
                            log::debug!(
                                target: "structure::verify",
                                "envelope header unpacking failed: {e}"
                            );
                            (
                                false,
                                format!("Envelope header unpacking failed: {e}"),
                                false,
                            )
                        }
                        Ok(header) => {
                            // Validate header field ranges against the located
                            // envelope size (version / hint_len / meta_len
                            // consistency) before trusting any downstream reads —
                            // a crafted or corrupted header must fail Level 2 with
                            // a domain error instead of being silently accepted.
                            if let Err(e) = header.validate_against(ube_total_size, file_len) {
                                (
                                    false,
                                    format!("Envelope header validation failed: {e}"),
                                    false,
                                )
                            } else if let Err(msg) = envelope_coordinates_agree(
                                &header,
                                &strategy_name,
                                ube_offset,
                                ube_total_size,
                                file_len,
                            ) {
                                (false, msg, header.is_encrypted())
                            } else if ube_stream
                                .seek(SeekFrom::Start(ube_total_size - 24))
                                .is_err()
                            {
                                (
                                    false,
                                    "Cannot seek to trailer".into(),
                                    header.is_encrypted(),
                                )
                            } else {
                                let mut trailer_bytes = [0u8; 24];
                                // Stealth: the locator already derived this magic.
                                // Official dialect: `None` keeps the legacy magics
                                // acceptable. Private dialect: only its own magic.
                                let expected_trailer_magic = if header.is_stealth() {
                                    stealth_trailer_magic
                                } else {
                                    profile.locator_magic().copied()
                                };

                                if ube_stream.read_exact(&mut trailer_bytes).is_err() {
                                    (false, "Cannot read trailer".into(), header.is_encrypted())
                                } else if let Ok(trailer) = EnvelopeTrailer::unpack(
                                    &trailer_bytes,
                                    expected_trailer_magic.as_ref(),
                                ) {
                                    // `locate_envelope` derived these numbers from
                                    // this very record, so comparing them with
                                    // themselves proved nothing (review R2 P1-9).
                                    // What the trailer still contributes is its
                                    // magic + CRC32 check; the coordinate check
                                    // happens above, where the authenticated
                                    // `offset_delta` anchors the envelope start and
                                    // `confine_location` anchored the end to the
                                    // physical file.
                                    // A relocated PNG `chunk` envelope keeps its
                                    // write-time `ube_offset` in the trailer while
                                    // `locate` reports the new physical offset, so
                                    // the two are intentionally different here. The
                                    // coordinate check lives in
                                    // `envelope_coordinates_agree`.
                                    debug_assert_eq!(trailer.ube_total_size, ube_total_size);
                                    let _ = &trailer;
                                    (
                                        true,
                                        format!(
                                            "Envelope valid at offset {ube_offset}, size {ube_total_size}B (CRC32 OK)"
                                        ),
                                        header.is_encrypted(),
                                    )
                                } else {
                                    (
                                        false,
                                        "Envelope trailer unpacking failed".into(),
                                        header.is_encrypted(),
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    // Level 3: Crypto & payload SHA-256.
    //
    // "No password was supplied" is a *skipped* level, not a failure: the
    // caller could not have checked, and exit code 0 used to hide the case that
    // *did* run and failed (wrong password, corrupted payload) behind the same
    // boolean as this one.
    let l3 = if !is_encrypted || password.is_some() {
        match open_authenticated_at(
            host,
            adapter,
            (ube_offset, ube_total_size, strategy_name),
            password,
            profile,
            stealth_header_magic,
            secrets.as_ref(),
        ) {
            Ok(mut env) => match verify_authenticated_payload(&mut env) {
                Ok(raw_size) => LevelStatus::pass(format!(
                    "Decryption and SHA-256 verified successfully (payload {raw_size} bytes)"
                )),
                Err(e) => LevelStatus::fail(e.to_string()),
            },
            Err(e) => LevelStatus::fail(e.to_string()),
        }
    } else {
        LevelStatus::skipped("Password required for cryptographic verification")
    };

    Ok(VerifyResult {
        carrier: PathBuf::from(label),
        format: adapter_format(adapter)?,
        level1_host: LevelStatus {
            ok: l1_ok,
            detail: l1_msg,
            skipped: false,
        },
        level2_envelope: LevelStatus {
            ok: l2_ok,
            detail: l2_msg,
            skipped: false,
        },
        level3_crypto: l3,
    })
}

/// Did a [`VerifyResult`] pass every level it was able to check?
///
/// Levels 1-3 cover container structure, the envelope header and the
/// authenticated payload. Host *restorability* is deliberately not part of this
/// gate: only `remove` reproduces the host and compares its SHA-256 with the
/// authenticated `orig_host_sha256` (see `verify_restored`), so `verify` can
/// pass while `remove` still refuses a carrier whose host bytes were altered.
/// If you need that check before touching the carrier, run `read`/`restore`
/// into a throwaway destination.
pub fn verify_passed(res: &VerifyResult) -> bool {
    res.level1_host.ok
        && res.level2_envelope.ok
        && (res.level3_crypto.ok || res.level3_crypto.skipped)
}

#[cfg(test)]
mod compact_meta_tests {
    use super::*;

    fn meta(name: &str, size: u64, ts: u64) -> CarrierMetadata {
        CarrierMetadata {
            filename: name.to_string(),
            raw_size: size,
            raw_sha256: "ab".repeat(32),
            created_at: ts,
        }
    }

    fn assert_same(actual: &CarrierMetadata, expected: &CarrierMetadata) {
        assert_eq!(actual.filename, expected.filename);
        assert_eq!(actual.raw_size, expected.raw_size);
        assert_eq!(actual.raw_sha256, expected.raw_sha256);
        assert_eq!(actual.created_at, expected.created_at);
    }

    #[test]
    fn compact_roundtrip_covers_width_and_text_edges() {
        let cases = [
            ("a", 0u64, 0u64),
            ("x.txt", 1, 1_700_000_000),
            ("目录/长文件名-测试.bin", u32::MAX as u64, u64::MAX / 2),
            ("n", u64::MAX, 127),
        ];
        for (name, size, ts) in cases {
            let original = meta(name, size, ts);
            let encoded = original.encode_compact().expect("encodable");
            let decoded = CarrierMetadata::decode_compact(&encoded).expect("decodable");
            assert_same(&decoded, &original);
        }
        // 300-byte name still fits the u16 length field
        let long = meta(&"n".repeat(300), 7, 7);
        let encoded = long.encode_compact().expect("encodable");
        assert_same(&CarrierMetadata::decode_compact(&encoded).unwrap(), &long);
    }

    #[test]
    fn compact_block_is_much_smaller_than_json() {
        let m = meta("s.txt", 1, 1_700_000_000);
        let compact = m.encode_compact().unwrap();
        let json = serde_json::to_vec(&m).unwrap();
        assert!(
            compact.len() + 80 < json.len(),
            "compact {} json {}",
            compact.len(),
            json.len()
        );
        // 1 version + 2 name_len + 5 name + 1 size + 32 digest + 5 timestamp
        assert_eq!(compact.len(), 46);
    }

    #[test]
    fn varint_rejects_values_that_overflow_u64() {
        // 9 continuation bytes followed by 0x02: the old loop shifted the
        // payload bit past bit 63 and returned 0 instead of reporting an error
        // (review P2-6).
        let mut overflowing = vec![0x80u8; 9];
        overflowing.push(0x02);
        let mut pos = 0;
        assert!(matches!(
            take_varint(&overflowing, &mut pos),
            Err(StrHideError::CorruptedData(_))
        ));

        // The canonical 10-byte encoding of u64::MAX still parses.
        let mut max = vec![0xffu8; 9];
        max.push(0x01);
        let mut pos = 0;
        assert_eq!(take_varint(&max, &mut pos).unwrap(), u64::MAX);

        // A 10th byte with the continuation bit set is "too long": it must not
        // be silently accepted either.
        let too_long = vec![0xffu8; 10];
        let mut pos = 0;
        assert!(take_varint(&too_long, &mut pos).is_err());
    }

    #[test]
    fn compact_rejects_corrupt_input() {
        assert!(CarrierMetadata::decode_compact(&[]).is_err());
        assert!(CarrierMetadata::decode_compact(&[0x01]).is_err());
        // unsupported version
        assert!(CarrierMetadata::decode_compact(&[0x02, 0x00, 0x00]).is_err());
        // truncated filename
        assert!(CarrierMetadata::decode_compact(&[0x01, 0x05, 0x00, b'a']).is_err());
        // truncated digest
        let mut v = vec![0x01, 0x01, 0x00, b'a'];
        put_varint(&mut v, 1);
        v.extend_from_slice(&[0u8; 10]);
        assert!(CarrierMetadata::decode_compact(&v).is_err());
        // invalid UTF-8 filename
        assert!(CarrierMetadata::decode_compact(&[0x01, 0x01, 0x00, 0xff]).is_err());
    }

    #[test]
    fn pre_v2_json_metadata_is_rejected() {
        let m = meta("legacy.bin", 42, 1_600_000_000);
        let json = serde_json::to_vec(&m).unwrap();
        // A pre-v2 carrier stores JSON with FLAG_COMPACT_META clear. That
        // combination is now a hard error rather than a second decode path.
        assert!(decode_metadata(&json, false).is_err());
        // The compact path must not accept JSON either.
        assert!(decode_metadata(&json, true).is_err());
        // And the compact layout still round-trips.
        let compact = m.encode_compact().unwrap();
        assert_same(&decode_metadata(&compact, true).unwrap(), &m);
    }

    #[test]
    fn unencodable_metadata_is_a_writer_error() {
        let long_name = meta(&"n".repeat(COMPACT_META_MAX_NAME + 1), 1, 1);
        assert!(long_name.encode_compact().is_none());
        assert!(encode_metadata(&long_name).is_err());

        let mut bad_digest = meta("x", 1, 1);
        bad_digest.raw_sha256 = "zz".repeat(32);
        assert!(bad_digest.encode_compact().is_none());
        assert!(encode_metadata(&bad_digest).is_err());
    }

    #[test]
    fn test_warning_render_bilingual() {
        use crate::core::i18n::{Lang, RenderCtx};

        let w1 = Warning::SizeInflation {
            ube_size: 1000,
            host_size: 1500,
            ratio_pct: 66.7,
        };
        assert_eq!(w1.render(RenderCtx::new(Lang::En)), w1.message());
        assert!(w1.render(RenderCtx::new(Lang::Zh)).contains("隐藏数据信封"));

        let w2 = Warning::SuspiciousStructures {
            hints: vec!["prIv chunk".into()],
        };
        assert_eq!(w2.render(RenderCtx::new(Lang::En)), w2.message());
        assert!(
            w2.render(RenderCtx::new(Lang::Zh))
                .contains("载体呈现与隐藏信封一致的结构")
        );
    }

    #[test]
    fn test_read_summary_and_metadata_inspection() {
        let read = ReadResult {
            carrier: PathBuf::from("test.png"),
            data: b"hello world".to_vec(),
            is_file: false,
            is_encrypted: false,
            filename: String::new(),
            raw_size: 11,
            written_file: None,
        };
        let summary = read.summary();
        assert_eq!(summary.raw_size, 11);
        assert_eq!(summary.text_preview, Some("hello world".into()));

        let meta = CarrierMetadata {
            filename: "secret.txt".into(),
            raw_size: 100,
            raw_sha256: "0".repeat(64),
            created_at: 12345678,
        };
        let inspection = MetadataInspection::Decrypted(meta.clone());
        let json = serde_json::to_string(&inspection).expect("serialize");
        assert!(json.contains("secret.txt"));

        let fail = MetadataInspection::DecryptFailed {
            error: "Invalid password".into(),
        };
        let json_fail = serde_json::to_string(&fail).expect("serialize");
        assert!(json_fail.contains("Invalid password"));
    }
}

#[cfg(test)]
mod envelope_coordinate_tests {
    use super::*;

    /// `inject_size` lives in the header but outside the AEAD's AAD, so a zero
    /// in that field must not be read as "this is a scattered strategy". Before
    /// the fix, any contiguous strategy (`eof`, `chunk`, `box_uuid`) with the
    /// field flipped to 0 skipped Level 2 entirely and `verify` passed a carrier
    /// whose coordinates disagreed with its body.
    #[test]
    fn zero_inject_size_only_exempts_pe_codebits() {
        let ube_total = 256u64;
        let file_len = 4096u64;

        let header = EnvelopeHeader {
            strategy_id: crate::structure::registry::strategy_to_id("eof").expect("eof id"),
            inject_offset: 0,
            offset_delta: 0,
            inject_size: 0,
            ..Default::default()
        };

        assert!(
            envelope_coordinates_agree(&header, "eof", 0, ube_total, file_len).is_err(),
            "a zeroed inject_size on a contiguous strategy must be rejected"
        );

        // `pe_codebits` is the one strategy that records 0/0 by construction.
        let header = EnvelopeHeader {
            strategy_id: crate::structure::registry::strategy_to_id("pe_codebits")
                .expect("codebits id"),
            ..header
        };
        assert!(
            envelope_coordinates_agree(&header, "pe_codebits", 0, ube_total, file_len).is_ok(),
            "the scattered strategy must still be exempt"
        );
    }
}

#[cfg(test)]
mod pbkdf2_budget_tests {
    use super::*;

    fn stego(payload: PayloadSource<'_>, password: Option<&str>, stealth: bool) -> Vec<u8> {
        let carrier = include_bytes!("../../tests/assets/minimal.png").to_vec();
        let (bytes, _) = write_carrier_bytes(
            &carrier,
            payload,
            &WriteOptions::default()
                .with_password_option(password)
                .with_stealth(stealth),
            &LocalParams::default(),
            &StructureProfile::new(),
        )
        .unwrap();
        bytes
    }

    /// Locating a stealth carrier derives the magics (one PBKDF2); Level 2
    /// derives the password material once and Level 3 reuses it. Before P1-7
    /// Level 1, Level 2's header unpack, its trailer check and Level 3 each
    /// repeated that work (six runs, ~300 ms for a 5-byte payload).
    #[test]
    fn verify_derives_the_password_pair_once_beyond_the_locator() {
        let bytes = stego(PayloadSource::Text("p1-7"), Some("pw"), true);
        crate::crypto::reset_pbkdf2_calls();
        let res = verify_carrier_bytes(&bytes, Some("pw"), &StructureProfile::new()).unwrap();
        assert!(verify_passed(&res), "{res:?}");
        assert_eq!(crate::crypto::pbkdf2_calls(), 2, "unexpected PBKDF2 count");
    }

    /// P2-12: the content domain already treats `Some("")` as "no password";
    /// the structure domain used it as a stealth credential. An empty string
    /// must not create an envelope whose secrecy rests on an empty secret.
    #[test]
    fn empty_password_does_not_create_a_stealth_envelope() {
        let carrier = include_bytes!("../../tests/assets/minimal.png").to_vec();
        let err = write_carrier_bytes(
            &carrier,
            PayloadSource::Text("p2-12"),
            &WriteOptions::default().with_password("").with_stealth(true),
            &LocalParams::default(),
            &StructureProfile::new(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("Stealth mode requires a password"),
            "unexpected error: {err}"
        );
    }

    /// The no-password path used to derive the profile default secret twice:
    /// once inside Level 2's header unpack and once again to authenticate the
    /// metadata in Level 3.
    #[test]
    fn verify_derives_the_default_pair_once() {
        let bytes = stego(PayloadSource::Text("p1-7"), None, false);
        crate::crypto::reset_pbkdf2_calls();
        let res = verify_carrier_bytes(&bytes, None, &StructureProfile::new()).unwrap();
        assert!(verify_passed(&res), "{res:?}");
        assert_eq!(crate::crypto::pbkdf2_calls(), 1, "unexpected PBKDF2 count");
    }

    /// Review G2 (P2-2): advertised strategy capacities never exceed the
    /// payload limit the engine enforces for the host. The review measured an
    /// 86,854-byte PNG whose `inspect` reported `unlimited (file grows)` /
    /// `2 GiB - 1` while the writer refused anything above 64 MiB.
    #[test]
    fn strategy_capacities_never_exceed_engine_payload_limit() {
        use crate::structure::adapters::StrategyCapacity;

        let mk = |capacity_bytes: Option<u64>| StrategyCapacity {
            strategy: "x".into(),
            capacity_bytes,
            available: true,
            limit: "native".into(),
            note: None,
        };

        // 86,854-byte host: 256x is below the 64 MiB floor, so every strategy
        // is capped at 64 MiB; lower native ceilings keep their own text.
        let mut caps = vec![mk(None), mk(Some(u32::MAX as u64)), mk(Some(100))];
        apply_engine_payload_limit(&mut caps, 86_854);
        assert_eq!(caps[0].capacity_bytes, Some(64 * 1024 * 1024));
        assert_eq!(caps[1].capacity_bytes, Some(64 * 1024 * 1024));
        assert_eq!(caps[2].capacity_bytes, Some(100), "lower native stays");
        assert!(caps[0].limit.contains("67,108,864"), "{}", caps[0].limit);
        assert_eq!(caps[2].limit, "native");

        // 8 MiB host: 256x = 2 GiB, clamped to the 1 GiB ceiling.
        let mut caps = vec![mk(None)];
        apply_engine_payload_limit(&mut caps, 8 * 1024 * 1024);
        assert_eq!(
            caps[0].capacity_bytes,
            Some(crate::crypto::MAX_VERIFY_PAYLOAD_SIZE)
        );

        // 8 GiB host: 256x is above the ceiling; still the ceiling.
        let mut caps = vec![mk(None)];
        apply_engine_payload_limit(&mut caps, 8u64 << 30);
        assert_eq!(
            caps[0].capacity_bytes,
            Some(crate::crypto::MAX_VERIFY_PAYLOAD_SIZE)
        );
    }
}
