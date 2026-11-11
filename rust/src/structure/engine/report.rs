//! Public result and warning types for the structure domain.
//!
//! These are the values every operation returns; keeping them in one module
//! makes the wire/serialization surface of the domain reviewable in a single
//! place.

use std::borrow::Cow;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::normalize_nfc;
use crate::errors::StrHideError;
use crate::formats::FileFormat;
use crate::structure::adapters::StrategyCapacity;

use super::metadata::MetadataInspection;

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
    /// Already-materialized bytes are returned as [`Cow::Borrowed`] to avoid
    /// payload copies in the write path.
    pub fn into_buffered(self) -> Result<(Cow<'a, [u8]>, String, bool), StrHideError> {
        Ok(match self {
            PayloadSource::Bytes(b) => (Cow::Borrowed(b), "payload.bin".to_string(), true),
            PayloadSource::File(p) => {
                // Cap the read itself: every write path rejects payloads above
                // `structure_payload_limit` (<= MAX_VERIFY_PAYLOAD_SIZE), so a
                // larger file can never be embedded. Reading it in full first
                // would allocate arbitrary amounts of memory before the limit
                // check in `write_core` runs. Same bounded-read shape as the
                // `Stdin` arm below.
                const MAX_FILE_PAYLOAD: u64 = crate::crypto::MAX_VERIFY_PAYLOAD_SIZE;
                let mut f = File::open(p)?;
                let mut b = Vec::new();
                let read = std::io::Read::take(&mut f, MAX_FILE_PAYLOAD + 1).read_to_end(&mut b)?;
                if read as u64 > MAX_FILE_PAYLOAD {
                    return Err(StrHideError::PayloadTooLarge(format!(
                        "Payload file exceeds the {MAX_FILE_PAYLOAD} byte limit"
                    )));
                }
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
                const MAX_STDIN_PAYLOAD: u64 = 1 << 30; // 1 GiB
                let mut b = Vec::new();
                let read = std::io::stdin()
                    .take(MAX_STDIN_PAYLOAD + 1)
                    .read_to_end(&mut b)?;
                if read as u64 > MAX_STDIN_PAYLOAD {
                    return Err(StrHideError::General(
                        "Payload from standard input exceeds the 1 GiB limit".into(),
                    ));
                }
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
    /// Warning message formatted for CLI rendering.
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

/// Outcome of a successful [`write_carrier`](super::write_carrier). Serialized
/// to JSON by the CLI.
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
    pub strategy: crate::structure::registry::StrategyId,
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

/// Outcome of a successful [`read_carrier`](super::read_carrier) /
/// [`read_carrier_with_dialect`](super::read_carrier_with_dialect).
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

/// Outcome of [`inspect_carrier`](super::inspect_carrier).
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
    pub strategy: Option<crate::structure::registry::StrategyId>,
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
    pub(super) fn pass(detail: impl Into<String>) -> Self {
        Self {
            ok: true,
            detail: detail.into(),
            skipped: false,
        }
    }

    /// A level that ran and failed.
    pub(super) fn fail(detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            detail: detail.into(),
            skipped: false,
        }
    }

    /// A level that could not be attempted.
    pub(super) fn skipped(detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            detail: detail.into(),
            skipped: true,
        }
    }
}

/// Outcome of [`verify_carrier`](super::verify_carrier): three independent checks.
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

/// Outcome of a successful [`remove_carrier`](super::remove_carrier).
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
