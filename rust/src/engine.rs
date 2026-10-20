//! High-level engine: write, read, inspect, verify, and remove operations.
//!
//! This is the module library callers should use. The flow for each operation
//! is:
//!
//! 1. Run rejection checks ([`crate::rejection`]).
//! 2. Snapshot the carrier's metadata (size, SHA-256, permissions, mtime/atime).
//! 3. Detect the carrier format via [`crate::router`] and locate any existing
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

use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngExt;
use serde::Serialize;

use crate::adapters::{FinalizeCtx, HostAdapter, SeekRead, StrategyCapacity, TrailerCtx};
use crate::crypto::{
    compress_stream, compute_file_sha256, decompress_stream, decrypt_metadata,
    decrypt_stream_from_chunks, derive_keys, derive_stealth_magics, encrypt_metadata,
    encrypt_stream_to_chunks, normalize_nfc,
};
use crate::envelope::{
    EnvelopeHeader, EnvelopeTrailer, FLAG_COMPACT_META, FLAG_COMPRESSED, FLAG_ENCRYPTED,
    FLAG_HAS_HINT, FLAG_IS_FILE, FLAG_STEALTH, HEADER_SIZE,
};
use crate::errors::StrHideError;
use crate::params::{LocalParams, Profile};
use crate::rejection::run_rejection_checks;
use crate::router::{find_adapter, find_adapter_or_reject, id_to_strategy, strategy_to_id};

/// Metadata about the payload being hidden, stored inside the encrypted
/// envelope metadata block.
///
/// This is the metadata that survives `read`: the original filename, the
/// uncompressed payload size, its SHA-256, and a write timestamp. On extract,
/// `raw_sha256` is re-computed over the decrypted payload and must match.
#[derive(Debug, Serialize)]
pub struct CarrierMetadata {
    pub filename: String,
    pub raw_size: u64,
    pub raw_sha256: String,
    pub created_at: u64,
}

/// Stealth mode password derivation domain separation string.
///
/// Re-exported from [`crate::params`] for the public API: the constant lives
/// next to [`Profile::stealth_domain`], which is what actually drives
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
    profile: &Profile,
) -> Result<Option<(u64, u64, String)>, StrHideError> {
    if let Some(pwd) = password {
        let magics = derive_stealth_magics(pwd, profile.domain())?;
        if let Some(loc) = adapter.locate(carrier, Some(&magics.1))? {
            return Ok(Some(loc));
        }
    }
    adapter.locate(carrier, profile.locator_magic())
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
    for _ in 0..10 {
        let byte = *input.get(*pos).ok_or_else(|| {
            StrHideError::CorruptedData("Corrupted compact metadata block: truncated varint".into())
        })?;
        *pos += 1;
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
            "Payload filename exceeds 65535 bytes or its SHA-256 is malformed;              cannot encode envelope metadata"
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
    pub fn into_buffered(self) -> Result<(Vec<u8>, String, bool), StrHideError> {
        Ok(match self {
            PayloadSource::Bytes(b) => (b.to_vec(), "payload.bin".to_string(), true),
            PayloadSource::File(p) => {
                let mut f = File::open(p)?;
                let mut b = Vec::new();
                f.read_to_end(&mut b)?;
                let name = p
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("payload.bin")
                    .to_string();
                (b, name, true)
            }
            PayloadSource::Text(t) => (normalize_nfc(t).into_bytes(), String::new(), false),
            PayloadSource::Stdin => {
                let mut b = Vec::new();
                std::io::stdin().read_to_end(&mut b)?;
                (b, String::new(), false)
            }
            PayloadSource::Buffered {
                data,
                filename,
                is_file,
            } => (data.to_vec(), filename.to_string(), is_file),
        })
    }
}

/// Outcome of a successful [`write_carrier`]. Serialized to JSON by the CLI.
#[derive(Debug, Serialize)]
pub struct WriteResult {
    /// Always `"success"` when the call returns `Ok`.
    pub status: String,
    /// Path the (possibly stego) carrier was written to.
    pub carrier: String,
    /// Detected carrier format: `"PNG"`, `"JPEG"`, `"MP4"`, `"ZIP"`,
    /// `"PDF"`, or `"PE"`.
    pub format: String,
    /// Strategy actually chosen (e.g. `"chunk"`, `"app_segment"`,
    /// `"pe_codebits"`).
    pub strategy: String,
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
    pub backup_file: Option<String>,
    /// Non-fatal warnings (e.g. envelope > 50% of carrier size, probable
    /// pre-existing stealth envelope).
    pub warning: Option<String>,
}

/// Outcome of a successful [`read_carrier`] / [`read_carrier_with`].
#[derive(Debug)]
pub struct ReadResult {
    /// Path the carrier was read from.
    pub carrier: String,
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
    pub written_file: Option<String>,
}

/// Outcome of [`inspect_carrier`].
///
/// Every field is `Option`-wrapped so the same type can describe a carrier
/// with no envelope: `has_hidden_data == false`, and all envelope-derived
/// fields are `None`. `strategies` is always populated.
#[derive(Debug, Serialize)]
pub struct InspectResult {
    /// Path inspected.
    pub carrier: String,
    /// Detected carrier format.
    pub format: String,
    /// Whether an envelope (standard, or stealth-with-the-supplied-password)
    /// was located.
    pub has_hidden_data: bool,
    /// Strategy the envelope was written with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
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
    pub metadata: Option<serde_json::Value>,
    /// Capacity of every supported strategy for this carrier, in recommended
    /// priority order. Always present (also when an envelope already exists,
    /// answering "how much more could fit").
    pub strategies: Vec<StrategyCapacity>,
    /// Content-adaptive pixel/DCT steganography capacity for PNG/JPEG carriers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_stego_capacity: Option<crate::stego::StegoCapacityInfo>,
}

/// Result of one verification level.
#[derive(Debug, Serialize)]
pub struct LevelStatus {
    /// Whether the level passed.
    pub ok: bool,
    /// Human-readable detail.
    pub detail: String,
}

/// Outcome of [`verify_carrier`]: three independent checks.
#[derive(Debug, Serialize)]
pub struct VerifyResult {
    pub carrier: String,
    pub format: String,
    /// Level 1: host container structure still parses (e.g. PNG CRCs, ZIP
    /// central directory, PE headers).
    pub level1_host: LevelStatus,
    /// Level 2: envelope header/trailer found and internally consistent
    /// (version, lengths, CRC, offsets).
    pub level2_envelope: LevelStatus,
    /// Level 3: payload actually decrypts and its SHA-256 matches metadata.
    pub level3_crypto: LevelStatus,
}

/// Outcome of a successful [`remove_carrier`].
#[derive(Debug, Serialize)]
pub struct RemoveResult {
    /// Always `"success"` when the call returns `Ok`.
    pub status: String,
    /// Path the restored carrier was written to.
    pub carrier: String,
    /// Size of the restored file (must equal `orig_host_size` recorded in the
    /// envelope).
    pub restored_size: u64,
    /// SHA-256 of the restored file, as a hex string.
    pub restored_sha256: String,
    /// Always `true` on the success path; kept so callers can assert on the
    /// struct rather than just on `Result::is_ok`.
    pub verified_identical: bool,
    /// Path of the backup kept for an in-place removal, if any.
    pub backup_file: Option<String>,
}

/// RAII guard removing an uncommitted temporary file on drop.
///
/// Any error return between creating the temp file and the successful atomic
/// rename leaves a half-written `*.strhide.tmp` behind without this guard.
/// Call `commit()` once the rename succeeded; afterwards the guard is inert.
struct TmpGuard {
    path: Option<PathBuf>,
}

impl TmpGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn commit(&mut self) {
        self.path = None;
    }
}

impl Drop for TmpGuard {
    fn drop(&mut self) {
        if let Some(p) = &self.path {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Sanitize an untrusted metadata filename down to a safe bare file name.
///
/// Envelope metadata (especially in unencrypted envelopes) is attacker-controlled
/// input: `../../etc/passwd` style values must never escape the output directory.
/// Only the final path component is kept; empty results and `.`/`..` fall back to
/// "extracted.bin".
///
/// Both `/` and `\` are treated as separators on every platform: the envelope may
/// be written on one OS and read on another, so the sanitized name must not depend
/// on the host's path rules (a Windows-style name read on Unix would otherwise
/// keep its backslashes verbatim). Names carrying a `:` (drive prefix like `C:`) are
/// rejected as well, so they cannot turn into uncreatable files on Windows.
pub fn sanitize_filename(name: &str) -> String {
    let candidate = name.rsplit(['/', '\\']).find(|seg| !seg.is_empty());
    match candidate {
        Some(n) if n != "." && n != ".." && !n.contains(':') => n.to_string(),
        _ => "extracted.bin".to_string(),
    }
}

/// Build the "no hidden data" error for a carrier that `locate` could not
/// resolve. A stealth envelope written with a password we were not given is
/// invisible to magic-based location by design; `suspicious_structures` gives
/// a password-independent structural opinion, which turns the bare "not found"
/// message into actionable guidance instead of a dead end.
fn no_hidden_data_error(
    carrier: &mut File,
    adapter: &'static dyn HostAdapter,
    carrier_path: &Path,
    password_supplied: bool,
) -> StrHideError {
    let mut msg = format!(
        "No hidden strhide data found in '{}'",
        carrier_path.display()
    );
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

/// Options controlling an injection. Bundled into a struct so the public API
/// stays readable and extensible as features grow (replaces a nine-parameter
/// positional signature that clippy flagged as `too_many_arguments`).
///
/// The `Default` values match the CLI defaults: `auto` strategy, timestamps and
/// in-place backup preserved, no encryption, no stealth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteOptions<'a> {
    /// Write the stego carrier here instead of overwriting the carrier.
    pub output_path: Option<&'a Path>,
    /// Password for encryption; required for `--stealth`.
    pub password: Option<&'a str>,
    /// Password hint (mutually exclusive with `stealth`, max 1024 bytes).
    pub password_hint: Option<&'a str>,
    /// Injection strategy name or `auto`.
    pub strategy: &'a str,
    /// Hide the envelope with password-derived magics (requires `password`).
    pub stealth: bool,
    /// Clone the carrier's original timestamps onto the result.
    pub preserve_time: bool,
    /// Keep a `<carrier>.bak` backup for in-place writes.
    pub backup: bool,
}

impl Default for WriteOptions<'_> {
    fn default() -> Self {
        Self {
            output_path: None,
            password: None,
            password_hint: None,
            strategy: "auto",
            stealth: false,
            preserve_time: true,
            backup: true,
        }
    }
}

/// Format a Unix timestamp (seconds) as `YYYYMMDD-HHMMSS` in UTC.
///
/// Days-to-civil conversion (Howard Hinnant's algorithm); avoids pulling in a
/// date-time dependency for a backup file name.
fn utc_stamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}{m:02}{d:02}-{hour:02}{minute:02}{second:02}")
}

/// Pick a backup path that never overwrites an existing backup.
///
/// In-place writes create `<carrier>.bak`; writing again would silently replace
/// the previous backup (and with it the only pre-write copy of the carrier).
/// Collisions fall back to `<carrier>.bak-<UTC timestamp>` and then a counter.
/// Mirrors the Python implementation.
fn next_backup_path(carrier: &Path) -> PathBuf {
    // Build the path by appending to the OsString: `Path::display()` is lossy
    // for non-UTF-8 paths (unpaired surrogates on Windows, arbitrary bytes on
    // Unix) and would turn a valid carrier path into a non-existent one.
    let with_suffix = |suffix: &str| {
        let mut os = carrier.as_os_str().to_os_string();
        os.push(suffix);
        PathBuf::from(os)
    };

    let base = with_suffix(".bak");
    if !base.exists() {
        return base;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let stamp = utc_stamp(now);
    for suffix in 0..1000u32 {
        let candidate = if suffix == 0 {
            with_suffix(&format!(".bak-{stamp}"))
        } else {
            with_suffix(&format!(".bak-{stamp}-{suffix}"))
        };
        if !candidate.exists() {
            return candidate;
        }
    }
    with_suffix(&format!(".bak-{stamp}-{}", std::process::id()))
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
/// use strhide::engine::{write_carrier, PayloadSource, WriteOptions};
/// # fn main() -> Result<(), strhide::errors::StrHideError> {
/// write_carrier(
///     std::path::Path::new("photo.png"),
///     PayloadSource::Text("secret"),
///     &WriteOptions { password: Some("pw"), ..WriteOptions::default() },
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
        &Profile::default(),
    )
}

/// Inject `source` into `carrier_path` with library-level tuning.
///
/// Same as [`write_carrier`], plus:
///
/// - `local`: writer-only knobs ([`LocalParams`]) that the reader never needs.
///   Passing different values than the reader uses is safe.
/// - `profile`: the private dialect ([`Profile`]). The reader must be given the
///   same profile; `Profile::default()` is the official dialect.
///
/// ```no_run
/// use strhide::engine::{write_carrier_with, PayloadSource, WriteOptions};
/// use strhide::params::{CompressionStrategy, LocalParams, Profile};
/// # fn main() -> Result<(), strhide::errors::StrHideError> {
/// // Both types are `#[non_exhaustive]`: build from `default()` with setters.
/// let profile = Profile::default().with_default_secret("my-private-dialect");
/// let local = LocalParams::default()
///     .with_chunk_size(64 * 1024)
///     .with_compression(CompressionStrategy::Never);
/// write_carrier_with(
///     std::path::Path::new("photo.png"),
///     PayloadSource::Text("secret"),
///     &WriteOptions::default(),
///     &local,
///     &profile,
/// )?;
/// # Ok(()) }
/// ```
pub fn write_carrier_with(
    carrier_path: &Path,
    source: PayloadSource,
    options: &WriteOptions<'_>,
    local: &LocalParams,
    profile: &Profile,
) -> Result<WriteResult, StrHideError> {
    local.validate()?;
    let output_path = options.output_path;
    let password = options.password;
    let password_hint = options.password_hint;
    let strategy = options.strategy;
    let stealth = options.stealth;
    let preserve_time = options.preserve_time;
    let backup = options.backup;

    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

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

    let target_path = output_path.unwrap_or(carrier_path);

    // 1. Run security rejection checks (carrier policy + target permissions)
    run_rejection_checks(carrier_path, target_path, local.rejection)?;

    // 2. Capture carrier metadata (stats, permissions, timestamps, full SHA-256)
    let meta = std::fs::metadata(carrier_path)?;
    let orig_host_size = meta.len();
    let orig_permissions = meta.permissions();
    let orig_atime = filetime::FileTime::from_last_access_time(&meta);
    let orig_mtime = filetime::FileTime::from_last_modification_time(&meta);
    let orig_host_sha256 = compute_file_sha256(carrier_path)?;

    // 3. Detect adapter & check existing envelope
    let (adapter, structural_warnings) = {
        let mut cf = File::open(carrier_path)?;
        let adapter = find_adapter_or_reject(&mut cf, &carrier_path.display().to_string())?;

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
            cf.seek(SeekFrom::Start(0))?;
            adapter.locate(&mut cf, profile.locator_magic())?.is_some()
        };
        if !occupied && profile.locator_magic().is_some() {
            cf.seek(SeekFrom::Start(0))?;
            occupied = adapter.locate(&mut cf, None)?.is_some();
        }
        if occupied {
            return Err(StrHideError::General(
                "Carrier already contains hidden data. Use remove first or specify another file."
                    .into(),
            ));
        }
        if let Some(pwd) = password {
            let magics = derive_stealth_magics(pwd, profile.domain())?;
            cf.seek(SeekFrom::Start(0))?;
            if adapter.locate(&mut cf, Some(&magics.1))?.is_some() {
                return Err(StrHideError::General(
                    "Carrier already contains hidden data (stealth envelope). Use remove first or specify another file.".into(),
                ));
            }
        }

        // Neither magic scan matched. A stealth envelope written with an
        // unknown password is undetectable by magic; scan structurally and
        // warn (not refuse) when the carrier shows an envelope-shaped
        // container, so the user learns a second envelope would stack on top.
        let warnings = adapter.suspicious_structures(&mut cf);
        (adapter, warnings)
    };

    // 4. Prepare data payload stream
    let (payload_raw_bytes, filename, is_file) = source.into_buffered()?;

    let raw_size = payload_raw_bytes.len() as u64;
    let raw_sha256 = {
        let h = crate::crypto::compute_sha256(&payload_raw_bytes);
        h.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    // 5. Compress data with Deflate. `CompressionStrategy::Auto` keeps the
    // historical integer criterion (cross-language identical: keep compression
    // only when it saves at least 2%: comp_len * 100 < raw_size * 98). The
    // level and the decision are writer-only; the reader just inflates raw
    // deflate when FLAG_COMPRESSED is set.
    let mut compressed_buf = Vec::new();
    let (_, comp_len) = compress_stream(
        &mut Cursor::new(&payload_raw_bytes),
        &mut compressed_buf,
        local.compression.level(),
    )?;

    let (to_encrypt_bytes, is_compressed) = if local.compression.should_compress(raw_size, comp_len)
    {
        // Keep the compressed stream and release the raw payload buffer early.
        let mut raw = payload_raw_bytes;
        raw.clear();
        raw.shrink_to_fit();
        (compressed_buf, true)
    } else {
        // Keep the raw payload and release the compressed buffer early.
        drop(compressed_buf);
        (payload_raw_bytes, false)
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
    let (payload_key, meta_key) = derive_keys(effective_password, &salt)?;

    let header_magic: [u8; 8];
    let trailer_magic: [u8; 4];

    if stealth && has_custom_password {
        flags |= FLAG_STEALTH;
        let magics = derive_stealth_magics(effective_password, profile.domain())?;
        header_magic = magics.0;
        trailer_magic = magics.1;
    } else {
        // The profile decides the dialect; `Profile::default()` yields the
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
    let exact_meta_len = meta_raw.len() as u64 + 16;
    // Must use the *configured* chunk size: `exact_ube_size` is cross-checked
    // against the real ciphertext length, so a mismatch here would fail-fast.
    let chunk_count = to_encrypt_len.div_ceil(local.chunk_size as u64).max(1);
    let exact_payload_len = to_encrypt_len + chunk_count * 20;
    let exact_ube_size =
        HEADER_SIZE as u64 + hint_bytes.len() as u64 + exact_meta_len + exact_payload_len + 24;

    let selected_strategy: String = if strategy == "auto" {
        let mut cf = File::open(carrier_path)?;
        adapter
            .choose_auto_strategy(&mut cf, exact_ube_size)
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
    let mut header = EnvelopeHeader {
        magic_header: header_magic,
        flags,
        strategy_id: strat_id,
        salt,
        base_nonce,
        orig_host_size,
        orig_host_sha256,
        hint_len: hint_bytes.len() as u32,
        ..Default::default()
    };

    let fixed_header_aad = header.get_aad();

    // Encrypt metadata
    let meta_block = encrypt_metadata(&meta_raw, &meta_key, &base_nonce, &fixed_header_aad)?;
    header.meta_len = meta_block.len() as u32;

    // Encrypt payload stream
    let mut payload_cipher_buf = Vec::new();
    let payload_written = encrypt_stream_to_chunks(
        &mut Cursor::new(&to_encrypt_bytes),
        &mut payload_cipher_buf,
        &payload_key,
        &base_nonce,
        &fixed_header_aad,
        local.chunk_size,
    )?;

    let ube_total_size = HEADER_SIZE as u64
        + hint_bytes.len() as u64
        + header.meta_len as u64
        + payload_written
        + 24;

    // Defensive cross-check: the exact pre-computation above must match reality.
    // A mismatch would indicate a protocol drift between crypto and engine.
    if ube_total_size != exact_ube_size {
        return Err(StrHideError::General(format!(
            "Internal envelope size mismatch: computed {ube_total_size}, expected {exact_ube_size}"
        )));
    }

    // Check size inflation warning (> 50%)
    let mut warning_msg = None;
    if orig_host_size > 0 && ube_total_size > (orig_host_size / 2) {
        let ratio_pct = (ube_total_size as f64 / orig_host_size as f64) * 100.0;
        // State the measured ratio and refer to the threshold separately. The
        // old text hard-coded "exceeds 50.0%" next to the real percentage,
        // which read like a contradiction for tiny carriers (e.g. "50.0% ...
        // 319.4%").
        warning_msg = Some(format!(
            "Hidden data envelope ({ube_total_size} bytes) is {ratio_pct:.1}% of the carrier file size ({orig_host_size} bytes), above the 50% inflation warning threshold. Noticeable file size inflation may compromise stealthiness!"
        ));
    }

    // Merge structural warnings (probable pre-existing stealth envelope).
    if !structural_warnings.is_empty() {
        let extra = format!(
            "Carrier shows structures consistent with a hidden envelope ({}). It may already contain a stealth envelope written with a different password; injecting now would stack a second envelope on top.",
            structural_warnings.join("; ")
        );
        warning_msg = Some(match warning_msg {
            Some(w) => format!("{w} {extra}"),
            None => extra,
        });
    }

    // Assemble full UBE (payload buffer is moved in, not copied)
    let mut tmp_ube = Vec::with_capacity(ube_total_size as usize);
    tmp_ube.extend_from_slice(&header.pack_with_profile(password, profile)?);
    if !hint_bytes.is_empty() {
        tmp_ube.extend_from_slice(&hint_bytes);
    }
    tmp_ube.extend_from_slice(&meta_block);
    tmp_ube.append(&mut payload_cipher_buf); // move bytes, no copy
    let dummy_trailer = if stealth && has_custom_password {
        EnvelopeTrailer::create_stealth(0, ube_total_size, trailer_magic)
    } else {
        EnvelopeTrailer::create(0, ube_total_size, trailer_magic)
    };
    tmp_ube.extend_from_slice(&dummy_trailer.pack());

    // 9. Inject into temporary target file.
    // TmpGuard removes the half-written temp file on any early return unless
    // commit() is called after the atomic rename succeeded. The name is built
    // from the OsString: `display()` is lossy for non-UTF-8 targets.
    let mut tmp_os = target_path.as_os_str().to_os_string();
    tmp_os.push(".strhide.tmp");
    let tmp_target = PathBuf::from(tmp_os);
    let mut tmp_guard = TmpGuard::new(tmp_target.clone());
    let (inject_offset, inject_size, patch_offset, orig_patch_val) = {
        let mut host_in = File::open(carrier_path)?;
        let mut out_file = File::create(&tmp_target).map_err(|e| {
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
        let mut ube_cursor = Cursor::new(&tmp_ube);
        adapter.inject(
            &mut host_in,
            &mut ube_cursor,
            &mut out_file,
            &selected_strategy,
        )?
    };

    // 10. Update real ube_offset in Header and Trailer
    let delta = {
        let mut cf = File::open(carrier_path)?;
        adapter.envelope_offset_delta(&mut cf, &selected_strategy, ube_total_size)?
    };
    let actual_ube_offset = inject_offset + delta;

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
        {
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&tmp_target)?;

            // Patch header
            f.seek(SeekFrom::Start(actual_ube_offset))?;
            f.write_all(&header.pack_with_profile(password, profile)?)?;

            // Patch trailer at end of UBE
            let trailer_ctx = TrailerCtx {
                actual_ube_offset,
                ube_total_size,
                inject_offset,
                inject_size,
                strategy: &selected_strategy,
            };
            let trailer_pos = adapter.trailer_offset(&trailer_ctx);
            f.seek(SeekFrom::Start(trailer_pos))?;
            f.write_all(&final_trailer.pack())?;

            // Post-write finalization (e.g. recalculating chunk CRCs)
            let fin_ctx = FinalizeCtx {
                ube_offset: actual_ube_offset,
                ube_total_size,
                inject_offset,
                inject_size,
                strategy: &selected_strategy,
            };
            adapter.finalize(&mut f, &fin_ctx)?;
        }
    }

    // 11. Self-verification: precisely verify the envelope just written at
    // actual_ube_offset (not merely "some envelope exists somewhere"), so a
    // stale envelope from a previous injection cannot satisfy the check.
    //
    // The envelope is read back through `open_ube_reader` rather than at raw
    // file offsets: for contiguous envelopes the virtual stream is a bounded
    // slice of the very same bytes, and for scattered strategies (pe_codebits)
    // there are no file offsets to read at all.
    {
        let mut f = File::open(&tmp_target)?;
        let mut ube_stream = adapter.open_ube_reader(
            &mut f,
            actual_ube_offset,
            ube_total_size,
            &selected_strategy,
        )?;
        let mut hdr_bytes = [0u8; HEADER_SIZE];
        ube_stream.read_exact(&mut hdr_bytes)?;
        let written_header = EnvelopeHeader::unpack_with_profile(&hdr_bytes, password, profile)?;
        if written_header.magic_header != header_magic
            || written_header.inject_offset != inject_offset
            || written_header.inject_size != inject_size
            || written_header.patch_offset != patch_offset
            || written_header.orig_patch_val != orig_patch_val
        {
            return Err(StrHideError::General(
                "Self-verification failed: header at injection offset does not match written parameters".into(),
            ));
        }
        ube_stream.seek(SeekFrom::Start(ube_total_size - 24))?;
        let mut tr_bytes = [0u8; 24];
        ube_stream.read_exact(&mut tr_bytes)?;
        let written_trailer = EnvelopeTrailer::unpack(&tr_bytes, Some(&trailer_magic))?;
        if written_trailer.ube_offset != actual_ube_offset
            || written_trailer.ube_total_size != ube_total_size
        {
            return Err(StrHideError::General(
                "Self-verification failed: trailer boundary parameters mismatch".into(),
            ));
        }
    }

    // 12. In-place backup (if applicable) & Atomic commit
    let is_inplace = std::path::absolute(target_path)? == std::path::absolute(carrier_path)?;
    let mut backup_file = None;
    if is_inplace && backup {
        let bak = next_backup_path(carrier_path);
        std::fs::copy(carrier_path, &bak)?;
        backup_file = Some(bak.display().to_string());
    }

    std::fs::rename(&tmp_target, target_path)?;
    tmp_guard.commit();

    // Restore original carrier permissions (mode/readonly) alongside timestamps.
    let _ = std::fs::set_permissions(target_path, orig_permissions);

    if preserve_time {
        let _ = filetime::set_file_times(target_path, orig_atime, orig_mtime);
    }

    let strategy_note = adapter.strategy_note(&selected_strategy, strategy == "auto");

    Ok(WriteResult {
        status: "success".into(),
        carrier: target_path.display().to_string(),
        format: adapter.format_name().into(),
        strategy: selected_strategy,
        strategy_note,
        raw_size,
        ube_size: ube_total_size,
        is_encrypted: has_custom_password,
        is_stealth: (flags & FLAG_STEALTH) != 0,
        password_hint: password_hint.map(|s| s.to_string()),
        backup_file,
        warning: warning_msg,
    })
}

/// Extract the payload of a carrier.
///
/// Refuses to overwrite an existing output file; use [`read_carrier_with`] with
/// `overwrite = true` (CLI: `--overwrite`) to allow it.
pub fn read_carrier(
    carrier_path: &Path,
    output_path: Option<&Path>,
    password: Option<&str>,
) -> Result<ReadResult, StrHideError> {
    read_carrier_with(carrier_path, output_path, password, false)
}

/// Extract the payload of a carrier, optionally replacing an existing output.
///
/// Without `overwrite`, an existing destination is an error: silently
/// truncating it would lose a user file, which contradicts the tool's
/// "lossless, restorable" contract.
pub fn read_carrier_with(
    carrier_path: &Path,
    output_path: Option<&Path>,
    password: Option<&str>,
    overwrite: bool,
) -> Result<ReadResult, StrHideError> {
    read_carrier_with_profile(
        carrier_path,
        output_path,
        password,
        overwrite,
        &Profile::default(),
    )
}

/// Extract the payload of a carrier written under `profile`.
///
/// The profile must be the same one used at write time. For the official
/// profile this is identical to [`read_carrier_with`]; for a private dialect a
/// mismatched profile cannot return payload bytes — the envelope is either not
/// found at all (stealth, or a custom trailer magic) or fails header/`AEAD`
/// validation (custom `default_secret` with the standard magics).
pub fn read_carrier_with_profile(
    carrier_path: &Path,
    output_path: Option<&Path>,
    password: Option<&str>,
    overwrite: bool,
    profile: &Profile,
) -> Result<ReadResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let mut f = File::open(carrier_path)?;
    let adapter = find_adapter_or_reject(&mut f, &carrier_path.display().to_string())?;

    let loc = locate_envelope(&mut f, adapter, password, profile)?;

    let (ube_offset, ube_total_size, strategy_name) = match loc {
        Some(l) => l,
        None => {
            return Err(no_hidden_data_error(
                &mut f,
                adapter,
                carrier_path,
                password.is_some(),
            ));
        }
    };

    let mut ube_stream =
        adapter.open_ube_reader(&mut f, ube_offset, ube_total_size, &strategy_name)?;

    // Read fixed header
    let mut header_bytes = [0u8; HEADER_SIZE];
    ube_stream.read_exact(&mut header_bytes)?;
    let header = EnvelopeHeader::unpack_with_profile(&header_bytes, password, profile)?;
    header.validate_against(ube_total_size)?;

    // Read hint if present
    let mut hint_str = None;
    if header.hint_len > 0 {
        let mut hint_buf = vec![0u8; header.hint_len as usize];
        ube_stream.read_exact(&mut hint_buf)?;
        hint_str = Some(String::from_utf8_lossy(&hint_buf).to_string());
    }

    let fixed_header_aad = header.get_aad();

    // Derive keys
    let (payload_key, meta_key) = if header.is_encrypted() {
        if password.is_none() {
            let hint_msg = match &hint_str {
                Some(h) => format!(" Hint: '{h}'."),
                None => String::new(),
            };
            return Err(StrHideError::Password(format!(
                "Password required to extract hidden data.{hint_msg}"
            )));
        }
        derive_keys(password.unwrap(), &header.salt)?
    } else {
        derive_keys(profile.secret(), &header.salt)?
    };

    // Read metadata
    let mut meta_bytes = vec![0u8; header.meta_len as usize];
    ube_stream.read_exact(&mut meta_bytes)?;

    // Metadata is always AEAD-sealed, even in an unencrypted envelope (the key
    // is then the profile's default secret). There is no plaintext fallback:
    // pre-v2 carriers stored metadata in the clear and are no longer readable.
    let meta_obj = decrypt_metadata(
        &meta_bytes,
        &meta_key,
        &header.base_nonce,
        &fixed_header_aad,
    )
    .map_err(|_| StrHideError::Password("Invalid password or corrupted metadata".into()))
    .and_then(|plain| decode_metadata(&plain, header.is_compact_meta()))?;

    // Read payload (checked_sub: validate_against already bounds the fields,
    // but keep the arithmetic defensive against corrupted envelopes)
    let total_payload_bytes = ube_total_size
        .checked_sub(HEADER_SIZE as u64)
        .and_then(|v| v.checked_sub(header.hint_len as u64))
        .and_then(|v| v.checked_sub(header.meta_len as u64))
        .and_then(|v| v.checked_sub(24))
        .ok_or_else(|| {
            StrHideError::CorruptedData(
                "Envelope size fields inconsistent: payload region underflow".into(),
            )
        })?;

    let mut decrypted_payload = Vec::new();
    decrypt_stream_from_chunks(
        &mut ube_stream,
        &mut decrypted_payload,
        &payload_key,
        &header.base_nonce,
        &fixed_header_aad,
        total_payload_bytes,
    )?;

    // Decompress if needed. `meta_obj.raw_size` is the declared uncompressed
    // size (inside the AEAD-protected metadata), so it doubles as a hard
    // expansion bound for untrusted carriers.
    let final_data = if header.is_compressed() {
        let mut decomp = Vec::new();
        decompress_stream(
            &mut Cursor::new(&decrypted_payload),
            &mut decomp,
            meta_obj.raw_size,
        )?;
        decomp
    } else {
        decrypted_payload
    };

    // Verify SHA-256
    let actual_sha256 = {
        let h = crate::crypto::compute_sha256(&final_data);
        h.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    if actual_sha256 != meta_obj.raw_sha256 {
        return Err(StrHideError::CorruptedData(format!(
            "Payload SHA-256 mismatch: {actual_sha256} != {}",
            meta_obj.raw_sha256
        )));
    }

    let mut written_file = None;
    if let Some(out_p) = output_path {
        let final_dest = if out_p.is_dir() {
            // Metadata filename is untrusted input: sanitize to a bare name so
            // crafted carriers cannot write outside the output directory.
            let fn_to_use = if meta_obj.filename.is_empty() {
                "extracted.bin".to_string()
            } else {
                sanitize_filename(&meta_obj.filename)
            };
            out_p.join(fn_to_use)
        } else {
            out_p.to_path_buf()
        };

        // Never truncate an existing file by accident: extracting several
        // carriers that contain the same payload name (or reading into a busy
        // directory) used to replace user files silently.
        if final_dest.exists() && !overwrite {
            return Err(StrHideError::Rejection(format!(
                "Refusing to overwrite existing file '{}'. Choose another -o path or pass --overwrite.",
                final_dest.display()
            )));
        }

        let mut out_f = File::create(&final_dest).map_err(|e| {
            let reason = match e.kind() {
                std::io::ErrorKind::NotFound => "the output directory does not exist",
                std::io::ErrorKind::PermissionDenied => "the output directory is not writable",
                _ => "the output file could not be created",
            };
            StrHideError::General(format!(
                "Cannot create '{}': {reason} [{e}]",
                final_dest.display()
            ))
        })?;
        out_f.write_all(&final_data)?;
        written_file = Some(final_dest.display().to_string());
    }

    Ok(ReadResult {
        carrier: carrier_path.display().to_string(),
        data: final_data,
        is_file: header.is_file(),
        is_encrypted: header.is_encrypted(),
        filename: meta_obj.filename,
        raw_size: meta_obj.raw_size,
        written_file,
    })
}

/// Strip the envelope from `carrier_path` and restore the original carrier
/// bit-for-bit.
///
/// When `output_path` is `None` the carrier is rewritten in place; otherwise
/// the restored bytes are written there (the original carrier is untouched).
///
/// The restored file is hashed and compared to the `orig_host_size` /
/// `orig_host_sha256` recorded in the envelope. On mismatch the new file is
/// discarded and [`StrHideError::RestoreMismatch`] is returned — usually
/// because a second envelope was layered on top and must be removed first.
///
/// `password` is required only when the envelope was written in stealth mode;
/// a non-stealth envelope is stripped regardless of password.
///
/// When `backup` is true and the write is in place, a `<carrier>.bak` file is
/// kept before overwriting.
pub fn remove_carrier(
    carrier_path: &Path,
    output_path: Option<&Path>,
    password: Option<&str>,
    backup: bool,
) -> Result<RemoveResult, StrHideError> {
    remove_carrier_with(
        carrier_path,
        output_path,
        password,
        backup,
        &Profile::default(),
    )
}

/// Strip the envelope of a carrier written under `profile`.
///
/// The profile must be the one used at write time: it drives envelope location
/// (custom magic), the stealth domain, and the `default_secret` used to decode
/// a non-password envelope.
pub fn remove_carrier_with(
    carrier_path: &Path,
    output_path: Option<&Path>,
    password: Option<&str>,
    backup: bool,
    profile: &Profile,
) -> Result<RemoveResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let target_path = output_path.unwrap_or(carrier_path);
    let meta = std::fs::metadata(carrier_path)?;
    let orig_permissions = meta.permissions();
    let orig_atime = filetime::FileTime::from_last_access_time(&meta);
    let orig_mtime = filetime::FileTime::from_last_modification_time(&meta);

    let header: EnvelopeHeader;
    let tmp_target = PathBuf::from(format!("{}.strhide.restoring.tmp", target_path.display()));
    let mut tmp_guard = TmpGuard::new(tmp_target.clone());

    {
        let mut cf = File::open(carrier_path)?;
        let adapter = find_adapter_or_reject(&mut cf, &carrier_path.display().to_string())?;

        let loc = locate_envelope(&mut cf, adapter, password, profile)?;

        let (ube_offset, ube_total_size, strategy_name) = match loc {
            Some(l) => l,
            None => {
                return Err(no_hidden_data_error(
                    &mut cf,
                    adapter,
                    carrier_path,
                    password.is_some(),
                ));
            }
        };

        // Read the header through the adapter's virtual envelope stream: for
        // contiguous envelopes this is a bounded slice of the same bytes the
        // old seek+read produced; for scattered strategies (pe_codebits) the
        // envelope has no file offset to seek to.
        {
            let mut header_bytes = [0u8; HEADER_SIZE];
            let mut ube_stream =
                adapter.open_ube_reader(&mut cf, ube_offset, ube_total_size, &strategy_name)?;
            ube_stream.read_exact(&mut header_bytes)?;
            header = EnvelopeHeader::unpack_with_profile(&header_bytes, password, profile)?;
            header.validate_against(ube_total_size)?;
        }

        let mut out_f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_target)?;

        adapter.strip(&mut cf, &mut out_f, &header)?;
    }

    // Verify restored file
    let restored_size = std::fs::metadata(&tmp_target)?.len();
    let restored_sha256 = compute_file_sha256(&tmp_target)?;

    if restored_size != header.orig_host_size || restored_sha256 != header.orig_host_sha256 {
        // Diagnose the common cause: the carrier carried a second envelope
        // (e.g. a stealth envelope underneath), so stripping this one cannot
        // reproduce the recorded original. Envelopes must be removed in
        // reverse order of injection.
        let mut diagnosis = String::new();
        if let Ok(mut rf) = File::open(&tmp_target)
            && let Some(r_adapter) = find_adapter(&mut rf)
        {
            let remaining = r_adapter
                .locate(&mut rf, profile.locator_magic())
                .ok()
                .flatten()
                .or_else(|| r_adapter.locate(&mut rf, None).ok().flatten())
                .or_else(|| {
                    password.and_then(|pwd| {
                        derive_stealth_magics(pwd, profile.domain())
                            .ok()
                            .and_then(|m| r_adapter.locate(&mut rf, Some(&m.1)).ok().flatten())
                    })
                });
            if remaining.is_some() {
                diagnosis = "\nDiagnosis: the restored file still contains another hidden envelope. Remove envelopes in reverse order of injection (most recently written first).".to_string();
            }
        }
        return Err(StrHideError::RestoreMismatch(format!(
            "Restored size: {restored_size} (expected {})\nRestored SHA256: {}\nExpected SHA256: {}{}",
            header.orig_host_size,
            restored_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            header
                .orig_host_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            diagnosis
        )));
    }

    let is_inplace = std::path::absolute(target_path)? == std::path::absolute(carrier_path)?;
    let mut backup_file = None;
    if is_inplace && backup {
        let bak = next_backup_path(carrier_path);
        std::fs::copy(carrier_path, &bak)?;
        backup_file = Some(bak.display().to_string());
    }

    std::fs::rename(&tmp_target, target_path)?;
    tmp_guard.commit();
    let _ = std::fs::set_permissions(target_path, orig_permissions);
    let _ = filetime::set_file_times(target_path, orig_atime, orig_mtime);

    Ok(RemoveResult {
        status: "success".into(),
        carrier: target_path.display().to_string(),
        restored_size,
        restored_sha256: restored_sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        verified_identical: true,
        backup_file,
    })
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
    inspect_carrier_with(carrier_path, password, &Profile::default())
}

/// Inspect a carrier written under `profile`.
///
/// A carrier whose envelope belongs to a different dialect reports
/// `has_hidden_data == false`: a private dialect is meant to be invisible to
/// readers that do not know it.
pub fn inspect_carrier_with(
    carrier_path: &Path,
    password: Option<&str>,
    profile: &Profile,
) -> Result<InspectResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let mut cf = File::open(carrier_path)?;
    let adapter = find_adapter_or_reject(&mut cf, &carrier_path.display().to_string())?;

    // Measured strategy capacities (design: folds the former `check` command
    // into `inspect`). Adapters that can answer statically ignore the reader;
    // PE measures `.text` density and zero slack, ZIP measures the EOCD offset.
    let strategies = adapter.strategy_capacities(Some(&mut cf));

    let content_stego_capacity = if adapter.format_name() == "PNG"
        || adapter.format_name() == "JPEG"
    {
        cf.rewind().ok();
        let mut buf = Vec::new();
        if cf.read_to_end(&mut buf).is_ok() {
            cf.rewind().ok();
            crate::stego::probe_carrier_capacity(&buf, &crate::stego::StegoOptions::default()).ok()
        } else {
            None
        }
    } else {
        None
    };

    let loc = locate_envelope(&mut cf, adapter, password, profile)?;

    let (ube_offset, ube_total_size, strategy_name) = match loc {
        Some(l) => l,
        None => {
            return Ok(InspectResult {
                carrier: carrier_path.display().to_string(),
                format: adapter.format_name().into(),
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
                strategies,
                content_stego_capacity,
            });
        }
    };

    let mut ube_stream =
        adapter.open_ube_reader(&mut cf, ube_offset, ube_total_size, &strategy_name)?;

    let mut header_bytes = [0u8; HEADER_SIZE];
    ube_stream.read_exact(&mut header_bytes)?;
    let header = EnvelopeHeader::unpack_with_profile(&header_bytes, password, profile)?;
    header.validate_against(ube_total_size)?;

    let mut hint_str = None;
    if header.hint_len > 0 {
        let mut hint_buf = vec![0u8; header.hint_len as usize];
        ube_stream.read_exact(&mut hint_buf)?;
        hint_str = Some(String::from_utf8_lossy(&hint_buf).to_string());
    }

    let mut meta_val = None;
    if !header.is_encrypted() {
        let mut meta_bytes = vec![0u8; header.meta_len as usize];
        if ube_stream.read_exact(&mut meta_bytes).is_ok() {
            let decoded = if let Ok((_, meta_key)) = derive_keys(profile.secret(), &header.salt)
                && let Ok(dec) = decrypt_metadata(
                    &meta_bytes,
                    &meta_key,
                    &header.base_nonce,
                    &header.get_aad(),
                ) {
                decode_metadata(&dec, header.is_compact_meta()).ok()
            } else {
                None
            };
            if let Some(meta_obj) = decoded
                && let Ok(val) = serde_json::to_value(&meta_obj)
            {
                meta_val = Some(val);
            }
        }
    } else if let Some(pwd) = password {
        let mut meta_bytes = vec![0u8; header.meta_len as usize];
        if ube_stream.read_exact(&mut meta_bytes).is_ok()
            && let Ok((_, meta_key)) = derive_keys(pwd, &header.salt)
        {
            if let Ok(dec) = decrypt_metadata(
                &meta_bytes,
                &meta_key,
                &header.base_nonce,
                &header.get_aad(),
            ) {
                if let Ok(meta_obj) = decode_metadata(&dec, header.is_compact_meta())
                    && let Ok(val) = serde_json::to_value(&meta_obj)
                {
                    meta_val = Some(val);
                }
            } else {
                meta_val = Some(serde_json::json!({"error": "Invalid password"}));
            }
        }
    }

    let reported_strategy = if header.strategy_id > 0 {
        id_to_strategy(header.strategy_id).to_string()
    } else {
        strategy_name
    };

    Ok(InspectResult {
        carrier: carrier_path.display().to_string(),
        format: adapter.format_name().into(),
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
        strategies,
        content_stego_capacity,
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
    verify_carrier_with(carrier_path, password, &Profile::default())
}

/// Verify a carrier written under `profile`.
///
/// Level 1 (host structure) is dialect-independent; levels 2 and 3 need the
/// same profile used at write time.
pub fn verify_carrier_with(
    carrier_path: &Path,
    password: Option<&str>,
    profile: &Profile,
) -> Result<VerifyResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let mut cf = File::open(carrier_path)?;
    let adapter = find_adapter_or_reject(&mut cf, &carrier_path.display().to_string())?;

    // Level 1: Host format integrity
    let (l1_ok, l1_msg) = adapter.verify_structure(&mut cf)?;

    let loc = locate_envelope(&mut cf, adapter, password, profile)?;

    let (ube_offset, ube_total_size, strategy_name) = match loc {
        Some(l) => l,
        None => {
            return Ok(VerifyResult {
                carrier: carrier_path.display().to_string(),
                format: adapter.format_name().into(),
                level1_host: LevelStatus {
                    ok: l1_ok,
                    detail: l1_msg,
                },
                level2_envelope: LevelStatus {
                    ok: false,
                    detail: "No envelope found".into(),
                },
                level3_crypto: LevelStatus {
                    ok: false,
                    detail: "Skipped (no envelope)".into(),
                },
            });
        }
    };

    let (l2_ok, l2_msg, is_encrypted, _is_stealth) = {
        match adapter.open_ube_reader(&mut cf, ube_offset, ube_total_size, &strategy_name) {
            Err(e) => (
                false,
                format!("Cannot open envelope reader: {e}"),
                false,
                false,
            ),
            Ok(mut ube_stream) => {
                let mut header_bytes = [0u8; HEADER_SIZE];
                if ube_stream.read_exact(&mut header_bytes).is_err() {
                    (false, "Cannot read header".into(), false, false)
                } else if let Ok(header) =
                    EnvelopeHeader::unpack_with_profile(&header_bytes, password, profile)
                {
                    // Validate header field ranges against the located envelope size
                    // (version / hint_len / meta_len consistency) before trusting any
                    // downstream reads — a crafted or corrupted header must fail Level
                    // 2 with a domain error instead of being silently accepted.
                    if let Err(e) = header.validate_against(ube_total_size) {
                        (
                            false,
                            format!("Envelope header validation failed: {e}"),
                            false,
                            false,
                        )
                    } else if ube_stream
                        .seek(SeekFrom::Start(ube_total_size - 24))
                        .is_err()
                    {
                        (
                            false,
                            "Cannot seek to trailer".into(),
                            header.is_encrypted(),
                            header.is_stealth(),
                        )
                    } else {
                        let mut trailer_bytes = [0u8; 24];
                        let expected_trailer_magic = match (header.is_stealth(), password) {
                            (true, Some(pwd)) => {
                                let magics = derive_stealth_magics(pwd, profile.domain())?;
                                Some(magics.1)
                            }
                            // Official dialect: `None` keeps the legacy magics
                            // acceptable. Private dialect: only its own magic.
                            _ => profile.locator_magic().copied(),
                        };

                        if ube_stream.read_exact(&mut trailer_bytes).is_err() {
                            (
                                false,
                                "Cannot read trailer".into(),
                                header.is_encrypted(),
                                header.is_stealth(),
                            )
                        } else if let Ok(trailer) =
                            EnvelopeTrailer::unpack(&trailer_bytes, expected_trailer_magic.as_ref())
                        {
                            if trailer.ube_offset != ube_offset
                                || trailer.ube_total_size != ube_total_size
                            {
                                (
                                    false,
                                    "Envelope trailer boundary parameters mismatch".into(),
                                    header.is_encrypted(),
                                    header.is_stealth(),
                                )
                            } else {
                                (
                                    true,
                                    format!(
                                        "Envelope valid at offset {ube_offset}, size {ube_total_size}B (CRC32 OK)"
                                    ),
                                    header.is_encrypted(),
                                    header.is_stealth(),
                                )
                            }
                        } else {
                            (
                                false,
                                "Envelope trailer unpacking failed".into(),
                                header.is_encrypted(),
                                header.is_stealth(),
                            )
                        }
                    }
                } else {
                    (
                        false,
                        "Envelope header unpacking failed".into(),
                        false,
                        false,
                    )
                }
            }
        }
    };

    // Level 3: Crypto & payload SHA-256
    let (l3_ok, l3_msg) = if !is_encrypted || password.is_some() {
        match read_carrier_with_profile(carrier_path, None, password, false, profile) {
            Ok(res) => (
                true,
                format!(
                    "Decryption and SHA-256 verified successfully (payload {} bytes)",
                    res.raw_size
                ),
            ),
            Err(e) => (false, e.to_string()),
        }
    } else {
        (
            false,
            "Password required for cryptographic verification".into(),
        )
    };

    Ok(VerifyResult {
        carrier: carrier_path.display().to_string(),
        format: adapter.format_name().into(),
        level1_host: LevelStatus {
            ok: l1_ok,
            detail: l1_msg,
        },
        level2_envelope: LevelStatus {
            ok: l2_ok,
            detail: l2_msg,
        },
        level3_crypto: LevelStatus {
            ok: l3_ok,
            detail: l3_msg,
        },
    })
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
}
