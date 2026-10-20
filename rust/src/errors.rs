//! Error types returned by every strhide public function.
//!
//! All fallible entry points in [`crate::engine`] and the primitives in
//! [`crate::crypto`] / [`crate::envelope`] return
//! [`Result<T, StrHideError>`](std::result::Result). The variants map
//! one-to-one to failure classes so callers can branch on them without
//! string-matching messages.

use thiserror::Error;

/// The single error type for the whole crate.
///
/// Variants are deliberately coarse-grained: the CLI renders them verbatim,
/// while library callers can match on the discriminant and attach their own
/// context.
#[derive(Error, Debug)]
pub enum StrHideError {
    /// An underlying I/O failure (missing file, permission denied, disk full,
    /// broken pipe). Wraps [`std::io::Error`] via `From`.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The envelope bytes on the carrier do not parse, the AEAD tag fails, or
    /// a length field is inconsistent with the declared envelope size. Also
    /// raised for JSON / compact-metadata decode failures and wrong-password
    /// metadata decryption.
    #[error("Corrupted data: {0}")]
    CorruptedData(String),

    /// A password was required but missing, or the supplied password could not
    /// decrypt an encrypted envelope. Stealth envelopes written with an
    /// unknown password are indistinguishable from "no envelope" by design.
    #[error("Password error: {0}")]
    Password(String),

    /// Pre-write safety rejection: the carrier is signed (PE Authenticode,
    /// PDF ByteRange, JAR signature), read-only, an unsupported APK, or the
    /// target directory is not writable.
    #[error("Rejection error: {0}")]
    Rejection(String),

    /// [`crate::engine::remove_carrier`] restored a file whose size or SHA-256
    /// does not match the original recorded in the envelope header. This
    /// usually means a second envelope was layered on top and must be removed
    /// first, most-recently-written first.
    #[error("100% restore verification failed: {0}")]
    RestoreMismatch(String),

    /// The carrier bytes do not match any supported format magic
    /// (PNG / JPEG / MP4 / ZIP / PDF / PE).
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    /// The carrier looks like a valid format but no envelope (standard or
    /// stealth-with-the-supplied-password) was located. The message may carry
    /// a structural hint when [`crate::adapters::HostAdapter::suspicious_structures`]
    /// detects an envelope-shaped container.
    #[error("{0}")]
    NoHiddenData(String),

    /// Any other user-facing failure: internal invariants, invalid arguments,
    /// unsupported strategy for the detected format, output path problems.
    #[error("{0}")]
    General(String),
}

impl From<serde_json::Error> for StrHideError {
    fn from(err: serde_json::Error) -> Self {
        StrHideError::CorruptedData(format!("JSON serialization error: {err}"))
    }
}
