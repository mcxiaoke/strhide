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

    /// A password was required but missing, and the envelope carries a hint
    /// that may help the user supply one.
    ///
    /// The hint is a **field**, not part of the message: the CLI prints it and
    /// then prompts. Extracting it from the rendered text (`split_once("Hint: '")`)
    /// meant any wording change in the engine silently broke the feature.
    #[error("Password error: {message}")]
    PasswordWithHint {
        /// What went wrong, without the hint appended.
        message: String,
        /// Free-form hint text stored in the envelope, if any.
        hint: Option<String>,
    },

    /// The STC trellis has no feasible path: some group contains only elements
    /// whose both directions are illegal (infinite cost). Not a retryable
    /// condition — re-seeding would leave the extractor unable to tell which
    /// round was used.
    ///
    /// Structured so the JPEG engine can recognise "this carrier's Huffman
    /// table cannot encode the required modifications" without matching on
    /// message text.
    #[error("Embedding infeasible: {0}")]
    TrellisInfeasible(String),

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

    /// The payload declares a format version, a critical extension, or a
    /// cipher suite this build does not implement. Distinct from
    /// [`CorruptedData`](Self::CorruptedData) on purpose: the bytes are
    /// well-formed, the binary is simply too old (or too private) to read them.
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(String),

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

impl StrHideError {
    /// Error category (used to translate category prefixes during CLI rendering).
    /// `NoHiddenData` and `General` do not carry a prefix and return `None`.
    pub fn category(&self) -> Option<crate::i18n::Msg> {
        match self {
            StrHideError::Io(_) => Some(crate::i18n::Msg::ErrIo),
            StrHideError::CorruptedData(_) => Some(crate::i18n::Msg::ErrCorrupted),
            StrHideError::Password(_) | StrHideError::PasswordWithHint { .. } => {
                Some(crate::i18n::Msg::ErrPassword)
            }
            StrHideError::Rejection(_) => Some(crate::i18n::Msg::ErrRejection),
            StrHideError::RestoreMismatch(_) => Some(crate::i18n::Msg::ErrRestoreMismatch),
            StrHideError::UnsupportedFormat(_) | StrHideError::UnsupportedVersion(_) => {
                Some(crate::i18n::Msg::ErrUnsupported)
            }
            StrHideError::TrellisInfeasible(_) => Some(crate::i18n::Msg::ErrUnsupported),
            StrHideError::NoHiddenData(_) | StrHideError::General(_) => None,
        }
    }

    /// Extracted detail text without the English category prefix.
    pub fn detail(&self) -> String {
        match self {
            StrHideError::Io(e) => e.to_string(),
            StrHideError::CorruptedData(s)
            | StrHideError::Password(s)
            | StrHideError::Rejection(s)
            | StrHideError::RestoreMismatch(s)
            | StrHideError::UnsupportedFormat(s)
            | StrHideError::UnsupportedVersion(s)
            | StrHideError::NoHiddenData(s)
            | StrHideError::General(s)
            | StrHideError::TrellisInfeasible(s) => s.clone(),
            StrHideError::PasswordWithHint { message, hint } => match hint {
                Some(h) => format!("{message}. Hint: '{h}'."),
                None => message.clone(),
            },
        }
    }

    /// The envelope's password hint, when the error carries one.
    ///
    /// A field rather than text to parse: the hint is arbitrary user input and
    /// may itself contain quotes, so any string-splitting scheme was fragile by
    /// construction.
    pub fn hint(&self) -> Option<&str> {
        match self {
            StrHideError::PasswordWithHint { hint, .. } => hint.as_deref(),
            _ => None,
        }
    }
}
