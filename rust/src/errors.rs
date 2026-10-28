//! Error types returned by every strhide public function.
//!
//! All fallible entry points in [`crate::structure`] and the primitives in
//! [`crate::crypto`] / [`crate::structure::envelope`] return
//! [`Result<T, StrHideError>`](std::result::Result). The variants map
//! one-to-one to failure classes so callers can branch on them without
//! string-matching messages.

use serde::{Deserialize, Serialize};
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
    /// table cannot encode the required modifications" by matching on
    /// [`TrellisCause`] instead of on message text (which i18n rendering or
    /// rewording would silently break).
    #[error("Embedding infeasible: {detail}")]
    TrellisInfeasible {
        /// Which shape of infeasibility the solver hit.
        cause: TrellisCause,
        /// Human-readable context (indices, counts); free-form.
        detail: String,
    },

    /// Pre-write safety rejection: the carrier is signed (PE Authenticode,
    /// PDF ByteRange, JAR signature), read-only, an unsupported APK, or the
    /// target directory is not writable.
    #[error("Rejection error: {0}")]
    Rejection(String),

    /// Target destination file already exists and overwrite was not permitted.
    #[error(
        "Refusing to overwrite existing file '{0}'. Choose another -o path or pass --overwrite."
    )]
    AlreadyExists(std::path::PathBuf),

    /// Target file is in use by another process (e.g. preview or media player lock).
    #[error("Target file '{0}' is in use by another process")]
    TargetBusy(std::path::PathBuf),

    /// The payload is larger than the recommended capacity of the requested
    /// safety tier while `SafetyEnforcement::Enforced` is in force.
    ///
    /// A separate variant rather than [`General`](Self::General) because the
    /// content domain retries some embeds through a fallback engine (the HEIF
    /// thumbnail bridge): a policy refusal is final, and must not be replaced
    /// by the fallback's unrelated "no bridgeable item" error.
    #[error(
        "Safety threshold exceeded: payload is {required_bytes} bytes, limit for tier '{tier}' is {available_bytes} bytes"
    )]
    SafetyThreshold {
        tier: crate::params::SafetyLevel,
        required_bytes: usize,
        available_bytes: usize,
    },

    /// [`crate::structure::remove_carrier`] restored a file whose size or SHA-256
    /// does not match the original recorded in the envelope header. This
    /// usually means a second envelope was layered on top and must be removed
    /// first, most-recently-written first.
    #[error("100% restore verification failed: restored size {restored_size} (expected {expected_size}) or SHA256 mismatch{}", if *.residual_envelope { "\nDiagnosis: the restored file still contains another hidden envelope. Remove envelopes in reverse order of injection (most recently written first)." } else { "" })]
    RestoreMismatch {
        restored_size: u64,
        expected_size: u64,
        restored_sha256: String,
        expected_sha256: String,
        residual_envelope: bool,
    },

    /// The carrier bytes do not match any supported format magic
    /// (PNG / JPEG / MP4 / ZIP / PDF / PE).
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    /// The carrier looks like a valid format but no envelope (standard or
    /// stealth-with-the-supplied-password) was located. The message may carry
    /// a structural hint when [`crate::structure::adapters::HostAdapter::suspicious_structures`]
    /// detects an envelope-shaped container.
    #[error("{0}")]
    NoHiddenData(String),

    /// The payload declares a format version, a critical extension, or a
    /// cipher suite this build does not implement. Distinct from
    /// [`CorruptedData`](Self::CorruptedData) on purpose: the bytes are
    /// well-formed, the binary is simply too old (or too private) to read them.
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(String),

    /// The caller asked to stop through a
    /// [`CancelToken`](crate::core::control::CancelToken), and the engine
    /// stopped at its next checkpoint.
    ///
    /// Not a failure: no output was committed and the carrier is untouched.
    /// A dedicated variant (rather than [`General`](Self::General)) so a GUI can
    /// tell "the user pressed cancel" from "this went wrong" without matching
    /// on message text.
    #[error("Operation cancelled")]
    Cancelled,

    /// Any other user-facing failure: internal invariants, invalid arguments,
    /// unsupported strategy for the detected format, output path problems.
    #[error("{0}")]
    General(String),
}

/// Which shape of STC infeasibility the solver hit.
///
/// The JPEG engine maps `DeadElement`/`DeadGroup` to its "over-optimised
/// Huffman table" diagnosis: a wet-point pattern where every candidate in a
/// parity group is locked by the carrier's table. `ExhaustedSlots` is the
/// HEVC engine's multi-round wrapper for "the exclusion loop ran out of
/// usable slots" and never occurs on the JPEG path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TrellisCause {
    /// One element whose both directions are illegal (the `u = 1` kernel
    /// path).
    DeadElement,
    /// A whole group with no legal element in any position (the `u > 1`
    /// kernel path).
    DeadGroup,
    /// The embed's exclude-and-retry loop ran out of usable slots.
    ExhaustedSlots,
}

#[cfg(feature = "structure-base")]
impl From<serde_json::Error> for StrHideError {
    fn from(err: serde_json::Error) -> Self {
        StrHideError::CorruptedData(format!("JSON serialization error: {err}"))
    }
}

impl StrHideError {
    /// Machine-readable error kind for frontends.
    pub fn kind(&self) -> ErrorKind {
        match self {
            StrHideError::Io(_) => ErrorKind::Io,
            StrHideError::CorruptedData(_) => ErrorKind::CorruptedData,
            StrHideError::Password(_) => ErrorKind::Password,
            StrHideError::PasswordWithHint { .. } => ErrorKind::PasswordWithHint,
            StrHideError::TrellisInfeasible { .. } => ErrorKind::TrellisInfeasible,
            StrHideError::Rejection(_) => ErrorKind::Rejection,
            StrHideError::AlreadyExists(_) => ErrorKind::AlreadyExists,
            StrHideError::TargetBusy(_) => ErrorKind::TargetBusy,
            StrHideError::SafetyThreshold { .. } => ErrorKind::SafetyThreshold,
            StrHideError::RestoreMismatch { .. } => ErrorKind::RestoreMismatch,
            StrHideError::UnsupportedFormat(_) => ErrorKind::UnsupportedFormat,
            StrHideError::NoHiddenData(_) => ErrorKind::NoHiddenData,
            StrHideError::UnsupportedVersion(_) => ErrorKind::UnsupportedVersion,
            StrHideError::Cancelled => ErrorKind::Cancelled,
            StrHideError::General(_) => ErrorKind::General,
        }
    }

    /// Error category (used to translate category prefixes during CLI rendering).
    /// `NoHiddenData` and `General` do not carry a prefix and return `None`.
    pub fn category(&self) -> Option<crate::core::i18n::Msg> {
        match self {
            StrHideError::Io(_) => Some(crate::core::i18n::Msg::ErrIo),
            StrHideError::CorruptedData(_) => Some(crate::core::i18n::Msg::ErrCorrupted),
            StrHideError::Password(_) | StrHideError::PasswordWithHint { .. } => {
                Some(crate::core::i18n::Msg::ErrPassword)
            }
            StrHideError::Rejection(_) | StrHideError::SafetyThreshold { .. } => {
                Some(crate::core::i18n::Msg::ErrRejection)
            }
            StrHideError::AlreadyExists(_) => Some(crate::core::i18n::Msg::ErrRejection),
            StrHideError::TargetBusy(_) => Some(crate::core::i18n::Msg::ErrIo),
            StrHideError::RestoreMismatch { .. } => {
                Some(crate::core::i18n::Msg::ErrRestoreMismatch)
            }
            StrHideError::UnsupportedFormat(_) | StrHideError::UnsupportedVersion(_) => {
                Some(crate::core::i18n::Msg::ErrUnsupported)
            }
            StrHideError::TrellisInfeasible { .. } => Some(crate::core::i18n::Msg::ErrUnsupported),
            // A cancellation is the caller's own decision, not an error class:
            // there is nothing to translate and nothing went wrong.
            StrHideError::Cancelled => None,
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
            | StrHideError::UnsupportedFormat(s)
            | StrHideError::UnsupportedVersion(s)
            | StrHideError::NoHiddenData(s)
            | StrHideError::General(s) => s.clone(),
            StrHideError::AlreadyExists(p) => {
                format!(
                    "Refusing to overwrite existing file '{}'. Choose another -o path or pass --overwrite.",
                    p.display()
                )
            }
            StrHideError::TargetBusy(p) => {
                format!("Target file '{}' is in use by another process", p.display())
            }
            StrHideError::SafetyThreshold {
                tier,
                required_bytes,
                available_bytes,
            } => {
                format!(
                    "Payload ({required_bytes} bytes) exceeds recommended safety threshold ({available_bytes} bytes, tier: '{tier}')."
                )
            }
            StrHideError::RestoreMismatch {
                restored_size,
                expected_size,
                restored_sha256,
                expected_sha256,
                residual_envelope,
            } => {
                let diag = if *residual_envelope {
                    "\nDiagnosis: the restored file still contains another hidden envelope. Remove envelopes in reverse order of injection (most recently written first)."
                } else {
                    ""
                };
                format!(
                    "Restored size: {restored_size} (expected {expected_size})\nRestored SHA256: {restored_sha256}\nExpected SHA256: {expected_sha256}{diag}"
                )
            }
            StrHideError::TrellisInfeasible { detail, .. } => detail.clone(),
            StrHideError::Cancelled => "Operation cancelled".into(),
            StrHideError::PasswordWithHint { message, hint } => match hint {
                Some(h) => format!("{message}. Hint: '{h}'."),
                None => message.clone(),
            },
        }
    }

    /// The envelope's password hint, when the error carries one.
    pub fn hint(&self) -> Option<&str> {
        match self {
            StrHideError::PasswordWithHint { hint, .. } => hint.as_deref(),
            _ => None,
        }
    }

    /// Structured, language-neutral view of this error for a front end using global lang.
    pub fn detail_i18n(&self) -> ErrorDetail {
        self.detail_i18n_with_ctx(crate::core::i18n::RenderCtx::current())
    }

    /// Structured, language-neutral view of this error for a front end using explicit RenderCtx.
    pub fn detail_i18n_with_ctx(&self, ctx: crate::core::i18n::RenderCtx) -> ErrorDetail {
        let cat = self.category();
        ErrorDetail {
            kind: self.kind(),
            category: cat,
            category_label: cat.map(|c| c.text(ctx.lang)),
            detail: self.detail(),
            hint: self.hint().map(str::to_string),
        }
    }
}

/// Machine-readable stable error kinds for GUI and IPC dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Io,
    CorruptedData,
    Password,
    PasswordWithHint,
    TrellisInfeasible,
    Rejection,
    AlreadyExists,
    TargetBusy,
    SafetyThreshold,
    RestoreMismatch,
    UnsupportedFormat,
    NoHiddenData,
    UnsupportedVersion,
    Cancelled,
    General,
}

/// The parts of an [`StrHideError`], separated so a non-English front end can
/// render it instead of scraping [`Display`](std::fmt::Display).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorDetail {
    /// Machine-readable stable classification.
    pub kind: ErrorKind,
    /// Localizable category enum key (serialized as its stable ID e.g. "ErrPassword").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<crate::core::i18n::Msg>,
    /// Pre-rendered category label in the active language.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category_label: Option<&'static str>,
    /// The detail text, in English. Engine-generated, so it is not translated;
    /// the category label around it is.
    pub detail: String,
    /// The envelope password hint, when the error carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

impl ErrorDetail {
    /// Render the same single line the CLI prints, in `lang`.
    pub fn render(&self, lang: crate::core::i18n::Lang) -> String {
        match self.category {
            Some(cat) => crate::core::i18n::format_msg(
                cat_line(lang),
                &[("prefix", &cat.text(lang)), ("detail", &self.detail)],
            ),
            None => crate::core::i18n::format_msg(plain_line(lang), &[("detail", &self.detail)]),
        }
    }

    /// The translated category label, for a front end that owns its own layout.
    pub fn category_text(&self, lang: crate::core::i18n::Lang) -> Option<&'static str> {
        self.category.map(|cat| cat.text(lang))
    }
}

/// The `"[ERROR] {prefix}: {detail}"` template in `lang`.
fn cat_line(lang: crate::core::i18n::Lang) -> &'static str {
    crate::core::i18n::Msg::ErrorLine.text(lang)
}

/// The `"[ERROR] {detail}"` template in `lang`.
fn plain_line(lang: crate::core::i18n::Lang) -> &'static str {
    crate::core::i18n::Msg::ErrorLinePlain.text(lang)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_error_detail_serialization_and_kind() {
        let err = StrHideError::Password("invalid password".into());
        let detail = err.detail_i18n();
        assert_eq!(detail.kind, ErrorKind::Password);
        assert_eq!(detail.category, Some(crate::core::i18n::Msg::ErrPassword));

        let json = serde_json::to_string(&detail).expect("serialize ErrorDetail");
        assert!(json.contains("\"kind\":\"password\""), "{json}");
        assert!(json.contains("\"category\":\"ErrPassword\""), "{json}");
        assert!(json.contains("\"detail\":\"invalid password\""), "{json}");
    }

    #[test]
    fn test_structured_error_variants() {
        let exists = StrHideError::AlreadyExists(PathBuf::from("secret.png"));
        assert_eq!(exists.kind(), ErrorKind::AlreadyExists);
        assert!(exists.detail().contains("secret.png"));

        let busy = StrHideError::TargetBusy(PathBuf::from("video.mp4"));
        assert_eq!(busy.kind(), ErrorKind::TargetBusy);
        assert!(busy.detail().contains("video.mp4"));

        let safety = StrHideError::SafetyThreshold {
            tier: crate::params::SafetyLevel::High,
            required_bytes: 1000,
            available_bytes: 500,
        };
        assert_eq!(safety.kind(), ErrorKind::SafetyThreshold);
        assert!(safety.detail().contains("1000"));
        assert!(safety.detail().contains("500"));
        assert!(safety.detail().contains("high"));

        let mismatch = StrHideError::RestoreMismatch {
            restored_size: 100,
            expected_size: 200,
            restored_sha256: "aaa".into(),
            expected_sha256: "bbb".into(),
            residual_envelope: true,
        };
        assert_eq!(mismatch.kind(), ErrorKind::RestoreMismatch);
        assert!(mismatch.detail().contains("another hidden envelope"));
    }

    #[test]
    fn test_detail_i18n_with_ctx() {
        let err = StrHideError::Password("wrong".into());
        let zh_ctx = crate::core::i18n::RenderCtx::new(crate::core::i18n::Lang::Zh);
        let detail_zh = err.detail_i18n_with_ctx(zh_ctx);
        assert_eq!(detail_zh.category_label, Some("密码错误或缺失"));

        let en_ctx = crate::core::i18n::RenderCtx::new(crate::core::i18n::Lang::En);
        let detail_en = err.detail_i18n_with_ctx(en_ctx);
        assert_eq!(detail_en.category_label, Some("Password error"));
    }
}
