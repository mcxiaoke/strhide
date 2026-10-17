//! Error types for strhide.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StrHideError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Corrupted data: {0}")]
    CorruptedData(String),

    #[error("Password error: {0}")]
    Password(String),

    #[error("Rejection error: {0}")]
    Rejection(String),

    #[error("100% restore verification failed: {0}")]
    RestoreMismatch(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("{0}")]
    General(String),
}

impl From<serde_json::Error> for StrHideError {
    fn from(err: serde_json::Error) -> Self {
        StrHideError::CorruptedData(format!("JSON serialization error: {err}"))
    }
}
