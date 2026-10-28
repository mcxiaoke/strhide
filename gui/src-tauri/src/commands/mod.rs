pub mod batch;
pub mod diag;
pub mod stego;
pub mod structure;

use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PayloadInputDto {
    /// Text typed directly into the UI (UTF-8)
    Text { content: String },
    /// Selected local payload file (streamed/read on demand by Rust)
    File { path: PathBuf },
}
