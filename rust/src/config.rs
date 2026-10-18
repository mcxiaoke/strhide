//! TOML configuration file support.
//!
//! Lookup order: explicit `--config <path>`, then `./strhide.toml`, then
//! `<home>/.strhide/config.toml` (`USERPROFILE` on Windows, `HOME` elsewhere).
//! Every key is optional; values act as defaults and never override explicit
//! CLI arguments or the `STRHIDE_PASSWORD` / `STRHIDE_TEXT` environment
//! variables.
//!
//! Recognized keys (all optional):
//!
//! ```toml
//! strategy      = "auto"        # write: auto | ask | <adapter strategy name>
//! stealth       = false         # write: stealth mode default
//! encrypt       = false         # write: encryption default
//! password      = "..."         # all: password default (plaintext on disk!)
//! password_file = "..."         # all: password file default
//! hint          = "..."         # write: password hint default
//! preserve_time = true          # write: timestamp preservation default
//! backup        = true          # write/remove: .bak backup default
//! unescape      = false         # write: escape-sequence decoding default
//! ```

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::errors::StrHideError;

/// Recognized top-level config keys; any other key triggers a warning so a
/// typo (e.g. `pasword`) cannot silently disable a setting.
const KNOWN_KEYS: &[&str] = &[
    "strategy",
    "stealth",
    "encrypt",
    "password",
    "password_file",
    "hint",
    "preserve_time",
    "backup",
    "unescape",
];

/// Parsed configuration file. Every field is optional; `None` means "not
/// configured, fall back to the built-in CLI defaults".
#[derive(Deserialize, Debug, Default, Clone)]
pub struct FileConfig {
    pub strategy: Option<String>,
    pub stealth: Option<bool>,
    pub encrypt: Option<bool>,
    pub password: Option<String>,
    pub password_file: Option<PathBuf>,
    pub hint: Option<String>,
    pub preserve_time: Option<bool>,
    pub backup: Option<bool>,
    pub unescape: Option<bool>,
}

/// Candidate paths in lookup order, excluding an explicit `--config` path.
fn default_candidates() -> Vec<PathBuf> {
    let mut out = vec![PathBuf::from("strhide.toml")];
    if let Some(home) = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
    {
        out.push(home.join(".strhide").join("config.toml"));
    }
    out
}

fn parse_config(text: &str, origin: &Path) -> Result<FileConfig, StrHideError> {
    let table: toml::Table = toml::from_str(text).map_err(|e| {
        StrHideError::General(format!(
            "Invalid TOML in config file '{}': {e}",
            origin.display()
        ))
    })?;
    for key in table.keys() {
        if !KNOWN_KEYS.contains(&key.as_str()) {
            eprintln!(
                "[WARNING] Unknown key '{key}' in config file '{}' (ignored).",
                origin.display()
            );
        }
    }
    toml::from_str(text).map_err(|e| {
        StrHideError::General(format!("Invalid config file '{}': {e}", origin.display()))
    })
}

/// Load the effective configuration. When `explicit` is given (the global
/// `--config` flag), a missing or unreadable file is a hard error; implicit
/// candidates that do not exist are silently skipped.
pub fn load(explicit: Option<&Path>) -> Result<FileConfig, StrHideError> {
    if let Some(p) = explicit {
        let text = std::fs::read_to_string(p).map_err(|e| {
            StrHideError::General(format!("Failed to read config file '{}': {e}", p.display()))
        })?;
        return parse_config(&text, p);
    }
    for cand in default_candidates() {
        match std::fs::read_to_string(&cand) {
            Ok(text) => return parse_config(&text, &cand),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(StrHideError::General(format!(
                    "Failed to read config file '{}': {e}",
                    cand.display()
                )));
            }
        }
    }
    Ok(FileConfig::default())
}
