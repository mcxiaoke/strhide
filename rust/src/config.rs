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
//! stego_secret  = "..."         # embed/extract: private default secret
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
    "stego_secret",
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
    /// Private default secret for content-adaptive steganography. Replaces the
    /// public built-in constant when no user password is given. Read/write must
    /// agree, so this belongs with the password, not with the tuning knobs.
    pub stego_secret: Option<String>,
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

fn parse_config(
    text: &str,
    origin: &Path,
    is_cwd_implicit: bool,
) -> Result<FileConfig, StrHideError> {
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
    let cfg: FileConfig = toml::from_str(text).map_err(|e| {
        StrHideError::General(format!("Invalid config file '{}': {e}", origin.display()))
    })?;

    if is_cwd_implicit
        && (cfg.password.is_some() || cfg.password_file.is_some() || cfg.stego_secret.is_some())
    {
        eprintln!(
            "[WARNING] Loaded sensitive password/secret keys from local CWD config '{}'. Ensure this file is trusted.",
            origin.display()
        );
    }

    Ok(cfg)
}

/// Load the effective configuration. When `explicit` is given (the global
/// `--config` flag), a missing or unreadable file is a hard error; implicit
/// candidates that do not exist are silently skipped.
pub fn load(explicit: Option<&Path>) -> Result<FileConfig, StrHideError> {
    if let Some(p) = explicit {
        let text = std::fs::read_to_string(p).map_err(|e| {
            StrHideError::General(format!("Failed to read config file '{}': {e}", p.display()))
        })?;
        return parse_config(&text, p, false);
    }
    for (i, cand) in default_candidates().iter().enumerate() {
        match std::fs::read_to_string(cand) {
            Ok(text) => {
                let is_cwd_implicit = i == 0;
                return parse_config(&text, cand, is_cwd_implicit);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwd_implicit_loads_password_and_secret() {
        let toml_str = r#"
            strategy = "pe_slack"
            password = "test_injected_pwd"
            stego_secret = "test_secret"
            backup = true
        "#;
        let cfg = parse_config(toml_str, Path::new("strhide.toml"), true).unwrap();
        assert_eq!(cfg.strategy.as_deref(), Some("pe_slack"));
        assert_eq!(cfg.backup, Some(true));
        assert_eq!(cfg.password.as_deref(), Some("test_injected_pwd"));
        assert_eq!(cfg.stego_secret.as_deref(), Some("test_secret"));
    }

    #[test]
    fn explicit_config_keeps_password_and_secret() {
        let toml_str = r#"
            password = "valid_user_pwd"
            stego_secret = "valid_secret"
        "#;
        let cfg = parse_config(toml_str, Path::new("explicit.toml"), false).unwrap();
        assert_eq!(cfg.password.as_deref(), Some("valid_user_pwd"));
        assert_eq!(cfg.stego_secret.as_deref(), Some("valid_secret"));
    }
}
