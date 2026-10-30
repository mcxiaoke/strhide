//! TOML configuration file support.
//!
//! Lookup order: explicit `--config <path>`, then `<exe_dir>/strhide.toml`
//! (or `<exe_dir>/config.toml`), then user configuration directory
//! (`~/.config/strhide/config.toml`, `~/.strhide/config.toml`, or `%APPDATA%\strhide\config.toml`),
//! then system configuration directory (`/etc/strhide/config.toml`,
//! `%ProgramData%\strhide\config.toml`). Current working directory (CWD) is intentionally
//! NOT searched to avoid security risks from untrusted directories.
//!
//! Every key is optional; values act as defaults and never override explicit
//! CLI arguments or the `STRHIDE_PASSWORD` / `STRHIDE_TEXT` environment
//! variables. Hardcoded passwords and password files are NOT supported in
//! configuration files.
//!
//! Recognized keys (all optional):
//!
//! ```toml
//! strategy      = "auto"        # write: auto | ask | <adapter strategy name>
//! stealth       = false         # write: stealth mode default
//! encrypt       = false         # write: encryption default
//! hint          = "..."         # write: password hint default
//! preserve_time = true          # write: timestamp preservation default
//! backup        = true          # write/remove: .bak backup default
//! unescape      = false         # write: escape-sequence decoding default
//! lang          = "zh"         # all: interface language (en|zh), default: auto-detect
//!
//! [stego]
//! safety         = "high"      # embed/capacity: paranoid | high | balanced
//! enforce_safety = false       # embed/capacity: refuse instead of warn above the tier
//! algorithm      = "auto"      # embed/capacity: auto | hill | suniw
//! ```
//!
//! An explicit CLI flag always wins over the configured default.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::errors::StrHideError;

/// Recognized top-level config keys; any other key triggers a warning so a
/// typo (e.g. `pasword`) cannot silently disable a setting.
const KNOWN_KEYS: &[&str] = &[
    "strategy",
    "stealth",
    "encrypt",
    "hint",
    "preserve_time",
    "backup",
    "unescape",
    "lang",
    "stego",
];

/// Recognized keys inside `[stego]`, checked the same way as [`KNOWN_KEYS`].
const STEGO_KEYS: &[&str] = &["safety", "enforce_safety", "algorithm"];

/// Parsed configuration file. Every field is optional; `None` means "not
/// configured, fall back to the built-in CLI defaults".
#[derive(Deserialize, Debug, Default, Clone)]
pub struct FileConfig {
    pub strategy: Option<String>,
    pub stealth: Option<bool>,
    pub encrypt: Option<bool>,
    pub hint: Option<String>,
    pub preserve_time: Option<bool>,
    pub backup: Option<bool>,
    pub unescape: Option<bool>,
    /// Interface language ("en" | "zh"); unset or invalid falls back to environment/system/English.
    pub lang: Option<String>,
    /// `[stego]` section: defaults for `embed` / `capacity`.
    pub stego: Option<StegoConfig>,
    /// Warnings collected during parsing (e.g. unknown keys).
    #[serde(skip)]
    pub warnings: Vec<String>,
    /// Absolute path of the loaded configuration file, if one was found and loaded.
    #[serde(skip)]
    pub loaded_from: Option<PathBuf>,
}

/// `[stego]` section: content-domain defaults applied when the matching CLI
/// flag is absent.
///
/// These mirror exactly three flags — `--safety`, `--enforce-safety`,
/// `--algorithm` — because those are the knobs a deployment wants to pin once
/// rather than repeat on every command line. Per-format tuning parameters stay
/// flag-only: they are experimentation knobs, not policy.
#[derive(Deserialize, Debug, Default, Clone)]
pub struct StegoConfig {
    /// Safety tier name (`paranoid` | `high` | `balanced`).
    pub safety: Option<String>,
    /// Refuse (instead of warn) when the payload exceeds the tier's capacity.
    pub enforce_safety: Option<bool>,
    /// Cost model / algorithm name (`auto` | `hill` | `suniw` | `uerd` | ...).
    pub algorithm: Option<String>,
}

/// Candidate paths in lookup order, excluding an explicit `--config` path.
/// Only searches:
/// 1. Exe directory (`strhide.toml`, `config.toml`)
/// 2. User config directory (`%APPDATA%/strhide/config.toml`, `~/.config/strhide/config.toml`, `~/.strhide/config.toml`)
/// 3. System config directory (`%ProgramData%/strhide/config.toml`, `/etc/strhide/config.toml`, `/etc/strhide.toml`)
///
/// CWD is explicitly excluded.
fn default_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();

    // 1. Executable directory: <exe_dir>/strhide.toml, <exe_dir>/config.toml
    if let Ok(exe) = std::env::current_exe()
        && let Some(exe_dir) = exe.parent()
    {
        out.push(exe_dir.join("strhide.toml"));
        out.push(exe_dir.join("config.toml"));
    }

    // 2. User configuration directory
    if let Some(appdata) = std::env::var_os("APPDATA").map(PathBuf::from) {
        out.push(appdata.join("strhide").join("config.toml"));
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
        out.push(xdg.join("strhide").join("config.toml"));
    }
    if let Some(home) = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
    {
        out.push(home.join(".config").join("strhide").join("config.toml"));
        out.push(home.join(".strhide").join("config.toml"));
    }

    // 3. System configuration directory
    #[cfg(windows)]
    {
        let program_data = std::env::var_os("ProgramData")
            .or_else(|| std::env::var_os("ALLUSERSPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        out.push(program_data.join("strhide").join("config.toml"));
    }
    #[cfg(not(windows))]
    {
        out.push(PathBuf::from("/etc/strhide/config.toml"));
        out.push(PathBuf::from("/etc/strhide.toml"));
        #[cfg(target_os = "macos")]
        {
            out.push(PathBuf::from(
                "/Library/Application Support/strhide/config.toml",
            ));
        }
    }

    let mut deduped = Vec::new();
    for p in out {
        if !deduped.contains(&p) {
            deduped.push(p);
        }
    }
    deduped
}

fn to_absolute_path(p: &Path) -> PathBuf {
    if let Ok(canon) = std::fs::canonicalize(p) {
        let s = canon.to_string_lossy();
        if let Some(stripped) = s.strip_prefix(r"\\?\") {
            PathBuf::from(stripped)
        } else {
            canon
        }
    } else if p.is_absolute() {
        p.to_path_buf()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(p)
    } else {
        p.to_path_buf()
    }
}

fn parse_config(text: &str, origin: &Path) -> Result<FileConfig, StrHideError> {
    let table: toml::Table = toml::from_str(text).map_err(|e| {
        StrHideError::General(format!(
            "Invalid TOML in config file '{}': {e}",
            origin.display()
        ))
    })?;

    let mut warnings = Vec::new();

    for key in table.keys() {
        if !KNOWN_KEYS.contains(&key.as_str()) {
            warnings.push(
                crate::t!(
                    crate::core::i18n::Msg::WarnConfigUnknownKey,
                    key = key,
                    path = origin.display()
                )
                .to_string(),
            );
        }
    }
    // The sections have their own key sets and were not checked at all, so
    // `[stego] algoritm = "hill"` was silently ignored: the default stayed in
    // force and nothing said why. Warn for those too (still warning-only —
    // refusing would break every config that carries a comment-shaped extra
    // key) (review R2 P1-8).
    for (section, known) in [("stego", STEGO_KEYS)] {
        let Some(sub) = table.get(section).and_then(|v| v.as_table()) else {
            continue;
        };
        for key in sub.keys() {
            if !known.contains(&key.as_str()) {
                warnings.push(
                    crate::t!(
                        crate::core::i18n::Msg::WarnConfigUnknownKey,
                        key = format!("[{section}].{key}"),
                        path = origin.display()
                    )
                    .to_string(),
                );
            }
        }
    }
    // Deserialise from the table that was already validated, instead of
    // parsing the same text a second time: two independent parses can disagree
    // (and used to report two different messages for one syntax error).
    let mut cfg: FileConfig = table.try_into().map_err(|e| {
        StrHideError::General(format!("Invalid config file '{}': {e}", origin.display()))
    })?;

    cfg.warnings = warnings;
    cfg.loaded_from = Some(to_absolute_path(origin));
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
        return parse_config(&text, p);
    }
    for cand in default_candidates() {
        match std::fs::read_to_string(&cand) {
            Ok(text) => {
                return parse_config(&text, &cand);
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
    fn password_keys_trigger_unknown_warning() {
        let toml_str = r#"
            strategy = "pe_slack"
            password = "test_pwd"
            password_file = "test.key"
            backup = true
        "#;
        let cfg = parse_config(toml_str, Path::new("test.toml")).unwrap();
        assert_eq!(cfg.strategy.as_deref(), Some("pe_slack"));
        assert_eq!(cfg.backup, Some(true));
        assert!(cfg.warnings.iter().any(|w| w.contains("password")));
        assert!(cfg.warnings.iter().any(|w| w.contains("password_file")));
    }

    #[test]
    fn stego_section_is_parsed() {
        let toml_str = r#"
            [stego]
            safety = "paranoid"
            enforce_safety = true
            algorithm = "hill"
        "#;
        let cfg = parse_config(toml_str, Path::new("explicit.toml")).unwrap();
        let stego = cfg.stego.expect("[stego] section must be captured");
        assert_eq!(stego.safety.as_deref(), Some("paranoid"));
        assert_eq!(stego.enforce_safety, Some(true));
        assert_eq!(stego.algorithm.as_deref(), Some("hill"));
    }

    #[test]
    fn absent_stego_section_leaves_defaults_alone() {
        let cfg = parse_config("backup = true", Path::new("explicit.toml")).unwrap();
        assert!(cfg.stego.is_none());
        assert!(cfg.loaded_from.is_some());
        assert!(cfg.loaded_from.unwrap().is_absolute());
    }

    #[test]
    fn removed_stego_credential_keys_are_ignored_as_unknown() {
        // `stego_secret` / `stego_domain` were removed from the CLI surface:
        // a leftover key in an old config must be reported as unknown (stderr
        // warning) and ignored, not silently honoured.
        let toml_str = r#"
            stego_secret = "leftover"
            stego_domain = "leftover"
        "#;
        let cfg = parse_config(toml_str, Path::new("explicit.toml")).unwrap();
        assert!(cfg.warnings.iter().any(|w| w.contains("stego_secret")));
        assert!(cfg.warnings.iter().any(|w| w.contains("stego_domain")));
    }
}
