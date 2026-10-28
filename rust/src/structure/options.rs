//! Per-call options for the structure domain: write, read, and restore.
//!
//! These carry **operation** inputs (paths, credentials, overwrite decisions).
//! They are deliberately separate from [`crate::structure::params::StructureProfile`], which carries the
//! long-lived *dialect*: options differ per call, a profile must be identical
//! on both sides.
//!
//! Read and restore used to take positional `Option<&str>` + `bool` arguments,
//! which made `read(p, out, Some("pw"), true)` and
//! `restore(p, out, Some("pw"), true, false)` impossible to read at the call
//! site and easy to get wrong (stage 4, plan §3.1).

use std::path::Path;

use crate::core::control::Control;
use crate::structure::registry::StrategyId;

/// Strongly typed strategy selection: either automatic selection or an explicit named strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum StrategyChoice {
    #[default]
    Auto,
    Named(StrategyId),
}

impl StrategyChoice {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Named(id) => id.name(),
        }
    }
}

impl From<&str> for StrategyChoice {
    fn from(s: &str) -> Self {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
            Self::Auto
        } else if let Some(id) = StrategyId::from_name(trimmed) {
            Self::Named(id)
        } else {
            Self::Auto
        }
    }
}

/// Options controlling an injection. Bundled into a struct so the public API
/// stays readable and extensible as features grow (replaces a nine-parameter
/// positional signature that clippy flagged as `too_many_arguments`).
///
/// The `Default` values match the CLI defaults: `auto` strategy, timestamps and
/// in-place backup preserved, no encryption, no stealth.
#[derive(Clone, Copy, PartialEq, Eq)]
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
    /// Progress reporting and cancellation channel.
    pub control: Control<'a>,
}

impl std::fmt::Debug for WriteOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteOptions")
            .field("output_path", &self.output_path)
            .field("password", &self.password.map(|_| "<redacted>"))
            .field("password_hint", &self.password_hint)
            .field("strategy", &self.strategy)
            .field("stealth", &self.stealth)
            .field("preserve_time", &self.preserve_time)
            .field("backup", &self.backup)
            .field("control", &self.control)
            .finish()
    }
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
            control: Control::none(),
        }
    }
}

impl<'a> WriteOptions<'a> {
    /// Set strategy name.
    pub const fn with_strategy(mut self, strategy: &'a str) -> Self {
        self.strategy = strategy;
        self
    }

    /// Set strategy from [`StrategyChoice`].
    pub fn with_strategy_choice(mut self, choice: StrategyChoice) -> Self {
        self.strategy = choice.as_str();
        self
    }

    /// Set [`control`](Self::control).
    pub const fn with_control(mut self, control: Control<'a>) -> Self {
        self.control = control;
        self
    }
}

/// Options controlling an extraction.
///
/// `output_path == None` returns the payload in
/// [`ReadResult::data`](crate::structure::ReadResult::data) instead of writing
/// a file. Without [`overwrite`](Self::overwrite) an existing destination is an
/// error: silently truncating it would lose a user file.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct ReadOptions<'a> {
    /// Write the payload here; `None` keeps it in memory.
    pub output_path: Option<&'a Path>,
    /// Password for decryption (or to locate a stealth envelope).
    pub password: Option<&'a str>,
    /// Replace an existing destination instead of refusing.
    pub overwrite: bool,
    /// Progress reporting and cancellation channel.
    pub control: Control<'a>,
}

impl std::fmt::Debug for ReadOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadOptions")
            .field("output_path", &self.output_path)
            .field("password", &self.password.map(|_| "<redacted>"))
            .field("overwrite", &self.overwrite)
            .field("control", &self.control)
            .finish()
    }
}

impl<'a> ReadOptions<'a> {
    /// Default options: in-memory payload, no password, no overwrite.
    pub const fn new() -> Self {
        Self {
            output_path: None,
            password: None,
            overwrite: false,
            control: Control::none(),
        }
    }

    /// Set [`output_path`](Self::output_path).
    pub const fn with_output(mut self, path: &'a Path) -> Self {
        self.output_path = Some(path);
        self
    }

    /// Set [`password`](Self::password).
    pub const fn with_password(mut self, password: &'a str) -> Self {
        self.password = Some(password);
        self
    }

    /// Set [`overwrite`](Self::overwrite).
    pub const fn with_overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }

    /// Set [`control`](Self::control).
    pub const fn with_control(mut self, control: Control<'a>) -> Self {
        self.control = control;
        self
    }
}

/// Options controlling a restore (envelope removal).
///
/// In-place restoration is the default (`output_path == None`); an explicit
/// path never overwrites an existing file unless
/// [`overwrite`](Self::overwrite) is set.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct RestoreOptions<'a> {
    /// Write the restored carrier here; `None` restores in place.
    pub output_path: Option<&'a Path>,
    /// Password for decryption (stealth envelopes only).
    pub password: Option<&'a str>,
    /// Keep a `<carrier>.bak` copy of the stego carrier before overwriting it.
    pub backup: bool,
    /// Replace an existing *different* destination instead of refusing.
    pub overwrite: bool,
    /// Progress reporting and cancellation channel.
    pub control: Control<'a>,
}

impl std::fmt::Debug for RestoreOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoreOptions")
            .field("output_path", &self.output_path)
            .field("password", &self.password.map(|_| "<redacted>"))
            .field("backup", &self.backup)
            .field("overwrite", &self.overwrite)
            .field("control", &self.control)
            .finish()
    }
}

impl<'a> RestoreOptions<'a> {
    /// Default options: in place, no password, no backup, no overwrite.
    pub const fn new() -> Self {
        Self {
            output_path: None,
            password: None,
            backup: false,
            overwrite: false,
            control: Control::none(),
        }
    }

    /// Set [`output_path`](Self::output_path).
    pub const fn with_output(mut self, path: &'a Path) -> Self {
        self.output_path = Some(path);
        self
    }

    /// Set [`password`](Self::password).
    pub const fn with_password(mut self, password: &'a str) -> Self {
        self.password = Some(password);
        self
    }

    /// Set [`backup`](Self::backup).
    pub const fn with_backup(mut self, backup: bool) -> Self {
        self.backup = backup;
        self
    }

    /// Set [`overwrite`](Self::overwrite).
    pub const fn with_overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }

    /// Set [`control`](Self::control).
    pub const fn with_control(mut self, control: Control<'a>) -> Self {
        self.control = control;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn write_defaults_match_the_cli() {
        let opts = WriteOptions::default();
        assert_eq!(opts.strategy, "auto");
        assert!(opts.preserve_time);
        assert!(opts.backup);
        assert!(!opts.stealth);
        assert!(opts.output_path.is_none());
    }

    #[test]
    fn read_and_restore_builders_are_const_and_chainable() {
        const OUT: &str = "out.bin";
        let path = PathBuf::from(OUT);
        let read = ReadOptions::new()
            .with_output(&path)
            .with_password("pw")
            .with_overwrite(true);
        assert_eq!(read.output_path, Some(path.as_path()));
        assert_eq!(read.password, Some("pw"));
        assert!(read.overwrite);

        let restore = RestoreOptions::new().with_backup(true);
        assert!(restore.backup);
        assert!(!restore.overwrite);
        assert!(restore.output_path.is_none());
    }

    #[test]
    fn password_is_redacted_in_debug() {
        let write_opts = WriteOptions {
            password: Some("super-secret-password"),
            ..WriteOptions::default()
        };
        let debug = format!("{write_opts:?}");
        assert!(!debug.contains("super-secret-password"));
        assert!(debug.contains("<redacted>"));

        let read_opts = ReadOptions::new().with_password("super-secret-password");
        let debug_read = format!("{read_opts:?}");
        assert!(!debug_read.contains("super-secret-password"));
        assert!(debug_read.contains("<redacted>"));

        let restore_opts = RestoreOptions::new().with_password("super-secret-password");
        let debug_restore = format!("{restore_opts:?}");
        assert!(!debug_restore.contains("super-secret-password"));
        assert!(debug_restore.contains("<redacted>"));
    }

    #[test]
    fn strategy_choice_roundtrips() {
        assert_eq!(StrategyChoice::from("auto"), StrategyChoice::Auto);
        assert_eq!(StrategyChoice::from(""), StrategyChoice::Auto);
        assert_eq!(
            StrategyChoice::from("eof"),
            StrategyChoice::Named(StrategyId::from_u8(1))
        );
        assert_eq!(StrategyChoice::Auto.as_str(), "auto");
    }
}
