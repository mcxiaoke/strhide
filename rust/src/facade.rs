// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! The single entry-point facade: a [`StrHide`] instance binds one private
//! dialect ([`Profile`]) and one writer-behaviour baseline ([`LocalParams`]),
//! then exposes every verb as an ordinary method.
//!
//! This is the shape used by the mature libraries in the field (OpenStego binds
//! its config at construction and exposes plain `embedData`/`extractData`
//! methods; reqwest builds a configured `Client` and calls methods on it):
//!
//! - **configuration and actions are separate.** The long-lived dialect and
//!   tuning are set once at construction; the verbs are plain methods that
//!   forward to the existing free functions in [`crate::engine`] and
//!   [`crate::stego`] (one to three lines each).
//! - **there is one surface, not two.** The structure-domain verbs (`write`,
//!   `read`, `restore`, ...) and the content-domain verbs (`embed`, `extract`,
//!   `probe`) are distinct words, so a root-level method is unambiguous; no
//!   namespace/direct dual form is needed.
//! - **path and bytes variants are both provided.** Services without a
//!   writable filesystem stay in memory; the file variants reuse the same
//!   atomic commit path as the CLI.
//!
//! # Example
//!
//! ```
//! use strhide::facade::StrHide;
//! use strhide::params::Profile;
//!
//! // The whole dialect is declared at compile time.
//! const ENGINE: StrHide = StrHide::new()
//!     .with_profile(Profile::new().with_default_secret("my-deployment-key"));
//!
//! assert!(!ENGINE.profile().is_official());
//! ```
//!
//! # Per-operation `LocalParams` override
//!
//! [`StrHide`] is [`Copy`], so a single call can run with different
//! writer-only knobs without mutating the engine and without a dedicated
//! method:
//!
//! ```
//! # use strhide::facade::StrHide;
//! # use strhide::params::{CompressionStrategy, LocalParams};
//! # let engine = StrHide::new();
//! let tuned = engine.with_local_params(
//!     LocalParams::new().with_compression(CompressionStrategy::Never),
//! );
//! // use `tuned` for this call; `engine` is unchanged.
//! let _ = tuned;
//! ```

#[cfg(feature = "cli")]
use std::ffi::OsString;
use std::path::Path;
#[cfg(feature = "content")]
use std::path::PathBuf;

use crate::errors::StrHideError;
use crate::params::{LocalParams, Profile};
#[cfg(feature = "content")]
use crate::stego::io::{embed_carrier_file, extract_carrier_file};
#[cfg(feature = "content")]
use crate::stego::{StegoCapacityInfo, StegoOptions, probe_carrier_capacity_with_profile};
#[cfg(feature = "content")]
use crate::stego::{embed_carrier_with_profile, extract_carrier_with_profile};
use crate::structure::{
    InspectResult, PayloadSource, ReadResult, RemoveResult, VerifyResult, WriteOptions,
    WriteResult, inspect_carrier_bytes, inspect_carrier_with, read_carrier_bytes,
    read_carrier_with_profile, remove_carrier_bytes, remove_carrier_with_options,
    verify_carrier_bytes, verify_carrier_with, write_carrier_bytes, write_carrier_with,
};

/// A configured strhide engine: one dialect plus one writer-behaviour baseline.
///
/// Construct with [`new`](Self::new) and the `const` builders
/// [`with_profile`](Self::with_profile) /
/// [`with_local_params`](Self::with_local_params), then call the verb methods.
///
/// Cheap and `Copy`: it only borrows static data and holds small `Copy`
/// configuration values, so passing it around or deriving a per-call variant
/// costs nothing.
#[derive(Debug, Clone, Copy)]
pub struct StrHide {
    profile: Profile,
    local: LocalParams,
}

impl Default for StrHide {
    fn default() -> Self {
        Self::new()
    }
}

impl StrHide {
    /// The official engine: official dialect and default writer behaviour.
    pub const fn new() -> Self {
        Self {
            profile: Profile::new(),
            local: LocalParams::new(),
        }
    }

    /// Bind a private dialect ([`Profile`]).
    pub const fn with_profile(mut self, profile: Profile) -> Self {
        self.profile = profile;
        self
    }

    /// Set the writer-behaviour baseline ([`LocalParams`]).
    pub const fn with_local_params(mut self, local: LocalParams) -> Self {
        self.local = local;
        self
    }

    /// The dialect this engine is bound to.
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// The writer-behaviour baseline.
    pub fn local_params(&self) -> &LocalParams {
        &self.local
    }

    // ─────────────────────────────── command line ────────────────────────────

    /// Run the command-line interface bound to this engine, returning the
    /// process exit code **without** calling [`std::process::exit`].
    ///
    /// The dialect and writer-behaviour baseline bound on this engine replace
    /// the hard-coded official defaults inside the CLI, so an embedding host
    /// can drive its own private command line. Explicit CLI flags still take
    /// precedence over the bound configuration.
    ///
    /// `argv` must include the program name as its first element, exactly as
    /// [`std::env::args_os`] returns it; clap uses that element for help and
    /// error output, so callers assembling arguments manually must supply one.
    #[cfg(feature = "cli")]
    pub fn run_cli_from(&self, argv: impl IntoIterator<Item = impl Into<OsString>>) -> i32 {
        let argv: Vec<OsString> = argv.into_iter().map(Into::into).collect();
        crate::cli::run_cli_with(self, argv)
    }

    // ───────────────────────── structure domain · path ─────────────────────────

    /// Inject `source` into the carrier at `carrier`, returning the result.
    pub fn write(
        &self,
        carrier: &Path,
        source: PayloadSource<'_>,
        options: &WriteOptions<'_>,
    ) -> Result<WriteResult, StrHideError> {
        write_carrier_with(carrier, source, options, &self.local, &self.profile)
    }

    /// Extract the payload from `carrier`, optionally writing it to `output`.
    ///
    /// Refuses to replace an existing destination; use
    /// [`read_with`](Self::read_with) to allow it.
    pub fn read(
        &self,
        carrier: &Path,
        output: Option<&Path>,
        password: Option<&str>,
    ) -> Result<ReadResult, StrHideError> {
        self.read_with(carrier, output, password, false)
    }

    /// Extract the payload, optionally allowing an existing destination to be
    /// replaced.
    ///
    /// `overwrite` is the read-side counterpart of `restore`'s `backup`: both
    /// were previously hard-coded on the facade (`false`), which forced callers
    /// that need either behaviour back to the five-parameter free functions.
    pub fn read_with(
        &self,
        carrier: &Path,
        output: Option<&Path>,
        password: Option<&str>,
        overwrite: bool,
    ) -> Result<ReadResult, StrHideError> {
        read_carrier_with_profile(carrier, output, password, overwrite, &self.profile)
    }

    /// Strip the envelope and restore the original carrier.
    ///
    /// Refuses to replace an existing destination; use
    /// [`restore_with`](Self::restore_with) to allow it.
    pub fn restore(
        &self,
        carrier: &Path,
        output: Option<&Path>,
        password: Option<&str>,
        backup: bool,
    ) -> Result<RemoveResult, StrHideError> {
        self.restore_with(carrier, output, password, backup, false)
    }

    /// Strip the envelope and restore the original carrier, optionally
    /// allowing an existing destination to be replaced.
    pub fn restore_with(
        &self,
        carrier: &Path,
        output: Option<&Path>,
        password: Option<&str>,
        backup: bool,
        overwrite: bool,
    ) -> Result<RemoveResult, StrHideError> {
        remove_carrier_with_options(carrier, output, password, backup, &self.profile, overwrite)
    }

    /// Inspect a carrier without modifying it.
    pub fn inspect(
        &self,
        carrier: &Path,
        password: Option<&str>,
    ) -> Result<InspectResult, StrHideError> {
        inspect_carrier_with(carrier, password, &self.profile)
    }

    /// Verify host structure, envelope integrity, and payload crypto.
    pub fn verify(
        &self,
        carrier: &Path,
        password: Option<&str>,
    ) -> Result<VerifyResult, StrHideError> {
        verify_carrier_with(carrier, password, &self.profile)
    }

    // ──────────────────────── structure domain · bytes ─────────────────────────

    /// Inject `source` into an in-memory carrier, returning the stego bytes.
    pub fn write_bytes(
        &self,
        carrier: &[u8],
        source: PayloadSource<'_>,
        options: &WriteOptions<'_>,
    ) -> Result<(Vec<u8>, WriteResult), StrHideError> {
        write_carrier_bytes(carrier, source, options, &self.local, &self.profile)
    }

    /// Extract the payload from an in-memory carrier.
    pub fn read_bytes(
        &self,
        carrier: &[u8],
        password: Option<&str>,
    ) -> Result<ReadResult, StrHideError> {
        read_carrier_bytes(carrier, password, &self.profile)
    }

    /// Strip the envelope from an in-memory carrier, returning restored bytes.
    pub fn restore_bytes(
        &self,
        carrier: &[u8],
        password: Option<&str>,
    ) -> Result<(Vec<u8>, RemoveResult), StrHideError> {
        remove_carrier_bytes(carrier, password, &self.profile)
    }

    /// Inspect an in-memory carrier.
    pub fn inspect_bytes(
        &self,
        carrier: &[u8],
        password: Option<&str>,
    ) -> Result<InspectResult, StrHideError> {
        inspect_carrier_bytes(carrier, password, &self.profile)
    }

    /// Verify an in-memory carrier.
    pub fn verify_bytes(
        &self,
        carrier: &[u8],
        password: Option<&str>,
    ) -> Result<VerifyResult, StrHideError> {
        verify_carrier_bytes(carrier, password, &self.profile)
    }

    // ───────────────────────── content domain · bytes ──────────────────────────

    #[cfg(feature = "content")]
    /// Embed `payload` into an in-memory image carrier, returning stego bytes.
    pub fn embed(
        &self,
        carrier: &[u8],
        payload: &[u8],
        options: &StegoOptions,
    ) -> Result<Vec<u8>, StrHideError> {
        embed_carrier_with_profile(carrier, payload, options, &self.profile)
    }

    #[cfg(feature = "content")]
    /// Extract the payload from an in-memory image carrier.
    pub fn extract(&self, carrier: &[u8], options: &StegoOptions) -> Result<Vec<u8>, StrHideError> {
        extract_carrier_with_profile(carrier, options, &self.profile)
    }

    #[cfg(feature = "content")]
    /// Probe the embedding capacity of an in-memory image carrier.
    pub fn probe(
        &self,
        carrier: &[u8],
        options: &StegoOptions,
    ) -> Result<StegoCapacityInfo, StrHideError> {
        probe_carrier_capacity_with_profile(carrier, options, &self.profile)
    }

    // ───────────────────────── content domain · file ───────────────────────────

    #[cfg(feature = "content")]
    /// Embed `payload` into an image file and commit it atomically.
    ///
    /// The carrier is read, the embedding is done in memory, and the result is
    /// committed through [`commit_carrier_bytes`] (temp file + atomic rename,
    /// optional `.bak`, timestamp preservation) -- the same path the CLI uses.
    ///
    /// When `target` is `None` the carrier is replaced in place; otherwise the
    /// result is written to `target` and the original carrier is left alone.
    /// Returns the created backup path, if any.
    pub fn embed_file(
        &self,
        carrier: &Path,
        target: Option<&Path>,
        payload: &[u8],
        options: &StegoOptions,
        backup: bool,
    ) -> Result<Option<PathBuf>, StrHideError> {
        embed_carrier_file(carrier, target, payload, options, &self.profile, backup)
    }

    #[cfg(feature = "content")]
    /// Extract the payload from an image file and write it to `output`.
    ///
    /// An existing destination is refused unless `overwrite` is set, matching
    /// the structure-domain `read` behaviour.
    pub fn extract_file(
        &self,
        carrier: &Path,
        output: &Path,
        options: &StegoOptions,
        overwrite: bool,
    ) -> Result<PathBuf, StrHideError> {
        let data = extract_carrier_file(carrier, options, &self.profile)?;

        let final_dest = if output.is_dir() {
            output.join("extracted.bin")
        } else {
            output.to_path_buf()
        };
        if final_dest.exists() && !overwrite {
            return Err(StrHideError::Rejection(format!(
                "Refusing to overwrite existing file '{}'. Choose another output or pass overwrite.",
                final_dest.display()
            )));
        }
        if let Some(parent) = final_dest.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        // Same temp+fsync+rename path the carrier writers use: a half-written
        // payload must never be visible under the destination name.
        crate::commit::write_bytes_atomic(&final_dest, &data)?;
        Ok(final_dest)
    }
}
