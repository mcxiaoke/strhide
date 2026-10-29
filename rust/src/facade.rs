// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! The single entry-point facade: a [`StrHide`] instance binds one [`Dialect`]
//! and one writer-behaviour baseline ([`LocalParams`]), then exposes the two
//! domains as sub-facades ([`StructureFacade`] / [`StegoFacade`]).
//!
//! Three design points (stage 4, plan §3.1):
//!
//! - **configuration and actions are separate.** The long-lived dialect and
//!   tuning are set once at construction; the verbs are plain methods that
//!   forward to the free functions in [`crate::structure`] and [`crate::stego`].
//! - **one domain per namespace.** `structure` (container envelopes) and
//!   `stego` (pixel / DCT / CABAC embedding) are reached through
//!   [`StrHide::structure`] and [`StrHide::stego`], so a verb name can never be
//!   ambiguous and neither domain leaks into the other's type signatures.
//! - **path and bytes variants are both provided.** Services without a
//!   writable filesystem stay in memory; the file variants reuse the same
//!   atomic commit path as the CLI.
//!
//! The module is compiled **unconditionally** — the domain methods simply
//! disappear when their feature is off, so `strhide::facade::StrHide` is a
//! usable type in every build (plan §1.1: the recommended entry point must not
//! be feature-gated).
//!
//! # Example
//!
//! ```
//! use strhide::facade::{Dialect, StrHide};
//!
//! // The whole dialect is declared at compile time and applies to both domains.
//! const ENGINE: StrHide = StrHide::new()
//!     .with_dialect(Dialect::new().with_default_secret("my-deployment-key"));
//!
//! assert!(!ENGINE.dialect().is_official());
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
#[cfg(feature = "content-base")]
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::core::control::Control;
#[cfg(feature = "content-base")]
use crate::core::payload::Payload;
#[cfg(feature = "content-base")]
use crate::errors::ErrorDetail;
use crate::errors::StrHideError;
#[cfg(feature = "structure-base")]
use crate::params::LocalParams;
#[cfg(feature = "structure-base")]
use crate::structure::params::StructureProfile;
#[cfg(feature = "structure-base")]
use crate::structure::{
    InspectResult, PayloadSource, ReadOptions, ReadResult, RemoveResult, RestoreOptions,
    VerifyResult, WriteOptions, WriteResult, inspect_carrier_bytes, inspect_carrier_with,
    read_carrier_bytes, read_carrier_with_dialect, remove_carrier_bytes,
    remove_carrier_with_dialect, verify_carrier_bytes, verify_carrier_with, write_carrier_bytes,
    write_carrier_with,
};

#[cfg(feature = "content-base")]
use crate::stego::io::{
    embed_carrier_file, extract_carrier_file_payload, inspect_carrier_file, probe_carrier_file,
    verify_carrier_file,
};
#[cfg(feature = "content-base")]
use crate::stego::params::StegoProfile;
#[cfg(feature = "content-base")]
use crate::stego::{
    EmbedOptions, ExtractOptions, InspectOptions, ProbeOptions, StegoCapacityInfo, StegoHeaderInfo,
    StegoVerifyResult, VerifyOptions, embed_carrier_with_dialect, extract_carrier_payload,
    inspect_carrier_with_dialect, probe_carrier_capacity_with_dialect, verify_carrier_with_dialect,
};

/// Target hiding domain in a carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    Structure,
    Content,
}

/// Options controlling a dual-domain inspection pass.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct DualOptions<'a> {
    pub password: Option<&'a str>,
    pub domain: Option<&'a str>,
    pub control: Control<'a>,
}

impl std::fmt::Debug for DualOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DualOptions")
            .field("password", &self.password.map(|_| "<redacted>"))
            .field("domain", &self.domain)
            .field("control", &self.control)
            .finish()
    }
}

/// Cross-domain inspection diagnosis.
#[derive(Debug, Serialize)]
pub struct DualInspect {
    #[cfg(feature = "structure-base")]
    #[serde(flatten)]
    pub structure: crate::structure::InspectResult,

    #[cfg(feature = "content-base")]
    #[serde(rename = "content_stego", skip_serializing_if = "Option::is_none")]
    pub content: Option<crate::stego::StegoHeaderInfo>,

    #[cfg(feature = "content-base")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_error: Option<ErrorDetail>,

    #[cfg(feature = "content-base")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_info: Option<crate::core::media::MediaInfo>,
}

/// Cross-domain verification result.
#[derive(Debug, Serialize)]
pub struct DualVerify {
    #[cfg(feature = "structure-base")]
    #[serde(flatten)]
    pub structure: crate::structure::VerifyResult,

    #[cfg(feature = "content-base")]
    #[serde(rename = "content_stego", skip_serializing_if = "Option::is_none")]
    pub content: Option<crate::stego::StegoVerifyResult>,
}

impl DualVerify {
    /// Returns true if either structure verification or content verification succeeded.
    pub fn is_any_ok(&self) -> bool {
        #[cfg(feature = "structure-base")]
        let struct_ok = crate::structure::verify_passed(&self.structure);
        #[cfg(not(feature = "structure-base"))]
        let struct_ok = false;

        #[cfg(feature = "content-base")]
        let content_ok = self
            .content
            .as_ref()
            .map(|c| c.is_all_ok())
            .unwrap_or(false);
        #[cfg(not(feature = "content-base"))]
        let content_ok = false;

        struct_ok || content_ok
    }
}

/// Options for automatic domain selection extraction.
#[cfg(all(feature = "structure-base", feature = "content-base"))]
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SmartExtractOptions<'a> {
    pub password: Option<&'a str>,
    pub domain: Option<&'a str>,
    /// Limits PBKDF2 iterations and tried cipher suites to avoid GUI hangs.
    pub limits: crate::stego::ExtractParams,
    /// Preferred domain when both domains hold hidden data (defaults to Structure).
    pub prefer: Option<Domain>,
    pub control: Control<'a>,
}

#[cfg(all(feature = "structure-base", feature = "content-base"))]
impl std::fmt::Debug for SmartExtractOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmartExtractOptions")
            .field("password", &self.password.map(|_| "<redacted>"))
            .field("domain", &self.domain)
            .field("limits", &self.limits)
            .field("prefer", &self.prefer)
            .field("control", &self.control)
            .finish()
    }
}

/// Structured outcome of automatic domain selection extraction.
#[cfg(all(feature = "structure-base", feature = "content-base"))]
#[derive(Debug, Clone)]
pub struct ExtractOutcome {
    pub payload: crate::core::payload::Payload<'static>,
    pub source: Domain,
    /// Set if the other domain also contained hidden data.
    pub also_present: Option<Domain>,
}

/// The private dialect for both domains, composed.
///
/// This is the one object a host stores: the structure half drives the UBE
/// envelope, the content half drives image embedding, and
/// [`with_default_secret`](Self::with_default_secret) sets both so the common
/// case (one private deployment secret) needs no thought.
///
/// Each half is optional at compile time: a `content`-only build has no
/// `structure` field, and a `structure`-only build has no `stego` field. The
/// all-default dialect is the official one, byte-compatible with every release.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Dialect {
    /// Structure-domain (UBE envelope) dialect.
    #[cfg(feature = "structure-base")]
    pub structure: StructureProfile,
    /// Content-domain (pixel / DCT / CABAC) dialect.
    #[cfg(feature = "content-base")]
    pub stego: StegoProfile,
}

impl Dialect {
    /// Official dialect: every field at its default.
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "structure-base")]
            structure: StructureProfile::new(),
            #[cfg(feature = "content-base")]
            stego: StegoProfile::new(),
        }
    }

    /// Set the private no-password secret on **both** halves.
    ///
    /// The two domains derive keys in different derivation domains, so the
    /// same string produces two unrelated keys — which is the intent: one
    /// deployment secret, two independent dialects.
    #[allow(unused_mut, unused_variables)]
    pub const fn with_default_secret(mut self, secret: &'static str) -> Self {
        #[cfg(feature = "structure-base")]
        {
            self.structure.default_secret = Some(secret);
        }
        #[cfg(feature = "content-base")]
        {
            self.stego.default_secret = Some(secret);
        }
        self
    }

    /// Replace the structure half.
    #[cfg(feature = "structure-base")]
    pub const fn with_structure_profile(mut self, structure: StructureProfile) -> Self {
        self.structure = structure;
        self
    }

    /// Replace the content half.
    #[cfg(feature = "content-base")]
    pub const fn with_stego_profile(mut self, stego: StegoProfile) -> Self {
        self.stego = stego;
        self
    }

    /// Set the content-domain secret only, leaving the UBE secret alone.
    #[cfg(feature = "content-base")]
    pub const fn with_stego_secret(mut self, secret: &'static str) -> Self {
        self.stego = self.stego.with_default_secret(secret);
        self
    }

    /// True when every field on every compiled-in domain is default.
    pub fn is_official(&self) -> bool {
        #[allow(unused_mut)]
        let mut ok = true;
        #[cfg(feature = "structure-base")]
        {
            ok = ok && self.structure.is_official();
        }
        #[cfg(feature = "content-base")]
        {
            ok = ok && self.stego.is_official();
        }
        ok
    }
}

/// A configured strhide engine: one dialect plus one writer-behaviour baseline.
///
/// Construct with [`new`](Self::new) and the `const` builders
/// [`with_dialect`](Self::with_dialect) /
/// [`with_local_params`](Self::with_local_params), then pick a domain with
/// [`structure`](Self::structure) or [`stego`](Self::stego).
///
/// Cheap and `Copy`: it only holds small `Copy` configuration values, so
/// passing it around or deriving a per-call variant costs nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct StrHide {
    dialect: Dialect,
    #[cfg(feature = "structure-base")]
    local: LocalParams,
}

impl StrHide {
    /// The official engine: official dialect and default writer behaviour.
    pub const fn new() -> Self {
        Self {
            dialect: Dialect::new(),
            #[cfg(feature = "structure-base")]
            local: LocalParams::new(),
        }
    }

    /// Bind a private dialect ([`Dialect`]).
    pub const fn with_dialect(mut self, dialect: Dialect) -> Self {
        self.dialect = dialect;
        self
    }

    /// Set the writer-behaviour baseline ([`LocalParams`]).
    #[cfg(feature = "structure-base")]
    pub const fn with_local_params(mut self, local: LocalParams) -> Self {
        self.local = local;
        self
    }

    /// The dialect this engine is bound to.
    pub fn dialect(&self) -> &Dialect {
        &self.dialect
    }

    /// The writer-behaviour baseline.
    #[cfg(feature = "structure-base")]
    pub fn local_params(&self) -> &LocalParams {
        &self.local
    }

    /// The structure (container envelope) domain.
    #[cfg(feature = "structure-base")]
    pub const fn structure(&self) -> StructureFacade<'_> {
        StructureFacade { engine: self }
    }

    /// The content (pixel / DCT / CABAC) domain.
    #[cfg(feature = "content-base")]
    pub const fn stego(&self) -> StegoFacade<'_> {
        StegoFacade { engine: self }
    }

    /// The analysis (black-box steganalysis) domain.
    #[cfg(feature = "analysis")]
    pub const fn analysis(&self) -> AnalysisFacade<'_> {
        AnalysisFacade { engine: self }
    }

    /// Cross-domain read-only inspection.
    pub fn inspect_any(
        &self,
        carrier: &Path,
        opts: &DualOptions<'_>,
    ) -> Result<DualInspect, StrHideError> {
        #[allow(unused_variables)]
        let _ = (carrier, opts);

        #[cfg(feature = "structure-base")]
        let structure = match crate::formats::sniff::sniff_file(carrier) {
            // Annex-B HEVC is a content-only carrier: there is no structure
            // adapter, so calling `inspect_file` would reject the file before
            // the content engine ever ran (which made `inspect`/`smart_extract`
            // fail on every .h265/.hevc stream).
            Ok(Some(format)) if !format.supports_structure() && format.supports_stego() => {
                crate::structure::InspectResult::not_applicable(carrier, format)
            }
            // Unreadable/unknown files still go through the structure domain so
            // the caller gets its usual, more precise rejection message.
            _ => self.structure().inspect_file(carrier, opts.password)?,
        };

        #[cfg(feature = "content-base")]
        let (content, content_error, media_info) = {
            let format = {
                #[cfg(feature = "structure-base")]
                {
                    Some(structure.format)
                }
                #[cfg(not(feature = "structure-base"))]
                {
                    crate::formats::sniff::sniff_file(carrier)?
                }
            };
            if format.is_some_and(|f| f.supports_stego()) {
                let stego_opts = crate::stego::InspectOptions {
                    password: opts.password,
                    domain: opts.domain,
                    limits: crate::stego::ExtractParams::default(),
                    control: opts.control,
                };
                match self.stego().inspect_file(carrier, &stego_opts) {
                    Ok(info) => {
                        let mi = info.media_info;
                        (Some(info), None, mi)
                    }
                    Err(e) => (None, Some(e.detail_i18n()), None),
                }
            } else {
                (None, None, None)
            }
        };

        Ok(DualInspect {
            #[cfg(feature = "structure-base")]
            structure,
            #[cfg(feature = "content-base")]
            content,
            #[cfg(feature = "content-base")]
            content_error,
            #[cfg(feature = "content-base")]
            media_info,
        })
    }

    /// Cross-domain verification.
    pub fn verify_any(
        &self,
        carrier: &Path,
        opts: &DualOptions<'_>,
    ) -> Result<DualVerify, StrHideError> {
        #[allow(unused_variables)]
        let _ = (carrier, opts);

        #[cfg(feature = "structure-base")]
        let structure = match crate::formats::sniff::sniff_file(carrier) {
            // Same content-only exemption as `inspect_any`.
            Ok(Some(format)) if !format.supports_structure() && format.supports_stego() => {
                crate::structure::VerifyResult::not_applicable(carrier, format)
            }
            _ => self.structure().verify_file(carrier, opts.password)?,
        };

        #[cfg(feature = "content-base")]
        let content = {
            let format = {
                #[cfg(feature = "structure-base")]
                {
                    Some(structure.format)
                }
                #[cfg(not(feature = "structure-base"))]
                {
                    crate::formats::sniff::sniff_file(carrier)?
                }
            };
            if format.is_some_and(|f| f.supports_stego()) {
                let ver_opts = crate::stego::VerifyOptions {
                    password: opts.password,
                    domain: opts.domain,
                    limits: crate::stego::ExtractParams::default(),
                    control: opts.control,
                };
                self.stego().verify_file(carrier, &ver_opts).ok()
            } else {
                None
            }
        };

        Ok(DualVerify {
            #[cfg(feature = "structure-base")]
            structure,
            #[cfg(feature = "content-base")]
            content,
        })
    }

    /// Auto-detect domain safe payload extraction (guided by cheap inspect_any).
    #[cfg(all(feature = "structure-base", feature = "content-base"))]
    pub fn smart_extract(
        &self,
        carrier: &Path,
        opts: &SmartExtractOptions<'_>,
    ) -> Result<ExtractOutcome, StrHideError> {
        let diag = self.inspect_any(
            carrier,
            &DualOptions {
                password: opts.password,
                domain: opts.domain,
                control: opts.control,
            },
        )?;
        let has_struct = diag.structure.has_hidden_data;
        let has_content = diag.content.as_ref().is_some_and(|c| c.has_hidden_data);

        let (chosen, also_present) = match (has_struct, has_content) {
            (true, true) => {
                let primary = opts.prefer.unwrap_or(Domain::Structure);
                let secondary = match primary {
                    Domain::Structure => Domain::Content,
                    Domain::Content => Domain::Structure,
                };
                (primary, Some(secondary))
            }
            (true, false) => (Domain::Structure, None),
            (false, true) => (Domain::Content, None),
            (false, false) => {
                return Err(StrHideError::NoHiddenData(format!(
                    "No hidden data found in '{}'",
                    carrier.display()
                )));
            }
        };

        match chosen {
            Domain::Structure => {
                let read_res = self.structure().read_file(
                    carrier,
                    &crate::structure::ReadOptions {
                        output_path: None,
                        password: opts.password,
                        overwrite: false,
                        control: opts.control,
                    },
                )?;
                let kind = if read_res.is_file {
                    crate::core::payload::PayloadKind::File
                } else {
                    crate::core::payload::PayloadKind::Text
                };
                let mut payload =
                    crate::core::payload::Payload::owned(read_res.data).with_kind(kind);
                if !read_res.filename.is_empty() {
                    payload = payload.with_name(read_res.filename);
                }
                Ok(ExtractOutcome {
                    payload,
                    source: Domain::Structure,
                    also_present,
                })
            }
            Domain::Content => {
                let ex_opts = crate::stego::ExtractOptions {
                    password: opts.password,
                    domain: opts.domain,
                    limits: opts.limits.clone(),
                    control: opts.control,
                    pool: None,
                };
                let payload = crate::stego::io::extract_carrier_file_payload(
                    carrier,
                    &ex_opts,
                    &self.dialect().stego,
                )?;
                Ok(ExtractOutcome {
                    payload,
                    source: Domain::Content,
                    also_present,
                })
            }
        }
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
}

// ───────────────────────────── structure domain ──────────────────────────────

/// Structure-domain verbs: format-preserving envelope injection, extraction,
/// restore, inspect, and verify.
///
/// Obtained from [`StrHide::structure`]; borrows the engine, so it is cheap and
/// cannot outlive it.
#[cfg(feature = "structure-base")]
#[derive(Debug, Clone, Copy)]
pub struct StructureFacade<'a> {
    engine: &'a StrHide,
}

#[cfg(feature = "structure-base")]
impl StructureFacade<'_> {
    /// Inject `source` into the carrier at `carrier`.
    pub fn write_file(
        &self,
        carrier: &Path,
        source: PayloadSource<'_>,
        options: &WriteOptions<'_>,
    ) -> Result<WriteResult, StrHideError> {
        write_carrier_with(
            carrier,
            source,
            options,
            self.engine.local_params(),
            &self.engine.dialect().structure,
        )
    }

    /// Inject `source` into an in-memory carrier, returning the stego bytes.
    pub fn write_bytes(
        &self,
        carrier: &[u8],
        source: PayloadSource<'_>,
        options: &WriteOptions<'_>,
    ) -> Result<(Vec<u8>, WriteResult), StrHideError> {
        write_carrier_bytes(
            carrier,
            source,
            options,
            self.engine.local_params(),
            &self.engine.dialect().structure,
        )
    }

    /// Extract the payload described by `options`.
    ///
    /// With [`ReadOptions::output_path`] unset the payload comes back in
    /// [`ReadResult::data`]; otherwise it is written there (refusing to replace
    /// an existing file unless [`ReadOptions::overwrite`] is set).
    pub fn read_file(
        &self,
        carrier: &Path,
        options: &ReadOptions<'_>,
    ) -> Result<ReadResult, StrHideError> {
        read_carrier_with_dialect(carrier, options, &self.engine.dialect().structure)
    }

    /// Extract the payload from an in-memory carrier.
    pub fn read_bytes(
        &self,
        carrier: &[u8],
        password: Option<&str>,
    ) -> Result<ReadResult, StrHideError> {
        read_carrier_bytes(carrier, password, &self.engine.dialect().structure)
    }

    /// Strip the envelope and restore the original carrier.
    pub fn restore_file(
        &self,
        carrier: &Path,
        options: &RestoreOptions<'_>,
    ) -> Result<RemoveResult, StrHideError> {
        remove_carrier_with_dialect(carrier, options, &self.engine.dialect().structure)
    }

    /// Strip the envelope from an in-memory carrier, returning restored bytes.
    pub fn restore_bytes(
        &self,
        carrier: &[u8],
        password: Option<&str>,
    ) -> Result<(Vec<u8>, RemoveResult), StrHideError> {
        remove_carrier_bytes(carrier, password, &self.engine.dialect().structure)
    }

    /// Inspect a carrier without modifying it.
    pub fn inspect_file(
        &self,
        carrier: &Path,
        password: Option<&str>,
    ) -> Result<InspectResult, StrHideError> {
        inspect_carrier_with(carrier, password, &self.engine.dialect().structure)
    }

    /// Inspect an in-memory carrier.
    pub fn inspect_bytes(
        &self,
        carrier: &[u8],
        password: Option<&str>,
    ) -> Result<InspectResult, StrHideError> {
        inspect_carrier_bytes(carrier, password, &self.engine.dialect().structure)
    }

    /// Verify host structure, envelope integrity, and payload crypto.
    pub fn verify_file(
        &self,
        carrier: &Path,
        password: Option<&str>,
    ) -> Result<VerifyResult, StrHideError> {
        verify_carrier_with(carrier, password, &self.engine.dialect().structure)
    }

    /// Verify an in-memory carrier.
    pub fn verify_bytes(
        &self,
        carrier: &[u8],
        password: Option<&str>,
    ) -> Result<VerifyResult, StrHideError> {
        verify_carrier_bytes(carrier, password, &self.engine.dialect().structure)
    }
}

// ────────────────────────────── content domain ───────────────────────────────

/// Content-domain verbs: embedding into pixels, DCT coefficients, or CABAC
/// bins, plus the capacity probe and the content-side diagnostics.
///
/// Obtained from [`StrHide::stego`]; borrows the engine.
#[cfg(feature = "content-base")]
#[derive(Debug, Clone, Copy)]
pub struct StegoFacade<'a> {
    engine: &'a StrHide,
}

#[cfg(feature = "content-base")]
impl StegoFacade<'_> {
    /// Embed `payload` into an in-memory image carrier, returning stego bytes.
    pub fn embed(
        &self,
        carrier: &[u8],
        payload: &Payload<'_>,
        options: &EmbedOptions<'_>,
    ) -> Result<Vec<u8>, StrHideError> {
        embed_carrier_with_dialect(carrier, payload, options, &self.engine.dialect().stego)
    }

    /// Extract the payload from an in-memory image carrier.
    ///
    /// Returns the unified [`Payload`], which carries the original filename
    /// when the micro-header recorded one (see plan §4.2).
    pub fn extract(
        &self,
        carrier: &[u8],
        options: &ExtractOptions<'_>,
    ) -> Result<Payload<'static>, StrHideError> {
        extract_carrier_payload(carrier, options, &self.engine.dialect().stego)
    }

    /// Probe the embedding capacity of an in-memory image carrier.
    pub fn probe(
        &self,
        carrier: &[u8],
        options: &ProbeOptions<'_>,
    ) -> Result<StegoCapacityInfo, StrHideError> {
        probe_carrier_capacity_with_dialect(carrier, options, &self.engine.dialect().stego)
    }

    /// Read-only feature/header inspection (no payload extraction).
    pub fn inspect(
        &self,
        carrier: &[u8],
        options: &InspectOptions<'_>,
    ) -> Result<StegoHeaderInfo, StrHideError> {
        inspect_carrier_with_dialect(carrier, options, &self.engine.dialect().stego)
    }

    /// Three-tier verification of a content-domain carrier.
    pub fn verify(
        &self,
        carrier: &[u8],
        options: &VerifyOptions<'_>,
    ) -> Result<StegoVerifyResult, StrHideError> {
        verify_carrier_with_dialect(carrier, options, &self.engine.dialect().stego)
    }

    /// Probe the embedding capacity of an image or video file.
    pub fn probe_file(
        &self,
        carrier: &Path,
        options: &ProbeOptions<'_>,
    ) -> Result<StegoCapacityInfo, StrHideError> {
        probe_carrier_file(carrier, options, &self.engine.dialect().stego)
    }

    /// Read-only feature/header inspection of an image or video file.
    pub fn inspect_file(
        &self,
        carrier: &Path,
        options: &InspectOptions<'_>,
    ) -> Result<StegoHeaderInfo, StrHideError> {
        inspect_carrier_file(carrier, options, &self.engine.dialect().stego)
    }

    /// Three-tier verification of a content-domain carrier file.
    pub fn verify_file(
        &self,
        carrier: &Path,
        options: &VerifyOptions<'_>,
    ) -> Result<StegoVerifyResult, StrHideError> {
        verify_carrier_file(carrier, options, &self.engine.dialect().stego)
    }

    /// Embed `payload` into an image file and commit it atomically.
    pub fn embed_file(
        &self,
        carrier: &Path,
        payload: &Payload<'_>,
        options: &EmbedOptions<'_>,
        target: &crate::commit::FileTarget<'_>,
    ) -> Result<crate::stego::StegoEmbedResult, StrHideError> {
        embed_carrier_file(
            carrier,
            payload,
            options,
            &self.engine.dialect().stego,
            target,
        )
    }

    /// Extract the payload from an image file and write it to `output`.
    ///
    /// An existing destination is refused unless `overwrite` is set, matching
    /// the structure-domain `read` behaviour. When `output` is a directory the
    /// payload is written inside it under its recorded (sanitized) filename, or
    /// `extracted.bin` when none was stored.
    pub fn extract_file(
        &self,
        carrier: &Path,
        output: &Path,
        options: &ExtractOptions<'_>,
        overwrite: bool,
    ) -> Result<PathBuf, StrHideError> {
        let payload = extract_carrier_file_payload(carrier, options, &self.engine.dialect().stego)?;
        let data = payload.data.to_vec();

        let final_dest = if output.is_dir() {
            let name = payload
                .name
                .as_deref()
                .map(crate::core::fs::sanitize_filename)
                .unwrap_or_else(|| "extracted.bin".to_string());
            output.join(name)
        } else {
            output.to_path_buf()
        };
        crate::core::pipeline::check_overwrite(&final_dest, overwrite)?;
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

// ───────────────────────────── analysis domain ──────────────────────────────

/// Analysis-domain verbs: black-box heuristic steganalysis of files or bytes.
///
/// Obtained from [`StrHide::analysis`].
#[cfg(feature = "analysis")]
#[derive(Debug, Clone, Copy)]
pub struct AnalysisFacade<'a> {
    #[allow(dead_code)]
    engine: &'a StrHide,
}

#[cfg(feature = "analysis")]
impl AnalysisFacade<'_> {
    /// Scan raw bytes in memory.
    pub fn scan_bytes(&self, data: &[u8], label: &str) -> crate::analysis::AnalysisReport {
        crate::analysis::scan_bytes(data, label)
    }

    /// Scan a file at `path`.
    pub fn scan_file(&self, path: &Path) -> Result<crate::analysis::AnalysisReport, StrHideError> {
        crate::analysis::scan_file(path)
    }
}
