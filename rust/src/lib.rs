//! # strhide
//!
//! `strhide` is a smart, format-preserving, lossless data-hiding library and
//! CLI. It hides text or a file inside an ordinary host ("carrier") file —
//! PNG, JPEG, MP4, ZIP, PDF, or a Windows PE executable — without changing the
//! host's visible format, rendering, or behavior, and restores the original
//! host **bit-for-bit** afterwards.
//!
//! ## Features
//!
//! - **Format-preserving injection** for six carrier families:
//!   PNG (`prIv` ancillary chunk), JPEG (APP15 segment), MP4 (`uuid` box),
//!   ZIP (pre-central-directory), PDF (incremental update), and Windows PE
//!   (section slack, x86/x64 instruction encoding, or overlay).
//! - **Content-adaptive steganography** for PNG (HILL / S-UNIWARD), JPEG
//!   (UERD / J-UNIWARD + ternary STC), and H.265/HEVC (CABAC bin flipping,
//!   Annex-B or MP4/MOV).
//! - **AES-256-GCM authenticated encryption** for both the payload and the
//!   metadata; keys derived with PBKDF2-HMAC-SHA256 (100 000 iterations) +
//!   HKDF-SHA256. Even without a password, envelopes are uniformly encrypted
//!   under a built-in public key so no plaintext leaks into a hex dump.
//! - **Stealth mode**: header/trailer magics, header sensitive fields, and
//!   trailer CRC are all derived from the password, so an envelope is
//!   indistinguishable from random bytes without it (plausible deniability).
//! - **Lossless restoration**: [`structure::remove_carrier`] verifies the
//!   restored carrier against the SHA-256 and size recorded in the envelope
//!   before committing, and refuses to commit on any mismatch.
//! - **Rejection-first design**: signed PE/PDF/JAR files, read-only targets,
//!   and unsupported containers are refused before any write happens.
//!
//! ## Supported carriers and strategies
//!
//! | Format | Primary strategy | Fallback |
//! |---|---|---|
//! | PNG | `chunk` (private ancillary chunk before IEND) | `eof` |
//! | JPEG | `app_segment` (APP15 before SOS) | `eof` |
//! | MP4 | `box_uuid` (ISO BMFF uuid box) | `eof` |
//! | ZIP | `pre_cd_inject` (before central directory) | `eof` |
//! | PDF | `incremental` (append updates) | `eof` |
//! | PE | `pe_codebits` / `pe_slack` / `pe_overlay` | `eof` |
//!
//! `strategy = "auto"` (the [`structure::WriteOptions`] default) picks the
//! primary strategy when it fits and falls back to `eof` transparently.
//!
//! ## CLI quick start
//!
//! ```text
//! strhide write carrier.png --text "hello" --password pw
//! strhide read  carrier.png --output out.txt --password pw
//! strhide inspect carrier.png --password pw
//! strhide verify carrier.png --password pw
//! strhide restore carrier.png --password pw
//! ```
//!
//! ## Library usage
//!
//! The recommended entry point is [`facade::StrHide`]: bind one
//! [`facade::Dialect`] once, then reach the two domains through
//! [`facade::StrHide::structure`] and [`facade::StrHide::stego`].
//!
//! ```no_run
//! # fn main() -> Result<(), strhide::errors::StrHideError> {
//! use strhide::facade::StrHide;
//! use strhide::structure::{PayloadSource, ReadOptions, WriteOptions};
//!
//! let engine = StrHide::new();
//!
//! // Write a text payload into an existing PNG carrier, in place.
//! engine.structure().write_file(
//!     std::path::Path::new("photo.png"),
//!     PayloadSource::Text("hello from strhide"),
//!     &WriteOptions {
//!         password: Some("s3cret"),
//!         ..WriteOptions::default()
//!     },
//! )?;
//!
//! // Extract it back (in memory: no `output_path`).
//! let read = engine.structure().read_file(
//!     std::path::Path::new("photo.png"),
//!     &ReadOptions::new().with_password("s3cret"),
//! )?;
//! assert_eq!(read.data, b"hello from strhide");
//! # Ok(())
//! # }
//! ```
//!
//! After `restore_file`, `photo.png` is byte-for-byte identical to the file
//! before the write.
//!
//! ## Tuning and private dialects
//!
//! The plain entry points use the historical defaults. Two orthogonal types
//! cover the rest:
//!
//! - [`params::LocalParams`] — writer-only knobs (chunk size, compression
//!   policy, rejection policy). The reader never needs them, so varying them is
//!   always safe.
//! - [`facade::Dialect`] — the private dialect, composed of
//!   [`structure::params::StructureProfile`] (envelope secret, stealth domain,
//!   magic pair) and [`stego::params::StegoProfile`] (image secret, HKDF
//!   domain, private wire-format identities). Read and write must use the
//!   **same** dialect; `Dialect::new()` is the official one.
//!
//! ## Crate layout
//!
//! The two domains are peers; neither may reference the other.
//!
//! - [`formats`] — layer 2: [`formats::FileFormat`], `sniff_bytes` /
//!   `sniff_stream`, and the [`formats::capability`] table ("what can this
//!   format carry?").
//! - [`structure`] — layer 3A, the container domain: [`structure::write_carrier`]
//!   and friends, with [`structure::envelope`] (UBE v2.2 wire format),
//!   [`structure::adapters`] (one `HostAdapter` per container),
//!   [`structure::registry`] (format routing, strategy IDs) and
//!   [`structure::params::StructureProfile`].
//! - [`stego`] — layer 3B, the content domain: PNG HILL, JPEG UERD + ternary
//!   STC, HEVC CABAC. Its public surface is re-exported at the crate root:
//!   [`JpegFormatProfile`] / [`DEFAULT_JPEG_FORMAT`] (wire-format identity),
//!   [`JpegParams`] / [`ExtractParams`] (per-call tuning), and
//!   [`embed_carrier`] / [`extract_carrier`] (entry points a private build
//!   calls with its own [`stego::params::StegoProfile`]).
//! - [`analysis`] — layer 4: black-box steganalysis.
//! - [`core`] — layer 1: [`core::i18n`] (message catalogue),
//!   [`core::control`] (progress + cancellation), [`core::payload`],
//!   [`core::media`], [`core::fs`], [`core::pipeline`] (batch orchestration)
//!   and, when the `config` feature is on, [`core::config`] (TOML settings).
//! - [`crypto`] / [`errors`] / [`params`] / [`commit`] — crate-root residents
//!   that a later batch moves under [`core`].
//! - [`cli`] — layer 5: the command line (feature `cli`).
//!
//! ## Prelude
//!
//! [`prelude`] re-exports the types most callers need, so a first integration
//! is one `use strhide::prelude::*;`.

extern crate alloc;

// Layer 1-2: shared by both domains, always compiled.
pub mod core;
pub mod formats;

// Layer 1: core re-exports for backwards compatibility
pub use core::crypto;
pub use core::errors;
pub use core::params;

#[cfg(any(feature = "structure-base", feature = "content-base"))]
pub use core::commit;

/// Historical path: the message catalogue used to live at `strhide::i18n`.
pub use crate::core::i18n;

// Layer 3A: structure domain (envelope injection, bit-exact restore).
#[cfg(feature = "structure-base")]
pub mod structure;

// Layer 3B: content domain (pixel / DCT / CABAC steganography).
#[cfg(feature = "content-base")]
pub mod stego;

// Layer 4: black-box steganalysis.
#[cfg(feature = "analysis")]
pub mod analysis;

// Layer 5: command line.
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub mod cli_i18n;

pub mod facade;

// ── Facade (always compiled; methods are gated per domain) ──────────────────
pub use facade::{Dialect, DualInspect, DualVerify, StrHide};

// ── Errors ─────────────────────────────────────────────────────────────────
pub use errors::{ErrorDetail, ErrorKind, StrHideError, TrellisCause};

// ── Formats ────────────────────────────────────────────────────────────────
pub use formats::sniff::FileFormat;

// ── Structure domain ───────────────────────────────────────────────────────
#[cfg(feature = "structure-base")]
pub use structure::params::StructureProfile;
#[cfg(feature = "structure-base")]
pub use structure::{
    PayloadSource, ReadOptions, ReadResult, ReadSummary, RemoveResult, RestoreOptions,
    StrategyChoice, StrategyId, Warning, WriteOptions, WriteResult,
};

// ── Content domain ─────────────────────────────────────────────────────────
#[cfg(feature = "content-base")]
pub use core::media::MediaInfo;
#[cfg(feature = "content-base")]
pub use core::payload::{Payload, PayloadKind};
#[cfg(feature = "content-base")]
pub use stego::params::StegoProfile;
#[cfg(feature = "content-base")]
pub use stego::{
    EmbedOptions, EmbedOutput, EmbedStats, ExtractOptions, InspectOptions, ProbeOptions,
    SafetyEnforcement, SafetyLevel, SafetyPolicy, StegoCapacityInfo, StegoEmbedResult,
    StegoHeaderInfo, StegoTuning, StegoVerifyResult, VerifyOptions, embed_carrier, extract_carrier,
    probe_carrier_capacity,
};
#[cfg(feature = "content-base")]
pub use stego::{
    compute_default_threads, default_thread_count, embed_carrier_with_dialect,
    extract_carrier_with_dialect, init_default_thread_pool, probe_carrier_capacity_with_dialect,
};

// ── Prelude ────────────────────────────────────────────────────────────────
pub mod prelude {
    //! The types a first integration needs.
    //!
    //! ```
    //! use strhide::prelude::*;
    //!
    //! let engine = StrHide::new();
    //! assert!(engine.dialect().is_official());
    //! ```

    pub use crate::errors::{ErrorDetail, ErrorKind, StrHideError};
    pub use crate::facade::{Dialect, DualInspect, DualVerify, StrHide};
    pub use crate::formats::sniff::FileFormat;
    pub use crate::params::{CompressionStrategy, LocalParams, RejectionPolicy};

    #[cfg(feature = "structure-base")]
    pub use crate::structure::params::StructureProfile;
    #[cfg(feature = "structure-base")]
    pub use crate::structure::{
        PayloadSource, ReadOptions, ReadResult, ReadSummary, RemoveResult, RestoreOptions,
        StrategyChoice, WriteOptions, WriteResult,
    };

    #[cfg(feature = "content-base")]
    pub use crate::core::media::MediaInfo;
    #[cfg(feature = "content-base")]
    pub use crate::core::payload::Payload;
    #[cfg(feature = "content-base")]
    pub use crate::stego::params::StegoProfile;
    #[cfg(feature = "content-base")]
    pub use crate::stego::{
        EmbedOptions, EmbedStats, ExtractOptions, ProbeOptions, SafetyEnforcement, SafetyLevel,
        SafetyPolicy, StegoCapacityInfo, StegoEmbedResult, StegoTuning,
    };
}

// Content-domain steganography surface.
#[cfg(feature = "content-base")]
pub use stego::format::{CipherSuite, GridRule};
#[cfg(feature = "content-hevc")]
pub use stego::format::{DEFAULT_HEVC_FORMAT, HevcFormatProfile};
#[cfg(feature = "content-jpeg")]
pub use stego::format::{DEFAULT_JPEG_FORMAT, JpegFormatProfile};
#[cfg(feature = "content-png")]
pub use stego::format::{OFFICIAL_PNG_FORMAT, PngFormatProfile};

#[cfg(feature = "content-jpeg")]
pub use stego::jpeg::cost::UerdCostModel;
#[cfg(feature = "content-base")]
pub use stego::params::ExtractParams;
#[cfg(feature = "content-jpeg")]
pub use stego::params::JpegParams;
#[cfg(feature = "content-png")]
pub use stego::params::PngParams;
#[cfg(feature = "content-jpeg")]
pub use stego::traits::JpegCostModel;
