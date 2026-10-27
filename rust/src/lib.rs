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
//! `strategy = "auto"` (the [`crate::structure::WriteOptions`] default) picks
//! the primary strategy when it fits and falls back to `eof` transparently.
//!
//! ## CLI quick start
//!
//! ```text
//! strhide write carrier.png --data-text "hello" --password pw
//! strhide read  carrier.png --output out.txt --password pw
//! strhide inspect carrier.png --password pw
//! strhide verify carrier.png --password pw
//! strhide restore carrier.png --password pw
//! ```
//!
//! ## Library usage
//!
//! The library entry points live in [`structure`]: [`structure::write_carrier`]
//! injects a payload, [`structure::read_carrier_with`] extracts it, and
//! [`structure::remove_carrier`] strips the envelope and restores the carrier.
//! Every fallible call returns a [`std::result::Result`] whose error type is
//! [`errors::StrHideError`].
//!
//! ```no_run
//! # fn main() -> Result<(), strhide::errors::StrHideError> {
//! use strhide::structure::{write_carrier, read_carrier_with, PayloadSource, WriteOptions};
//!
//! // Write a text payload into an existing PNG carrier, in place.
//! write_carrier(
//!     std::path::Path::new("photo.png"),
//!     PayloadSource::Text("hello from strhide"),
//!     &WriteOptions {
//!         password: Some("s3cret"),
//!         ..WriteOptions::default()
//!     },
//! )?;
//!
//! // Extract it back.
//! let extracted = read_carrier_with(
//!     std::path::Path::new("photo.png"),
//!     None,            // write to a Vec, not a file
//!     Some("s3cret"),
//!     false,
//! )?;
//! assert_eq!(extracted.data, b"hello from strhide");
//! # Ok(())
//! # }
//! ```
//!
//! After `remove_carrier`, `photo.png` is byte-for-byte identical to the file
//! before the write.
//!
//! ## Tuning and private dialects
//!
//! The plain entry points use the historical defaults. To change writer-only
//! behaviour without touching the wire format, pass [`params::LocalParams`] to
//! [`structure::write_carrier_with`]; to key envelopes with your own secret (so
//! that an official binary cannot read them), pass a [`params::Profile`] to the
//! `*_with` entry points of [`structure`]:
//!
//! - [`params::LocalParams`] — chunk size, compression policy, rejection
//!   policy. The reader never needs these, so varying them is always safe.
//! - [`params::Profile`] — private default secret, stealth derivation domain,
//!   custom magic pair. Read and write must use the **same** profile;
//!   `Profile::default()` is the official dialect.
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
//!   [`structure::adapters`] (one `HostAdapter` per container) and
//!   [`structure::registry`] (format routing + strategy IDs).
//! - [`stego`] — layer 3B, the content domain: PNG HILL, JPEG UERD + ternary
//!   STC, HEVC CABAC. Its public surface is re-exported at the crate root:
//!   [`JpegFormatProfile`] / [`DEFAULT_JPEG_FORMAT`] (wire-format identity),
//!   [`JpegParams`] / [`ExtractParams`] (per-call tuning), and
//!   [`embed`] / [`extract`] (the JPEG entry points a private build calls with
//!   its own profile).
//! - [`analysis`] — layer 4: black-box steganalysis.
//! - [`core`] — layer 1: [`core::i18n`] (message catalogue) and, when the
//!   `config` feature is on, [`core::config`] (TOML settings).
//! - [`crypto`] / [`errors`] / [`params`] / [`commit`] — stage-1 residents that
//!   stage 2 moves under [`core`].
//! - [`cli`] — layer 5: the command line (feature `cli`).

extern crate alloc;

// Layer 1-2: shared by both domains, always compiled.
pub mod core;
pub mod formats;
pub mod sniff;

pub mod crypto;
pub mod errors;
pub mod params;

#[cfg(any(feature = "structure", feature = "content"))]
pub mod commit;

/// Historical path: the message catalogue used to live at `strhide::i18n`.
pub use crate::core::i18n;

// Layer 3A: structure domain (envelope injection, bit-exact restore).
#[cfg(feature = "structure")]
pub mod structure;

// Layer 3B: content domain (pixel / DCT / CABAC steganography).
#[cfg(feature = "content")]
pub mod stego;

// Layer 4: black-box steganalysis.
#[cfg(feature = "analysis")]
pub mod analysis;

// Layer 5: command line.
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub mod cli_i18n;

#[cfg(feature = "structure")]
pub mod facade;

// Content-domain steganography surface.
#[cfg(feature = "content")]
pub use stego::format::{
    CipherSuite, DEFAULT_HEVC_FORMAT, DEFAULT_JPEG_FORMAT, GridRule, HevcFormatProfile,
    JpegFormatProfile, OFFICIAL_PNG_FORMAT, PngFormatProfile,
};
#[cfg(feature = "content")]
pub use stego::jpeg::cost::UerdCostModel;
#[cfg(feature = "content")]
pub use stego::params::{ExtractParams, JpegParams};
#[cfg(feature = "content")]
pub use stego::traits::JpegCostModel;
