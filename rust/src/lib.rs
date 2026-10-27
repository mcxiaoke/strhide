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
//! - **Lossless restoration**: [`engine::remove_carrier`] verifies the
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
//! `strategy = "auto"` (the [`crate::engine::WriteOptions`] default) picks
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
//! The library entry points live in [`engine`]: [`engine::write_carrier`]
//! injects a payload, [`engine::read_carrier_with`] extracts it, and
//! [`engine::remove_carrier`] strips the envelope and restores the carrier.
//! Every fallible call returns a [`std::result::Result`] whose error type is
//! [`errors::StrHideError`].
//!
//! ```no_run
//! # fn main() -> Result<(), strhide::errors::StrHideError> {
//! use strhide::engine::{write_carrier, read_carrier_with, PayloadSource, WriteOptions};
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
//! [`engine::write_carrier_with`]; to key envelopes with your own secret (so
//! that an official binary cannot read them), pass a [`params::Profile`] to the
//! `*_with` entry points of [`engine`]:
//!
//! - [`params::LocalParams`] — chunk size, compression policy, rejection
//!   policy. The reader never needs these, so varying them is always safe.
//! - [`params::Profile`] — private default secret, stealth derivation domain,
//!   custom magic pair. Read and write must use the **same** profile;
//!   `Profile::default()` is the official dialect.
//!
//! ## Crate layout
//!
//! - [`engine`] — the high-level write / read / inspect / verify / remove API.
//! - [`envelope`] — binary serialization of the 112-byte header and 24-byte
//!   trailer (UBE v2.2 wire format).
//! - [`crypto`] — AES-256-GCM chunked encryption, PBKDF2/HKDF key derivation,
//!   raw-deflate compression, SHA-256 helpers.
//! - [`adapters`] — the [`adapters::HostAdapter`] trait and one implementation
//!   per carrier format (PNG, JPEG, MP4, ZIP, PDF, PE).
//! - [`router`] — format sniffing and strategy name ↔ ID mapping.
//! - [`rejection`] — pre-write safety checks (signed files, read-only targets,
//!   APK, signature containers).
//! - [`errors`] — the single [`errors::StrHideError`] error enum.
//! - [`params`] — library tuning knobs ([`params::LocalParams`]) and private
//!   dialect profiles ([`params::Profile`]).
//! - [`stego`] — content-adaptive image steganography (PNG HILL, JPEG UERD +
//!   ternary STC). Its public surface is re-exported at the crate root:
//!   [`JpegFormatProfile`] / [`DEFAULT_JPEG_FORMAT`] (wire-format identity),
//!   [`JpegParams`] / [`ExtractParams`] (per-call tuning), and
//!   [`embed`] / [`extract`] (the JPEG entry points a private build calls with
//!   its own profile).
//! - [`config`] / [`cli`] / [`analysis`] — internal plumbing for the binary.

extern crate alloc;

pub mod formats;
pub mod sniff;

pub mod crypto;
pub mod errors;
pub mod params;

#[cfg(any(feature = "engine", feature = "stego"))]
pub mod commit;

#[cfg(feature = "engine")]
pub mod adapters;
#[cfg(feature = "engine")]
pub mod engine;
#[cfg(feature = "engine")]
pub mod envelope;
#[cfg(feature = "engine")]
pub mod rejection;
#[cfg(feature = "engine")]
pub mod router;

#[cfg(feature = "stego")]
pub mod jpeg;
#[cfg(feature = "stego")]
pub mod stego;

#[cfg(feature = "cli")]
pub mod analysis;
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub mod cli_i18n;
#[cfg(feature = "cli")]
pub mod config;
#[cfg(feature = "cli")]
pub mod i18n;

#[cfg(feature = "engine")]
pub mod facade;

// Content-domain steganography surface.
#[cfg(feature = "stego")]
pub use stego::format::{
    CipherSuite, DEFAULT_HEVC_FORMAT, DEFAULT_JPEG_FORMAT, GridRule, HevcFormatProfile,
    JpegFormatProfile, OFFICIAL_PNG_FORMAT, PngFormatProfile,
};
#[cfg(feature = "stego")]
pub use stego::jpeg::cost::UerdCostModel;
#[cfg(feature = "stego")]
pub use stego::params::{ExtractParams, JpegParams};
#[cfg(feature = "stego")]
pub use stego::traits::JpegCostModel;
