//! Cross-domain foundations shared by both engines.
//!
//! `core` holds nothing format-specific: cryptography, the error type, the
//! payload model and the small I/O helpers are consumed identically by the
//! structure domain and the content domain, so they cannot live under either.
//!
//! Contents:
//!
//! - [`i18n`] — the message catalogue (needed by [`crate::errors`], hence
//!   `core` and not `cli`);
//! - [`payload`] — the unified payload type both domains consume;
//! - [`control`] — progress reporting and cooperative cancellation;
//! - [`media`] — the typed `MediaInfo` used by result structs;
//! - [`fs`] — untrusted-filename sanitization shared by both domains;
//! - [`pipeline`] — batch orchestration (multi-carrier rules, output-path
//!   derivation, preflight), also usable by a GUI or an HTTP service;
//! - [`config`] — the TOML settings model (feature `config`).
//!
//! The remaining crate-root residents (`crypto`, `errors`, `params`, `commit`)
//! move here in a later batch so each commit stays reviewable.

pub mod control;
pub mod fs;
pub mod i18n;
pub mod media;
pub mod payload;
pub mod pipeline;

#[cfg(feature = "config")]
pub mod config;
