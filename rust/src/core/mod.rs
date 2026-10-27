//! Cross-domain foundations shared by both engines.
//!
//! `core` holds nothing format-specific: cryptography, the error type, the
//! payload model and the small I/O helpers are consumed identically by the
//! structure domain and the content domain, so they cannot live under either.
//!
//! This module currently holds the pieces stage 1 needed to move out of `cli`
//! -- the message catalogue ([`i18n`], which [`crate::errors`] needs for
//! `category()`) and the TOML settings model ([`config`]) -- plus the stage-2
//! foundations both domains share: [`payload`] (the unified payload type) and
//! [`control`] (progress reporting and cooperative cancellation). The remaining
//! crate-root residents (`crypto`, `errors`, `params`, `commit`) move here in a
//! later batch so each commit stays reviewable.

pub mod control;
pub mod i18n;
pub mod payload;

#[cfg(feature = "config")]
pub mod config;
