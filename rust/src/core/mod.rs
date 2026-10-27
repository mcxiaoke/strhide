//! Cross-domain foundations shared by both engines.
//!
//! `core` holds nothing format-specific: cryptography, the error type, the
//! payload model and the small I/O helpers are consumed identically by the
//! structure domain and the content domain, so they cannot live under either.
//!
//! This module currently holds the pieces stage 1 needed to move out of `cli`:
//! the message catalogue ([`i18n`], which [`crate::errors`] needs for
//! `category()`) and the TOML settings model ([`config`]). Stage 2 moves
//! `crypto`, `errors`, `params` and `commit` here as well; they stay at the
//! crate root until then so this commit stays reviewable.

pub mod i18n;

#[cfg(feature = "config")]
pub mod config;
