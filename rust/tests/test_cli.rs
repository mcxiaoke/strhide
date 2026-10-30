//! Unified CLI integration tests suite.
//!
//! The whole binary is gated on the `cli` feature: the library's default
//! feature set deliberately excludes the command line (clap/toml/rpassword),
//! so `cargo test` on the defaults builds an empty binary here. CI runs
//! `cargo test --all-features` to cover it.
#![cfg(feature = "cli")]

#[path = "common/mod.rs"]
pub mod common;

#[path = "test_cli/batch.rs"]
mod batch;
#[path = "test_cli/cli_unification.rs"]
mod cli_unification;
#[path = "test_cli/config.rs"]
mod config;
#[path = "test_cli/domains.rs"]
mod domains;
#[path = "test_cli/i18n.rs"]
mod i18n;
#[path = "test_cli/p2.rs"]
mod p2;
#[path = "test_cli/scan.rs"]
mod scan;
#[path = "test_cli/sources.rs"]
mod sources;
#[path = "test_cli/verify.rs"]
mod verify;
