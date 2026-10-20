//! Unified CLI integration tests suite.

#[path = "common/mod.rs"]
pub mod common;

#[path = "test_cli/batch.rs"]
mod batch;
#[path = "test_cli/config.rs"]
mod config;
#[path = "test_cli/p2.rs"]
mod p2;
#[path = "test_cli/scan.rs"]
mod scan;
#[path = "test_cli/sources.rs"]
mod sources;
#[path = "test_cli/verify.rs"]
mod verify;
