//! Unified regression, bug fixes, protocol edge-cases, and real samples test suite.
//!
//! Submodules:
//! - `fixes`: regression tests for historic fixes (dirty tails, EOCD spoofing, etc.).
//! - `p2_fixes`: error propagation and corruption detection across carriers.
//! - `p2_protocol`: protocol-level envelope validation and PDF xref streams.
//! - `review_20261019`: findings lockdown from comprehensive code reviews.
//! - `real_samples`: integration checks against real-world media and executable files.

#[path = "common/mod.rs"]
pub mod common;

#[path = "test_regression/fixes.rs"]
mod fixes;
#[path = "test_regression/p2_fixes.rs"]
mod p2_fixes;
#[path = "test_regression/p2_protocol.rs"]
mod p2_protocol;
#[path = "test_regression/real_samples.rs"]
mod real_samples;
#[path = "test_regression/review_20261019.rs"]
mod review_20261019;
