//! Unified regression, bug fixes, protocol edge-cases, and real samples test suite.
//!
//! Submodules:
//! - `fixes`: regression tests for historic fixes (dirty tails, EOCD spoofing, etc.).
//! - `p2_fixes`: error propagation and corruption detection across carriers.
//! - `p2_protocol`: protocol-level envelope validation and PDF xref streams.
//! - `review_20261019`: edge cases and security boundaries regression tests.
//! - `review_20261025`: structure-domain regression tests.
//! - `review_20261030`: box-size overflow, decoy EOCD, and patch spans regression tests.
//! - `review_20261031`: central-directory slice bounds and cancel-token regression tests.
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
#[path = "test_regression/review_20261025.rs"]
mod review_20261025;
#[path = "test_regression/review_20261030.rs"]
mod review_20261030;
#[path = "test_regression/review_20261031.rs"]
mod review_20261031;
