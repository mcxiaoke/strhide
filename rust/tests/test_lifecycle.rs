//! Unified carrier lifecycle integration tests suite.
//!
//! Submodules:
//! - `matrix`: format-preserving injection & bit-for-bit restore matrix across carriers and strategies.
//! - `stego`: content-adaptive pixel/DCT steganography lifecycle (HILL, UERD, STC).
//! - `compact_meta`: compact metadata envelope encoding on marginal carriers.
//! - `jpeg_multisegment`: multi-segment JPEG APP15 payload splitting.
//! - `unicode_and_binary`: UTF-8/Unicode and arbitrary binary payloads.

#[path = "common/mod.rs"]
pub mod common;

#[path = "test_lifecycle/compact_meta.rs"]
mod compact_meta;
#[path = "test_lifecycle/jpeg_multisegment.rs"]
mod jpeg_multisegment;
#[path = "test_lifecycle/matrix.rs"]
mod matrix;
#[path = "test_lifecycle/stego.rs"]
mod stego;
#[path = "test_lifecycle/unicode_and_binary.rs"]
mod unicode_and_binary;
