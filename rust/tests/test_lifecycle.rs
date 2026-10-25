//! Unified carrier lifecycle integration tests suite.
//!
//! Submodules:
//! - `matrix`: format-preserving injection & bit-for-bit restore matrix across carriers and strategies.
//! - `stego`: content-adaptive pixel/DCT steganography lifecycle (HILL, UERD, STC).
//! - `stego_v3`: STC-V3 wire-format contract (superblock, extensions, suites, slots).
//! - `compact_meta`: compact metadata envelope encoding on marginal carriers.
//! - `jpeg_multisegment`: multi-segment JPEG APP15 payload splitting.
//! - `unicode_and_binary`: UTF-8/Unicode and arbitrary binary payloads.
//! - `profile`: `LocalParams` / `Profile` plumbing and dialect isolation (M1).
//! - `jpeg_juniward`: J-UNIWARD cost model integration.
//! - `jpeg_polarization`: Cost polarization end-to-end behavior.
//! - `png_self_describing`: PNG self-describing wire format.
//! - `reproducible`: Seeded deterministic embedding reproducibility.
//! - `api_bytes`: In-memory carrier bytes API.
//! - `facade`: StrHide facade integration tests.

#[path = "common/mod.rs"]
pub mod common;

#[path = "test_lifecycle/api_bytes.rs"]
mod api_bytes;
#[path = "test_lifecycle/compact_meta.rs"]
mod compact_meta;
#[path = "test_lifecycle/facade.rs"]
mod facade;
#[path = "test_lifecycle/jpeg_juniward.rs"]
mod jpeg_juniward;
#[path = "test_lifecycle/jpeg_multisegment.rs"]
mod jpeg_multisegment;
#[path = "test_lifecycle/jpeg_polarization.rs"]
mod jpeg_polarization;
#[path = "test_lifecycle/matrix.rs"]
mod matrix;
#[path = "test_lifecycle/png_self_describing.rs"]
mod png_self_describing;
#[path = "test_lifecycle/profile.rs"]
mod profile;
#[path = "test_lifecycle/reproducible.rs"]
mod reproducible;
#[path = "test_lifecycle/stego.rs"]
mod stego;
#[path = "test_lifecycle/stego_v3.rs"]
mod stego_v3;
#[path = "test_lifecycle/unicode_and_binary.rs"]
mod unicode_and_binary;
