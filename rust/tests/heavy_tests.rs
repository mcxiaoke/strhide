//! Unified heavy, corpus-level stress and forensic evaluation test suite.
//!
//! All tests in this suite are ignored by default and named with `heavy_` prefix.
//! Run with:
//! ```text
//! cargo test --release --test heavy_tests -- --ignored --nocapture
//! # or run a specific subset:
//! cargo test heavy_all_algorithms -- --ignored --nocapture
//! cargo test heavy_hevc_mp4 -- --ignored --nocapture
//! cargo test heavy_batch_stego -- --ignored --nocapture
//! cargo test heavy_stego_evaluation -- --ignored --nocapture
//! ```

#[path = "heavy/heavy_algorithm_matrix.rs"]
pub mod heavy_algorithm_matrix;
#[path = "heavy/heavy_coexistence.rs"]
pub mod heavy_coexistence;
#[path = "heavy/heavy_media.rs"]
pub mod heavy_media;
#[path = "heavy/heavy_stego.rs"]
pub mod heavy_stego;
