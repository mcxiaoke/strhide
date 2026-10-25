//! Unified local-only, large-corpus, slow-evaluation and benchmark test suite.
//!
//! All tests in this suite are ignored by default and named with `local_` prefix.
//! Run with:
//! ```text
//! cargo test --release --test local_tests -- --ignored --nocapture
//! # or run a specific subset:
//! cargo test local_batch_corpus -- --ignored --nocapture
//! cargo test local_batch_stego -- --ignored --nocapture
//! cargo test local_media -- --ignored --nocapture
//! cargo test local_bench -- --ignored --nocapture
//! ```

#[path = "common/mod.rs"]
pub mod common;

#[path = "local/local_bench.rs"]
pub mod local_bench;
#[path = "local/local_corpus.rs"]
pub mod local_corpus;
#[path = "local/local_media.rs"]
pub mod local_media;
#[path = "local/local_stego.rs"]
pub mod local_stego;
