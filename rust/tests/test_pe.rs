//! Unified PE carrier strategies integration tests suite.
//!
//! Submodules:
//! - `codebits`: instruction replacement steganography via x86/x64 instruction encoding channel.
//! - `slack`: PE section alignment padding steganography with zero size inflation.

#[path = "common/mod.rs"]
pub mod common;

#[path = "test_pe/codebits.rs"]
mod codebits;
#[path = "test_pe/slack.rs"]
mod slack;
