//! Unified multimedia carriers (HEIF, HEVC) integration tests suite.
//!
//! Submodules:
//! - `heif_stego_bridge`: HEIF carrier unsupported format and safety handling.
//! - `hevc_stego`: HEVC carrier capacity models, roundtrip gradient, and SPS scaling.

#[path = "common/mod.rs"]
pub mod common;

#[path = "test_media/heif_stego_bridge.rs"]
mod heif_stego_bridge;
#[path = "test_media/hevc_stego.rs"]
mod hevc_stego;
