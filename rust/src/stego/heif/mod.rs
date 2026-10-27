//! HEIF/HEIC content-domain bridge steganography module.
//!
//! Bridges embedded JPEG thumbnails or uncompressed auxiliary items within ISO BMFF containers
//! to existing content-adaptive steganography engines (`stego::jpeg` and `stego::png`).
//!
//! The primary HEVC/AVIF photo stream remains 100% bit-exact and untouched.

#[cfg(feature = "content-heif-bridge")]
pub mod thumb_bridge;

#[cfg(feature = "content-heif-bridge")]
pub use thumb_bridge::{
    BridgeTarget, BridgeTargetKind, embed_heif_bridge, extract_heif_bridge,
    probe_heif_bridge_capacity,
};
