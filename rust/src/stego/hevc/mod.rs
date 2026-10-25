//! HEVC / H.265 content-domain steganography module (Scheme C).
//!
//! Provides in-place Sign Data Hiding (SDH) and CABAC bypass-mode bitstream steganography
//! with zero bitrate expansion (Δ = 0) and zero container structure mutation.
//!
//! The public surface is the three engine entries below; the parsing, slot and
//! CABAC-recording internals are implementation details reachable by path but
//! undocumented.

#[doc(hidden)]
pub mod bitstream;
pub mod engine;
#[doc(hidden)]
pub mod error;
#[doc(hidden)]
pub mod heif_boxes;
#[doc(hidden)]
pub mod slot;
#[doc(hidden)]
pub mod sniff;

pub use engine::{
    embed_hevc, extract_hevc, extract_hevc_dimensions, probe_hevc_capacity,
    probe_hevc_capacity_info,
};
