//! HEVC / H.265 content-domain steganography module (Scheme C).
//!
//! Provides in-place Sign Data Hiding (SDH) and CABAC bypass-mode bitstream steganography
//! with zero bitrate expansion (Δ = 0) and zero container structure mutation.

pub mod bitstream;
pub mod engine;
pub mod error;
pub mod heif_boxes;
pub mod slot;
pub mod sniff;

pub use rust_h265 as h265;

pub use bitstream::{HevcNalSpan, compute_hevc_cover_digest, is_epb_safe_flip};
pub use engine::{embed_hevc, extract_hevc, probe_hevc_capacity};
pub use error::{HevcError, Result};
pub use heif_boxes::{HeifHevcTarget, PhysicalNalSpan, parse_heif_targets};
pub use slot::{BinOp, CabacRecorder, StegoSlot};
pub use sniff::{HevcCarrierKind, is_hevc_annexb, sniff_hevc_carrier};
