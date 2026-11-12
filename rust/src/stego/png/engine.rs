//! Spatial domain steganographic embedding and extraction engine (PNG).
//!
//! Uses content-adaptive distortion costs (e.g. HILL) to isolate complex texture
//! and noisy regions, completely avoiding smooth areas.
//!
//! # Embedding operation
//!
//! Bits are written by **ternary `±1` matching**: a slot whose LSB must change
//! moves to `val + 1` or `val - 1`, whichever is cheaper and legal, instead of
//! having its LSB replaced. Both directions flip the LSB, so the payload bit is
//! still the slot's parity and extraction is unchanged.

#[path = "codec.rs"]
mod codec;

pub use codec::{IdatInfo, PngChunk, RawImage, decode_png, encode_png};

mod capacity;
mod embed;
mod extract;
mod inspect;
mod layout;

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;

pub use capacity::probe_png_capacity;
pub use embed::embed_png;
pub(crate) use embed::embed_png_with_stats;
pub use extract::extract_png;
pub(crate) use inspect::{inspect_png, verify_png};
pub use layout::png_pre_salt;

/// Inclusive range of pixel values the spatial engine may embed into.
///
/// The bounds are the class-interior rule: from a value in `[8, 247]` at least
/// one of `val ± 1` stays inside the same eight-value class, and no move can
/// reach 0 or 255. Both the writer and the extractor must use this range
/// verbatim; it is exported so tests can assert against the same constant
/// instead of re-typing the bounds.
pub const SPATIAL_ELIGIBLE_MIN: u8 = 8;
pub const SPATIAL_ELIGIBLE_MAX: u8 = 247;

/// `format_id` written into the V4 content envelope for PNG carriers.
pub(crate) const PNG_FORMAT_ID: u8 = 1;

#[cfg(test)]
pub(crate) use capacity::{body_payload_fits, max_raw_payload_for_pools};
#[cfg(test)]
use codec::{choose_deflate_level, deflate_len, filter_row, write_chunk};
#[cfg(test)]
pub(crate) use extract::png_keys;
#[cfg(test)]
pub(crate) use layout::{
    ChannelMode, SlotPlan, check_pipeline_budget, embed_channel, exclusion_permille, header_layout,
    header_pool, max_body_slots_within_pipeline, read_slot_bytes,
};
