//! HEVC / H.265 In-place CABAC Bypass Steganography Engine (Scheme C).
//!
//! Provides zero bitrate expansion (Δ = 0), content-adaptive distortion-minimized
//! steganographic embedding and extraction directly within H.265/HEVC bitstreams.

#[cfg(test)]
pub(crate) use super::superblock::HEVC_HEADER_SLOTS_MAX;
#[cfg(test)]
pub(crate) use super::superblock::HEVC_MAX_EXT_BYTES;
#[cfg(test)]
use super::superblock::HEVC_V4_CRC_SPAN;
#[cfg(test)]
use super::superblock::hevc_header_slots;
pub(crate) use super::superblock::superblock_positions;
#[cfg(test)]
pub(crate) use super::superblock::{
    HEVC_SUPERBLOCK_BYTES, HEVC_SUPERBLOCK_MIN_SLOTS, hevc_extension_slots,
};
pub use super::superblock::{HEVC_SUPERBLOCK_POOL_SLOTS, HevcSuperblockV4};

#[cfg(test)]
use crate::core::control::Control;
#[cfg(test)]
use crate::core::crypto::{CipherSuiteId, Credential};
#[cfg(test)]
use crate::core::payload::Payload;
#[cfg(test)]
use crate::errors::StrHideError;
#[cfg(test)]
use crate::stego::SafetyPolicy;
#[cfg(test)]
use crate::stego::coding::StcTrellis;
#[cfg(test)]
use crate::stego::envelope::BODY_OVERHEAD;
#[cfg(test)]
use crate::stego::envelope::{
    Freshness, build_plaintext, build_v4_aad_with, encrypt_v4_with_aad, unpack_v4_envelope_parts,
};
#[cfg(test)]
use crate::stego::format::{derive_l2_locator_keys, derive_locator_master};
#[cfg(test)]
use crate::stego::header::{CONTENT_ENVELOPE_VERSION, FLAG_EXT_PRESENT};
#[cfg(test)]
use crate::stego::hevc::sniff::{
    NAL_RASL_N, NAL_RASL_R, NAL_TRAIL_N, NAL_TSA_N, sniff_hevc_carrier,
};
#[cfg(test)]
use crate::stego::params::ExtractParams;
#[cfg(test)]
use capacity::enforce_safety;
#[cfg(test)]
use embed::validate_hevc_patches;
#[cfg(test)]
use inspect::sample_prefix_has_inter;
#[cfg(test)]
use record::record_carrier_state;
#[cfg(test)]
use scan::{BAND_NON_REFERENCE, BAND_REFERENCE, BitPacker, bit_at, picture_band};
#[cfg(test)]
use scan::{Capture, CarrierRecord, DigestInputs, active_parameter_sets, is_non_reference_vcl};
#[cfg(test)]
use std::collections::HashSet;
#[cfg(test)]
use support::hevc_max_raw_payload;
#[cfg(test)]
use support::hevc_window_target_slots;
#[cfg(test)]
use support::{
    HEVC_FORMAT_ID, StopCondition, band_positions, legacy_credential, tags_have_critical,
};

mod capacity;
mod embed;
mod extract;
mod inspect;
mod layout;
mod record;
mod reencode;
mod scan;
mod support;
mod verify;

pub use capacity::{
    extract_hevc_dimensions, probe_hevc_capacity, probe_hevc_capacity_ext, probe_hevc_capacity_info,
};
pub use embed::{
    HevcCarrierPatch, apply_hevc_patches, embed_hevc, embed_hevc_patches_with_factor,
    embed_hevc_with_info, embed_hevc_with_info_v4,
};
pub(crate) use embed::{embed_hevc_patches, embed_hevc_patches_v4};
pub use extract::{extract_hevc, extract_hevc_v4};
pub(crate) use inspect::{
    inspect_hevc, inspect_hevc_mp4_file, inspect_hevc_mp4_file_v4, inspect_hevc_v4,
};
pub use layout::EmbedPeakEstimate;
pub(crate) use layout::{EMBED_WINDOW_GOPS, embed_window_bytes, estimate_embed_peak_bytes};
pub use record::{ScanStats, bench_scan_slices};
pub(crate) use verify::{verify_hevc, verify_hevc_v4};

#[cfg(test)]
#[path = "tests/capture_tests.rs"]
mod capture_tests;

#[cfg(test)]
#[path = "tests/dialect_tests.rs"]
mod dialect_tests;

/// Regression tests for the safety-policy gate: verify that `--enforce-safety`
/// blocks appropriately on the HEVC path.
#[cfg(test)]
#[path = "tests/safety_policy_tests.rs"]
mod safety_policy_tests;

#[cfg(test)]
#[path = "tests/annex_b_parameter_set_tests.rs"]
mod annex_b_parameter_set_tests;

/// Regression test: the writer's decode window must never fall below the
/// reader's fixed `HEVC_SUPERBLOCK_POOL_SLOTS` header pool.
#[cfg(test)]
#[path = "tests/window_tests.rs"]
mod window_tests;

#[cfg(test)]
#[path = "tests/v4_superblock_tests.rs"]
mod v4_superblock_tests;

#[cfg(test)]
#[path = "tests/mkv_crc_tests.rs"]
mod mkv_crc_tests;
