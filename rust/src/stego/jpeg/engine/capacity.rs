//! Capacity probing and layout planning for the JPEG engine.
//!
//! These functions only inspect the carrier (decode preflight, geometry,
//! pipeline budget) and never embed; keeping them apart from the embed/extract
//! pipeline makes the resource ceilings easy to audit in one place.

use crate::core::control::{Control, Stage};
use crate::core::crypto::CipherSuiteId;
use crate::core::media::MediaInfo;
use crate::errors::StrHideError;
use crate::stego::StegoCapacityInfo;
use crate::stego::envelope::{BODY_OVERHEAD, build_plaintext_bytes};
use crate::stego::format::JpegFormatProfile;
use crate::stego::header::{MAX_EXT_BYTES, Tlv, encode_extension_for_write};
use crate::stego::jpeg::dht;
use crate::stego::jpeg::v3_layout::{self, Layout};
use crate::stego::params::JpegParams;
use crate::stego::traits::JpegCostModel;

use super::map_dct_error;

/// Safety caps for the JPEG decode/allocation path.
///
/// `MAX_JPEG_MCU_COUNT` mirrors `dct-io 0.1.1`; it is checked here as well so the
/// capacity probe and the embedder reject the same carriers for the same reason.
/// `MAX_JPEG_TOTAL_BLOCKS` is a forward-compatible cap a decoder fork would
/// enforce (six 8x8 blocks per MCU); it is checked here too so a future decoder
/// change cannot make the probe and the embedder disagree.
const MAX_JPEG_MCU_COUNT: usize = 1_048_576;
const MAX_JPEG_TOTAL_BLOCKS: usize = 6_291_456;
/// Whole-pipeline working-set ceiling: coefficients + UERD costs + slot grid +
/// the working copy. The trellis bitmap is checked separately once the layout is
/// known (its size depends on the payload). 8 GiB admits a full-capacity 100 MP
/// baseline grid (about 5.4 GiB) while still rejecting pathological 200+ MP
/// allocations; the uncounted per-block state/slot-mask temporaries are about
/// 0.3 GiB at that size.
const MAX_PIPELINE_BYTES: u64 = 8 << 30;
/// Per-block estimate for the arrays that exist for every carrier:
/// coefficients (128 B), UERD costs (512 B), slot grid (252 B), work copy (128 B).
pub(super) const PIPELINE_BYTES_PER_BLOCK: u64 = 128 + 512 + 63 * 4 + 128;
pub(super) const PIPELINE_FIXED_BYTES: u64 = 64 << 20;

/// Carrier metadata plus the cheap resource estimate, shared by embed, extract
/// and probe so all three paths agree on what the carrier can do.
pub(super) struct CarrierPreflight {
    pub(super) info: dct_io::JpegInfo,
    pub(super) base_bytes: u64,
}

pub(super) fn preflight_jpeg(carrier_bytes: &[u8]) -> Result<CarrierPreflight, StrHideError> {
    let info = dct_io::inspect(carrier_bytes).map_err(map_dct_error)?;
    if info.components.is_empty() {
        return Err(StrHideError::UnsupportedFormat(
            "JPEG has no image components".into(),
        ));
    }
    // The slot grid, the luma cost table and `components_mask` all assume a
    // single luma plane (grayscale) or Y/Cb/Cr. A 4-component CMYK file would
    // silently treat the C plane as luma, so refuse it up front instead of
    // guessing.
    if info.components.len() != 1 && info.components.len() != 3 {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported JPEG variant: {} components (only grayscale and YCbCr are supported)",
            info.components.len()
        )));
    }
    let max_h = info
        .components
        .iter()
        .map(|c| c.h_samp as usize)
        .max()
        .unwrap_or(1)
        .max(1);
    let max_v = info
        .components
        .iter()
        .map(|c| c.v_samp as usize)
        .max()
        .unwrap_or(1)
        .max(1);
    let mcu_cols = (info.width as usize).div_ceil(max_h * 8);
    let mcu_rows = (info.height as usize).div_ceil(max_v * 8);
    let mcu_count = mcu_cols.checked_mul(mcu_rows).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unsupported JPEG variant: image dimensions overflow the MCU count".into(),
        )
    })?;
    if mcu_count > MAX_JPEG_MCU_COUNT {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported JPEG variant: image too large ({mcu_count} MCUs; max {MAX_JPEG_MCU_COUNT})"
        )));
    }
    let total_blocks: usize = info.components.iter().map(|c| c.block_count).sum();
    if total_blocks > MAX_JPEG_TOTAL_BLOCKS {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported JPEG variant: image too large ({total_blocks} 8x8 blocks; max {MAX_JPEG_TOTAL_BLOCKS})"
        )));
    }
    let base_bytes =
        PIPELINE_FIXED_BYTES.saturating_add(total_blocks as u64 * PIPELINE_BYTES_PER_BLOCK);
    if base_bytes > MAX_PIPELINE_BYTES {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported JPEG variant: image needs about {} MiB of working memory; the {} MiB budget would be exceeded",
            base_bytes >> 20,
            MAX_PIPELINE_BYTES >> 20
        )));
    }
    Ok(CarrierPreflight { info, base_bytes })
}

/// Backtracking-bitmap size for a body of `body_n` slots at height `h`.
fn estimate_backtrack_bytes(body_n: usize, h: u8) -> u64 {
    crate::stego::coding::backtrack_bitmap_bytes(body_n, h)
}

pub(super) fn check_pipeline_budget(
    base_bytes: u64,
    body_n: usize,
    h: u8,
) -> Result<(), StrHideError> {
    let total = base_bytes.saturating_add(estimate_backtrack_bytes(body_n, h));
    if total > MAX_PIPELINE_BYTES {
        return Err(StrHideError::PayloadTooLarge(format!(
            "This payload needs about {} MiB of working memory; the {} MiB budget would be exceeded (use a smaller payload or a smaller --stc-h)",
            total >> 20,
            MAX_PIPELINE_BYTES >> 20
        )));
    }
    Ok(())
}

/// Body slots whose backtracking bitmap still fits the pipeline budget.
///
/// The probe has to subtract the same bitmap cost `check_pipeline_budget`
/// charges the embedder; otherwise a very large grid advertises tens of MB
/// that the writer can never actually allocate.
fn max_body_slots_within_pipeline(base_bytes: u64, h: u8) -> usize {
    let states = 1u64 << h.min(10);
    let words_per_col = states.div_ceil(64);
    let bytes_per_slot = words_per_col * 8;
    let remaining = MAX_PIPELINE_BYTES.saturating_sub(base_bytes);
    usize::try_from(remaining / bytes_per_slot).unwrap_or(usize::MAX)
}

/// Payload ceiling the safety tier recommends for this coefficient grid.
///
/// The single source of truth for both the embed-time enforcement and the
/// capacity probe; they used to spell the same two lines out separately.
fn recommended_bytes(
    total_coeffs: usize,
    body_slots: usize,
    level: crate::params::SafetyLevel,
) -> usize {
    let bpp_bits = (total_coeffs as f64 * level.bpp_limit()).floor() as usize;
    let ratio_bits = (body_slots as f64 / level.target_ratio()).floor() as usize;
    (bpp_bits.min(ratio_bits) / 8).saturating_sub(BODY_OVERHEAD)
}

pub(super) fn enforced_payload_limit(
    total_coeffs: usize,
    body_slots: usize,
    safety: crate::stego::params::SafetyPolicy,
) -> usize {
    recommended_bytes(total_coeffs, body_slots, safety.level)
}

/// Shared capacity builder so that embedding never has to decode
/// the carrier or parse DHT/geometry a second time to report capacity.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_jpeg_capacity_info(
    info: &dct_io::JpegInfo,
    base_bytes: u64,
    has_incomplete_table: bool,
    cost_model: &dyn JpegCostModel,
    params: &JpegParams,
    safety_level: crate::stego::SafetyLevel,
    fmt: &JpegFormatProfile,
    extension: &[u8],
) -> Result<StegoCapacityInfo, StrHideError> {
    let geom = crate::stego::jpeg::geometry::component_geometry(info, 0, 0);
    let block_count = geom.grid_w * geom.grid_h;
    let n_total = block_count * fmt.grid_rule.slots_per_block();
    let ext_bytes = extension.len();
    let hdr_n = fmt.header_slots(ext_bytes);
    if n_total <= hdr_n {
        return Err(StrHideError::PayloadTooLarge(format!(
            "Capacity exceeded: header needs {hdr_n} slots, the carrier grid has {n_total}"
        )));
    }
    let body_slots = n_total - hdr_n;
    // The writer charges the trellis bitmap against the same 8 GiB pipeline
    // budget; a probe that ignored it advertised capacities the embedder
    // rejects outright.
    let body_slots = body_slots.min(max_body_slots_within_pipeline(base_bytes, params.stc_h));

    // The physical ceiling is `u = 1`; `u` grows from there as the payload
    // shrinks, so this is the largest payload that fits at all.
    let mut max_bits = v3_layout::max_payload_bits(body_slots, params.stc_h);
    let mut max_raw_is_grouped = false;
    // ... unless the carrier's Huffman table is over-optimised. `u = 1` then
    // has no routing freedom around dead slots and cross-zero chains, and
    // `u = 2` still fails often enough to be a coin flip at these loads, so
    // the embedder requires `u = 3` (`embed_once`) and the grouped bound is
    // the real ceiling. Reporting the geometric one here would advertise a
    // capacity that always fails.
    if has_incomplete_table {
        let room = body_slots.min(crate::stego::params::max_grouped_backtrack_slots(
            params.stc_h,
        ));
        let grouped_bits = (room / 3).saturating_sub(params.stc_h as usize - 1);
        if grouped_bits < max_bits {
            max_bits = grouped_bits;
            max_raw_is_grouped = true;
        }
    }
    let max_ciphertext_bytes = max_bits / 8;
    let max_raw_payload_bytes = max_ciphertext_bytes.saturating_sub(BODY_OVERHEAD);

    let total_coeffs = block_count * 64;
    let effective_budget = params.effective_slot_budget(body_slots);

    let recommended_max_bytes = recommended_bytes(total_coeffs, body_slots, safety_level);
    let tier_limits = crate::params::SafetyLevel::ALL
        .map(|level| recommended_bytes(total_coeffs, body_slots, level));

    // Report the change rate of the group size the recommended payload would
    // actually use, which is what the user sees if they follow the advice.
    let recommended_bits = (recommended_max_bytes + BODY_OVERHEAD) * 8;
    let u = v3_layout::compute(
        n_total,
        hdr_n,
        recommended_bits,
        params.stc_h,
        effective_budget,
    )
    .map(|layout| layout.u)
    .unwrap_or(1);

    Ok(StegoCapacityInfo {
        format: "JPEG".into(),
        algorithm: cost_model.id().into(),
        total_elements: total_coeffs,
        available_slots: body_slots,
        max_raw_payload_bytes,
        max_raw_is_grouped,
        recommended_max_bytes,
        tier_limits,
        estimated_change_rate: crate::stego::coding::expected_stc_change_rate(u),
        safety_level: safety_level.as_str().into(),
        safety_bpp_limit: safety_level.bpp_limit(),
        is_estimated: false,
        media_info: Some(MediaInfo::new(
            u32::from(info.width),
            u32::from(info.height),
        )),
    })
}

/// Probe the embedding capacity of a JPEG carrier.
///
/// The complete expert entry: `safety_level` picks the tier `recommended_max_bytes`
/// is derived from, `fmt` supplies the grid geometry the budget is measured
/// against.
pub fn probe_jpeg_capacity(
    carrier_bytes: &[u8],
    cost_model: &dyn JpegCostModel,
    params: &JpegParams,
    extensions: &[Tlv],
    safety_level: crate::stego::SafetyLevel,
    fmt: &JpegFormatProfile,
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    fmt.validate()?;
    params.validate()?;
    control.stage(Stage::Decode);
    control.check()?;
    let extension = encode_extension_for_write(extensions)?;
    if extension.len() > MAX_EXT_BYTES {
        return Err(StrHideError::General(format!(
            "Extension area is {} bytes, the maximum is {MAX_EXT_BYTES}",
            extension.len()
        )));
    }
    let preflight = preflight_jpeg(carrier_bytes)?;
    let has_incomplete_table =
        dht::luma_ac_symbols(carrier_bytes).is_some_and(|t| !t.is_complete());
    build_jpeg_capacity_info(
        &preflight.info,
        preflight.base_bytes,
        has_incomplete_table,
        cost_model,
        params,
        safety_level,
        fmt,
        &extension,
    )
}

/// Layout information for diagnostics and tests: the resolved group size and
/// body slot count for a given payload.
///
/// Takes the payload bytes, not just its length: [`crate::stego::envelope::build_plaintext`] deflates
/// the payload whenever that is smaller, and the ciphertext length (plaintext +
/// AEAD tag, the suite comes from `params.cipher_suite`) is what actually
/// decides `u`. A length-only API reported the layout of an uncompressed
/// envelope -- exactly the case where the real writer picks a larger `u`.
pub fn layout_for_payload(
    carrier_bytes: &[u8],
    payload: &[u8],
    suite_id: u16,
    extensions: &[Tlv],
    params: &JpegParams,
    fmt: &JpegFormatProfile,
) -> Result<Layout, StrHideError> {
    fmt.validate()?;
    params.validate()?;
    let suite = CipherSuiteId::from_u16(suite_id).ok_or_else(|| {
        StrHideError::UnsupportedVersion(format!(
            "Cipher suite {suite_id} is not implemented by this build"
        ))
    })?;
    let preflight = preflight_jpeg(carrier_bytes)?;
    let coeffs = dct_io::read_coefficients(carrier_bytes).map_err(map_dct_error)?;
    if coeffs.components.is_empty() {
        return Err(StrHideError::UnsupportedFormat(
            "JPEG has no image components".into(),
        ));
    }
    let block_count = coeffs.components[0].blocks.len();
    let n_total = block_count * fmt.grid_rule.slots_per_block();
    let ext_bytes = encode_extension_for_write(extensions)?.len();
    let hdr_n = fmt.header_slots(ext_bytes);
    let plaintext = build_plaintext_bytes(payload)?;
    let ciphertext_len = plaintext.len() + suite.tag_len();
    let body_slots = n_total.saturating_sub(hdr_n);
    let effective_budget = params.effective_slot_budget(body_slots);
    let bits = ciphertext_len * 8;
    // Same grouped floor the embedder applies: report the layout the embed
    // will actually use, not the one the distortion heuristic alone picks.
    let budget = if dht::luma_ac_symbols(carrier_bytes).is_some_and(|t| !t.is_complete()) {
        crate::stego::params::grouped_body_budget(body_slots, bits, params.stc_h, effective_budget)
            .ok_or_else(|| {
                StrHideError::PayloadTooLarge(
                    "Payload too large for this carrier: its over-optimised Huffman table forces a less dense encoding (u >= 3) and the payload does not fit. Reduce the payload or re-save the carrier with a standard (Annex K) table.".into(),
                )
            })?
    } else {
        effective_budget
    };
    let layout = v3_layout::compute(n_total, hdr_n, bits, params.stc_h, budget)?;
    check_pipeline_budget(preflight.base_bytes, layout.body_n, params.stc_h)?;
    Ok(layout)
}
