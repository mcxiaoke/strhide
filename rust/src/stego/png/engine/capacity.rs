//! Spatial domain capacity probing (PNG).

use crate::core::control::{Control, Stage};
use crate::core::crypto::Credential;
use crate::core::media::MediaInfo;
use crate::errors::StrHideError;
use crate::stego::format::{derive_l2_locator_keys, derive_locator_master};
use crate::stego::header::{MAX_EXT_BYTES, Tlv, encode_extension_for_write};
use crate::stego::params::PngParams;
use crate::stego::traits::PngCostModel;
use crate::stego::{StegoCapacityInfo, StegoCodec};

use super::codec::{RawImage, decode_png};
use super::layout::{
    ChannelMode, SlotPlan, exclusion_permille, max_body_slots_within_pipeline, png_pre_salt,
    recommended_bytes_for,
};

/// Would the embedder accept `raw_bytes` on the green or RGB body pool?
///
/// This mirrors the codec/`u` resolution in [`embed_png_with_stats`] exactly:
/// `Auto` (and `Stc` with `stc_u = 0`) re-resolve the group size against each
/// candidate pool, while fixed codecs use the configured group size. Capacity
/// probing and embedding therefore share one accounting rule instead of the
/// probe assuming `u = 1` and the writer using whatever the pool resolves to.
///
/// `total_pixels` feeds the same pipeline-memory budget the embedder enforces
/// in [`check_pipeline_budget`]: a payload whose slots fit the pool but whose
/// working set would exceed [`MAX_PIPELINE_BYTES`] is reported as not fitting,
/// so the probe never advertises a size the writer must refuse.
pub(crate) fn body_payload_fits(
    params: &PngParams,
    pool_green: usize,
    pool_rgb: Option<usize>,
    raw_bytes: usize,
    total_pixels: usize,
) -> Result<bool, StrHideError> {
    let ciphertext_bytes = raw_bytes.saturating_add(crate::stego::envelope::BODY_OVERHEAD);
    let Some(bits) = ciphertext_bytes.checked_mul(8) else {
        return Ok(false);
    };
    for pool in std::iter::once(pool_green).chain(pool_rgb) {
        if pool == 0 {
            continue;
        }
        let (codec, u) = if matches!(params.codec, StegoCodec::Auto)
            || (params.codec == StegoCodec::Stc && params.stc_u == 0)
        {
            crate::stego::coding::auto_select_codec(pool, bits)
        } else {
            match params.codec {
                StegoCodec::Stc => (StegoCodec::Stc, params.stc_u),
                StegoCodec::Hamming => (StegoCodec::Hamming, 0),
                StegoCodec::Auto => unreachable!("handled above"),
            }
        };
        let slots = crate::stego::coding::slots_for_codec(bits, codec, params.stc_h, u)?;
        if slots > pool {
            continue;
        }
        // Same budget rule as the embedder: the trellis bitmap is only
        // charged when the STC codec runs (Hamming has no trellis).
        let trellis_h = match codec {
            StegoCodec::Hamming => None,
            _ => Some(params.stc_h),
        };
        if slots <= max_body_slots_within_pipeline(total_pixels, trellis_h) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Largest raw payload the writer accepts on the given body pools.
///
/// Binary search over `body_payload_fits`, so it uses the *same* slot
/// accounting as the embedder. The previous closed-form inverse assumed
/// `u = 1` and overshot by a few bytes whenever the pool resolved a larger
/// group size or a codec whose warm-up rows do not invert exactly.
pub(crate) fn max_raw_payload_for_pools(
    params: &PngParams,
    pool_green: usize,
    pool_rgb: Option<usize>,
    total_pixels: usize,
) -> Result<usize, StrHideError> {
    let largest_pool = pool_green.max(pool_rgb.unwrap_or(0));
    if largest_pool == 0 {
        return Ok(0);
    }
    // Even the densest codec (Hamming) needs more than one slot per byte of
    // ciphertext, so `8 * slots` is a safe, generous upper bound.
    let mut lo = 0usize;
    let mut hi = largest_pool.saturating_mul(8);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if body_payload_fits(params, pool_green, pool_rgb, mid, total_pixels)? {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Ok(lo)
}

/// Construct the capacity metadata directly from an already computed [`SlotPlan`].
///
/// Shared between embedding and probing so that embedding never has to decode
/// the carrier or recompute the distortion cost map a second time to report capacity.
pub(crate) fn build_png_capacity_with_pools(
    image: &RawImage,
    plan: &SlotPlan,
    params: &PngParams,
    cost_model_id: &str,
    safety_level: crate::stego::SafetyLevel,
) -> Result<(StegoCapacityInfo, usize, Option<usize>), StrHideError> {
    let w = image.width as usize;
    let h = image.height as usize;
    let total_pixels = w * h;

    let header_fits = plan.header_fits();
    let pool_green = if header_fits {
        plan.count_body_slots(image, 1, ChannelMode::Green)
    } else {
        0
    };
    let pool_rgb = (header_fits && image.channels >= 3)
        .then(|| plan.count_body_slots(image, 1, ChannelMode::Rgb));
    let available_body_slots = match pool_rgb {
        Some(rgb) => rgb,
        None => pool_green,
    };
    let ratio_slots = pool_green;

    let max_raw_payload_bytes =
        max_raw_payload_for_pools(params, pool_green, pool_rgb, total_pixels)?;

    let recommended_max_bytes = recommended_bytes_for(total_pixels, ratio_slots, safety_level);
    let hamming_k = crate::stego::coding::DEFAULT_HAMMING_K;
    let tier_limits = crate::params::SafetyLevel::ALL
        .map(|level| recommended_bytes_for(total_pixels, ratio_slots, level));

    let info = StegoCapacityInfo {
        format: "PNG".into(),
        algorithm: cost_model_id.into(),
        total_elements: total_pixels,
        available_slots: available_body_slots,
        max_raw_payload_bytes,
        max_raw_is_grouped: false,
        recommended_max_bytes,
        tier_limits,
        estimated_change_rate: match params.codec {
            StegoCodec::Hamming => crate::stego::coding::expected_change_rate(hamming_k),
            StegoCodec::Stc if params.stc_u > 0 => {
                crate::stego::coding::expected_stc_change_rate(params.stc_u)
            }
            StegoCodec::Stc | StegoCodec::Auto => crate::stego::coding::expected_stc_change_rate(3),
        },
        safety_level: safety_level.as_str().into(),
        safety_bpp_limit: safety_level.bpp_limit(),
        is_estimated: false,
        media_info: Some(MediaInfo::new(image.width, image.height)),
    };
    Ok((info, pool_green, pool_rgb))
}

pub(crate) fn build_png_capacity_info(
    image: &RawImage,
    plan: &SlotPlan,
    params: &PngParams,
    cost_model_id: &str,
    safety_level: crate::stego::SafetyLevel,
) -> Result<StegoCapacityInfo, StrHideError> {
    build_png_capacity_with_pools(image, plan, params, cost_model_id, safety_level)
        .map(|(info, _, _)| info)
}

/// Probe the embedding capacity of a PNG carrier.
///
/// The complete expert entry: `safety_level` picks the tier `recommended_max_bytes`
/// is derived from; `secret`/`domain` key the header-slot permutation, which
/// decides which pixels are available to the payload.
#[allow(clippy::too_many_arguments)]
pub fn probe_png_capacity(
    carrier_bytes: &[u8],
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    safety_level: crate::stego::SafetyLevel,
    cred: Credential<'_>,
    domain: Option<&str>,
    extensions: &[Tlv],
    spatial: &crate::stego::format::PngFormatProfile,
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    params.validate()?;
    // Probe with the same wire-quantised hyperparameters the embedder will
    // use, so the advertised capacity matches the pool embedding sees.
    let params = params.wire_quantized();
    let extension = encode_extension_for_write(extensions)?;
    if extension.len() > MAX_EXT_BYTES {
        return Err(StrHideError::General(format!(
            "Extension area is {} bytes, the maximum is {MAX_EXT_BYTES}",
            extension.len()
        )));
    }
    control.stage(Stage::Decode);
    let image = decode_png(carrier_bytes)?;

    control.stage(Stage::CostMap);
    let costs = cost_model.compute_cost(
        &image.pixels,
        image.width as usize,
        image.height as usize,
        image.channels,
        &params,
    );
    control.check()?;

    // Same credential, carrier identity and extension area as the writer: the
    // header permutation (and therefore the body pool) must match exactly.
    let cipher = spatial.cipher;
    let pre_salt = png_pre_salt(&image, spatial);
    let master = derive_locator_master(cred, domain, cipher, &pre_salt)?;
    let locator = derive_l2_locator_keys(&master, cipher, b"strhide-v4-hdr-magic", domain)?;
    let plan = SlotPlan::build(
        &image,
        &costs,
        &locator.locate_seed,
        extension.len(),
        exclusion_permille(params.exclusion_percentile),
    )?;
    build_png_capacity_info(&image, &plan, &params, cost_model.id(), safety_level)
}
