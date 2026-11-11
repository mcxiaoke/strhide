//! HEVC / H.265 In-place CABAC Bypass Steganography Engine (Scheme C).
//!
//! Provides zero bitrate expansion (Δ = 0), content-adaptive distortion-minimized
//! steganographic embedding and extraction directly within H.265/HEVC bitstreams.

use std::collections::{BTreeMap, HashSet};

use crate::core::control::{Control, Event, Stage};
use crate::core::crypto::{CONTENT_L1_PBKDF2_ITERATIONS, CipherSuiteId, Credential};
use crate::core::media::MediaInfo;
use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::stego::coding::{Move, StcTrellis};
use crate::stego::envelope::{
    BODY_OVERHEAD, Freshness, build_plaintext, build_v4_aad_with, encrypt_v4_with_aad,
    unpack_v4_envelope_parts,
};
use crate::stego::format::{
    HevcFormatProfile, derive_l2_locator_keys, derive_l3_session_keys, derive_locator_master,
};
use crate::stego::header::{
    CONTENT_ENVELOPE_VERSION, FLAG_EXT_CRITICAL, FLAG_EXT_PRESENT, Tlv, encode_extension_for_write,
    parse_extension, validate_ext_critical_flag,
};
use crate::stego::hevc::bitstream::{parse_annex_b_spans, rbsp_to_nal};
use crate::stego::hevc::heif_boxes::parse_heif_targets;
use crate::stego::hevc::mkv_boxes::refresh_mkv_crcs;
use crate::stego::hevc::mp4_boxes::parse_mp4_targets;
use crate::stego::hevc::slot::{CabacRecorder, RecordMode, SubstreamRecord};
use crate::stego::hevc::sniff::{HevcCarrierKind, NAL_SPS_NUT, sniff_hevc_carrier};
use crate::stego::options::{StegoHeaderInfo, StegoVerifyResult, VerifyLevel};
use crate::stego::params::ExtractParams;
use crate::stego::{SafetyLevel, SafetyPolicy, StegoCapacityInfo};
use oxideav_h265::cabac::ContextModel;
use oxideav_h265::encoder::bitwriter::BitWriter;
use oxideav_h265::encoder::cabac::CabacEncoder;
use rayon::prelude::*;
use rusty_h265::Decoder;
use rusty_h265::ctu::Ablate;
use rusty_h265::observer::ENCODER_CONTEXTS;
use rusty_h265::ps::parse_sps;

#[cfg(test)]
pub(crate) use super::superblock::HEVC_HEADER_SLOTS_MAX;
#[cfg(test)]
pub(crate) use super::superblock::HEVC_MAX_EXT_BYTES;
#[cfg(test)]
use super::superblock::HEVC_V4_CRC_SPAN;
pub(crate) use super::superblock::{
    HEVC_EXT_STC_H, HEVC_EXT_STC_U, HEVC_SUPERBLOCK_BYTES, HEVC_SUPERBLOCK_MIN_SLOTS,
    hevc_extension_slots, superblock_positions,
};
pub use super::superblock::{HEVC_SUPERBLOCK_POOL_SLOTS, HevcSuperblockV4};
use super::superblock::{hevc_header_slots, keyed_band_params};
#[cfg(test)]
use crate::stego::hevc::sniff::{NAL_RASL_N, NAL_RASL_R, NAL_TRAIL_N, NAL_TSA_N};
#[cfg(test)]
use scan::{BAND_NON_REFERENCE, BAND_REFERENCE, BitPacker, bit_at};
#[cfg(test)]
use scan::{active_parameter_sets, is_non_reference_vcl};

mod layout;
mod record;
mod scan;
mod support;

pub use layout::EmbedPeakEstimate;
pub(crate) use layout::{EMBED_WINDOW_GOPS, embed_window_bytes, estimate_embed_peak_bytes};
pub use record::{ScanStats, bench_scan_slices};
use record::{record_carrier_state, record_carrier_state_with_capacity};
use scan::{
    Capture, CarrierRecord, DigestInputs, PoolProfile, SliceContext, SlotSink, absorb_recorder,
    candidate_slice, count_pictures, derive_carrier_digest, drain_frames, is_irap,
    owned_parameter_sets, picture_band, scan_hevc_slot_count,
};
use support::{
    CAPACITY_PROBE_SEED, EpbConflict, FORBIDDEN_SLOT_SURCHARGE, HEVC_FORMAT_ID, MAX_EMBED_ROUNDS,
    SlotBitTrace, StopCondition, check_l1_floor, extension_len, get_body_slot_indices,
    has_critical_tlv, hevc_max_raw_payload, hevc_session_salt, hevc_window_target_slots,
    legacy_credential, nal_header_fields, nal_rbsp, tags_have_critical,
};

/// Capacity probe: maximum embeddable payload size in bytes, without extensions.
pub fn probe_hevc_capacity(carrier: &[u8], fmt: &HevcFormatProfile) -> Result<usize, StrHideError> {
    probe_hevc_capacity_ext(carrier, &[], fmt)
}

/// Capacity probe with the same extension area the writer will use.
///
/// The `ext_len` is the decisive part of `probe == embed`: a probe that ignores
/// the extension slots advertises bytes the writer cannot place.
pub fn probe_hevc_capacity_ext(
    carrier: &[u8],
    extensions: &[Tlv],
    fmt: &HevcFormatProfile,
) -> Result<usize, StrHideError> {
    sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;
    let ext_len = extension_len(extensions)?;
    let total_slots = scan_hevc_slot_count(carrier)?;
    hevc_max_raw_payload(total_slots, ext_len, fmt)
}

/// Cropped output geometry of an SPS in luma samples (§7.4.3.2.1).
///
/// `rusty_h265` reports the coded size plus the conformance-window offsets in
/// chroma units; the crop is scaled by `SubWidthC`/`SubHeightC` (Table 6-1).
/// For 4:2:0 — every carrier this engine accepts — that is 2/2.
fn sps_dimensions(rbsp: &[u8]) -> Option<(u32, u32)> {
    let sps = parse_sps(rbsp).ok()?;
    let (sub_w, sub_h): (u32, u32) = match sps.chroma_format_idc {
        1 => (2, 2),
        2 => (2, 1),
        _ => (1, 1),
    };
    let crop_w = sub_w.saturating_mul(sps.conf_win[0].saturating_add(sps.conf_win[1]));
    let crop_h = sub_h.saturating_mul(sps.conf_win[2].saturating_add(sps.conf_win[3]));
    Some((
        sps.width.saturating_sub(crop_w),
        sps.height.saturating_sub(crop_h),
    ))
}

/// Extracts the picture dimensions `(width, height)` in luma samples from the carrier's SPS.
pub fn extract_hevc_dimensions(carrier: &[u8]) -> Result<(u32, u32), StrHideError> {
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;

    match kind {
        HevcCarrierKind::HeifContainer => {
            let target = parse_heif_targets(carrier)
                .map_err(|e| StrHideError::UnsupportedFormat(format!("HEIF parse error: {e}")))?;
            if let Some(dims) = target.dimensions {
                return Ok(dims);
            }
            for ps in &target.parameter_sets {
                if ps.len() > 2
                    && (ps[0] >> 1) & 0x3F == NAL_SPS_NUT
                    && let Some(dims) = sps_dimensions(&nal_rbsp(ps))
                {
                    return Ok(dims);
                }
            }
        }
        HevcCarrierKind::AnnexBStream => {
            let spans = parse_annex_b_spans(carrier);
            for span in &spans {
                if span.nal_type == NAL_SPS_NUT {
                    let end = span.end_offset().min(carrier.len());
                    let nal = &carrier[span.header_offset..end];
                    if nal.len() > 2
                        && let Some(dims) = sps_dimensions(&nal_rbsp(nal))
                    {
                        return Ok(dims);
                    }
                }
            }
        }
        // MP4 and MKV both carry the authoritative SPS in their
        // `HEVCDecoderConfigurationRecord`, so they share this arm.
        HevcCarrierKind::Mp4Container | HevcCarrierKind::MkvContainer => {
            let parameter_sets = match kind {
                HevcCarrierKind::MkvContainer => {
                    crate::stego::hevc::mkv_boxes::parse_mkv_parameter_sets(carrier).map_err(
                        |e| StrHideError::UnsupportedFormat(format!("MKV parse error: {e}")),
                    )?
                }
                _ => {
                    parse_mp4_targets(carrier)
                        .map_err(|e| {
                            StrHideError::UnsupportedFormat(format!("MP4/MOV parse error: {e}"))
                        })?
                        .parameter_sets
                }
            };
            // The sample entries carry no size of their own that can be
            // trusted (they duplicate the SPS, and some writers leave them
            // wrong); the `hvcC` SPS is the same one the decoder will use.
            for ps in &parameter_sets {
                if ps.len() > 2
                    && (ps[0] >> 1) & 0x3F == NAL_SPS_NUT
                    && let Some(dims) = sps_dimensions(&nal_rbsp(ps))
                {
                    return Ok(dims);
                }
            }
        }
    }

    Err(StrHideError::General(
        "No valid SPS found in HEVC carrier".into(),
    ))
}

/// Full capacity probe returning structured [`StegoCapacityInfo`], with recommended
/// payload capacity scaled by the caller's [`SafetyLevel`] and carrier dimensions.
///
/// If `exact` is false, carriers with >150 selectable slices employ fast 20%
/// sample-weighted estimation to deliver sub-second probe responses.
pub fn probe_hevc_capacity_info(
    carrier: &[u8],
    extensions: &[Tlv],
    fmt: &HevcFormatProfile,
    safety_level: SafetyLevel,
    exact: bool,
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;
    let ext_len = extension_len(extensions)?;
    control.stage(Stage::Decode);
    let pool = probe_hevc_pool(carrier, kind, exact, control)?;
    // The pool scan is the long part of an exact probe; report before the
    // (cheap) summary is built so a cancellation lands after the scan, not
    // silently in the middle of it.
    control.check()?;
    build_hevc_capacity_info(carrier, kind, fmt, &pool, ext_len, safety_level)
}

fn count_absorbed_slots(recorder: &mut CabacRecorder, rbsp: &[u8]) -> usize {
    let is_multi_sub = recorder.substreams.len() > 1;
    let mut excluded = std::collections::HashSet::new();
    if is_multi_sub {
        for sub in &recorder.substreams {
            if sub.rbsp_byte_start <= sub.rbsp_byte_end && sub.rbsp_byte_end <= rbsp.len() {
                let sub_data = &rbsp[sub.rbsp_byte_start..sub.rbsp_byte_end];
                if sub_data
                    .windows(3)
                    .any(|w| w[0] == 0 && w[1] == 0 && w[2] <= 3)
                {
                    excluded.insert(sub.substream_idx);
                }
            }
        }
    }
    if is_multi_sub && !excluded.is_empty() {
        recorder
            .slots
            .iter()
            .filter(|s| !excluded.contains(&(s.substream_idx as usize)))
            .count()
    } else {
        recorder.slots.len()
    }
}

fn probe_hevc_pool(
    carrier: &[u8],
    kind: HevcCarrierKind,
    exact: bool,
    control: &Control<'_>,
) -> Result<PoolProfile, StrHideError> {
    if kind != HevcCarrierKind::Mp4Container || exact {
        let record =
            record_carrier_state(carrier, kind, Capture::Count, StopCondition::All, control)?;
        return Ok(PoolProfile::from_record(&record));
    }

    let target = parse_mp4_targets(carrier)
        .map_err(|e| StrHideError::UnsupportedFormat(format!("MP4/MOV parse error: {e}")))?;

    let mut decoder = Decoder::new();
    decoder.skip_loop_filters = true;
    decoder.ablate = Ablate {
        mc: true,
        intra: true,
        residual: true,
    };

    let mut decode_error: Option<String> = None;
    for ps in &target.parameter_sets {
        if let Err(e) = decoder.push_nal(ps, None) {
            decode_error.get_or_insert_with(|| format!("parameter set: {e}"));
        }
    }

    let mut candidates = Vec::with_capacity(target.slice_spans.len());
    for span in &target.slice_spans {
        if let Some(cand) = candidate_slice(carrier, span.start..span.end()) {
            candidates.push(cand);
        }
    }

    let has_inter = candidates.iter().any(|c| !is_irap(c.nal_type));

    // Pictures and per-band picture counts are exact and free: slice headers are
    // not decoded, only `first_slice_segment_in_pic_flag` is read.
    let (pictures, band_pictures) = count_pictures(carrier, kind, &candidates, has_inter);
    let mut band_total_bytes = [0usize; 2];
    let mut selectable = 0usize;
    for cand in &candidates {
        let band = picture_band(cand.nal_type, has_inter);
        if let Some(b) = band {
            band_total_bytes[b as usize] += cand.span.len();
            selectable += 1;
        }
    }

    // 150 pictures or fewer: full scan (0% estimation error, fast enough)
    if selectable <= 150 {
        let record =
            record_carrier_state(carrier, kind, Capture::Count, StopCondition::All, control)?;
        return Ok(PoolProfile::from_record(&record));
    }

    // Sample 20%, clamped to [150, 1000]
    let sample_limit = ((selectable as f64 * 0.20).round() as usize).clamp(150, 1000);
    let mut recorded_slices = 0usize;
    let mut band_recorded_slots = [0usize; 2];
    let mut band_sampled_bytes = [0usize; 2];

    control.stage_sized(Stage::Decode, sample_limit as u64);

    for (c_idx, cand) in candidates.iter().enumerate() {
        if c_idx % 16 == 0 {
            control.check()?;
            control.report(Event::progress(
                Stage::Decode,
                recorded_slices as u64,
                Some(sample_limit as u64),
            ));
        }
        let slice_bytes = &carrier[cand.span.clone()];
        if slice_bytes.len() < 2 {
            continue;
        }
        let Some(band) = picture_band(cand.nal_type, has_inter) else {
            if let Err(e) = decoder.push_nal(slice_bytes, None) {
                decode_error.get_or_insert_with(|| e.to_string());
            }
            drain_frames(&mut decoder);
            continue;
        };

        if recorded_slices >= sample_limit {
            break;
        }

        let mut recorder = CabacRecorder::with_slice_capacity(
            recorded_slices,
            band,
            RecordMode::Slots,
            slice_bytes.len(),
        );
        let decoded = decoder.decode_nal_with_observer(slice_bytes, &mut recorder);
        drain_frames(&mut decoder);

        match decoded {
            Err(e) => {
                decode_error.get_or_insert_with(|| e.to_string());
            }
            Ok(_) if recorder.substreams.is_empty() => {}
            Ok(_) => {
                let absorbed = if recorder.substreams.len() > 1 {
                    let rbsp = nal_rbsp(slice_bytes);
                    count_absorbed_slots(&mut recorder, &rbsp)
                } else {
                    count_absorbed_slots(&mut recorder, &[])
                };
                band_recorded_slots[band as usize] += absorbed;
                band_sampled_bytes[band as usize] += cand.span.len();
                recorded_slices += 1;
            }
        }
    }

    if recorded_slices == 0
        && let Some(reason) = decode_error
    {
        return Err(StrHideError::UnsupportedFormat(format!(
            "HEVC carrier could not be decoded: {reason}"
        )));
    }

    // Scale each band by its own byte ratio: the two bands have very different
    // slot densities (a reference picture carries 2-3x the residual of a
    // non-reference one), so a single global ratio would bias the estimate.
    let mut band_slots = [0usize; 2];
    for b in 0..2 {
        band_slots[b] = if band_sampled_bytes[b] > 0 {
            ((band_recorded_slots[b] as f64 / band_sampled_bytes[b] as f64)
                * band_total_bytes[b] as f64)
                .round() as usize
        } else {
            0
        };
    }

    Ok(PoolProfile {
        total_slots: band_slots[0] + band_slots[1],
        band_slots,
        band_pictures,
        pictures,
        is_estimated: true,
    })
}

/// Slots per modification of the payload budget: one payload bit occupies
/// `stc_u = 2` slots and about a quarter of the selected slots get flipped, so
/// one flip corresponds to four slots. Used to turn "flips per reference
/// picture" into a slot budget.
const SLOTS_PER_REF_FLIP: usize = 4;

/// Helper to construct [`StegoCapacityInfo`] from the recorded pool geometry.
///
/// Two different policies meet here, because a still picture and a video do not
/// distort the same way:
///
/// * **Still carrier** (one picture): the payload is bounded by
///   `min(bpp_limit * pixels, slots / target_ratio)`, the still-image anchors
///   calibrated on DIV2K.
/// * **Video** (more than one picture): those anchors do not work. `bpp * pixels`
///   ignores length (it pinned every 1080p video to 25.3 KiB), and
///   `slots / target_ratio` bounds the fraction of the *pool*, while the real
///   damage comes from flips in pictures that later pictures predict from. The
///   budget is therefore spent on the drift ladder: a fraction of the
///   drift-free band, plus a fixed number of flips per reference picture.
pub(crate) fn build_hevc_capacity_info(
    carrier: &[u8],
    kind: HevcCarrierKind,
    fmt: &HevcFormatProfile,
    pool: &PoolProfile,
    ext_len: usize,
    safety_level: SafetyLevel,
) -> Result<StegoCapacityInfo, StrHideError> {
    let format_name = kind.label();

    let total_slots = pool.total_slots;
    let trellis = StcTrellis::from_seed_grouped(CAPACITY_PROBE_SEED, fmt.stc_h, fmt.stc_u)?;
    let hdr_slots = hevc_header_slots(ext_len);

    let max_raw_payload_bytes = hevc_max_raw_payload(total_slots, ext_len, fmt)?;

    // Extract picture dimensions from SPS to derive the true element count.
    // That count is pixels times pictures: the per-frame version was the bug
    // that made a 13.6 s video and a 6.4 s video recommend the same 25.3 KiB.
    let (width, height) = extract_hevc_dimensions(carrier).unwrap_or((0, 0));
    let picture_count = pool.pictures.max(1);
    let total_pixels = (width as usize) * (height as usize);
    let total_elements = if total_pixels > 0 {
        total_pixels.saturating_mul(picture_count)
    } else {
        total_slots
    };

    // Usable slots the tier's drift ladder allows, for one tier. Written once so
    // the probe's recommendation and the `[paranoid, high, balanced]` table the
    // GUI reads cannot drift apart.
    let target_bits_for = |level: SafetyLevel| -> usize {
        if picture_count > 1 {
            let budget = level.video_budget();
            let non_ref_slots =
                (pool.band_slots[0] as f64 * budget.non_ref_fraction).floor() as usize;
            let ref_slots = budget
                .ref_flips_per_picture
                .saturating_mul(pool.band_pictures[1])
                .saturating_mul(SLOTS_PER_REF_FLIP)
                .min(pool.band_slots[1]);
            let ladder_slots = non_ref_slots.saturating_add(ref_slots);
            // The writer's own gate (see `embed_hevc_patches_with_factor`) sizes
            // the stream window as `body_needed * (1 / non_ref_fraction)`, so it
            // only accepts `body_needed <= (total - SUPERBLOCK) * non_ref_fraction`.
            // Without this clamp the ladder alone could advertise a payload the
            // embedder then rejected: on an all-I/P stream every slot sits in the
            // reference band, so `ref_slots` alone is a large promise the gate
            // never honours.
            let gate_slots = ((total_slots.saturating_sub(hdr_slots) as f64)
                * budget.non_ref_fraction)
                .floor() as usize;
            trellis.message_bits(ladder_slots.min(gate_slots))
        } else {
            let bpp_bits = (total_elements as f64 * level.bpp_limit()).floor() as usize;
            let ratio_bits = (total_slots as f64 / level.target_ratio()).floor() as usize;
            bpp_bits.min(ratio_bits)
        }
    };
    let recommended_for = |level: SafetyLevel| -> usize {
        (target_bits_for(level) / 8)
            .saturating_sub(BODY_OVERHEAD)
            .min(max_raw_payload_bytes)
    };
    let recommended_max_bytes = recommended_for(safety_level);
    let tier_limits = SafetyLevel::ALL.map(recommended_for);

    let media_info = if width > 0 && height > 0 {
        let base = MediaInfo::new(width, height);
        let video = if kind == HevcCarrierKind::Mp4Container {
            parse_mp4_targets(carrier).ok().and_then(|target| {
                let fps = target.fps?;
                let sec = target.duration_secs?;
                let bps = if sec > 0.0 {
                    (carrier.len() as f64 * 8.0) / sec
                } else {
                    0.0
                };
                Some((fps, sec, bps))
            })
        } else {
            None
        };
        Some(match video {
            Some((fps, sec, bps)) => base.with_video(
                fps as f32,
                (sec * 1000.0).round() as u64,
                bps.round() as u64,
            ),
            None => base,
        })
    } else {
        None
    };

    Ok(StegoCapacityInfo {
        format: format_name.into(),
        algorithm: "HEVC-CABAC-InPlace".into(),
        total_elements,
        available_slots: total_slots,
        max_raw_payload_bytes,
        max_raw_is_grouped: false,
        recommended_max_bytes,
        tier_limits,
        estimated_change_rate: 0.25,
        safety_level: safety_level.as_str().into(),
        safety_bpp_limit: safety_level.bpp_limit(),
        is_estimated: pool.is_estimated,
        media_info,
    })
}

/// Refuse a payload that is above the enforced safety tier.
///
/// Takes plain numbers instead of a [`StegoCapacityInfo`] so the policy decision
/// is unit-testable without a carrier: the bug this guards against was passing
/// only `SafetyLevel` down the call chain, which silently dropped
/// `SafetyEnforcement::Enforced` and made `--enforce-safety` a no-op for every
/// HEVC carrier.
fn enforce_safety(
    payload_len: usize,
    recommended_max_bytes: usize,
    _max_raw_payload_bytes: usize,
    safety: SafetyPolicy,
) -> Result<(), StrHideError> {
    if !safety.is_enforced() || payload_len <= recommended_max_bytes {
        return Ok(());
    }
    Err(StrHideError::SafetyThreshold {
        tier: safety.level,
        required_bytes: payload_len,
        available_bytes: recommended_max_bytes,
    })
}

/// Embed a payload into an HEVC/HEIC carrier using content-adaptive sign-bit steganography.
///
/// The complete expert entry. `secret` is the resolved credential (explicit
/// password, else the profile's private stego secret, else `None` for the
/// official public constant); `domain` isolates the HKDF derivation; `fmt` is
/// the wire-format identity; `freshness` supplies the nonce (`Seeded` makes
/// the output reproducible for the same inputs); `safety` is the full policy,
/// so `Enforced` blocks an over-tier payload instead of only warning.
/// An in-place modification patch for an HEVC carrier: `(byte_range, replacement_nal_bytes)`.
pub type HevcCarrierPatch = (std::ops::Range<usize>, Vec<u8>);

/// Check that every patch fits the carrier it will be applied to.
///
/// The patch list is produced by the HEVC scanner itself, so a mismatch here
/// means an engine invariant broke. Validating before the copy keeps that
/// internal failure a normal error instead of a slice-index panic, which
/// `panic = "abort"` would turn into process termination.
fn validate_hevc_patches(
    carrier_len: usize,
    patches: &[HevcCarrierPatch],
) -> Result<(), StrHideError> {
    for (index, (span, re_nal)) in patches.iter().enumerate() {
        if span.start > span.end || span.end > carrier_len || re_nal.len() != span.len() {
            return Err(StrHideError::General(format!(
                "HEVC patch {index} does not fit the carrier: span {span:?}, {} replacement bytes, carrier {carrier_len} bytes",
                re_nal.len()
            )));
        }
    }
    Ok(())
}

/// Apply in-place NAL patches to a mutable carrier buffer.
///
/// Panics on a patch whose span falls outside `carrier` or whose replacement
/// length differs from the span length; callers that build patches dynamically
/// must verify them first (`validate_hevc_patches`). The production embed path
/// does exactly that, so this panic is reachable only for direct misuse.
pub fn apply_hevc_patches(carrier: &mut [u8], patches: &[HevcCarrierPatch]) {
    for (span, re_nal) in patches {
        debug_assert!(
            span.start <= span.end && span.end <= carrier.len() && re_nal.len() == span.len(),
            "HEVC patch {span:?} does not fit the {} byte carrier",
            carrier.len()
        );
        carrier[span.clone()].copy_from_slice(re_nal);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn embed_hevc_with_info(
    carrier: &[u8],
    payload: &Payload<'_>,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
) -> Result<(Vec<u8>, StegoCapacityInfo, crate::stego::EmbedStats), StrHideError> {
    embed_hevc_with_info_v4(
        carrier,
        payload,
        legacy_credential(secret)?,
        domain,
        fmt.cipher.default_suite.as_u16(),
        &[],
        fmt,
        freshness,
        safety,
        control,
    )
}

/// Credential-aware embed with the full V4 options.
#[allow(clippy::too_many_arguments)]
pub fn embed_hevc_with_info_v4(
    carrier: &[u8],
    payload: &Payload<'_>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
) -> Result<(Vec<u8>, StegoCapacityInfo, crate::stego::EmbedStats), StrHideError> {
    let (patches, capacity_info, stats) = embed_hevc_patches_v4(
        carrier, payload, cred, domain, suite_id, extensions, fmt, freshness, safety, control,
    )?;
    let mut out_carrier = carrier.to_vec();
    validate_hevc_patches(out_carrier.len(), &patches)?;
    apply_hevc_patches(&mut out_carrier, &patches);

    // A Matroska muxer covers every finalised element with a CRC-32; the
    // patches above invalidate any checksum that covers a modified block.
    // Refresh here, on the single in-memory entry every caller reaches, so a
    // direct library user gets the same valid file as `MkvEngine` did.
    if sniff_hevc_carrier(carrier) == Some(HevcCarrierKind::MkvContainer) {
        refresh_mkv_crcs(carrier, &mut out_carrier).map_err(|e| {
            StrHideError::CorruptedData(format!("MKV checksum refresh failed: {e}"))
        })?;
    }

    Ok((out_carrier, capacity_info, stats))
}

/// Embed a payload into an HEVC carrier and return in-place NAL delta patches.
///
/// This avoids cloning or mutating the entire carrier in memory, allowing zero-heap-overhead
/// streaming commit to disk via `commit_carrier_patches`.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(crate) fn embed_hevc_patches(
    carrier: &[u8],
    payload: &Payload<'_>,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
) -> Result<
    (
        Vec<HevcCarrierPatch>,
        StegoCapacityInfo,
        crate::stego::EmbedStats,
    ),
    StrHideError,
> {
    embed_hevc_patches_with_factor(
        carrier, payload, secret, domain, fmt, freshness, safety, control, 1.0,
    )
}

/// Credential-aware patch embed with the full V4 options.
#[allow(clippy::too_many_arguments)]
pub(crate) fn embed_hevc_patches_v4(
    carrier: &[u8],
    payload: &Payload<'_>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
) -> Result<
    (
        Vec<HevcCarrierPatch>,
        StegoCapacityInfo,
        crate::stego::EmbedStats,
    ),
    StrHideError,
> {
    embed_hevc_patches_with_factor_v4(
        carrier, payload, cred, domain, suite_id, extensions, fmt, freshness, safety, control, 1.0,
    )
}

#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn embed_hevc_patches_with_factor(
    carrier: &[u8],
    payload: &Payload<'_>,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
    window_factor: f64,
) -> Result<
    (
        Vec<HevcCarrierPatch>,
        StegoCapacityInfo,
        crate::stego::EmbedStats,
    ),
    StrHideError,
> {
    embed_hevc_patches_with_factor_v4(
        carrier,
        payload,
        legacy_credential(secret)?,
        domain,
        fmt.cipher.default_suite.as_u16(),
        &[],
        fmt,
        freshness,
        safety,
        control,
        window_factor,
    )
}

#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn embed_hevc_patches_with_factor_v4(
    carrier: &[u8],
    payload: &Payload<'_>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
    window_factor: f64,
) -> Result<
    (
        Vec<HevcCarrierPatch>,
        StegoCapacityInfo,
        crate::stego::EmbedStats,
    ),
    StrHideError,
> {
    if payload.is_empty() {
        return Err(StrHideError::General("Cannot embed empty payload".into()));
    }
    let suite = CipherSuiteId::from_u16(suite_id).ok_or_else(|| {
        StrHideError::UnsupportedVersion(format!("Unknown content cipher suite id {suite_id}"))
    })?;
    let ext_len = extension_len(extensions)?;
    let extension = encode_extension_for_write(extensions)?;

    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;

    // 1. Calculate required capacity and stream window
    let plaintext = build_plaintext(payload)?;
    let body_msg_len = plaintext.len() + suite.tag_len();
    let body_needed_slots = StcTrellis::slots_for_params(body_msg_len * 8, fmt.stc_h, fmt.stc_u);
    let hdr_slots = hevc_header_slots(ext_len);
    let non_ref_fraction = safety.level.video_budget().non_ref_fraction;
    let factor = if window_factor > 1.0 {
        window_factor
    } else if kind == HevcCarrierKind::HeifContainer {
        1.0
    } else {
        (1.0 / non_ref_fraction).max(1.0)
    };
    let desired_body_slots = ((body_needed_slots as f64) * factor).ceil() as usize;
    // The writer must decode at least as many slots as the reader's first pass
    // (`StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS)`). Both sides derive
    // the header permutation from `pool_size = recorded_slots.min(POOL_SLOTS)`;
    // a smaller write window would place the header over a different pool size
    // and make small payloads unreadable on large carriers.
    let target_slots = hevc_window_target_slots(hdr_slots, desired_body_slots);

    control.stage(Stage::Decode);
    // MP4 keeps the sampled probe as the capacity contract; every other
    // container reports exact slots, so the window pass can count the rest of
    // the carrier itself and skip the second full decode.
    let exact_capacity = kind != HevcCarrierKind::Mp4Container;
    let record = if exact_capacity {
        record_carrier_state_with_capacity(
            carrier,
            kind,
            Capture::Full,
            StopCondition::TargetSlots(target_slots),
            control,
        )?
    } else {
        record_carrier_state(
            carrier,
            kind,
            Capture::Full,
            StopCondition::TargetSlots(target_slots),
            control,
        )?
    };
    control.check()?;
    control.stage(Stage::Solve);
    let pool = PoolProfile::from_record(&record);
    // Capacity is a property of the whole carrier, not of the write window:
    // `TargetSlots` deliberately stops recording once the payload needs are
    // met, so building the report from `pool` under-reports by the ratio of
    // carrier capacity to the window (measured 112x on a 12 MB MKV). Reuse the
    // same pool the probe uses instead of inventing a second estimator.
    //
    // A record whose slot count stayed below `target_slots` cannot have hit the
    // early stop, so it already covers the whole carrier and needs no second
    // decode pass. The same is true when the recording pass kept counting after
    // the stop (`capacity_band_counts` is whole-carrier by construction).
    let capacity_pool;
    let capacity_source =
        if record.capacity_band_counts.is_some() || record.total_slots() < target_slots {
            &pool
        } else {
            capacity_pool = probe_hevc_pool(carrier, kind, false, control)?;
            &capacity_pool
        };
    let capacity_info =
        build_hevc_capacity_info(carrier, kind, fmt, capacity_source, ext_len, safety.level)?;

    enforce_safety(
        payload.len(),
        capacity_info.recommended_max_bytes,
        capacity_info.max_raw_payload_bytes,
        safety,
    )?;

    let slice_contexts = record.slice_contexts;
    let all_slots = record.all_slots;
    let total_slots = all_slots.len();
    let pool_size = total_slots.min(HEVC_SUPERBLOCK_POOL_SLOTS);

    if pool_size < hdr_slots || total_slots < hdr_slots + body_needed_slots {
        return Err(StrHideError::PayloadTooLarge(format!(
            "HEVC carrier capacity exceeded: needed at least {} slots, but carrier only has {}",
            hdr_slots + body_needed_slots,
            total_slots
        )));
    }

    // A container that only ever holds video is a video carrier regardless of
    // how many pictures it has; an Annex-B stream or a HEIF still is judged by
    // the picture count.
    let is_video = matches!(
        kind,
        HevcCarrierKind::Mp4Container | HevcCarrierKind::MkvContainer
    ) || record.pictures > 1;
    if is_video && total_slots < hdr_slots + desired_body_slots {
        let current_tier = safety.level.as_str();
        let hint = match safety.level {
            SafetyLevel::Paranoid => {
                "carrier capacity insufficient for paranoid tier (0.1 budget); try '--safety high' (0.2) or '--safety balanced' (0.4)"
            }
            SafetyLevel::High => {
                "carrier capacity insufficient for default high tier (0.2 budget); try '--safety balanced' (0.4)"
            }
            SafetyLevel::Balanced => {
                "carrier capacity insufficient for balanced tier (0.4 budget); payload is too large for this carrier"
            }
        };
        return Err(StrHideError::General(format!(
            "HEVC capacity insufficient for tier '{current_tier}': needed {needed} slots ({factor:.1}x sparsity), carrier only has {available} slots. Hint: {hint}",
            needed = hdr_slots + desired_body_slots,
            available = total_slots,
        )));
    }

    // 2. L1/L2 locator, session keys and keyed slot plans
    let cover_digest = derive_carrier_digest(carrier, &record.digest_inputs, fmt);
    let master = derive_locator_master(cred, domain, fmt.cipher, &cover_digest)?;
    let locator = derive_l2_locator_keys(&master, fmt.cipher, fmt.magic_label, domain)?;

    let fresh_binding =
        Freshness::seeded_binding(carrier, payload.as_bytes(), HEVC_FORMAT_ID, &extension);
    let nonce_bytes = freshness.nonce(0, &fresh_binding);
    let session = derive_l3_session_keys(
        fmt.cipher,
        suite,
        &master,
        &hevc_session_salt(fmt.session_salt_label, &nonce_bytes),
        domain,
    )?;

    let header_positions = superblock_positions(pool_size, &locator.locate_seed, ext_len);
    let (body_band0, body_band1) = get_body_slot_indices(
        total_slots,
        pool_size,
        &header_positions,
        &record.slice_slot_ranges,
    );
    let body_bands = vec![
        0..body_band0.len(),
        body_band0.len()..(body_band0.len() + body_band1.len()),
    ];
    let mut all_body_indices = body_band0;
    all_body_indices.extend(body_band1);
    let body_positions_rel = band_positions(&body_bands, body_needed_slots, &session.perm_seed);
    let body_positions: Vec<usize> = body_positions_rel
        .into_iter()
        .map(|rel| all_body_indices[rel])
        .collect();

    // 3. Prepare Superblock, extension area and AEAD ciphertext
    let window_slices = u16::try_from(slice_contexts.len()).map_err(|_| {
        StrHideError::UnsupportedFormat(format!(
            "HEVC carrier has {} slices, exceeding the superblock window slice limit (65535)",
            slice_contexts.len()
        ))
    })?;

    let flags = (if ext_len > 0 { FLAG_EXT_PRESENT } else { 0 })
        | (if has_critical_tlv(extensions) {
            FLAG_EXT_CRITICAL
        } else {
            0
        });
    let body_len = u32::try_from(body_msg_len).map_err(|_| {
        StrHideError::General("HEVC payload exceeds the 32-bit body length field".into())
    })?;
    let sb = HevcSuperblockV4 {
        magic: locator.magic4,
        version: CONTENT_ENVELOPE_VERSION,
        flags,
        stc_u: fmt.stc_u,
        window_slices,
        ext_len: ext_len as u8,
        suite_id,
        body_len,
        nonce: nonce_bytes,
    };
    let sb_bytes = sb.encode();
    let aad = build_v4_aad_with(fmt.cipher.aad_prefix, HEVC_FORMAT_ID, &sb_bytes, &extension);
    let ciphertext = encrypt_v4_with_aad(suite, &session.enc_key, &nonce_bytes, &aad, &plaintext)?;

    let sb_trellis =
        StcTrellis::from_seed_grouped(locator.header_stc_seed, HEVC_EXT_STC_H, HEVC_EXT_STC_U)?;
    let ext_trellis =
        StcTrellis::from_seed_grouped(locator.ext_stc_seed, HEVC_EXT_STC_H, HEVC_EXT_STC_U)?;
    let body_trellis = StcTrellis::from_seed_grouped(session.stc_seed, fmt.stc_h, fmt.stc_u)?;
    let base_positions = &header_positions[..HEVC_SUPERBLOCK_MIN_SLOTS];
    let ext_positions = &header_positions[HEVC_SUPERBLOCK_MIN_SLOTS..];

    let mut forbidden: HashSet<usize> = HashSet::new();
    let mut bad_substreams: HashSet<(usize, usize)> = HashSet::new();

    for round in 0..MAX_EMBED_ROUNDS {
        control.check()?;

        // 3a. Solve Superblock STC
        let mut sb_cover_bits = Vec::with_capacity(base_positions.len());
        let mut sb_costs = Vec::with_capacity(base_positions.len());
        let mut sb_moves = Vec::with_capacity(base_positions.len());
        for &pos in base_positions {
            let slot = &all_slots[pos];
            sb_cover_bits.push(slot.original_bit);
            sb_costs.push(if forbidden.contains(&pos) {
                slot.cost as f64 + FORBIDDEN_SLOT_SURCHARGE
            } else {
                slot.cost as f64
            });
            sb_moves.push(if slot.original_bit == 0 {
                Move::PlusOnly
            } else {
                Move::MinusOnly
            });
        }
        let mut sb_deltas = vec![0i8; base_positions.len()];
        if let Err(e) = sb_trellis.embed_with_deltas(
            &sb_cover_bits,
            &sb_moves,
            &sb_costs,
            &sb_costs,
            &sb_bytes,
            &mut sb_deltas,
        ) {
            if round == 0 {
                return Err(e);
            }
            return Err(StrHideError::TrellisInfeasible {
                cause: crate::errors::TrellisCause::ExhaustedSlots,
                detail: format!(
                    "HEVC Superblock STC exhausted usable slots after {round} round(s) ({} slot(s) excluded): {e}",
                    forbidden.len()
                ),
            });
        }

        // 3a-bis. Solve the extension TLV area STC (keyed by the L2 ext seed)
        let mut ext_cover_bits = Vec::with_capacity(ext_positions.len());
        let mut ext_costs = Vec::with_capacity(ext_positions.len());
        let mut ext_moves = Vec::with_capacity(ext_positions.len());
        for &pos in ext_positions {
            let slot = &all_slots[pos];
            ext_cover_bits.push(slot.original_bit);
            ext_costs.push(if forbidden.contains(&pos) {
                slot.cost as f64 + FORBIDDEN_SLOT_SURCHARGE
            } else {
                slot.cost as f64
            });
            ext_moves.push(if slot.original_bit == 0 {
                Move::PlusOnly
            } else {
                Move::MinusOnly
            });
        }
        let mut ext_deltas = vec![0i8; ext_positions.len()];
        if ext_len > 0
            && let Err(e) = ext_trellis.embed_with_deltas(
                &ext_cover_bits,
                &ext_moves,
                &ext_costs,
                &ext_costs,
                &extension,
                &mut ext_deltas,
            )
        {
            if round == 0 {
                return Err(e);
            }
            return Err(StrHideError::TrellisInfeasible {
                cause: crate::errors::TrellisCause::ExhaustedSlots,
                detail: format!(
                    "HEVC extension area STC exhausted usable slots after {round} round(s) ({} slot(s) excluded): {e}",
                    forbidden.len()
                ),
            });
        }

        // 3b. Solve Body STC using cost closure (zero-allocation for body_costs)
        let mut body_cover_bits = Vec::with_capacity(body_positions.len());
        let mut body_moves = Vec::with_capacity(body_positions.len());
        for &pos in &body_positions {
            let slot = &all_slots[pos];
            body_cover_bits.push(slot.original_bit);
            body_moves.push(if slot.original_bit == 0 {
                Move::PlusOnly
            } else {
                Move::MinusOnly
            });
        }
        let mut body_deltas = vec![0i8; body_positions.len()];
        if let Err(e) = body_trellis.embed_with_cost_fn(
            &body_cover_bits,
            &body_moves,
            |j| {
                let pos = body_positions[j];
                let cost = if forbidden.contains(&pos) {
                    all_slots[pos].cost as f64 + FORBIDDEN_SLOT_SURCHARGE
                } else {
                    all_slots[pos].cost as f64
                };
                (cost, cost)
            },
            &ciphertext,
            &mut body_deltas,
        ) {
            if round == 0 {
                return Err(e);
            }
            return Err(StrHideError::TrellisInfeasible {
                cause: crate::errors::TrellisCause::ExhaustedSlots,
                detail: format!(
                    "HEVC Body STC exhausted usable slots after {round} round(s) ({} slot(s) excluded): {e}",
                    forbidden.len()
                ),
            });
        }

        let mut flips_per_slice: BTreeMap<usize, Vec<(usize, usize)>> = BTreeMap::new();
        for (i, &delta) in sb_deltas.iter().enumerate() {
            if delta != 0 {
                let global_slot_idx = base_positions[i];
                let slot = &all_slots[global_slot_idx];
                flips_per_slice
                    .entry(slot.slice_idx as usize)
                    .or_default()
                    .push((slot.op_idx as usize, global_slot_idx));
            }
        }
        for (i, &delta) in ext_deltas.iter().enumerate() {
            if delta != 0 {
                let global_slot_idx = ext_positions[i];
                let slot = &all_slots[global_slot_idx];
                flips_per_slice
                    .entry(slot.slice_idx as usize)
                    .or_default()
                    .push((slot.op_idx as usize, global_slot_idx));
            }
        }
        for (i, &delta) in body_deltas.iter().enumerate() {
            if delta != 0 {
                let global_slot_idx = body_positions[i];
                let slot = &all_slots[global_slot_idx];
                flips_per_slice
                    .entry(slot.slice_idx as usize)
                    .or_default()
                    .push((slot.op_idx as usize, global_slot_idx));
            }
        }
        for entries in flips_per_slice.values_mut() {
            entries.sort_unstable_by_key(|(op_idx, _)| *op_idx);
        }

        // 3c. Re-encode every touched slice in parallel using rayon (including journal fidelity checks)
        let mut conflicts: Vec<EpbConflict> = Vec::new();
        let mut reencoded_slices = Vec::new();

        let slice_items: Vec<(usize, &Vec<(usize, usize)>)> = flips_per_slice
            .iter()
            .map(|(&idx, entries)| (idx, entries))
            .collect();

        control.stage_sized(Stage::Encode, slice_items.len() as u64);

        let outcomes: Result<Vec<SliceReencodeOutcome>, StrHideError> = slice_items
            .into_par_iter()
            .map(|(slice_idx, flipped_entries)| {
                control.check()?;
                let ctx = slice_contexts.get(slice_idx).ok_or_else(|| {
                    StrHideError::General(format!(
                        "HEVC slice index {slice_idx} has no recorded context"
                    ))
                })?;
                Ok(reencode_slice(slice_idx, ctx, flipped_entries))
            })
            .collect();
        let outcomes = outcomes?;

        for outcome in outcomes {
            match outcome {
                SliceReencodeOutcome::Success { span, re_nal } => {
                    reencoded_slices.push((span, re_nal));
                }
                SliceReencodeOutcome::Conflict(c) => {
                    conflicts.extend(c);
                }
                SliceReencodeOutcome::BadSubstream(slice_idx, sub_idx) => {
                    bad_substreams.insert((slice_idx, sub_idx));
                }
                SliceReencodeOutcome::LengthError(msg) => {
                    return Err(StrHideError::General(msg));
                }
            }
        }

        let mut had_bad_substream = false;
        for &pos in header_positions.iter().chain(body_positions.iter()) {
            let slot = &all_slots[pos];
            if bad_substreams.contains(&(slot.slice_idx as usize, slot.substream_idx as usize))
                && forbidden.insert(pos)
            {
                had_bad_substream = true;
            }
        }
        if had_bad_substream {
            continue;
        }

        if conflicts.is_empty() && reencoded_slices.len() == flips_per_slice.len() {
            let modified_slots = sb_deltas.iter().filter(|&&d| d != 0).count()
                + ext_deltas.iter().filter(|&&d| d != 0).count()
                + body_deltas.iter().filter(|&&d| d != 0).count();
            let stats = crate::stego::EmbedStats {
                modified_slots,
                total_candidate_slots: total_slots,
            };
            return Ok((reencoded_slices, capacity_info, stats));
        }

        // 3c. Exclude the slots whose flipped bits sit next to a disturbed
        //     window. A bypass bin owns one codeword bit but its carry can
        //     rewrite the neighbouring bytes, so widen the radius every round.
        let radius = 8usize << round.min(3);
        let mut progress = 0usize;
        for (window, trace) in &conflicts {
            let lo = window.saturating_sub(radius);
            let hi = window + radius;
            for &(global, byte_lo, byte_hi) in trace {
                if global < total_slots
                    && byte_hi >= lo
                    && byte_lo <= hi
                    && forbidden.insert(global)
                {
                    progress += 1;
                }
            }
        }

        if progress == 0 {
            // The carry travelled further than any traced flip: exclude the
            // closest flip that precedes the window so the next round cannot
            // stall on the same conflict.
            for (window, trace) in &conflicts {
                if let Some(&(global, _, _)) = trace
                    .iter()
                    .filter(|(_, _, byte_hi)| *byte_hi <= *window)
                    .max_by_key(|(_, _, byte_hi)| *byte_hi)
                    && global < total_slots
                    && forbidden.insert(global)
                {
                    progress += 1;
                }
            }
        }

        if progress == 0 {
            // `conflicts` can be empty here when a BadSubstream hit a substream
            // whose slots were all excluded in an earlier round: the slice
            // failed to re-encode, yet there is no EPB trace to point at.
            // Report that explicitly instead of indexing `conflicts[0]`.
            if conflicts.is_empty() {
                return Err(StrHideError::General(format!(
                    "HEVC stego cannot resolve a substream whose slots were already excluded \
                     (round {round}, {} slot(s) forbidden)",
                    forbidden.len()
                )));
            }
            return Err(StrHideError::General(format!(
                "HEVC stego cannot localize the emulation-prevention conflict at RBSP byte {}",
                conflicts[0].0
            )));
        }
    }

    Err(StrHideError::General(format!(
        "HEVC stego cannot settle on an EPB-safe flip set within {MAX_EMBED_ROUNDS} rounds"
    )))
}

pub(crate) fn embed_hevc_payload(
    carrier: &[u8],
    payload: &Payload<'_>,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
) -> Result<Vec<u8>, StrHideError> {
    embed_hevc_with_info(
        carrier,
        payload,
        secret,
        domain,
        fmt,
        freshness,
        SafetyPolicy::new(),
        &Control::none(),
    )
    .map(|(bytes, _, _)| bytes)
}

/// Embed a payload into an HEVC/HEIC carrier using content-adaptive sign-bit steganography.
///
/// Wrapper around [`embed_hevc_with_info`] discarding the structured capacity metadata.
pub fn embed_hevc(
    carrier: &[u8],
    payload: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
) -> Result<Vec<u8>, StrHideError> {
    embed_hevc_payload(
        carrier,
        &Payload::bytes(payload),
        secret,
        domain,
        fmt,
        freshness,
    )
}

/// Re-encode one CABAC substream from its recorded journal.
///
/// `flipped_ops` marks the journal entries whose bypass bin was inverted. The
/// second return value lists, for every inverted bin, the global slot index and
/// the `[first, last)` bit range it can occupy in the output stream, which lets
/// the caller map a broken `00 00 xx` window back to a slot.
fn encode_substream(
    slice: &SliceContext,
    sub: &SubstreamRecord,
    flipped_ops: &[(usize, usize)],
) -> Result<(Vec<u8>, Vec<SlotBitTrace>), StrHideError> {
    let mut enc = CabacEncoder::new();
    let mut writer = BitWriter::new();
    let mut ctx_array = [ContextModel::init(154, 26); ENCODER_CONTEXTS];
    for (model, &state) in ctx_array.iter_mut().zip(sub.init_contexts.iter()) {
        *model = ContextModel {
            p_state_idx: state >> 1,
            val_mps: state & 1,
        };
    }

    let ops = &slice.ops[sub.op_start..sub.op_end];
    let mut trace = Vec::new();

    let mut flip_cursor = 0usize;
    while flip_cursor < flipped_ops.len() && flipped_ops[flip_cursor].0 < sub.op_start {
        flip_cursor += 1;
    }

    for (offset, op) in ops.iter().enumerate() {
        let op_idx = sub.op_start + offset;
        let mut flipped_global = None;
        if flip_cursor < flipped_ops.len() && flipped_ops[flip_cursor].0 == op_idx {
            flipped_global = Some(flipped_ops[flip_cursor].1);
            flip_cursor += 1;
        }
        let flipped = flipped_global.is_some();
        if op.is_decision() {
            let idx = op.ctx_idx();
            // A context index outside the model array means the journal and
            // this build disagree about the syntax. Skipping the bin would
            // silently desynchronise the replay, so it is a hard error: the
            // caller marks the substream unsupported.
            let ctx = ctx_array.get_mut(idx).ok_or_else(|| {
                StrHideError::CorruptedData(format!(
                    "CABAC context index {idx} is out of range (ENCODER_CONTEXTS = {ENCODER_CONTEXTS})"
                ))
            })?;
            enc.encode_decision(&mut writer, ctx, op.bit());
        } else if op.is_bypass() {
            let out_bit = if flipped { op.bit() ^ 1 } else { op.bit() };
            let bit_lo = writer.bit_len();
            enc.encode_bypass(&mut writer, out_bit);
            let bit_hi = writer.bit_len();
            if op.is_stego()
                && let Some(global) = flipped_global
            {
                trace.push((global, bit_lo, bit_hi));
            }
        } else {
            enc.encode_terminate(&mut writer, op.bit());
        }
    }

    // H.265 §9.3.2.6 / §7.3.8.2 substream termination:
    // - The final substream of a slice ends with `end_of_slice_segment_flag = 1`
    //   (`BinOp::Terminate { bit: 1 }` already recorded at the end of `ops`).
    // - Mid-slice WPP/tile substreams end their CTU row with
    //   `end_of_slice_segment_flag = 0` (`BinOp::Terminate { bit: 0 }`), followed
    //   in the bitstream by `end_of_subset_one_bit = 1` and byte alignment.
    //   The decoder jumps straight to the next entry point after
    //   `Terminate { bit: 0 }` and so never records that bit; emitting
    //   `encode_terminate(1)` here reconstructs the exact standard substream
    //   tail, which is what makes mid-row substreams usable at all.
    //
    // Verified 2026-10-25 by replaying every substream of the local corpus: all
    // match byte-exactly (512×512 WPP 16/16, real HEICs 768/768 each).
    if !ops
        .last()
        .is_some_and(|op| op.is_terminate() && op.bit() == 1)
    {
        enc.encode_terminate(&mut writer, 1);
    }
    writer.align_zero();
    Ok((writer.finish(), trace))
}

enum SliceReencodeOutcome {
    Success {
        span: std::ops::Range<usize>,
        re_nal: Vec<u8>,
    },
    Conflict(Vec<EpbConflict>),
    BadSubstream(usize, usize),
    LengthError(String),
}

fn reencode_slice(
    slice_idx: usize,
    slice_rec: &SliceContext,
    flipped_entries: &[(usize, usize)],
) -> SliceReencodeOutcome {
    let mut substream_ids: Vec<usize> = flipped_entries
        .iter()
        .filter_map(|&(op_idx, _)| {
            slice_rec
                .substreams
                .iter()
                .position(|s| op_idx >= s.op_start && op_idx < s.op_end)
        })
        .collect();
    substream_ids.sort_unstable();
    substream_ids.dedup();

    let mut modified_rbsp = slice_rec.orig_rbsp.clone();
    let mut trace: Vec<SlotBitTrace> = Vec::new();

    for sub_idx in &substream_ids {
        let sub = &slice_rec.substreams[*sub_idx];
        let cover = &slice_rec.orig_rbsp[sub.rbsp_byte_start..sub.rbsp_byte_end];
        match encode_substream(slice_rec, sub, &[]) {
            Ok((replay, _)) if replay_matches_cover(&replay, cover) => {}
            _ => return SliceReencodeOutcome::BadSubstream(slice_idx, *sub_idx),
        }

        let orig_sub_len = sub.rbsp_byte_end.saturating_sub(sub.rbsp_byte_start);
        let (reencoded, sub_trace) = match encode_substream(slice_rec, sub, flipped_entries) {
            Ok(pair) => pair,
            Err(_) => return SliceReencodeOutcome::BadSubstream(slice_idx, *sub_idx),
        };

        // A replay that is 1-4 bytes shorter is padded to the original span.
        // This is not dead tolerance: real HEIC carriers (e.g. the
        // IMG_5887.HEIC baseline) legitimately produce such replays, and
        // rejecting them made the content embed fail. Keep the padding until
        // `encode_substream` can be made length-exact; the EPB conflict scan and
        // the final NAL length check below still gate the result.
        if reencoded.len() == orig_sub_len {
            modified_rbsp[sub.rbsp_byte_start..sub.rbsp_byte_end].copy_from_slice(&reencoded);
        } else if reencoded.len() < orig_sub_len && orig_sub_len - reencoded.len() <= 4 {
            modified_rbsp[sub.rbsp_byte_start..sub.rbsp_byte_start + reencoded.len()]
                .copy_from_slice(&reencoded);
            for b in &mut modified_rbsp[sub.rbsp_byte_start + reencoded.len()..sub.rbsp_byte_end] {
                *b = 0;
            }
        } else {
            return SliceReencodeOutcome::BadSubstream(slice_idx, *sub_idx);
        }

        for (global, bit_lo, bit_hi) in sub_trace {
            trace.push((
                global,
                sub.rbsp_byte_start + bit_lo / 8,
                sub.rbsp_byte_start + bit_hi.saturating_sub(1) / 8,
            ));
        }
    }

    let mut conflicts = Vec::new();
    for p in 2..modified_rbsp.len() {
        let now_starts_epb =
            modified_rbsp[p - 2] == 0 && modified_rbsp[p - 1] == 0 && modified_rbsp[p] <= 3;
        let cover_starts_epb = slice_rec.orig_rbsp[p - 2] == 0
            && slice_rec.orig_rbsp[p - 1] == 0
            && slice_rec.orig_rbsp[p] <= 3;
        if now_starts_epb != cover_starts_epb {
            conflicts.push((p, trace));
            return SliceReencodeOutcome::Conflict(conflicts);
        }
    }

    let re_nal = rbsp_to_nal(
        slice_rec.nal_type,
        slice_rec.layer_id,
        slice_rec.temporal_id,
        &modified_rbsp,
    );
    if re_nal.len() == slice_rec.carrier_span.len() {
        SliceReencodeOutcome::Success {
            span: slice_rec.carrier_span.clone(),
            re_nal,
        }
    } else {
        SliceReencodeOutcome::LengthError(format!(
            "HEVC slice {slice_idx}: re-encoded NAL is {} bytes but the cover span is {} bytes",
            re_nal.len(),
            slice_rec.carrier_span.len()
        ))
    }
}

/// Is the journal replay byte-identical to the cover substream?
///
/// A shortfall of up to four trailing zero bytes is accepted: those are the HEVC
/// `cabac_zero_word`s that the journal does not model and the re-encoder
/// restores as padding. Anything else means the recorder and the stream
/// disagree about the syntax in this substream.
fn replay_matches_cover(replay: &[u8], cover: &[u8]) -> bool {
    if replay == cover {
        return true;
    }
    cover.len() > replay.len()
        && cover.len() - replay.len() <= 4
        && cover.starts_with(replay)
        && cover[replay.len()..].iter().all(|b| *b == 0)
}

/// Keyed stride permutation of each drift band, consumed band by band.
///
/// Element `i` maps to slot `band.start + (j * stride) mod len` where `j` is the
/// element's index inside that band. `stride` is derived per band from the
/// payload key (SplitMix64, see `keyed_band_params`); the fixed Weyl step of
/// earlier builds was removed. Consecutive elements therefore land in
/// different slices, different pictures and different corners of the frame.
/// Consuming slots in recording order
/// instead concentrates the whole payload on the first item -- for a burst
/// `.heic` (dozens of independent pictures in one file) that flattens the
/// primary image while the other 40-odd pictures stay pristine.
///
/// Two properties matter:
///
/// * `count` only decides how many elements are produced; the mapping of element
///   `i` never depends on it, which is what lets the extractor read the header
///   prefix and then the full message with the same mapping.
/// * Bands are never interleaved. A payload that fits in band 0 (pictures
///   nothing predicts from) never reaches band 1, so the drift-free rung is
///   exhausted before any reference picture is touched.
fn band_positions(
    bands: &[std::ops::Range<usize>],
    count: usize,
    perm_seed: &[u8; 32],
) -> Vec<usize> {
    let mut out = Vec::with_capacity(count);
    for band in bands {
        if out.len() >= count {
            break;
        }
        let len = band.len();
        if len == 0 {
            continue;
        }
        let (start, stride) = keyed_band_params(len, perm_seed, band.start);
        for i in 0..len {
            if out.len() >= count {
                break;
            }
            // `i * stride` overflows `usize` on 32-bit targets once a burst
            // HEIC exposes a few billion slots; the modulus only needs the
            // product's low bits, so the multiply runs in `u64`.
            out.push(
                band.start + ((start as u64 + i as u64 * stride as u64) % len as u64) as usize,
            );
        }
    }
    out
}

/// Extract hidden payload from an HEVC/HEIC carrier.
pub fn extract_hevc(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    extract_hevc_v4(
        carrier,
        legacy_credential(secret)?,
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// Credential-aware extraction with explicit policy limits.
pub fn extract_hevc_v4(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    control.check()?;
    check_l1_floor(&cred, limits)?;
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;

    // 1. First stage: scan up to HEVC_SUPERBLOCK_POOL_SLOTS to read the header.
    let sb_record = record_carrier_state(
        carrier,
        kind,
        Capture::Bits,
        StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
        control,
    )?;
    extract_hevc_from_sb_record_v4(carrier, kind, sb_record, cred, domain, fmt, limits, control)
}

#[allow(clippy::too_many_arguments)]
fn extract_hevc_from_sb_record(
    carrier: &[u8],
    kind: HevcCarrierKind,
    sb_record: CarrierRecord,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    extract_hevc_from_sb_record_v4(
        carrier,
        kind,
        sb_record,
        legacy_credential(secret)?,
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// The header half of an extraction: everything read and validated before any
/// body slot is touched.
struct HevcHeaderRead {
    sb: HevcSuperblockV4,
    sb_bytes: [u8; HEVC_SUPERBLOCK_BYTES],
    header_positions: Vec<usize>,
    extension: Vec<u8>,
    extension_tags: Vec<u8>,
    session: crate::stego::format::SessionKeys,
}

/// Locate, decode and validate the V4 header (base + extension).
///
/// Order matters and is the same for `extract`, `inspect` and `verify`:
/// CRC/version/magic → structural bounds → extension TLV → `validate_header`
/// (suite/body_len/header slots) → L3 session keys. Every failure is folded to
/// `NoHiddenData` so a wrong password and a tampered header are indistinguishable.
fn read_hevc_header_v4(
    carrier: &[u8],
    record: &CarrierRecord,
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
) -> Result<Option<HevcHeaderRead>, StrHideError> {
    let total_slots = record.total_slots();
    let pool_size = total_slots.min(HEVC_SUPERBLOCK_POOL_SLOTS);
    if pool_size < HEVC_SUPERBLOCK_MIN_SLOTS {
        return Ok(None);
    }

    let cover_digest = derive_carrier_digest(carrier, &record.digest_inputs, fmt);
    let master = derive_locator_master(cred, domain, fmt.cipher, &cover_digest)
        .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;
    let locator = derive_l2_locator_keys(&master, fmt.cipher, fmt.magic_label, domain)
        .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;

    let base_positions = superblock_positions(pool_size, &locator.locate_seed, 0);
    let sb_bits: Vec<u8> = base_positions
        .iter()
        .map(|&p| record.raw_slot_bit(p))
        .collect();
    let sb_trellis =
        StcTrellis::from_seed_grouped(locator.header_stc_seed, HEVC_EXT_STC_H, HEVC_EXT_STC_U)
            .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;
    let sb_raw = sb_trellis.extract(&sb_bits, HEVC_SUPERBLOCK_BYTES * 8);
    if sb_raw.len() < HEVC_SUPERBLOCK_BYTES {
        return Ok(None);
    }
    let mut sb_bytes = [0u8; HEVC_SUPERBLOCK_BYTES];
    sb_bytes.copy_from_slice(&sb_raw[..HEVC_SUPERBLOCK_BYTES]);

    let Ok(sb) = HevcSuperblockV4::decode(&sb_bytes, locator.magic4) else {
        return Ok(None);
    };

    let header_slots = hevc_header_slots(sb.ext_len as usize);
    if header_slots > pool_size || header_slots > total_slots {
        return Ok(None);
    }
    if limits
        .validate_header(sb.suite_id, sb.body_len, header_slots, total_slots)
        .is_err()
    {
        return Ok(None);
    }

    let ext_bytes = sb.ext_len as usize;
    let header_positions = superblock_positions(pool_size, &locator.locate_seed, ext_bytes);
    let ext_slots = hevc_extension_slots(ext_bytes);
    let mut extension = Vec::new();
    let mut extension_tags = Vec::new();
    if ext_slots > 0 {
        let ext_positions = &header_positions[HEVC_SUPERBLOCK_MIN_SLOTS..];
        let ext_bits: Vec<u8> = ext_positions
            .iter()
            .map(|&p| record.raw_slot_bit(p))
            .collect();
        let ext_trellis =
            StcTrellis::from_seed_grouped(locator.ext_stc_seed, HEVC_EXT_STC_H, HEVC_EXT_STC_U)
                .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;
        // The trellis message is the extension *bytes*, not the slot count.
        extension = ext_trellis.extract(&ext_bits, ext_bytes * 8);
        if extension.len() < ext_bytes {
            return Ok(None);
        }
        let tlvs = parse_extension(&extension)
            .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;
        extension_tags = tlvs.iter().map(|(tag, _)| *tag).collect();
    }
    // The flag and the TLVs must agree before any caller trusts the header.
    validate_ext_critical_flag(sb.flags, &extension)
        .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;

    let suite = CipherSuiteId::from_u16(sb.suite_id)
        .ok_or_else(|| StrHideError::NoHiddenData("No valid payload found".into()))?;
    let session = derive_l3_session_keys(
        fmt.cipher,
        suite,
        &master,
        &hevc_session_salt(fmt.session_salt_label, &sb.nonce),
        domain,
    )
    .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;

    Ok(Some(HevcHeaderRead {
        sb,
        sb_bytes,
        header_positions,
        extension,
        extension_tags,
        session,
    }))
}

#[allow(clippy::too_many_arguments)]
fn extract_hevc_from_sb_record_v4(
    carrier: &[u8],
    _kind: HevcCarrierKind,
    sb_record: CarrierRecord,
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    control.check()?;
    check_l1_floor(&cred, limits)?;
    let no_data = || StrHideError::NoHiddenData("No valid payload found".into());

    let header =
        read_hevc_header_v4(carrier, &sb_record, cred, domain, fmt, limits)?.ok_or_else(no_data)?;
    extract_hevc_with_header(carrier, _kind, sb_record, &header, fmt, limits, control)
}

/// Body extraction over an already-read, policy-checked V4 header.
///
/// `verify` reads the header for its level-2 verdict and then needs the same
/// header for level 3; re-deriving it would pay the 200k-iteration L1 twice for
/// one request (plan M-14).
#[allow(clippy::too_many_arguments)]
fn extract_hevc_with_header(
    carrier: &[u8],
    kind: HevcCarrierKind,
    sb_record: CarrierRecord,
    header: &HevcHeaderRead,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    let no_data = || StrHideError::NoHiddenData("No valid payload found".into());

    // 2. Second stage: read the Body, but only after the header passed policy.
    let w0 = header.sb.window_slices as usize;
    let body_record = if sb_record.recorded_slices >= w0 {
        sb_record
    } else {
        record_carrier_state(
            carrier,
            kind,
            Capture::Bits,
            StopCondition::TargetSlices(w0),
            control,
        )?
    };

    let total_window_slots = body_record.total_slots();
    let pool_size = total_window_slots.min(HEVC_SUPERBLOCK_POOL_SLOTS);
    if pool_size < header.header_positions.len() {
        return Err(no_data());
    }
    let (body_band0, body_band1) = get_body_slot_indices(
        total_window_slots,
        pool_size,
        &header.header_positions,
        &body_record.slice_slot_ranges,
    );

    let body_trellis =
        StcTrellis::from_seed_grouped(header.session.stc_seed, fmt.stc_h, header.sb.stc_u)?;
    let body_msg_len = header.sb.body_len as usize;
    let body_needed_slots = body_trellis.slots_for(body_msg_len * 8);

    let available_body_slots = body_band0.len() + body_band1.len();
    if available_body_slots < body_needed_slots {
        return Err(no_data());
    }

    let body_bands = vec![
        0..body_band0.len(),
        body_band0.len()..(body_band0.len() + body_band1.len()),
    ];
    let mut all_body_indices = body_band0;
    all_body_indices.extend(body_band1);
    let body_positions_rel =
        band_positions(&body_bands, body_needed_slots, &header.session.perm_seed);
    let body_bits: Vec<u8> = body_positions_rel
        .into_iter()
        .map(|rel| body_record.raw_slot_bit(all_body_indices[rel]))
        .collect();

    let ciphertext = body_trellis.extract(&body_bits, body_msg_len * 8);
    if ciphertext.len() < body_msg_len {
        return Err(no_data());
    }
    let ciphertext = &ciphertext[..body_msg_len];

    let aad = build_v4_aad_with(
        fmt.cipher.aad_prefix,
        HEVC_FORMAT_ID,
        &header.sb_bytes,
        &header.extension,
    );
    let suite = CipherSuiteId::from_u16(header.sb.suite_id).ok_or_else(no_data)?;
    let payload = unpack_v4_envelope_parts(
        suite,
        &header.session.enc_key,
        &header.sb.nonce,
        &aad,
        ciphertext,
        limits,
    )?;

    // Critical extension TLVs are only meaningful after AEAD proved the header
    // is authentic; an unknown critical tag means this build cannot honour the
    // carrier's contract.
    let flag_critical = header.sb.flags & FLAG_EXT_CRITICAL != 0;
    let has_critical = tags_have_critical(&header.extension_tags);
    if flag_critical != has_critical || has_critical {
        return Err(no_data());
    }

    Ok(payload)
}

#[allow(dead_code)]
fn extract_hevc_record(
    carrier: &[u8],
    record: &CarrierRecord,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;
    extract_hevc_from_sb_record(
        carrier,
        kind,
        CarrierRecord {
            slice_contexts: record.slice_contexts.clone(),
            all_slots: record.all_slots.clone(),
            band_bits: record.band_bits.clone(),
            bands: record.bands.clone(),
            pictures: record.pictures,
            band_pictures: record.band_pictures,
            digest_inputs: match &record.digest_inputs {
                DigestInputs::ParameterSets { parameter_sets } => DigestInputs::ParameterSets {
                    parameter_sets: parameter_sets.clone(),
                },
                DigestInputs::AnnexB { spans } => DigestInputs::AnnexB {
                    spans: spans.clone(),
                },
            },
            recorded_slices: record.recorded_slices,
            raw_bits: record.raw_bits.clone(),
            slice_slot_ranges: record.slice_slot_ranges.clone(),
            capacity_band_counts: record.capacity_band_counts,
        },
        secret,
        domain,
        fmt,
        control,
    )
}

/// Inspect HEVC carrier for steganographic header using an already recorded carrier state.
#[allow(clippy::too_many_arguments)]
fn inspect_hevc_record(
    carrier: &[u8],
    kind: HevcCarrierKind,
    record: &CarrierRecord,
    media_info: Option<MediaInfo>,
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    control.check()?;
    let media_info = media_info.or_else(|| {
        let (width, height) = extract_hevc_dimensions(carrier).unwrap_or((0, 0));
        if width > 0 && height > 0 {
            Some(MediaInfo::new(width, height))
        } else {
            None
        }
    });
    let mut empty_info = StegoHeaderInfo::empty(kind.label());
    empty_info.media_info = media_info;

    if check_l1_floor(&cred, limits).is_err() {
        log::debug!(
            target: "stego::inspect",
            "hevc inspect skipped: level-1 key derivation exceeds the configured PBKDF2 budget"
        );
        return Ok(empty_info);
    }
    let header = match read_hevc_header_v4(carrier, record, cred, domain, fmt, limits) {
        Ok(Some(header)) => header,
        // "No header here" is the normal answer for a clean carrier and must
        // stay silent; only a failure to *read* one is worth a record.
        Ok(None) => return Ok(empty_info),
        Err(e) => {
            log::debug!(
                target: "stego::inspect",
                "hevc header read failed for {}: {e}",
                kind.label()
            );
            return Ok(empty_info);
        }
    };

    Ok(hevc_header_info(kind, &header, media_info).unwrap_or(empty_info))
}

/// Header report shared by `inspect` and `verify`.
fn hevc_header_info(
    kind: HevcCarrierKind,
    header: &HevcHeaderRead,
    media_info: Option<MediaInfo>,
) -> Option<StegoHeaderInfo> {
    let _suite = CipherSuiteId::from_u16(header.sb.suite_id)?;
    // Plaintext length is unknowable prior to decryption due to variable compression,
    // optional filename micro-headers, and AEAD overhead. Report `None` until decrypted.
    Some(StegoHeaderInfo {
        format: kind.label().to_string(),
        has_hidden_data: true,
        algorithm: Some("HEVC-CABAC-InPlace".into()),
        codec: Some(format!("STC (h=7, u={})", header.sb.stc_u)),
        envelope_len: Some(
            HEVC_SUPERBLOCK_BYTES + header.extension.len() + header.sb.body_len as usize,
        ),
        payload_len: None,
        media_info,
        note: None,
    })
}

/// Inspect HEVC carrier for steganographic header.
#[allow(dead_code)]
pub(crate) fn inspect_hevc(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    inspect_hevc_v4(
        carrier,
        legacy_credential(secret)?,
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// Credential-aware inspection with explicit policy limits.
pub(crate) fn inspect_hevc_v4(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    control.check()?;
    let kind = match sniff_hevc_carrier(carrier) {
        Some(k) => k,
        None => return Ok(StegoHeaderInfo::empty("HEVC")),
    };

    let (width, height) = extract_hevc_dimensions(carrier).unwrap_or((0, 0));
    let media_info = if width > 0 && height > 0 {
        Some(MediaInfo::new(width, height))
    } else {
        None
    };
    let mut empty_info = StegoHeaderInfo::empty(kind.label());
    empty_info.media_info = media_info;

    let record = match record_carrier_state(
        carrier,
        kind,
        Capture::Bits,
        StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
        control,
    ) {
        Ok(r) => r,
        Err(e) => {
            // Reaching a carrier that sniffs as HEVC and then fails to record
            // its structure is a parse failure, not "nothing hidden".
            log::debug!(
                target: "stego::inspect",
                "hevc carrier record failed for {}: {e}",
                kind.label()
            );
            return Ok(empty_info);
        }
    };
    inspect_hevc_record(
        carrier, kind, &record, media_info, cred, domain, fmt, limits, control,
    )
}

/// Prefix of a sample the streaming has-inter probe reads. Every VCL NAL that
/// identifies a picture sits at or near the sample start (AUD/SEI prefixes are
/// a few hundred bytes), so 1 MiB is enough without materialising a 64 MiB
/// sample just to classify it.
const HAS_INTER_PREFIX_BYTES: usize = 1024 * 1024;

/// Does the sample prefix contain a non-IRAP VCL NAL?
///
/// Walks the length-prefixed NALs exactly like `collect_sample_slice_spans`
/// (VCL only, forbidden bit clear, non-zero temporal id) but stops at the first
/// incomplete NAL instead of rejecting the prefix as truncated.
fn sample_prefix_has_inter(prefix: &[u8], length_size: usize) -> bool {
    if !(1..=4).contains(&length_size) {
        return false;
    }
    let mut pos = 0usize;
    while pos + length_size <= prefix.len() {
        let nal_len = match length_size {
            1 => prefix[pos] as usize,
            2 => u16::from_be_bytes([prefix[pos], prefix[pos + 1]]) as usize,
            3 => {
                ((prefix[pos] as usize) << 16)
                    | ((prefix[pos + 1] as usize) << 8)
                    | prefix[pos + 2] as usize
            }
            _ => u32::from_be_bytes([
                prefix[pos],
                prefix[pos + 1],
                prefix[pos + 2],
                prefix[pos + 3],
            ]) as usize,
        };
        let nal_start = pos + length_size;
        if nal_start + 2 > prefix.len() {
            return false;
        }
        let b0 = prefix[nal_start];
        let b1 = prefix[nal_start + 1];
        let nal_type = (b0 >> 1) & 0x3F;
        if nal_type <= 31 && (b0 & 0x80) == 0 && (b1 & 0x07) > 0 && !is_irap(nal_type) {
            return true;
        }
        let Some(nal_end) = nal_start.checked_add(nal_len) else {
            return false;
        };
        if nal_end > prefix.len() {
            return false;
        }
        pos = nal_end;
    }
    false
}

/// Stream-inspect an MP4 carrier directly from disk using Seek + Read, so peak
/// memory stays bounded by the `moov` (<= 32 MiB) plus one sample
/// (<= `MAX_HEVC_SAMPLE_BYTES`) even for multi-gigabyte video files.
#[allow(dead_code)]
pub(crate) fn inspect_hevc_mp4_file(
    carrier_path: &std::path::Path,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    inspect_hevc_mp4_file_v4(
        carrier_path,
        legacy_credential(secret)?,
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// Credential-aware streaming MP4 inspection with explicit policy limits.
pub(crate) fn inspect_hevc_mp4_file_v4(
    carrier_path: &std::path::Path,
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    use std::io::{Read, Seek, SeekFrom};
    control.check()?;

    let mut file = std::fs::File::open(carrier_path)?;
    let file_len = file.metadata()?.len() as usize;

    let mut pos: u64 = 0;
    let mut moov_box: Option<(u64, usize)> = None;
    while pos + 8 <= file_len as u64 {
        file.seek(SeekFrom::Start(pos))?;
        let mut header = [0u8; 8];
        if file.read_exact(&mut header).is_err() {
            break;
        }
        let size32 = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let tag = [header[4], header[5], header[6], header[7]];
        let (header_len, total_size) = if size32 == 1 {
            let mut s64 = [0u8; 8];
            if file.read_exact(&mut s64).is_err() {
                break;
            }
            (16u64, u64::from_be_bytes(s64))
        } else if size32 == 0 {
            (8u64, (file_len as u64) - pos)
        } else {
            (8u64, size32 as u64)
        };
        if total_size < header_len
            || pos
                .checked_add(total_size)
                .is_none_or(|e| e > file_len as u64)
        {
            break;
        }
        if &tag == b"moov" {
            moov_box = Some((pos, total_size as usize));
            break;
        }
        pos += total_size;
    }

    let (moov_pos, moov_size) = match moov_box {
        Some(b) => b,
        None => return Ok(StegoHeaderInfo::empty("MP4/HEVC")),
    };

    if moov_size > 32 * 1024 * 1024 {
        return Err(StrHideError::UnsupportedFormat(
            "MP4 moov box exceeds 32 MiB".into(),
        ));
    }

    file.seek(SeekFrom::Start(moov_pos))?;
    let mut moov_bytes = vec![0u8; moov_size];
    file.read_exact(&mut moov_bytes)?;

    let target = match crate::stego::hevc::mp4_boxes::parse_moov_target(&moov_bytes, file_len) {
        Ok(t) => t,
        Err(e) => {
            // The moov box was located and read; failing to parse its targets
            // is a malformed container, not an empty carrier.
            log::debug!(
                target: "stego::inspect",
                "mp4 moov target parse failed: {e}"
            );
            return Ok(StegoHeaderInfo::empty("MP4/HEVC"));
        }
    };

    let mut media_info = None;
    for ps in &target.parameter_sets {
        if ps.len() > 2
            && (ps[0] >> 1) & 0x3F == NAL_SPS_NUT
            && let Some(dims) = sps_dimensions(&nal_rbsp(ps))
        {
            let base = MediaInfo::new(dims.0, dims.1);
            media_info = Some(match (target.fps, target.duration_secs) {
                (Some(fps), Some(sec)) if sec > 0.0 => {
                    let bps = (file_len as f64 * 8.0) / sec;
                    base.with_video(
                        fps as f32,
                        (sec * 1000.0).round() as u64,
                        bps.round() as u64,
                    )
                }
                _ => base,
            });
            break;
        }
    }

    let mut empty_info = StegoHeaderInfo::empty("MP4/HEVC");
    empty_info.media_info = media_info;

    // Detect if this MP4 stream contains inter-coded frames (P/B). When has_inter is true,
    // IDR/IRAP frames are excluded from the superblock pool to protect prediction stability.
    let mut has_inter = false;
    for &(sample_offset, sample_size) in &target.samples {
        if sample_size < target.length_size + 2 || sample_offset + sample_size > file_len {
            continue;
        }
        // Same ceiling as `parse_mp4_targets`: samples the byte-level path
        // skips must not influence `has_inter` here either.
        if sample_size <= crate::stego::hevc::mp4_boxes::MAX_HEVC_SAMPLE_BYTES {
            let prefix_len = sample_size.min(HAS_INTER_PREFIX_BYTES);
            let mut hdr_buf = vec![0u8; prefix_len];
            if file.seek(SeekFrom::Start(sample_offset as u64)).is_ok()
                && file.read_exact(&mut hdr_buf).is_ok()
                && sample_prefix_has_inter(&hdr_buf, target.length_size)
            {
                has_inter = true;
                break;
            }
        }
    }

    let mut decoder = Decoder::new();
    decoder.skip_loop_filters = true;
    decoder.ablate = Ablate {
        mc: true,
        intra: true,
        residual: true,
    };
    for ps in &target.parameter_sets {
        let _ = decoder.push_nal(ps, None);
    }
    let parameter_sets = owned_parameter_sets(&target.parameter_sets);

    let mut sink = SlotSink::new(Capture::Bits);
    let mut recorded_slices = 0usize;
    let mut slice_idx = 0usize;

    for &(sample_offset, sample_size) in &target.samples {
        control.check()?;
        if sample_size < 4 || sample_offset + sample_size > file_len {
            continue;
        }
        if sample_size > crate::stego::hevc::mp4_boxes::MAX_HEVC_SAMPLE_BYTES {
            // Same ceiling the byte-level recorder applies, so the slot pool is
            // rebuilt from the same set of samples.
            continue;
        }
        file.seek(SeekFrom::Start(sample_offset as u64))?;
        let mut sample_buf = vec![0u8; sample_size];
        if file.read_exact(&mut sample_buf).is_err() {
            continue;
        }

        let mut spans = Vec::new();
        if crate::stego::hevc::mp4_boxes::collect_sample_slice_spans(
            &sample_buf,
            0,
            sample_size,
            target.length_size,
            &mut spans,
        )
        .is_err()
        {
            continue;
        }

        for span in spans {
            let slice_bytes = &sample_buf[span.start..span.end()];
            if slice_bytes.len() < 2 {
                continue;
            }
            let (nal_type, _, _) = nal_header_fields(slice_bytes);
            let Some(band) = picture_band(nal_type, has_inter) else {
                let _ = decoder.push_nal(slice_bytes, None);
                drain_frames(&mut decoder);
                continue;
            };

            let mut recorder = CabacRecorder::with_slice_mode(slice_idx, band, RecordMode::Slots);
            let decoded = decoder.decode_nal_with_observer(slice_bytes, &mut recorder);
            drain_frames(&mut decoder);
            if decoded.is_ok() && !recorder.substreams.is_empty() {
                let rbsp = nal_rbsp(slice_bytes);
                if absorb_recorder(&mut recorder, &rbsp, &mut sink) {
                    recorded_slices += 1;
                    slice_idx += 1;
                    let current_slots = sink.counts[0] + sink.counts[1];
                    if current_slots >= HEVC_SUPERBLOCK_POOL_SLOTS {
                        break;
                    }
                }
            }
        }

        let current_slots = sink.counts[0] + sink.counts[1];
        if current_slots >= HEVC_SUPERBLOCK_POOL_SLOTS {
            break;
        }
    }

    let total_slots = sink.counts[0] + sink.counts[1];
    if total_slots < HEVC_SUPERBLOCK_MIN_SLOTS {
        return Ok(empty_info);
    }

    let SlotSink {
        counts,
        band_bits,
        raw_bits,
        raw_slots,
        slice_slot_ranges,
        ..
    } = sink;
    let band0_len = counts[0];
    let [band0_bits, band1_bits] = band_bits;
    let bands = vec![0..band0_len, band0_len..total_slots];

    let record = CarrierRecord {
        slice_contexts: Vec::new(),
        all_slots: raw_slots,
        band_bits: [band0_bits.bytes, band1_bits.bytes],
        bands,
        pictures: target.picture_count,
        band_pictures: [target.picture_count, 0],
        digest_inputs: DigestInputs::ParameterSets { parameter_sets },
        recorded_slices,
        raw_bits: raw_bits.bytes,
        slice_slot_ranges,
        capacity_band_counts: None,
    };

    inspect_hevc_record(
        &[],
        HevcCarrierKind::Mp4Container,
        &record,
        media_info,
        cred,
        domain,
        fmt,
        limits,
        control,
    )
}

/// Three-level diagnostic verification for HEVC carriers.
#[allow(dead_code)]
pub(crate) fn verify_hevc(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    verify_hevc_v4(
        carrier,
        legacy_credential(secret)?,
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// Credential-aware three-level verification with explicit policy limits.
pub(crate) fn verify_hevc_v4(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    control.check()?;
    let mut levels = Vec::new();
    let format_name = sniff_hevc_carrier(carrier).map_or("HEVC", |k| k.label());

    let kind = match sniff_hevc_carrier(carrier) {
        Some(k) => k,
        None => {
            levels.push(VerifyLevel::fail(
                1,
                "HEVC container format",
                "Unrecognized HEVC carrier",
            ));
            levels.push(VerifyLevel::fail(
                2,
                "Stego header",
                "Skipped due to level 1 failure",
            ));
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                "Skipped due to level 1 failure",
            ));
            return Ok(StegoVerifyResult::new(format_name, levels));
        }
    };

    let record = match record_carrier_state(
        carrier,
        kind,
        Capture::Bits,
        StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
        control,
    ) {
        Ok(rec) => {
            levels.push(VerifyLevel::pass(
                1,
                format!(
                    "HEVC bitstream and CABAC slots valid ({} slots)",
                    rec.total_slots()
                ),
            ));
            rec
        }
        Err(e) => {
            levels.push(VerifyLevel::fail(1, "HEVC bitstream parse", e.to_string()));
            levels.push(VerifyLevel::fail(
                2,
                "Stego header",
                "Skipped due to level 1 failure",
            ));
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                "Skipped due to level 1 failure",
            ));
            return Ok(StegoVerifyResult::new(format_name, levels));
        }
    };
    control.check()?;

    // The V4 L1 cost is fixed; a policy below it must fail with a policy
    // verdict, not "wrong password" (plan §4.2), and it must not pay PBKDF2.
    if matches!(cred, Credential::Password(_))
        && limits.max_pbkdf2_iterations < CONTENT_L1_PBKDF2_ITERATIONS
    {
        levels.push(VerifyLevel::fail(
            2,
            "Stego header",
            format!(
                "PBKDF2 iteration limit {} is below the V4 L1 cost {}",
                limits.max_pbkdf2_iterations, CONTENT_L1_PBKDF2_ITERATIONS
            ),
        ));
        levels.push(VerifyLevel::fail(
            3,
            "Payload decryption",
            "Skipped due to level 2 policy failure",
        ));
        return Ok(StegoVerifyResult::new(format_name, levels));
    }

    // One header read serves both level 2 and level 3: re-deriving it in the
    // extract step paid the 200k-iteration L1 twice for one request (M-14).
    let media_info = {
        let (width, height) = extract_hevc_dimensions(carrier).unwrap_or((0, 0));
        if width > 0 && height > 0 {
            Some(MediaInfo::new(width, height))
        } else {
            None
        }
    };
    let header = match read_hevc_header_v4(carrier, &record, cred, domain, fmt, limits) {
        Ok(Some(header)) => header,
        // Split from the `Err` arm on purpose: reporting "wrong password" for
        // a carrier the reader could not parse sends the user chasing a
        // credential that was never the problem.
        Ok(None) => {
            levels.push(VerifyLevel::fail(
                2,
                "Stego header",
                "No valid HEVC stego signature found (or wrong password)",
            ));
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                "No stego header to extract payload from",
            ));
            return Ok(StegoVerifyResult::new(format_name, levels));
        }
        Err(e) => {
            log::debug!(target: "stego::verify", "hevc header read failed: {e}");
            levels.push(VerifyLevel::fail(
                2,
                "Stego header",
                format!("Stego header could not be read: {e}"),
            ));
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                "Skipped because the header could not be read",
            ));
            return Ok(StegoVerifyResult::new(format_name, levels));
        }
    };
    let Some(header_info) = hevc_header_info(kind, &header, media_info) else {
        levels.push(VerifyLevel::fail(
            2,
            "Stego header",
            "No valid HEVC stego signature found (or wrong password)",
        ));
        levels.push(VerifyLevel::fail(
            3,
            "Payload decryption",
            "No stego header to extract payload from",
        ));
        return Ok(StegoVerifyResult::new(format_name, levels));
    };
    levels.push(VerifyLevel::pass(
        2,
        format!(
            "Stego header valid (payload: {} B, total: {} B)",
            header_info.payload_len.unwrap_or(0),
            header_info.envelope_len.unwrap_or(0),
        ),
    ));
    control.check()?;

    match extract_hevc_with_header(carrier, kind, record, &header, fmt, limits, control) {
        Ok(payload) => {
            let desc = match payload.name() {
                Some(name) => format!(
                    "Payload decrypted & verified ({} bytes, filename: '{}')",
                    payload.len(),
                    name
                ),
                None => format!(
                    "Payload decrypted & verified ({} bytes, raw/text)",
                    payload.len()
                ),
            };
            levels.push(VerifyLevel::pass(3, desc));
        }
        Err(e) => {
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                format!("Decryption or authentication failed: {e}"),
            ));
        }
    }

    Ok(StegoVerifyResult::new(format_name, levels))
}

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
