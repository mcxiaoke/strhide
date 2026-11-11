//! Capacity probing: slot estimation, SPS dimensions and safety tiers.
//!
//! `probe` and `embed` must agree to the byte, so every formula that turns
//! slots into a payload lives here, next to the scan that measures them.

use crate::core::control::{Control, Event, Stage};
use crate::core::media::MediaInfo;
use crate::errors::StrHideError;
use crate::stego::coding::StcTrellis;
use crate::stego::envelope::BODY_OVERHEAD;
use crate::stego::format::HevcFormatProfile;
use crate::stego::header::Tlv;
use crate::stego::hevc::bitstream::parse_annex_b_spans;
use crate::stego::hevc::heif_boxes::parse_heif_targets;
use crate::stego::hevc::slot::{CabacRecorder, RecordMode};
use crate::stego::hevc::sniff::{HevcCarrierKind, NAL_SPS_NUT, sniff_hevc_carrier};
use crate::stego::{SafetyLevel, SafetyPolicy, StegoCapacityInfo};
use rusty_h265::Decoder;
use rusty_h265::ctu::Ablate;
use rusty_h265::ps::parse_sps;

use super::record::record_carrier_state;
use super::scan::{
    Capture, PoolProfile, candidate_slice, count_pictures, drain_frames, is_irap, picture_band,
    scan_hevc_slot_count,
};
use super::support::{
    CAPACITY_PROBE_SEED, StopCondition, extension_len, hevc_max_raw_payload, nal_rbsp,
};
use crate::stego::hevc::mp4_boxes::parse_mp4_targets;
use crate::stego::hevc::superblock::hevc_header_slots;

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
pub(super) fn sps_dimensions(rbsp: &[u8]) -> Option<(u32, u32)> {
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

pub(super) fn probe_hevc_pool(
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
pub(super) fn enforce_safety(
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
