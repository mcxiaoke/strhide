//! HEVC / H.265 In-place CABAC Bypass Steganography Engine (Scheme C).
//!
//! Provides zero bitrate expansion (Δ = 0), content-adaptive distortion-minimized
//! steganographic embedding and extraction directly within H.265/HEVC bitstreams.

use aes_gcm::aead::{Aead, KeyInit, Payload as AeadPayload};
use aes_gcm::{Aes256Gcm, Nonce};
use crc32fast::Hasher as Crc32;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

use crate::core::control::{Control, Event, Stage};
use crate::core::media::MediaInfo;
use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::stego::coding::{Move, StcTrellis};
use crate::stego::envelope::{
    Freshness, PUBLIC_DEFAULT_SECRET, decode_micro_header, derive_domain_subkey_with_label,
    encode_micro_header,
};
use crate::stego::format::HevcFormatProfile;
use crate::stego::hevc::bitstream::{compute_hevc_cover_digest, parse_annex_b_spans, rbsp_to_nal};
use crate::stego::hevc::heif_boxes::parse_heif_targets;
use crate::stego::hevc::mp4_boxes::parse_mp4_targets;
use crate::stego::hevc::slot::{BinOp, CabacRecorder, RecordMode, StegoSlot, SubstreamRecord};
use crate::stego::hevc::sniff::{
    HevcCarrierKind, NAL_RADL_N, NAL_RASL_N, NAL_RASL_R, NAL_SPS_NUT, NAL_STSA_N, NAL_TRAIL_N,
    NAL_TSA_N, sniff_hevc_carrier,
};
use crate::stego::options::{StegoHeaderInfo, StegoVerifyResult, VerifyLevel};
use crate::stego::{SafetyLevel, SafetyPolicy, StegoCapacityInfo};
use oxideav_h265::cabac::ContextModel;
use oxideav_h265::encoder::bitwriter::BitWriter;
use oxideav_h265::encoder::cabac::CabacEncoder;
use rayon::prelude::*;
use rusty_h265::Decoder;
use rusty_h265::ctu::Ablate;
use rusty_h265::observer::ENCODER_CONTEXTS;
use rusty_h265::ps::parse_sps;

/// Derive the 4-byte header magic from the format's magic label and the
/// effective secret.
///
/// A fixed magic (`SH25`) plus a password-independent header location was a
/// presence oracle: anyone could locate the header slots from the parameter
/// sets alone and check for the constant, without any credential. Deriving it
/// from `label ‖ secret` means a carrier only "looks like Scheme C" to a
/// holder of the same dialect; for everyone else the header reads as noise,
/// exactly like an empty carrier.
fn derive_magic(label: &[u8], secret: &[u8]) -> [u8; 4] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(secret);
    let digest = hasher.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

/// The three header fields the writer needs back, read straight off the 2-byte
/// NAL header (§7.3.1.2). The decoder hands us the same stream but not the
/// envelope, and the span table only covers Annex-B carriers.
fn nal_header_fields(nal: &[u8]) -> (u8, u8, u8) {
    debug_assert!(nal.len() >= 2, "a NAL header is two bytes");
    let (b0, b1) = (nal[0], nal[1]);
    (
        (b0 >> 1) & 0x3F,
        ((b0 & 0x01) << 5) | (b1 >> 3),
        (b1 & 0x07).saturating_sub(1),
    )
}

/// RBSP payload of a NAL unit (§7.4.2 emulation prevention removal).
///
/// The decoder applies exactly this transform before CABAC, so the substream
/// byte offsets in the journal index the buffer this returns.
fn nal_rbsp(nal: &[u8]) -> Vec<u8> {
    rusty_h265::nal::unescape(&nal[2..]).data
}

/// Fixed seed for the capacity probe's trellis. Only `slots_for` is used
/// (which depends on `h`/`u`, not the seed), so any value works.
const CAPACITY_PROBE_SEED: u64 = 0x5465_676f;

/// Maximum number of STC re-solves while settling the flip set. Each round
/// either drops the slots that disturbed an emulation-prevention (EPB) window,
/// drops a substream whose journal does not replay the cover, or gives up, so
/// the loop always makes progress. Healthy carriers settle in one round.
const MAX_EMBED_ROUNDS: usize = 24;

/// Extra cost added to a slot excluded by an earlier round. It must lift the
/// slot strictly above its own legal cost: a legal high-displacement slot
/// already costs `HIGH_DISPLACEMENT_PENALTY + l2_cost`, so reusing the bare
/// penalty here made excluded slots *cheaper* and the trellis preferred them.
const FORBIDDEN_SLOT_SURCHARGE: f64 = 1e9;

/// Fixed 32-byte HEVC Superblock for Scheme C v2.
pub const HEVC_SUPERBLOCK_BYTES: usize = 32;
/// Number of initial carrier slots that form the Superblock candidate pool.
pub const HEVC_SUPERBLOCK_POOL_SLOTS: usize = 2048;
/// Minimum slots needed to embed the 32-byte Superblock with STC h=7, u=2.
pub const HEVC_SUPERBLOCK_MIN_SLOTS: usize = 524;
/// AES-256-GCM tag length appended to the ciphertext.
pub const HEVC_TAG_BYTES: usize = 16;

/// Fixed-size 32-byte header anchored in the initial carrier slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HevcSuperblock {
    /// 4-byte credential-derived magic.
    pub magic: [u8; 4],
    /// High 4 bits: version (0x2); bit 0: multi-window flag.
    pub version_and_flags: u8,
    /// STC group size `u` used for the payload body.
    pub stc_u_body: u8,
    /// Number of recorded candidate slices in the primary window W0.
    pub window_slices: u16,
    /// Total number of windows M (1 for single-window).
    pub total_windows: u16,
    /// Reserved, must be 0.
    pub reserved: u16,
    /// Compressed/micro-header payload length in bytes.
    pub payload_len: u32,
    /// Payload CRC32.
    pub payload_crc32: u32,
    /// AES-256-GCM 12-byte nonce.
    pub nonce: [u8; 12],
}

impl HevcSuperblock {
    pub fn encode(&self) -> [u8; HEVC_SUPERBLOCK_BYTES] {
        let mut buf = [0u8; HEVC_SUPERBLOCK_BYTES];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4] = self.version_and_flags;
        buf[5] = self.stc_u_body;
        buf[6..8].copy_from_slice(&self.window_slices.to_be_bytes());
        buf[8..10].copy_from_slice(&self.total_windows.to_be_bytes());
        buf[10..12].copy_from_slice(&self.reserved.to_be_bytes());
        buf[12..16].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[16..20].copy_from_slice(&self.payload_crc32.to_be_bytes());
        buf[20..32].copy_from_slice(&self.nonce);
        buf
    }

    pub fn decode(buf: &[u8; HEVC_SUPERBLOCK_BYTES]) -> Result<Self, StrHideError> {
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buf[0..4]);
        let version_and_flags = buf[4];
        let version = version_and_flags >> 4;
        if version != 2 {
            return Err(StrHideError::CorruptedData(format!(
                "Unsupported HEVC stego version: {version}"
            )));
        }
        let stc_u_body = buf[5];
        let window_slices = u16::from_be_bytes([buf[6], buf[7]]);
        let total_windows = u16::from_be_bytes([buf[8], buf[9]]);
        let reserved = u16::from_be_bytes([buf[10], buf[11]]);
        let payload_len = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let payload_crc32 = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&buf[20..32]);
        Ok(HevcSuperblock {
            magic,
            version_and_flags,
            stc_u_body,
            window_slices,
            total_windows,
            reserved,
            payload_len,
            payload_crc32,
            nonce,
        })
    }
}

/// Early-exit stopping condition for streaming NAL decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopCondition {
    /// Full scan (for probe_hevc_capacity).
    All,
    /// Stop as soon as at least `min_slots` are accumulated (for Superblock probing).
    MinSlots(usize),
    /// Stop after `target` recorded slices (for window extraction).
    TargetSlices(usize),
    /// Stop as soon as at least `target` slots are accumulated (for window embedding).
    TargetSlots(usize),
}

/// Select the deterministic Weyl slots for the 32-byte Superblock within candidate pool.
pub fn superblock_positions(pool_size: usize) -> Vec<usize> {
    assert!(pool_size >= HEVC_SUPERBLOCK_MIN_SLOTS);
    let count = HEVC_SUPERBLOCK_MIN_SLOTS;
    let stride = permutation_stride(pool_size);
    let mut positions = Vec::with_capacity(count);
    for i in 0..count {
        positions.push(((i as u64 * stride as u64) % pool_size as u64) as usize);
    }
    positions
}

/// Partition non-Superblock slots within the window into Band 0 and Band 1 stream indices.
fn get_body_slot_indices(
    total_slots: usize,
    pool_size: usize,
    sb_positions: &[usize],
    slice_slot_ranges: &[(usize, u8)],
) -> (Vec<usize>, Vec<usize>) {
    let pool_limit = pool_size.min(total_slots);
    let mut is_sb_small = vec![false; pool_limit];
    for &pos in sb_positions {
        if pos < pool_limit {
            is_sb_small[pos] = true;
        }
    }
    let mut band0 = Vec::new();
    let mut band1 = Vec::new();
    let mut current_slot = 0usize;
    for &(count, band) in slice_slot_ranges {
        let end_slot = (current_slot + count).min(total_slots);
        if current_slot >= end_slot {
            current_slot += count;
            continue;
        }
        let target = if band == 0 { &mut band0 } else { &mut band1 };
        if current_slot < pool_limit {
            let prefix_end = end_slot.min(pool_limit);
            for (offset, &is_sb) in is_sb_small[current_slot..prefix_end].iter().enumerate() {
                if !is_sb {
                    target.push(current_slot + offset);
                }
            }
            if end_slot > pool_limit {
                target.extend(pool_limit..end_slot);
            }
        } else {
            target.extend(current_slot..end_slot);
        }
        current_slot += count;
    }
    (band0, band1)
}

/// `fmt.header_bytes` must at least cover the fixed Superblock.
fn check_header_bytes(fmt: &HevcFormatProfile) -> Result<(), StrHideError> {
    if fmt.header_bytes < HEVC_SUPERBLOCK_BYTES {
        return Err(StrHideError::UnsupportedVersion(format!(
            "HevcFormatProfile.header_bytes must be >= {HEVC_SUPERBLOCK_BYTES}, got {}",
            fmt.header_bytes
        )));
    }
    Ok(())
}

/// Where a flipped bypass bin landed in the codeword:
/// `(global slot index, first affected RBSP byte, last affected RBSP byte)`.
type SlotBitTrace = (usize, usize, usize);

/// A disturbed emulation-prevention window: the RBSP byte that starts the
/// `00 00 xx<=3` triple, plus the trace of every flipped slot in that slice.
type EpbConflict = (usize, Vec<SlotBitTrace>);

/// Capacity probe: returns the maximum embeddable payload size in bytes.
///
/// `fmt` supplies the trellis geometry and header size the capacity is
/// measured against, so a private dialect reports its own ceiling.
pub fn probe_hevc_capacity(carrier: &[u8], fmt: &HevcFormatProfile) -> Result<usize, StrHideError> {
    sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;
    let total_slots = scan_hevc_slot_count(carrier)?;
    let trellis = StcTrellis::from_seed_grouped(CAPACITY_PROBE_SEED, fmt.stc_h, fmt.stc_u)?;
    if total_slots < HEVC_SUPERBLOCK_MIN_SLOTS {
        return Ok(0);
    }
    let body_slots = total_slots.saturating_sub(HEVC_SUPERBLOCK_MIN_SLOTS);
    let available_bits = trellis.message_bits(body_slots);
    let available_bytes = (available_bits / 8).saturating_sub(HEVC_TAG_BYTES);
    Ok(available_bytes.saturating_sub(1))
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
        HevcCarrierKind::Mp4Container => {
            let target = parse_mp4_targets(carrier).map_err(|e| {
                StrHideError::UnsupportedFormat(format!("MP4/MOV parse error: {e}"))
            })?;
            // The sample entries carry no size of their own that can be
            // trusted (they duplicate the SPS, and some writers leave them
            // wrong); the `hvcC` SPS is the same one the decoder will use.
            for ps in &target.parameter_sets {
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
    control.stage(Stage::Decode);
    let pool = probe_hevc_pool(carrier, kind, exact, control)?;
    // The pool scan is the long part of an exact probe; report before the
    // (cheap) summary is built so a cancellation lands after the scan, not
    // silently in the middle of it.
    control.check()?;
    build_hevc_capacity_info(carrier, kind, fmt, &pool, safety_level)
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
    safety_level: SafetyLevel,
) -> Result<StegoCapacityInfo, StrHideError> {
    let format_name = match kind {
        HevcCarrierKind::HeifContainer => "HEIF/HEVC",
        HevcCarrierKind::AnnexBStream => "HEVC-AnnexB",
        HevcCarrierKind::Mp4Container => "MP4/HEVC",
    };

    let total_slots = pool.total_slots;
    let trellis = StcTrellis::from_seed_grouped(CAPACITY_PROBE_SEED, fmt.stc_h, fmt.stc_u)?;

    let max_raw_payload_bytes = if total_slots < HEVC_SUPERBLOCK_MIN_SLOTS {
        0
    } else {
        let body_slots = total_slots.saturating_sub(HEVC_SUPERBLOCK_MIN_SLOTS);
        let available_bits = trellis.message_bits(body_slots);
        let available_bytes = (available_bits / 8).saturating_sub(HEVC_TAG_BYTES);
        available_bytes.saturating_sub(1)
    };

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

    let target_bits = if picture_count > 1 {
        let budget = safety_level.video_budget();
        let non_ref_slots = (pool.band_slots[0] as f64 * budget.non_ref_fraction).floor() as usize;
        let ref_slots = budget
            .ref_flips_per_picture
            .saturating_mul(pool.band_pictures[1])
            .saturating_mul(SLOTS_PER_REF_FLIP)
            .min(pool.band_slots[1]);
        trellis.message_bits(non_ref_slots.saturating_add(ref_slots))
    } else {
        let bpp_bits = (total_elements as f64 * safety_level.bpp_limit()).floor() as usize;
        let ratio_bits = (total_slots as f64 / safety_level.target_ratio()).floor() as usize;
        bpp_bits.min(ratio_bits)
    };
    let recommended_max_bytes = (target_bits / 8)
        .saturating_sub(fmt.header_bytes + 1)
        .min(max_raw_payload_bytes);

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

/// Apply in-place NAL patches to a mutable carrier buffer.
pub fn apply_hevc_patches(carrier: &mut [u8], patches: &[HevcCarrierPatch]) {
    for (span, re_nal) in patches {
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
    let (patches, capacity_info, stats) = embed_hevc_patches(
        carrier, payload, secret, domain, fmt, freshness, safety, control,
    )?;
    let mut out_carrier = carrier.to_vec();
    apply_hevc_patches(&mut out_carrier, &patches);
    Ok((out_carrier, capacity_info, stats))
}

/// Embed a payload into an HEVC carrier and return in-place NAL delta patches.
///
/// This avoids cloning or mutating the entire carrier in memory, allowing zero-heap-overhead
/// streaming commit to disk via `commit_carrier_patches`.
#[allow(clippy::too_many_arguments)]
pub fn embed_hevc_patches(
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
    if payload.is_empty() {
        return Err(StrHideError::General("Cannot embed empty payload".into()));
    }
    check_header_bytes(fmt)?;

    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;

    // 1. Calculate required capacity and stream window
    let uncompressed = encode_micro_header(payload);
    let body_msg_len = uncompressed.len() + HEVC_TAG_BYTES;
    let body_needed_slots = StcTrellis::slots_for_params(body_msg_len * 8, fmt.stc_h, fmt.stc_u);
    let non_ref_fraction = safety.level.video_budget().non_ref_fraction;
    let factor = if window_factor > 1.0 {
        window_factor
    } else if kind == HevcCarrierKind::HeifContainer {
        1.0
    } else {
        (1.0 / non_ref_fraction).max(1.0)
    };
    let desired_body_slots = ((body_needed_slots as f64) * factor).ceil() as usize;
    let target_slots = HEVC_SUPERBLOCK_POOL_SLOTS + desired_body_slots + 128;

    control.stage(Stage::Decode);
    let record = record_carrier_state(
        carrier,
        kind,
        Capture::Full,
        StopCondition::TargetSlots(target_slots),
        control,
    )?;
    control.check()?;
    control.stage(Stage::Solve);
    let pool = PoolProfile::from_record(&record);
    let capacity_info = build_hevc_capacity_info(carrier, kind, fmt, &pool, safety.level)?;

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

    if pool_size < HEVC_SUPERBLOCK_MIN_SLOTS
        || total_slots < HEVC_SUPERBLOCK_MIN_SLOTS + body_needed_slots
    {
        return Err(StrHideError::General(format!(
            "HEVC carrier capacity exceeded: needed at least {} slots, but carrier only has {}",
            HEVC_SUPERBLOCK_MIN_SLOTS + body_needed_slots,
            total_slots
        )));
    }

    let is_video = kind == HevcCarrierKind::Mp4Container || record.pictures > 1;
    if is_video && total_slots < HEVC_SUPERBLOCK_MIN_SLOTS + desired_body_slots {
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
            needed = HEVC_SUPERBLOCK_MIN_SLOTS + desired_body_slots,
            available = total_slots,
        )));
    }

    // 2. Derive Superblock and Body slot positions
    let sb_positions = superblock_positions(pool_size);
    let (body_band0, body_band1) = get_body_slot_indices(
        total_slots,
        pool_size,
        &sb_positions,
        &record.slice_slot_ranges,
    );
    let body_bands = vec![
        0..body_band0.len(),
        body_band0.len()..(body_band0.len() + body_band1.len()),
    ];
    let mut all_body_indices = body_band0;
    all_body_indices.extend(body_band1);
    let body_positions_rel = band_positions(&body_bands, body_needed_slots);
    let body_positions: Vec<usize> = body_positions_rel
        .into_iter()
        .map(|rel| all_body_indices[rel])
        .collect();

    // 3. Prepare Superblock and AEAD ciphertext
    let cover_digest = derive_carrier_digest(carrier, &record.digest_inputs, fmt);
    let key = derive_hevc_key(secret, domain, &cover_digest, fmt);
    let magic = derive_magic(fmt.magic_label, effective_secret(secret).as_bytes());
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| StrHideError::General(format!("AES-GCM key init failed: {e}")))?;

    let fresh_binding = Freshness::seeded_binding(carrier, payload.as_bytes());
    let nonce_bytes = freshness.nonce(0, &fresh_binding);
    let nonce = Nonce::from(nonce_bytes);

    let mut crc = Crc32::new();
    crc.update(&uncompressed);
    let payload_crc = crc.finalize();

    let window_slices = u16::try_from(slice_contexts.len()).map_err(|_| {
        StrHideError::UnsupportedFormat(format!(
            "HEVC carrier has {} slices, exceeding the superblock window slice limit (65535)",
            slice_contexts.len()
        ))
    })?;

    let sb = HevcSuperblock {
        magic,
        version_and_flags: 0x20,
        stc_u_body: fmt.stc_u,
        window_slices,
        total_windows: 1,
        reserved: 0,
        payload_len: uncompressed.len() as u32,
        payload_crc32: payload_crc,
        nonce: nonce_bytes,
    };
    let sb_bytes = sb.encode();

    let ciphertext = cipher
        .encrypt(
            &nonce,
            AeadPayload {
                msg: uncompressed.as_slice(),
                aad: &sb_bytes,
            },
        )
        .map_err(|e| StrHideError::General(format!("HEVC payload encryption failed: {e}")))?;

    let seed = trellis_seed_from_key(&key, &cover_digest);
    let sb_trellis = StcTrellis::from_seed_grouped(seed, 7, 2)?;
    let body_trellis = StcTrellis::from_seed_grouped(seed, fmt.stc_h, fmt.stc_u)?;

    let mut forbidden: HashSet<usize> = HashSet::new();
    let mut bad_substreams: HashSet<(usize, usize)> = HashSet::new();

    for round in 0..MAX_EMBED_ROUNDS {
        control.check()?;

        // 3a. Solve Superblock STC
        let mut sb_cover_bits = Vec::with_capacity(sb_positions.len());
        let mut sb_costs = Vec::with_capacity(sb_positions.len());
        let mut sb_moves = Vec::with_capacity(sb_positions.len());
        for &pos in &sb_positions {
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
        let mut sb_deltas = vec![0i8; sb_positions.len()];
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
                let global_slot_idx = sb_positions[i];
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
                Ok(reencode_slice(
                    slice_idx,
                    &slice_contexts[slice_idx],
                    flipped_entries,
                ))
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
        for &pos in sb_positions.iter().chain(body_positions.iter()) {
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

pub fn embed_hevc_payload(
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

/// Deterministic Weyl permutation of each drift band, consumed band by band.
///
/// Element `i` maps to slot `band.start + (j * stride) mod len` where `j` is the
/// element's index inside that band. `stride` is ~0.618 of the band and coprime
/// with it, so consecutive elements land in different slices, different pictures
/// and different corners of the frame. Consuming slots in recording order
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
fn band_positions(bands: &[std::ops::Range<usize>], count: usize) -> Vec<usize> {
    let mut out = Vec::with_capacity(count);
    for band in bands {
        if out.len() >= count {
            break;
        }
        let len = band.len();
        if len == 0 {
            continue;
        }
        let stride = permutation_stride(len);
        for i in 0..len {
            if out.len() >= count {
                break;
            }
            // `i * stride` overflows `usize` on 32-bit targets once a burst
            // HEIC exposes a few billion slots; the modulus only needs the
            // product's low bits, so the multiply runs in `u64`.
            out.push(band.start + ((i as u64 * stride as u64) % len as u64) as usize);
        }
    }
    out
}

/// Weyl stride for a band of `len` slots: ~0.618 of it and coprime with it.
fn permutation_stride(len: usize) -> usize {
    let mut stride = ((len as u64 * 618_034) / 1_000_000) as usize;
    stride = stride.max(1);
    while gcd_usize(stride, len) != 1 {
        stride += 1;
        if stride >= len {
            return 1;
        }
    }
    stride
}

fn gcd_usize(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

/// Extract hidden payload from an HEVC/HEIC carrier.
pub fn extract_hevc(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    control.check()?;
    check_header_bytes(fmt)?;
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;

    // 1. First stage: scan up to HEVC_SUPERBLOCK_POOL_SLOTS to read and verify Superblock
    let sb_record = record_carrier_state(
        carrier,
        kind,
        Capture::Bits,
        StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
        control,
    )?;
    extract_hevc_from_sb_record(carrier, kind, sb_record, secret, domain, fmt, control)
}

fn extract_hevc_from_sb_record(
    carrier: &[u8],
    kind: HevcCarrierKind,
    sb_record: CarrierRecord,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    control.check()?;
    let total_slots = sb_record.total_slots();
    let pool_size = total_slots.min(HEVC_SUPERBLOCK_POOL_SLOTS);
    if pool_size < HEVC_SUPERBLOCK_MIN_SLOTS {
        return Err(StrHideError::CorruptedData(
            "Insufficient HEVC slots for Superblock".into(),
        ));
    }

    let cover_digest = derive_carrier_digest(carrier, &sb_record.digest_inputs, fmt);
    let key = derive_hevc_key(secret, domain, &cover_digest, fmt);
    let seed = trellis_seed_from_key(&key, &cover_digest);

    let sb_positions = superblock_positions(pool_size);
    let sb_bits: Vec<u8> = sb_positions
        .iter()
        .map(|&p| sb_record.raw_slot_bit(p))
        .collect();

    let sb_trellis = StcTrellis::from_seed_grouped(seed, 7, 2)?;
    let sb_raw = sb_trellis.extract(&sb_bits, HEVC_SUPERBLOCK_BYTES * 8);
    if sb_raw.len() < HEVC_SUPERBLOCK_BYTES {
        return Err(StrHideError::CorruptedData(
            "HEVC Superblock is truncated".into(),
        ));
    }
    let mut sb_bytes = [0u8; HEVC_SUPERBLOCK_BYTES];
    sb_bytes.copy_from_slice(&sb_raw[0..HEVC_SUPERBLOCK_BYTES]);
    let sb = HevcSuperblock::decode(&sb_bytes)?;

    let expected_magic = derive_magic(fmt.magic_label, effective_secret(secret).as_bytes());
    if sb.magic != expected_magic {
        return Err(StrHideError::CorruptedData(
            "Invalid HEVC stego signature".into(),
        ));
    }

    // 2. Second stage: read Body
    let w0 = sb.window_slices as usize;
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
    let (body_band0, body_band1) = get_body_slot_indices(
        total_window_slots,
        pool_size,
        &sb_positions,
        &body_record.slice_slot_ranges,
    );

    let body_msg_len = (sb.payload_len as usize)
        .checked_add(HEVC_TAG_BYTES)
        .ok_or_else(|| StrHideError::CorruptedData("HEVC payload length overflows".into()))?;
    let body_trellis = StcTrellis::from_seed_grouped(seed, fmt.stc_h, sb.stc_u_body)?;
    let body_needed_slots = body_trellis.slots_for(body_msg_len * 8);

    let available_body_slots = body_band0.len() + body_band1.len();
    if available_body_slots < body_needed_slots {
        return Err(StrHideError::CorruptedData(
            "Carrier window truncated for declared payload".into(),
        ));
    }

    let body_bands = vec![
        0..body_band0.len(),
        body_band0.len()..(body_band0.len() + body_band1.len()),
    ];
    let mut all_body_indices = body_band0;
    all_body_indices.extend(body_band1);
    let body_positions_rel = band_positions(&body_bands, body_needed_slots);
    let body_bits: Vec<u8> = body_positions_rel
        .into_iter()
        .map(|rel| body_record.raw_slot_bit(all_body_indices[rel]))
        .collect();

    let ciphertext = body_trellis.extract(&body_bits, body_msg_len * 8);
    if ciphertext.len() < body_msg_len {
        return Err(StrHideError::CorruptedData(
            "Carrier truncated for declared payload".into(),
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| StrHideError::General(format!("AES-GCM key init failed: {e}")))?;
    let nonce = Nonce::from(sb.nonce);

    let decrypted = cipher
        .decrypt(
            &nonce,
            AeadPayload {
                msg: &ciphertext[0..body_msg_len],
                aad: &sb_bytes,
            },
        )
        .map_err(|_| {
            StrHideError::Password("Authentication failed or incorrect password".into())
        })?;

    let mut crc = Crc32::new();
    crc.update(&decrypted);
    if crc.finalize() != sb.payload_crc32 {
        return Err(StrHideError::CorruptedData(
            "CRC32 mismatch in HEVC payload".into(),
        ));
    }

    decode_micro_header(&decrypted)
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
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
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
    let mut empty_info = StegoHeaderInfo::empty(match kind {
        HevcCarrierKind::HeifContainer => "HEIF/HEVC",
        HevcCarrierKind::AnnexBStream => "HEVC-AnnexB",
        HevcCarrierKind::Mp4Container => "MP4/HEVC",
    });
    empty_info.media_info = media_info;

    let total_slots = record.total_slots();
    let pool_size = total_slots.min(HEVC_SUPERBLOCK_POOL_SLOTS);
    if pool_size < HEVC_SUPERBLOCK_MIN_SLOTS {
        return Ok(empty_info);
    }

    let cover_digest = derive_carrier_digest(carrier, &record.digest_inputs, fmt);
    let key = derive_hevc_key(secret, domain, &cover_digest, fmt);
    let seed = trellis_seed_from_key(&key, &cover_digest);

    let sb_positions = superblock_positions(pool_size);
    let sb_bits: Vec<u8> = sb_positions
        .iter()
        .map(|&p| record.raw_slot_bit(p))
        .collect();

    let sb_trellis = match StcTrellis::from_seed_grouped(seed, 7, 2) {
        Ok(t) => t,
        Err(_) => return Ok(empty_info),
    };
    let sb_raw = sb_trellis.extract(&sb_bits, HEVC_SUPERBLOCK_BYTES * 8);
    if sb_raw.len() < HEVC_SUPERBLOCK_BYTES {
        return Ok(empty_info);
    }
    let mut sb_bytes = [0u8; HEVC_SUPERBLOCK_BYTES];
    sb_bytes.copy_from_slice(&sb_raw[0..HEVC_SUPERBLOCK_BYTES]);
    let sb = match HevcSuperblock::decode(&sb_bytes) {
        Ok(s) => s,
        Err(_) => return Ok(empty_info),
    };

    let expected_magic = derive_magic(fmt.magic_label, effective_secret(secret).as_bytes());
    if sb.magic != expected_magic {
        return Ok(empty_info);
    }

    let payload_len = sb.payload_len as usize;
    Ok(StegoHeaderInfo {
        format: match kind {
            HevcCarrierKind::HeifContainer => "HEIF/HEVC".into(),
            HevcCarrierKind::AnnexBStream => "HEVC-AnnexB".into(),
            HevcCarrierKind::Mp4Container => "MP4/HEVC".into(),
        },
        has_hidden_data: true,
        algorithm: Some("HEVC-CABAC-InPlace".into()),
        codec: Some(format!("STC (h=7, u={})", sb.stc_u_body)),
        envelope_len: Some(HEVC_SUPERBLOCK_BYTES + HEVC_TAG_BYTES + payload_len),
        payload_len: Some(payload_len),
        media_info,
        note: None,
    })
}

/// Inspect HEVC carrier for steganographic header.
pub fn inspect_hevc(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    control.check()?;
    check_header_bytes(fmt)?;
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
    let mut empty_info = StegoHeaderInfo::empty(match kind {
        HevcCarrierKind::HeifContainer => "HEIF/HEVC",
        HevcCarrierKind::AnnexBStream => "HEVC-AnnexB",
        HevcCarrierKind::Mp4Container => "MP4/HEVC",
    });
    empty_info.media_info = media_info;

    let record = match record_carrier_state(
        carrier,
        kind,
        Capture::Bits,
        StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
        control,
    ) {
        Ok(r) => r,
        Err(_) => return Ok(empty_info),
    };
    inspect_hevc_record(
        carrier, kind, &record, media_info, secret, domain, fmt, control,
    )
}

/// Stream-inspect an MP4 carrier directly from disk using Seek + Read, bounding peak memory to < 8 MiB
/// even for multi-gigabyte video files.
pub fn inspect_hevc_mp4_file(
    carrier_path: &std::path::Path,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    use std::io::{Read, Seek, SeekFrom};
    control.check()?;
    check_header_bytes(fmt)?;

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
        Err(_) => return Ok(StegoHeaderInfo::empty("MP4/HEVC")),
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
        if sample_size <= 256 * 1024 {
            let mut hdr_buf = vec![0u8; sample_size];
            if file.seek(SeekFrom::Start(sample_offset as u64)).is_ok()
                && file.read_exact(&mut hdr_buf).is_ok()
            {
                let mut spans = Vec::new();
                if crate::stego::hevc::mp4_boxes::collect_sample_slice_spans(
                    &hdr_buf,
                    0,
                    sample_size,
                    target.length_size,
                    &mut spans,
                )
                .is_ok()
                    && spans.iter().any(|s| {
                        let (nt, _, _) = nal_header_fields(&hdr_buf[s.start..s.end()]);
                        !is_irap(nt)
                    })
                {
                    has_inter = true;
                    break;
                }
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
        if sample_size > 8 * 1024 * 1024 {
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
                absorb_recorder(&mut recorder, &rbsp, &mut sink);
                recorded_slices += 1;
                slice_idx += 1;
                let current_slots = sink.counts[0] + sink.counts[1];
                if current_slots >= HEVC_SUPERBLOCK_POOL_SLOTS {
                    break;
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
    };

    inspect_hevc_record(
        &[],
        HevcCarrierKind::Mp4Container,
        &record,
        media_info,
        secret,
        domain,
        fmt,
        control,
    )
}

/// Three-level diagnostic verification for HEVC carriers.
pub fn verify_hevc(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    control.check()?;
    let mut levels = Vec::new();
    let format_name = match sniff_hevc_carrier(carrier) {
        Some(HevcCarrierKind::HeifContainer) => "HEIF/HEVC",
        Some(HevcCarrierKind::AnnexBStream) => "HEVC-AnnexB",
        Some(HevcCarrierKind::Mp4Container) => "MP4/HEVC",
        None => "HEVC",
    };

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

    let header_info =
        inspect_hevc_record(carrier, kind, &record, None, secret, domain, fmt, control)?;
    if !header_info.has_hidden_data {
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
    levels.push(VerifyLevel::pass(
        2,
        format!(
            "Stego header valid (payload: {} B, total: {} B)",
            header_info.payload_len.unwrap_or(0),
            header_info.envelope_len.unwrap_or(0),
        ),
    ));
    control.check()?;

    match extract_hevc_from_sb_record(carrier, kind, record, secret, domain, fmt, control) {
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

/// Helper struct for slice recording and span tracking.
#[derive(Clone)]
struct SliceContext {
    carrier_span: std::ops::Range<usize>,
    nal_type: u8,
    layer_id: u8,
    temporal_id: u8,
    #[allow(dead_code)]
    band: u8,
    orig_rbsp: Vec<u8>,
    ops: Vec<BinOp>,
    substreams: Vec<SubstreamRecord>,
}

/// How much of every recorded slot `record_carrier_state` keeps.
///
/// Every pass used to build the full 32-byte [`StegoSlot`] pool even when it
/// only needed a count. A 24-minute 1080p carrier has 5.7e8 slots, i.e. 18 GB
/// (34 GB once `Vec` doubles to the next power of two) for data a capacity probe
/// never reads. The capture level is what keeps a probe at a few counters and an
/// extract at one bit per slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Capture {
    /// Per-band slot counts only: capacity probe, verify.
    Count,
    /// Counts plus the sign bit of every slot in pool order: extract, inspect.
    Bits,
    /// Full slot records, replay journal and RBSP: embed.
    Full,
}

/// One pass over the carrier: the recorded slice journals and slot pool,
/// plus the container parse the digest derivation reuses — deriving the
/// cover digest must not walk the container a second time (audit 2026-10-24
/// 2.5).
struct CarrierRecord {
    slice_contexts: Vec<SliceContext>,
    /// Slot pool in stream recording order.
    /// Populated by [`Capture::Full`] only.
    all_slots: Vec<StegoSlot>,
    /// Sign bit of every slot, packed LSB-first, one vector per band in
    /// recording order.
    band_bits: [Vec<u8>; 2],
    /// Pool ranges of each band, in consumption order.
    bands: Vec<std::ops::Range<usize>>,
    /// Pictures in the carrier (all VCL, including excluded IRAPs).
    pictures: usize,
    /// Pictures that may carry slots, per band.
    band_pictures: [usize; 2],
    digest_inputs: DigestInputs,
    /// Total slices recorded in this window pass.
    recorded_slices: usize,
    /// Sign bit of every recorded slot in stream order.
    raw_bits: Vec<u8>,
    /// (slot_count, band) for each recorded slice.
    slice_slot_ranges: Vec<(usize, u8)>,
}

impl CarrierRecord {
    /// Size of the slot pool. Valid for every capture level.
    fn total_slots(&self) -> usize {
        self.bands.iter().map(|range| range.len()).sum()
    }

    /// Sign bit at pool position `index`, where the pool is band 0 followed by
    /// band 1. Valid for [`Capture::Bits`].
    #[cfg(test)]
    fn slot_bit(&self, index: usize) -> u8 {
        let band = usize::from(index >= self.bands[0].len());
        let range = &self.bands[band];
        debug_assert!(range.contains(&index));
        bit_at(&self.band_bits[band], index.saturating_sub(range.start))
    }

    /// Sign bit at stream position `index`. Valid for [`Capture::Bits`].
    fn raw_slot_bit(&self, index: usize) -> u8 {
        bit_at(&self.raw_bits, index)
    }
}

/// Read bit `index` out of an LSB-first packed vector.
#[inline]
fn bit_at(bits: &[u8], index: usize) -> u8 {
    bits.get(index / 8)
        .map_or(0, |byte| (byte >> (index % 8)) & 1)
}

/// Append-only LSB-first bit vector. One sign bit per slot instead of 32 bytes.
#[derive(Default)]
struct BitPacker {
    bytes: Vec<u8>,
    len: usize,
}

impl BitPacker {
    #[inline]
    fn push(&mut self, bit: u8) {
        if self.len.is_multiple_of(8) {
            self.bytes.push(0);
        }
        if bit & 1 != 0 {
            let last = self.bytes.len() - 1;
            self.bytes[last] |= 1 << (self.len % 8);
        }
        self.len += 1;
    }

    fn truncate(&mut self, new_len: usize) {
        if new_len >= self.len {
            return;
        }
        self.len = new_len;
        let needed_bytes = self.len.div_ceil(8);
        self.bytes.truncate(needed_bytes);
        if let Some(last) = self.bytes.last_mut() {
            let rem = self.len % 8;
            if rem != 0 {
                *last &= (1 << rem) - 1;
            }
        }
    }

    fn extend(&mut self, other: &BitPacker) {
        if other.len == 0 {
            return;
        }
        let shift = self.len % 8;
        if shift == 0 {
            self.bytes.extend_from_slice(&other.bytes);
            self.len += other.len;
            return;
        }
        let inv_shift = 8 - shift;
        for &b in &other.bytes {
            let last = self.bytes.len() - 1;
            self.bytes[last] |= b << shift;
            self.bytes.push(b >> inv_shift);
        }
        self.len += other.len;
        let needed_bytes = self.len.div_ceil(8);
        self.bytes.truncate(needed_bytes);
        if let Some(last) = self.bytes.last_mut() {
            let rem = self.len % 8;
            if rem != 0 {
                *last &= (1 << rem) - 1;
            }
        }
    }
}

/// Where the slots of the current slice go, according to [`Capture`].
struct SlotSink {
    capture: Capture,
    /// Slots that entered the pool, per band.
    counts: [usize; 2],
    band_bits: [BitPacker; 2],
    raw_bits: BitPacker,
    raw_slots: Vec<StegoSlot>,
    slice_slot_ranges: Vec<(usize, u8)>,
}

impl SlotSink {
    fn new(capture: Capture) -> Self {
        SlotSink {
            capture,
            counts: [0; 2],
            band_bits: [BitPacker::default(), BitPacker::default()],
            raw_bits: BitPacker::default(),
            raw_slots: Vec::new(),
            slice_slot_ranges: Vec::new(),
        }
    }

    /// Record one pool slot.
    fn push(&mut self, slot: StegoSlot, band: usize) {
        self.counts[band] += 1;
        match self.capture {
            Capture::Count => {}
            Capture::Bits => {
                self.band_bits[band].push(slot.original_bit);
                self.raw_bits.push(slot.original_bit);
            }
            Capture::Full => {
                self.raw_slots.push(slot);
            }
        }
    }
}

/// Pool geometry the capacity report needs: how big the ladder is, how it is
/// split, and how many pictures each rung holds.
pub(crate) struct PoolProfile {
    total_slots: usize,
    band_slots: [usize; 2],
    band_pictures: [usize; 2],
    pictures: usize,
    is_estimated: bool,
}

impl PoolProfile {
    fn from_record(record: &CarrierRecord) -> Self {
        let mut band_slots = [0usize; 2];
        // `bands` is [band 0, band 1] in that order. Index by position, not by
        // `range.start`: an empty band 0 makes both ranges start at 0, and
        // testing the start silently credited band 1's slots to band 0 -- which
        // let an all-reference video spend the drift-free budget it does not
        // have.
        for (index, range) in record.bands.iter().enumerate().take(2) {
            band_slots[index] = range.len();
        }
        PoolProfile {
            total_slots: record.total_slots(),
            band_slots,
            band_pictures: record.band_pictures,
            pictures: record.pictures,
            is_estimated: false,
        }
    }
}

/// The already-parsed container pieces `derive_carrier_digest` needs.
enum DigestInputs {
    /// HEIF/HEIC and MP4/MOV: owned copies of the `hvcC` VPS/SPS/PPS NAL bytes.
    ///
    /// Both containers keep the parameter sets in a `hvcC` record that the
    /// embedder never touches, so one digest recipe covers both.
    ParameterSets { parameter_sets: Vec<Vec<u8>> },
    /// Annex-B: the NAL span table.
    AnnexB {
        spans: Vec<crate::stego::hevc::bitstream::HevcNalSpan>,
    },
}

/// One VCL NAL unit that may be recorded, in decode order.
#[derive(Clone)]
struct CandidateSlice {
    /// File byte range of the NAL (header included, length prefix or start
    /// code excluded) -- the exact range the re-encoder writes back.
    span: std::ops::Range<usize>,
    nal_type: u8,
    layer_id: u8,
    temporal_id: u8,
}

struct GopSliceRecord {
    recorded_slices: usize,
    sink: SlotSink,
    slice_contexts: Vec<SliceContext>,
    decode_error: Option<String>,
}

impl GopSliceRecord {
    fn new(capture: Capture) -> Self {
        GopSliceRecord {
            recorded_slices: 0,
            sink: SlotSink::new(capture),
            slice_contexts: Vec::new(),
            decode_error: None,
        }
    }

    fn truncate_to_slices(&mut self, kept_slices: usize) {
        if kept_slices >= self.recorded_slices {
            return;
        }
        let new_counts_0: usize = self.sink.slice_slot_ranges[..kept_slices]
            .iter()
            .filter(|(_, b)| *b == 0)
            .map(|(c, _)| *c)
            .sum();
        let new_counts_1: usize = self.sink.slice_slot_ranges[..kept_slices]
            .iter()
            .filter(|(_, b)| *b == 1)
            .map(|(c, _)| *c)
            .sum();
        let total_kept_slots = new_counts_0 + new_counts_1;

        self.sink.counts = [new_counts_0, new_counts_1];
        self.sink.slice_slot_ranges.truncate(kept_slices);
        match self.sink.capture {
            Capture::Count => {}
            Capture::Bits => {
                self.sink.band_bits[0].truncate(new_counts_0);
                self.sink.band_bits[1].truncate(new_counts_1);
                self.sink.raw_bits.truncate(total_kept_slots);
            }
            Capture::Full => {
                self.sink.raw_slots.truncate(total_kept_slots);
                self.slice_contexts.truncate(kept_slices);
            }
        }
        self.recorded_slices = kept_slices;
    }
}

fn find_gop_ranges(carrier: &[u8], candidates: &[CandidateSlice]) -> Vec<std::ops::Range<usize>> {
    if candidates.is_empty() {
        return Vec::new();
    }
    let mut gop_starts = Vec::new();
    for (idx, cand) in candidates.iter().enumerate() {
        if idx == 0 || (is_irap(cand.nal_type) && starts_picture(&carrier[cand.span.clone()])) {
            gop_starts.push(idx);
        }
    }
    let mut ranges = Vec::with_capacity(gop_starts.len());
    for i in 0..gop_starts.len() {
        let start = gop_starts[i];
        let end = if i + 1 < gop_starts.len() {
            gop_starts[i + 1]
        } else {
            candidates.len()
        };
        ranges.push(start..end);
    }
    ranges
}

fn estimate_gops_for_slices(
    remaining_gops: &[std::ops::Range<usize>],
    candidates: &[CandidateSlice],
    has_inter: bool,
    needed_slices: usize,
) -> usize {
    let mut sum = 0usize;
    for (i, range) in remaining_gops.iter().enumerate() {
        for cand in &candidates[range.clone()] {
            if picture_band(cand.nal_type, has_inter).is_some() {
                sum += 1;
            }
        }
        if sum >= needed_slices {
            return i + 1;
        }
    }
    remaining_gops.len().max(1)
}

fn decode_gop_slice_range(
    carrier: &[u8],
    candidates: &[CandidateSlice],
    parameter_sets: &[Vec<u8>],
    has_inter: bool,
    mode: RecordMode,
    capture: Capture,
) -> Result<GopSliceRecord, String> {
    let mut decoder = Decoder::new();
    decoder.skip_loop_filters = true;
    decoder.ablate = Ablate {
        mc: true,
        intra: true,
        residual: true,
    };
    for ps in parameter_sets {
        if let Err(e) = decoder.push_nal(ps, None) {
            return Err(format!("parameter set: {e}"));
        }
    }

    let mut record = GopSliceRecord::new(capture);
    let mut decode_error: Option<String> = None;
    let mut local_slice_idx = 0usize;

    for cand in candidates {
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

        let mut recorder =
            CabacRecorder::with_slice_capacity(local_slice_idx, band, mode, slice_bytes.len());
        let decoded = decoder.decode_nal_with_observer(slice_bytes, &mut recorder);
        drain_frames(&mut decoder);

        match decoded {
            Err(e) => {
                decode_error.get_or_insert_with(|| e.to_string());
            }
            Ok(_) if recorder.substreams.is_empty() => {}
            Ok(_) => {
                let is_multi_sub = recorder.substreams.len() > 1;
                let rbsp = if is_multi_sub || capture == Capture::Full {
                    nal_rbsp(slice_bytes)
                } else {
                    Vec::new()
                };
                absorb_recorder(&mut recorder, &rbsp, &mut record.sink);
                record.recorded_slices += 1;
                if capture == Capture::Full {
                    record.slice_contexts.push(SliceContext {
                        carrier_span: cand.span.clone(),
                        nal_type: cand.nal_type,
                        layer_id: cand.layer_id,
                        temporal_id: cand.temporal_id,
                        band,
                        orig_rbsp: rbsp,
                        ops: recorder.ops,
                        substreams: recorder.substreams,
                    });
                }
                local_slice_idx += 1;
            }
        }
    }

    record.decode_error = decode_error;
    Ok(record)
}

fn merge_gop_record(
    global_sink: &mut SlotSink,
    global_slice_contexts: &mut Vec<SliceContext>,
    global_recorded_slices: &mut usize,
    mut gop: GopSliceRecord,
) {
    global_sink.counts[0] += gop.sink.counts[0];
    global_sink.counts[1] += gop.sink.counts[1];
    global_sink
        .slice_slot_ranges
        .extend_from_slice(&gop.sink.slice_slot_ranges);

    match global_sink.capture {
        Capture::Count => {}
        Capture::Bits => {
            global_sink.band_bits[0].extend(&gop.sink.band_bits[0]);
            global_sink.band_bits[1].extend(&gop.sink.band_bits[1]);
            global_sink.raw_bits.extend(&gop.sink.raw_bits);
        }
        Capture::Full => {
            let base_slice_idx = *global_recorded_slices as u32;
            for slot in &mut gop.sink.raw_slots {
                slot.slice_idx += base_slice_idx;
            }
            global_sink.raw_slots.extend(gop.sink.raw_slots);
            global_slice_contexts.extend(gop.slice_contexts);
        }
    }
    *global_recorded_slices += gop.recorded_slices;
}

fn record_carrier_state(
    carrier: &[u8],
    kind: HevcCarrierKind,
    capture: Capture,
    stop: StopCondition,
    control: &Control<'_>,
) -> Result<CarrierRecord, StrHideError> {
    let mode = if capture == Capture::Full {
        RecordMode::Embed
    } else {
        RecordMode::Slots
    };

    let (candidates, digest_inputs, parameter_sets) = match kind {
        HevcCarrierKind::HeifContainer => {
            let target = parse_heif_targets(carrier)
                .map_err(|e| StrHideError::UnsupportedFormat(format!("HEIF parse error: {e}")))?;
            let parameter_sets = owned_parameter_sets(&target.parameter_sets);
            let mut candidates = Vec::with_capacity(target.slice_spans.len());
            for span in &target.slice_spans {
                if let Some(cand) = candidate_slice(carrier, span.start..span.end()) {
                    candidates.push(cand);
                }
            }
            (
                candidates,
                DigestInputs::ParameterSets {
                    parameter_sets: parameter_sets.clone(),
                },
                parameter_sets,
            )
        }
        HevcCarrierKind::Mp4Container => {
            let target = parse_mp4_targets(carrier).map_err(|e| {
                StrHideError::UnsupportedFormat(format!("MP4/MOV parse error: {e}"))
            })?;
            let parameter_sets = owned_parameter_sets(&target.parameter_sets);
            let mut candidates = Vec::with_capacity(target.slice_spans.len());
            for span in &target.slice_spans {
                if let Some(cand) = candidate_slice(carrier, span.start..span.end()) {
                    candidates.push(cand);
                }
            }
            (
                candidates,
                DigestInputs::ParameterSets {
                    parameter_sets: parameter_sets.clone(),
                },
                parameter_sets,
            )
        }
        HevcCarrierKind::AnnexBStream => {
            let spans = parse_annex_b_spans(carrier);
            let mut parameter_sets = Vec::new();
            for span in &spans {
                if span.is_param_set() {
                    let end = span.end_offset().min(carrier.len());
                    parameter_sets.push(carrier[span.header_offset..end].to_vec());
                }
            }
            let mut candidates = Vec::new();
            for span in &spans {
                if !span.is_vcl() {
                    continue;
                }
                let range = span.header_offset..span.end_offset().min(carrier.len());
                if let Some(cand) = candidate_slice(carrier, range) {
                    candidates.push(cand);
                }
            }
            (candidates, DigestInputs::AnnexB { spans }, parameter_sets)
        }
    };

    let has_inter = candidates.iter().any(|c| !is_irap(c.nal_type));

    let (pictures, band_pictures) = if capture == Capture::Bits {
        (1, [1, 0])
    } else {
        count_pictures(carrier, kind, &candidates, has_inter)
    };

    let gop_ranges = find_gop_ranges(carrier, &candidates);
    let total_slices = candidates.len();
    control.stage_sized(Stage::Decode, total_slices as u64);

    let mut global_sink = SlotSink::new(capture);
    let mut global_slice_contexts = Vec::new();
    let mut global_recorded_slices = 0usize;
    let mut decode_error: Option<String> = None;

    let mut gop_idx = 0;
    while gop_idx < gop_ranges.len() {
        control.check()?;
        let batch_size = match stop {
            StopCondition::All => 32,
            StopCondition::MinSlots(min) => {
                if min <= 2048 {
                    1
                } else {
                    16
                }
            }
            StopCondition::TargetSlices(target_slices) => {
                let needed = target_slices.saturating_sub(global_recorded_slices);
                let est_gops = estimate_gops_for_slices(
                    &gop_ranges[gop_idx..],
                    &candidates,
                    has_inter,
                    needed,
                );
                est_gops.clamp(1, 48)
            }
            StopCondition::TargetSlots(_) => 16,
        };

        let end_idx = (gop_idx + batch_size).min(gop_ranges.len());
        let batch_ranges = &gop_ranges[gop_idx..end_idx];

        let batch_results: Vec<Result<GopSliceRecord, String>> = batch_ranges
            .par_iter()
            .map(|range| {
                decode_gop_slice_range(
                    carrier,
                    &candidates[range.clone()],
                    &parameter_sets,
                    has_inter,
                    mode,
                    capture,
                )
            })
            .collect();

        let mut finished = false;
        for gop_res in batch_results {
            let mut gop = match gop_res {
                Ok(g) => g,
                Err(e) => {
                    decode_error.get_or_insert(e);
                    continue;
                }
            };
            if let Some(err) = gop.decode_error.take() {
                decode_error.get_or_insert(err);
            }

            let mut current_slots = global_sink.counts[0] + global_sink.counts[1];
            let mut current_slices = global_recorded_slices;
            let mut slices_to_take = gop.recorded_slices;
            let mut stop_now = false;

            for (idx, &(slot_cnt, _band)) in gop.sink.slice_slot_ranges.iter().enumerate() {
                current_slots += slot_cnt;
                current_slices += 1;
                let should_stop = match stop {
                    StopCondition::All => false,
                    StopCondition::MinSlots(min) => current_slots >= min,
                    StopCondition::TargetSlices(target_slices) => current_slices >= target_slices,
                    StopCondition::TargetSlots(target) => current_slots >= target,
                };
                if should_stop {
                    slices_to_take = idx + 1;
                    stop_now = true;
                    break;
                }
            }

            if slices_to_take < gop.recorded_slices {
                gop.truncate_to_slices(slices_to_take);
            }

            merge_gop_record(
                &mut global_sink,
                &mut global_slice_contexts,
                &mut global_recorded_slices,
                gop,
            );

            if stop_now {
                finished = true;
                break;
            }
        }

        control.report(Event::progress(
            Stage::Decode,
            gop_ranges[..end_idx].iter().map(|r| r.len()).sum::<usize>() as u64,
            Some(total_slices as u64),
        ));

        if finished {
            break;
        }
        gop_idx = end_idx;
    }

    if global_recorded_slices == 0
        && let Some(reason) = decode_error
    {
        return Err(StrHideError::UnsupportedFormat(format!(
            "HEVC carrier could not be decoded: {reason}"
        )));
    }

    let SlotSink {
        counts,
        band_bits,
        raw_bits,
        raw_slots,
        slice_slot_ranges,
        ..
    } = global_sink;
    let band0_len = counts[0];
    let total_slots = counts[0] + counts[1];

    let [band0_bits, band1_bits] = band_bits;
    let bands = vec![0..band0_len, band0_len..total_slots];

    Ok(CarrierRecord {
        slice_contexts: global_slice_contexts,
        all_slots: raw_slots,
        band_bits: [band0_bits.bytes, band1_bits.bytes],
        bands,
        pictures,
        band_pictures,
        digest_inputs,
        recorded_slices: global_recorded_slices,
        raw_bits: raw_bits.bytes,
        slice_slot_ranges,
    })
}

fn owned_parameter_sets(parameter_sets: &[&[u8]]) -> Vec<Vec<u8>> {
    parameter_sets.iter().map(|ps| ps.to_vec()).collect()
}

/// Wrap one candidate span, reading its NAL header fields (H.265 7.3.1.2).
///
/// Returns `None` for a span too short to hold a header, for a set
/// `forbidden_zero_bit`, or for `temporal_id_plus1 == 0` (invalid per spec and
/// the same rule the Annex-B parser applies).
fn candidate_slice(carrier: &[u8], span: std::ops::Range<usize>) -> Option<CandidateSlice> {
    let nal = carrier.get(span.clone())?;
    if nal.len() < 2 {
        return None;
    }
    let b0 = nal[0];
    let b1 = nal[1];
    if (b0 & 0x80) != 0 || (b1 & 0x07) == 0 {
        return None;
    }
    let (nal_type, layer_id, temporal_id) = nal_header_fields(nal);
    Some(CandidateSlice {
        span,
        nal_type,
        layer_id,
        temporal_id,
    })
}

/// Non-reference VCL NAL types (H.265 Table 7-1, even values in 0..=8).
///
/// A picture of one of these types is not added to the decoded picture buffer,
/// so no later picture predicts from it: flipping its coefficients cannot drift
/// into the rest of the video.
fn is_non_reference_vcl(nal_type: u8) -> bool {
    matches!(
        nal_type,
        NAL_TRAIL_N | NAL_TSA_N | NAL_STSA_N | NAL_RADL_N | NAL_RASL_N
    )
}

/// IRAP (intra random access point) VCL types: BLA/IDR/CRA, H.265 Table 7-1.
///
/// These are the prediction roots of a GOP. A flip in one of them is seen by
/// every picture that follows until the next IRAP, which is why they are the
/// one class the ladder never spends: measured at equal payload, including them
/// costs 15-20 dB (`docs/hevc_video_capacity_quality_audit_20261026.md` §2).
fn is_irap(nal_type: u8) -> bool {
    (16..=23).contains(&nal_type)
}

/// Drift-free band: pictures nothing predicts from.
const BAND_NON_REFERENCE: u8 = 0;
/// Reference band: pictures later pictures predict from until the next IRAP.
const BAND_REFERENCE: u8 = 1;

/// Place a VCL picture on the drift ladder, or `None` when it may not carry
/// slots at all.
///
/// * **No inter picture anywhere** (still image, all-intra stream): nothing is
///   predicted from anything, so every picture is drift-free.
/// * **Otherwise**: non-reference pictures are drift-free (band 0), reference
///   non-IRAP pictures are band 1, and IRAPs are excluded.
///
/// The answer depends only on the sequence of `nal_unit_type` values, which
/// embedding never changes (sign flips live inside the CABAC payload), so both
/// ends derive the same ladder and the wire header carries no flag.
fn picture_band(nal_type: u8, has_inter: bool) -> Option<u8> {
    if nal_type == NAL_RASL_N || nal_type == NAL_RASL_R {
        return None;
    }
    if !has_inter || is_non_reference_vcl(nal_type) {
        return Some(BAND_NON_REFERENCE);
    }
    if is_irap(nal_type) {
        return None;
    }
    Some(BAND_REFERENCE)
}

/// Count the pictures of a carrier and how many of them sit on each rung.
///
/// A HEIF carrier is a single image: its grid tiles are separate items, each a
/// standalone picture, but they are all the same image, so counting them would
/// inflate every per-picture budget by the tile count. For streams the answer
/// comes from `first_slice_segment_in_pic_flag`, which the container parsers do
/// not expose (a multi-slice picture is one sample, several NAL units).
fn count_pictures(
    carrier: &[u8],
    kind: HevcCarrierKind,
    candidates: &[CandidateSlice],
    has_inter: bool,
) -> (usize, [usize; 2]) {
    let mut band_pictures = [0usize; 2];
    if kind == HevcCarrierKind::HeifContainer {
        if let Some(first) = candidates.first()
            && let Some(band) = picture_band(first.nal_type, has_inter)
        {
            band_pictures[band as usize] = 1;
        }
        return (1, band_pictures);
    }

    let mut pictures = 0usize;
    for cand in candidates {
        if !starts_picture(&carrier[cand.span.clone()]) {
            continue;
        }
        pictures += 1;
        if let Some(band) = picture_band(cand.nal_type, has_inter) {
            band_pictures[band as usize] += 1;
        }
    }
    (pictures.max(1), band_pictures)
}

/// Does this VCL NAL start a new picture?
///
/// `first_slice_segment_in_pic_flag` is the first syntax element of every slice
/// segment header (H.265 §7.3.6.1), i.e. the MSB of the first RBSP byte. A
/// picture made of several slices must be counted once: the per-picture budgets
/// are expressed per picture, not per slice.
fn starts_picture(nal: &[u8]) -> bool {
    nal.get(2).is_some_and(|&first| (first & 0x80) != 0)
}

/// Drop every decoded picture the decoder has queued.
///
/// The decoder hands finished pictures out through a queue and only
/// `next_frame` releases them; each entry pins its sample planes through an
/// `Arc<Picture>` the DPB shares, so the buffers come back only when the last
/// handle goes. This engine never looks at pixels — it wants the bin stream —
/// so leaving the queue alone would hold one picture per frame of the carrier
/// (12 MB each at 4K; a five-clip corpus peaked at 2.0 GB without this).
fn drain_frames(decoder: &mut Decoder) {
    while decoder.next_frame().is_ok() {}
}

/// Move a slice's recorded slots into the carrier-wide slot pool.
///
/// Returns the recorder-local → global slot mapping the re-encoder uses to walk
/// from a recorded bypass bin back to the trellis element it carries.
///
/// Multi-substream slices (WPP / tiles) address their substreams through
/// `entry_point_offset`s expressed in **NAL** bytes, so a substream that already
/// carries a `00 00 xx<=3` window stays out of the pool: flipping near it could
/// shift every following substream even when the total NAL length is preserved.
fn absorb_recorder(recorder: &mut CabacRecorder, rbsp: &[u8], sink: &mut SlotSink) {
    if recorder.mode() == RecordMode::Embed && recorder.next_pending_slot() != recorder.slots.len()
    {
        // Slice decoding was truncated mid-slice before levels backfilled signs.
        // Discard all incomplete slots from this slice so desynced slots never enter the pool.
        recorder.slots.clear();
        recorder.reset_pending();
        return;
    }

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

    let band = recorder.current_band as usize;
    let start_count = sink.counts[0] + sink.counts[1];

    if sink.capture == Capture::Count && (!is_multi_sub || excluded.is_empty()) {
        let count = recorder.slots.len();
        sink.counts[band] += count;
        sink.slice_slot_ranges.push((count, recorder.current_band));
        recorder.slots.clear();
        recorder.reset_pending();
        return;
    }

    for slot in recorder.slots.drain(..) {
        if is_multi_sub && excluded.contains(&(slot.substream_idx as usize)) {
            continue;
        }
        sink.push(slot, band);
    }
    let added = (sink.counts[0] + sink.counts[1]) - start_count;
    sink.slice_slot_ranges.push((added, recorder.current_band));
    recorder.reset_pending();
}

fn scan_hevc_slot_count(carrier: &[u8]) -> Result<usize, StrHideError> {
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;
    let record = record_carrier_state(
        carrier,
        kind,
        Capture::Count,
        StopCondition::All,
        &Control::none(),
    )?;
    Ok(record.total_slots())
}

/// Derive the 64-bit STC trellis seed.
///
/// Keyed through the (secret-derived) HEVC key rather than through the public
/// carrier digest alone, so the slot Weyl permutation and the STC code
/// structure are reproducible only with the credential — the same security
/// model as the PNG/JPEG engines. A passwordless analyst can then neither
/// reproduce the permutation for structural detection nor locate the
/// plaintext message header (whose CRC32 would otherwise be an offline
/// guessing oracle for low-entropy payloads).
///
/// HKDF-SHA256 can always produce 8 bytes, so the error branch is defensive
/// only, mirroring [`derive_hevc_key`]'s fallback style.
fn trellis_seed_from_key(key: &[u8; 32], cover_digest: &[u8; 32]) -> u64 {
    let hk = Hkdf::<Sha256>::new(Some(cover_digest), key);
    let mut buf = [0u8; 8];
    if hk
        .expand(b"strhide-hevc-trellis-seed-v1", &mut buf)
        .is_err()
    {
        return 0;
    }
    u64::from_be_bytes(buf)
}

/// Derive the cover digest from the container parse `record_carrier_state`
/// already produced — the container is walked exactly once per operation
/// (audit 2026-10-24 2.5).
fn derive_carrier_digest(
    carrier: &[u8],
    inputs: &DigestInputs,
    fmt: &HevcFormatProfile,
) -> [u8; 32] {
    match inputs {
        DigestInputs::ParameterSets { parameter_sets } => {
            // Hash the parameter set *contents*. They are immutable during
            // embedding, which is what makes the digest — and therefore
            // the AES key and the keyed trellis seed — identical on both
            // ends.
            //
            // (Feeding them through `compute_hevc_cover_digest` would need
            // byte offsets into `carrier`; the parsed sets are copies, and
            // an offset of 0 quietly hashed the file header instead.)
            let mut hasher = Sha256::new();
            hasher.update(fmt.cover_salt);
            hasher.update((parameter_sets.len() as u64).to_be_bytes());
            for ps in parameter_sets {
                hasher.update((ps.len() as u64).to_be_bytes());
                hasher.update(ps);
            }
            hasher.finalize().into()
        }
        DigestInputs::AnnexB { spans } => compute_hevc_cover_digest(carrier, spans, fmt.cover_salt),
    }
}

/// The credential actually fed to key derivation: the explicit secret, else
/// the shared public constant -- the same resolution the PNG/JPEG engines use,
/// so there is exactly one public default key in the whole crate.
fn effective_secret(secret: Option<&str>) -> String {
    match secret.filter(|s| !s.is_empty()) {
        Some(s) => crate::crypto::normalize_nfc(s),
        None => PUBLIC_DEFAULT_SECRET.to_string(),
    }
}

fn derive_hevc_key(
    secret: Option<&str>,
    domain: Option<&str>,
    salt: &[u8; 32],
    fmt: &HevcFormatProfile,
) -> [u8; 32] {
    let secret_bytes = effective_secret(secret);
    // Optional domain isolation: subkey the secret first, exactly like the
    // stego envelope layer, so the same password under two domains yields
    // unrelated keys.
    let ikm: Vec<u8> = match derive_domain_subkey_with_label(
        secret_bytes.as_bytes(),
        domain,
        b"strhide-hevc-domain-v1",
    ) {
        Some(sub) => sub.to_vec(),
        None => secret_bytes.into_bytes(),
    };
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut key = [0u8; 32];
    // HKDF-SHA256 can always produce 32 bytes (255 * 32 > 32), so this
    // cannot fail. Use `unwrap_or_default` rather than `expect` so that a
    // hypothetical future change of hash/len cannot abort the process.
    if hk.expand(fmt.kdf_info, &mut key).is_err() {
        return [0u8; 32];
    }
    key
}

#[cfg(test)]
mod capture_tests {
    use super::*;

    fn record(bands: Vec<std::ops::Range<usize>>, band_bits: [Vec<u8>; 2]) -> CarrierRecord {
        let total = bands.iter().map(|r| r.len()).sum();
        CarrierRecord {
            slice_contexts: Vec::new(),
            all_slots: Vec::new(),
            band_bits,
            bands,
            pictures: 1,
            band_pictures: [1, 0],
            digest_inputs: DigestInputs::ParameterSets {
                parameter_sets: Vec::new(),
            },
            recorded_slices: 1,
            raw_bits: Vec::new(),
            slice_slot_ranges: vec![(total, 0)],
        }
    }

    fn pack(bits: &[u8]) -> Vec<u8> {
        let mut packer = BitPacker::default();
        for &bit in bits {
            packer.push(bit);
        }
        packer.bytes
    }

    /// `Capture::Bits` must answer exactly what `all_slots[p].original_bit`
    /// answered, including across byte boundaries and across the drift-ladder
    /// partition.
    #[test]
    fn slot_bit_matches_the_pool_order() {
        // band 0: 10 slots (not a byte multiple), band 1: 3 slots.
        let band0 = [1u8, 0, 1, 1, 0, 0, 0, 1, 1, 0];
        let band1 = [0u8, 1, 1];
        let rec = record(vec![0..10, 10..13], [pack(&band0), pack(&band1)]);
        assert_eq!(rec.total_slots(), 13);
        let expected: Vec<u8> = band0.iter().chain(band1.iter()).copied().collect();
        for (index, &want) in expected.iter().enumerate() {
            assert_eq!(rec.slot_bit(index), want, "pool position {index}");
        }
    }

    /// An empty band 0 shifts band 1 to pool position 0; the mapping must not
    /// fall back to band 0's (empty) buffer.
    #[test]
    fn slot_bit_handles_an_empty_leading_band() {
        let rec = record(vec![0..0, 0..4], [Vec::new(), pack(&[1, 0, 0, 1])]);
        assert_eq!(rec.total_slots(), 4);
        assert_eq!(
            (0..4).map(|i| rec.slot_bit(i)).collect::<Vec<_>>(),
            vec![1, 0, 0, 1]
        );
    }

    /// LSB-first packing, including the last partial byte.
    #[test]
    fn bit_packer_packs_lsb_first() {
        assert_eq!(pack(&[1]), vec![0b0000_0001]);
        assert_eq!(pack(&[0, 0, 0, 0, 0, 0, 0, 1]), vec![0b1000_0000]);
        assert_eq!(pack(&[1; 9]), vec![0xFF, 0b0000_0001]);
        assert_eq!(pack(&[]), Vec::<u8>::new());
    }

    #[test]
    fn superblock_encode_decode_roundtrip() {
        let sb = HevcSuperblock {
            magic: [0x53, 0x54, 0x52, 0x48],
            version_and_flags: 0x20,
            stc_u_body: 2,
            window_slices: 12,
            total_windows: 1,
            reserved: 0,
            payload_len: 1024,
            payload_crc32: 0xDEADBEEF,
            nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };
        let encoded = sb.encode();
        assert_eq!(encoded.len(), HEVC_SUPERBLOCK_BYTES);
        let decoded = HevcSuperblock::decode(&encoded).expect("decode superblock");
        assert_eq!(sb, decoded);
    }

    #[test]
    fn superblock_positions_are_distinct() {
        let positions = superblock_positions(2048);
        assert_eq!(positions.len(), HEVC_SUPERBLOCK_MIN_SLOTS);
        let set: HashSet<usize> = positions.iter().copied().collect();
        assert_eq!(set.len(), HEVC_SUPERBLOCK_MIN_SLOTS);
        for &p in &positions {
            assert!(p < 2048);
        }
    }

    #[test]
    fn bitpacker_extend_and_truncate_correctness() {
        for len1 in 0..35 {
            for len2 in 0..35 {
                let bits1: Vec<u8> = (0..len1).map(|i| ((i * 7 + 3) % 2) as u8).collect();
                let bits2: Vec<u8> = (0..len2).map(|i| ((i * 11 + 5) % 2) as u8).collect();

                let mut p1 = BitPacker::default();
                for &b in &bits1 {
                    p1.push(b);
                }

                let mut p2 = BitPacker::default();
                for &b in &bits2 {
                    p2.push(b);
                }

                p1.extend(&p2);

                assert_eq!(p1.len, len1 + len2);
                let combined: Vec<u8> = bits1.iter().chain(bits2.iter()).copied().collect();
                for (i, &expected) in combined.iter().enumerate() {
                    assert_eq!(
                        bit_at(&p1.bytes, i),
                        expected,
                        "Mismatch at index {i} for len1={len1}, len2={len2}"
                    );
                }

                // Test truncate
                for trunc_len in [0, len1 / 2, len1, len1 + len2 / 2, len1 + len2] {
                    let mut p_trunc = BitPacker::default();
                    for &b in &combined {
                        p_trunc.push(b);
                    }
                    p_trunc.truncate(trunc_len);
                    assert_eq!(p_trunc.len, trunc_len);
                    for (i, &expected) in combined.iter().enumerate().take(trunc_len) {
                        assert_eq!(
                            bit_at(&p_trunc.bytes, i),
                            expected,
                            "Truncate mismatch at {i} for trunc_len={trunc_len}"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod dialect_tests {
    use super::*;
    use crate::stego::format::DEFAULT_HEVC_FORMAT;
    use crate::stego::hevc::sniff::{NAL_IDR_W_RADL, NAL_TRAIL_R};

    /// The literals below are pinned to `docs/api/WIRE_SPEC.md` §13.11.2. The
    /// spec is the only reproduction recipe a private build has; if an
    /// implementation constant changes without the doc (or vice versa),
    /// third-party rebuilds silently produce mutually unreadable carriers.
    #[test]
    fn default_format_literals_match_the_wire_spec() {
        let fmt = &DEFAULT_HEVC_FORMAT;
        assert_eq!(fmt.magic_label, b"strhide-hevc-magic-v2");
        assert_eq!(fmt.cover_salt, b"strhide-hevc-cover-v1");
        assert_eq!(fmt.kdf_info, b"strhide-hevc-aes-key");
        assert_eq!(fmt.stc_h, 7);
        assert_eq!(fmt.stc_u, 2);
        assert_eq!(fmt.header_bytes, 48);
    }

    /// The magic must depend on the credential. A fixed magic plus a
    /// password-independent header location was a presence oracle; this test
    /// locks in the fix.
    #[test]
    fn magic_is_derived_from_the_secret_not_a_constant() {
        let m1 = derive_magic(DEFAULT_HEVC_FORMAT.magic_label, b"secret-one");
        let m2 = derive_magic(DEFAULT_HEVC_FORMAT.magic_label, b"secret-two");
        assert_ne!(m1, m2, "different secrets must yield different magics");
        // Same inputs are stable (both ends derive the same value).
        assert_eq!(
            m1,
            derive_magic(DEFAULT_HEVC_FORMAT.magic_label, b"secret-one")
        );
    }

    /// The no-secret fallback is the shared public constant, not a
    /// HEVC-private string: one public default key per crate, resolved through
    /// the same chain as PNG/JPEG.
    #[test]
    fn no_secret_falls_back_to_the_public_constant() {
        assert_eq!(
            effective_secret(None),
            PUBLIC_DEFAULT_SECRET,
            "the third public default key constant must stay deleted"
        );
        assert_eq!(
            effective_secret(Some("")),
            PUBLIC_DEFAULT_SECRET,
            "an empty secret counts as 'not supplied'"
        );
        assert_ne!(effective_secret(Some("pw")), PUBLIC_DEFAULT_SECRET);
    }

    /// Domain isolation subkeys the credential: same secret, different domain,
    /// unrelated key.
    #[test]
    fn domain_changes_the_derived_key() {
        let digest = [7u8; 32];
        let fmt = &DEFAULT_HEVC_FORMAT;
        let k_none = derive_hevc_key(Some("pw"), None, &digest, fmt);
        let k_domain = derive_hevc_key(Some("pw"), Some("org.acme"), &digest, fmt);
        assert_ne!(k_none, k_domain);
    }

    /// The ladder is stateless and depends only on the NAL type sequence: a
    /// non-reference picture sits on the drift-free rung, a reference non-IRAP
    /// picture on the second rung, an IRAP is excluded. An all-intra stream
    /// (still image, all-IDR video) has nothing predicted from anything, so
    /// every picture is drift-free.
    #[test]
    fn ladder_is_stateless_and_has_two_rungs() {
        // Inter stream: non-reference -> band 0, reference -> band 1.
        assert_eq!(picture_band(NAL_TRAIL_N, true), Some(BAND_NON_REFERENCE));
        assert_eq!(picture_band(NAL_TSA_N, true), Some(BAND_NON_REFERENCE));
        assert_eq!(picture_band(NAL_RASL_N, true), None);
        assert_eq!(picture_band(NAL_RASL_R, true), None);
        assert_eq!(picture_band(NAL_TRAIL_R, true), Some(BAND_REFERENCE));
        // IRAP is the prediction root of a whole GOP: never carries slots when
        // the stream has inter pictures.
        assert_eq!(picture_band(NAL_IDR_W_RADL, true), None);
        assert_eq!(picture_band(21, true), None);

        // All-intra: nothing predicts from anything, so everything is band 0 --
        // that is the still-image case and the all-IDR video case.
        assert_eq!(picture_band(NAL_TRAIL_R, false), Some(BAND_NON_REFERENCE));
        assert_eq!(
            picture_band(NAL_IDR_W_RADL, false),
            Some(BAND_NON_REFERENCE)
        );
        assert_eq!(picture_band(NAL_TRAIL_N, false), Some(BAND_NON_REFERENCE));
    }

    /// Band order is the drift ladder: element 0..len(band0) all land in band 0,
    /// so a 40-byte header and a small payload never touch a reference picture.
    #[test]
    fn band_positions_exhaust_the_drift_free_rung_first() {
        let bands = vec![0..10usize, 10..40];
        let positions = band_positions(&bands, 10);
        assert_eq!(positions.len(), 10);
        assert!(positions.iter().all(|p| *p < 10));
        // Every slot of the band is used exactly once (a permutation).
        let mut seen = positions.clone();
        seen.sort_unstable();
        assert_eq!(seen, (0..10).collect::<Vec<_>>());

        // Spilling into band 1 happens only after band 0 is exhausted.
        let wide = band_positions(&bands, 25);
        assert!(wide[..10].iter().all(|p| *p < 10));
        assert!(wide[10..].iter().all(|p| (10..40).contains(p)));
    }

    /// Element `i` must map to the same slot no matter how many elements are
    /// requested -- the extractor reads the header with a short prefix and then
    /// the whole message with a longer one.
    #[test]
    fn band_positions_are_prefix_stable() {
        let bands = vec![0..7usize, 7..23, 23..24];
        let full = band_positions(&bands, 24);
        for count in [1usize, 5, 7, 12, 23] {
            assert_eq!(band_positions(&bands, count), full[..count].to_vec());
        }
        // Empty bands (no slots recorded) must not shift the mapping.
        let with_empty = vec![0..0usize, 0..7, 7..7, 7..23];
        assert_eq!(band_positions(&with_empty, 12), full[..12].to_vec());
    }

    #[test]
    fn non_reference_types_are_the_even_vcl_range() {
        for t in 0u8..=9 {
            assert_eq!(is_non_reference_vcl(t), t % 2 == 0, "nal_type {t}");
        }
        // 16..=21 (BLA/IDR/CRA) are all reference pictures.
        for t in 16u8..=21 {
            assert!(!is_non_reference_vcl(t), "nal_type {t} is an IRAP");
        }
    }
}

/// Regression tests for the safety-policy gate (bug B1: the HEVC path used to
/// receive only the tier's level, so `--enforce-safety` never blocked).
#[cfg(test)]
mod safety_policy_tests {
    use super::enforce_safety;
    use crate::errors::StrHideError;
    use crate::stego::{SafetyEnforcement, SafetyLevel, SafetyPolicy};

    fn policy(enforcement: SafetyEnforcement) -> SafetyPolicy {
        SafetyPolicy {
            level: SafetyLevel::High,
            enforcement,
        }
    }

    #[test]
    fn advisory_policy_never_blocks_an_over_tier_payload() {
        let p = policy(SafetyEnforcement::Advisory);
        assert!(enforce_safety(10_000, 4_788, 16_618, p).is_ok());
    }

    #[test]
    fn enforced_policy_blocks_an_over_tier_payload() {
        let p = policy(SafetyEnforcement::Enforced);
        let err = enforce_safety(9_216, 4_788, 16_618, p).expect_err("must be refused");
        assert!(
            matches!(err, StrHideError::SafetyThreshold { .. }),
            "expected SafetyThreshold, got {err:?}"
        );
        let text = err.to_string();
        assert!(text.contains("4788") && text.contains("9216"), "{text}");
    }

    #[test]
    fn enforced_policy_allows_a_payload_at_the_recommended_boundary() {
        let p = policy(SafetyEnforcement::Enforced);
        assert!(enforce_safety(4_788, 4_788, 16_618, p).is_ok());
        assert!(enforce_safety(0, 4_788, 16_618, p).is_ok());
    }
}

#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct ScanStats {
    pub slices_scanned: usize,
    pub total_slots: usize,
    pub band0_slots: usize,
    pub band1_slots: usize,
    pub elapsed_micros: u64,
}

#[doc(hidden)]
pub fn bench_scan_slices(
    carrier: &[u8],
    slice_count: usize,
    full_capture: bool,
) -> Result<ScanStats, StrHideError> {
    let kind = sniff_hevc_carrier(carrier)
        .ok_or_else(|| StrHideError::UnsupportedFormat("Not HEVC carrier".into()))?;
    let capture = if full_capture {
        Capture::Full
    } else {
        Capture::Bits
    };
    let t0 = std::time::Instant::now();
    let record = record_carrier_state(
        carrier,
        kind,
        capture,
        StopCondition::TargetSlices(slice_count),
        &Control::none(),
    )?;
    let elapsed = t0.elapsed().as_micros() as u64;
    let band0 = record.bands.first().map_or(0, |r| r.len());
    let band1 = record.bands.get(1).map_or(0, |r| r.len());
    Ok(ScanStats {
        slices_scanned: record.slice_slot_ranges.len(),
        total_slots: band0 + band1,
        band0_slots: band0,
        band1_slots: band1,
        elapsed_micros: elapsed,
    })
}
