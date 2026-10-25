//! HEVC / H.265 In-place CABAC Bypass Steganography Engine (Scheme C).
//!
//! Provides zero bitrate expansion (Δ = 0), content-adaptive distortion-minimized
//! steganographic embedding and extraction directly within H.265/HEVC bitstreams.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use crc32fast::Hasher as Crc32;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::errors::StrHideError;
use crate::stego::coding::{Move, StcTrellis};
use crate::stego::envelope::{Freshness, PUBLIC_DEFAULT_SECRET, derive_domain_subkey_with_label};
use crate::stego::format::HevcFormatProfile;
use crate::stego::hevc::bitstream::{compute_hevc_cover_digest, parse_annex_b_spans, rbsp_to_nal};
use crate::stego::hevc::heif_boxes::parse_heif_targets;
use crate::stego::hevc::mp4_boxes::parse_mp4_targets;
use crate::stego::hevc::slot::{BinOp, CabacRecorder, StegoSlot, SubstreamRecord};
use crate::stego::hevc::sniff::{
    HevcCarrierKind, NAL_RADL_N, NAL_RASL_N, NAL_SPS_NUT, NAL_STSA_N, NAL_TRAIL_N, NAL_TSA_N,
    sniff_hevc_carrier,
};
use crate::stego::{SafetyLevel, StegoCapacityInfo};
use oxideav_h265::cabac::ContextModel;
use oxideav_h265::encoder::bitwriter::BitWriter;
use oxideav_h265::encoder::cabac::CabacEncoder;
use rusty_h265::Decoder;
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

/// On-wire message header of an HEVC stego carrier:
/// `[magic 4][payload_len 4][payload crc32 4][nonce 12]`. The GCM tag does not
/// live here -- it trails the ciphertext (audit 2026-10-24 2.2: the constants
/// used to be hard-coded at the call sites while `fmt.header_bytes` described
/// a different quantity, so a private dialect with a small `header_bytes`
/// panicked on `header_bytes[12..24]`).
const HEVC_MSG_HEADER_BYTES: usize = 24;
/// AES-256-GCM tag length appended to the ciphertext.
const HEVC_TAG_BYTES: usize = 16;

/// `fmt.header_bytes` must at least cover the fixed message header, or the
/// extractor could not read the payload length. The default profile budgets 40
/// = `HEVC_MSG_HEADER_BYTES + HEVC_TAG_BYTES`, the true total overhead.
fn check_header_bytes(fmt: &HevcFormatProfile) -> Result<(), StrHideError> {
    if fmt.header_bytes < HEVC_MSG_HEADER_BYTES {
        return Err(StrHideError::UnsupportedVersion(format!(
            "HevcFormatProfile.header_bytes must be >= {HEVC_MSG_HEADER_BYTES}, got {}",
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
    let slots = scan_hevc_slots(carrier)?;
    let total_slots = slots.len();
    let trellis = StcTrellis::from_seed_grouped(CAPACITY_PROBE_SEED, fmt.stc_h, fmt.stc_u)?;
    let header_bits = fmt.header_bytes * 8;
    let min_needed_slots = trellis.slots_for(header_bits);
    if total_slots < min_needed_slots {
        return Ok(0);
    }
    // `message_bits` is the exact inverse of `slots_for` (n/u - (h-1)), so the
    // bound honours both the group size and the warm-up rows. The previous
    // hard-coded `total_slots / 2` ignored both and over-reported by h-1 bits,
    // which crossed the byte boundary on most carriers (audit 2026-10-24 2.1:
    // 9 of 14 corpus files advertised one byte more than embed accepts).
    let available_bits = trellis
        .message_bits(total_slots)
        .saturating_sub(header_bits);
    Ok(available_bits / 8)
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
pub fn probe_hevc_capacity_info(
    carrier: &[u8],
    fmt: &HevcFormatProfile,
    safety_level: SafetyLevel,
) -> Result<StegoCapacityInfo, StrHideError> {
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;
    let format_name = match kind {
        HevcCarrierKind::HeifContainer => "HEIF/HEVC",
        HevcCarrierKind::AnnexBStream => "HEVC-AnnexB",
        HevcCarrierKind::Mp4Container => "MP4/HEVC",
    };

    let slots = scan_hevc_slots(carrier)?;
    let total_slots = slots.len();
    let trellis = StcTrellis::from_seed_grouped(CAPACITY_PROBE_SEED, fmt.stc_h, fmt.stc_u)?;
    let header_bits = fmt.header_bytes * 8;
    let min_needed_slots = trellis.slots_for(header_bits);

    let max_raw_payload_bytes = if total_slots < min_needed_slots {
        0
    } else {
        // Exact inverse of `slots_for` (audit 2026-10-24 2.1): honours the
        // group size `u` and the h-1 warm-up rows instead of a hard-coded 1/2.
        let available_bits = trellis
            .message_bits(total_slots)
            .saturating_sub(header_bits);
        available_bits / 8
    };

    // Extract picture dimensions from SPS to derive true pixel count
    let (width, height) = extract_hevc_dimensions(carrier).unwrap_or((0, 0));
    let total_pixels = (width as usize) * (height as usize);
    let total_elements = if total_pixels > 0 {
        total_pixels
    } else {
        total_slots
    };

    // Safety-bounded recommended capacity:
    // min(bpp_limit * total_pixels, available_slots / target_ratio)
    let bpp_bits = (total_elements as f64 * safety_level.bpp_limit()).floor() as usize;
    let ratio_bits = (total_slots as f64 / safety_level.target_ratio()).floor() as usize;
    let target_bits = bpp_bits.min(ratio_bits);
    let recommended_max_bytes = (target_bits / 8)
        .saturating_sub(fmt.header_bytes)
        .min(max_raw_payload_bytes);

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
    })
}

/// Embed a payload into an HEVC/HEIC carrier using content-adaptive sign-bit steganography.
///
/// The complete expert entry. `secret` is the resolved credential (explicit
/// password, else the profile's private stego secret, else `None` for the
/// official public constant); `domain` isolates the HKDF derivation; `fmt` is
/// the wire-format identity; `freshness` supplies the nonce (`Seeded` makes
/// the output reproducible for the same inputs).
pub fn embed_hevc(
    carrier: &[u8],
    payload: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
) -> Result<Vec<u8>, StrHideError> {
    if payload.is_empty() {
        return Err(StrHideError::General("Cannot embed empty payload".into()));
    }
    check_header_bytes(fmt)?;

    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;

    // 1. Scan and record all slices and substreams
    let record = record_carrier_state(carrier, kind)?;
    let slice_contexts = record.slice_contexts;
    let all_slots = record.all_slots;
    let total_slots = all_slots.len();

    // 2. Prepare ciphertext and envelope
    let cover_digest = derive_carrier_digest(carrier, &record.digest_inputs, fmt);
    let key = derive_hevc_key(secret, domain, &cover_digest, fmt);
    let magic = derive_magic(fmt.magic_label, effective_secret(secret).as_bytes());
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| StrHideError::General(format!("AES-GCM key init failed: {e}")))?;

    // Seeded runs bind the nonce to this (cover, payload) pair: the HEVC key
    // derives from a cover digest that two same-parameter carriers share, so
    // an unbound seeded nonce could repeat a (key, nonce) pair across inputs.
    let fresh_binding = Freshness::seeded_binding(carrier, payload);
    let nonce_bytes = freshness.nonce(0, &fresh_binding);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| StrHideError::General(format!("HEVC payload encryption failed: {e}")))?;

    let mut crc = Crc32::new();
    crc.update(payload);
    let payload_crc = crc.finalize();

    let mut message = Vec::with_capacity(HEVC_MSG_HEADER_BYTES + ciphertext.len());
    message.extend_from_slice(&magic);
    message.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    message.extend_from_slice(&payload_crc.to_be_bytes());
    message.extend_from_slice(&nonce_bytes);
    message.extend_from_slice(&ciphertext);

    let seed = trellis_seed_from_key(&key, &cover_digest);
    let trellis = StcTrellis::from_seed_grouped(seed, fmt.stc_h, fmt.stc_u)?;
    let needed_slots = trellis.slots_for(message.len() * 8);

    if total_slots < needed_slots {
        return Err(StrHideError::General(format!(
            "HEVC capacity exceeded: needed {} slots, carrier available {}",
            needed_slots, total_slots
        )));
    }

    // 3. Element order, then solve / re-encode until the flip set is safe.
    //
    //    Slots are consumed in a deterministic Weyl permutation of the pool
    //    (`slot_positions`), not in recording order. Recording order is
    //    spatial: it starts at the first item (for a burst .heic, the primary
    //    image) and inside it at the first slices, so a small payload used to
    //    eat the first picture's signs wholesale and flatten it. The extractor
    //    derives the same permutation from `total_slots` alone, so no side
    //    information is needed.
    //
    //    Two things can make an individual slot unusable:
    //      * flipping it disturbs a `00 00 xx<=3` boundary, so RBSP->NAL
    //        emulation prevention would insert/drop a byte and break the
    //        zero-expansion promise; and
    //      * the journal of its substream does not replay the cover byte for
    //        byte, i.e. that substream uses syntax the recorder does not model
    //        (PCM sample data, aligned bypass coding, an unparsed PPS
    //        extension, ...).
    //
    //    Both are discovered while embedding. Such slots get an infinite STC
    //    cost and are simply never flipped -- the slot *set* never changes,
    //    because extraction has no way to learn about the exclusion.
    let positions = slot_positions(total_slots, needed_slots);
    let mut forbidden = vec![false; total_slots];
    let mut bad_substreams: HashSet<(usize, usize)> = HashSet::new();
    let mut replay_ok: HashMap<(usize, usize), bool> = HashMap::new();
    let mut out_carrier = carrier.to_vec();

    for round in 0..MAX_EMBED_ROUNDS {
        let mut cover_bits = Vec::with_capacity(needed_slots);
        let mut costs = Vec::with_capacity(needed_slots);
        let mut moves = Vec::with_capacity(needed_slots);
        for &pos in &positions {
            let slot = &all_slots[pos];
            cover_bits.push(slot.original_bit);
            costs.push(if forbidden[pos] {
                f64::INFINITY
            } else {
                slot.cost
            });
            // A bypass sign bit is one bit of the arithmetic codeword: flipping
            // it only inverts the geometrically negated coefficient.
            moves.push(if slot.original_bit == 0 {
                Move::PlusOnly
            } else {
                Move::MinusOnly
            });
        }

        let mut deltas = vec![0i8; needed_slots];
        if let Err(e) =
            trellis.embed_with_deltas(&cover_bits, &moves, &costs, &costs, &message, &mut deltas)
        {
            if round == 0 {
                return Err(e);
            }
            return Err(StrHideError::TrellisInfeasible {
                cause: crate::errors::TrellisCause::ExhaustedSlots,
                detail: format!(
                    "HEVC stego exhausted usable slots after {round} round(s) ({} slot(s) excluded, {} unsupported substream(s)): {e}",
                    forbidden.iter().filter(|x| **x).count(),
                    bad_substreams.len()
                ),
            });
        }

        let mut flips_per_slice: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        let mut touched: BTreeSet<(usize, usize)> = BTreeSet::new();
        for (i, &delta) in deltas.iter().enumerate() {
            if delta != 0 {
                let slot = &all_slots[positions[i]];
                flips_per_slice
                    .entry(slot.slice_idx)
                    .or_default()
                    .push(slot.op_idx);
                touched.insert((slot.slice_idx, slot.substream_idx));
            }
        }

        // 3a. Journal fidelity: before a substream is rewritten, prove that its
        //     recorded journal reproduces the cover exactly.
        let mut unsound = Vec::new();
        for &(slice_idx, sub_idx) in &touched {
            let ok = *replay_ok.entry((slice_idx, sub_idx)).or_insert_with(|| {
                let slice_rec = &slice_contexts[slice_idx];
                let sub = &slice_rec.substreams[sub_idx];
                let cover = &slice_rec.orig_rbsp[sub.rbsp_byte_start..sub.rbsp_byte_end];
                // A journal that cannot even be replayed without flips is not
                // sound for flipping: treat it as a bad substream.
                match encode_substream(slice_rec, sub, &[]) {
                    Ok((replay, _)) => replay_matches_cover(&replay, cover),
                    Err(_) => false,
                }
            });
            if !ok && bad_substreams.insert((slice_idx, sub_idx)) {
                unsound.push((slice_idx, sub_idx));
            }
        }
        if !unsound.is_empty() {
            for &pos in &positions {
                let slot = &all_slots[pos];
                if bad_substreams.contains(&(slot.slice_idx, slot.substream_idx)) {
                    forbidden[pos] = true;
                }
            }
            continue;
        }

        // 3b. Re-encode every touched slice and check that the emulation
        //     prevention window set is unchanged.
        let mut conflicts: Vec<EpbConflict> = Vec::new();
        let mut reencoded_slices = Vec::new();

        for (slice_idx, op_indices) in &flips_per_slice {
            let slice_rec = &slice_contexts[*slice_idx];
            let mut flipped_ops = vec![false; slice_rec.ops.len()];
            for &op_idx in op_indices {
                flipped_ops[op_idx] = true;
            }

            let mut substream_ids: Vec<usize> = op_indices
                .iter()
                .filter_map(|&op_idx| {
                    slice_rec
                        .substreams
                        .iter()
                        .position(|s| op_idx >= s.op_start && op_idx < s.op_end)
                })
                .collect();
            substream_ids.sort_unstable();
            substream_ids.dedup();

            let mut modified_rbsp = slice_rec.orig_rbsp.clone();
            // (global slot, first touched RBSP byte, last touched RBSP byte)
            let mut trace: Vec<SlotBitTrace> = Vec::new();
            let mut slice_ok = true;

            for sub_idx in &substream_ids {
                let sub = &slice_rec.substreams[*sub_idx];
                let orig_sub_len = sub.rbsp_byte_end.saturating_sub(sub.rbsp_byte_start);
                let (reencoded, sub_trace) = match encode_substream(slice_rec, sub, &flipped_ops) {
                    Ok(pair) => pair,
                    Err(_) => {
                        // Journal/stream disagreement inside this substream:
                        // drop it like a length mismatch instead of writing
                        // a desynchronised re-encode.
                        bad_substreams.insert((*slice_idx, *sub_idx));
                        slice_ok = false;
                        break;
                    }
                };

                if reencoded.len() == orig_sub_len {
                    modified_rbsp[sub.rbsp_byte_start..sub.rbsp_byte_end]
                        .copy_from_slice(&reencoded);
                } else if reencoded.len() < orig_sub_len && orig_sub_len - reencoded.len() <= 4 {
                    // Trailing `cabac_zero_word` padding: the cover carried zero
                    // words that the journal does not model.
                    modified_rbsp[sub.rbsp_byte_start..sub.rbsp_byte_start + reencoded.len()]
                        .copy_from_slice(&reencoded);
                    for b in
                        &mut modified_rbsp[sub.rbsp_byte_start + reencoded.len()..sub.rbsp_byte_end]
                    {
                        *b = 0;
                    }
                } else {
                    // The flip footprint escaped the substream: treat the whole
                    // substream as unsupported rather than guessing.
                    bad_substreams.insert((*slice_idx, *sub_idx));
                    slice_ok = false;
                    break;
                }

                for (global, bit_lo, bit_hi) in sub_trace {
                    trace.push((
                        global,
                        sub.rbsp_byte_start + bit_lo / 8,
                        sub.rbsp_byte_start + bit_hi.saturating_sub(1) / 8,
                    ));
                }
            }

            if slice_ok {
                // Emulation prevention byte insertion is a pure function of the
                // `00 00 xx<=3` windows, so comparing those windows is
                // equivalent to comparing the NAL lengths -- and it also catches
                // a "one byte added, one byte dropped" swap that keeps the
                // length intact but shifts every following WPP entry point.
                for p in 2..modified_rbsp.len() {
                    let now_starts_epb = modified_rbsp[p - 2] == 0
                        && modified_rbsp[p - 1] == 0
                        && modified_rbsp[p] <= 3;
                    let cover_starts_epb = slice_rec.orig_rbsp[p - 2] == 0
                        && slice_rec.orig_rbsp[p - 1] == 0
                        && slice_rec.orig_rbsp[p] <= 3;
                    if now_starts_epb != cover_starts_epb {
                        conflicts.push((p, trace.clone()));
                        slice_ok = false;
                        break;
                    }
                }
            }

            if !slice_ok {
                continue;
            }

            let re_nal = rbsp_to_nal(
                slice_rec.nal_type,
                slice_rec.layer_id,
                slice_rec.temporal_id,
                &modified_rbsp,
            );
            if re_nal.len() == slice_rec.carrier_span.len() {
                reencoded_slices.push((slice_rec.carrier_span.clone(), re_nal));
            } else {
                return Err(StrHideError::General(format!(
                    "HEVC slice {slice_idx}: re-encoded NAL is {} bytes but the cover span is {} bytes",
                    re_nal.len(),
                    slice_rec.carrier_span.len()
                )));
            }
        }

        let mut had_bad_substream = false;
        for &pos in &positions {
            let slot = &all_slots[pos];
            if bad_substreams.contains(&(slot.slice_idx, slot.substream_idx)) && !forbidden[pos] {
                forbidden[pos] = true;
                had_bad_substream = true;
            }
        }
        if had_bad_substream {
            continue;
        }

        if conflicts.is_empty() && reencoded_slices.len() == flips_per_slice.len() {
            for (span, re_nal) in reencoded_slices {
                out_carrier[span].copy_from_slice(&re_nal);
            }
            return Ok(out_carrier);
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
                if global < total_slots && !forbidden[global] && byte_hi >= lo && byte_lo <= hi {
                    forbidden[global] = true;
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
                    && !forbidden[global]
                {
                    forbidden[global] = true;
                    progress += 1;
                }
            }
        }

        if progress == 0 {
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

/// Re-encode one CABAC substream from its recorded journal.
///
/// `flipped_ops` marks the journal entries whose bypass bin was inverted. The
/// second return value lists, for every inverted bin, the global slot index and
/// the `[first, last)` bit range it can occupy in the output stream, which lets
/// the caller map a broken `00 00 xx` window back to a slot.
fn encode_substream(
    slice: &SliceContext,
    sub: &SubstreamRecord,
    flipped_ops: &[bool],
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

    for (offset, op) in ops.iter().enumerate() {
        let op_idx = sub.op_start + offset;
        let flipped = flipped_ops.get(op_idx).copied().unwrap_or(false);
        match *op {
            BinOp::Decision { ctx_idx, bit } => {
                let idx = ctx_idx as usize;
                // A context index outside the model array means the journal and
                // this build disagree about the syntax. Skipping the bin would
                // silently desynchronise the replay, so it is a hard error: the
                // caller marks the substream unsupported.
                let ctx = ctx_array.get_mut(idx).ok_or_else(|| {
                    StrHideError::CorruptedData(format!(
                        "CABAC context index {idx} is out of range (ENCODER_CONTEXTS = {ENCODER_CONTEXTS})"
                    ))
                })?;
                enc.encode_decision(&mut writer, ctx, bit);
            }
            BinOp::Bypass { bit, slot_idx } => {
                let out_bit = if flipped { bit ^ 1 } else { bit };
                let bit_lo = writer.bit_len();
                enc.encode_bypass(&mut writer, out_bit);
                let bit_hi = writer.bit_len();
                if flipped
                    && let Some(local) = slot_idx
                    && let Some(&Some(global)) = slice.slot_map.get(local)
                {
                    trace.push((global, bit_lo, bit_hi));
                }
            }
            BinOp::Terminate { bit } => enc.encode_terminate(&mut writer, bit),
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
    if !matches!(ops.last(), Some(BinOp::Terminate { bit: 1 })) {
        enc.encode_terminate(&mut writer, 1);
    }
    writer.align_zero();
    Ok((writer.finish(), trace))
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

/// Deterministic Weyl permutation of the slot pool, shared by the embedder and
/// the extractor.
///
/// Element `i` maps to slot `(i * stride) mod total`. `stride` is ~0.618 of the
/// pool and coprime with it, so consecutive elements land in different slices,
/// different items and different corners of the picture. Consuming slots in
/// recording order instead concentrates the whole payload on the first item --
/// for a burst `.heic` (dozens of independent pictures in one file) that
/// flattens the primary image while the other 40-odd pictures stay pristine.
///
/// `count` only decides how many elements are produced; the mapping of element
/// `i` never depends on it, which is what lets the extractor read the header
/// prefix and the full message with the same permutation.
fn slot_positions(total: usize, count: usize) -> Vec<usize> {
    if total == 0 {
        return Vec::new();
    }
    let mut stride = ((total as u64 * 618_034) / 1_000_000) as usize;
    stride = stride.max(1);
    while gcd_usize(stride, total) != 1 {
        stride += 1;
        if stride >= total {
            stride = 1;
            break;
        }
    }
    (0..count.min(total))
        // `i * stride` overflows `usize` on 32-bit targets once a burst HEIC
        // exposes a few billion slots; the modulus only needs the product's low
        // bits, so the multiply runs in `u64`.
        .map(|i| ((i as u64 * stride as u64) % total as u64) as usize)
        .collect()
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
///
/// The complete expert entry: same credential, domain and format identity the
/// embedder used. A wrong secret produces the same derived-magic mismatch an
/// empty carrier would, so the failure carries no oracle.
pub fn extract_hevc(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
) -> Result<Vec<u8>, StrHideError> {
    check_header_bytes(fmt)?;
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;

    let record = record_carrier_state(carrier, kind)?;
    let all_slots = record.all_slots;
    let cover_digest = derive_carrier_digest(carrier, &record.digest_inputs, fmt);
    // The trellis seed is keyed through the secret-derived key (see
    // `trellis_seed_from_key`), so it is derived before anything reads slots.
    let key = derive_hevc_key(secret, domain, &cover_digest, fmt);
    let seed = trellis_seed_from_key(&key, &cover_digest);
    let trellis = StcTrellis::from_seed_grouped(seed, fmt.stc_h, fmt.stc_u)?;

    let header_slots_count = trellis.slots_for(fmt.header_bytes * 8);
    if all_slots.len() < header_slots_count {
        return Err(StrHideError::CorruptedData(
            "Insufficient HEVC slots for header".into(),
        ));
    }

    // The slot permutation must match the embedder's exactly: it is derived
    // from `all_slots.len()` alone, and element `i` maps to the same slot no
    // matter how many elements are read, so the header prefix and the full
    // message stay consistent.
    let header_positions = slot_positions(all_slots.len(), header_slots_count);
    let header_bits: Vec<u8> = header_positions
        .iter()
        .map(|&p| all_slots[p].original_bit)
        .collect();

    // `fmt.header_bytes` is the fixed prefix this read sizes; the on-wire
    // layout it must at least cover is HEVC_MSG_HEADER_BYTES bytes.
    let header_bytes = trellis.extract(&header_bits, fmt.header_bytes * 8);

    if header_bytes.len() < HEVC_MSG_HEADER_BYTES {
        return Err(StrHideError::CorruptedData(
            "HEVC stego header is truncated".into(),
        ));
    }

    let expected_magic = derive_magic(fmt.magic_label, effective_secret(secret).as_bytes());
    if header_bytes[0..4] != expected_magic {
        return Err(StrHideError::CorruptedData(
            "Invalid HEVC stego signature".into(),
        ));
    }

    // `payload_len` comes straight from the carrier, i.e. it is
    // attacker-controlled. Every arithmetic step below uses checked
    // operations so that a hostile header cannot overflow the length
    // computation on a 32-bit target.
    let payload_len = u32::from_be_bytes([
        header_bytes[4],
        header_bytes[5],
        header_bytes[6],
        header_bytes[7],
    ]) as usize;
    let expected_crc = u32::from_be_bytes([
        header_bytes[8],
        header_bytes[9],
        header_bytes[10],
        header_bytes[11],
    ]);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&header_bytes[12..HEVC_MSG_HEADER_BYTES]);

    let total_msg_len = HEVC_MSG_HEADER_BYTES
        .checked_add(payload_len)
        .and_then(|v| v.checked_add(HEVC_TAG_BYTES))
        .ok_or_else(|| StrHideError::CorruptedData("HEVC stego header length overflows".into()))?;
    let total_msg_bits = total_msg_len
        .checked_mul(8)
        .ok_or_else(|| StrHideError::CorruptedData("HEVC stego header length overflows".into()))?;
    let total_needed_slots = trellis.slots_for(total_msg_bits);
    if total_needed_slots > all_slots.len() {
        return Err(StrHideError::CorruptedData(
            "Carrier truncated for declared payload".into(),
        ));
    }

    let msg_positions = slot_positions(all_slots.len(), total_needed_slots);
    let cover_bits: Vec<u8> = msg_positions
        .iter()
        .map(|&p| all_slots[p].original_bit)
        .collect();
    let msg_bytes = trellis.extract(&cover_bits, total_msg_bits);
    // `extract` clamps to the trellis capacity, so a short vector here means
    // the carrier cannot hold the declared payload. Check before slicing.
    if msg_bytes.len() < total_msg_len {
        return Err(StrHideError::CorruptedData(
            "Carrier truncated for declared payload".into(),
        ));
    }
    let ciphertext = &msg_bytes[HEVC_MSG_HEADER_BYTES..total_msg_len];

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| StrHideError::General(format!("AES-GCM key init failed: {e}")))?;
    let nonce = Nonce::from(nonce_bytes);

    let decrypted = cipher.decrypt(&nonce, ciphertext).map_err(|_| {
        StrHideError::Password("Authentication failed or incorrect password".into())
    })?;

    let mut crc = Crc32::new();
    crc.update(&decrypted);
    if crc.finalize() != expected_crc {
        return Err(StrHideError::CorruptedData(
            "CRC32 mismatch in HEVC payload".into(),
        ));
    }

    Ok(decrypted)
}

/// Helper struct for slice recording and span tracking.
#[derive(Clone)]
struct SliceContext {
    carrier_span: std::ops::Range<usize>,
    nal_type: u8,
    layer_id: u8,
    temporal_id: u8,
    orig_rbsp: Vec<u8>,
    ops: Vec<BinOp>,
    substreams: Vec<SubstreamRecord>,
    /// Recorder-local slot index → global slot index. `None` marks a slot the
    /// recorder captured but the engine deliberately dropped (EPB-prone
    /// substream in a multi-substream slice).
    slot_map: Vec<Option<usize>>,
}

/// One pass over the carrier: the recorded slice journals and slot pool,
/// plus the container parse the digest derivation reuses — deriving the
/// cover digest must not walk the container a second time (audit 2026-10-24
/// 2.5).
struct CarrierRecord {
    slice_contexts: Vec<SliceContext>,
    all_slots: Vec<StegoSlot>,
    digest_inputs: DigestInputs,
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

fn record_carrier_state(
    carrier: &[u8],
    kind: HevcCarrierKind,
) -> Result<CarrierRecord, StrHideError> {
    let mut decoder = Decoder::new();
    // First decode error, kept so a carrier that yields no slices can say why
    // instead of presenting as "0 bytes of capacity".
    let mut decode_error: Option<String> = None;

    let (candidates, digest_inputs) = match kind {
        HevcCarrierKind::HeifContainer => {
            let target = parse_heif_targets(carrier)
                .map_err(|e| StrHideError::UnsupportedFormat(format!("HEIF parse error: {e}")))?;
            for ps in &target.parameter_sets {
                if let Err(e) = decoder.push_nal(ps, None) {
                    decode_error.get_or_insert_with(|| format!("parameter set: {e}"));
                }
            }
            let parameter_sets = owned_parameter_sets(&target.parameter_sets);
            let mut candidates = Vec::with_capacity(target.slice_spans.len());
            for span in &target.slice_spans {
                if let Some(cand) = candidate_slice(carrier, span.start..span.end()) {
                    candidates.push(cand);
                }
            }
            (candidates, DigestInputs::ParameterSets { parameter_sets })
        }
        HevcCarrierKind::Mp4Container => {
            let target = parse_mp4_targets(carrier).map_err(|e| {
                StrHideError::UnsupportedFormat(format!("MP4/MOV parse error: {e}"))
            })?;
            for ps in &target.parameter_sets {
                if let Err(e) = decoder.push_nal(ps, None) {
                    decode_error.get_or_insert_with(|| format!("parameter set: {e}"));
                }
            }
            let parameter_sets = owned_parameter_sets(&target.parameter_sets);
            let mut candidates = Vec::with_capacity(target.slice_spans.len());
            for span in &target.slice_spans {
                if let Some(cand) = candidate_slice(carrier, span.start..span.end()) {
                    candidates.push(cand);
                }
            }
            (candidates, DigestInputs::ParameterSets { parameter_sets })
        }
        HevcCarrierKind::AnnexBStream => {
            let spans = parse_annex_b_spans(carrier);
            for span in &spans {
                if span.is_param_set() {
                    let end = span.end_offset().min(carrier.len());
                    if let Err(e) = decoder.push_nal(&carrier[span.header_offset..end], None) {
                        decode_error.get_or_insert_with(|| format!("parameter set: {e}"));
                    }
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
            (candidates, DigestInputs::AnnexB { spans })
        }
    };

    // The gate decides which slices *contribute slots*; it must never decide
    // which slices the decoder *sees*. A P/B picture needs its reference
    // pictures in the DPB, and the decoder skips everything until it meets an
    // IRAP ("stream does not start with an IRAP", H.265 8.1.3) -- feeding only
    // the non-reference pictures therefore yields exactly zero recordings.
    // Every candidate is pushed in decode order; unselected ones go through the
    // plain path with no observer attached.
    let has_non_reference = candidates.iter().any(|c| is_non_reference_vcl(c.nal_type));

    let mut slice_contexts = Vec::new();
    let mut all_slots = Vec::new();

    // `slice_idx` indexes `slice_contexts`, so it advances only when a slice is
    // actually recorded. Using the enumeration index of the candidate list
    // would desynchronise the two as soon as one slice fails to decode, and
    // `slot.slice_idx` would then point at the wrong context during embedding.
    let mut slice_idx = 0usize;
    for cand in &candidates {
        let slice_bytes = &carrier[cand.span.clone()];
        if slice_bytes.len() < 2 {
            continue;
        }
        if !selectable(cand.nal_type, has_non_reference) {
            if let Err(e) = decoder.push_nal(slice_bytes, None) {
                decode_error.get_or_insert_with(|| e.to_string());
            }
            drain_frames(&mut decoder);
            continue;
        }
        let mut recorder = CabacRecorder::with_slice(slice_idx);
        let decoded = decoder.decode_nal_with_observer(slice_bytes, &mut recorder);
        drain_frames(&mut decoder);
        match decoded {
            Err(e) => {
                decode_error.get_or_insert_with(|| e.to_string());
            }
            // A picture the decoder skipped (H.265 8.1.3: RASL with no leading
            // IRAP) records nothing and must not consume a slice index.
            Ok(_) if recorder.substreams.is_empty() => {}
            Ok(_) => {
                let rbsp = nal_rbsp(slice_bytes);
                let slot_map = absorb_recorder(&mut recorder, &rbsp, &mut all_slots);
                slice_contexts.push(SliceContext {
                    carrier_span: cand.span.clone(),
                    nal_type: cand.nal_type,
                    layer_id: cand.layer_id,
                    temporal_id: cand.temporal_id,
                    orig_rbsp: rbsp,
                    ops: recorder.ops,
                    substreams: recorder.substreams,
                    slot_map,
                });
                slice_idx += 1;
            }
        }
    }

    // A carrier the decoder refused outright (Range Extensions, >10-bit, a
    // truncated stream) would otherwise surface as "0 bytes of capacity" --
    // indistinguishable from a carrier that is simply too small. Name the
    // reason instead of reporting an empty pool.
    if slice_contexts.is_empty()
        && let Some(reason) = decode_error
    {
        return Err(StrHideError::UnsupportedFormat(format!(
            "HEVC carrier could not be decoded: {reason}"
        )));
    }

    Ok(CarrierRecord {
        slice_contexts,
        all_slots,
        digest_inputs,
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

/// Two-tier deterministic frame-type gate.
///
/// * **Tier A** -- the stream contains at least one non-reference picture
///   (`TRAIL_N`/`TSA_N`/`STSA_N`/`RADL_N`/`RASL_N`): record **only** those.
///   They never enter the DPB, so the embedding provably cannot drift into a
///   later frame. iPhone MP4 and MOV recordings land here (~50% of pictures).
/// * **Tier B** -- the stream has no non-reference picture at all: record every
///   VCL NAL. This is the still-image case (HEIC, a single-IDR stream: all IRAP,
///   nothing predicts forwards in a meaningful way), and the all-`TRAIL_R`
///   case some Android hardware encoders emit, where Tier A would leave 0
///   slots. The magnitude-aware cost model bounds each flip; measured drift
///   over 78 frames at 2 KiB stays at PSNR 39-40 dB with no accumulation.
///
/// The choice depends only on the sequence of `nal_unit_type` values, which
/// embedding never changes (sign flips live inside the CABAC payload), so both
/// ends derive the same slot pool and the wire header carries no flag.
fn selectable(nal_type: u8, has_non_reference: bool) -> bool {
    !has_non_reference || is_non_reference_vcl(nal_type)
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
fn absorb_recorder(
    recorder: &mut CabacRecorder,
    rbsp: &[u8],
    all_slots: &mut Vec<StegoSlot>,
) -> Vec<Option<usize>> {
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

    let mut slot_map = Vec::with_capacity(recorder.slots.len());
    for mut slot in recorder.slots.drain(..) {
        if is_multi_sub && excluded.contains(&slot.substream_idx) {
            slot_map.push(None);
            continue;
        }
        slot.slot_idx = all_slots.len();
        slot_map.push(Some(slot.slot_idx));
        all_slots.push(slot);
    }
    slot_map
}

fn scan_hevc_slots(carrier: &[u8]) -> Result<Vec<StegoSlot>, StrHideError> {
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;
    let record = record_carrier_state(carrier, kind)?;
    Ok(record.all_slots)
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
        assert_eq!(fmt.magic_label, b"strhide-hevc-magic-v1");
        assert_eq!(fmt.cover_salt, b"strhide-hevc-cover-v1");
        assert_eq!(fmt.kdf_info, b"strhide-hevc-aes-key");
        assert_eq!(fmt.stc_h, 7);
        assert_eq!(fmt.stc_u, 2);
        assert_eq!(fmt.header_bytes, 40);
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

    /// The gate keeps only non-reference pictures when the stream has any, and
    /// keeps everything when it has none -- the still-image case and the
    /// all-reference case, where Tier A would leave no capacity at all.
    #[test]
    fn gate_is_two_tier_and_stateless() {
        // Tier A: a stream that has non-reference pictures records only those.
        assert!(selectable(NAL_TRAIL_N, true));
        assert!(selectable(NAL_TSA_N, true));
        assert!(selectable(NAL_RASL_N, true));
        assert!(!selectable(NAL_TRAIL_R, true));
        // IDR_W_RADL is a reference picture: dropped too, even though it is an
        // IRAP, because the stream does hold non-reference pictures to use.
        assert!(!selectable(NAL_IDR_W_RADL, true));

        // Tier B: no non-reference picture anywhere -> record everything. That
        // is the still-image case (all IRAP) and the all-`TRAIL_R` case some
        // Android encoders emit, where Tier A would leave no capacity at all.
        assert!(selectable(NAL_TRAIL_R, false));
        assert!(selectable(NAL_IDR_W_RADL, false));
        assert!(selectable(NAL_TRAIL_N, false));
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
