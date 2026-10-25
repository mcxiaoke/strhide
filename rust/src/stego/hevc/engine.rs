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
use crate::stego::hevc::slot::{BinOp, CabacRecorder, StegoSlot, SubstreamRecord};
use crate::stego::hevc::sniff::{HevcCarrierKind, NAL_SPS_NUT, sniff_hevc_carrier};
use crate::stego::{SafetyLevel, StegoCapacityInfo};
use oxideav_h265::cabac::ContextModel;
use oxideav_h265::encoder::bitwriter::BitWriter;
use oxideav_h265::encoder::cabac::CabacEncoder;
use rust_h265::HEVC_CONTEXTS;
use rust_h265::decoder::Decoder;
use rust_h265::nal::parse_nal;
use rust_h265::{NalUnitType, parse_sps};

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

/// Helper converting NalUnitType to raw 6-bit NAL unit type integer without modifying upstream rust_h265.
fn nal_type_to_u8(t: rust_h265::NalUnitType) -> u8 {
    match t {
        rust_h265::NalUnitType::TrailN => 0,
        rust_h265::NalUnitType::TrailR => 1,
        rust_h265::NalUnitType::TsaN => 2,
        rust_h265::NalUnitType::TsaR => 3,
        rust_h265::NalUnitType::StsaN => 4,
        rust_h265::NalUnitType::StsaR => 5,
        rust_h265::NalUnitType::RadlN => 6,
        rust_h265::NalUnitType::RadlR => 7,
        rust_h265::NalUnitType::RaslN => 8,
        rust_h265::NalUnitType::RaslR => 9,
        rust_h265::NalUnitType::BlaWLp => 16,
        rust_h265::NalUnitType::BlaWRadl => 17,
        rust_h265::NalUnitType::BlaNLp => 18,
        rust_h265::NalUnitType::IdrWRadl => 19,
        rust_h265::NalUnitType::IdrNLp => 20,
        rust_h265::NalUnitType::Cra => 21,
        rust_h265::NalUnitType::Vps => 32,
        rust_h265::NalUnitType::Sps => 33,
        rust_h265::NalUnitType::Pps => 34,
        rust_h265::NalUnitType::Aud => 35,
        rust_h265::NalUnitType::Eos => 36,
        rust_h265::NalUnitType::Eob => 37,
        rust_h265::NalUnitType::Fd => 38,
        rust_h265::NalUnitType::PrefixSei => 39,
        rust_h265::NalUnitType::SuffixSei => 40,
        rust_h265::NalUnitType::Other(v) => v,
    }
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

/// MP4/MOV containers are recognised by the sniffer but not implemented
/// (audit 2026-10-24 2.3): say so explicitly at every entry point instead of
/// a generic failure from deep inside the pipeline.
fn mp4_unsupported() -> StrHideError {
    StrHideError::UnsupportedFormat(
        "MP4/MOV HEVC carriers are not supported yet; remux to HEIF or a raw Annex-B bitstream"
            .into(),
    )
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
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;
    if kind == HevcCarrierKind::Mp4Container {
        return Err(mp4_unsupported());
    }
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
                if let Some(unit) = parse_nal(ps)
                    && unit.nal_unit_type == NalUnitType::Sps
                    && let Ok(sps) = parse_sps(&unit.rbsp)
                {
                    return Ok((sps.cropped_width(), sps.cropped_height()));
                }
            }
        }
        HevcCarrierKind::AnnexBStream => {
            let spans = parse_annex_b_spans(carrier);
            for span in &spans {
                if span.nal_type == NAL_SPS_NUT {
                    let end = span.end_offset().min(carrier.len());
                    if let Some(unit) = parse_nal(&carrier[span.header_offset..end])
                        && let Ok(sps) = parse_sps(&unit.rbsp)
                    {
                        return Ok((sps.cropped_width(), sps.cropped_height()));
                    }
                }
            }
        }
        HevcCarrierKind::Mp4Container => {
            return Err(mp4_unsupported());
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
    if kind == HevcCarrierKind::Mp4Container {
        return Err(mp4_unsupported());
    }

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
    if kind == HevcCarrierKind::Mp4Container {
        return Err(mp4_unsupported());
    }

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
                let (replay, _) = encode_substream(slice_rec, sub, &[]);
                replay_matches_cover(&replay, cover)
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
                let (reencoded, sub_trace) = encode_substream(slice_rec, sub, &flipped_ops);

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
) -> (Vec<u8>, Vec<SlotBitTrace>) {
    let mut enc = CabacEncoder::new();
    let mut writer = BitWriter::new();
    let mut ctx_array = [ContextModel::init(154, 26); HEVC_CONTEXTS];
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
                if idx < HEVC_CONTEXTS {
                    enc.encode_decision(&mut writer, &mut ctx_array[idx], bit);
                }
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

    // Mid-slice WPP/tile row substreams are deliberately left out of the
    // rewrite path: their journal ends with `Terminate{bit:0}` (row-end
    // more_data=false) and the remaining bits are the cover encoder's
    // substream finish, whose exact bit pattern differs between HM's and
    // x265's writers. Re-synthesizing that tail never replayed byte-exactly,
    // so the 3a check below disqualifies every mid-slice substream and the
    // payload falls back to the end-of-slice substreams only. Making them
    // usable requires pricing sign flips by the decoded coefficient
    // magnitude (sign bins decode before levels, so the cost must be
    // back-filled from the decoder); see the review report's §3.4#6.
    if !matches!(ops.last(), Some(BinOp::Terminate { bit: 1 })) {
        enc.encode_terminate(&mut writer, 1);
    }
    writer.align_zero();
    (writer.finish(), trace)
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
        .map(|i| (i * stride) % total)
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
    if kind == HevcCarrierKind::Mp4Container {
        return Err(mp4_unsupported());
    }

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
    /// HEIF/HEIC: owned copies of the VPS/SPS/PPS NAL bytes.
    Heif { parameter_sets: Vec<Vec<u8>> },
    /// Annex-B: the NAL span table.
    AnnexB {
        spans: Vec<crate::stego::hevc::bitstream::HevcNalSpan>,
    },
}

fn record_carrier_state(
    carrier: &[u8],
    kind: HevcCarrierKind,
) -> Result<CarrierRecord, StrHideError> {
    let mut slice_contexts = Vec::new();
    let mut all_slots = Vec::new();

    let mut decoder = Decoder::new();

    let digest_inputs = match kind {
        HevcCarrierKind::HeifContainer => {
            let target = parse_heif_targets(carrier)
                .map_err(|e| StrHideError::UnsupportedFormat(format!("HEIF parse error: {e}")))?;
            for ps in &target.parameter_sets {
                if let Some(unit) = parse_nal(ps) {
                    let _ = decoder.decode_nal(&unit);
                }
            }
            let parameter_sets = target
                .parameter_sets
                .iter()
                .map(|ps| ps.to_vec())
                .collect::<Vec<Vec<u8>>>();

            // `slice_idx` indexes `slice_contexts`, so it advances only when a
            // slice is actually recorded. Using the enumeration index of
            // `slice_spans` would desynchronise the two as soon as one slice
            // fails to decode, and `slot.slice_idx` would then point at the
            // wrong context (or out of bounds) during embedding.
            let mut slice_idx = 0usize;
            for span in target.slice_spans.iter() {
                let range = span.start..span.end();
                if range.end > carrier.len() {
                    continue;
                }
                let slice_bytes = &carrier[range.clone()];
                if let Some(slice_unit) = parse_nal(slice_bytes) {
                    let mut recorder = CabacRecorder::with_slice(slice_idx);
                    if decoder
                        .decode_nal_with_observer(&slice_unit, &mut recorder)
                        .is_ok()
                    {
                        let slot_map =
                            absorb_recorder(&mut recorder, &slice_unit.rbsp, &mut all_slots);
                        slice_contexts.push(SliceContext {
                            carrier_span: range,
                            nal_type: nal_type_to_u8(slice_unit.nal_unit_type),
                            layer_id: slice_unit.nuh_layer_id,
                            temporal_id: slice_unit.temporal_id,
                            orig_rbsp: slice_unit.rbsp.clone().into_owned(),
                            ops: recorder.ops,
                            substreams: recorder.substreams,
                            slot_map,
                        });
                        slice_idx += 1;
                    }
                }
            }
            DigestInputs::Heif { parameter_sets }
        }
        HevcCarrierKind::AnnexBStream => {
            let spans = parse_annex_b_spans(carrier);
            for span in &spans {
                if span.is_param_set() {
                    let end = span.end_offset().min(carrier.len());
                    if let Some(unit) = parse_nal(&carrier[span.header_offset..end]) {
                        let _ = decoder.decode_nal(&unit);
                    }
                }
            }

            let mut slice_idx = 0;
            for span in &spans {
                if span.is_vcl() {
                    let end = span.end_offset().min(carrier.len());
                    let range = span.header_offset..end;
                    if let Some(unit) = parse_nal(&carrier[range.clone()]) {
                        let mut recorder = CabacRecorder::with_slice(slice_idx);
                        if decoder
                            .decode_nal_with_observer(&unit, &mut recorder)
                            .is_ok()
                        {
                            let slot_map =
                                absorb_recorder(&mut recorder, &unit.rbsp, &mut all_slots);
                            slice_contexts.push(SliceContext {
                                carrier_span: range,
                                nal_type: nal_type_to_u8(unit.nal_unit_type),
                                layer_id: unit.nuh_layer_id,
                                temporal_id: unit.temporal_id,
                                orig_rbsp: unit.rbsp.clone().into_owned(),
                                ops: recorder.ops,
                                substreams: recorder.substreams,
                                slot_map,
                            });
                            slice_idx += 1;
                        }
                    }
                }
            }
            DigestInputs::AnnexB {
                spans: spans.clone(),
            }
        }
        _ => {
            return Err(StrHideError::UnsupportedFormat(
                "Carrier format not supported yet for HEVC stego".into(),
            ));
        }
    };

    Ok(CarrierRecord {
        slice_contexts,
        all_slots,
        digest_inputs,
    })
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
        DigestInputs::Heif { parameter_sets } => {
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
}
