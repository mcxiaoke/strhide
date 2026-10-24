//! HEVC / H.265 In-place CABAC Bypass Steganography Engine (Scheme C).
//!
//! Provides zero bitrate expansion (Δ = 0), content-adaptive distortion-minimized
//! steganographic embedding and extraction directly within H.265/HEVC bitstreams.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use crc32fast::Hasher as Crc32;
use hkdf::Hkdf;
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::errors::StrHideError;
use crate::stego::coding::{Move, StcTrellis};
use crate::stego::hevc::bitstream::{compute_hevc_cover_digest, parse_annex_b_spans, rbsp_to_nal};
use crate::stego::hevc::heif_boxes::parse_heif_targets;
use crate::stego::hevc::slot::{BinOp, CabacRecorder, StegoSlot, SubstreamRecord};
use crate::stego::hevc::sniff::{HevcCarrierKind, sniff_hevc_carrier};
use oxideav_h265::cabac::ContextModel;
use oxideav_h265::encoder::bitwriter::BitWriter;
use oxideav_h265::encoder::cabac::CabacEncoder;
use rust_h265::HEVC_CONTEXTS;
use rust_h265::decoder::Decoder;
use rust_h265::nal::parse_nal;

/// Steganographic magic signature in ciphertext header (StrHide HEVC).
const HEVC_STEGO_MAGIC: &[u8; 4] = b"SH25";

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

/// Fixed header length in bytes: Magic (4) + Len (4) + CRC32 (4) + Nonce (12) + Tag (16) = 40 bytes (320 bits).
const HEVC_HEADER_BYTES: usize = 40;

/// Default public salt if none provided.
const DEFAULT_HEVC_SALT: &[u8] = b"strhide-hevc-salt-2026";

/// Maximum number of STC re-solves while settling the flip set. Each round
/// either drops the slots that disturbed an emulation-prevention (EPB) window,
/// drops a substream whose journal does not replay the cover, or gives up, so
/// the loop always makes progress. Healthy carriers settle in one round.
const MAX_EMBED_ROUNDS: usize = 24;

/// Where a flipped bypass bin landed in the codeword:
/// `(global slot index, first affected RBSP byte, last affected RBSP byte)`.
type SlotBitTrace = (usize, usize, usize);

/// A disturbed emulation-prevention window: the RBSP byte that starts the
/// `00 00 xx<=3` triple, plus the trace of every flipped slot in that slice.
type EpbConflict = (usize, Vec<SlotBitTrace>);

/// Capacity probe: returns the maximum embeddable payload size in bytes.
pub fn probe_hevc_capacity(carrier: &[u8]) -> Result<usize, StrHideError> {
    let slots = scan_hevc_slots(carrier)?;
    let total_slots = slots.len();
    let trellis = StcTrellis::from_seed_grouped(0x5465_676f, 7, 2)?;
    let min_needed_slots = trellis.slots_for(HEVC_HEADER_BYTES * 8);
    if total_slots < min_needed_slots {
        return Ok(0);
    }
    // Rate 1/2: ~2 slots per payload bit
    let available_bits = (total_slots / 2).saturating_sub(HEVC_HEADER_BYTES * 8);
    Ok(available_bits / 8)
}

/// Embed a payload into an HEVC/HEIC carrier using content-adaptive sign-bit steganography.
pub fn embed_hevc(
    carrier: &[u8],
    payload: &[u8],
    password: Option<&str>,
) -> Result<Vec<u8>, StrHideError> {
    if payload.is_empty() {
        return Err(StrHideError::General("Cannot embed empty payload".into()));
    }

    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;

    // 1. Scan and record all slices and substreams
    let (_carrier_buf, slice_contexts, all_slots) = record_carrier_state(carrier, kind)?;
    let total_slots = all_slots.len();

    // 2. Prepare ciphertext and envelope
    let cover_digest = derive_carrier_digest(carrier, kind);
    let key = derive_hevc_key(password, &cover_digest);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| StrHideError::General(format!("AES-GCM key init failed: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| StrHideError::General(format!("HEVC payload encryption failed: {e}")))?;

    let mut crc = Crc32::new();
    crc.update(payload);
    let payload_crc = crc.finalize();

    let mut message = Vec::with_capacity(20 + ciphertext.len());
    message.extend_from_slice(HEVC_STEGO_MAGIC);
    message.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    message.extend_from_slice(&payload_crc.to_be_bytes());
    message.extend_from_slice(&nonce_bytes);
    message.extend_from_slice(&ciphertext);

    let seed = seed_from_digest(&cover_digest);
    let trellis = StcTrellis::from_seed_grouped(seed, 7, 2)?;
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
            return Err(StrHideError::TrellisInfeasible(format!(
                "HEVC stego exhausted usable slots after {round} round(s) ({} slot(s) excluded, {} unsupported substream(s)): {e}",
                forbidden.iter().filter(|x| **x).count(),
                bad_substreams.len()
            )));
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

        if conflicts.is_empty() {
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
pub fn extract_hevc(carrier: &[u8], password: Option<&str>) -> Result<Vec<u8>, StrHideError> {
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;

    let all_slots = scan_hevc_slots(carrier)?;
    let cover_digest = derive_carrier_digest(carrier, kind);
    let seed = seed_from_digest(&cover_digest);
    let trellis = StcTrellis::from_seed_grouped(seed, 7, 2)?;

    let header_slots_count = trellis.slots_for(HEVC_HEADER_BYTES * 8);
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

    // Extract first 40 bytes (320 bits) of header
    let header_bytes = trellis.extract(&header_bits, HEVC_HEADER_BYTES * 8);

    if header_bytes.len() < HEVC_HEADER_BYTES {
        return Err(StrHideError::CorruptedData(
            "HEVC stego header is truncated".into(),
        ));
    }

    if &header_bytes[0..4] != HEVC_STEGO_MAGIC {
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
    nonce_bytes.copy_from_slice(&header_bytes[12..24]);

    let total_msg_len = 24usize
        .checked_add(payload_len)
        .and_then(|v| v.checked_add(16))
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
    let ciphertext = &msg_bytes[24..total_msg_len];

    let key = derive_hevc_key(password, &cover_digest);
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

type CarrierRecord = (Vec<u8>, Vec<SliceContext>, Vec<StegoSlot>);

fn record_carrier_state(
    carrier: &[u8],
    kind: HevcCarrierKind,
) -> Result<CarrierRecord, StrHideError> {
    let out_carrier = carrier.to_vec();
    let mut slice_contexts = Vec::new();
    let mut all_slots = Vec::new();

    let mut decoder = Decoder::new();

    match kind {
        HevcCarrierKind::HeifContainer => {
            let target = parse_heif_targets(carrier)
                .map_err(|e| StrHideError::UnsupportedFormat(format!("HEIF parse error: {e}")))?;
            for ps in &target.parameter_sets {
                if let Some(unit) = parse_nal(ps) {
                    let _ = decoder.decode_nal(&unit);
                }
            }

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
        }
        _ => {
            return Err(StrHideError::UnsupportedFormat(
                "Carrier format not supported yet for HEVC stego".into(),
            ));
        }
    }

    Ok((out_carrier, slice_contexts, all_slots))
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
    let (_, _, slots) = record_carrier_state(carrier, kind)?;
    Ok(slots)
}

/// Derive the 64-bit trellis seed from a carrier digest.
///
/// The digest is a fixed `[u8; 32]`, so this conversion is infallible; the
/// helper exists so that no call site needs an `unwrap()` on a
/// slice-to-array conversion.
#[inline]
fn seed_from_digest(cover_digest: &[u8; 32]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&cover_digest[0..8]);
    u64::from_be_bytes(buf)
}

fn derive_carrier_digest(carrier: &[u8], kind: HevcCarrierKind) -> [u8; 32] {
    match kind {
        HevcCarrierKind::HeifContainer => {
            if let Ok(target) = parse_heif_targets(carrier) {
                // Hash the parameter set *contents*. They are immutable during
                // embedding, which is what makes the digest — and therefore the
                // trellis seed and the AES key — identical on both ends.
                //
                // (Feeding them through `compute_hevc_cover_digest` would need
                // byte offsets into `carrier`; the parsed sets are copies, and
                // an offset of 0 quietly hashed the file header instead.)
                let mut hasher = Sha256::new();
                hasher.update(DEFAULT_HEVC_SALT);
                hasher.update((target.parameter_sets.len() as u64).to_be_bytes());
                for ps in &target.parameter_sets {
                    hasher.update((ps.len() as u64).to_be_bytes());
                    hasher.update(ps);
                }
                hasher.finalize().into()
            } else {
                [0u8; 32]
            }
        }
        HevcCarrierKind::AnnexBStream => {
            let spans = parse_annex_b_spans(carrier);
            compute_hevc_cover_digest(carrier, &spans, DEFAULT_HEVC_SALT)
        }
        _ => [0u8; 32],
    }
}

fn derive_hevc_key(password: Option<&str>, salt: &[u8; 32]) -> [u8; 32] {
    let pw_bytes = password
        .unwrap_or("strhide-hevc-default-key-2026")
        .as_bytes();
    let hk = Hkdf::<Sha256>::new(Some(salt), pw_bytes);
    let mut key = [0u8; 32];
    // HKDF-SHA256 can always produce 32 bytes (255 * 32 > 32), so this
    // cannot fail. Use `unwrap_or_default` rather than `expect` so that a
    // hypothetical future change of hash/len cannot abort the process.
    if hk.expand(b"strhide-hevc-aes256-key", &mut key).is_err() {
        return [0u8; 32];
    }
    key
}
