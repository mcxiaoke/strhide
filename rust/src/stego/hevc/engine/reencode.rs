//! Slice re-encoding: replay a recorded CABAC journal with flipped bins.
//!
//! Embedding never rewrites a whole stream: it inverts the bypass bins the STC
//! chose and re-encodes only the slices that own them. Everything here turns
//! "flip these slots" into "these NAL byte spans change", and rejects a slice
//! whose replay would desynchronise the decoder or introduce an emulation
//! prevention sequence the cover does not have.

use crate::errors::StrHideError;
use crate::stego::hevc::bitstream::rbsp_to_nal;
use crate::stego::hevc::slot::SubstreamRecord;
use oxideav_h265::cabac::ContextModel;
use oxideav_h265::encoder::bitwriter::BitWriter;
use oxideav_h265::encoder::cabac::CabacEncoder;
use rusty_h265::observer::ENCODER_CONTEXTS;

use super::scan::SliceContext;
use super::support::{EpbConflict, SlotBitTrace};

/// Re-encode one CABAC substream from its recorded journal.
///
/// `flipped_ops` marks the journal entries whose bypass bin was inverted. The
/// second return value lists, for every inverted bin, the global slot index and
/// the `[first, last)` bit range it can occupy in the output stream, which lets
/// the caller map a broken `00 00 xx` window back to a slot.
pub(super) fn encode_substream(
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

pub(super) enum SliceReencodeOutcome {
    Success {
        span: std::ops::Range<usize>,
        re_nal: Vec<u8>,
    },
    Conflict(Vec<EpbConflict>),
    BadSubstream(usize, usize),
    LengthError(String),
}

pub(super) fn reencode_slice(
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
