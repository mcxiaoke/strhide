//! Carrier scanning: recorded slot pools, GOP decoding and prediction bands.
//!
//! Everything here reads a carrier and never writes one. The recorder is the
//! single pass both embedding and extraction rely on, which is why the capture
//! level (counts, bits, full slots) is an explicit parameter instead of three
//! near-identical walkers.

use sha2::{Digest, Sha256};

use crate::core::control::Control;
use crate::errors::StrHideError;
use crate::stego::format::HevcFormatProfile;
use crate::stego::hevc::bitstream::compute_hevc_cover_digest;
use crate::stego::hevc::slot::{BinOp, CabacRecorder, RecordMode, StegoSlot, SubstreamRecord};
use crate::stego::hevc::sniff::{
    HevcCarrierKind, NAL_RADL_N, NAL_RASL_N, NAL_RASL_R, NAL_STSA_N, NAL_TRAIL_N, NAL_TSA_N,
    sniff_hevc_carrier,
};
use rusty_h265::Decoder;
use rusty_h265::ctu::Ablate;

use super::record::record_carrier_state;
use super::support::{StopCondition, nal_header_fields, nal_rbsp};

/// One source slice: where it sits, its prediction band and its journal.
/// Helper struct for slice recording and span tracking.
#[derive(Clone)]
pub(crate) struct SliceContext {
    pub(crate) carrier_span: std::ops::Range<usize>,
    pub(crate) nal_type: u8,
    pub(crate) layer_id: u8,
    pub(crate) temporal_id: u8,
    #[allow(dead_code)]
    pub(crate) band: u8,
    pub(crate) orig_rbsp: Vec<u8>,
    pub(crate) ops: Vec<BinOp>,
    pub(crate) substreams: Vec<SubstreamRecord>,
}

/// How much of every recorded slot `record_carrier_state` keeps.
///
/// Every pass used to build the full 32-byte [`StegoSlot`] pool even when it
/// only needed a count. A 24-minute 1080p carrier has 5.7e8 slots, i.e. 18 GB
/// (34 GB once `Vec` doubles to the next power of two) for data a capacity probe
/// never reads. The capture level is what keeps a probe at a few counters and an
/// extract at one bit per slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Capture {
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
pub(crate) struct CarrierRecord {
    pub(crate) slice_contexts: Vec<SliceContext>,
    /// Slot pool in stream recording order.
    /// Populated by [`Capture::Full`] only.
    pub(crate) all_slots: Vec<StegoSlot>,
    /// Sign bit of every slot, packed LSB-first, one vector per band in
    /// recording order.
    pub(crate) band_bits: [Vec<u8>; 2],
    /// Pool ranges of each band, in consumption order.
    pub(crate) bands: Vec<std::ops::Range<usize>>,
    /// Pictures in the carrier (all VCL, including excluded IRAPs).
    pub(crate) pictures: usize,
    /// Pictures that may carry slots, per band.
    pub(crate) band_pictures: [usize; 2],
    pub(crate) digest_inputs: DigestInputs,
    /// Total slices recorded in this window pass.
    pub(crate) recorded_slices: usize,
    /// Sign bit of every recorded slot in stream order.
    pub(crate) raw_bits: Vec<u8>,
    /// (slot_count, band) for each recorded slice.
    pub(crate) slice_slot_ranges: Vec<(usize, u8)>,
    /// Whole-carrier slot counts per band when the recording pass continued
    /// counting after the write window stopped (`record_carrier_state_with_capacity`).
    /// `None` means `bands` only covers the write window.
    pub(crate) capacity_band_counts: Option<[usize; 2]>,
}

impl CarrierRecord {
    /// Size of the slot pool. Valid for every capture level.
    pub(crate) fn total_slots(&self) -> usize {
        self.bands.iter().map(|range| range.len()).sum()
    }

    /// Sign bit at pool position `index`, where the pool is band 0 followed by
    /// band 1. Valid for [`Capture::Bits`].
    #[cfg(test)]
    pub(crate) fn slot_bit(&self, index: usize) -> u8 {
        let band = usize::from(index >= self.bands[0].len());
        let range = &self.bands[band];
        debug_assert!(range.contains(&index));
        bit_at(&self.band_bits[band], index.saturating_sub(range.start))
    }

    /// Sign bit at stream position `index`. Valid for [`Capture::Bits`].
    pub(crate) fn raw_slot_bit(&self, index: usize) -> u8 {
        bit_at(&self.raw_bits, index)
    }
}

/// Read bit `index` out of an LSB-first packed vector.
#[inline]
pub(super) fn bit_at(bits: &[u8], index: usize) -> u8 {
    bits.get(index / 8)
        .map_or(0, |byte| (byte >> (index % 8)) & 1)
}

/// Append-only LSB-first bit vector. One sign bit per slot instead of 32 bytes.
#[derive(Default)]
pub(super) struct BitPacker {
    pub(super) bytes: Vec<u8>,
    pub(super) len: usize,
}

impl BitPacker {
    #[inline]
    pub(super) fn push(&mut self, bit: u8) {
        if self.len.is_multiple_of(8) {
            self.bytes.push(0);
        }
        if bit & 1 != 0 {
            let last = self.bytes.len() - 1;
            self.bytes[last] |= 1 << (self.len % 8);
        }
        self.len += 1;
    }

    pub(super) fn truncate(&mut self, new_len: usize) {
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

    pub(super) fn extend(&mut self, other: &BitPacker) {
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
pub(super) struct SlotSink {
    pub(super) capture: Capture,
    /// Slots that entered the pool, per band.
    pub(super) counts: [usize; 2],
    pub(super) band_bits: [BitPacker; 2],
    pub(super) raw_bits: BitPacker,
    pub(super) raw_slots: Vec<StegoSlot>,
    pub(super) slice_slot_ranges: Vec<(usize, u8)>,
}

impl SlotSink {
    pub(super) fn new(capture: Capture) -> Self {
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
    pub(super) fn push(&mut self, slot: StegoSlot, band: usize) {
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
    pub(crate) total_slots: usize,
    pub(crate) band_slots: [usize; 2],
    pub(crate) band_pictures: [usize; 2],
    pub(crate) pictures: usize,
    pub(crate) is_estimated: bool,
}

impl PoolProfile {
    pub(crate) fn from_record(record: &CarrierRecord) -> Self {
        if let Some(band_slots) = record.capacity_band_counts {
            return PoolProfile {
                total_slots: band_slots[0] + band_slots[1],
                band_slots,
                band_pictures: record.band_pictures,
                pictures: record.pictures,
                is_estimated: false,
            };
        }
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
pub(crate) enum DigestInputs {
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
pub(super) struct CandidateSlice {
    /// File byte range of the NAL (header included, length prefix or start
    /// code excluded) -- the exact range the re-encoder writes back.
    pub(super) span: std::ops::Range<usize>,
    pub(super) nal_type: u8,
    pub(super) layer_id: u8,
    pub(super) temporal_id: u8,
}

pub(super) struct GopSliceRecord {
    pub(super) recorded_slices: usize,
    pub(super) sink: SlotSink,
    pub(super) slice_contexts: Vec<SliceContext>,
    pub(super) decode_error: Option<String>,
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

    pub(super) fn truncate_to_slices(&mut self, kept_slices: usize) {
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

pub(super) fn find_gop_ranges(
    carrier: &[u8],
    candidates: &[CandidateSlice],
) -> Vec<std::ops::Range<usize>> {
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

pub(super) fn estimate_gops_for_slices(
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

/// Decode one GOP, stopping after `slot_budget` recorded slots when given.
///
/// The budget is the batch's remaining target: a GOP that reaches it on its own
/// has already supplied everything the window needs, and the merge truncates to
/// the exact slice anyway. Stopping here instead of decoding the GOP out turns
/// the embed's transient footprint from "every slice of the batch" into "the
/// slices that survive truncation" — the difference between decoding 1200
/// frames and 1 for a 4 KiB payload.
pub(super) fn decode_gop_slice_range(
    carrier: &[u8],
    candidates: &[CandidateSlice],
    parameter_sets: &[&[u8]],
    has_inter: bool,
    mode: RecordMode,
    capture: Capture,
    slot_budget: Option<usize>,
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
                // A slice that decoded only part-way has its slots discarded
                // inside `absorb_recorder`; it must not advance the slice
                // counter either, or later slots point at the wrong context.
                if absorb_recorder(&mut recorder, &rbsp, &mut record.sink) {
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
                if let Some(budget) = slot_budget
                    && record.sink.counts[0] + record.sink.counts[1] >= budget
                {
                    break;
                }
            }
        }
    }

    record.decode_error = decode_error;
    Ok(record)
}

pub(super) fn merge_gop_record(
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

/// Parameter sets that are active at a GOP's first slice.
///
/// Container carriers (`hvcC`) declare every set up front (`ends = None`). An
/// Annex-B stream may redefine SPS/PPS mid-file, so a GOP may only see the sets
/// that physically precede it. Feeding the whole file's sets to every GOP made
/// the last definition of `sps/pps id 0` overwrite the earlier ones, decoding
/// early GOPs with the wrong geometry.
pub(super) fn active_parameter_sets<'a>(
    sets: &'a [Vec<u8>],
    ends: Option<&[usize]>,
    gop_start_byte: usize,
) -> Vec<&'a [u8]> {
    match ends {
        None => sets.iter().map(Vec::as_slice).collect(),
        Some(ends) => sets
            .iter()
            .zip(ends)
            .filter(|(_, end)| **end <= gop_start_byte)
            .map(|(ps, _)| ps.as_slice())
            .collect(),
    }
}
pub(super) fn owned_parameter_sets(parameter_sets: &[&[u8]]) -> Vec<Vec<u8>> {
    parameter_sets.iter().map(|ps| ps.to_vec()).collect()
}

/// Wrap one candidate span, reading its NAL header fields (H.265 7.3.1.2).
///
/// Returns `None` for a span too short to hold a header, for a set
/// `forbidden_zero_bit`, or for `temporal_id_plus1 == 0` (invalid per spec and
/// the same rule the Annex-B parser applies).
pub(super) fn candidate_slice(
    carrier: &[u8],
    span: std::ops::Range<usize>,
) -> Option<CandidateSlice> {
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
pub(super) fn is_non_reference_vcl(nal_type: u8) -> bool {
    matches!(
        nal_type,
        NAL_TRAIL_N | NAL_TSA_N | NAL_STSA_N | NAL_RADL_N | NAL_RASL_N
    )
}

/// IRAP (intra random access point) VCL types: BLA/IDR/CRA, H.265 Table 7-1.
///
/// These are the prediction roots of a GOP. A flip in one of them is seen by
/// every picture that follows until the next IRAP, which is why they are the
/// one class the ladder never spends (avoiding severe quality degradation).
pub(super) fn is_irap(nal_type: u8) -> bool {
    (16..=23).contains(&nal_type)
}

/// Drift-free band: pictures nothing predicts from.
pub(super) const BAND_NON_REFERENCE: u8 = 0;
/// Reference band: pictures later pictures predict from until the next IRAP.
pub(super) const BAND_REFERENCE: u8 = 1;

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
pub(super) fn picture_band(nal_type: u8, has_inter: bool) -> Option<u8> {
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
pub(super) fn count_pictures(
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
pub(super) fn starts_picture(nal: &[u8]) -> bool {
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
pub(super) fn drain_frames(decoder: &mut Decoder) {
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
pub(super) fn absorb_recorder(
    recorder: &mut CabacRecorder,
    rbsp: &[u8],
    sink: &mut SlotSink,
) -> bool {
    if recorder.next_pending_slot() != recorder.slots.len() {
        // Slice decoding was truncated mid-slice before every sign got its
        // level back-fill. Discard all incomplete slots from this slice so
        // desynced slots never enter the pool. The check runs in every record
        // mode: embed used to drop the slice while extract (slot-only mode)
        // kept its slots, which shifted every later global slot index.
        recorder.slots.clear();
        recorder.reset_pending();
        return false;
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
        return true;
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
    true
}

pub(super) fn scan_hevc_slot_count(carrier: &[u8]) -> Result<usize, StrHideError> {
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

/// Derive the cover digest from the container parse `record_carrier_state`
/// already produced — the container is walked exactly once per operation
/// (audit 2026-10-24 2.5).
pub(super) fn derive_carrier_digest(
    carrier: &[u8],
    inputs: &DigestInputs,
    fmt: &HevcFormatProfile,
) -> [u8; 32] {
    // V4 pre_salt domain separation: only immutable metadata may enter, and
    // the label keeps HEVC salts distinct from JPEG/PNG ones even if the same
    // cover bytes are reused.
    let mut salt = Vec::with_capacity(fmt.cover_salt.len() + 8);
    salt.extend_from_slice(fmt.cover_salt);
    salt.extend_from_slice(b"hevc-v4");
    match inputs {
        DigestInputs::ParameterSets { parameter_sets } => {
            // Hash the parameter set *contents*. They are immutable during
            // embedding, which is what makes the digest — and therefore the
            // L1/L2/L3 keys and every keyed slot plan — identical on both ends.
            //
            // (Feeding them through `compute_hevc_cover_digest` would need
            // byte offsets into `carrier`; the parsed sets are copies, and
            // an offset of 0 quietly hashed the file header instead.)
            let mut hasher = Sha256::new();
            hasher.update(&salt);
            hasher.update((parameter_sets.len() as u64).to_be_bytes());
            for ps in parameter_sets {
                hasher.update((ps.len() as u64).to_be_bytes());
                hasher.update(ps);
            }
            hasher.finalize().into()
        }
        DigestInputs::AnnexB { spans } => compute_hevc_cover_digest(carrier, spans, &salt),
    }
}
