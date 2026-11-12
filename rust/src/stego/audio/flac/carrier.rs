//! FLAC carrier and slot mutation abstractions for strhide steganography.

use crate::errors::StrHideError;
use crate::stego::audio::core::SlotCarrier;
use crate::stego::audio::cost::{CostParams, PcmScale};
use crate::stego::coding::Move;
use crate::stego::header::PNG_AUDIO_BASE_SLOTS;

use super::bits::{self, BitWriter};
use super::frame::{self, ParsedFrame};
use super::md5::Md5;
use super::{COST_WINDOW, DRIFT_BUDGET, FlacAnalysis, MD5_OFFSET, StreamInfo, analyse};

/// One addressable residual.
#[derive(Debug, Clone)]
pub(crate) struct FlacSlot {
    /// Absolute bit offset of the codeword's first bit (`u64` to prevent overflow on large audio files).
    pub(crate) bit_offset: u64,
    /// Rice parameter of its partition.
    k: u8,
    /// Current residual value.
    value: i32,
    /// Perceptual cost of moving it by one.
    cost: f32,
    /// The chain of residuals that cancel the move's effect on the predictor,
    /// one per predictor tap. Empty for FIXED order 0, where a residual *is*
    /// the sample.
    pub(crate) comp: Vec<CompSlot>,
}

/// One link of that chain.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CompSlot {
    pub(crate) bit_offset: u64,
    k: u8,
    value: i32,
    /// Rice-coded rather than escape-coded.
    rice: bool,
    /// Delta to apply when the data slot moves `+1`.
    plus: i32,
    /// Delta to apply when it moves `-1`.
    minus: i32,
}

impl CompSlot {
    /// Whether `delta` can be written into this codeword without changing its
    /// width. A zero delta writes nothing, so it is always available.
    fn accepts(&self, delta: i32) -> bool {
        frame::comp_accepts(self.k as u32, self.value as i64, self.rice, delta)
    }
}

/// A subframe tail retained from the validating scan.
///
/// Tails carry no compensation chain, so one is a fixed handful of bytes rather
/// than a heap allocation, and there is exactly one per subframe. Keeping the
/// whole pool is therefore cheap and lets the header picks be selected once the
/// walk has revealed the thinning denominator.
pub(crate) struct FlacTail {
    pub(crate) bit_offset: u64,
    pub(crate) k: u8,
    pub(crate) value: i32,
    pub(crate) cost: f32,
}

impl FlacTail {
    fn to_slot(&self) -> FlacSlot {
        FlacSlot {
            bit_offset: self.bit_offset,
            k: self.k,
            value: self.value,
            cost: self.cost,
            comp: Vec::new(),
        }
    }
}

/// A FLAC carrier presented as an array of already-selected residual slots.
///
/// Unlike the WAV carrier, the slot array is materialised: the trellis
/// addresses slots by plan position, and the engine hands over exactly the
/// ones the keyed thinning chose. The `SlotMap` for this carrier is therefore
/// the identity.
pub(crate) struct FlacCarrier<'a> {
    bytes: &'a mut [u8],
    info: StreamInfo,
    pub(crate) slots: Vec<FlacSlot>,
    modified: usize,
    /// Total residuals written to the stream (data slots + non-zero compensation taps).
    residuals_written: usize,
    /// Of the structural pool, how many can move in at least one direction.
    /// Reporting only -- selection never reads it (`analysis.slots` is the
    /// cross-end denominator).
    total_usable: usize,
    /// Finalized PCM MD5 computed during refresh_checksums.
    pcm_md5: Option<[u8; 16]>,
    /// Cover bytes, when the decoded-waveform drift is measured during
    /// finalize instead of by a second decode of both files afterwards.
    cover: Option<&'a [u8]>,
    /// Largest per-sample difference from the cover, in stored sample units.
    drift: i64,
}

impl FlacCarrier<'_> {
    pub(crate) const MIN_GROUP: u8 = 3;

    /// Total residuals actually modified in the carrier (data moves plus compensation writes).
    #[allow(dead_code)]
    pub(crate) fn residuals_written(&self) -> usize {
        self.residuals_written
    }

    /// Largest per-sample difference from the cover measured during the
    /// finalize pass; zero when no cover was tracked.
    pub(crate) fn pcm_max_drift(&self) -> i64 {
        self.drift
    }
}

impl<'a> FlacCarrier<'a> {
    /// Compare the decoded waveform against `cover` during the next finalize.
    ///
    /// The finalize pass already decodes the patched file to recompute the
    /// `STREAMINFO` MD5, so measuring the drift there costs one cover decode
    /// instead of a second decode of both files.
    pub(crate) fn track_drift(&mut self, cover: &'a [u8]) {
        self.cover = Some(cover);
    }

    /// Fail-closed: refuse a carrier this build cannot decode exactly.
    fn ensure_decodable(info: &StreamInfo, analysis: &FlacAnalysis) -> Result<(), StrHideError> {
        if info.md5 != [0u8; 16] && analysis.pcm_md5 != info.md5 {
            return Err(StrHideError::UnsupportedFormat(
                "FLAC carrier could not be fully validated (decoded PCM does not match the \
                 STREAMINFO MD5); refusing to modify a file this build cannot decode exactly"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Both pools must be large enough for the header and the requested body.
    fn ensure_pools(
        analysis: &FlacAnalysis,
        body_slots: usize,
        header_slots: usize,
    ) -> Result<(), StrHideError> {
        // Two disjoint pools, both derived from structural predicates plus the
        // bucket tests a legal move preserves:
        //   * subframe tails -- the last residual of every subframe -- need no
        //     compensation, so they are always writable; the fixed 512-slot
        //     header lives here because a header bit has nowhere to go if its
        //     slot cannot be moved;
        //   * everything else feeds the body, where the trellis can route
        //     around a slot whose compensation chain does not fit.
        //
        // The body's denominator is `analysis.slots` (invariant across embedding) rather
        // than `usable`, ensuring encoder and decoder address the identical codeword pool.
        if header_slots < PNG_AUDIO_BASE_SLOTS {
            return Err(StrHideError::General(format!(
                "FLAC header area must be at least {PNG_AUDIO_BASE_SLOTS} slots, got {header_slots}"
            )));
        }
        if analysis.tails < header_slots {
            return Err(StrHideError::General(format!(
                concat!(
                    "FLAC carrier has {tails} usable subframe tails but the ",
                    "{header}-slot header needs that many; ",
                    "the file is too short for this carrier"
                ),
                tails = analysis.tails,
                header = header_slots
            )));
        }
        if analysis.slots < body_slots {
            return Err(StrHideError::General(format!(
                "FLAC carrier has {} residual slots, {body_slots} required",
                analysis.slots
            )));
        }
        Ok(())
    }

    /// Materialise a carrier that exposes only the header area (base + extension
    /// picks, no body).
    ///
    /// The extraction side reads the base header before it knows `ext_len`, so
    /// its first view needs nothing but the tail pool. When the validating scan
    /// already retained that pool (`analyse_with_tails`), this constructor
    /// selects the picks without walking the file a second time. The resulting
    /// slot array is exactly what [`FlacCarrier::new`] would have built for
    /// `body_slots = 0`.
    pub(crate) fn header_view(
        bytes: &'a mut [u8],
        info: StreamInfo,
        analysis: &FlacAnalysis,
        tails: &[FlacTail],
        header_slots: usize,
        header_phase: u64,
        ext_phase: u64,
    ) -> Result<Self, StrHideError> {
        Self::ensure_decodable(&info, analysis)?;
        Self::ensure_pools(analysis, 0, header_slots)?;
        if tails.len() != analysis.tails {
            return Err(StrHideError::General(format!(
                "FLAC tail pool has {} entries, the analysis counted {}",
                tails.len(),
                analysis.tails
            )));
        }
        let ext_slots = header_slots - PNG_AUDIO_BASE_SLOTS;
        let (mut header_picks, ext_picks) =
            pick_tails(tails, header_slots, header_phase, ext_phase);
        if header_picks.len() != PNG_AUDIO_BASE_SLOTS || ext_picks.len() != ext_slots {
            return Err(StrHideError::General(format!(
                "FLAC slot selection produced {} base and {} extension slots, expected {} and {}",
                header_picks.len(),
                ext_picks.len(),
                PNG_AUDIO_BASE_SLOTS,
                ext_slots
            )));
        }
        header_picks.extend(ext_picks);
        Ok(Self {
            bytes,
            info,
            slots: header_picks,
            modified: 0,
            residuals_written: 0,
            total_usable: analysis.usable,
            pcm_md5: None,
            cover: None,
            drift: 0,
        })
    }

    /// Materialise the carrier's slot array.
    ///
    /// `body_slots` is the number of trellis slots the payload needs; both ends
    /// derive it (the writer from the payload, the reader from the envelope
    /// length in the header). Header and body picks are disjoint by
    /// construction: the body thinning runs over the eligible stream *minus*
    /// the header's picks, so the two never address the same codeword.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        bytes: &'a mut [u8],
        info: StreamInfo,
        analysis: &FlacAnalysis,
        body_slots: usize,
        header_slots: usize,
        header_phase: u64,
        ext_phase: u64,
        body_phase: u64,
    ) -> Result<Self, StrHideError> {
        let scale = info.scale();
        let defaults = info.defaults();
        Self::ensure_decodable(&info, analysis)?;
        Self::ensure_pools(analysis, body_slots, header_slots)?;
        let total = analysis.slots;
        let total_usable = analysis.usable;
        let tail_total = analysis.tails;
        let ext_slots = header_slots - PNG_AUDIO_BASE_SLOTS;

        // Pass 2: collect the tail pool and the body picks in one sweep.
        //
        // The base 512 picks are thinned over *all* tails, so their denominator
        // is only known when the sweep is over; retaining the (small) tail pool
        // is what lets `pick_tails` apply the same rules afterwards. Body picks
        // need `total`, which came from the validating pass, so they can be
        // decided inline. The base count stays fixed at 512: a variable
        // `wanted` would shift every base index as soon as an extension was
        // present, and the extraction pass that reads the base header (before
        // it knows `ext_len`) would address the wrong slots.
        let mut tail_pool: Vec<FlacTail> = Vec::with_capacity(tail_total);
        let mut body_picks: Vec<FlacSlot> = Vec::with_capacity(body_slots);
        let mut body_seen = 0usize;
        let mut pos = info.audio_offset;
        let mut samples_decoded = 0u64;

        while pos < bytes.len() && bytes[pos] != 0 {
            if info.total_samples > 0 && samples_decoded >= info.total_samples {
                break;
            }
            let parsed = frame::parse_frame(bytes, pos, &defaults).map_err(|_| {
                StrHideError::CorruptedData(format!(
                    "FLAC frame at byte {pos} could not be decoded"
                ))
            })?;
            let frame_samples = parsed.samples.first().map_or(0, Vec::len) as u64;
            samples_decoded += frame_samples;
            for slot in parsed.tails.iter() {
                tail_pool.push(FlacTail {
                    bit_offset: slot.bit_offset as u64,
                    k: slot.k as u8,
                    value: slot.value as i32,
                    cost: slot_cost(&parsed, slot, &scale),
                });
            }
            if body_slots > 0 {
                for slot in parsed.slots.iter() {
                    // Membership is structural: every residual with a full
                    // compensation chain is in the pool, movable or not. A
                    // residual that cannot move today keeps its parity and the
                    // trellis routes around it (`move_legality` reports
                    // `Move::None`); dropping it here would renumber every
                    // following plan slot differently on the two ends.
                    let index = body_seen;
                    body_seen += 1;
                    if thin_pick(index, total, body_slots, body_phase)
                        && let Some(entry) = make_slot(slot, &parsed, &scale)
                    {
                        body_picks.push(entry);
                    }
                }
            }
            pos = parsed.crc16_offset + 2;
        }

        let (mut header_picks, ext_picks) =
            pick_tails(&tail_pool, header_slots, header_phase, ext_phase);

        if header_picks.len() != PNG_AUDIO_BASE_SLOTS
            || ext_picks.len() != ext_slots
            || body_picks.len() != body_slots
        {
            return Err(StrHideError::General(format!(
                "FLAC slot selection produced {} base, {} extension and {} body slots, expected {} and {} and {}",
                header_picks.len(),
                ext_picks.len(),
                body_picks.len(),
                PNG_AUDIO_BASE_SLOTS,
                ext_slots,
                body_slots
            )));
        }

        log::debug!(
            target: "stego::audio::flac",
            "flac-stats: eligible={} usable={} stuck_rate={:.3} tails={}",
            total,
            analysis.usable,
            1.0 - analysis.usable as f64 / total.max(1) as f64,
            tail_total
        );
        // The plan addresses base header, extension, then body.
        header_picks.extend(ext_picks);
        header_picks.extend(body_picks);
        let slots = header_picks;

        Ok(Self {
            bytes,
            info,
            slots,
            modified: 0,
            residuals_written: 0,
            total_usable,
            pcm_md5: None,
            cover: None,
            drift: 0,
        })
    }

    /// Recompute every frame checksum that covers a changed codeword, then the
    /// `STREAMINFO` MD5, both from a fresh decode of the patched file.
    fn refresh_checksums(&mut self) -> Result<(), StrHideError> {
        let defaults = self.info.defaults();
        let mut hasher = Md5::new();
        let mut pos = self.info.audio_offset;
        let mut samples_decoded = 0u64;
        // The drift gate compares the decoded waveform against the cover. This
        // pass already decodes the patched file, so comparing frame by frame
        // here saves decoding the stego file a second time.
        let cover = self.cover;
        let mut cover_pos = self.info.audio_offset;
        let mut drift = 0i64;
        // Slots were collected in file order for each half, so sort a copy of
        // the offsets once: the frame walk then advances a single cursor.
        let mut offsets: Vec<u64> = self
            .slots
            .iter()
            .flat_map(|s| std::iter::once(s.bit_offset).chain(s.comp.iter().map(|c| c.bit_offset)))
            .collect();
        offsets.sort_unstable();
        let mut cursor = 0usize;

        while pos < self.bytes.len() && self.bytes[pos] != 0 {
            if self.info.total_samples > 0 && samples_decoded >= self.info.total_samples {
                break;
            }
            // Trusted parse: this frame's own checksum is stale until the line
            // below rewrites it.
            let parsed = frame::parse_frame_trusted(self.bytes, pos, &defaults).map_err(|_| {
                StrHideError::CorruptedData(format!(
                    "FLAC frame at byte {pos} could not be re-decoded after patching"
                ))
            })?;
            let frame_samples = parsed.samples.first().map_or(0, Vec::len) as u64;
            samples_decoded += frame_samples;
            hasher.absorb(&parsed.samples, self.info.md5_bytes_per_sample());
            if let Some(cover_bytes) = cover
                && self.residuals_written > 0
            {
                let original = frame::parse_frame(cover_bytes, cover_pos, &defaults).map_err(|_| {
                    StrHideError::CorruptedData(format!(
                        "FLAC cover frame at byte {cover_pos} could not be decoded while measuring drift"
                    ))
                })?;
                cover_pos = original.crc16_offset + 2;
                drift = drift.max(decoded_drift_units(&original, &parsed)?);
            }

            let frame_start_bit = parsed.start * 8;
            let frame_end_bit = (parsed.crc16_offset + 2) * 8;
            let mut touched = false;
            while cursor < offsets.len() {
                let bit = offsets[cursor];
                if bit >= frame_end_bit as u64 {
                    break;
                }
                if bit >= frame_start_bit as u64 {
                    touched = true;
                }
                cursor += 1;
            }
            if touched {
                let computed = frame::crc16(&self.bytes[parsed.start..parsed.crc16_offset]);
                let at = parsed.crc16_offset;
                self.bytes[at..at + 2].copy_from_slice(&computed.to_be_bytes());
            }
            pos = parsed.crc16_offset + 2;
        }

        let md5 = hasher.finish();
        self.pcm_md5 = Some(md5);
        self.drift = drift;
        if MD5_OFFSET + 16 <= self.bytes.len() {
            self.bytes[MD5_OFFSET..MD5_OFFSET + 16].copy_from_slice(&md5);
        }

        // Re-decode the patched file with frame CRC verification enabled and
        // compare the PCM digest. The pass above wrote those CRCs and this MD5
        // from samples it decoded with `verify_crc = false`, so on its own it
        // can only agree with itself: if a patch desynchronised the frame walk,
        // the wrong samples and their self-consistent checksums both ship. Only
        // this checked re-decode can tell the difference, so it runs in release
        // builds too -- one extra decode is cheaper than a carrier that decodes
        // to different audio than its STREAMINFO claims.
        {
            let recheck = analyse(self.bytes, &self.info)?;
            if recheck.pcm_md5 != md5 {
                return Err(StrHideError::General(
                    "FLAC PCM checksum changed between passes; refusing to emit the carrier".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Which directions a materialised slot can move in.
#[inline]
fn slot_legality(slot: &FlacSlot) -> Move {
    let k = slot.k as u32;
    let bucket = frame::fold(slot.value as i64) >> k;
    let own_plus = k >= 1 && (frame::fold(slot.value as i64 + 1) >> k) == bucket;
    let own_minus = k >= 1 && (frame::fold(slot.value as i64 - 1) >> k) == bucket;
    combine(
        own_plus && slot.comp.iter().all(|c| c.accepts(c.plus)),
        own_minus && slot.comp.iter().all(|c| c.accepts(c.minus)),
    )
}

/// Same test straight off a parsed slot, for the capacity pass.
#[inline]
pub(super) fn slot_legality_raw(slot: &frame::ResidualSlot, parsed: &ParsedFrame) -> Move {
    let start = slot.comp_start as usize;
    let end = start.saturating_add(slot.comp_len as usize);
    let chain = parsed.comps.get(start..end).unwrap_or(&[]);
    let k = slot.k;
    let bucket = frame::fold(slot.value) >> k;
    let own_plus = k >= 1 && (frame::fold(slot.value + 1) >> k) == bucket;
    let own_minus = k >= 1 && (frame::fold(slot.value - 1) >> k) == bucket;
    combine(
        own_plus && chain.iter().all(|c| c.accepts(c.plus)),
        own_minus && chain.iter().all(|c| c.accepts(c.minus)),
    )
}

#[inline]
fn combine(plus: bool, minus: bool) -> Move {
    match (plus, minus) {
        (true, true) => Move::Both,
        (true, false) => Move::PlusOnly,
        (false, true) => Move::MinusOnly,
        (false, false) => Move::None,
    }
}

/// Even thinning: pick `wanted` of `range` items, offset by a keyed phase.
///
/// `floor(((i + 1) * wanted + phase) / range)` increments exactly `wanted`
/// times over `i in 0..range`, so the pick count is exact for any phase and the
/// selection is reproducible from `(range, wanted, phase)` alone.
#[inline]
fn thin_pick(index: usize, range: usize, wanted: usize, phase: u64) -> bool {
    if wanted == 0 || range == 0 {
        return false;
    }
    let phase = phase % range as u64;
    let before = ((index as u128 * wanted as u128) + phase as u128) / range as u128;
    let after = (((index + 1) as u128 * wanted as u128) + phase as u128) / range as u128;
    after != before
}

/// Select the base and extension header picks from a retained tail pool.
///
/// Base picks are thinned over the whole pool; extension picks are thinned
/// independently over the tails the base pass left behind. Both keep the pool's
/// file order, which is what the plan layout expects.
fn pick_tails(
    tails: &[FlacTail],
    header_slots: usize,
    header_phase: u64,
    ext_phase: u64,
) -> (Vec<FlacSlot>, Vec<FlacSlot>) {
    let tail_total = tails.len();
    let ext_slots = header_slots.saturating_sub(PNG_AUDIO_BASE_SLOTS);
    let mut base_picks: Vec<FlacSlot> = Vec::with_capacity(PNG_AUDIO_BASE_SLOTS);
    let mut ext_picks: Vec<FlacSlot> = Vec::with_capacity(ext_slots);
    let mut nonbase_seen = 0usize;
    for (index, tail) in tails.iter().enumerate() {
        if thin_pick(index, tail_total, PNG_AUDIO_BASE_SLOTS, header_phase) {
            if base_picks.len() < PNG_AUDIO_BASE_SLOTS {
                base_picks.push(tail.to_slot());
            }
        } else {
            if ext_slots > 0
                && thin_pick(
                    nonbase_seen,
                    tail_total.saturating_sub(PNG_AUDIO_BASE_SLOTS),
                    ext_slots,
                    ext_phase,
                )
            {
                ext_picks.push(tail.to_slot());
            }
            nonbase_seen += 1;
        }
    }
    (base_picks, ext_picks)
}

impl SlotCarrier for FlacCarrier<'_> {
    fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Capacity stays priced on the *movable* count: a report must not promise
    /// payloads the trellis cannot encode. The plan itself thins over the
    /// structural pool, so the two numbers serve different purposes and neither
    /// one feeds slot selection.
    fn capacity_slots(&self) -> usize {
        self.total_usable + PNG_AUDIO_BASE_SLOTS
    }

    fn min_group(&self) -> u8 {
        3
    }

    fn slot_value(&self, index: usize) -> i32 {
        self.slots.get(index).map_or(0, |s| s.value)
    }

    fn move_legality(&self, index: usize) -> Move {
        // A direction is only usable when the slot itself stays in its bucket
        // *and* every compensating codeword can absorb its share. The chain is
        // why an otherwise movable slot can still be stuck: the waveform would
        // be left with an uncompensated step, which is far more audible than
        // the single-sample flip the payload asked for. `Move::None` keeps such
        // a slot in the plan -- dropping it would renumber every following plan
        // slot, and the extractor derives the plan from the stego file.
        self.slots.get(index).map_or(Move::None, slot_legality)
    }

    fn cost(&self, index: usize, _params: &CostParams) -> f64 {
        self.slots
            .get(index)
            .map_or(f64::MAX / 4.0, |s| s.cost as f64)
    }

    fn apply(&mut self, index: usize, delta: i8) -> Result<(), StrHideError> {
        if delta == 0 {
            return Ok(());
        }
        let slot = self
            .slots
            .get(index)
            .cloned()
            .ok_or_else(|| StrHideError::General("FLAC slot index out of range".into()))?;
        let moved = slot.value as i64 + delta as i64;
        if !(i32::MIN as i64..=i32::MAX as i64).contains(&moved) {
            return Err(StrHideError::General(
                "FLAC residual move overflowed i32".into(),
            ));
        }
        // The recorded value must match the stream: a stale offset or a stale
        // value would write into the middle of a neighbouring codeword and
        // desynchronise the frame.
        let k = slot.k as u32;
        let actual = read_codeword(self.bytes, slot.bit_offset as usize, k);
        if actual != Some(slot.value) {
            return Err(StrHideError::General(format!(
                "FLAC slot {} disagrees with the stream at bit {} (recorded {}, read {actual:?}, k={k})",
                index, slot.bit_offset, slot.value
            )));
        }
        write_remainder(
            self.bytes,
            slot.bit_offset as usize,
            k,
            slot.value as i64,
            moved,
        )?;

        // Cancel the predictor's reaction at every tap it reaches, so the
        // waveform is untouched after the slot's own sample.
        let mut written = Vec::with_capacity(slot.comp.len());
        for comp in &slot.comp {
            let shift = if delta > 0 { comp.plus } else { comp.minus };
            let target = comp.value as i64 + shift as i64;
            if !comp.accepts(shift) {
                return Err(StrHideError::General(format!(
                    "FLAC compensation at bit {} cannot absorb {shift}",
                    comp.bit_offset
                )));
            }
            if shift != 0 {
                write_remainder(
                    self.bytes,
                    comp.bit_offset as usize,
                    comp.k as u32,
                    comp.value as i64,
                    target,
                )?;
                self.residuals_written += 1;
            }
            written.push((comp.bit_offset, target as i32));
        }

        if let Some(entry) = self.slots.get_mut(index) {
            entry.value = moved as i32;
            for (offset, value) in written {
                if let Some(comp) = entry.comp.iter_mut().find(|c| c.bit_offset == offset) {
                    comp.value = value;
                }
            }
            self.modified += 1;
            self.residuals_written += 1;
        }

        Ok(())
    }

    fn finalize(&mut self) -> Result<(), StrHideError> {
        self.refresh_checksums()
    }

    fn modified_slots(&self) -> usize {
        self.residuals_written
    }

    fn format_label(&self) -> &'static str {
        "FLAC"
    }

    fn describe(&self) -> Option<String> {
        Some(format!(
            "{}-bit FLAC, {} channel(s), {} Hz, {} samples",
            self.info.bits_per_sample,
            self.info.channels,
            self.info.sample_rate,
            self.info.total_samples
        ))
    }
}

/// Lightweight, zero-copy, zero-residual-decode carrier view strictly for capacity probing.
pub(crate) struct FlacCapacityView {
    pub(crate) total_usable: usize,
    pub(crate) header_total: usize,
}

impl SlotCarrier for FlacCapacityView {
    fn slot_count(&self) -> usize {
        0
    }

    fn capacity_slots(&self) -> usize {
        self.total_usable + PNG_AUDIO_BASE_SLOTS
    }

    fn header_capacity(&self) -> usize {
        self.header_total
    }

    fn format_label(&self) -> &'static str {
        "FLAC"
    }

    fn min_group(&self) -> u8 {
        FlacCarrier::MIN_GROUP
    }

    fn cost(&self, _slot: usize, _params: &CostParams) -> f64 {
        1.0
    }

    fn move_legality(&self, _index: usize) -> Move {
        Move::None
    }

    fn slot_value(&self, _slot: usize) -> i32 {
        0
    }

    fn apply(&mut self, _slot: usize, _delta: i8) -> Result<(), StrHideError> {
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), StrHideError> {
        Ok(())
    }

    fn modified_slots(&self) -> usize {
        0
    }
}

/// Decode the residual stored at `bit_offset` with Rice parameter `k`.
fn read_codeword(bytes: &[u8], bit_offset: usize, k: u32) -> Option<i32> {
    let mut reader = bits::BitReader::new(bytes, bit_offset);
    let quotient = reader.unary().ok()?;
    let remainder = reader.read(k).ok()? as u64;
    let folded = ((quotient as u64) << k) | remainder;
    let value = if folded & 1 == 0 {
        (folded >> 1) as i64
    } else {
        -((folded >> 1) as i64) - 1
    };
    Some(value as i32)
}

/// Turn a parsed slot into a carrier slot.
///
/// The compensation chain is copied out of the frame's pool: the pool is freed
/// with the frame, and the trellis keeps slots alive long after `analyse` has
/// walked past it.
pub(crate) fn make_slot(
    slot: &frame::ResidualSlot,
    parsed: &ParsedFrame,
    scale: &PcmScale,
) -> Option<FlacSlot> {
    let start = slot.comp_start as usize;
    let end = start.checked_add(slot.comp_len as usize)?;
    let chain = parsed.comps.get(start..end)?;
    Some(FlacSlot {
        bit_offset: slot.bit_offset as u64,
        k: slot.k as u8,
        value: slot.value as i32,
        cost: slot_cost(parsed, slot, scale),
        comp: chain
            .iter()
            .map(|c| CompSlot {
                bit_offset: c.bit_offset as u64,
                k: c.k as u8,
                value: c.value as i32,
                rice: c.rice,
                plus: c.plus,
                minus: c.minus,
            })
            .collect(),
    })
}

/// Rewrite a Rice codeword's remainder so it decodes to `new`, keeping its width.
///
/// Only the remainder bits are touched: `v` and `new` share a `u >> k` bucket,
/// so the unary prefix -- and with it the codeword length -- is unchanged. The
/// readback proves the offset arithmetic, because a wrong position would write
/// into a neighbouring codeword and only surface frames later as a parse error.
fn write_remainder(
    bytes: &mut [u8],
    bit_offset: usize,
    k: u32,
    old: i64,
    new: i64,
) -> Result<(), StrHideError> {
    if old == new {
        return Ok(());
    }
    let old_u = frame::fold(old);
    let new_u = frame::fold(new);
    if (old_u >> k) != (new_u >> k) {
        return Err(StrHideError::General(format!(
            "FLAC codeword at bit {bit_offset} would change width (k={k})"
        )));
    }
    let unary_bits = (old_u >> k) as usize + 1;
    let mask = if k == 0 { 0 } else { (1u32 << k) - 1 };
    let mut writer = BitWriter::new(bytes, bit_offset + unary_bits);
    writer.write(k, (new_u as u32) & mask)?;
    if read_codeword(bytes, bit_offset, k) != Some(new as i32) {
        return Err(StrHideError::General(format!(
            "FLAC codeword readback mismatch at bit {bit_offset} (wrote {new})"
        )));
    }
    Ok(())
}

/// Local perceptual cost of the sample a residual reconstructs.
///
/// Same shape as the WAV model -- short-time energy plus the local slope -- but
/// evaluated on the plane the residual belongs to, so a mid/side frame is
/// priced by the signal the residual actually moves.
pub(super) fn slot_cost(parsed: &ParsedFrame, slot: &frame::ResidualSlot, scale: &PcmScale) -> f32 {
    let plane = parsed
        .samples
        .get(slot.channel as usize)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if plane.is_empty() {
        return f32::MAX / 4.0;
    }
    let index = (slot.sample_index as usize).min(plane.len() - 1);
    let lo = index.saturating_sub(COST_WINDOW);
    let hi = (index + COST_WINDOW + 1).min(plane.len());
    let mut energy = 0.0f64;
    for &sample in &plane[lo..hi] {
        let normalised = sample as f64 / scale.full;
        energy += normalised * normalised;
    }
    let rms = (energy / (hi - lo).max(1) as f64).sqrt();
    let slope = if index == 0 {
        0.0
    } else {
        ((plane[index] - plane[index - 1]) as f64 / scale.full).abs()
    };
    let energy_metric = rms + 0.5 * slope;
    if energy_metric < 1e-7 {
        // Digital silence: a one-unit move is maximally audible there.
        return 1e6;
    }
    (1.0 / (1e-3 + energy_metric)) as f32
}

/// Largest decoded-sample difference between two versions of one frame, in
/// units of one **stored** sample step.
///
/// The decoded values are output units, but the compensation chain moves stored
/// values. A subframe with `w` wasted bits stores samples shifted right by `w`,
/// so one stored step is `2^w` output units; the frame's worst difference is
/// divided by that factor (rounded up) before it is compared with
/// [`DRIFT_BUDGET`]. Without this, a perfectly compensated embed in a
/// `wasted_bits > 0` carrier was reported as a `2^w`-unit smear and refused.
///
/// Shared by the embed-time gate and [`max_sample_drift`] so both measure the
/// waveform the same way.
pub(super) fn decoded_drift_units(a: &ParsedFrame, b: &ParsedFrame) -> Result<i64, StrHideError> {
    if a.samples.len() != b.samples.len() {
        return Err(StrHideError::CorruptedData(
            "cover and stego frames disagree on the channel count".into(),
        ));
    }
    let mut frame_worst = 0i64;
    let mut frame_at = (0usize, 0usize);
    let mut first: Option<(usize, usize, i64, i64)> = None;
    let mut count = 0usize;
    for (ci, (plane_a, plane_b)) in a.samples.iter().zip(b.samples.iter()).enumerate() {
        for (si, (x, y)) in plane_a.iter().zip(plane_b.iter()).enumerate() {
            if x != y {
                count += 1;
                if first.is_none() {
                    first = Some((ci, si, *x, *y));
                }
            }
            if (x - y).abs() > frame_worst {
                frame_worst = (x - y).abs();
                frame_at = (ci, si);
            }
        }
    }
    // One stored step is `2^w` output units. Mixed wasted counts inside one
    // frame are rare (real encoders pick them per subframe from the same
    // signal, so they normally agree); taking the largest keeps the gate
    // in stored units and can only be *more* lenient for such files.
    let wasted = a
        .wasted
        .iter()
        .chain(b.wasted.iter())
        .max()
        .copied()
        .unwrap_or(0)
        .min(31);
    let scale = 1i64 << wasted;
    let frame_units = if frame_worst == 0 {
        0
    } else {
        (frame_worst + scale - 1) / scale
    };
    if frame_units > DRIFT_BUDGET {
        let f = first.unwrap_or((0, 0, 0, 0));
        log::debug!(
            target: "stego::audio::flac",
            "drift {frame_worst} output units = {frame_units} stored units (wasted {wasted}) at frame@{} ch{} sample{} (cover {} vs stego {}) | first ch{} sample{} {}->{} | {count} diffs",
            a.start,
            frame_at.0,
            frame_at.1,
            a.samples[frame_at.0][frame_at.1],
            b.samples[frame_at.0][frame_at.1],
            f.0,
            f.1,
            f.2,
            f.3
        );
    }
    Ok(frame_units)
}
