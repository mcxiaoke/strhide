//! FLAC content-domain carrier: in-place, length-preserving residual coding.
//!
//! # The idea
//!
//! A FLAC frame stores, for every sample, a *residual* -- the part of the signal
//! its own linear predictor could not explain -- as a Rice code. Changing that
//! residual by one changes the decoded sample by one, and the codeword keeps
//! its width whenever the move stays inside the same `u >> k` bucket. A payload
//! can therefore be written **without moving a single byte**: frame boundaries,
//! the seek table's sample numbers and the file length all stay as they were.
//!
//! This is why the module does not follow the obvious
//! "decode -> modify -> re-encode" route: re-encoding rewrites LPC orders, Rice
//! partitions, frame sizes and the vendor string, which is a textbook
//! double-compression fingerprint. Here the encoder's own decisions survive;
//! only the last few bits of individual codewords differ.
//!
//! # What has to be recomputed
//!
//! | Field | Why |
//! | :--- | :--- |
//! | frame `CRC-16` | it covers the codeword bytes we just changed |
//! | `STREAMINFO` MD5 | it covers the decoded PCM, which follows the residuals |
//!
//! Both are fixed-size, so the file length is unaffected. The frame-header
//! `CRC-8` needs nothing: no header byte changes.
//!
//! # Fail-closed contract
//!
//! The MD5 in `STREAMINFO` is a checksum of the *entire* decoded signal, which
//! makes it a free correctness oracle: if this module's decoder reproduces it
//! exactly, the parser understood every subframe type, predictor, wasted-bit
//! shift and stereo mode in the file. Embedding is only allowed after that
//! check passes, so a carrier this build cannot fully decode is refused with a
//! clear message instead of being silently corrupted.
//!
//! # Slot selection
//!
//! A one-hour FLAC holds tens of millions of residuals; materialising all of
//! them would cost hundreds of megabytes. Instead both ends **stream** the
//! file once and apply the same keyed even thinning: slot `i` of the `total`
//! eligible ones is taken when `floor(((i+1)*wanted + phase) / total)` differs
//! from the previous step. `total` and `wanted` are both derivable from the
//! file (the stego file preserves `total` by construction), so the reader
//! selects exactly the writer's slots with O(payload) memory.

mod bits;
#[cfg(test)]
mod e2e;
mod frame;

use crate::errors::StrHideError;
use crate::stego::audio::core::SlotCarrier;
use crate::stego::audio::cost::{CostParams, PcmScale};
use crate::stego::coding::Move;
use crate::stego::header::PNG_AUDIO_BASE_SLOTS;
use bits::BitWriter;
use frame::{ParsedFrame, StreamDefaults};

/// Offset of the MD5 field inside the file: `fLaC` + block header + 18 bytes.
const MD5_OFFSET: usize = 8 + 18;

/// Half-width of the cost window, in samples.
const COST_WINDOW: usize = 16;

/// Slots the capacity report charges per payload bit.
///
/// The planner picks the STC group size `u` from the slot-to-bit ratio, and
/// `u = 1` -- one slot per bit, every slot pinned to a target parity -- cannot
/// tolerate a residual that refuses to move: measured on `01_Sphere.flac`
/// (9% of slots immovable) it fails on element 6 every time. `u = 2` and `3`
/// let neighbouring columns absorb the stuck ones, so the carrier reports a
/// slot count that keeps the ratio at 3, i.e. `u = 2` at full capacity.
/// Reporting the geometric maximum instead would promise payloads the trellis
/// cannot encode.
/// How far the decoded waveform may move, in units of one LSB.
///
/// The compensation chain cancels predictor reaction at every tap; under exact
/// integer compensation the waveform moves by at most 1 unit (or 2 units under
/// stereo decorrelation where integer division rounds). The budget is a correctness
/// gate catching any failure that leaks error into neighbours.
pub(crate) const DRIFT_BUDGET: i64 = 2;

/// Parsed `STREAMINFO`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamInfo {
    pub sample_rate: u32,
    pub channels: u8,
    pub bits_per_sample: u8,
    pub total_samples: u64,
    pub md5: [u8; 16],
    /// Byte offset of the first frame.
    pub audio_offset: usize,
}

impl StreamInfo {
    fn defaults(&self) -> StreamDefaults {
        StreamDefaults {
            sample_rate: self.sample_rate,
            bits_per_sample: self.bits_per_sample as u32,
        }
    }

    fn scale(&self) -> PcmScale {
        PcmScale::new(self.bits_per_sample as u32, 0)
    }

    fn md5_bytes_per_sample(&self) -> usize {
        (self.bits_per_sample as usize).div_ceil(8)
    }
}

/// Parse the FLAC marker and the metadata block chain.
pub(crate) fn parse_stream_info(bytes: &[u8]) -> Result<StreamInfo, StrHideError> {
    if bytes.len() < 4 + 4 + 34 || &bytes[0..4] != b"fLaC" {
        return Err(StrHideError::UnsupportedFormat(
            "not a native FLAC stream (missing 'fLaC' marker)".into(),
        ));
    }

    let mut pos = 4usize;
    let mut streaminfo: Option<[u8; 34]> = None;
    loop {
        let header = *bytes.get(pos).ok_or_else(|| {
            StrHideError::CorruptedData("FLAC metadata chain is truncated".into())
        })?;
        let last = header & 0x80 != 0;
        let block_type = header & 0x7F;
        let length = u32::from_be_bytes([
            0,
            *bytes.get(pos + 1).unwrap_or(&0),
            *bytes.get(pos + 2).unwrap_or(&0),
            *bytes.get(pos + 3).unwrap_or(&0),
        ]) as usize;
        let payload = pos + 4;
        if payload + length > bytes.len() {
            return Err(StrHideError::CorruptedData(
                "FLAC metadata block runs past the end of the file".into(),
            ));
        }
        if block_type == 0 {
            let slice = bytes
                .get(payload..payload + 34)
                .ok_or_else(|| StrHideError::CorruptedData("STREAMINFO is truncated".into()))?;
            let mut info = [0u8; 34];
            info.copy_from_slice(slice);
            streaminfo = Some(info);
        }
        pos = payload + length;
        if last {
            break;
        }
    }

    let info = streaminfo.ok_or_else(|| {
        StrHideError::UnsupportedFormat("FLAC file has no STREAMINFO block".into())
    })?;

    let min_block_size = u16::from_be_bytes([info[0], info[1]]);
    let max_block_size = u16::from_be_bytes([info[2], info[3]]);
    let packed = u64::from_be_bytes([
        info[10], info[11], info[12], info[13], info[14], info[15], info[16], info[17],
    ]);
    let sample_rate = (packed >> 44) as u32;
    let channels = (((packed >> 41) & 0x7) + 1) as u8;
    let bits_per_sample = (((packed >> 36) & 0x1F) + 1) as u8;
    let total_samples = packed & ((1 << 36) - 1);
    let mut md5 = [0u8; 16];
    md5.copy_from_slice(&info[18..34]);

    if min_block_size == 0 || max_block_size == 0 {
        return Err(StrHideError::CorruptedData(
            "FLAC declares a zero block size".into(),
        ));
    }
    if !(4..=32).contains(&bits_per_sample) {
        return Err(StrHideError::UnsupportedFormat(format!(
            "FLAC sample depth {bits_per_sample} is outside 4..=32"
        )));
    }

    Ok(StreamInfo {
        sample_rate,
        channels,
        bits_per_sample,
        total_samples,
        md5,
        audio_offset: pos,
    })
}

/// Outcome of a validating decode pass.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FlacAnalysis {
    /// MD5 of the decoded PCM, to be compared with `STREAMINFO`.
    pub pcm_md5: [u8; 16],
    /// Body candidates: residuals with a full compensation chain.
    ///
    /// This is a **structural** count: it depends only on the frame's subframe
    /// types, predictor orders and Rice parameters, all of which a legal move
    /// preserves. Both ends therefore derive the same number, which is what
    /// makes it the only admissible denominator for slot selection.
    pub slots: usize,
    /// Of those, how many can actually move in at least one direction *right
    /// now*.
    ///
    /// Value-dependent by definition: a move rewrites residual values, and the
    /// bucket/compensation tests that decide legality read those values. Both
    /// the cover and its stego can therefore report different numbers. Only the
    /// capacity report uses this -- it must never take part in slot selection,
    /// because the plan has to be derived from the stego file alone.
    pub usable: usize,
    /// Subframe tails, the header's pool.
    pub tails: usize,
}

/// Decode every frame and report the PCM checksum and the slot count.
///
/// Touches nothing; this is the pass that decides whether the carrier is
/// trustworthy enough to modify.
pub(crate) fn analyse(bytes: &[u8], info: &StreamInfo) -> Result<FlacAnalysis, StrHideError> {
    let defaults = info.defaults();
    let mut hasher = Md5::new();
    let mut pos = info.audio_offset;
    let mut frames = 0usize;
    let mut slots = 0usize;
    let mut usable = 0usize;
    let mut tails = 0usize;
    let mut samples_decoded = 0u64;

    while pos < bytes.len() {
        if info.total_samples > 0 && samples_decoded >= info.total_samples {
            break;
        }
        // Some encoders pad the tail with zero bytes or non-audio tags.
        if bytes[pos] == 0 {
            break;
        }
        let parsed = frame::parse_frame(bytes, pos, &defaults).map_err(|_| {
            StrHideError::CorruptedData(format!("FLAC frame at byte {pos} could not be decoded"))
        })?;
        let frame_samples = parsed.samples.first().map_or(0, Vec::len) as u64;
        samples_decoded += frame_samples;
        hasher.absorb(&parsed.samples, info.md5_bytes_per_sample());
        slots += parsed.slots.len();
        tails += parsed.tails.len();
        usable += parsed
            .slots
            .iter()
            .filter(|slot| !matches!(slot_legality_raw(slot, &parsed), Move::None))
            .count();
        frames += 1;
        pos = parsed.crc16_offset + 2;
    }

    if frames == 0 {
        return Err(StrHideError::UnsupportedFormat(
            "FLAC file contains no audio frames".into(),
        ));
    }

    Ok(FlacAnalysis {
        pcm_md5: hasher.finish(),
        slots,
        usable,
        tails,
    })
}

/// One addressable residual.
#[derive(Debug, Clone)]
struct FlacSlot {
    /// Absolute bit offset of the codeword's first bit.
    bit_offset: u32,
    /// Rice parameter of its partition.
    k: u8,
    /// Current residual value.
    value: i32,
    /// Perceptual cost of moving it by one.
    cost: f32,
    /// The chain of residuals that cancel the move's effect on the predictor,
    /// one per predictor tap. Empty for FIXED order 0, where a residual *is*
    /// the sample.
    comp: Vec<CompSlot>,
}

/// One link of that chain.
#[derive(Debug, Clone, Copy)]
struct CompSlot {
    bit_offset: u32,
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

/// A FLAC carrier presented as an array of already-selected residual slots.
///
/// Unlike the WAV carrier, the slot array is materialised: the trellis
/// addresses slots by plan position, and the engine hands over exactly the
/// ones the keyed thinning chose. The `SlotMap` for this carrier is therefore
/// the identity.
pub(crate) struct FlacCarrier<'a> {
    bytes: &'a mut [u8],
    info: StreamInfo,
    slots: Vec<FlacSlot>,
    modified: usize,
    /// Total residuals written to the stream (data slots + non-zero compensation taps).
    residuals_written: usize,
    /// Of the structural pool, how many can move in at least one direction.
    /// Reporting only -- selection never reads it (`analysis.slots` is the
    /// cross-end denominator).
    total_usable: usize,
    /// Finalized PCM MD5 computed during refresh_checksums.
    pcm_md5: Option<[u8; 16]>,
}

impl FlacCarrier<'_> {
    pub(crate) const MIN_GROUP: u8 = 3;

    /// Total residuals actually modified in the carrier (data moves plus compensation writes).
    #[allow(dead_code)]
    pub(crate) fn residuals_written(&self) -> usize {
        self.residuals_written
    }

    /// PCM MD5 computed when refreshing checksums after patch application.
    pub(crate) fn pcm_md5(&self) -> Option<[u8; 16]> {
        self.pcm_md5
    }
}

impl<'a> FlacCarrier<'a> {
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

        if info.md5 != [0u8; 16] && analysis.pcm_md5 != info.md5 {
            return Err(StrHideError::UnsupportedFormat(
                "FLAC carrier could not be fully validated (decoded PCM does not match the \
                 STREAMINFO MD5); refusing to modify a file this build cannot decode exactly"
                    .into(),
            ));
        }
        // Two disjoint pools, both derived from structural predicates plus the
        // bucket tests a legal move preserves:
        //   * subframe tails -- the last residual of every subframe -- need no
        //     compensation, so they are always writable; the fixed 512-slot
        //     header lives here because a header bit has nowhere to go if its
        //     slot cannot be moved;
        //   * everything else feeds the body, where the trellis can route
        //     around a slot whose compensation chain does not fit.
        //
        // The body's denominator is `analysis.slots`, never `analysis.usable`:
        // the latter counts slots that are legal *for the current residual
        // values*, and embedding rewrites exactly those values. A reader that
        // thinned over a different denominator would address a different set of
        // codewords and the payload would never decrypt (review P0-1).
        let total = analysis.slots;
        let total_usable = analysis.usable;
        let tail_total = analysis.tails;
        if header_slots < PNG_AUDIO_BASE_SLOTS {
            return Err(StrHideError::General(format!(
                "FLAC header area must be at least {PNG_AUDIO_BASE_SLOTS} slots, got {header_slots}"
            )));
        }
        let ext_slots = header_slots - PNG_AUDIO_BASE_SLOTS;
        if tail_total < header_slots {
            return Err(StrHideError::General(format!(
                concat!(
                    "FLAC carrier has {tails} usable subframe tails but the ",
                    "{header}-slot header needs that many; ",
                    "the file is too short for this carrier"
                ),
                tails = tail_total,
                header = header_slots
            )));
        }
        if total < body_slots {
            return Err(StrHideError::General(format!(
                "FLAC carrier has {} residual slots, {body_slots} required",
                total
            )));
        }

        // Pass 2: collect header picks and body picks in one sweep.
        //
        // The base 512 picks are thinned over *all* tails, and the extension
        // picks are thinned independently over the remaining (`tail_total - 512`)
        // tails. Keeping the base count fixed at 512 is what makes this stable:
        // a variable `wanted` would shift every base index as soon as an
        // extension was present, and the extraction pass that reads the base
        // header (before it knows `ext_len`) would address the wrong slots.
        let mut header_picks: Vec<FlacSlot> = Vec::with_capacity(header_slots);
        let mut ext_picks: Vec<FlacSlot> = Vec::with_capacity(ext_slots);
        let mut body_picks: Vec<FlacSlot> = Vec::with_capacity(body_slots);
        let mut tails_seen = 0usize;
        let mut nonbase_seen = 0usize;
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
                let index = tails_seen;
                tails_seen += 1;
                if thin_pick(index, tail_total, PNG_AUDIO_BASE_SLOTS, header_phase) {
                    if header_picks.len() < PNG_AUDIO_BASE_SLOTS
                        && let Some(entry) = make_slot(slot, &parsed, &scale)
                    {
                        header_picks.push(entry);
                    }
                } else {
                    if ext_slots > 0
                        && thin_pick(
                            nonbase_seen,
                            tail_total.saturating_sub(PNG_AUDIO_BASE_SLOTS),
                            ext_slots,
                            ext_phase,
                        )
                        && let Some(entry) = make_slot(slot, &parsed, &scale)
                    {
                        ext_picks.push(entry);
                    }
                    nonbase_seen += 1;
                }
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
            if header_picks.len() >= PNG_AUDIO_BASE_SLOTS
                && ext_picks.len() >= ext_slots
                && body_picks.len() >= body_slots
            {
                break;
            }
            pos = parsed.crc16_offset + 2;
        }

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

        if std::env::var_os("STRHIDE_FLAC_STATS").is_some() {
            eprintln!(
                "flac-stats: eligible={} usable={} stuck_rate={:.3} tails={}",
                total,
                analysis.usable,
                1.0 - analysis.usable as f64 / total.max(1) as f64,
                tail_total
            );
        }
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
        })
    }

    /// Recompute every frame checksum that covers a changed codeword, then the
    /// `STREAMINFO` MD5, both from a fresh decode of the patched file.
    fn refresh_checksums(&mut self) -> Result<(), StrHideError> {
        let defaults = self.info.defaults();
        let mut hasher = Md5::new();
        let mut pos = self.info.audio_offset;
        let mut samples_decoded = 0u64;
        // Slots were collected in file order for each half, so sort a copy of
        // the offsets once: the frame walk then advances a single cursor.
        let mut offsets: Vec<u32> = self
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

            let frame_start_bit = parsed.start * 8;
            let frame_end_bit = (parsed.crc16_offset + 2) * 8;
            let mut touched = false;
            while cursor < offsets.len() {
                let bit = offsets[cursor] as usize;
                if bit >= frame_end_bit {
                    break;
                }
                if bit >= frame_start_bit {
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
        if MD5_OFFSET + 16 <= self.bytes.len() {
            self.bytes[MD5_OFFSET..MD5_OFFSET + 16].copy_from_slice(&md5);
        }

        // Under debug assertions, verify with full recheck. In release builds,
        // avoid redundant whole-file decoding because frame CRCs and STREAMINFO MD5
        // were just computed and verified from the exact same decoded samples.
        #[cfg(debug_assertions)]
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
fn slot_legality_raw(slot: &frame::ResidualSlot, parsed: &ParsedFrame) -> Move {
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
fn make_slot(
    slot: &frame::ResidualSlot,
    parsed: &ParsedFrame,
    scale: &PcmScale,
) -> Option<FlacSlot> {
    let start = slot.comp_start as usize;
    let end = start.checked_add(slot.comp_len as usize)?;
    let chain = parsed.comps.get(start..end)?;
    Some(FlacSlot {
        bit_offset: slot.bit_offset as u32,
        k: slot.k as u8,
        value: slot.value as i32,
        cost: slot_cost(parsed, slot, scale),
        comp: chain
            .iter()
            .map(|c| CompSlot {
                bit_offset: c.bit_offset as u32,
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
    writer.write(k, (new_u as u32) & mask);
    #[cfg(debug_assertions)]
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
fn slot_cost(parsed: &ParsedFrame, slot: &frame::ResidualSlot, scale: &PcmScale) -> f32 {
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

/// Largest per-sample difference between two versions of the same FLAC file.
///
/// Walks both files frame by frame so the working set stays one frame, and
/// compares the *decoded* planes -- which is what a listener hears. The embedder
/// uses it to prove that the residual moves it made did not smear the waveform.
pub(crate) fn max_sample_drift(
    cover: &[u8],
    stego: &[u8],
    info: &StreamInfo,
) -> Result<i64, StrHideError> {
    let defaults = info.defaults();
    let mut pos_a = info.audio_offset;
    let mut pos_b = info.audio_offset;
    let mut worst = 0i64;
    let mut samples_decoded = 0u64;

    while pos_a < cover.len() && pos_b < stego.len() && cover[pos_a] != 0 {
        if info.total_samples > 0 && samples_decoded >= info.total_samples {
            break;
        }
        let a = frame::parse_frame(cover, pos_a, &defaults).map_err(|_| {
            StrHideError::CorruptedData(format!("cover frame at {pos_a} could not be decoded"))
        })?;
        let b = frame::parse_frame(stego, pos_b, &defaults).map_err(|_| {
            StrHideError::CorruptedData(format!("stego frame at {pos_b} could not be decoded"))
        })?;
        let frame_samples = a.samples.first().map_or(0, Vec::len) as u64;
        samples_decoded += frame_samples;
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
        if frame_worst > 8 && std::env::var_os("STRHIDE_FLAC_DEBUG").is_some() {
            let f = first.unwrap_or((0, 0, 0, 0));
            eprintln!(
                "flac-debug: drift {frame_worst} at frame@{} ch{} sample{} (cover {} vs stego {}) | first ch{} sample{} {}->{} | {count} diffs",
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
        worst = worst.max(frame_worst);
        pos_a = a.crc16_offset + 2;
        pos_b = b.crc16_offset + 2;
    }
    Ok(worst)
}

/// MD5 over FLAC's interleaved little-endian PCM.
///
/// `sha2` is already a dependency, but `STREAMINFO` is specified in terms of
/// MD5 and pulling a second hash crate in for one 16-byte field is not worth
/// it. This is the textbook implementation; it runs at most three times per
/// file (validate, refresh, verify).
struct Md5 {
    state: [u32; 4],
    block: [u8; 64],
    block_len: usize,
    length_bytes: u64,
}

impl Md5 {
    fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            block: [0u8; 64],
            block_len: 0,
            length_bytes: 0,
        }
    }

    fn absorb(&mut self, planes: &[Vec<i64>], bytes_per_sample: usize) {
        let block = planes.first().map_or(0, Vec::len);
        for i in 0..block {
            for plane in planes {
                let raw = plane[i].to_le_bytes();
                self.update(&raw[..bytes_per_sample]);
            }
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.length_bytes = self.length_bytes.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let take = (64 - self.block_len).min(data.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&data[..take]);
            self.block_len += take;
            data = &data[take..];
            if self.block_len == 64 {
                let block = self.block;
                self.transform(&block);
                self.block_len = 0;
            }
        }
    }

    fn transform(&mut self, block: &[u8; 64]) {
        const S: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];
        const K: [u32; 64] = [
            0xd76a_a478,
            0xe8c7_b756,
            0x2420_70db,
            0xc1bd_ceee,
            0xf57c_0faf,
            0x4787_c62a,
            0xa830_4613,
            0xfd46_9501,
            0x6980_98d8,
            0x8b44_f7af,
            0xffff_5bb1,
            0x895c_d7be,
            0x6b90_1122,
            0xfd98_7193,
            0xa679_438e,
            0x49b4_0821,
            0xf61e_2562,
            0xc040_b340,
            0x265e_5a51,
            0xe9b6_c7aa,
            0xd62f_105d,
            0x0244_1453,
            0xd8a1_e681,
            0xe7d3_fbc8,
            0x21e1_cde6,
            0xc337_07d6,
            0xf4d5_0d87,
            0x455a_14ed,
            0xa9e3_e905,
            0xfcef_a3f8,
            0x676f_02d9,
            0x8d2a_4c8a,
            0xfffa_3942,
            0x8771_f681,
            0x6d9d_6122,
            0xfde5_380c,
            0xa4be_ea44,
            0x4bde_cfa9,
            0xf6bb_4b60,
            0xbebf_bc70,
            0x289b_7ec6,
            0xeaa1_27fa,
            0xd4ef_3085,
            0x0488_1d05,
            0xd9d4_d039,
            0xe6db_99e5,
            0x1fa2_7cf8,
            0xc4ac_5665,
            0xf429_2244,
            0x432a_ff97,
            0xab94_23a7,
            0xfc93_a039,
            0x655b_59c3,
            0x8f0c_cc92,
            0xffef_f47d,
            0x8584_5dd1,
            0x6fa8_7e4f,
            0xfe2c_e6e0,
            0xa301_4314,
            0x4e08_11a1,
            0xf753_7e82,
            0xbd3a_f235,
            0x2ad7_d2bb,
            0xeb86_d391,
        ];

        let mut m = [0u32; 16];
        for (i, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
            m[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        let [mut a, mut b, mut c, mut d] = self.state;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = tmp;
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }

    fn finish(mut self) -> [u8; 16] {
        let bit_len = self.length_bytes.wrapping_mul(8);
        self.update(&[0x80]);
        while self.block_len != 56 {
            self.update(&[0]);
        }
        // `update` would count the length bytes; append them directly.
        self.block[56..64].copy_from_slice(&bit_len.to_le_bytes());
        let block = self.block;
        self.transform(&block);
        let mut out = [0u8; 16];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8; 16]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn md5_of(data: &[u8]) -> String {
        let mut hasher = Md5::new();
        hasher.update(data);
        hex(&hasher.finish())
    }

    #[test]
    fn md5_matches_known_vectors() {
        assert_eq!(md5_of(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_of(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_of(b"The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
        // A multi-block message exercises the 64-byte path and the padding.
        let long = vec![b'a'; 1000];
        assert_eq!(md5_of(&long), "cabe45dcc9ae5b66ba86600cca6b8ba8");
    }

    #[test]
    fn md5_absorb_matches_a_flat_byte_stream() {
        // Interleaved little-endian samples must hash exactly like the byte
        // stream a decoder would feed the same MD5.
        let left = vec![1i64, -2, 300];
        let right = vec![-1i64, 2, -300];
        let mut hasher = Md5::new();
        hasher.absorb(&[left.clone(), right.clone()], 2);
        let mut flat = Vec::new();
        for i in 0..3 {
            flat.extend_from_slice(&(left[i] as i16).to_le_bytes());
            flat.extend_from_slice(&(right[i] as i16).to_le_bytes());
        }
        assert_eq!(hasher.finish(), {
            let mut h = Md5::new();
            h.update(&flat);
            h.finish()
        });
    }

    /// Corpus harness: decodes every `*.flac` under `STRHIDE_FLAC_CORPUS` and
    /// reports, per file, whether the decoded PCM matches `STREAMINFO`.
    ///
    /// Ignored by default (it needs a corpus on disk); run with
    /// `STRHIDE_FLAC_CORPUS=<dir> cargo test --all-features --lib flac_corpus -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn flac_corpus_validates() {
        let dir = match std::env::var("STRHIDE_FLAC_CORPUS") {
            Ok(dir) => dir,
            Err(_) => return,
        };
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
            .expect("corpus dir")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "flac"))
            .collect();
        files.sort();

        let mut ok = 0usize;
        let mut failed = Vec::new();
        for path in &files {
            let bytes = std::fs::read(path).expect("read");
            let info = match parse_stream_info(&bytes) {
                Ok(info) => info,
                Err(e) => {
                    failed.push(format!("{}: {e}", path.display()));
                    continue;
                }
            };
            match analyse(&bytes, &info) {
                Ok(analysis) => {
                    if analysis.pcm_md5 == info.md5 || info.md5 == [0u8; 16] {
                        ok += 1;
                        println!(
                            "OK   {} ({} slots, {} samples)",
                            path.display(),
                            analysis.slots,
                            info.total_samples
                        );
                    } else {
                        failed.push(format!("{}: MD5 mismatch", path.display()));
                    }
                }
                Err(e) => failed.push(format!("{}: {e}", path.display())),
            }
        }
        println!(
            "
{ok} / {} files validated",
            files.len()
        );
        for line in &failed {
            println!("FAIL {line}");
        }
        assert!(
            failed.is_empty(),
            "{} of {} FLAC files could not be validated",
            failed.len(),
            files.len()
        );
    }

    #[test]
    fn rejects_a_file_without_the_flac_marker() {
        let err = parse_stream_info(b"RIFF....WAVE................").unwrap_err();
        assert!(err.to_string().contains("fLaC"));
    }
}
