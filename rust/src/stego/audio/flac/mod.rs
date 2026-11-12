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
mod carrier;
#[cfg(test)]
mod e2e;
mod frame;
mod md5;
#[cfg(test)]
mod tests;

#[cfg(test)]
use carrier::decoded_drift_units;
#[cfg(test)]
pub(crate) use carrier::make_slot;
pub(crate) use carrier::{FlacCapacityView, FlacCarrier, FlacTail};
use carrier::{slot_cost, slot_legality_raw};
use md5::Md5;

use crate::errors::StrHideError;
use crate::stego::audio::cost::PcmScale;
use crate::stego::coding::Move;
use frame::StreamDefaults;

/// Offset of the MD5 field inside the file: `fLaC` + block header + 18 bytes.
///
/// [`parse_stream_info`] rejects any stream whose STREAMINFO is not the first
/// metadata block, so this constant is the only place the MD5 can live.
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
/// How far the decoded waveform may move, in units of one **stored** sample step.
///
/// The compensation chain cancels predictor reaction at every tap; under exact
/// integer compensation the waveform moves by at most 1 unit (or 2 units under
/// stereo decorrelation where integer division rounds). The budget is a correctness
/// gate catching any failure that leaks error into neighbours.
///
/// A subframe that declares `w` wasted bits stores its samples shifted right by
/// `w`, so one residual step moves the decoded waveform by `2^w` output units.
/// `max_sample_drift` normalises each frame by that factor before comparing, so
/// this budget keeps its meaning (`1` = one stored step) for every carrier, not
/// only for files with `wasted_bits == 0`.
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
            // The spec makes STREAMINFO the first metadata block, and the
            // writer rewrites the MD5 at the fixed [`MD5_OFFSET`]. Accepting a
            // STREAMINFO anywhere else let `refresh_checksums` overwrite the
            // first block's payload while the real MD5 stayed stale, which
            // produced carriers that embed fine and never extract again.
            if pos != 4 {
                return Err(StrHideError::CorruptedData(
                    "FLAC STREAMINFO must be the first metadata block".into(),
                ));
            }
            if length != 34 {
                return Err(StrHideError::CorruptedData(format!(
                    "FLAC STREAMINFO block is {length} bytes, expected 34"
                )));
            }
            let slice = bytes
                .get(payload..payload + 34)
                .ok_or_else(|| StrHideError::CorruptedData("STREAMINFO is truncated".into()))?;
            let mut info = [0u8; 34];
            info.copy_from_slice(slice);
            streaminfo = Some(info);
        } else if pos == 4 {
            return Err(StrHideError::CorruptedData(
                "FLAC metadata chain does not start with STREAMINFO".into(),
            ));
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
    Ok(scan_stream(bytes, info, false)?.0)
}

/// Same validating scan, but also retains the subframe-tail pool.
///
/// The header slots are thinned over *all* tails, so their denominator is only
/// known once the walk is over. Tails are one per subframe (thousands, not
/// millions) and carry no compensation chain, so keeping them lets the caller
/// select the header picks without a second decode pass.
pub(crate) fn analyse_with_tails(
    bytes: &[u8],
    info: &StreamInfo,
) -> Result<(FlacAnalysis, Vec<FlacTail>), StrHideError> {
    scan_stream(bytes, info, true)
}

fn scan_stream(
    bytes: &[u8],
    info: &StreamInfo,
    keep_tails: bool,
) -> Result<(FlacAnalysis, Vec<FlacTail>), StrHideError> {
    let defaults = info.defaults();
    let scale = info.scale();
    let mut hasher = Md5::new();
    let mut pos = info.audio_offset;
    let mut frames = 0usize;
    let mut slots = 0usize;
    let mut usable = 0usize;
    let mut tails = 0usize;
    let mut samples_decoded = 0u64;
    let mut tail_pool: Vec<FlacTail> = Vec::new();

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
        if keep_tails {
            for tail in &parsed.tails {
                tail_pool.push(FlacTail {
                    bit_offset: tail.bit_offset as u64,
                    k: tail.k as u8,
                    value: tail.value as i32,
                    cost: slot_cost(&parsed, tail, &scale),
                });
            }
        }
        frames += 1;
        pos = parsed.crc16_offset + 2;
    }

    if frames == 0 {
        return Err(StrHideError::UnsupportedFormat(
            "FLAC file contains no audio frames".into(),
        ));
    }

    Ok((
        FlacAnalysis {
            pcm_md5: hasher.finish(),
            slots,
            usable,
            tails,
        },
        tail_pool,
    ))
}

/// Largest per-sample difference between two versions of the same FLAC file,
/// measured in units of one **stored** sample step.
///
/// Walks both files frame by frame so the working set stays one frame, and
/// compares the *decoded* planes -- which is what a listener hears. Embedding
/// measures this during the finalize pass; this standalone walk remains for
/// tests that compare two finished files.
#[cfg(test)]
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
        worst = worst.max(decoded_drift_units(&a, &b)?);
        pos_a = a.crc16_offset + 2;
        pos_b = b.crc16_offset + 2;
    }
    Ok(worst)
}
