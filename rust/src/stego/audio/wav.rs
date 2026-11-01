//! RIFF/WAVE parsing for the content domain.
//!
//! The structure domain already walks RIFF chunks
//! ([`crate::structure::adapters::riff`]), but it works through a `SeekRead`
//! stream and answers "where can I add a chunk", never "where does the sample
//! data start". The content domain needs the second question answered exactly,
//! on a byte slice it is about to overwrite in place, so the walk is repeated
//! here with different requirements:
//!
//! * **`data` may be huge** -- no payload is copied, only offsets are kept.
//! * **Layout must be validated**, not merely parsed: a block-aligned data
//!   chunk whose size disagrees with its own `fmt ` would make slot arithmetic
//!   address the wrong bytes, and every later `±1` would land on a random
//!   offset.
//!
//! # Accepted layouts
//!
//! `WAVE_FORMAT_PCM` (`0x0001`) and `WAVE_FORMAT_EXTENSIBLE` (`0xFFFE`) whose
//! SubFormat GUID says PCM, with 8/16/24/32-bit integer samples. Everything
//! else -- float PCM, ADPCM, RF64's `ds64` 64-bit sizes -- is rejected by name
//! rather than guessed at.
//!
//! # Rejections that matter
//!
//! * `data` size `0xFFFF_FFFF`: the RF64/streaming sentinel, not a real size.
//! * `data` size not a multiple of `block_align`: trailing partial frames.
//! * `data` extending past the file: truncated carrier.
//! * `block_align != channels * bytes_per_sample`: interleaving arithmetic
//!   would not hold.

use crate::errors::StrHideError;
use crate::stego::audio::core::SlotCarrier;
use crate::stego::audio::cost::{CostParams, PcmScale};
use crate::stego::audio::sample::SampleKind;
use crate::stego::coding::Move;

/// `WAVE_FORMAT_PCM`.
const FORMAT_PCM: u16 = 0x0001;
/// `WAVE_FORMAT_EXTENSIBLE`.
const FORMAT_EXTENSIBLE: u16 = 0xFFFE;

/// Everything the slot layer needs from a WAV file.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WavLayout {
    /// First byte of PCM data (already past the `data` chunk header).
    pub data_offset: usize,
    /// Length of the PCM data in bytes.
    pub data_len: usize,
    /// Sample storage layout.
    pub kind: SampleKind,
    /// Channel count.
    pub channels: u16,
    /// Sample rate in Hz (reported, not used for slot math).
    pub sample_rate: u32,
    /// Bytes per frame (`channels * kind.bytes()`).
    pub block_align: u16,
}

impl WavLayout {
    /// Number of sample components addressable as slots.
    pub(crate) fn slot_count(&self) -> usize {
        self.data_len / self.kind.bytes()
    }

    /// Frames (`data_len / block_align`).
    pub(crate) fn frame_count(&self) -> usize {
        self.data_len / self.block_align.max(1) as usize
    }

    /// Duration in seconds, when the rate is sane.
    pub(crate) fn duration_secs(&self) -> Option<f64> {
        if self.sample_rate == 0 {
            return None;
        }
        Some(self.frame_count() as f64 / self.sample_rate as f64)
    }

    /// Amplitude normalisation for the cost model.
    pub(crate) fn scale(&self) -> PcmScale {
        let center = if self.kind == SampleKind::U8 { 128 } else { 0 };
        PcmScale::new(self.kind.bits(), center)
    }
}

/// Read one little-endian `u32` at `offset`, or `None` when out of bounds.
fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map(u32::from_le_bytes)
}

/// Read one little-endian `u16` at `offset`, or `None` when out of bounds.
fn le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
        .map(u16::from_le_bytes)
}

/// Parse a WAV file and locate its PCM payload.
pub(crate) fn parse_wav(bytes: &[u8]) -> Result<WavLayout, StrHideError> {
    let truncated = || StrHideError::CorruptedData("WAV file is truncated".into());

    if bytes.len() < 12 {
        return Err(truncated());
    }
    if &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return Err(StrHideError::UnsupportedFormat(
            "not a RIFF/WAVE file".into(),
        ));
    }

    let mut fmt: Option<(u16, u16, u32, u16, u16)> = None;
    let mut data: Option<(usize, usize)> = None;

    let mut cursor = 12usize;
    while cursor + 8 <= bytes.len() {
        let id = &bytes[cursor..cursor + 4];
        let size = le_u32(bytes, cursor + 4).ok_or_else(truncated)? as usize;
        let payload = cursor + 8;
        // A `data` chunk may declare more than the file holds when the writer
        // was interrupted; anything else claiming a size past EOF is corrupt.
        let available = bytes.len().saturating_sub(payload);

        if id == b"data" {
            if size == u32::MAX as usize {
                return Err(StrHideError::UnsupportedFormat(
                    "RF64/streaming WAV (data size 0xFFFFFFFF) is not supported".into(),
                ));
            }
            if size > available {
                return Err(truncated());
            }
            data = Some((payload, size));
        } else if id == b"fmt " {
            if size < 16 || size > available {
                return Err(truncated());
            }
            let format_tag = le_u16(bytes, payload).ok_or_else(truncated)?;
            let channels = le_u16(bytes, payload + 2).ok_or_else(truncated)?;
            let sample_rate = le_u32(bytes, payload + 4).ok_or_else(truncated)?;
            let block_align = le_u16(bytes, payload + 12).ok_or_else(truncated)?;
            let bits = le_u16(bytes, payload + 14).ok_or_else(truncated)?;

            let effective_tag = if format_tag == FORMAT_EXTENSIBLE {
                // cbSize(2) + valid bits(2) + channel mask(4) + SubFormat GUID(16).
                if size < 40 {
                    return Err(StrHideError::UnsupportedFormat(
                        "WAVE_FORMAT_EXTENSIBLE chunk is shorter than 40 bytes".into(),
                    ));
                }
                le_u16(bytes, payload + 24).ok_or_else(truncated)?
            } else {
                format_tag
            };
            if effective_tag != FORMAT_PCM {
                return Err(StrHideError::UnsupportedFormat(format!(
                    "WAV format tag {effective_tag:#06x} is not integer PCM; \
                     only PCM (and PCM-subformat EXTENSIBLE) carriers are supported"
                )));
            }
            fmt = Some((effective_tag, channels, sample_rate, block_align, bits));
        }

        // Chunks are word aligned; an odd size carries one pad byte.
        let advance = size + (size & 1);
        match payload.checked_add(advance) {
            Some(next) if next > cursor => cursor = next,
            // Zero-size terminal chunk or a cycle: stop rather than spin.
            _ => break,
        }
    }

    let (_, channels, sample_rate, block_align, bits) =
        fmt.ok_or_else(|| StrHideError::UnsupportedFormat("WAV file has no 'fmt ' chunk".into()))?;
    let (data_offset, data_len) =
        data.ok_or_else(|| StrHideError::UnsupportedFormat("WAV file has no 'data' chunk".into()))?;

    if channels == 0 {
        return Err(StrHideError::CorruptedData(
            "WAV declares zero channels".into(),
        ));
    }
    let kind = SampleKind::from_bits(bits)?;
    let expected_align = channels as usize * kind.bytes();
    if block_align as usize != expected_align {
        return Err(StrHideError::CorruptedData(format!(
            "WAV block alignment {block_align} disagrees with {channels} channels of {bits}-bit samples ({expected_align})"
        )));
    }
    if data_len % expected_align != 0 {
        return Err(StrHideError::CorruptedData(format!(
            "WAV data chunk ({data_len} bytes) is not a whole number of {expected_align}-byte frames"
        )));
    }

    Ok(WavLayout {
        data_offset,
        data_len,
        kind,
        channels,
        sample_rate,
        block_align,
    })
}

/// A WAV carrier presented as a slot array.
///
/// Holds the whole file mutably: the `data` chunk is overwritten in place and
/// every other byte -- chunk headers, RIFF size, extra chunks -- is left
/// untouched, which is what keeps the file the same length with the same
/// offsets.
pub(crate) struct PcmCarrier<'a> {
    bytes: &'a mut [u8],
    layout: WavLayout,
    scale: PcmScale,
    /// Number of slots modified so far.
    modified: usize,
}

impl<'a> PcmCarrier<'a> {
    pub(crate) fn new(bytes: &'a mut [u8], layout: WavLayout) -> Self {
        let scale = layout.scale();
        Self {
            bytes,
            layout,
            scale,
            modified: 0,
        }
    }

    /// Byte offset of slot `index`, which must be below `slot_count()`.
    #[inline]
    fn offset_of(&self, index: usize) -> usize {
        self.layout.data_offset + index * self.layout.kind.bytes()
    }
}

impl SlotCarrier for PcmCarrier<'_> {
    fn slot_count(&self) -> usize {
        self.layout.slot_count()
    }

    fn slot_value(&self, index: usize) -> i32 {
        self.layout.kind.read(self.bytes, self.offset_of(index))
    }

    fn move_legality(&self, index: usize) -> Move {
        // Linear PCM has no value-class invariant to preserve, only the two
        // ends of the representable range. A slot sitting on an extreme may
        // still be used, just in the one direction that stays in range --
        // reporting `Both` there would let the trellis pick a move that
        // clamps to a no-op, leaving the parity unchanged and the payload bit
        // wrong.
        let value = self.slot_value(index);
        let kind = self.layout.kind;
        if value >= kind.max_value() {
            Move::MinusOnly
        } else if value <= kind.min_value() {
            Move::PlusOnly
        } else {
            Move::Both
        }
    }

    fn cost(&self, index: usize, params: &CostParams) -> f64 {
        params.cost_at(self.slot_count(), index, self.scale, |j| self.slot_value(j))
    }

    fn apply(&mut self, index: usize, delta: i8) -> Result<(), StrHideError> {
        if delta == 0 {
            return Ok(());
        }
        let kind = self.layout.kind;
        let offset = self.offset_of(index);
        let value = kind.read(self.bytes, offset) as i64 + delta as i64;
        let clamped = value.clamp(kind.min_value() as i64, kind.max_value() as i64) as i32;
        kind.write(self.bytes, offset, clamped);
        self.modified += 1;
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), StrHideError> {
        // Nothing to recompute: a PCM WAV carries no checksum over `data`.
        Ok(())
    }

    fn modified_slots(&self) -> usize {
        self.modified
    }

    fn format_label(&self) -> &'static str {
        "WAV"
    }

    fn describe(&self) -> Option<String> {
        let duration = self
            .layout
            .duration_secs()
            .map(|s| format!("{s:.1}s"))
            .unwrap_or_else(|| "unknown length".into());
        Some(format!(
            "{}-bit PCM, {} channel(s), {} Hz, {} frames, {duration}",
            self.layout.kind.bits(),
            self.layout.channels,
            self.layout.sample_rate,
            self.layout.frame_count()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal 16-bit stereo WAV with `frames` frames of a quiet tone.
    fn build_wav(frames: usize, channels: u16, bits: u16) -> Vec<u8> {
        let kind = SampleKind::from_bits(bits).unwrap();
        let block = channels as usize * kind.bytes();
        let data_len = frames * block;
        let mut out = Vec::with_capacity(44 + data_len);
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&((36 + data_len) as u32).to_le_bytes());
        out.extend_from_slice(b"WAVE");
        out.extend_from_slice(b"fmt ");
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&channels.to_le_bytes());
        out.extend_from_slice(&48_000u32.to_le_bytes());
        out.extend_from_slice(&((48_000 * block) as u32).to_le_bytes());
        out.extend_from_slice(&(block as u16).to_le_bytes());
        out.extend_from_slice(&bits.to_le_bytes());
        out.extend_from_slice(b"data");
        out.extend_from_slice(&(data_len as u32).to_le_bytes());
        for i in 0..frames {
            for c in 0..channels as usize {
                let value = (i as i32 * 7 + c as i32 * 3) % 2000 - 1000;
                let mut buf = [0u8; 4];
                kind.write(&mut buf, 0, value);
                out.extend_from_slice(&buf[..kind.bytes()]);
            }
        }
        out
    }

    #[test]
    fn parses_a_minimal_stereo_wav() {
        let bytes = build_wav(1000, 2, 16);
        let layout = parse_wav(&bytes).unwrap();
        assert_eq!(layout.data_offset, 44);
        assert_eq!(layout.data_len, 4000);
        assert_eq!(layout.channels, 2);
        assert_eq!(layout.kind, SampleKind::I16);
        assert_eq!(layout.slot_count(), 2000);
        assert_eq!(layout.frame_count(), 1000);
        assert!((layout.duration_secs().unwrap() - 1000.0 / 48_000.0).abs() < 1e-9);
    }

    #[test]
    fn skips_unknown_chunks_before_and_after_data() {
        let base = build_wav(64, 1, 16);
        // Insert a LIST chunk (odd length, so it also exercises the pad byte)
        // between `fmt ` and `data`.
        let fmt_end = 12 + 8 + 16;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&base[..fmt_end]);
        bytes.extend_from_slice(b"LIST");
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(b"INFOx");
        bytes.push(0); // pad
        bytes.extend_from_slice(&base[fmt_end..]);
        let riff_len = (bytes.len() - 8) as u32;
        bytes[4..8].copy_from_slice(&riff_len.to_le_bytes());

        // inserted chunk = 8-byte header + 5-byte payload + 1 pad byte, then
        // the 8-byte `data` header of the original file.
        let layout = parse_wav(&bytes).unwrap();
        assert_eq!(layout.data_offset, fmt_end + 14 + 8);
        assert_eq!(layout.frame_count(), 64);
    }

    #[test]
    fn rejects_float_and_rf64_by_name() {
        let mut bytes = build_wav(8, 1, 16);
        bytes[20..22].copy_from_slice(&3u16.to_le_bytes()); // IEEE float
        let err = parse_wav(&bytes).unwrap_err().to_string();
        assert!(err.contains("not integer PCM"), "{err}");

        let mut bytes = build_wav(8, 1, 16);
        let data_size_at = 40;
        bytes[data_size_at..data_size_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let err = parse_wav(&bytes).unwrap_err().to_string();
        assert!(err.contains("RF64"), "{err}");
    }

    #[test]
    fn rejects_inconsistent_block_alignment() {
        let mut bytes = build_wav(8, 2, 16);
        bytes[32..34].copy_from_slice(&2u16.to_le_bytes()); // should be 4
        assert!(parse_wav(&bytes).is_err());
    }

    #[test]
    fn rejects_a_truncated_data_chunk() {
        let mut bytes = build_wav(8, 1, 16);
        bytes.truncate(bytes.len() - 4);
        assert!(parse_wav(&bytes).is_err());
    }

    #[test]
    fn sample_round_trip_through_the_carrier() {
        let mut bytes = build_wav(256, 2, 16);
        let layout = parse_wav(&bytes).unwrap();
        let before: Vec<i32> = (0..layout.slot_count())
            .map(|i| layout.kind.read(&bytes, layout.data_offset + i * 2))
            .collect();
        {
            let mut carrier = PcmCarrier::new(&mut bytes, layout);
            assert_eq!(carrier.slot_count(), 512);
            for i in [0usize, 1, 255, 511] {
                assert_eq!(carrier.slot_value(i), before[i]);
                carrier.apply(i, 1).unwrap();
                assert_eq!(carrier.slot_value(i), before[i] + 1);
            }
            assert_eq!(carrier.modified_slots(), 4);
        }
        // Everything outside `data` is untouched.
        let header = build_wav(256, 2, 16);
        assert_eq!(&bytes[..layout.data_offset], &header[..layout.data_offset]);
    }
}
