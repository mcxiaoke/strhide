//! FLAC frame parsing, sample reconstruction and residual slot discovery.
//!
//! One frame at a time: parse the header, decode every subframe into samples,
//! and record the bit position of every *usable* Rice codeword.
//!
//! # Why a decoder lives in a hiding tool
//!
//! In-place FLAC steganography changes a stored residual, which changes the
//! samples the decoder reconstructs. Two things follow, and both need a real
//! decoder:
//!
//! 1. `STREAMINFO` carries an MD5 of the decoded PCM. Changing a sample without
//!    refreshing it makes `flac -t` and every well-behaved player report a
//!    corrupt file. The MD5 is only computable from reconstructed samples.
//! 2. The perceptual cost model prices a change by the local signal energy,
//!    which is again the reconstructed sample.
//!
//! The decoder is therefore not a convenience -- it is what makes the result
//! *verifiable*: the whole file's MD5 is checked before anything is written.
//!
//! # What makes a residual usable
//!
//! A residual `e` is Rice coded as `u = fold(e)`, with codeword length
//! `(u >> k) + 1 + k`. A `±1` sample move changes `u` by one or two, so the
//! codeword keeps its width **iff the move stays inside the same `u >> k`
//! bucket**. Requiring `k >= 1` and `u >> k >= 1` makes eligibility depend only
//! on quantities that the move itself preserves, so the extractor derives the
//! identical slot set from the stego file.

use crate::stego::audio::flac::bits::{BitEof, BitReader};

/// Report a malformed field, optionally with its bit position.
///
/// `STRHIDE_FLAC_DEBUG=1` turns the diagnostics on; the lookup is cached so the
/// branch costs nothing when it is off. Kept next to the parser because every
/// call site knows the position it was reading.
#[inline]
fn bad(reason: &'static str, pos: usize) -> BitEof {
    use std::sync::OnceLock;
    static DEBUG: OnceLock<bool> = OnceLock::new();
    if *DEBUG.get_or_init(|| std::env::var_os("STRHIDE_FLAC_DEBUG").is_some()) {
        eprintln!("flac-debug: {reason} at bit {pos} (byte {})", pos / 8);
    }
    BitEof
}

/// One residual that absorbs part of the predictor's reaction to a slot move.
///
/// Moving the residual of sample `j` changes sample `j` by one, and the
/// predictor then feeds that change into sample `j+1`, `j+2`, ... for exactly
/// `order` steps. Each of those samples gets its own compensating residual, and
/// once the predictor window has slid past `j` the waveform is back to the
/// original bit for bit.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Compensation {
    /// Absolute bit offset of the compensating codeword.
    pub bit_offset: usize,
    /// Rice parameter of that codeword.
    pub k: u32,
    /// Current value of the compensating residual.
    pub value: i64,
    /// Delta it must take when the slot moves `+1`.
    pub plus: i32,
    /// Delta it must take when the slot moves `-1`.
    pub minus: i32,
    /// `false` for escape-coded residuals, whose bits are raw rather than Rice
    /// and therefore cannot be rewritten without changing the codeword width.
    pub rice: bool,
}

impl Compensation {
    /// Whether `delta` can be written here without changing the codeword width.
    ///
    /// A zero delta writes nothing, so it is always available -- which is the
    /// common case, because the predictor's reaction rounds to zero at most
    /// taps and only the nearest ones see a non-zero share.
    pub(crate) fn accepts(&self, delta: i32) -> bool {
        comp_accepts(self.k, self.value, self.rice, delta)
    }
}

/// Shared width test for a Rice codeword holding `value`.
pub(crate) fn comp_accepts(k: u32, value: i64, rice: bool, delta: i32) -> bool {
    if delta == 0 {
        return true;
    }
    if !rice || k == 0 {
        return false;
    }
    let old = fold(value);
    let new = fold(value + delta as i64);
    (old >> k) == (new >> k)
}

/// A Rice-coded residual that can carry one bit.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResidualSlot {
    /// Absolute bit offset of the codeword's first bit (its unary zeros).
    pub bit_offset: usize,
    /// Rice parameter of the partition this residual belongs to.
    pub k: u32,
    /// Current residual value, i.e. the first difference the predictor left.
    pub value: i64,
    /// Subframe (channel plane) the codeword belongs to.
    pub channel: u8,
    /// Position of the residual inside that plane, which is also the sample
    /// index the residual reconstructs -- the cost model prices it there.
    pub sample_index: u32,
    /// Index of this slot's compensation chain inside [`ParsedFrame::comps`].
    pub comp_start: u32,
    /// Length of that chain, i.e. the predictor order (zero for FIXED order 0,
    /// where a residual *is* the sample and nothing propagates).
    pub comp_len: u32,
}

/// A fully decoded frame.
pub(crate) struct ParsedFrame {
    /// Byte offset of the frame's sync word.
    pub start: usize,
    /// Interleaved-free sample planes: `samples[channel][frame_sample]`.
    pub samples: Vec<Vec<i64>>,
    /// Byte offset of the frame's CRC-16 (frame ends two bytes later).
    pub crc16_offset: usize,
    /// Usable residual codewords, in decode order.
    pub slots: Vec<ResidualSlot>,
    /// Pool of compensation entries referenced by [`ResidualSlot::comp_start`].
    pub comps: Vec<Compensation>,
    /// The last residual of every subframe that can be moved either way.
    ///
    /// A block ends at the last sample, so moving that residual changes exactly
    /// one sample and has nothing to compensate. That makes these slots
    /// *unconditionally* writable -- which is what the fixed 512-slot header
    /// needs, since a header bit that cannot be written has nowhere to go.
    pub tails: Vec<ResidualSlot>,
}

/// Sample rate table indexed by the 4-bit header code (12..=14 are explicit).
const SAMPLE_RATES: [u32; 12] = [
    0, 88_200, 176_400, 192_000, 8_000, 16_000, 22_050, 24_000, 32_000, 44_100, 48_000, 96_000,
];

/// Values a frame inherits from `STREAMINFO` when its header omits them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamDefaults {
    pub sample_rate: u32,
    pub bits_per_sample: u32,
}

fn byte(bytes: &[u8], index: usize) -> Result<u8, BitEof> {
    bytes.get(index).copied().ok_or(BitEof)
}

fn be16(bytes: &[u8], index: usize) -> Result<u16, BitEof> {
    let hi = byte(bytes, index)?;
    let lo = byte(bytes, index + 1)?;
    Ok(u16::from_be_bytes([hi, lo]))
}

/// Decode FLAC's UTF-8-style frame/sample number.
fn read_coded_number(bytes: &[u8], pos: usize) -> Result<(u64, usize), BitEof> {
    let first = byte(bytes, pos)?;
    if first & 0x80 == 0 {
        return Ok((first as u64, 1));
    }
    let extra = first.leading_ones() as usize - 1;
    if extra == 0 || extra > 6 {
        return Err(BitEof);
    }
    let mut value = (first & (0xFF >> (extra + 1))) as u64;
    for i in 1..=extra {
        let next = byte(bytes, pos + i)?;
        if next & 0xC0 != 0x80 {
            return Err(BitEof);
        }
        value = (value << 6) | (next & 0x3F) as u64;
    }
    Ok((value, extra + 1))
}

fn crc8(data: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// `CRC-16` over a frame, polynomial `x^16 + x^15 + x^2 + 1`.
pub(crate) fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x8005
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Parse one frame starting at `start`.
pub(crate) fn parse_frame(
    bytes: &[u8],
    start: usize,
    defaults: &StreamDefaults,
) -> Result<ParsedFrame, BitEof> {
    parse_frame_with(bytes, start, defaults, true)
}

/// Re-parse a frame whose payload has just been rewritten.
///
/// The frame's own `CRC-16` is stale until the caller recomputes it, so the
/// checksum check has to be skipped here -- every other structural check still
/// runs. `FlacCarrier::finalize` performs a final *checked* pass once the
/// checksums are written, so a frame that is genuinely broken is still caught.
pub(crate) fn parse_frame_trusted(
    bytes: &[u8],
    start: usize,
    defaults: &StreamDefaults,
) -> Result<ParsedFrame, BitEof> {
    parse_frame_with(bytes, start, defaults, false)
}

fn parse_frame_with(
    bytes: &[u8],
    start: usize,
    defaults: &StreamDefaults,
    verify_crc: bool,
) -> Result<ParsedFrame, BitEof> {
    let result = parse_frame_inner(bytes, start, defaults, verify_crc);
    if result.is_err() {
        use std::sync::OnceLock;
        static DEBUG: OnceLock<bool> = OnceLock::new();
        if *DEBUG.get_or_init(|| std::env::var_os("STRHIDE_FLAC_DEBUG").is_some()) {
            let head: Vec<String> = bytes
                .get(start..(start + 8).min(bytes.len()))
                .unwrap_or(&[])
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            eprintln!(
                "flac-debug: frame at byte {start} failed, head=[{}]",
                head.join(" ")
            );
        }
    }
    result
}

fn parse_frame_inner(
    bytes: &[u8],
    start: usize,
    defaults: &StreamDefaults,
    verify_crc: bool,
) -> Result<ParsedFrame, BitEof> {
    let b0 = byte(bytes, start)?;
    let b1 = byte(bytes, start + 1)?;
    if b0 != 0xFF || (b1 & 0xFE) != 0xF8 {
        return Err(BitEof);
    }
    let b2 = byte(bytes, start + 2)?;
    let b3 = byte(bytes, start + 3)?;
    let block_code = (b2 >> 4) & 0xF;
    let rate_code = b2 & 0xF;
    let assignment = (b3 >> 4) & 0xF;
    let size_code = (b3 >> 1) & 0x7;
    let mut pos = start + 4;

    let (number, number_len) = read_coded_number(bytes, pos)?;
    pos += number_len;

    let block_size = match block_code {
        0 => return Err(bad("reserved block size code", pos)), // reserved
        1 => 192,
        2..=5 => 576usize << (block_code - 2),
        6 => {
            let extra = byte(bytes, pos)? as usize;
            pos += 1;
            extra + 1
        }
        7 => {
            let extra = be16(bytes, pos)? as usize;
            pos += 2;
            extra + 1
        }
        8 => 256,
        _ => 256usize << (block_code - 8),
    };
    if block_size == 0 || block_size > u16::MAX as usize {
        return Err(bad("block size out of range", pos));
    }

    let sample_rate = match rate_code {
        0 => defaults.sample_rate,
        12 => {
            let khz = byte(bytes, pos)? as u32;
            pos += 1;
            khz * 1000
        }
        13 => {
            let hz = be16(bytes, pos)? as u32;
            pos += 2;
            hz
        }
        14 => {
            let tens = be16(bytes, pos)? as u32;
            pos += 2;
            tens * 10
        }
        15 => return Err(bad("invalid sample rate code", pos)), // invalid
        code => SAMPLE_RATES[code as usize],
    };

    let bits_per_sample = match size_code {
        0 => defaults.bits_per_sample,
        1 => 8,
        2 => 12,
        4 => 16,
        5 => 20,
        6 => 24,
        _ => return Err(bad("reserved sample size code", pos)), // 3 and 7 are reserved
    };

    let channels = match assignment {
        0..=7 => assignment as usize + 1,
        8..=10 => 2,
        _ => return Err(bad("reserved channel assignment", pos)),
    };

    // Header CRC-8 covers every header byte before it.
    if crc8(&bytes[start..pos]) != byte(bytes, pos)? {
        return Err(bad("header CRC-8 mismatch", pos));
    }
    pos += 1;

    // `sample_rate` / `bits_per_sample` / `number` are parsed because they
    // affect the bit layout and must be consumed in order; nothing downstream
    // needs them once the subframes are read.
    let _ = (sample_rate, number, bits_per_sample);

    if std::env::var_os("STRHIDE_FLAC_DEBUG").is_some() {
        eprintln!(
            "flac-debug: frame@{start} block={block_size} bits={bits_per_sample} assign={assignment} ch={channels} subframe_at={pos}"
        );
    }
    let mut reader = BitReader::new(bytes, pos * 8);
    let mut planes: Vec<Vec<i64>> = Vec::with_capacity(channels);
    let mut slots: Vec<ResidualSlot> = Vec::new();
    let mut comps: Vec<Compensation> = Vec::new();
    let mut tails: Vec<ResidualSlot> = Vec::new();

    for channel in 0..channels {
        // Which of the two subframes is the "side" difference depends on the
        // assignment (FLAC §9.1.3):
        //   8  left/side  -> (left, side)
        //   9  right/side -> (side, right)   <- the difference comes FIRST
        //   10 mid/side   -> (mid, side)
        // The side plane carries one extra bit of precision.
        let is_side = match assignment {
            8 | 10 => channel == 1,
            9 => channel == 0,
            _ => false,
        };
        let mut channel_bps = if is_side {
            bits_per_sample + 1
        } else {
            bits_per_sample
        };
        let plane = decode_subframe(
            &mut reader,
            block_size,
            &mut channel_bps,
            channel as u8,
            &mut slots,
            &mut comps,
            &mut tails,
        )?;
        planes.push(plane);
    }

    reader.align();
    let crc16_offset = reader.position() / 8;
    let stored = be16(bytes, crc16_offset)?;
    if verify_crc && crc16(&bytes[start..crc16_offset]) != stored {
        return Err(bad("frame CRC-16 mismatch", crc16_offset));
    }

    let samples = undo_stereo(assignment, planes, bits_per_sample);
    Ok(ParsedFrame {
        start,
        samples,
        crc16_offset,
        slots,
        comps,
        tails,
    })
}

/// Decode one subframe into `block_size` samples.
fn decode_subframe(
    reader: &mut BitReader<'_>,
    block_size: usize,
    bps: &mut u32,
    channel: u8,
    slots: &mut Vec<ResidualSlot>,
    comps: &mut Vec<Compensation>,
    tails: &mut Vec<ResidualSlot>,
) -> Result<Vec<i64>, BitEof> {
    if reader.read(1)? != 0 {
        return Err(bad("subframe padding bit set", reader.position()));
    }
    let sub_type = reader.read(6)?;
    let wasted_flag = reader.read(1)?;
    if std::env::var_os("STRHIDE_FLAC_DEBUG").is_some() {
        eprintln!(
            "flac-debug:   subframe type={sub_type} wasted={wasted_flag} bps={bps} at bit {}",
            reader.position() - 8
        );
    }
    let wasted = if wasted_flag == 1 {
        let count = reader.unary()? + 1;
        if count >= *bps {
            return Err(bad("wasted bits exceed sample depth", reader.position()));
        }
        *bps -= count;
        count
    } else {
        0
    };

    let mut samples = match sub_type {
        0 => {
            let value = reader.read_signed(*bps)?;
            vec![value; block_size]
        }
        1 => {
            let mut out = Vec::with_capacity(block_size);
            for _ in 0..block_size {
                out.push(reader.read_signed(*bps)?);
            }
            out
        }
        8..=12 => {
            let order = (sub_type - 8) as usize;
            decode_predictive(
                reader, block_size, *bps, order, channel, false, slots, comps, tails,
            )?
        }
        t if t >= 32 => {
            let order = ((t & 0x1F) + 1) as usize;
            decode_predictive(
                reader, block_size, *bps, order, channel, true, slots, comps, tails,
            )?
        }
        _ => return Err(bad("reserved subframe type", reader.position())),
    };

    if wasted > 0 {
        for sample in &mut samples {
            *sample *= 1i64 << wasted;
        }
    }
    Ok(samples)
}

/// Shared FIXED/LPC body: warm-up samples, residuals, then the predictor.
#[allow(clippy::too_many_arguments)]
fn decode_predictive(
    reader: &mut BitReader<'_>,
    block_size: usize,
    bps: u32,
    order: usize,
    channel: u8,
    is_lpc: bool,
    slots: &mut Vec<ResidualSlot>,
    comps: &mut Vec<Compensation>,
    tails: &mut Vec<ResidualSlot>,
) -> Result<Vec<i64>, BitEof> {
    if order > block_size {
        return Err(bad("predictor order exceeds block size", reader.position()));
    }
    let mut samples: Vec<i64> = Vec::with_capacity(block_size);
    for _ in 0..order {
        samples.push(reader.read_signed(bps)?);
    }
    // Residuals are kept separately: the compensation chain for a slot depends
    // on the `order` residuals that follow it, which are only known later.
    let mut raw: Vec<i64> = Vec::with_capacity(block_size - order);
    let mut raw_addr: Vec<ResidualAddr> = Vec::with_capacity(block_size - order);

    // LPC only: the quantiser and the coefficients follow the warm-up samples,
    // not the subframe header (FLAC §9.2.5). Reading them before the warm-ups
    // desynchronises every following subframe.
    let lpc: Option<(Vec<i64>, i32)> = if is_lpc {
        let precision = reader.read(4)? + 1;
        if precision == 16 {
            return Err(bad("invalid LPC precision", reader.position()));
        }
        let raw_shift = reader.read(5)? as i32;
        let shift = if raw_shift >= 16 {
            raw_shift - 32
        } else {
            raw_shift
        };
        let mut coeffs = Vec::with_capacity(order);
        for _ in 0..order {
            coeffs.push(reader.read_signed(precision)?);
        }
        Some((coeffs, shift))
    } else {
        None
    };

    let method = reader.read(2)?;
    if method > 1 {
        return Err(bad("reserved residual coding method", reader.position()));
    }
    let partition_order = reader.read(4)?;
    let partitions = 1usize << partition_order;
    if !block_size.is_multiple_of(partitions) {
        return Err(bad(
            "partition count does not divide the block",
            reader.position(),
        ));
    }
    let per_partition = block_size / partitions;
    let param_bits = 4 + method;
    let escape = (1u32 << param_bits) - 1;
    if std::env::var_os("STRHIDE_FLAC_DEBUG").is_some() {
        eprintln!(
            "flac-debug:     residual method={method} porder={partition_order} per={per_partition} order={order} at bit {}",
            reader.position()
        );
    }

    for partition in 0..partitions {
        let count = if partition == 0 {
            per_partition.checked_sub(order).ok_or(BitEof)?
        } else {
            per_partition
        };
        // The Rice parameter lives inside the partition loop, immediately
        // before that partition's residuals (FFmpeg flacdec.c decode_residuals).
        let k = reader.read(param_bits)?;
        if k == escape {
            let raw_bits = reader.read(5)?;
            if raw_bits > 32 {
                return Err(bad("escape bit width above 32", reader.position()));
            }
            for _ in 0..count {
                let at = reader.position();
                let value = reader.read_signed(raw_bits)?;
                samples.push(value);
                raw.push(value);
                raw_addr.push(ResidualAddr {
                    offset: at,
                    k: raw_bits,
                    rice: false,
                });
            }
            continue;
        }
        for _ in 0..count {
            let bit_offset = reader.position();
            let quotient = reader.unary()? as u64;
            let remainder = if k > 0 { reader.read(k)? as u64 } else { 0 };
            let folded = (quotient << k) | remainder;
            let value = unfold(folded);
            samples.push(value);
            raw.push(value);
            raw_addr.push(ResidualAddr {
                offset: bit_offset,
                k,
                rice: true,
            });
        }
    }

    // Reconstruct: sample = prediction(previous reconstructed samples) + residual.
    let warmup = samples.len().min(order);
    for i in order..block_size {
        let residual = samples[i];
        // Wrapping arithmetic on purpose: a *correctly* parsed frame cannot
        // overflow (|sample| < 2^31, |coef| < 2^15, order <= 32), but a
        // desynchronised parse produces nonsense values, and a panic there
        // would turn "this file is not understood" into a crash. Garbage in,
        // wrong PCM out, MD5 mismatch, clean refusal.
        let prediction = match lpc {
            None => match order {
                0 => 0,
                1 => samples[i - 1],
                2 => samples[i - 1].wrapping_mul(2).wrapping_sub(samples[i - 2]),
                3 => samples[i - 1]
                    .wrapping_mul(3)
                    .wrapping_sub(samples[i - 2].wrapping_mul(3))
                    .wrapping_add(samples[i - 3]),
                4 => samples[i - 1]
                    .wrapping_mul(4)
                    .wrapping_sub(samples[i - 2].wrapping_mul(6))
                    .wrapping_add(samples[i - 3].wrapping_mul(4))
                    .wrapping_sub(samples[i - 4]),
                _ => return Err(bad("unsupported fixed predictor order", reader.position())),
            },
            Some((ref coeffs, shift)) => {
                let mut sum: i64 = 0;
                for (j, &coef) in coeffs.iter().enumerate() {
                    sum = sum.wrapping_add(coef.wrapping_mul(samples[i - 1 - j]));
                }
                if shift >= 0 {
                    sum >> shift
                } else {
                    sum.wrapping_shl((-shift) as u32)
                }
            }
        };
        samples[i] = prediction.wrapping_add(residual);
    }
    debug_assert_eq!(warmup, order);

    collect_slots(
        order,
        lpc.as_ref(),
        &samples,
        &raw,
        &raw_addr,
        channel,
        slots,
        comps,
        tails,
    );
    Ok(samples)
}

/// Where one residual lives, and how its codeword is encoded.
#[derive(Debug, Clone, Copy)]
struct ResidualAddr {
    /// Absolute bit offset of the codeword's first bit.
    offset: usize,
    /// Rice parameter, or the fixed width when `rice` is false.
    k: u32,
    /// Rice-coded (rewritable inside its bucket) rather than escape-coded.
    rice: bool,
}

/// Walk a subframe's residuals and emit the slots that can carry payload.
///
/// # Why the predictor needs a chain of compensations
///
/// Moving the residual of sample `j` changes sample `j` by one. The predictor
/// for sample `j+1` reads `j`, so its prediction moves too; compensating that
/// one residual restores `j+1` -- but the predictor for `j+2` still reads `j`,
/// and so on for exactly `order` samples, until the sliding window has passed
/// `j`. A single-step compensation therefore does not stop the error, it only
/// delays it: measured on real music, a lone `±1` residual move smeared into a
/// drift of thousands of units (SNR 7 dB). The chain below cancels the error at
/// every step, so the decoded waveform differs from the cover by exactly the one
/// sample the slot moved.
///
/// # Why the spacing is fixed
///
/// A slot at `j` owns `j+1 ..= j+order`, so the next candidate starts at
/// `j+order+1`. The extractor has to derive this same set from the stego file
/// alone, and only quantities a legal move preserves may take part in the
/// decision: the Rice parameter, the `u >> k` bucket, and whether a direction
/// stays inside that bucket. Whether a *compensating* residual can absorb its
/// delta depends on the sample values, which the move changes -- so it may only
/// gate the move direction (see `move_legality`), never membership here.
#[allow(clippy::too_many_arguments)]
fn collect_slots(
    order: usize,
    lpc: Option<&(Vec<i64>, i32)>,
    samples: &[i64],
    raw: &[i64],
    raw_addr: &[ResidualAddr],
    channel: u8,
    slots: &mut Vec<ResidualSlot>,
    comps: &mut Vec<Compensation>,
    tails: &mut Vec<ResidualSlot>,
) {
    // The last residual carries no prediction forward: it reconstructs the
    // block's final sample and nothing reads that sample. It is therefore the
    // only position that is writable without any compensation at all, and the
    // header -- whose bits cannot be rerouted -- is built from these.
    if let Some(last) = raw.len().checked_sub(1) {
        let addr = raw_addr[last];
        let value = raw[last];
        let folded = fold(value);
        // `has_legal_move`, not "both directions": a header bit needs the
        // *parity* it asks for, and +1 and -1 flip the parity identically, so
        // one legal direction is enough. Requiring both would make the pool
        // depend on the value's position inside the bucket, which the move
        // changes -- and the reader would then count a different number of
        // tails and pick entirely different slots.
        if addr.rice && addr.k >= 1 && (folded >> addr.k) >= 1 && has_legal_move(folded, addr.k) {
            tails.push(ResidualSlot {
                bit_offset: addr.offset,
                k: addr.k,
                value,
                channel,
                sample_index: (order + last) as u32,
                comp_start: 0,
                comp_len: 0,
            });
        }
    }

    let mut index = 0usize;
    while index < raw.len() {
        let addr = raw_addr[index];
        let value = raw[index];
        let folded = fold(value);
        let usable =
            addr.rice && addr.k >= 1 && (folded >> addr.k) >= 1 && has_legal_move(folded, addr.k);
        // The chain must stay inside the block, and the final position is
        // reserved for the header, so a slot near the end has no successors to
        // compensate with and is skipped. Both conditions are structural, so
        // the writer and the reader agree on them without looking at values.
        // ... and the very last residual of the subframe is the header's, so no
        // body chain may reach it either.
        let fits = index + order + 1 < raw.len();
        if !usable || !fits {
            index += 1;
            continue;
        }

        let plane = order + index;
        let start = comps.len();
        for lag in 1..=order {
            let target = order + index + lag;
            let ahead = raw_addr[index + lag];
            let base = predict_at(samples, target, order, lpc, plane, 0);
            let plus = base.wrapping_sub(predict_at(samples, target, order, lpc, plane, 1));
            let minus = base.wrapping_sub(predict_at(samples, target, order, lpc, plane, -1));
            comps.push(Compensation {
                bit_offset: ahead.offset,
                k: ahead.k,
                value: raw[index + lag],
                plus: clamp_i32(plus),
                minus: clamp_i32(minus),
                rice: ahead.rice,
            });
        }
        slots.push(ResidualSlot {
            bit_offset: addr.offset,
            k: addr.k,
            value,
            channel,
            sample_index: plane as u32,
            comp_start: start as u32,
            comp_len: order as u32,
        });
        index += order + 1;
    }
}

#[inline]
fn clamp_i32(value: i64) -> i32 {
    value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

/// Prediction for sample `index` with sample `shifted` moved by `delta`.
///
/// `shifted` is not necessarily `index - 1`: the chain walks the predictor
/// window tap by tap, so the shifted sample sits at lag `index - 1 - shifted`.
fn predict_at(
    samples: &[i64],
    index: usize,
    order: usize,
    lpc: Option<&(Vec<i64>, i32)>,
    shifted: usize,
    delta: i64,
) -> i64 {
    #[inline]
    fn tap(samples: &[i64], index: usize, lag: usize, shifted: usize, delta: i64) -> i64 {
        let idx = index - 1 - lag;
        let value = samples[idx];
        if idx == shifted {
            value.wrapping_add(delta)
        } else {
            value
        }
    }
    match lpc {
        None => match order {
            0 => 0,
            1 => tap(samples, index, 0, shifted, delta),
            2 => tap(samples, index, 0, shifted, delta)
                .wrapping_mul(2)
                .wrapping_sub(tap(samples, index, 1, shifted, delta)),
            3 => tap(samples, index, 0, shifted, delta)
                .wrapping_mul(3)
                .wrapping_sub(tap(samples, index, 1, shifted, delta).wrapping_mul(3))
                .wrapping_add(tap(samples, index, 2, shifted, delta)),
            _ => tap(samples, index, 0, shifted, delta)
                .wrapping_mul(4)
                .wrapping_sub(tap(samples, index, 1, shifted, delta).wrapping_mul(6))
                .wrapping_add(tap(samples, index, 2, shifted, delta).wrapping_mul(4))
                .wrapping_sub(tap(samples, index, 3, shifted, delta)),
        },
        Some((coeffs, lpc_shift)) => {
            let mut sum: i64 = 0;
            for (lag, &coef) in coeffs.iter().enumerate() {
                sum = sum.wrapping_add(coef.wrapping_mul(tap(samples, index, lag, shifted, delta)));
            }
            if *lpc_shift >= 0 {
                sum >> *lpc_shift
            } else {
                sum.wrapping_shl((-*lpc_shift) as u32)
            }
        }
    }
}

/// Whether `u ± 1` sample moves keep the folded value inside its `u >> k`
/// bucket (i.e. keep the Rice codeword width unchanged).
#[inline]
fn has_legal_move(folded: u64, k: u32) -> bool {
    let bucket = folded >> k;
    let value = unfold(folded);
    let up = fold(value + 1) >> k == bucket;
    let down = fold(value - 1) >> k == bucket;
    up || down
}

/// Inverse of FLAC's Rice folding: `u = 2e` for `e >= 0`, `u = -2e - 1` otherwise.
#[inline]
fn unfold(folded: u64) -> i64 {
    if folded & 1 == 0 {
        (folded >> 1) as i64
    } else {
        -((folded >> 1) as i64) - 1
    }
}

/// Fold a signed residual back into the Rice domain.
#[inline]
pub(crate) fn fold(value: i64) -> u64 {
    if value >= 0 {
        (value as u64) << 1
    } else {
        ((-value) as u64) * 2 - 1
    }
}

/// Undo left/side, right/side and mid/side decorrelation.
///
/// FLAC stores channel 0 as the "primary" plane of the pair and channel 1 as the
/// side difference; which one is left, right or mid depends on the assignment.
fn undo_stereo(assignment: u8, mut planes: Vec<Vec<i64>>, _bps: u32) -> Vec<Vec<i64>> {
    if planes.len() != 2 || !(8..=10).contains(&assignment) {
        return planes;
    }
    let second = planes.pop().expect("two planes");
    let first = planes.pop().expect("two planes");

    let (left, right) = match assignment {
        // left + side: channel 0 is left, channel 1 is left - right.
        8 => {
            let left = first;
            let side = second;
            let right: Vec<i64> = left.iter().zip(side.iter()).map(|(l, s)| l - s).collect();
            (left, right)
        }
        // right + side: the stream order is (side, right), so `primary` here is
        // the side difference and `side` is the right channel.
        9 => {
            let difference = first;
            let right = second;
            let left: Vec<i64> = right
                .iter()
                .zip(difference.iter())
                .map(|(r, d)| r + d)
                .collect();
            (left, right)
        }
        // mid + side: mid = (l + r) >> 1, so the low bit of the difference is
        // preserved in the side channel and must be folded back before the
        // final rounding shift.
        _ => {
            let mid = first;
            let side = second;
            let mut left = Vec::with_capacity(mid.len());
            let mut right = Vec::with_capacity(mid.len());
            for (mid, s) in mid.iter().zip(side.iter()) {
                let mid2 = (mid << 1) | (s & 1);
                left.push((mid2 + s) >> 1);
                right.push((mid2 - s) >> 1);
            }
            (left, right)
        }
    };
    vec![left, right]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rice_folding_round_trips() {
        for value in [-1000i64, -3, -2, -1, 0, 1, 2, 3, 1000] {
            assert_eq!(unfold(fold(value)), value, "value {value}");
        }
        assert_eq!(fold(0), 0);
        assert_eq!(fold(1), 2);
        assert_eq!(fold(-1), 1);
    }

    #[test]
    fn crc8_matches_the_reference_vector() {
        // CRC-8/SMBUS (poly 0x07, init 0), the check value FLAC's frame-header
        // CRC is defined as: "123456789" -> 0xF4.
        assert_eq!(crc8(b"123456789"), 0xF4);
    }

    #[test]
    fn crc16_matches_the_reference_polynomial() {
        // CRC-16/UMTS: poly 0x8005, init 0, MSB-first, no final XOR; the check
        // value for "123456789" is 0xFEE8. (0xBB3D is the *reflected* ARC
        // variant, which FLAC does not use.)
        assert_eq!(crc16(b"123456789"), 0xFEE8);
    }

    #[test]
    fn coded_number_decoding_handles_multibyte_forms() {
        assert_eq!(read_coded_number(&[0x00], 0).unwrap(), (0, 1));
        assert_eq!(read_coded_number(&[0x7F], 0).unwrap(), (127, 1));
        // 0xC2 0x80 -> 0x80 = 128
        assert_eq!(read_coded_number(&[0xC2, 0x80], 0).unwrap(), (128, 2));
    }

    #[test]
    fn stereo_modes_reconstruct_the_original_channels() {
        let left = vec![100i64, -200, 300, 0];
        let right = vec![50i64, -100, 150, 0];

        // left + side
        let side: Vec<i64> = left.iter().zip(&right).map(|(l, r)| l - r).collect();
        let out = undo_stereo(8, vec![left.clone(), side], 16);
        assert_eq!(out[0], left);
        assert_eq!(out[1], right);

        // right + side: the difference comes first in the stream.
        let side: Vec<i64> = left.iter().zip(&right).map(|(l, r)| l - r).collect();
        let out = undo_stereo(9, vec![side, right.clone()], 16);
        assert_eq!(out[0], left);
        assert_eq!(out[1], right);

        // mid + side
        let mid: Vec<i64> = left.iter().zip(&right).map(|(l, r)| (l + r) >> 1).collect();
        let side: Vec<i64> = left.iter().zip(&right).map(|(l, r)| l - r).collect();
        let out = undo_stereo(10, vec![mid, side], 16);
        assert_eq!(out[0], left);
        assert_eq!(out[1], right);
    }
}
