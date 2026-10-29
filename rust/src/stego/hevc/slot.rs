//! HEVC CABAC Steganography Slot and Bin Recording Types.

use alloc::vec::Vec;

use rusty_h265::observer::ENCODER_CONTEXTS;

/// A recorded CABAC arithmetic decoding operation, packed into two bytes.
///
/// The journal is by far the largest allocation of the engine: a 13.6 s
/// 1080p60 stream records ~270 M bins, so every byte per bin is 270 MB and the
/// obvious Rust shape (`enum` with `Option<usize>` to address the slot) is 16
/// bytes per bin -- 4.3 GB for that one video, which is what made a HEVC embed
/// peak above 7 GB. The packed form keeps exactly the same information in
/// 16 bits:
///
/// ```text
/// bits  1..=0  kind: 0 = decision, 1 = bypass, 2 = terminate
/// bit      2  bin value
/// bit      3  bypass only: this bin is a stego slot (a non-DC sign bit)
/// bits 15..=4  decision only: CABAC context index (12 bits)
/// ```
///
/// A bypass bin deliberately does *not* store the slot index any more: the
/// slot a bypass bin belongs to is its position among the stego-flagged bypass
/// bins of the same slice, which the re-encoder re-derives by counting as it
/// walks the substream (see `SubstreamRecord::slot_start`). That is the same
/// number the recorder stamped onto the slot, without spending 8 bytes per bin
/// on it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BinOp(u16);

impl BinOp {
    const KIND_MASK: u16 = 0b11;
    const KIND_DECISION: u16 = 0;
    const KIND_BYPASS: u16 = 1;
    const KIND_TERMINATE: u16 = 2;
    const VALUE_SHIFT: u32 = 2;
    const STEGO: u16 = 1 << 3;
    const CTX_SHIFT: u32 = 4;
    /// Largest context index the 12-bit field can hold.
    ///
    /// `ENCODER_CONTEXTS` is 179, so this is only a saturation guard: a context
    /// index that does not fit is stored saturated and therefore fails the
    /// re-encoder's range check, which marks the substream unsupported instead
    /// of silently re-encoding it with the wrong model.
    const CTX_MAX: u16 = 0x0FFF;

    /// A context-mode decision bin.
    #[inline]
    pub fn decision(ctx_idx: usize, bit: u8) -> Self {
        let ctx = if ctx_idx >= Self::CTX_MAX as usize {
            Self::CTX_MAX
        } else {
            ctx_idx as u16
        };
        Self(Self::KIND_DECISION | Self::value(bit) | (ctx << Self::CTX_SHIFT))
    }

    /// An equiprobable bypass bin. `stego` marks a bypass bin that carries a
    /// slot (a non-DC coefficient sign).
    #[inline]
    pub fn bypass(bit: u8, stego: bool) -> Self {
        let flag = if stego { Self::STEGO } else { 0 };
        Self(Self::KIND_BYPASS | Self::value(bit) | flag)
    }

    /// An end-of-slice or end-of-substream terminate bin.
    #[inline]
    pub fn terminate(bit: u8) -> Self {
        Self(Self::KIND_TERMINATE | Self::value(bit))
    }

    #[inline]
    fn value(bit: u8) -> u16 {
        ((bit & 1) as u16) << Self::VALUE_SHIFT
    }

    #[inline]
    pub fn is_decision(self) -> bool {
        self.0 & Self::KIND_MASK == Self::KIND_DECISION
    }

    #[inline]
    pub fn is_bypass(self) -> bool {
        self.0 & Self::KIND_MASK == Self::KIND_BYPASS
    }

    #[inline]
    pub fn is_terminate(self) -> bool {
        self.0 & Self::KIND_MASK == Self::KIND_TERMINATE
    }

    /// The recorded bin value (0 or 1).
    #[inline]
    pub fn bit(self) -> u8 {
        ((self.0 >> Self::VALUE_SHIFT) & 1) as u8
    }

    /// CABAC context index of a decision bin (0 for other kinds).
    #[inline]
    pub fn ctx_idx(self) -> usize {
        (self.0 >> Self::CTX_SHIFT) as usize
    }

    /// Whether this bypass bin is a stego slot.
    #[inline]
    pub fn is_stego(self) -> bool {
        self.0 & Self::STEGO != 0
    }
}

impl core::fmt::Debug for BinOp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_decision() {
            write!(
                f,
                "Decision {{ ctx_idx: {}, bit: {} }}",
                self.ctx_idx(),
                self.bit()
            )
        } else if self.is_bypass() {
            write!(
                f,
                "Bypass {{ bit: {}, stego: {} }}",
                self.bit(),
                self.is_stego()
            )
        } else {
            write!(f, "Terminate {{ bit: {} }}", self.bit())
        }
    }
}

/// A candidate steganographic slot corresponding to an in-place CABAC bypass sign bit.
///
/// Field widths are chosen for the pool, not for the arithmetic: a video
/// carrier at 1080p60 yields ~17 M slots in a 13 s clip, so 32 bytes here
/// (where four `usize` fields made it 56) is the difference between one and two
/// gigabytes. `qp` stays an `i16` because the H.265 QP range for 8-bit video is
/// -6..=51 and the value is only consumed as an `i32` by the cost model.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StegoSlot {
    /// Perceptual distortion cost for STC matrix coding.
    pub cost: f32,
    /// Index in the slice's recorded `BinOp` sequence.
    pub op_idx: u32,
    /// 0-based slice index within the carrier.
    pub slice_idx: u32,
    /// Substream index within the slice.
    pub substream_idx: u16,
    /// Original sign bit (0 = positive, 1 = negative).
    pub original_bit: u8,
    pub _pad: u8,
}

const _: () = assert!(core::mem::size_of::<StegoSlot>() == 16);
const _: () = assert!(core::mem::size_of::<BinOp>() == 2);

/// Metadata and boundaries for a WPP/Tile substream within a slice.
#[derive(Clone, Debug)]
pub struct SubstreamRecord {
    pub substream_idx: usize,
    /// Offset in the slice's `ops` Vec where this substream starts.
    pub op_start: usize,
    /// Offset in the slice's `ops` Vec where this substream ends.
    pub op_end: usize,
    /// Recorder-local index of the first slot this substream contributes.
    ///
    /// A [`BinOp`] no longer stores the slot index, so the re-encoder derives
    /// it by counting stego-flagged bypass bins as it walks the substream from
    /// `op_start`; this is the counter's starting value.
    pub slot_start: usize,
    /// Initial CABAC context model for this substream (179 bytes: the native
    /// decoder states widened to the encoder's slot layout).
    pub init_contexts: [u8; ENCODER_CONTEXTS],
    /// Byte offset in the RBSP where this substream starts.
    pub rbsp_byte_start: usize,
    /// Byte offset in the RBSP where this substream ends.
    pub rbsp_byte_end: usize,
}

/// What a [`CabacRecorder`] captures.
///
/// Embedding needs the full journal: every touched substream is re-encoded from
/// its recorded bin sequence. Extraction, inspection, verification and capacity
/// probing only read slot sign bits, so they can skip the journal, the cost
/// model and the slot map — the journal is ~2 bytes per CABAC bin (hundreds of
/// millions on a video), which used to be the bulk of a `read`'s footprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RecordMode {
    /// Journal + perceptual cost + slot map: everything `embed` replays.
    #[default]
    Embed,
    /// Slot bits only: no journal, no cost model, no slot map.
    Slots,
}

/// Intermediate coordinate and transform metadata waiting for magnitude back-fill.
///
/// Kept only during the decoding of a single slice and drained on absorption.
/// Not stored on the long-lived [`StegoSlot`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct PendingSignInfo {
    pub trafo_size: u8,
    pub c_idx: u8,
    pub x_c: u8,
    pub y_c: u8,
}

/// Recorder attached to the CABAC decoding loop to capture the bin stream
/// and isolate stego sign positions for re-encoding.
#[derive(Default, Clone, Debug)]
pub struct CabacRecorder {
    /// Full sequence of CABAC bins in decode order (empty in
    /// [`RecordMode::Slots`]).
    pub ops: Vec<BinOp>,
    /// Isolated steganographic bypass sign slots.
    pub slots: Vec<StegoSlot>,
    /// Substream boundaries and initial contexts.
    pub substreams: Vec<SubstreamRecord>,
    /// Intermediate slice-local sign geometry for `record_stego_level` back-fill.
    pub(crate) pending_signs: Vec<PendingSignInfo>,
    /// What this recorder captures.
    mode: RecordMode,
    /// Current slice index being decoded.
    pub current_slice_idx: usize,
    /// Current substream index.
    pub current_substream_idx: usize,
    /// Drift band of the picture currently being decoded (see
    /// [`StegoSlot::band`]); stamped onto every slot this recorder produces.
    pub current_band: u8,
    /// Next slot awaiting its magnitude back-fill from `record_stego_level`.
    ///
    /// Sign bins decode before levels, so `record_stego_sign` can only store a
    /// provisional cost. The vendor hook then reports the coefficient magnitude
    /// in the very same coding-group order, which makes a plain cursor enough:
    /// the only entries without a slot are the DC `(0, 0)` signs, and both
    /// callbacks skip those on the same coordinate test.
    next_pending_slot: usize,
}

/// Largest sample deviation (8-bit levels) a single sign flip may cause before
/// its slot is treated as a last resort.
const SAFE_MAX_SAMPLE_DELTA: f64 = 32.0;

/// Cost handed to slots whose flip would move a sample too far, or whose
/// coefficient is too large to be a cheap carrier.
///
/// Deliberately finite: `f64::INFINITY` would let a `u = 2` trellis group whose
/// two slots are both unusable collapse into `TrellisCause::DeadGroup`. This
/// value keeps such slots ~1e6 times more expensive than a typical flip, so the
/// trellis avoids them at any realistic payload while still being able to use
/// them when the payload genuinely needs every slot.
pub(crate) const HIGH_DISPLACEMENT_PENALTY: f64 = 1_000_000.0;

/// Provisional bit depth assumed by `record_stego_sign`, whose call site does
/// not carry one. Always superseded by the real value in `record_stego_level`.
const PROVISIONAL_BIT_DEPTH: u8 = 8;

/// Where a coefficient sits and whether the block was transformed.
///
/// Bundled rather than passed as six arguments: the cost model reads all of
/// them together, and the tuple form was one clippy `too_many_arguments` away
/// from being unreadable at the call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlipGeometry {
    /// Transform unit size in samples (4, 8, 16, 32).
    pub trafo_size: u8,
    /// Colour plane (0 luma, 1 Cb, 2 Cr).
    pub c_idx: u8,
    /// Coefficient coordinates inside the transform unit.
    pub x_c: u8,
    pub y_c: u8,
    /// Bit depth of the plane the coefficient belongs to.
    pub bit_depth: u8,
    /// The decoder did not transform this block (`transform_skip_flag` or
    /// `cu_transquant_bypass_flag`), so the magnitude is a residual sample.
    pub sample_domain: bool,
}

/// Distortion cost of flipping one coefficient sign, from the decoded magnitude.
///
/// A sign flip changes the coefficient from `+dq` to `-dq`, i.e. by `2 * dq` in
/// the transform domain. The two-pass inverse transform of H.265 §8.6.4 has a
/// fixed total right shift of 19 bits and basis peaks of 64 (DC) / ~64·√2 (any
/// other frequency) regardless of block size, so the worst single-sample shift
/// is `dq * g(x_c) * g(y_c) / 64` in samples of `bit_depth`.
///
/// `abs_dq` already carries the `bdShift = bitDepth + log2(N) - 5` right shift of
/// §8.6.3, which is where the `1/N` block-size factor lives. Dividing by `N`
/// again would understate a 32×32 block by 8× per sample and 64× in energy.
/// A non-positive `abs_dq` means "unknown" and is priced as a single level.
///
/// `sample_domain` marks blocks the decoder did **not** transform
/// (`transform_skip_flag` / `cu_transquant_bypass_flag`): there `abs_dq` is
/// already a residual sample, the basis peak of 64 does not apply, and a sign
/// flip moves that one sample. Without the distinction a skipped 4×4 block at
/// QP 32 reported 26 samples and was priced 32× cheaper than the transform-path
/// coefficient of the same magnitude.
#[inline]
pub fn compute_sign_flip_cost(abs_level: u32, abs_dq: i32, geom: FlipGeometry) -> f64 {
    let dq = if abs_dq > 0 { abs_dq as f64 } else { 1.0 };
    cost_from_dq(abs_level, dq, geom)
}

/// Provisional cost for `record_stego_sign`, where the level has not been
/// decoded yet and only the §8.6.3 quantizer step is available.
#[inline]
pub fn provisional_sign_flip_cost(
    abs_level: u32,
    qp: i32,
    trafo_size: u8,
    c_idx: u8,
    x_c: u8,
    y_c: u8,
) -> f64 {
    let n = trafo_size.max(4) as f64;
    let q_step = 2.0_f64.powf((qp - 4) as f64 / 6.0);
    let dq = abs_level.max(1) as f64 * q_step * (64.0 / n);
    cost_from_dq(
        abs_level,
        dq,
        FlipGeometry {
            trafo_size,
            c_idx,
            x_c,
            y_c,
            bit_depth: PROVISIONAL_BIT_DEPTH,
            // The sign callback fires before `transform_skip_flag` is used to
            // report a level, so assume the transform path here; the level
            // callback overwrites this cost for every coefficient that carries
            // a sign.
            sample_domain: false,
        },
    )
}

#[derive(Clone, Copy, Debug)]
pub struct CostFactors {
    pub scale: f32,
    pub weight: f32,
}

type CostLutTable = [[[[[[CostFactors; 2]; 5]; 64]; 3]; 2]; 4];

/// Compile-time precomputed geometry cost lookup table (~120 KB).
/// Indexed by:
/// - `trafo_idx: 0..4` (TU size 4, 8, 16, 32)
/// - `is_chroma: 0..2` (0 luma, 1 chroma)
/// - `zero_axes: 0..3` (number of zero axes in (x_c == 0) + (y_c == 0))
/// - `manhattan_xy: 0..64` (clamped x_c + y_c)
/// - `bd_idx: 0..5` (bit_depth - 8 clamped to 0..4)
/// - `sample_domain: 0..2` (0 transform path, 1 sample domain)
const fn init_cost_lut() -> CostLutTable {
    let mut table = [[[[[[CostFactors {
        scale: 0.0,
        weight: 0.0,
    }; 2]; 5]; 64]; 3]; 2]; 4];
    let mut t = 0;
    while t < 4 {
        let n = match t {
            0 => 4.0f64,
            1 => 8.0f64,
            2 => 16.0f64,
            _ => 32.0f64,
        };
        let block_energy = 1.0 + 0.05 * (n / 4.0) * (n / 4.0);
        let mut c = 0;
        while c < 2 {
            let comp_factor = if c == 0 { 1.0f64 } else { 0.7f64 };
            let mut z = 0;
            while z < 3 {
                let gx_gy = match z {
                    2 => 1.0f64,
                    1 => core::f64::consts::SQRT_2,
                    _ => 2.0f64,
                };
                let mut m = 0;
                while m < 64 {
                    let freq_masking = 1.0 + (m as f64) * 0.35;
                    let mut bd = 0;
                    while bd < 5 {
                        let bd_shift = match bd {
                            0 => 1.0f64,
                            1 => 2.0f64,
                            2 => 4.0f64,
                            3 => 8.0f64,
                            _ => 16.0f64,
                        };
                        let mut sd = 0;
                        while sd < 2 {
                            let basis_peak = if sd == 1 { 1.0f64 } else { gx_gy / 64.0f64 };
                            let scale = (basis_peak / bd_shift) as f32;
                            let weight = (scale as f64 * scale as f64 * block_energy * comp_factor
                                / freq_masking) as f32;
                            table[t][c][z][m][bd][sd] = CostFactors { scale, weight };
                            sd += 1;
                        }
                        bd += 1;
                    }
                    m += 1;
                }
                z += 1;
            }
            c += 1;
        }
        t += 1;
    }
    table
}

pub static COST_GEOM_LUT: CostLutTable = init_cost_lut();

#[inline]
fn cost_from_dq(abs_level: u32, dq: f64, geom: FlipGeometry) -> f64 {
    let FlipGeometry {
        trafo_size,
        c_idx,
        x_c,
        y_c,
        bit_depth,
        sample_domain,
    } = geom;

    let trafo_idx = match trafo_size {
        4 => 0,
        8 => 1,
        16 => 2,
        32 => 3,
        _ => (trafo_size.trailing_zeros().saturating_sub(2) as usize).min(3),
    };
    let is_chroma = (c_idx != 0) as usize;
    let zero_axes = (x_c == 0) as usize + (y_c == 0) as usize;
    let manhattan_xy = ((x_c as usize) + (y_c as usize)).min(63);
    let bd_idx = (bit_depth.saturating_sub(8) as usize).min(4);
    let sd_idx = sample_domain as usize;

    let factors = COST_GEOM_LUT[trafo_idx][is_chroma][zero_axes][manhattan_xy][bd_idx][sd_idx];
    let dq_f32 = dq as f32;
    let peak_sample_delta = dq_f32 * factors.scale;
    let l2_cost = dq_f32 * dq_f32 * factors.weight;

    if peak_sample_delta > SAFE_MAX_SAMPLE_DELTA as f32 || abs_level > 4 {
        HIGH_DISPLACEMENT_PENALTY + (l2_cost as f64)
    } else {
        (l2_cost as f64).max(0.1)
    }
}

impl CabacRecorder {
    /// Create a new empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset for a new slice while keeping accumulated global slots or create fresh.
    ///
    /// `band` is the drift band of the picture this slice belongs to; it is
    /// stamped onto every slot the recorder produces, and the pool order in
    /// `embed_hevc` is derived from it.
    pub fn with_slice(slice_idx: usize, band: u8) -> Self {
        Self::with_slice_mode(slice_idx, band, RecordMode::Embed)
    }

    /// [`Self::with_slice`] with an explicit [`RecordMode`].
    pub fn with_slice_mode(slice_idx: usize, band: u8, mode: RecordMode) -> Self {
        CabacRecorder {
            ops: Vec::new(),
            slots: Vec::new(),
            substreams: Vec::new(),
            pending_signs: Vec::new(),
            mode,
            current_slice_idx: slice_idx,
            current_substream_idx: 0,
            current_band: band,
            next_pending_slot: 0,
        }
    }

    /// [`Self::with_slice_mode`] with capacity preallocated based on slice byte length.
    pub fn with_slice_capacity(
        slice_idx: usize,
        band: u8,
        mode: RecordMode,
        slice_len: usize,
    ) -> Self {
        let (ops_cap, slots_cap) = match mode {
            RecordMode::Embed => (slice_len.saturating_mul(18), slice_len),
            RecordMode::Slots => (0, slice_len),
        };
        CabacRecorder {
            ops: Vec::with_capacity(ops_cap),
            slots: Vec::with_capacity(slots_cap),
            substreams: Vec::with_capacity(1),
            pending_signs: if mode == RecordMode::Embed {
                Vec::with_capacity(slots_cap)
            } else {
                Vec::new()
            },
            mode,
            current_slice_idx: slice_idx,
            current_substream_idx: 0,
            current_band: band,
            next_pending_slot: 0,
        }
    }

    /// Number of slots awaiting level magnitude backfill.
    #[inline]
    pub fn next_pending_slot(&self) -> usize {
        self.next_pending_slot
    }

    /// Current recording mode.
    #[inline]
    pub fn mode(&self) -> RecordMode {
        self.mode
    }

    /// Clear pending coordinate metadata and reset magnitude backfill cursor.
    pub fn reset_pending(&mut self) {
        self.pending_signs.clear();
        self.next_pending_slot = 0;
    }

    /// Whether this recorder keeps the replayable bin journal.
    #[inline]
    fn journals(&self) -> bool {
        self.mode == RecordMode::Embed
    }

    /// Mark the beginning of a new substream.
    pub fn start_substream(
        &mut self,
        substream_idx: usize,
        rbsp_byte_start: usize,
        init_contexts: &[u8; ENCODER_CONTEXTS],
    ) {
        if let Some(prev) = self.substreams.last_mut() {
            prev.op_end = self.ops.len();
            prev.rbsp_byte_end = rbsp_byte_start;
        }
        self.current_substream_idx = substream_idx;
        self.substreams.push(SubstreamRecord {
            substream_idx,
            op_start: self.ops.len(),
            op_end: self.ops.len(),
            slot_start: self.slots.len(),
            init_contexts: *init_contexts,
            rbsp_byte_start,
            rbsp_byte_end: 0,
        });
    }

    /// Mark the end of the slice data.
    pub fn finish_slice(&mut self, rbsp_len: usize) {
        if let Some(prev) = self.substreams.last_mut() {
            prev.op_end = self.ops.len();
            prev.rbsp_byte_end = rbsp_len;
        }
    }

    /// Record a context decision bin.
    #[inline]
    pub fn record_decision(&mut self, ctx_idx: usize, bit: u32) {
        if self.journals() {
            self.ops.push(BinOp::decision(ctx_idx, bit as u8));
        }
    }

    /// Record a generic bypass bin (non-stego).
    #[inline]
    pub fn record_bypass(&mut self, bit: u32) {
        if self.journals() {
            self.ops.push(BinOp::bypass(bit as u8, false));
        }
    }

    /// Record a bypass sign bit as a potential stego slot.
    #[inline]
    pub fn record_stego_sign(
        &mut self,
        bit: u32,
        _qp: i32,
        trafo_size: u8,
        c_idx: u8,
        x_c: u8,
        y_c: u8,
    ) {
        let original_bit = bit as u8;
        let journals = self.journals();

        // DC coefficients (x_c == 0 && y_c == 0) never take part in embedding:
        // flipping a DC sign shifts the average level of the entire transform block,
        // causing severe reconstruction distortion and boundary discontinuities.
        if x_c == 0 && y_c == 0 {
            if journals {
                self.ops.push(BinOp::bypass(original_bit, false));
            }
            return;
        }

        debug_assert!(self.slots.len() <= u32::MAX as usize);
        debug_assert!(self.ops.len() <= u32::MAX as usize);
        let op_idx = self.ops.len() as u32;

        if journals {
            self.pending_signs.push(PendingSignInfo {
                trafo_size,
                c_idx,
                x_c,
                y_c,
            });
        }

        // Provisional cost: sign bins decode before their levels, so the real
        // magnitude is unknown here. `record_stego_level` unconditionally overwrites
        // this with the real distortion cost in the same coding group. Using
        // HIGH_DISPLACEMENT_PENALTY avoids millions of redundant powf evaluations
        // while safely penalising any incomplete slots if a slice is truncated.
        let cost = if journals {
            HIGH_DISPLACEMENT_PENALTY as f32
        } else {
            0.0
        };

        self.slots.push(StegoSlot {
            cost,
            op_idx,
            slice_idx: self.current_slice_idx as u32,
            substream_idx: self.current_substream_idx as u16,
            original_bit,
            _pad: 0,
        });

        if journals {
            self.ops.push(BinOp::bypass(original_bit, true));
        }
    }

    /// Back-fill the magnitude of the coefficient whose sign was just recorded,
    /// and replace the provisional cost with the real distortion estimate.
    ///
    /// The decoder reports one call per recorded sign, in coding-group order.
    /// DC `(0, 0)` signs never create a slot, and this method mirrors that skip
    /// on the same coordinate test, so the cursor stays aligned without any
    /// per-entry placeholder table.
    #[inline]
    pub fn record_stego_level(
        &mut self,
        x_c: u8,
        y_c: u8,
        abs_level: u32,
        abs_dq: i32,
        bit_depth: u8,
        sample_domain: bool,
    ) {
        if x_c == 0 && y_c == 0 {
            return;
        }
        // The magnitude only feeds the distortion cost, which is what the
        // trellis ranks slots by. A read-only pass never ranks anything, so it
        // skips the per-coefficient cost model (and its `powf`) entirely.
        if !self.journals() {
            return;
        }
        let Some(pending) = self.pending_signs.get(self.next_pending_slot) else {
            debug_assert!(false, "record_stego_level outran record_stego_sign");
            return;
        };
        debug_assert_eq!(
            (pending.x_c, pending.y_c),
            (x_c, y_c),
            "sign/level coordinate desync at slot {}",
            self.next_pending_slot
        );
        let cost = compute_sign_flip_cost(
            abs_level,
            abs_dq,
            FlipGeometry {
                trafo_size: pending.trafo_size,
                c_idx: pending.c_idx,
                x_c: pending.x_c,
                y_c: pending.y_c,
                bit_depth,
                sample_domain,
            },
        ) as f32;
        if let Some(slot) = self.slots.get_mut(self.next_pending_slot) {
            slot.cost = cost;
        }
        self.next_pending_slot += 1;
    }

    /// Record a terminate bin.
    #[inline]
    pub fn record_terminate(&mut self, bit: u32) {
        if self.journals() {
            self.ops.push(BinOp::terminate(bit as u8));
        }
    }
}

impl rusty_h265::observer::CabacObserver for CabacRecorder {
    fn start_substream(
        &mut self,
        substream_idx: usize,
        rbsp_byte_start: usize,
        init_contexts: &[u8; ENCODER_CONTEXTS],
    ) {
        self.start_substream(substream_idx, rbsp_byte_start, init_contexts);
    }

    fn finish_slice(&mut self, rbsp_len: usize) {
        self.finish_slice(rbsp_len);
    }

    fn record_decision(&mut self, ctx_idx: usize, bit: u32) {
        self.record_decision(ctx_idx, bit);
    }

    fn record_bypass(&mut self, bit: u32) {
        self.record_bypass(bit);
    }

    fn record_stego_sign(
        &mut self,
        bit: u32,
        qp: i32,
        trafo_size: u8,
        c_idx: u8,
        x_c: u8,
        y_c: u8,
    ) {
        self.record_stego_sign(bit, qp, trafo_size, c_idx, x_c, y_c);
    }

    fn record_stego_level(
        &mut self,
        x_c: u8,
        y_c: u8,
        abs_level: u32,
        abs_dq: i32,
        bit_depth: u8,
        sample_domain: bool,
    ) {
        self.record_stego_level(x_c, y_c, abs_level, abs_dq, bit_depth, sample_domain);
    }

    fn record_terminate(&mut self, bit: u32) {
        self.record_terminate(bit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Geometry shorthand: `(size, plane, x, y, depth, sample_domain)`.
    fn g(
        trafo_size: u8,
        c_idx: u8,
        x_c: u8,
        y_c: u8,
        bit_depth: u8,
        sample_domain: bool,
    ) -> FlipGeometry {
        FlipGeometry {
            trafo_size,
            c_idx,
            x_c,
            y_c,
            bit_depth,
            sample_domain,
        }
    }

    /// Sign bins decode before their levels: the recorder must pair each later
    /// `record_stego_level` with the slot created by the matching
    /// `record_stego_sign`, even though the DC sign in between creates no slot.
    #[test]
    fn level_backfill_stays_aligned_across_dc() {
        let mut rec = CabacRecorder::new();
        // (0,0) is DC: recorded as a bin, never as a slot.
        rec.record_stego_sign(0, 27, 8, 0, 0, 0);
        rec.record_stego_sign(1, 27, 8, 0, 2, 0);
        rec.record_stego_sign(0, 27, 8, 0, 3, 1);
        assert_eq!(rec.slots.len(), 2);
        // The DC sign is journaled as a plain bypass bin, the signs that own a
        // slot are flagged.
        assert!(rec.ops[0].is_bypass() && !rec.ops[0].is_stego());
        assert!(rec.ops[1].is_bypass() && rec.ops[1].is_stego());
        assert!(rec.ops[2].is_bypass() && rec.ops[2].is_stego());

        rec.record_stego_level(0, 0, 9, 700, 8, false);
        rec.record_stego_level(2, 0, 1, 42, 8, false);
        rec.record_stego_level(3, 1, 2, 84, 8, false);

        assert_eq!((rec.pending_signs[0].x_c, rec.pending_signs[0].y_c), (2, 0));
        assert_eq!((rec.pending_signs[1].x_c, rec.pending_signs[1].y_c), (3, 1));
        assert_eq!(
            rec.slots[0].cost,
            compute_sign_flip_cost(1, 42, g(8, 0, 2, 0, 8, false)) as f32
        );
        assert_eq!(
            rec.slots[1].cost,
            compute_sign_flip_cost(2, 84, g(8, 0, 3, 1, 8, false)) as f32
        );
    }

    /// The whole point of the model: cost must follow the decoded magnitude, not
    /// just the frequency position.
    #[test]
    fn cost_tracks_coefficient_magnitude() {
        let small = compute_sign_flip_cost(1, 40, g(8, 0, 2, 2, 8, false));
        let large = compute_sign_flip_cost(1, 400, g(8, 0, 2, 2, 8, false));
        // Cost is quadratic in the magnitude, so 10× the coefficient is 100× the
        // cost (asserted with slack for the frequency/energy factors).
        assert!(large > small * 50.0, "small={small} large={large}");

        // A flip that would move a sample by more than the soft limit must be
        // penalised, and the penalty must stay finite so the STC never sees
        // `INFINITY` for a slot it may still have to use.
        let huge = compute_sign_flip_cost(1, 10_000, g(32, 0, 1, 0, 8, false));
        assert!(huge.is_finite(), "penalty must be finite");
        assert!(huge >= HIGH_DISPLACEMENT_PENALTY);
    }

    /// Large coefficients are expensive regardless of geometry: they cannot be
    /// flipped without a visible step.
    #[test]
    fn large_level_is_penalised() {
        let cost = compute_sign_flip_cost(9, 40, g(8, 0, 3, 3, 8, false));
        assert!(cost >= HIGH_DISPLACEMENT_PENALTY);
    }

    /// Displacement is expressed in 8-bit levels, so the same dequantized value
    /// is 16× cheaper in energy at 10-bit.
    #[test]
    fn cost_normalises_bit_depth() {
        let eight = compute_sign_flip_cost(1, 90, g(8, 0, 2, 0, 8, false));
        let ten = compute_sign_flip_cost(1, 90, g(8, 0, 2, 0, 10, false));
        assert!((eight / ten - 16.0).abs() < 0.5, "eight={eight} ten={ten}");
    }

    /// A skipped 4×4 block at QP 32 reports 26 samples. The transform path would
    /// divide that by the basis peak and price it like a sub-sample error; the
    /// sample domain must not, because flipping the sign moves that residual
    /// sample by its full magnitude.
    #[test]
    fn sample_domain_skips_the_basis_peak() {
        let transform = compute_sign_flip_cost(2, 26, g(4, 0, 1, 1, 8, false));
        let skipped = compute_sign_flip_cost(2, 26, g(4, 0, 1, 1, 8, true));
        assert!(
            skipped > 500.0 * transform,
            "skipped={skipped} transform={transform}"
        );
        // 32x in amplitude is ~1000x in energy, before the masking factors.
        assert!(skipped.is_finite() && skipped < HIGH_DISPLACEMENT_PENALTY);
        // A one-sample residual stays a cheap slot, so skipped blocks are still
        // usable when a payload needs them.
        let tiny = compute_sign_flip_cost(1, 1, g(4, 0, 1, 1, 8, true));
        assert!(tiny < 10.0, "tiny={tiny}");
    }

    /// The packed journal must carry every field the re-encoder reads, with no
    /// aliasing between the kind bits and the payload bits.
    #[test]
    fn binop_packing_roundtrips() {
        for ctx in [0usize, 1, 63, 178, 4094] {
            for bit in [0u8, 1] {
                let op = BinOp::decision(ctx, bit);
                assert!(op.is_decision() && !op.is_bypass() && !op.is_terminate());
                assert_eq!(op.ctx_idx(), ctx);
                assert_eq!(op.bit(), bit);
                assert!(!op.is_stego(), "a decision bin is never a stego slot");
            }
        }
        for bit in [0u8, 1] {
            for stego in [false, true] {
                let op = BinOp::bypass(bit, stego);
                assert!(op.is_bypass() && !op.is_decision() && !op.is_terminate());
                assert_eq!(op.bit(), bit);
                assert_eq!(op.is_stego(), stego);
                assert_eq!(op.ctx_idx(), 0);
            }
            let op = BinOp::terminate(bit);
            assert!(op.is_terminate() && !op.is_decision() && !op.is_bypass());
            assert_eq!(op.bit(), bit);
            assert!(!op.is_stego());
        }
        // An index that does not fit the 12-bit field saturates instead of
        // wrapping into a *valid* context number.
        let saturated = BinOp::decision(0x1234, 0);
        assert!(saturated.is_decision());
        assert!(saturated.ctx_idx() >= ENCODER_CONTEXTS);
    }

    /// A read-only recorder keeps the slot signs but spends nothing on the
    /// journal, the cost model or the substream slot addresses.
    #[test]
    fn slots_mode_skips_the_journal() {
        let mut rec = CabacRecorder::with_slice_mode(0, 0, RecordMode::Slots);
        rec.start_substream(0, 0, &[0u8; ENCODER_CONTEXTS]);
        rec.record_decision(7, 1);
        rec.record_bypass(0);
        rec.record_stego_sign(1, 27, 8, 0, 2, 0);
        rec.record_stego_level(2, 0, 1, 42, 8, false);
        rec.record_terminate(1);
        rec.finish_slice(64);

        assert!(rec.ops.is_empty(), "no journal in slot-only mode");
        assert_eq!(rec.slots.len(), 1);
        assert_eq!(rec.slots[0].original_bit, 1);
        assert_eq!(rec.slots[0].cost, 0.0, "cost model is not run");
        assert_eq!(rec.substreams[0].slot_start, 0);

        // The embed mode must see exactly the same slot, with a real cost.
        let mut full = CabacRecorder::with_slice_mode(0, 0, RecordMode::Embed);
        full.start_substream(0, 0, &[0u8; ENCODER_CONTEXTS]);
        full.record_decision(7, 1);
        full.record_bypass(0);
        full.record_stego_sign(1, 27, 8, 0, 2, 0);
        full.record_stego_level(2, 0, 1, 42, 8, false);
        full.record_terminate(1);
        full.finish_slice(64);

        assert_eq!(full.slots[0].original_bit, rec.slots[0].original_bit);
        assert!(full.slots[0].cost > 0.0);
        assert_eq!(full.ops.len(), 4);
    }
}
