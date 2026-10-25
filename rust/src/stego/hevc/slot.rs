//! HEVC CABAC Steganography Slot and Bin Recording Types.

use alloc::vec::Vec;

use rusty_h265::observer::ENCODER_CONTEXTS;

/// A recorded CABAC arithmetic decoding operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    /// Context-mode decision bin.
    Decision { ctx_idx: u16, bit: u8 },
    /// Equiprobable bypass bin.
    Bypass { bit: u8, slot_idx: Option<usize> },
    /// End-of-slice or end-of-substream terminate bin.
    Terminate { bit: u8 },
}

/// A candidate steganographic slot corresponding to an in-place CABAC bypass sign bit.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StegoSlot {
    /// Global index across all slices in the carrier.
    pub slot_idx: usize,
    /// 0-based slice index within the carrier.
    pub slice_idx: usize,
    /// Substream index within the slice.
    pub substream_idx: usize,
    /// Index in the slice's recorded `BinOp` sequence.
    pub op_idx: usize,
    /// Original sign bit (0 = positive, 1 = negative).
    pub original_bit: u8,
    /// Slice or block quantization parameter (QP).
    pub qp: i32,
    /// Transform unit size (4, 8, 16, 32).
    pub trafo_size: u8,
    /// Color plane index (0: Luma Y, 1: Cb, 2: Cr).
    pub c_idx: u8,
    /// 2D coordinate inside the transform unit.
    pub x_c: u8,
    pub y_c: u8,
    /// Perceptual distortion cost for STC matrix coding.
    pub cost: f64,
}

/// Metadata and boundaries for a WPP/Tile substream within a slice.
#[derive(Clone, Debug)]
pub struct SubstreamRecord {
    pub substream_idx: usize,
    /// Offset in the slice's `ops` Vec where this substream starts.
    pub op_start: usize,
    /// Offset in the slice's `ops` Vec where this substream ends.
    pub op_end: usize,
    /// Initial CABAC context model for this substream (179 bytes: the native
    /// decoder states widened to the encoder's slot layout).
    pub init_contexts: [u8; ENCODER_CONTEXTS],
    /// Byte offset in the RBSP where this substream starts.
    pub rbsp_byte_start: usize,
    /// Byte offset in the RBSP where this substream ends.
    pub rbsp_byte_end: usize,
}

/// Recorder attached to the CABAC decoding loop to capture the bin stream
/// and isolate stego sign positions for re-encoding.
#[derive(Default, Clone, Debug)]
pub struct CabacRecorder {
    /// Full sequence of CABAC bins in decode order.
    pub ops: Vec<BinOp>,
    /// Isolated steganographic bypass sign slots.
    pub slots: Vec<StegoSlot>,
    /// Substream boundaries and initial contexts.
    pub substreams: Vec<SubstreamRecord>,
    /// Current slice index being decoded.
    pub current_slice_idx: usize,
    /// Current substream index.
    pub current_substream_idx: usize,
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
const HIGH_DISPLACEMENT_PENALTY: f64 = 1_000_000.0;

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
    let n = trafo_size.max(4) as f64;

    let gx = if x_c == 0 {
        1.0
    } else {
        core::f64::consts::SQRT_2
    };
    let gy = if y_c == 0 {
        1.0
    } else {
        core::f64::consts::SQRT_2
    };
    // Transform path: the coefficient is spread over the block by the inverse
    // basis, whose peak is 64 (DC) / 64·√2 (any other frequency).
    // Sample domain (transform skip or transquant bypass): the coefficient *is*
    // a residual sample, so the whole block basis gain is absent and dividing
    // by 64 would price it ~32x too cheap -- exactly the case a skipped 4x4
    // block at QP 32 hits, where a 26-sample error looked as harmless as a
    // sub-sample one.
    let basis_peak = if sample_domain { 1.0 } else { gx * gy / 64.0 };
    let peak_sample_delta = dq * basis_peak / 2f64.powi(bit_depth as i32 - 8);

    // Whole-block energy term: a large TU spreads the same error over more
    // samples, so its PSNR cost is lower per flipped sign than a small TU's.
    let block_energy = 1.0 + 0.05 * (n / 4.0) * (n / 4.0);
    // High frequencies and chroma carry less visible error.
    let freq_masking = 1.0 + ((x_c + y_c) as f64) * 0.35;
    let comp_factor = if c_idx == 0 { 1.0 } else { 0.7 };
    let l2_cost = peak_sample_delta * peak_sample_delta * block_energy * comp_factor / freq_masking;

    if peak_sample_delta > SAFE_MAX_SAMPLE_DELTA || abs_level > 4 {
        HIGH_DISPLACEMENT_PENALTY + l2_cost
    } else {
        l2_cost.max(0.1)
    }
}

impl CabacRecorder {
    /// Create a new empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset for a new slice while keeping accumulated global slots or create fresh.
    pub fn with_slice(slice_idx: usize) -> Self {
        CabacRecorder {
            ops: Vec::new(),
            slots: Vec::new(),
            substreams: Vec::new(),
            current_slice_idx: slice_idx,
            current_substream_idx: 0,
            next_pending_slot: 0,
        }
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
        self.ops.push(BinOp::Decision {
            ctx_idx: ctx_idx as u16,
            bit: bit as u8,
        });
    }

    /// Record a generic bypass bin (non-stego).
    #[inline]
    pub fn record_bypass(&mut self, bit: u32) {
        self.ops.push(BinOp::Bypass {
            bit: bit as u8,
            slot_idx: None,
        });
    }

    /// Record a bypass sign bit as a potential stego slot.
    #[inline]
    pub fn record_stego_sign(
        &mut self,
        bit: u32,
        qp: i32,
        trafo_size: u8,
        c_idx: u8,
        x_c: u8,
        y_c: u8,
    ) {
        let original_bit = bit as u8;

        // DC coefficients (x_c == 0 && y_c == 0) never take part in embedding:
        // flipping a DC sign shifts the average level of the entire transform block,
        // causing severe reconstruction distortion and boundary discontinuities.
        if x_c == 0 && y_c == 0 {
            self.ops.push(BinOp::Bypass {
                bit: original_bit,
                slot_idx: None,
            });
            return;
        }

        let slot_idx = self.slots.len();
        let op_idx = self.ops.len();

        // Provisional cost: sign bins decode before their levels, so the real
        // magnitude is unknown here. `record_stego_level` overwrites this in the
        // same coding group.
        let cost = provisional_sign_flip_cost(1, qp, trafo_size, c_idx, x_c, y_c);

        self.slots.push(StegoSlot {
            slot_idx,
            slice_idx: self.current_slice_idx,
            substream_idx: self.current_substream_idx,
            op_idx,
            original_bit,
            qp,
            trafo_size,
            c_idx,
            x_c,
            y_c,
            cost,
        });

        self.ops.push(BinOp::Bypass {
            bit: original_bit,
            slot_idx: Some(slot_idx),
        });
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
        let Some(slot) = self.slots.get_mut(self.next_pending_slot) else {
            debug_assert!(false, "record_stego_level outran record_stego_sign");
            return;
        };
        debug_assert_eq!(
            (slot.x_c, slot.y_c),
            (x_c, y_c),
            "sign/level coordinate desync at slot {}",
            self.next_pending_slot
        );
        slot.cost = compute_sign_flip_cost(
            abs_level,
            abs_dq,
            FlipGeometry {
                trafo_size: slot.trafo_size,
                c_idx: slot.c_idx,
                x_c: slot.x_c,
                y_c: slot.y_c,
                bit_depth,
                sample_domain,
            },
        );
        self.next_pending_slot += 1;
    }

    /// Record a terminate bin.
    #[inline]
    pub fn record_terminate(&mut self, bit: u32) {
        self.ops.push(BinOp::Terminate { bit: bit as u8 });
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
        assert!(matches!(rec.ops[0], BinOp::Bypass { slot_idx: None, .. }));

        rec.record_stego_level(0, 0, 9, 700, 8, false);
        rec.record_stego_level(2, 0, 1, 42, 8, false);
        rec.record_stego_level(3, 1, 2, 84, 8, false);

        assert_eq!((rec.slots[0].x_c, rec.slots[0].y_c), (2, 0));
        assert_eq!((rec.slots[1].x_c, rec.slots[1].y_c), (3, 1));
        assert_eq!(
            rec.slots[0].cost,
            compute_sign_flip_cost(1, 42, g(8, 0, 2, 0, 8, false))
        );
        assert_eq!(
            rec.slots[1].cost,
            compute_sign_flip_cost(2, 84, g(8, 0, 3, 1, 8, false))
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
}
