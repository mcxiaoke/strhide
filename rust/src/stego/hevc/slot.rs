//! HEVC CABAC Steganography Slot and Bin Recording Types.

use alloc::vec::Vec;

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
    /// Initial CABAC context model for this substream (179 bytes).
    pub init_contexts: [u8; rust_h265::HEVC_CONTEXTS],
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
        }
    }

    /// Mark the beginning of a new substream.
    pub fn start_substream(
        &mut self,
        substream_idx: usize,
        rbsp_byte_start: usize,
        init_contexts: &[u8; rust_h265::HEVC_CONTEXTS],
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
        let slot_idx = self.slots.len();
        let op_idx = self.ops.len();
        let original_bit = bit as u8;

        // Content-adaptive distortion cost model:
        // Higher frequencies (x_c + y_c large) have lower distortion cost.
        // Chroma components have slightly lower distortion cost than Luma.
        let freq_dist = (x_c + y_c) as f64;
        let freq_factor = 1.0 / (1.0 + freq_dist * 0.35);
        let comp_factor = if c_idx == 0 { 1.0 } else { 0.7 };
        let cost = (10.0 * freq_factor * comp_factor).max(0.1);

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

    /// Record a terminate bin.
    #[inline]
    pub fn record_terminate(&mut self, bit: u32) {
        self.ops.push(BinOp::Terminate { bit: bit as u8 });
    }
}

impl rust_h265::CabacObserver for CabacRecorder {
    fn start_substream(
        &mut self,
        substream_idx: usize,
        rbsp_byte_start: usize,
        init_contexts: &[u8; rust_h265::HEVC_CONTEXTS],
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

    fn record_terminate(&mut self, bit: u32) {
        self.record_terminate(bit);
    }
}
