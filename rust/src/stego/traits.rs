//! Abstract traits for spatial and transform-domain steganography algorithms.
//!
//! Decoupled to allow adding new distortion functions (e.g. S-UNIWARD,
//! J-UNIWARD) or fine-tuning existing ones without affecting the embedding
//! engines.

use crate::stego::params::{JpegParams, PngParams};

/// Trait implemented by spatial-domain distortion cost models (e.g. HILL, WOW).
pub trait PngCostModel: Send + Sync {
    /// Unique identifier for the algorithm (e.g. "hill", "wow").
    fn id(&self) -> &'static str;

    /// Human-readable algorithm name and reference.
    fn description(&self) -> &'static str;

    /// Compute per-pixel distortion cost map.
    ///
    /// - `pixels`: Grayscale or color plane pixel values in [0, 255].
    /// - `width`: Image width in pixels.
    /// - `height`: Image height in pixels.
    /// - `channels`: Number of color channels (1 for grayscale, 3 for RGB, 4 for RGBA).
    /// - `params`: Tunable algorithm parameters (filters, window sizes, sensitivities).
    ///
    /// Returns a flat vector of length `width * height`, representing the cost of changing
    /// each pixel (+1 or -1). Higher cost indicates sensitive/smooth areas that should
    /// NOT be modified; lower cost indicates complex textures ideal for hiding data.
    fn compute_cost(
        &self,
        pixels: &[u8],
        width: usize,
        height: usize,
        channels: usize,
        params: &PngParams,
    ) -> Vec<f64>;

    /// Per-slot directional costs `(rho_plus, rho_minus)` for the requested
    /// pixel indices.
    ///
    /// `slots` lists **pixel indices** (into the `width * height` plane of
    /// `channel`), and both returned vectors have exactly `slots.len()`
    /// entries in the same order. `rho_plus[i]` / `rho_minus[i]` cost raising
    /// / lowering that pixel by one. Only the *direction* choice inside a
    /// Hamming/STC block uses these; slot ranking always uses `base`, so an
    /// asymmetric model can never change which slots the extractor picks.
    /// The default is symmetric: both directions reuse `base`.
    ///
    /// Taking a slot list instead of materializing full-plane maps keeps the
    /// working set proportional to the payload, not the carrier: a 50 MP
    /// embed needs a few thousand directional values, not two 400 MB planes
    /// per channel (the same reasoning the JPEG side applies to its bias
    /// vector in [`JpegCostModel::bias`]).
    ///
    /// `channel` is the byte offset the engine embeds into, so a model that
    /// wants a local reference (e.g. the neighborhood mean) reads the same
    /// plane the writer modifies.
    #[allow(clippy::too_many_arguments)]
    fn direction_costs(
        &self,
        base: &[f64],
        _pixels: &[u8],
        _width: usize,
        _height: usize,
        _channels: usize,
        _channel: usize,
        slots: &[usize],
    ) -> (Vec<f64>, Vec<f64>) {
        (
            slots.iter().map(|&i| base[i]).collect(),
            slots.iter().map(|&i| base[i]).collect(),
        )
    }
}

/// Trait implemented by JPEG DCT domain distortion cost models (e.g. UERD, J-UNIWARD).
pub trait JpegCostModel: Send + Sync {
    /// Unique identifier for the algorithm (e.g. "uerd", "juniward").
    fn id(&self) -> &'static str;

    /// Human-readable algorithm name and reference.
    fn description(&self) -> &'static str;

    /// Compute per-coefficient distortion cost given parsed JPEG coefficients.
    ///
    /// - `coeffs`: Quantized DCT coefficients from baseline JPEG.
    /// - `geometry`: Block-grid geometry of the component being embedded into
    ///   (see [`JpegGeometry`]); built by the engine from the same file.
    /// - `params`: Tunable JPEG algorithm parameters (neighborhood weights).
    ///
    /// Returns a flat vector where each entry corresponds to an eligible AC coefficient,
    /// indicating its modification cost.
    fn compute_cost(
        &self,
        coeffs: &dct_io::JpegCoefficients,
        geometry: &JpegGeometry,
        params: &JpegParams,
    ) -> Vec<f64>;

    /// Per-coefficient directional bias for ternary embedding.
    ///
    /// Returns `None` when the model has no directional preference, in which
    /// case both moves are priced at [`JpegCostModel::compute_cost`]. Otherwise
    /// the vector has the same layout as `compute_cost`
    /// (`bias[bi * 64 + k]`) and each entry says which of the two moves is the
    /// less detectable one:
    ///
    /// * `+1` — raising the coefficient by one is the cheaper direction;
    /// * `-1` — lowering it is the cheaper direction;
    /// * `0` — no preference; both directions stay symmetric.
    ///
    /// The engine discounts the preferred direction by
    /// [`JpegParams::polarize_weight`] and leaves the other at the symmetric
    /// cost, so `1.0` disables the whole mechanism.
    ///
    /// # Why a bias vector and not `(rho_plus, rho_minus)`
    ///
    /// A full pair costs `16` bytes per coefficient. JPEG carriers reach 100 MP
    /// (`block_count * 64` = ~6.3M coefficients), where the symmetric cost map
    /// alone is already ~50 MB; two more maps would triple the working set that
    /// [`JpegParams::effective_slot_budget`] and the preflight ceiling are sized
    /// against. A sign per coefficient is 16x smaller and expresses everything
    /// the polarization family of models needs.
    ///
    /// # Embed-side only
    ///
    /// Extraction never computes costs (JPEG slots are geometric and keyed), so
    /// a model may derive the bias from cover information the extractor could
    /// not reproduce -- which is exactly what makes polarization free.
    fn direction_bias(
        &self,
        _coeffs: &dct_io::JpegCoefficients,
        _geometry: &JpegGeometry,
        _params: &JpegParams,
    ) -> Option<Vec<i8>> {
        None
    }
}

/// Block-grid geometry of the component a [`JpegCostModel`] embeds into.
///
/// `dct-io` hands out each component's blocks in **MCU-interleaved** order
/// (see [`crate::stego::jpeg::geometry`]), so a neighbourhood-based cost
/// model needs the index -> (row, col) mapping; a grid width alone is not
/// enough, and neither `ceil(sqrt(n))` nor `ceil(width/8)` reproduces the
/// true layout for 4:2:0 carriers.
#[derive(Debug, Clone)]
pub struct JpegGeometry {
    /// Grid width in blocks of the component's MCU-padded block grid.
    pub grid_w: usize,
    /// Grid height in blocks. May exceed `ceil(height/8)`: the final MCU row
    /// is padded, and `dct-io` decodes those padding blocks as well.
    pub grid_h: usize,
    /// Block index -> (row, col) inside the padded grid, in the decoder's
    /// block order. Same length as the component's block array.
    pub positions: Vec<(usize, usize)>,
    /// The file's own luminance quantization table in natural order, resolved
    /// by the engine (Annex K standard table as fallback).
    pub luma_q: [u16; 64],
}
