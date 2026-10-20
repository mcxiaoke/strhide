//! Abstract traits for spatial and transform-domain steganography algorithms.
//!
//! Decoupled to allow adding new distortion functions (e.g. S-UNIWARD,
//! J-UNIWARD) or fine-tuning existing ones without affecting the embedding
//! engines.

use crate::stego::params::{JpegParams, SpatialParams};

/// Trait implemented by spatial-domain distortion cost models (e.g. HILL, WOW).
pub trait SpatialCostModel: Send + Sync {
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
        params: &SpatialParams,
    ) -> Vec<f64>;

    /// Split the symmetric cost map into `(rho_plus, rho_minus)`.
    ///
    /// `rho_plus[i]` / `rho_minus[i]` cost raising / lowering pixel `i` by one.
    /// Only the *direction* choice inside a Hamming/STC block uses these; slot
    /// ranking always uses `base`, so an asymmetric model can never change
    /// which slots the extractor picks. The default is symmetric.
    ///
    /// `channel` is the byte offset the engine embeds into, so a model that
    /// wants a local reference (e.g. the neighborhood mean) reads the same
    /// plane the writer modifies.
    fn direction_costs(
        &self,
        base: &[f64],
        _pixels: &[u8],
        _width: usize,
        _height: usize,
        _channels: usize,
        _channel: usize,
    ) -> (Vec<f64>, Vec<f64>) {
        (base.to_vec(), base.to_vec())
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
