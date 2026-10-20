//! Abstract traits for spatial and transform-domain steganography algorithms.
//!
//! Decoupled to allow adding new distortion functions (e.g. S-UNIWARD, WOW, J-UNIWARD)
//! or fine-tuning existing ones without affecting the embedding engines.

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
    /// - `params`: Tunable JPEG algorithm parameters (neighborhood weights, DC weights).
    ///
    /// Returns a flat vector where each entry corresponds to an eligible AC coefficient,
    /// indicating its modification cost.
    fn compute_cost(&self, coeffs: &dct_io::JpegCoefficients, params: &JpegParams) -> Vec<f64>;
}
