//! MiPOD: Minimising the Power of Optimal Detector (spatial domain).
//!
//! Based on V. Sedighi, R. Cogranne and J. Fridrich, "Content-Adaptive
//! Steganography by Minimizing Statistical Detectability", IEEE Transactions
//! on Information Forensics and Security, vol. 11, no. 2, pp. 221-234, 2016.
//!
//! # Pipeline
//!
//! 1. **Class-masked luminance** (`pixel & 0xF8`), exactly like
//!    [`super::hill::HillCostModel`] and [`super::suniward::SuniwardCostModel`].
//!    The PNG engine only moves pixels inside their eight-value class, so the
//!    masked plane is bit-identical between cover and stego and the extractor
//!    rebuilds the same slot ranking.
//! 2. **Wiener residual** with the paper's fixed `w = 2` window.
//! 3. **Pixelwise local cosine model** (`p = 9`, degree `l = 9`, `q = 45`
//!    basis functions, `36` degrees of freedom) via the shared separable
//!    estimator, variance floor `0.01` (Eq. 27).
//! 4. **Fisher information** `I_n = 2 / sigma_n^4`, smoothed with the
//!    7 x 7 moving average recommended in Section VI-F.
//! 5. **Cost conversion**: `beta_n` and the Lagrange multiplier solve
//!    `ln((1 - 2 beta_n)/beta_n) = 2 lambda I_n beta_n` under the ternary
//!    entropy constraint, converted to additive STC costs
//!    `rho_n = ln(1/beta_n - 2)`.
//!
//! # The `alpha` knob
//!
//! `alpha` (bits per pixel, default `0.20`) is only the *reference payload*
//! the Lagrange multiplier is calibrated for: MiPOD costs depend on the
//! payload, and the engine does not hand the real payload to a cost model.
//! Because `rho` is a strictly increasing function of `I` for every positive
//! `lambda` (see [`crate::stego::cost_calibration`]), changing `alpha`
//! rescales costs without changing their order. Extraction therefore does
//! not need `alpha` (it is not carried in the feature word) and cannot
//! desynchronise because of it.

use rayon::prelude::*;

use crate::stego::cost_calibration::fisher_to_costs;
use crate::stego::params::PngParams;
use crate::stego::spatial_variance::{box_smooth, estimate_variance};
use crate::stego::traits::PngCostModel;

/// Block size `p` of the local cosine model (paper "medium" setting).
const BLOCK_P: usize = 9;
/// Polynomial degree `l` (`q = l(l+1)/2 = 45`).
const DEGREE: usize = 9;
/// Wiener window from Section V of the paper (`w = 2`, fixed).
const WIENER_WINDOW: usize = 2;
/// Variance floor from Eq. (27).
const VARIANCE_FLOOR: f64 = 0.01;
/// Fisher-information smoothing window from Section VI-F.
const FI_SMOOTH_WINDOW: usize = 7;
/// Reference payload in bits per pixel used to calibrate `lambda`.
const DEFAULT_TARGET_BPP: f64 = 0.20;

pub struct MipodCostModel;

impl Default for MipodCostModel {
    fn default() -> Self {
        Self
    }
}

impl PngCostModel for MipodCostModel {
    fn id(&self) -> &'static str {
        "mipod"
    }

    fn description(&self) -> &'static str {
        "MiPOD statistical detectability model (Sedighi et al., IEEE TIFS 2016)"
    }

    fn compute_cost(
        &self,
        pixels: &[u8],
        width: usize,
        height: usize,
        channels: usize,
        params: &PngParams,
    ) -> Vec<f64> {
        let (w, h) = (width, height);
        if w == 0 || h == 0 || pixels.is_empty() || pixels.len() < w * h * channels {
            return Vec::new();
        }

        let plane = class_masked_luminance(pixels, w, h, channels);
        let mut variances =
            estimate_variance(&plane, w, h, BLOCK_P, DEGREE, WIENER_WINDOW, VARIANCE_FLOOR);
        drop(plane);
        if variances.is_empty() {
            return Vec::new();
        }

        // I = 2 / sigma^4, in place.
        variances
            .par_iter_mut()
            .for_each(|var| *var = 2.0 / (*var * *var));
        let smoothed = box_smooth(variances, w, h, FI_SMOOTH_WINDOW);

        let alpha = params.model_option("alpha", DEFAULT_TARGET_BPP);
        let alpha = if alpha.is_finite() {
            alpha.clamp(0.01, 0.90)
        } else {
            DEFAULT_TARGET_BPP
        };
        let target_bits = alpha * (w * h) as f64;
        fisher_to_costs(smoothed, target_bits)
    }
}

/// Grayscale plane built from the invariant class bits of each channel.
///
/// The same reduction HILL and S-UNIWARD use, so switching cost models does
/// not silently change which pixels are considered textured.
fn class_masked_luminance(pixels: &[u8], w: usize, h: usize, channels: usize) -> Vec<f64> {
    let n = w * h;
    let mut plane = vec![0.0f64; n];
    if channels == 1 {
        for (dst, &src) in plane.iter_mut().zip(pixels.iter()) {
            *dst = (src & 0xF8) as f64;
        }
    } else if channels >= 3 {
        for (i, dst) in plane.iter_mut().enumerate() {
            let r = (pixels[i * channels] & 0xF8) as f64;
            let g = (pixels[i * channels + 1] & 0xF8) as f64;
            let b = (pixels[i * channels + 2] & 0xF8) as f64;
            *dst = 0.299 * r + 0.587 * g + 0.114 * b;
        }
    } else {
        for (dst, chunk) in plane.iter_mut().zip(pixels.chunks(channels)) {
            *dst = (chunk[0] & 0xF8) as f64;
        }
    }
    plane
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic texture: flat on the left, checkerboard on the right.
    fn flat_and_textured(w: usize, h: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(w * h);
        for y in 0..h {
            for x in 0..w {
                out.push(if x < w / 2 {
                    128
                } else if (x + y) % 2 == 0 {
                    200
                } else {
                    56
                });
            }
        }
        out
    }

    fn texture_rgb(w: usize, h: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(w * h * 3);
        let mut state = 0x1234_5678u32;
        for i in 0..h {
            for j in 0..w {
                for c in 0..3 {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    let base = ((i * 255 / h.max(1)) + (j * 255 / w.max(1))) / 2;
                    let noise = ((state >> 24) & 0x0F) as usize;
                    out.push((base + noise + c * 3).min(255) as u8);
                }
            }
        }
        out
    }

    #[test]
    fn flat_regions_cost_more_than_textured_regions() {
        let (w, h) = (32, 32);
        let pixels = flat_and_textured(w, h);
        let model = MipodCostModel;
        let costs = model.compute_cost(&pixels, w, h, 1, &PngParams::default());
        assert_eq!(costs.len(), w * h);
        assert!(costs.iter().all(|c| c.is_finite() && *c >= 0.0));

        let flat = costs[16 * w + 4];
        let textured = costs[16 * w + 24];
        assert!(
            flat > textured * 2.0,
            "flat region cost ({flat}) must clearly exceed textured ({textured})"
        );
    }

    /// The cost map must be bit-identical after every eligible pixel moves
    /// inside its eight-value class; extraction depends on it.
    #[test]
    fn cost_map_is_invariant_under_class_internal_moves() {
        let (w, h) = (64, 48);
        let cover = texture_rgb(w, h);
        let model = MipodCostModel;
        let params = PngParams::default();
        let base_cover = model.compute_cost(&cover, w, h, 3, &params);

        let mut stego = cover.clone();
        let mut moved = 0usize;
        for i in (0..w * h).step_by(3) {
            let idx = i * 3 + 1;
            let v = stego[idx];
            if !(8..=247).contains(&v) {
                continue;
            }
            let residue = v % 8;
            let next = if residue == 0 {
                v + 1
            } else if residue == 7 {
                v - 1
            } else if i % 2 == 0 {
                v + 1
            } else {
                v - 1
            };
            assert_eq!(v & 0xF8, next & 0xF8, "test setup must stay in class");
            stego[idx] = next;
            moved += 1;
        }
        assert!(moved > 100, "test needs a meaningful number of moves");

        let base_stego = model.compute_cost(&stego, w, h, 3, &params);
        assert_eq!(base_cover.len(), base_stego.len());
        for (i, (a, b)) in base_cover.iter().zip(base_stego.iter()).enumerate() {
            assert_eq!(
                a.to_bits(),
                b.to_bits(),
                "pixel {i}: cost map changed after a class-internal move"
            );
        }
    }

    /// The reference payload only rescales costs; it must not reorder them.
    #[test]
    fn reference_payload_does_not_reorder_costs() {
        let (w, h) = (48, 48);
        let pixels = texture_rgb(w, h);
        let model = MipodCostModel;

        let mut low = PngParams::default();
        low.algorithm_options.insert("alpha".into(), 0.05);
        let mut high = PngParams::default();
        high.algorithm_options.insert("alpha".into(), 0.80);

        let a = model.compute_cost(&pixels, w, h, 3, &low);
        let b = model.compute_cost(&pixels, w, h, 3, &high);
        let mut ia: Vec<usize> = (0..a.len()).collect();
        ia.sort_unstable_by(|&i, &j| a[i].total_cmp(&a[j]));
        for w in ia.windows(2) {
            assert!(
                b[w[0]] <= b[w[1]],
                "alpha changed the slot order at {} / {}",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn short_buffers_are_rejected_without_panicking() {
        let model = MipodCostModel;
        let short = vec![128u8; 16 * 16 * 3 - 7];
        assert!(
            model
                .compute_cost(&short, 16, 16, 3, &PngParams::default())
                .is_empty()
        );
    }
}
