//! J-MiPOD: statistically-based distortion for JPEG images.
//!
//! Based on R. Cogranne, Q. Giboulot and P. Bas, "Steganography by Minimizing
//! Statistical Detectability: The cases of JPEG and Color Images", ACM
//! IH&MMSec 2020, and the authors' released implementation.
//!
//! # Pipeline (Algorithm 1)
//!
//! 1. **Spatial decompression**: dequantize and inverse-DCT the luminance
//!    component ([`super::precover::decompress_luma`]).
//! 2. **Pixel residual variances**: the MiPOD estimator from Section V, here
//!    with the released implementation's small `p = 3` / `l = 3` neighbourhood
//!    (the paper's text refers to the MiPOD estimator, whose recommended
//!    medium setting is `9 x 9`; both are self-consistent, `3 x 3` is
//!    markedly cheaper and matches the reference code). No `0.01` spatial
//!    floor: as Cogranne et al. warn, such a floor combined with `q_k^2`
//!    would assign overly high change probabilities to high-frequency
//!    coefficients of flat blocks. Only a `1e-6` numerical floor is kept.
//! 3. **Variance propagation to the 64 DCT modes (Eq. 8)**: under the
//!    independent spatial Gaussian model, the unquantized coefficient
//!    variances are `B^T S B` with `B = C ⊙ C`, then divided by `q_k^2` to
//!    obtain the quantized-coefficient variance. A `1e-5` floor (the
//!    released code's numerical guard) prevents `1 / sigma^4` from exploding.
//! 4. **Change rates / costs**: the Lagrange multiplier is calibrated over
//!    all AC coefficients to the reference payload `alpha` in **bits per
//!    non-zero AC coefficient** (`bpnzAC`, the J-UNIGRAM convention used by
//!    the released code), then converted to additive STC costs. DC is never
//!    embedded into and is priced wet.
//!
//! # Deviations from the released implementation (documented, not accidental)
//!
//! * No 3 x 3 post-filter on the Fisher map (the 2020 paper does not specify one).
//! * Wiener uses `w = 2` with Matlab `wiener2` zero-padding semantics.
//! * `alpha` is a reference rate only; JPEG extraction never computes costs.

use rayon::prelude::*;

use crate::stego::cost_calibration::fisher_to_costs;
use crate::stego::params::JpegParams;
use crate::stego::spatial_variance::estimate_variance;
use crate::stego::traits::{JpegCostModel, JpegGeometry};

use super::precover;

/// Side length of one DCT block.
const N: usize = 8;
/// Spatial variance block size (released implementation: `VarianceEstimationDCT2D(...,3,3)`).
const SPATIAL_P: usize = 3;
/// Spatial polynomial degree.
const SPATIAL_DEGREE: usize = 3;
/// Wiener window from the MiPOD/J-MiPOD references.
const WIENER_WINDOW: usize = 2;
/// Numerical-only spatial variance floor (paper: do not threshold).
const SPATIAL_VARIANCE_FLOOR: f64 = 1e-6;
/// Quantized-coefficient variance floor (released implementation).
const DCT_VARIANCE_FLOOR: f64 = 1e-5;
/// Reference payload in bits per non-zero AC coefficient.
const DEFAULT_TARGET_BPNZAC: f64 = 0.20;

pub struct JmipodCostModel;

impl Default for JmipodCostModel {
    fn default() -> Self {
        Self
    }
}

impl JpegCostModel for JmipodCostModel {
    fn id(&self) -> &'static str {
        "jmipod"
    }

    fn description(&self) -> &'static str {
        "J-MiPOD statistical DCT detectability model (Cogranne et al., ACM IH&MMSec 2020)"
    }

    fn compute_cost(
        &self,
        coeffs: &dct_io::JpegCoefficients,
        geometry: &JpegGeometry,
        params: &JpegParams,
    ) -> Vec<f64> {
        let total_blocks = coeffs.components.first().map_or(0, |c| c.blocks.len());
        if total_blocks == 0 {
            return Vec::new();
        }
        let wet = vec![params.wet_cost; total_blocks * 64];
        let Some((plane, pw, ph)) = precover::decompress_luma(coeffs, geometry) else {
            return wet;
        };
        if geometry.positions.len() != total_blocks || geometry.grid_w == 0 || geometry.grid_h == 0
        {
            return wet;
        }

        let spatial = estimate_variance(
            &plane,
            pw,
            ph,
            SPATIAL_P,
            SPATIAL_DEGREE,
            WIENER_WINDOW,
            SPATIAL_VARIANCE_FLOOR,
        );
        if spatial.is_empty() {
            return wet;
        }

        // Elementwise-squared DCT basis and squared quantization steps.
        let basis = precover::dct_basis();
        let mut bsq = [[0.0f64; N]; N];
        for (y, row) in bsq.iter_mut().enumerate() {
            for (v, cell) in row.iter_mut().enumerate() {
                *cell = basis[y][v] * basis[y][v];
            }
        }
        let q_sq: [f64; 64] = std::array::from_fn(|k| (geometry.luma_q[k].max(1) as f64).powi(2));

        let mut fisher = vec![0.0f64; total_blocks * 64];
        fisher
            .par_chunks_mut(64)
            .zip(geometry.positions.par_iter())
            .for_each(|(block_fi, &(r, c))| {
                let var_dct = propagate_block_variance(&spatial, pw, r, c, &bsq);
                // k = 0 (DC) stays inactive: no entropy contribution and the
                // caller prices it wet.
                for k in 1..64 {
                    let var_q = (var_dct[k] / q_sq[k]).max(DCT_VARIANCE_FLOOR);
                    block_fi[k] = 2.0 / (var_q * var_q);
                }
            });

        // Reference payload: bits per non-zero AC coefficient, as in the
        // released code. A fully flat carrier has no non-zero AC to count,
        // so fall back to the total AC count to keep a usable reference rate.
        let nz_ac: usize = coeffs.components[0]
            .blocks
            .iter()
            .map(|block| block[1..].iter().filter(|&&v| v != 0).count())
            .sum();
        let reference = if nz_ac > 0 { nz_ac } else { total_blocks * 63 };

        let alpha = params.model_option("alpha", DEFAULT_TARGET_BPNZAC);
        let alpha = if alpha.is_finite() {
            alpha.clamp(0.01, 0.90)
        } else {
            DEFAULT_TARGET_BPNZAC
        };
        let target_bits = alpha * reference as f64;

        drop(plane);
        drop(spatial);
        let mut costs = fisher_to_costs(fisher, target_bits);
        for bi in 0..total_blocks {
            costs[bi * 64] = params.wet_cost;
        }
        costs
    }
}

/// `Var(u_{v,u}) = sum_{y,x} C[y,v]^2 C[x,u]^2 sigma[y,x]^2`, natural order.
///
/// Kept as a named function so the unit test can compare it against the
/// explicit 64 x 64 DCT covariance diagonal.
fn propagate_block_variance(
    spatial: &[f64],
    pw: usize,
    r: usize,
    c: usize,
    bsq: &[[f64; N]; N],
) -> [f64; 64] {
    let y0 = r * N;
    let x0 = c * N;
    let mut mid = [[0.0f64; N]; N];
    for (y, mid_row) in mid.iter_mut().enumerate() {
        let row_off = (y0 + y) * pw + x0;
        for (u, cell) in mid_row.iter_mut().enumerate() {
            let mut sum = 0.0f64;
            for x in 0..N {
                sum += spatial[row_off + x] * bsq[x][u];
            }
            *cell = sum;
        }
    }
    let mut out = [0.0f64; 64];
    for v in 0..N {
        for u in 0..N {
            let mut var_dct = 0.0f64;
            for y in 0..N {
                var_dct += bsq[y][v] * mid[y][u];
            }
            out[v * N + u] = var_dct;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::jpeg::geometry::component_geometry;
    use dct_io::{ComponentCoefficients, ComponentInfo, JpegCoefficients, JpegInfo};

    fn squared_basis() -> [[f64; N]; N] {
        let basis = precover::dct_basis();
        let mut bsq = [[0.0f64; N]; N];
        for (y, row) in bsq.iter_mut().enumerate() {
            for (v, cell) in row.iter_mut().enumerate() {
                *cell = basis[y][v] * basis[y][v];
            }
        }
        bsq
    }

    /// Build a 2 x 2 block JPEG whose first three blocks are flat and whose
    /// last block carries strong AC texture.
    fn two_by_two() -> JpegCoefficients {
        let mut blocks = vec![[0i16; 64]; 4];
        for (k, cell) in blocks[3].iter_mut().enumerate().skip(1) {
            *cell = if k % 2 == 0 { 18 } else { -14 };
        }
        JpegCoefficients {
            components: vec![ComponentCoefficients { id: 1, blocks }],
        }
    }

    fn geometry_for(coeffs: &JpegCoefficients) -> JpegGeometry {
        let info = JpegInfo {
            width: 16,
            height: 16,
            components: vec![ComponentInfo {
                id: 1,
                h_samp: 1,
                v_samp: 1,
                block_count: coeffs.components[0].blocks.len(),
            }],
        };
        component_geometry(&info, 0, coeffs.components[0].blocks.len())
    }

    /// `B^T S B` must equal the diagonal of the explicit 64 x 64 DCT
    /// covariance transformation.
    #[test]
    fn separable_variance_propagation_matches_the_64x64_matrix() {
        let mut spatial = vec![0.0f64; 8 * 8];
        let mut state = 0x1234_5678u32;
        for v in spatial.iter_mut() {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *v = 1.0 + (state % 1000) as f64 / 100.0;
        }
        let bsq = squared_basis();
        let got = propagate_block_variance(&spatial, 8, 0, 0, &bsq);

        // Explicit 2-D DCT basis: D[(v,u), (y,x)] = C[y,v] * C[x,u].
        let basis = precover::dct_basis();
        let mut explicit = [0.0f64; 64];
        for v in 0..N {
            for u in 0..N {
                let mut sum = 0.0f64;
                for y in 0..N {
                    for x in 0..N {
                        let d = basis[y][v] * basis[x][u];
                        sum += d * d * spatial[y * N + x];
                    }
                }
                explicit[v * N + u] = sum;
            }
        }
        for k in 0..64 {
            assert!(
                (got[k] - explicit[k]).abs() < 1e-9 * explicit[k].abs().max(1.0),
                "k={k}: {} vs {}",
                got[k],
                explicit[k]
            );
        }
    }

    #[test]
    fn dc_is_wet_and_busy_blocks_are_cheaper_than_flat_blocks() {
        let coeffs = two_by_two();
        let geometry = geometry_for(&coeffs);
        let params = JpegParams::default();
        let costs = JmipodCostModel.compute_cost(&coeffs, &geometry, &params);
        assert_eq!(costs.len(), 4 * 64);
        for bi in 0..4 {
            assert_eq!(
                costs[bi * 64],
                params.wet_cost,
                "DC of block {bi} must be wet"
            );
        }
        assert!(costs.iter().all(|c| c.is_finite() && *c >= 0.0));

        // Mean AC cost: flat blocks 0..2 vs textured block 3.
        let flat: f64 = (0..3)
            .flat_map(|bi| (1..64).map(move |k| bi * 64 + k))
            .map(|i| costs[i])
            .sum::<f64>()
            / (3.0 * 63.0);
        let busy: f64 = (1..64).map(|k| costs[3 * 64 + k]).sum::<f64>() / 63.0;
        assert!(
            flat > busy * 2.0,
            "flat blocks must be more expensive (flat {flat}, busy {busy})"
        );
    }

    /// Within a busy block, the low-frequency mode (small quantization step)
    /// must be cheaper than the highest-frequency mode (largest step).
    #[test]
    fn high_frequency_modes_cost_more_than_low_frequency_modes() {
        let coeffs = two_by_two();
        let geometry = geometry_for(&coeffs);
        let params = JpegParams::default();
        let costs = JmipodCostModel.compute_cost(&coeffs, &geometry, &params);
        assert!(
            costs[3 * 64 + 1] < costs[3 * 64 + 63],
            "k=1 ({}) must be cheaper than k=63 ({})",
            costs[3 * 64 + 1],
            costs[3 * 64 + 63]
        );
    }

    #[test]
    fn cost_map_is_deterministic() {
        let coeffs = two_by_two();
        let geometry = geometry_for(&coeffs);
        let params = JpegParams::default();
        let a = JmipodCostModel.compute_cost(&coeffs, &geometry, &params);
        let b = JmipodCostModel.compute_cost(&coeffs, &geometry, &params);
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.to_bits(), y.to_bits());
        }
    }
}
