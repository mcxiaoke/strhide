//! J-UNIWARD: JPEG-domain Universal Wavelet Relative Distortion.
//!
//! Based on V. Holub, J. Fridrich and T. Denemark, "Universal distortion
//! function for steganography in an arbitrary domain", EURASIP Journal on
//! Information Security, 2014.
//!
//! # The idea
//!
//! Distortion is measured in the wavelet domain, relative to the cover's own
//! wavelet content: a change is cheap where the cover already has strong
//! wavelet energy (texture, edges) and expensive where it has none (flat areas).
//! A DCT coefficient change of `±1` perturbs a whole spatial block, so the
//! distortion of one coefficient is a sum over the wavelet response of that
//! perturbation, weighted by how little wavelet energy the cover has there.
//!
//! # Cost
//!
//! The inner sum has a 23x23 support per coefficient and cannot be factorised:
//! the weight is `1 / (|residual| + sigma)`, which varies per position, so the
//! absolute-value kernel (`|u ⊗ v|`) never collapses into two 1D passes the way
//! the residual itself does. That is why J-UNIWARD is roughly two orders of
//! magnitude more expensive than UERD, and why it is a comparison model rather
//! than a default. Measured cost is documented in the assessment doc.
//!
//! The model is symmetric: `|ΔR|` is unchanged when the sign of the change
//! flips, so both directions cost the same and no [`JpegCostModel::direction_bias`]
//! is provided.

use crate::stego::params::JpegParams;
use crate::stego::traits::{JpegCostModel, JpegGeometry};
use crate::stego::wavelet;

use super::precover;

pub struct JuniwardCostModel;

impl Default for JuniwardCostModel {
    fn default() -> Self {
        Self
    }
}

/// Stabilising constant, `2^-6` as in the paper.
///
/// Overridable through [`JpegParams::algorithm_options`] under the key `sigma`.
const DEFAULT_SIGMA: f64 = 1.0 / 64.0;

/// Side length of one DCT block.
const N: usize = 8;
/// Support of the distortion sum along one axis: `N + TAPS - 1`.
const SUPPORT: usize = N + wavelet::TAPS - 1;
/// First offset of the support relative to the block origin, `-(TAPS/2 - 1)`.
const SUPPORT_START: isize = -(wavelet::HALF as isize - 1);

impl JpegCostModel for JuniwardCostModel {
    fn id(&self) -> &'static str {
        "juniward"
    }

    fn description(&self) -> &'static str {
        "J-UNIWARD wavelet-relative distortion model (EURASIP JIS 2014)"
    }

    fn compute_cost(
        &self,
        coeffs: &dct_io::JpegCoefficients,
        geometry: &JpegGeometry,
        params: &JpegParams,
    ) -> Vec<f64> {
        let total_blocks = coeffs.components.first().map_or(0, |c| c.blocks.len());
        // Start at zero and accumulate: the contributions are positive sums over
        // three bands. DC is set wet at the end -- it never takes part in
        // embedding, and leaving it at zero would make it look free.
        let mut costs = vec![0.0f64; total_blocks * 64];
        if total_blocks == 0 {
            return costs;
        }
        let Some((plane, pw, ph)) = precover::decompress_luma(coeffs, geometry) else {
            return vec![params.wet_cost; total_blocks * 64];
        };
        if geometry.positions.len() != total_blocks {
            return vec![params.wet_cost; total_blocks * 64];
        }

        let sigma = params
            .model_option("sigma", DEFAULT_SIGMA)
            .max(f64::MIN_POSITIVE);
        let basis = precover::dct_basis();
        let q: [f64; 64] = std::array::from_fn(|i| geometry.luma_q[i].max(1) as f64);

        // One band at a time: the residual and its reciprocal plane are the two
        // large allocations here, and keeping only one alive bounds the working
        // set regardless of how many bands there are.
        for (f1, f2) in wavelet::bands() {
            let residual = separable_residual(&plane, pw, ph, &f1, &f2);
            let recip: Vec<f32> = residual
                .iter()
                .map(|v| (1.0 / (v.abs() + sigma)) as f32)
                .collect();

            let (u, v) = footprint(&basis, &f1, &f2);

            let mut patch = vec![0.0f32; SUPPORT * SUPPORT];
            for (bi, &(br, bc)) in geometry.positions.iter().enumerate() {
                gather_patch(&recip, pw, ph, br * N, bc * N, &mut patch);

                for (i, u_row) in u.iter().enumerate() {
                    for (j, v_row) in v.iter().enumerate() {
                        // DC never takes part in embedding; leaving it wet keeps
                        // the cover digest stable.
                        let k = i * N + j;
                        if k == 0 {
                            continue;
                        }
                        let mut sum = 0.0f32;
                        for (ky, &uy) in u_row.iter().enumerate() {
                            if uy == 0.0 {
                                continue;
                            }
                            let row = &patch[ky * SUPPORT..(ky + 1) * SUPPORT];
                            let mut acc = 0.0f32;
                            for (kx, &pv) in row.iter().enumerate() {
                                acc += pv * v_row[kx];
                            }
                            sum += uy * acc;
                        }
                        // `q` scales the perturbation, and `sum` is already
                        // relative distortion, so the paper's rho is q * sum.
                        costs[bi * 64 + k] += (q[k] as f32 * sum) as f64;
                    }
                }
            }
        }

        // Zero, negative or non-finite costs would make a coefficient look free
        // to the trellis, and anything above the wet cap has to saturate so the
        // search stays numerically sane. DC is wet unconditionally.
        for (i, c) in costs.iter_mut().enumerate() {
            if i % 64 == 0 || !c.is_finite() || *c <= 0.0 || *c > params.wet_cost {
                *c = params.wet_cost;
            }
        }
        costs
    }
}

/// Wavelet residual of one band: `R[y][x] = Σ_{a,b} f1[a] f2[b] · plane[y+a-8][x+b-8]`.
///
/// The 2D filter is separable, so this runs as two 1D passes. Edge pixels clamp
/// instead of zero-padding: zero padding would fake "no texture" along the
/// border and make the outermost ring look artificially expensive to change.
fn separable_residual(
    plane: &[f64],
    pw: usize,
    ph: usize,
    f1: &[f64; wavelet::TAPS],
    f2: &[f64; wavelet::TAPS],
) -> Vec<f64> {
    let mut horizontal = vec![0.0f64; pw * ph];
    for y in 0..ph {
        let row = &plane[y * pw..(y + 1) * pw];
        let out = &mut horizontal[y * pw..(y + 1) * pw];
        for (x, dst) in out.iter_mut().enumerate() {
            let mut acc = 0.0;
            for (b, &cb) in f2.iter().enumerate() {
                let sx = (x as isize + b as isize - wavelet::HALF as isize)
                    .clamp(0, pw as isize - 1) as usize;
                acc += cb * row[sx];
            }
            *dst = acc;
        }
    }

    let mut out = vec![0.0f64; pw * ph];
    for y in 0..ph {
        for x in 0..pw {
            let mut acc = 0.0;
            for (a, &ca) in f1.iter().enumerate() {
                let sy = (y as isize + a as isize - wavelet::HALF as isize)
                    .clamp(0, ph as isize - 1) as usize;
                acc += ca * horizontal[sy * pw + x];
            }
            out[y * pw + x] = acc;
        }
    }
    out
}

/// Per-coefficient wavelet footprint of a `±1` change, as two 1D profiles.
///
/// `u[i][ky]` / `v[j][kx]` are the 23-tap responses of the block's DCT basis
/// function along each axis, so the 2D footprint of coefficient `(i, j)` is the
/// outer product `u[i] ⊗ v[j]`. The absolute value of an outer product is the
/// outer product of the absolute values, which is why the distortion sum can
/// take `|u|` and `|v|` up front.
fn footprint(
    basis: &[[f64; N]; N],
    f1: &[f64; wavelet::TAPS],
    f2: &[f64; wavelet::TAPS],
) -> ([[f32; SUPPORT]; N], [[f32; SUPPORT]; N]) {
    let mut u = [[0.0f32; SUPPORT]; N];
    let mut v = [[0.0f32; SUPPORT]; N];

    for (i, u_row) in u.iter_mut().enumerate() {
        for (ky, dst) in u_row.iter_mut().enumerate() {
            let t = ky as isize + SUPPORT_START;
            let mut acc = 0.0f64;
            for (a, &ca) in f1.iter().enumerate() {
                let idx = t + a as isize;
                if (0..N as isize).contains(&idx) {
                    acc += ca * basis[idx as usize][i];
                }
            }
            *dst = acc.abs() as f32;
        }
    }
    for (j, v_row) in v.iter_mut().enumerate() {
        for (kx, dst) in v_row.iter_mut().enumerate() {
            let t = kx as isize + SUPPORT_START;
            let mut acc = 0.0f64;
            for (b, &cb) in f2.iter().enumerate() {
                let idx = t + b as isize;
                if (0..N as isize).contains(&idx) {
                    acc += cb * basis[idx as usize][j];
                }
            }
            *dst = acc.abs() as f32;
        }
    }
    (u, v)
}

/// Copy the `SUPPORT x SUPPORT` reciprocal-residual window centred on the block
/// into `patch`, clamping at the plane borders.
fn gather_patch(recip: &[f32], pw: usize, ph: usize, y0: usize, x0: usize, patch: &mut [f32]) {
    for ky in 0..SUPPORT {
        let sy = (y0 as isize + SUPPORT_START + ky as isize).clamp(0, ph as isize - 1) as usize;
        let dst = &mut patch[ky * SUPPORT..(ky + 1) * SUPPORT];
        for (kx, dst_v) in dst.iter_mut().enumerate() {
            let sx = (x0 as isize + SUPPORT_START + kx as isize).clamp(0, pw as isize - 1) as usize;
            *dst_v = recip[sy * pw + sx];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The footprint of the DC coefficient must be near zero in the high-pass
    /// bands (a constant block has no wavelet detail), and clearly larger for a
    /// mid-band AC coefficient. This is the property that makes the model
    /// texture-adaptive at all.
    #[test]
    fn footprint_reflects_frequency_content() {
        let basis = precover::dct_basis();
        let bands = wavelet::bands();

        let dc_energy: f32 = {
            let (u, v) = footprint(&basis, &bands[2].0, &bands[2].1);
            u[0].iter().map(|x| x * x).sum::<f32>() * v[0].iter().map(|x| x * x).sum::<f32>()
        };
        let ac_energy: f32 = {
            let (u, v) = footprint(&basis, &bands[2].0, &bands[2].1);
            u[3].iter().map(|x| x * x).sum::<f32>() * v[3].iter().map(|x| x * x).sum::<f32>()
        };
        assert!(
            ac_energy > dc_energy * 10.0,
            "an AC coefficient must disturb the high-pass band far more than DC \
             (dc {dc_energy:e}, ac {ac_energy:e})"
        );
    }

    /// A constant plane has no wavelet detail, so the reciprocal residual is one
    /// huge constant and every cost saturates at the wet cap. The point of the
    /// test is that nothing comes out as zero or NaN.
    #[test]
    fn flat_plane_produces_finite_costs() {
        let blocks = vec![[0i16; 64]; 4];
        let mut blocks = blocks;
        for b in blocks.iter_mut() {
            b[0] = 800; // flat mid-grey once dequantized with an all-ones table
        }
        let coeffs = dct_io::JpegCoefficients {
            components: vec![dct_io::ComponentCoefficients { id: 1, blocks }],
        };
        let geometry = JpegGeometry {
            grid_w: 2,
            grid_h: 2,
            positions: vec![(0, 0), (0, 1), (1, 0), (1, 1)],
            luma_q: [1u16; 64],
        };
        let costs = JuniwardCostModel.compute_cost(&coeffs, &geometry, &JpegParams::default());
        assert_eq!(costs.len(), 4 * 64);
        assert!(
            costs.iter().all(|c| c.is_finite() && *c > 0.0),
            "a flat carrier must still produce finite, positive costs"
        );
    }
}
