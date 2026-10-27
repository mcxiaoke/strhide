//! Uniform Embedding Revisited Distortion (UERD) for JPEG DCT coefficients.
//!
//! An **UERD-inspired variant** of L. Guo, J. Ni, W. Su, C. Tang and
//! Y.-Q. Shi, "Using Statistical Image Model for JPEG Steganography:
//! Uniform Embedding Revisited", IEEE Transactions on Information Forensics
//! and Security, 2015. Deliberate deviations from the paper's formula
//! (embed-side only — extraction is cost-free, so the round trip does not
//! depend on any of them):
//!
//! - the numerator uses `Q[k]` to the **first** power, not `Q[k]^2`, and the
//!   inter-block `D = 1.5` factor (first row/column modes) is absent;
//! - the denominator smooths the block energy over the **8-neighbourhood
//!   including diagonals, averaged** over existing neighbours
//!   (`J + w·avg`), not the paper's `J + 0.25·(sum of the four
//!   cross-neighbours)` — the neighbourhood term is therefore weaker and
//!   mixed with diagonal blocks;
//! - border blocks average over their actually-present neighbours instead
//!   of the paper's zero-padded shifted sum.
//!
//! These change the *ordering* between modes/blocks relative to the paper's
//! UERD while keeping its qualitative shape (high-energy textured blocks are
//! cheap, flat blocks expensive). Aligning the formula requires a detection
//! evaluation to justify (see the review report M4), which has not been run;
//! until then this module claims fidelity to the idea, not the arithmetic.
//!
//! Evaluates embedding distortion directly on quantized DCT coefficients and
//! their 8-neighborhood block energies, spreading modifications across complex,
//! high-energy blocks and avoiding flat/smooth areas.
//!
//! Two corrections over the naive port (both verified 2026-10-20):
//!
//! - **Block geometry**: the 8-neighborhood smoothing runs on the component's
//!   true MCU-padded block grid via [`crate::stego::jpeg::geometry`]. The
//!   block array is MCU-interleaved for subsampled carriers, so a raster
//!   assumption (`ceil(sqrt(n))` or `ceil(width/8)`) smooths across
//!   non-adjacent blocks on every 4:2:0 image.
//! - **Quantization table**: the per-frequency weight `Q[k]` is the file's
//!   own luminance table (parsed from the DQT segment), not the hard-coded
//!   Annex K table, so custom-quality carriers get a correctly ordered cost
//!   map. Annex K remains the fallback for files without a parsable DQT.

use crate::stego::params::JpegParams;
use crate::stego::traits::{JpegCostModel, JpegGeometry};

use super::precover;

pub struct UerdCostModel;

impl Default for UerdCostModel {
    fn default() -> Self {
        Self
    }
}

impl JpegCostModel for UerdCostModel {
    fn id(&self) -> &'static str {
        "uerd"
    }

    fn description(&self) -> &'static str {
        "UERD-inspired DCT distortion variant (deviates from Guo et al. IEEE TIFS 2015: Q^1, 8-neighbour average; see module docs)"
    }

    fn compute_cost(
        &self,
        coeffs: &dct_io::JpegCoefficients,
        geometry: &JpegGeometry,
        params: &JpegParams,
    ) -> Vec<f64> {
        if coeffs.components.is_empty() {
            return Vec::new();
        }

        // Primary embedding target is the luminance component (Y, index 0)
        let comp = &coeffs.components[0];
        let total_blocks = comp.blocks.len();
        if total_blocks == 0 {
            return Vec::new();
        }

        // The engine builds the geometry from the same file; a length
        // mismatch means the carrier changed under us. Refuse rather than
        // silently smooth on a wrong grid (the engine surfaces this as a
        // cost-dimension error).
        let (grid_w, grid_h) = (geometry.grid_w, geometry.grid_h);
        if geometry.positions.len() != total_blocks
            || grid_w == 0
            || grid_h == 0
            || grid_w * grid_h < total_blocks
        {
            return Vec::new();
        }

        // The file's own luminance quantization table, natural order
        // (Annex K fallback resolved by the engine).
        let q: [f64; 64] = std::array::from_fn(|i| (geometry.luma_q[i].max(1)) as f64);

        // Step 1: Compute block energy Eb for each block: sum of |C_k * Q_k| for AC coefficients (k=1..63)
        let mut block_energies = vec![0.0f64; total_blocks];
        for (bi, block) in comp.blocks.iter().enumerate() {
            let mut energy = 0.0f64;
            for k in 1..64 {
                let coeff = block[k];
                // Mask the LSB of the absolute coefficient. This does NOT
                // make the energy "±1 invariant" (|c|=3 contributes 2 before
                // a flip and 4 after) — it makes the *quantized* contribution
                // a step function of |c|, so a ±1 modification can only move
                // a coefficient's energy contribution by one step, never to a
                // different step. The price of a move therefore never depends
                // on the exact value the embedder is about to change. The
                // `unsigned_abs` also avoids the i16::MIN negation panic.
                let coeff_energy = (coeff.unsigned_abs() & !1) as f64;
                energy += coeff_energy * q[k];
            }
            block_energies[bi] = energy;
        }

        // Step 2: Compute smoothed block energy using 8-neighborhood convolution
        // on the component's true (MCU-padded) block grid.
        //
        // Inverse grid: cell -> block index, usize::MAX marks an empty cell
        // (possible for carriers whose padded grid exceeds the block count).
        let mut cell_of = vec![usize::MAX; grid_w * grid_h];
        for (bi, &(r, c)) in geometry.positions.iter().enumerate() {
            let idx = r * grid_w + c;
            if idx < cell_of.len() {
                cell_of[idx] = bi;
            }
        }

        let nw = params.neighbor_weight;
        let mut smoothed_energies = vec![0.0f64; total_blocks];

        for (bi, &(r, c)) in geometry.positions.iter().enumerate() {
            let cur_e = block_energies[bi];
            let mut neighbor_sum = 0.0f64;
            let mut neighbor_count = 0usize;

            for dr in [-1isize, 0, 1] {
                let nr = r as isize + dr;
                if nr < 0 || nr >= grid_h as isize {
                    continue;
                }
                for dc in [-1isize, 0, 1] {
                    if dr == 0 && dc == 0 {
                        continue;
                    }
                    let nc = c as isize + dc;
                    if nc < 0 || nc >= grid_w as isize {
                        continue;
                    }
                    let n_bi = cell_of[nr as usize * grid_w + nc as usize];
                    if n_bi != usize::MAX {
                        neighbor_sum += block_energies[n_bi];
                        neighbor_count += 1;
                    }
                }
            }

            let neighbor_avg = if neighbor_count > 0 {
                neighbor_sum / neighbor_count as f64
            } else {
                cur_e
            };

            smoothed_energies[bi] = cur_e + nw * neighbor_avg;
        }

        // Step 3: Compute the cost of one `±1` move for every AC coefficient.
        //
        // Every position is priced, including zero coefficients: the V3 code is
        // ternary and may legally create a coefficient, so `|c| >= 2` is no
        // longer a gate. The block energy uses the `|c| & !1` step function
        // (see Step 1), so a move can shift a coefficient's energy
        // contribution by one step but the price never depends on the exact
        // value the embedder is about to change.
        let mut costs = vec![params.wet_cost; total_blocks * 64];

        for (bi, &block_rho) in smoothed_energies.iter().enumerate() {
            debug_assert!(bi < total_blocks);
            if block_rho <= 0.0 {
                // A completely flat block (all AC zero): nothing to hide in, so
                // every position keeps the wet cost.
                continue;
            }

            for k in 1..64 {
                let cost = q[k] / block_rho;
                // A saturation cap keeps the search numerically sane on
                // degenerate carriers without changing the ordering.
                costs[bi * 64 + k] = cost.min(params.wet_cost);
            }
        }

        costs
    }

    /// UERD plus cost polarization.
    ///
    /// UERD's own distortion is symmetric: it prices a `±1` move by the block's
    /// energy and the mode's quantizer step, and says nothing about *which way*
    /// a coefficient should move. That leaves free information on the table. A
    /// JPEG coefficient is a quantized sample of a smooth signal, so the value
    /// it "should" have had can be estimated (dequantize, denoise, re-quantize
    /// -- see [`precover`]). Moving towards that estimate is less visible than
    /// moving away from it, because it is the direction the signal lies in.
    ///
    /// This is the cost polarization step from `hstego` (MIT), expressed as a
    /// per-coefficient bias instead of a pre-multiplied cost pair:
    ///
    /// ```text
    /// s = sign(precover_estimate - coeff)
    /// bias[k] = +1  if s > 0     (raise towards the estimate)
    ///         = -1  if s < 0     (lower towards the estimate)
    ///         =  0  otherwise
    /// ```
    ///
    /// The engine discounts the preferred direction by
    /// [`JpegParams::polarize_weight`] (`hstego` uses `0.65`); `1.0` disables
    /// the mechanism and this method returns `None`, so the symmetric cost map
    /// of [`UerdCostModel::compute_cost`] is used unchanged.
    fn direction_bias(
        &self,
        coeffs: &dct_io::JpegCoefficients,
        geometry: &JpegGeometry,
        params: &JpegParams,
    ) -> Option<Vec<i8>> {
        // `1.0` is "no discount", i.e. the feature is off. Returning `None`
        // keeps the engine on the symmetric path (and skips the whole
        // decompress-denoise-recompress round trip).
        if (params.polarize_weight - 1.0).abs() <= f64::EPSILON {
            return None;
        }
        let bias = precover::bias(coeffs, geometry, 0.0)?;
        debug_assert_eq!(
            bias.len(),
            coeffs.components.first().map_or(0, |c| c.blocks.len()) * 64
        );
        Some(bias)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::jpeg_segments::STANDARD_LUMA_QT;
    use crate::stego::jpeg::geometry::component_geometry;
    use dct_io::{ComponentCoefficients, JpegCoefficients};

    fn params() -> JpegParams {
        JpegParams::default()
    }

    /// 8-block 4:2:0-like layout on a 4x2 padded grid (same as the geometry
    /// unit test): positions interleave two block rows.
    fn geometry_420() -> JpegGeometry {
        let info = dct_io::JpegInfo {
            width: 32,
            height: 16,
            components: vec![dct_io::ComponentInfo {
                id: 1,
                h_samp: 2,
                v_samp: 2,
                block_count: 8,
            }],
        };
        component_geometry(&info, 0, 8)
    }

    /// Build coefficients where every block carries the same base energy
    /// except `spike_block`, whose energy is `spike_energy`.
    fn coeffs_with_spike(base: i16, spike_block: usize, spike: i16) -> JpegCoefficients {
        let mut blocks = vec![[0i16; 64]; 8];
        for (bi, b) in blocks.iter_mut().enumerate() {
            let v = if bi == spike_block { spike } else { base };
            b[1] = v;
            b[2] = v;
        }
        JpegCoefficients {
            components: vec![ComponentCoefficients { id: 1, blocks }],
        }
    }

    #[test]
    fn rejects_geometry_length_mismatch() {
        let coeffs = coeffs_with_spike(4, 0, 2000);
        let mut geometry = geometry_420();
        geometry.positions.pop(); // now 7 positions for 8 blocks
        let costs = UerdCostModel.compute_cost(&coeffs, &geometry, &params());
        assert!(costs.is_empty(), "mismatched geometry must be refused");
    }

    #[test]
    fn smoothing_uses_true_spatial_neighbours() {
        // All blocks share energy E except block 0 (grid cell (0,0)), which
        // is huge. On the true grid, block 0's neighbours are exactly the
        // cells (0,1), (1,0), (1,1) -- indices 1, 2, 3. Block 4 = (0,2) is
        // two cells away and must NOT be pulled up by the spike.
        let coeffs = coeffs_with_spike(4, 0, 4000);
        let geometry = geometry_420();
        let costs = UerdCostModel.compute_cost(&coeffs, &geometry, &params());
        assert_eq!(costs.len(), 8 * 64);

        let cost_of = |bi: usize, k: usize| costs[bi * 64 + k];

        // Lower cost == higher smoothed energy.
        // Block 1 (0,1): neighbour of the spike -> strongly pulled up.
        // Block 4 (0,2): not a neighbour -> only its own energy + smooth
        // neighbours (all E) -> cost Q[1] / (1.25 E).
        assert!(
            cost_of(1, 1) < cost_of(4, 1),
            "spike's true neighbour must rank cheaper than a distant block"
        );

        // Exact value for the untouched cell: E + 0.25 * E = 1.25 E.
        let q1 = STANDARD_LUMA_QT[1] as f64;
        let e = 4.0 * (STANDARD_LUMA_QT[1] as f64) + 4.0 * (STANDARD_LUMA_QT[2] as f64);
        let expected = q1 / (1.25 * e);
        assert!(
            (cost_of(4, 1) - expected).abs() < 1e-9,
            "distant block cost {:.6}, expected {:.6}",
            cost_of(4, 1),
            expected
        );
    }

    #[test]
    fn uses_file_quant_table_not_annex_k() {
        let coeffs = coeffs_with_spike(4, 0, 4000);
        let mut geometry = geometry_420();
        // A file whose luma table is uniformly 1: costs must scale with it.
        geometry.luma_q = [1u16; 64];
        let costs = UerdCostModel.compute_cost(&coeffs, &geometry, &params());
        let e = 4.0 * 1.0 + 4.0 * 1.0; // both modes now weighted by Q=1
        let expected = 1.0 / (1.25 * e);
        assert!((costs[4 * 64 + 1] - expected).abs() < 1e-9);
    }
}
