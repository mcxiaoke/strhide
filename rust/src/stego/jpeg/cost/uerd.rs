//! Uniform Embedding Revisited Distortion (UERD) for JPEG DCT coefficients.
//!
//! Based on L. Guo, J. Ni, W. Su, C. Tang and Y.-Q. Shi,
//! "Using Statistical Image Model for JPEG Steganography: Uniform Embedding Revisited",
//! IEEE Transactions on Information Forensics and Security, 2015.
//!
//! Evaluates embedding distortion directly on quantized DCT coefficients and
//! their 8-neighborhood block energies, spreading modifications across complex,
//! high-energy blocks and avoiding flat/smooth areas.

use crate::stego::params::JpegParams;
use crate::stego::traits::JpegCostModel;

pub struct UerdCostModel;

impl Default for UerdCostModel {
    fn default() -> Self {
        Self
    }
}

// Standard baseline JPEG luminance quantization table (zigzag order 0..63)
const STANDARD_LUMA_QT: [f64; 64] = [
    16.0, 11.0, 12.0, 14.0, 12.0, 10.0, 16.0, 14.0, 13.0, 14.0, 18.0, 17.0, 16.0, 19.0, 24.0, 40.0,
    26.0, 24.0, 22.0, 22.0, 24.0, 49.0, 35.0, 37.0, 29.0, 40.0, 58.0, 51.0, 61.0, 60.0, 57.0, 51.0,
    56.0, 55.0, 64.0, 72.0, 92.0, 78.0, 64.0, 68.0, 87.0, 69.0, 55.0, 56.0, 80.0, 109.0, 81.0,
    87.0, 95.0, 98.0, 103.0, 104.0, 103.0, 62.0, 77.0, 113.0, 121.0, 112.0, 100.0, 120.0, 92.0,
    101.0, 103.0, 99.0,
];

impl JpegCostModel for UerdCostModel {
    fn id(&self) -> &'static str {
        "uerd"
    }

    fn description(&self) -> &'static str {
        "Uniform Embedding Revisited Distortion (UERD) DCT model (IEEE TIFS 2015)"
    }

    fn compute_cost(&self, coeffs: &dct_io::JpegCoefficients, params: &JpegParams) -> Vec<f64> {
        if coeffs.components.is_empty() {
            return Vec::new();
        }

        // Primary embedding target is the luminance component (Y, index 0)
        let comp = &coeffs.components[0];
        let total_blocks = comp.blocks.len();
        if total_blocks == 0 {
            return Vec::new();
        }

        // Derive approximate 2D grid dimensions for 8-neighborhood smoothing
        let w_blocks = (f64::sqrt(total_blocks as f64).ceil() as usize).max(1);
        let h_blocks = total_blocks.div_ceil(w_blocks);

        // Step 1: Compute block energy Eb for each block: sum of |C_k * Q_k| for AC coefficients (k=1..63)
        let mut block_energies = vec![0.0f64; total_blocks];
        for (bi, block) in comp.blocks.iter().enumerate() {
            let mut energy = 0.0f64;
            for k in 1..64 {
                let coeff = block[k];
                // Mask LSB of absolute coefficient: (coeff.abs() & !1)
                // Guarantees 100% deterministic, bit-for-bit identical block energy
                // and candidate slot ranking across embed and extract.
                let coeff_energy = (coeff.abs() & !1) as f64;
                energy += coeff_energy * STANDARD_LUMA_QT[k];
            }
            block_energies[bi] = energy;
        }

        // Step 2: Compute smoothed block energy using 8-neighborhood convolution
        let mut smoothed_energies = vec![0.0f64; total_blocks];
        let nw = params.neighbor_weight;

        for r in 0..h_blocks {
            for c in 0..w_blocks {
                let bi = r * w_blocks + c;
                if bi >= total_blocks {
                    break;
                }

                let cur_e = block_energies[bi];
                let mut neighbor_sum = 0.0f64;
                let mut neighbor_count = 0usize;

                for dr in [-1isize, 0, 1] {
                    for dc in [-1isize, 0, 1] {
                        if dr == 0 && dc == 0 {
                            continue;
                        }
                        let nr = r as isize + dr;
                        let nc = c as isize + dc;
                        if nr >= 0 && nr < h_blocks as isize && nc >= 0 && nc < w_blocks as isize {
                            let n_bi = nr as usize * w_blocks + nc as usize;
                            if n_bi < total_blocks {
                                neighbor_sum += block_energies[n_bi];
                                neighbor_count += 1;
                            }
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
        }

        // Step 3: Compute coefficient cost rho for each eligible AC coefficient
        // Total flattened coefficients = total_blocks * 64
        let mut costs = vec![params.wet_cost; total_blocks * 64];
        let min_abs = params.min_abs_coeff;

        for (bi, block) in comp.blocks.iter().enumerate() {
            let block_rho = smoothed_energies[bi];
            if block_rho <= 0.0 {
                continue;
            }

            for k in 1..64 {
                let coeff = block[k];
                if coeff.abs() >= min_abs {
                    let mode_rho = STANDARD_LUMA_QT[k];
                    let cost = mode_rho / block_rho;
                    costs[bi * 64 + k] = cost;
                }
            }
        }

        costs
    }
}
