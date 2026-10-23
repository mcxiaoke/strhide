//! Cover-derived "precover" estimate for JPEG cost polarization.
//!
//! # What this estimates, and why
//!
//! A JPEG's coefficients are the quantization of a real-world signal. For any
//! given coefficient there is a *range* of underlying values that would have
//! quantized to the same integer, and the centre of that range is the most
//! likely original value. Recovering that centre gives a side-information
//! channel the decoder cannot see: a `±1` move that brings the coefficient
//! *towards* the estimated original is the less visible one, because it is the
//! direction the signal actually lies in.
//!
//! The estimate is built the way `hstego` (MIT) does it:
//!
//! 1. dequantize and inverse-DCT the luma blocks back to a pixel plane;
//! 2. denoise that plane with a local adaptive Wiener filter -- this is the
//!    "precover": the same image without the quantization noise;
//! 3. forward-DCT and re-quantize the precover, and compare each coefficient
//!    with the file's actual one. The sign of that difference is the preference.
//!
//! # Scope
//!
//! This is **embed-side only**. JPEG slot selection is geometric and keyed, so
//! the extractor never needs a cost map and never sees this module. That is
//! what makes the whole trick free: nothing has to be reproducible on the stego.
//!
//! # Fidelity caveats
//!
//! * The Wiener stage reproduces `scipy.signal.wiener(im, (3, 3))`'s formula but
//!   uses edge clamping instead of `scipy`'s mirrored padding. The difference is
//!   confined to the outermost block ring and only slightly perturbs the sign
//!   near it; the estimate is a heuristic in the first place.
//! * Decompression skips the JPEG level shift (`+128`). The level shift only
//!   moves the DC term and every statistic this module uses (local mean, local
//!   variance, the sign of an AC difference) is invariant to it, so skipping it
//!   removes a subtraction and changes nothing that is read.

use dct_io::JpegCoefficients;

use crate::stego::traits::JpegGeometry;

/// Side length of one DCT block.
const N: usize = 8;

/// `COS[x][u] = C(u)/2 * cos((2x + 1) u pi / 16)`.
///
/// Same basis as `analysis::calibration`, kept local so this module stays
/// self-contained.
fn dct_basis() -> [[f64; N]; N] {
    let mut m = [[0.0f64; N]; N];
    for (x, row) in m.iter_mut().enumerate() {
        for (u, v) in row.iter_mut().enumerate() {
            let cu = if u == 0 {
                std::f64::consts::FRAC_1_SQRT_2
            } else {
                1.0
            };
            *v = 0.5 * cu * (((2 * x + 1) as f64) * (u as f64) * std::f64::consts::PI / 16.0).cos();
        }
    }
    m
}

/// Inverse 8x8 DCT: `block = C * F * C^T`, natural (row-major) order in and out.
fn idct_block(f: &[f64; 64], basis: &[[f64; N]; N]) -> [[f64; N]; N] {
    // tmp[y][u] = sum_v C[y][v] * F[v][u]
    let mut tmp = [[0.0f64; N]; N];
    for y in 0..N {
        for u in 0..N {
            let mut sum = 0.0;
            for v in 0..N {
                sum += basis[y][v] * f[v * N + u];
            }
            tmp[y][u] = sum;
        }
    }
    // out[y][x] = sum_u tmp[y][u] * C[x][u]
    let mut out = [[0.0f64; N]; N];
    for y in 0..N {
        for x in 0..N {
            let mut sum = 0.0;
            for u in 0..N {
                sum += tmp[y][u] * basis[x][u];
            }
            out[y][x] = sum;
        }
    }
    out
}

/// Forward 8x8 DCT: `F = C^T * block * C`, natural order out.
fn fdct_block(block: &[[f64; N]; N], basis: &[[f64; N]; N]) -> [f64; 64] {
    // tmp[v][x] = sum_y C[y][v] * block[y][x]
    let mut tmp = [[0.0f64; N]; N];
    for v in 0..N {
        for x in 0..N {
            let mut sum = 0.0;
            for y in 0..N {
                sum += basis[y][v] * block[y][x];
            }
            tmp[v][x] = sum;
        }
    }
    let mut out = [0.0f64; 64];
    for v in 0..N {
        for u in 0..N {
            let mut sum = 0.0;
            for x in 0..N {
                sum += tmp[v][x] * basis[x][u];
            }
            out[v * N + u] = sum;
        }
    }
    out
}

/// Edge-clamped index, used by the local statistics of [`wiener3`].
#[inline]
fn clamp_index(i: isize, n: usize) -> usize {
    i.clamp(0, n as isize - 1) as usize
}

/// 3x3 local adaptive Wiener denoise, matching `scipy.signal.wiener(im, (3, 3))`.
///
/// `noise` is the mean of the local variance, as in `scipy` when it is left
/// unspecified: pixels whose local variance is below it are replaced by the
/// local mean outright, which is what removes flat-area quantization noise.
fn wiener3(plane: &[f64], w: usize, h: usize) -> Vec<f64> {
    if w == 0 || h == 0 || plane.len() < w * h {
        return Vec::new();
    }
    const INV9: f64 = 1.0 / 9.0;

    let mut mean = vec![0.0f64; w * h];
    let mut var = vec![0.0f64; w * h];
    let mut total_var = 0.0f64;

    for y in 0..h {
        for x in 0..w {
            let mut s = 0.0f64;
            let mut s2 = 0.0f64;
            for dy in -1isize..=1 {
                let yy = clamp_index(y as isize + dy, h);
                for dx in -1isize..=1 {
                    let xx = clamp_index(x as isize + dx, w);
                    let v = plane[yy * w + xx];
                    s += v;
                    s2 += v * v;
                }
            }
            let m = s * INV9;
            let v = (s2 * INV9 - m * m).max(0.0);
            mean[y * w + x] = m;
            var[y * w + x] = v;
            total_var += v;
        }
    }

    let noise = total_var / (w * h) as f64;
    if noise <= 0.0 {
        return plane.to_vec();
    }

    let mut out = vec![0.0f64; w * h];
    for i in 0..w * h {
        let v = var[i];
        out[i] = if v < noise {
            mean[i]
        } else {
            mean[i] + (v - noise) / v * (plane[i] - mean[i])
        };
    }
    out
}

/// Estimate what the cover's quantized coefficients "should" have been.
///
/// Returns one `[f64; 64]` per block of the first component, in natural order
/// and indexed by block index (`bi`), i.e. the same indexing the cost map uses
/// (`bi * 64 + k`). `None` when the geometry does not describe the block set.
pub fn estimate(coeffs: &JpegCoefficients, geometry: &JpegGeometry) -> Option<Vec<[f64; 64]>> {
    let comp = coeffs.components.first()?;
    let total_blocks = comp.blocks.len();
    if total_blocks == 0 || geometry.positions.len() != total_blocks {
        return None;
    }
    let (grid_w, grid_h) = (geometry.grid_w, geometry.grid_h);
    if grid_w == 0 || grid_h == 0 || grid_w * grid_h < total_blocks {
        return None;
    }

    let q: [f64; 64] = std::array::from_fn(|i| geometry.luma_q[i].max(1) as f64);
    let basis = dct_basis();
    let (pw, ph) = (grid_w * N, grid_h * N);

    // 1) dequantize + IDCT into one pixel plane
    let mut plane = vec![0.0f64; pw * ph];
    for (bi, &(r, c)) in geometry.positions.iter().enumerate() {
        let mut dequantized = [0.0f64; 64];
        for k in 0..64 {
            dequantized[k] = comp.blocks[bi][k] as f64 * q[k];
        }
        let block = idct_block(&dequantized, &basis);
        for (y, block_row) in block.iter().enumerate() {
            let row = (r * N + y) * pw + c * N;
            plane[row..row + N].copy_from_slice(block_row);
        }
    }

    // 2) precover: remove the quantization noise
    let precover = wiener3(&plane, pw, ph);

    // 3) forward DCT + dequantize-normalise, back into per-block estimates
    let mut out = vec![[0.0f64; 64]; total_blocks];
    for (bi, &(r, c)) in geometry.positions.iter().enumerate() {
        let mut block = [[0.0f64; N]; N];
        for (y, block_row) in block.iter_mut().enumerate() {
            let row = (r * N + y) * pw + c * N;
            block_row.copy_from_slice(&precover[row..row + N]);
        }
        let freq = fdct_block(&block, &basis);
        for k in 0..64 {
            // Not rounded: keeping the fractional part avoids manufacturing
            // ties exactly at `.5`, which would make the sign arbitrary.
            out[bi][k] = freq[k] / q[k];
        }
    }

    Some(out)
}

/// Sign of `estimate - actual` per coefficient, as the bias the engine consumes.
///
/// `+1` means the estimate is *above* the actual coefficient, so raising the
/// coefficient moves towards it and is the cheaper direction. `-1` is the
/// mirror case, `0` means the two agree to within `dead_zone` quantizer steps
/// and there is no preference worth acting on.
pub fn bias(coeffs: &JpegCoefficients, geometry: &JpegGeometry, dead_zone: f64) -> Option<Vec<i8>> {
    let estimate = estimate(coeffs, geometry)?;
    let blocks = &coeffs.components.first()?.blocks;
    let total = blocks.len() * 64;
    let mut out = vec![0i8; total];
    let dead_zone = dead_zone.max(0.0);

    for (bi, block) in blocks.iter().enumerate() {
        for k in 1..64 {
            let delta = estimate[bi][k] - block[k] as f64;
            out[bi * 64 + k] = if delta > dead_zone {
                1
            } else if delta < -dead_zone {
                -1
            } else {
                0
            };
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DCT followed by IDCT must return the original block (the basis is
    /// orthonormal by construction, so this is exact up to float rounding).
    #[test]
    fn dct_roundtrip_is_identity() {
        let basis = dct_basis();
        let mut block = [[0.0f64; N]; N];
        for (y, row) in block.iter_mut().enumerate() {
            for (x, v) in row.iter_mut().enumerate() {
                *v = ((y * 13 + x * 7) % 29) as f64 - 14.0;
            }
        }
        let freq = fdct_block(&block, &basis);
        let back = idct_block(&freq, &basis);
        for y in 0..N {
            for x in 0..N {
                assert!(
                    (back[y][x] - block[y][x]).abs() < 1e-9,
                    "({y},{x}): {} vs {}",
                    back[y][x],
                    block[y][x]
                );
            }
        }
    }

    /// A pure DC block decompresses to a constant plane, so the Wiener filter
    /// must return the same constant and the re-quantised AC terms must be ~0.
    #[test]
    fn flat_plane_stays_flat() {
        let plane = vec![40.0f64; 16 * 16];
        let out = wiener3(&plane, 16, 16);
        for (i, v) in out.iter().enumerate() {
            assert!((v - 40.0).abs() < 1e-9, "pixel {i}: {v}");
        }
    }

    /// The Wiener stage must leave a constant alone even when the local variance
    /// is exactly zero (the `noise <= 0` early return).
    #[test]
    fn zero_variance_short_circuits() {
        let plane = vec![7.0f64; 64];
        assert_eq!(wiener3(&plane, 8, 8), plane);
    }
}
