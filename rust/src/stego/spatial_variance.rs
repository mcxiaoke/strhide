//! Shared spatial-domain variance estimator for MiPOD and J-MiPOD.
//!
//! Both cost models need the same per-pixel estimate `sigma_n^2`:
//!
//! 1. **Content suppression**: `r = z - wiener2(z)`, where `wiener2` is the
//!    Matlab adaptive Wiener filter (`local mean m`, `local variance v`,
//!    noise power `nu2 = mean(v)`, `out = m + max(v - nu2, 0) / v * (z - m)`),
//!    hence `r = (z - m) * min(1, nu2 / v)`.
//! 2. **Local parametric model**: for a `p x p` neighbourhood (`p` odd),
//!    project `r_n` onto the orthogonal complement of the 2-D cosine
//!    polynomial model `{phi_ku ⊗ phi_kv : ku + kv < degree}` and divide by
//!    the degrees of freedom `p^2 - degree(degree + 1)/2`.
//!
//! # Why this is separable
//!
//! `phi_k(a) = c_k sqrt(2/p) cos(pi k (2a + 1) / 2p)` is the orthonormal
//! 1-D DCT-II basis, so the model space is exactly the span of the 2-D
//! tensor-product basis vectors with `ku + kv < degree`. Its orthogonal
//! complement is therefore spanned by the basis vectors with
//! `ku + kv >= degree`, and Parseval's identity gives
//!
//! ```text
//! ||P_G^perp r_n||^2 = sum_{ku + kv >= degree} <phi_ku ⊗ phi_kv, r_n>^2
//! ```
//!
//! Every inner product is a separable pair of 1-D dot products, so no matrix
//! is built and no linear solve is needed. The identity is verified against an
//! explicit `P = I - G(G^T G)^{-1}G^T` in the unit tests below.
//!
//! # Memory
//!
//! The 2-D projections are never materialized for the whole image. Output
//! rows are processed in bands sized to a fixed byte budget: only the
//! horizontal projections of `band + 2 * half` rows are alive (~16 MB by
//! default), independent of image height.

use rayon::prelude::*;

/// Byte budget for one band of horizontal projections.
const BAND_BYTES: usize = 16 << 20;

/// Mirror index into `[0, n)` with the edge included (NumPy `symmetric`).
///
/// The paper specifies mirror padding for the variance estimator, and its
/// convention repeats the edge sample (`-1 -> 0`, `-2 -> 1`).
#[inline]
pub(crate) fn reflect_index(mut i: isize, n: isize) -> usize {
    if n <= 1 {
        return 0;
    }
    let period = 2 * n;
    i = i.rem_euclid(period);
    if i >= n {
        (period - 1 - i) as usize
    } else {
        i as usize
    }
}

/// Orthonormal 1-D DCT-II basis: `basis[k][a] = phi_k(a)`, `a = 0..p`.
fn dct_basis(p: usize) -> Vec<Vec<f64>> {
    let scale0 = (1.0 / p as f64).sqrt();
    let scalek = (2.0 / p as f64).sqrt();
    (0..p)
        .map(|k| {
            let s = if k == 0 { scale0 } else { scalek };
            (0..p)
                .map(|a| {
                    s * (std::f64::consts::PI * k as f64 * (2 * a + 1) as f64 / (2.0 * p as f64))
                        .cos()
                })
                .collect()
        })
        .collect()
}

/// Matlab `wiener2` residual `r = z - wiener2(z)` with a `window x window`
/// kernel, **zero padding** and an even window anchored at its top-left sample.
///
/// Matlab's `filter2`-based local mean for an even kernel reads
/// `(z[y..y+win][x..x+win])`, so this reproduces `wiener2(X,[2 2])`, the
/// window used by both the MiPOD paper (`w = 2`) and the official MiPOD /
/// J-MiPOD releases. Odd windows are centred.
///
/// `noise` is the image-wide mean of the local variance, as in `wiener2` when
/// the noise power is left unspecified.
pub(crate) fn wiener_residual(plane: &[f64], w: usize, h: usize, window: usize) -> Vec<f64> {
    let n = w * h;
    if w == 0 || h == 0 || window < 2 || plane.len() < n {
        return Vec::new();
    }
    let anchor = if window.is_multiple_of(2) {
        0isize
    } else {
        (window / 2) as isize
    };
    let area = (window * window) as f64;

    let mut mean = vec![0.0f64; n];
    let mut var = vec![0.0f64; n];
    mean.par_chunks_mut(w)
        .zip(var.par_chunks_mut(w))
        .enumerate()
        .for_each(|(y, (mean_row, var_row))| {
            for (x, (m, v)) in mean_row.iter_mut().zip(var_row.iter_mut()).enumerate() {
                let mut sum = 0.0f64;
                let mut sum_sq = 0.0f64;
                for dy in 0..window {
                    let sy = y as isize + dy as isize - anchor;
                    if sy < 0 || sy >= h as isize {
                        continue; // zero padding
                    }
                    let src = &plane[sy as usize * w..(sy as usize + 1) * w];
                    for dx in 0..window {
                        let sx = x as isize + dx as isize - anchor;
                        if sx < 0 || sx >= w as isize {
                            continue;
                        }
                        let val = src[sx as usize];
                        sum += val;
                        sum_sq += val * val;
                    }
                }
                let mu = sum / area;
                *m = mu;
                // E[x^2] - E[x]^2 can go slightly negative in floating point.
                *v = (sum_sq / area - mu * mu).max(0.0);
            }
        });

    // Deterministic reduction: per-row sums are independent, and the row sums
    // are accumulated in index order, so the result does not depend on how
    // many Rayon threads ran the rows.
    let row_sums: Vec<f64> = var.par_chunks(w).map(|row| row.iter().sum()).collect();
    let noise = row_sums.iter().sum::<f64>() / n as f64;
    if noise <= 0.0 {
        return vec![0.0f64; n];
    }

    // Reuse `mean` as the residual: it is no longer needed once every pixel
    // has been visited, which keeps one full-image plane out of the peak
    // working set.
    mean.par_iter_mut().enumerate().for_each(|(i, out)| {
        let v = var[i];
        let diff = plane[i] - *out;
        // `out = mean` when v <= noise, and `mean + (v - noise)/v * diff`
        // otherwise; the residual is `diff * min(1, noise / v)`.
        *out = if v > noise { (noise / v) * diff } else { diff };
    });
    mean
}

/// `||P_G^perp r_n||^2` for every pixel of `residual`, with mirror padding.
///
/// `degree == p` is the configuration used by both models; the loops below
/// also cover `degree < p` correctly because the complement explicitly
/// includes the `ku = 0` / `kv = 0` pairs that fall outside the model.
fn complement_energy(residual: &[f64], w: usize, h: usize, p: usize, degree: usize) -> Vec<f64> {
    let n = w * h;
    let half = (p - 1) / 2;
    let stride = w * p;
    let basis = dct_basis(p);

    // One band of output rows needs horizontal projections for
    // `[y0 - half, y1 - 1 + half]`, i.e. `rows + 2*half` source rows.
    let per_row = stride * std::mem::size_of::<f64>();
    let band = (BAND_BYTES / per_row.max(1)).max(1).min(h);

    let mut energies = vec![0.0f64; n];
    let mut y0 = 0usize;
    while y0 < h {
        let y1 = (y0 + band).min(h);
        let rows = y1 - y0;
        let src_rows = rows + 2 * half;

        let mut horiz = vec![0.0f64; src_rows * stride];
        horiz
            .par_chunks_mut(stride)
            .enumerate()
            .for_each(|(bi, dst)| {
                let sy = reflect_index(y0 as isize - half as isize + bi as isize, h as isize);
                let src = &residual[sy * w..(sy + 1) * w];
                for x in 0..w {
                    for (kv, b) in basis.iter().enumerate() {
                        let mut sum = 0.0f64;
                        for (a, &coef) in b.iter().enumerate() {
                            let sx =
                                reflect_index(x as isize + a as isize - half as isize, w as isize);
                            sum += coef * src[sx];
                        }
                        dst[x * p + kv] = sum;
                    }
                }
            });

        energies[y0 * w..y1 * w]
            .par_chunks_mut(w)
            .enumerate()
            .for_each(|(li, row)| {
                for (x, dst) in row.iter_mut().enumerate() {
                    let mut norm_sq = 0.0f64;
                    for kv in 0..p {
                        // Complement: ku + kv >= degree, with ku >= 0.
                        let ku_start = degree.saturating_sub(kv);
                        for b in basis.iter().skip(ku_start) {
                            let mut proj = 0.0f64;
                            for (a, &coef) in b.iter().enumerate() {
                                proj += coef * horiz[(li + a) * stride + x * p + kv];
                            }
                            norm_sq += proj * proj;
                        }
                    }
                    *dst = norm_sq;
                }
            });

        y0 = y1;
    }
    energies
}

/// Per-pixel variance estimate `max(floor, ||P_G^perp r_n||^2 / dof)`.
///
/// `plane` must be row-major `w x h`. `degree < p` is supported (the
/// complement then includes the DC-row/DC-column basis vectors), but the two
/// shipped models both use `degree == p`.
pub(crate) fn estimate_variance(
    plane: &[f64],
    w: usize,
    h: usize,
    block_p: usize,
    degree: usize,
    wiener_window: usize,
    variance_floor: f64,
) -> Vec<f64> {
    let n = w * h;
    if w == 0 || h == 0 || plane.len() < n {
        return Vec::new();
    }
    assert!(
        block_p >= 3 && !block_p.is_multiple_of(2),
        "block size must be odd and >= 3"
    );
    assert!(degree <= block_p, "degree must not exceed the block size");

    let residual = wiener_residual(plane, w, h, wiener_window);
    if residual.is_empty() {
        return vec![variance_floor; n];
    }
    let mut energies = complement_energy(&residual, w, h, block_p, degree);
    drop(residual);
    let q = degree * (degree + 1) / 2;
    let dof = (block_p * block_p - q) as f64;
    debug_assert!(dof > 0.0);

    // Convert in place: a second full-image plane would otherwise double the
    // peak working set on large carriers.
    energies
        .par_iter_mut()
        .for_each(|e| *e = (*e / dof).max(variance_floor));
    energies
}

/// Separable `window x window` box average with mirror padding.
///
/// Consumes the input and reuses its buffer for the output, so only one
/// horizontal intermediate plane is needed.
pub(crate) fn box_smooth(mut plane: Vec<f64>, w: usize, h: usize, window: usize) -> Vec<f64> {
    let n = w * h;
    if w == 0 || h == 0 || plane.len() < n || window <= 1 {
        return plane;
    }
    let half = (window / 2) as isize;
    let inv = 1.0 / window as f64;

    let mut tmp = vec![0.0f64; n];
    tmp.par_chunks_mut(w).enumerate().for_each(|(y, row)| {
        let src = &plane[y * w..(y + 1) * w];
        for (x, dst) in row.iter_mut().enumerate() {
            let mut sum = 0.0f64;
            for d in -half..=half {
                sum += src[reflect_index(x as isize + d, w as isize)];
            }
            *dst = sum * inv;
        }
    });

    plane.par_chunks_mut(w).enumerate().for_each(|(y, row)| {
        for (x, dst) in row.iter_mut().enumerate() {
            let mut sum = 0.0f64;
            for d in -half..=half {
                sum += tmp[reflect_index(y as isize + d, h as isize) * w + x];
            }
            *dst = sum * inv;
        }
    });
    plane
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Explicit `P = I - G(G^T G)^{-1}G^T`, built the way the reference
    /// implementations (conseal, official Matlab) build `G`.
    fn explicit_projector(p: usize, degree: usize) -> Vec<f64> {
        // G[:, k] = vec of phi_ku ⊗ phi_kv for ku + kv < degree, k in order.
        let basis = dct_basis(p);
        let q = degree * (degree + 1) / 2;
        let mut g = vec![0.0f64; p * p * q];
        let mut k = 0;
        for ku in 0..degree {
            for kv in 0..(degree - ku) {
                for y in 0..p {
                    for x in 0..p {
                        g[(y * p + x) * q + k] = basis[ku][y] * basis[kv][x];
                    }
                }
                k += 1;
            }
        }
        debug_assert_eq!(k, q);

        // Probability `p = I - G (G^T G)^{-1} G^T` via Cholesky-free
        // Gauss-Jordan on the q x q Gram matrix.
        let mut gram = vec![0.0f64; q * q];
        for i in 0..q {
            for j in 0..q {
                gram[i * q + j] = (0..p * p).map(|r| g[r * q + i] * g[r * q + j]).sum();
            }
        }
        let mut inv = vec![0.0f64; q * q];
        for i in 0..q {
            inv[i * q + i] = 1.0;
        }
        for col in 0..q {
            let mut pivot = col;
            for r in col + 1..q {
                if gram[r * q + col].abs() > gram[pivot * q + col].abs() {
                    pivot = r;
                }
            }
            if pivot != col {
                for c in 0..q {
                    gram.swap(col * q + c, pivot * q + c);
                    inv.swap(col * q + c, pivot * q + c);
                }
            }
            let d = gram[col * q + col];
            for c in 0..q {
                gram[col * q + c] /= d;
                inv[col * q + c] /= d;
            }
            for r in 0..q {
                if r == col {
                    continue;
                }
                let f = gram[r * q + col];
                for c in 0..q {
                    gram[r * q + c] -= f * gram[col * q + c];
                    inv[r * q + c] -= f * inv[col * q + c];
                }
            }
        }
        let mut proj = vec![0.0f64; p * p * p * p];
        for a in 0..p * p {
            for b in 0..p * p {
                let mut v = (a == b) as u8 as f64;
                for i in 0..q {
                    for j in 0..q {
                        v -= g[a * q + i] * inv[i * q + j] * g[b * q + j];
                    }
                }
                proj[a * p * p + b] = v;
            }
        }
        proj
    }

    fn random_plane(w: usize, h: usize, seed: u64) -> Vec<f64> {
        let mut state = seed;
        (0..w * h)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state % 200) as f64 - 100.0
            })
            .collect()
    }

    /// The separable complement energy must equal `||P_G^perp r_n||^2` for
    /// every pixel, for both shipped configurations and a `degree < p` case.
    #[test]
    fn separable_complement_equals_explicit_projector() {
        for &(p, degree) in &[(3usize, 3usize), (9, 9), (5, 4)] {
            let w = 12;
            let h = 10;
            let residual = random_plane(w, h, 0x1234_5678_9abc_def0);
            let proj = explicit_projector(p, degree);
            let half = (p - 1) / 2;
            let energies = complement_energy(&residual, w, h, p, degree);

            for y in 0..h {
                for x in 0..w {
                    let mut win = vec![0.0f64; p * p];
                    for (a, win_row) in win.chunks_mut(p).enumerate() {
                        for (b, v) in win_row.iter_mut().enumerate() {
                            let sy =
                                reflect_index(y as isize + a as isize - half as isize, h as isize);
                            let sx =
                                reflect_index(x as isize + b as isize - half as isize, w as isize);
                            *v = residual[sy * w + sx];
                        }
                    }
                    let mut exact = 0.0f64;
                    for a in 0..p * p {
                        let row = &proj[a * p * p..(a + 1) * p * p];
                        let mut dot = 0.0f64;
                        for b in 0..p * p {
                            dot += row[b] * win[b];
                        }
                        exact += dot * dot;
                    }
                    let got = energies[y * w + x];
                    let scale = exact.abs().max(1.0);
                    assert!(
                        (got - exact).abs() / scale < 1e-11,
                        "p={p}, degree={degree}, pixel ({y},{x}): {got} vs {exact}"
                    );
                }
            }
        }
    }

    /// A constant plane has zero residual away from the zero-padded border
    /// (`wiener2` treats out-of-range samples as zeros), so the variance
    /// estimate sits on the floor in the interior.
    #[test]
    fn flat_plane_interior_has_floor_variance() {
        let (w, h) = (24, 18);
        let plane = vec![120.0f64; w * h];
        let residual = wiener_residual(&plane, w, h, 2);
        for y in 0..h - 1 {
            for x in 0..w - 1 {
                assert_eq!(residual[y * w + x], 0.0, "interior ({y},{x})");
            }
        }
        let var = estimate_variance(&plane, w, h, 9, 9, 2, 0.25);
        for y in 4..h - 4 {
            for x in 4..w - 4 {
                assert_eq!(var[y * w + x], 0.25, "interior ({y},{x})");
            }
        }
    }

    /// The Wiener residual must be zero on a constant and follow the
    /// `(noise / v) * (z - m)` formula on a textured plane.
    #[test]
    fn wiener_residual_is_finite_and_bounded() {
        let (w, h) = (17, 13);
        let plane = random_plane(w, h, 0xdead_beef_0bad_f00d);
        let residual = wiener_residual(&plane, w, h, 2);
        for (i, r) in residual.iter().enumerate() {
            let local = plane[i];
            assert!(r.is_finite(), "residual {i} is not finite");
            assert!(r.abs() <= local.abs() + 200.0, "residual {i} exploded");
        }
    }

    #[test]
    fn box_smooth_preserves_a_constant() {
        let (w, h) = (16, 16);
        let plane = vec![7.5f64; w * h];
        let out = box_smooth(plane, w, h, 7);
        assert!(out.iter().all(|v| (*v - 7.5).abs() < 1e-12));
    }
}
