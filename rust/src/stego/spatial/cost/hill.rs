//! High-Low-Low (HILL) spatial domain distortion cost function.
//!
//! Based on B. Li, M. Wang, J. Huang and X. Li,
//! "A New Cost Function for Spatial Image Steganography", ICIP 2014.
//!
//! Evaluates content complexity using a high-pass filter followed by two
//! stages of low-pass smoothing, assigning low costs to complex textures and
//! high costs to smooth/flat areas.

use crate::stego::params::SpatialParams;
use crate::stego::traits::SpatialCostModel;

pub struct HillCostModel;

impl Default for HillCostModel {
    fn default() -> Self {
        Self
    }
}

impl SpatialCostModel for HillCostModel {
    fn id(&self) -> &'static str {
        "hill"
    }

    fn description(&self) -> &'static str {
        "High-Low-Low (HILL) content-adaptive spatial distortion model (ICIP 2014)"
    }

    fn compute_cost(
        &self,
        pixels: &[u8],
        width: usize,
        height: usize,
        channels: usize,
        params: &SpatialParams,
    ) -> Vec<f64> {
        let (h, w) = (height, width);
        if w == 0 || h == 0 || pixels.is_empty() {
            return Vec::new();
        }

        // Convert pixels to grayscale luminance using high 7 bits (pixel & 0xFE).
        // Masking the LSB guarantees 100% deterministic, bit-for-bit identical
        // cost calculation and candidate slot ranking on both embed and extract.
        let mut gray = vec![0.0f64; h * w];
        if channels == 1 {
            for (dst, &src) in gray.iter_mut().zip(pixels.iter()) {
                *dst = (src & 0xFE) as f64;
            }
        } else if channels >= 3 {
            for i in 0..h * w {
                let r = (pixels[i * channels] & 0xFE) as f64;
                let g = (pixels[i * channels + 1] & 0xFE) as f64;
                let b = (pixels[i * channels + 2] & 0xFE) as f64;
                gray[i] = 0.299 * r + 0.587 * g + 0.114 * b;
            }
        } else {
            for (dst, chunk) in gray.iter_mut().zip(pixels.chunks(channels)) {
                *dst = (chunk[0] & 0xFE) as f64;
            }
        }

        // Symmetric padding: pad by (p1 + p2) / 2 = (3 + 15) / 2 = 9
        let pad = 9usize;
        let (x_pad, hp, wp) = pad_symmetric(&gray, h, w, pad);

        // Stage 1: High-pass filtering (KB 3x3 kernel)
        // High-pass residual: I1 = |x * KB|
        let (h1, w1) = (hp - 2, wp - 2);
        let mut i1 = vec![0.0f64; h1 * w1];
        let kb = &params.high_pass_kernel;
        for i in 0..h1 {
            let r0 = &x_pad[i * wp..(i + 1) * wp];
            let r1 = &x_pad[(i + 1) * wp..(i + 2) * wp];
            let r2 = &x_pad[(i + 2) * wp..(i + 3) * wp];
            for (j, dst) in i1[i * w1..(i + 1) * w1].iter_mut().enumerate() {
                let val = kb[0] * r0[j]
                    + kb[1] * r0[j + 1]
                    + kb[2] * r0[j + 2]
                    + kb[3] * r1[j]
                    + kb[4] * r1[j + 1]
                    + kb[5] * r1[j + 2]
                    + kb[6] * r2[j]
                    + kb[7] * r2[j + 1]
                    + kb[8] * r2[j + 2];
                *dst = val.abs();
            }
        }

        // Stage 2: Low-pass filtering (3x3 average), followed by reciprocal
        let p1 = params.p1_window.max(1);
        let l1 = 1.0f64 / (p1 * p1) as f64;
        let (h2, w2) = (h1 - (p1 - 1), w1 - (p1 - 1));
        let mut i2 = vec![0.0f64; h2 * w2];
        let eps = params.epsilon.max(1e-12);

        for i in 0..h2 {
            for j in 0..w2 {
                let mut sum = 0.0f64;
                for u in 0..p1 {
                    let row = &i1[(i + u) * w1 + j..(i + u) * w1 + j + p1];
                    sum += row.iter().sum::<f64>();
                }
                let avg = sum * l1;
                i2[i * w2 + j] = 1.0f64 / avg.max(eps);
            }
        }

        // Stage 3: Low-pass filtering (15x15 average), separable convolution
        let p2 = params.p2_window.max(1);
        let l2 = 1.0f64 / p2 as f64;

        // Vertical pass
        let mut tmp = vec![0.0f64; h * w2];
        for i in 0..h {
            let dst = &mut tmp[i * w2..(i + 1) * w2];
            for u in 0..p2 {
                let src = &i2[(i + u) * w2..(i + u + 1) * w2];
                for (d, &s) in dst.iter_mut().zip(src) {
                    *d += s * l2;
                }
            }
        }

        // Horizontal pass
        let mut cost = vec![0.0f64; h * w];
        for i in 0..h {
            let src = &tmp[i * w2..(i + 1) * w2];
            for (j, dst) in cost[i * w..(i + 1) * w].iter_mut().enumerate() {
                *dst = src[j..j + p2].iter().sum::<f64>() * l2;
            }
        }

        cost
    }
}

/// Mirror index into [0, n), edge included (SciPy boundary='symm').
fn reflect_index(mut i: isize, n: isize) -> usize {
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

/// Symmetric padding of a row-major 2D matrix of shape [h, w].
fn pad_symmetric(input: &[f64], h: usize, w: usize, pad: usize) -> (Vec<f64>, usize, usize) {
    let (hp, wp) = (h + 2 * pad, w + 2 * pad);
    let cols: Vec<usize> = (0..wp)
        .map(|j| reflect_index(j as isize - pad as isize, w as isize))
        .collect();
    let mut output = vec![0.0f64; hp * wp];
    for i in 0..hp {
        let ii = reflect_index(i as isize - pad as isize, h as isize);
        let src = &input[ii * w..(ii + 1) * w];
        for (dst, &jj) in output[i * wp..(i + 1) * wp].iter_mut().zip(&cols) {
            *dst = src[jj];
        }
    }
    (output, hp, wp)
}
