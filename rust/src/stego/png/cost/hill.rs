//! High-Low-Low (HILL) spatial domain distortion cost function.
//!
//! Based on B. Li, M. Wang, J. Huang and X. Li,
//! "A New Cost Function for Spatial Image Steganography", ICIP 2014.
//!
//! Evaluates content complexity using a high-pass filter followed by two
//! stages of low-pass smoothing, assigning low costs to complex textures and
//! high costs to smooth/flat areas.

use crate::stego::params::PngParams;
use crate::stego::traits::PngCostModel;

pub struct HillCostModel;

impl Default for HillCostModel {
    fn default() -> Self {
        Self
    }
}

impl PngCostModel for HillCostModel {
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
        params: &PngParams,
    ) -> Vec<f64> {
        let (h, w) = (height, width);
        if w == 0 || h == 0 || pixels.is_empty() {
            return Vec::new();
        }

        // Convert pixels to grayscale luminance using the invariant class bits
        // (`pixel & 0xF8`). The spatial engine only moves pixels inside their
        // eight-value class, so masking the low three bits keeps the cost map
        // bit-for-bit identical between embed and extract — which is what makes
        // the cost-sorted slot ranking reproducible on the stego image.
        let mut gray = vec![0.0f64; h * w];
        if channels == 1 {
            for (dst, &src) in gray.iter_mut().zip(pixels.iter()) {
                *dst = class_value(src) as f64;
            }
        } else if channels >= 3 {
            for i in 0..h * w {
                let r = class_value(pixels[i * channels]) as f64;
                let g = class_value(pixels[i * channels + 1]) as f64;
                let b = class_value(pixels[i * channels + 2]) as f64;
                gray[i] = 0.299 * r + 0.587 * g + 0.114 * b;
            }
        } else {
            for (dst, chunk) in gray.iter_mut().zip(pixels.chunks(channels)) {
                *dst = class_value(chunk[0]) as f64;
            }
        }

        // Symmetric padding must absorb every stage's row/column loss so the
        // final cost map is exactly h x w (composition of scipy `mode='same'`
        // convolutions). Losses: high-pass 2, stage-2 (p1 - 1), stage-3 (p2 - 1),
        // hence `2 * pad = 2 + (p1 - 1) + (p2 - 1)`.
        //
        // For the default windows (p1 = 3, p2 = 15) this is 1 + 1 + 7 = 9, i.e.
        // bit-for-bit identical to the previously hard-coded constant. Any
        // other window pair needs the derived value; the old constant 9 made
        // every p1 + p2 > 18 combination index out of bounds.
        // `p1`/`p2` are validated as positive odd numbers by
        // `PngParams::validate`, so the halving below is exact.
        let p1 = params.p1_window.max(1);
        let p2 = params.p2_window.max(1);
        let pad = 1 + (p1 - 1) / 2 + (p2 - 1) / 2;
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

        // Stage 2: Low-pass filtering (p1 x p1 box average), followed by reciprocal
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

        // Stage 3: Low-pass filtering (p2 x p2 average), separable convolution
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

    /// Asymmetric HILL costs: a `±1` move that brings the pixel *towards* its
    /// neighbourhood mean costs less than one that pushes it further away.
    ///
    /// HILL measures local high-pass energy, so a move that reduces the local
    /// residual is the less visible of the two. The exact per-direction energy
    /// cannot be evaluated per slot at a sane cost, so this uses the squared
    /// residual to the mean of the eight class-masked neighbours as a proxy.
    /// It only ever decides *which way* a slot moves, never *which slot* is
    /// used: ranking stays on the symmetric `base` map, so extraction does not
    /// see this term at all.
    fn direction_costs(
        &self,
        base: &[f64],
        pixels: &[u8],
        width: usize,
        height: usize,
        channels: usize,
        channel: usize,
    ) -> (Vec<f64>, Vec<f64>) {
        let mut plus = Vec::with_capacity(base.len());
        let mut minus = Vec::with_capacity(base.len());
        if width == 0 || height == 0 || base.is_empty() {
            return (plus, minus);
        }
        for i in 0..height {
            for j in 0..width {
                let idx = i * width + j;
                let mean = neighbor_class_mean(pixels, width, height, channels, channel, i, j);
                let v = class_value(pixels[idx * channels + channel]) as f64;
                let rp = ((v + 1.0 - mean) / 255.0).powi(2);
                let rm = ((v - 1.0 - mean) / 255.0).powi(2);
                plus.push(base[idx] * (1.0 + 4.0 * rp));
                minus.push(base[idx] * (1.0 + 4.0 * rm));
            }
        }
        (plus, minus)
    }
}

/// Class representative used by every HILL stage: the low three bits of a
/// pixel are invisible to the cost map because the writer never leaves the
/// pixel's eight-value class.
#[inline]
fn class_value(v: u8) -> u8 {
    v & 0xF8
}

/// Mean of the eight class-masked neighbours of `(i, j)` (centre excluded),
/// with edge clamping. Used only by [`HillCostModel::direction_costs`].
fn neighbor_class_mean(
    pixels: &[u8],
    width: usize,
    height: usize,
    channels: usize,
    channel: usize,
    i: usize,
    j: usize,
) -> f64 {
    let mut sum = 0.0f64;
    for di in -1i32..=1 {
        for dj in -1i32..=1 {
            if di == 0 && dj == 0 {
                continue;
            }
            let ni = (i as i32 + di).clamp(0, height as i32 - 1) as usize;
            let nj = (j as i32 + dj).clamp(0, width as i32 - 1) as usize;
            sum += class_value(pixels[(ni * width + nj) * channels + channel]) as f64;
        }
    }
    sum / 8.0
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic texture: a smooth gradient plus a pseudo-random component,
    /// so both flat and busy regions exist.
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
    fn cost_map_is_invariant_under_class_internal_moves() {
        let (w, h) = (64usize, 48usize);
        let cover = texture_rgb(w, h);
        let params = PngParams::default();
        let model = HillCostModel;

        let base_cover = model.compute_cost(&cover, w, h, 3, &params);

        // Move every third embeddable pixel by ±1, staying inside its class.
        let mut stego = cover.clone();
        let mut moved = 0usize;
        for i in 0..w * h {
            let idx = i * 3 + 1;
            let v = stego[idx];
            if !(8..=247).contains(&v) || i % 3 != 0 {
                continue;
            }
            let r = v % 8;
            let next = if r == 0 {
                v + 1
            } else if r == 7 {
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

    #[test]
    fn direction_costs_follow_the_local_mean() {
        // A dark pixel in a bright neighbourhood should be cheaper to raise
        // than to lower, and vice versa.
        let (w, h) = (8usize, 8usize);
        let mut pixels = vec![200u8; w * h * 3];
        let centre = (3 * w + 3) * 3 + 1;
        pixels[centre] = 96;

        let params = PngParams::default();
        let model = HillCostModel;
        let base = model.compute_cost(&pixels, w, h, 3, &params);
        let (plus, minus) = model.direction_costs(&base, &pixels, w, h, 3, 1);

        let idx = 3 * w + 3;
        assert!(
            plus[idx] < minus[idx],
            "raising a dark pixel towards a bright neighbourhood must be cheaper              (plus {:.6} vs minus {:.6})",
            plus[idx],
            minus[idx]
        );

        pixels[centre] = 240;
        pixels[0] = 100;
        let base = model.compute_cost(&pixels, w, h, 3, &params);
        let (plus, minus) = model.direction_costs(&base, &pixels, w, h, 3, 1);
        assert!(
            minus[idx] < plus[idx],
            "lowering a bright pixel towards a dark neighbourhood must be cheaper              (plus {:.6} vs minus {:.6})",
            plus[idx],
            minus[idx]
        );
    }
}
