//! S-UNIWARD: spatial-domain Universal Wavelet Relative Distortion.
//!
//! Based on V. Holub, J. Fridrich and T. Denemark, "Universal distortion
//! function for steganography in an arbitrary domain", EURASIP Journal on
//! Information Security, 2014.
//!
//! # The measure
//!
//! Distortion is the relative change of the cover's wavelet content:
//!
//! ```text
//! ρ(p) = Σ_band Σ_{p'} |ξ(p → p')| / (|R(p')| + σ)
//! ```
//!
//! where `R` is the cover's wavelet residual and `ξ` is the response of the
//! same wavelet transform to a unit change at `p`. A change is cheap where the
//! cover already has wavelet energy and expensive where it has none, which is
//! exactly "spend your changes in the texture".
//!
//! # Why this is cheap (and J-UNIWARD is not)
//!
//! A single pixel change is a delta, so its wavelet response `ξ` *is* the
//! analysis filter centred at that pixel -- a 2D filter that is separable by
//! construction. `|ξ|` is therefore separable too (`|a ⊗ b| = |a| ⊗ |b|`), so
//! the whole cost collapses into two 16-tap 1D passes per band. In J-UNIWARD
//! the same change perturbs a whole 8x8 block, the response is not a delta, and
//! the equivalent step needs a 23x23 double sum per coefficient.
//!
//! # Symmetry
//!
//! `|ξ|` does not depend on the sign of the change, so `ρ(+1) = ρ(-1)`. No
//! directional preference, hence no [`crate::stego::traits::PngCostModel::direction_costs`]
//! override.
//!
//! # Class invariance
//!
//! The spatial engine *ranks slots by cost* and recomputes that ranking on the
//! stego, so the map has to be bit-identical after embedding. Both the
//! eligibility rule and the writer keep every modified pixel inside its
//! eight-value class (`val & 0xF8` unchanged), so the cost must be computed on
//! class-masked values -- exactly what HILL does, and for the same reason.

use crate::stego::params::PngParams;
use crate::stego::traits::PngCostModel;
use crate::stego::wavelet;

pub struct SuniwardCostModel;

impl Default for SuniwardCostModel {
    fn default() -> Self {
        Self
    }
}

/// Stabilising constant.
///
/// `1.0` matches the reference implementations (conseal / stegolab) on 8-bit
/// input; the paper's `2^-6` figure is the JPEG-domain setting. Overridable
/// through [`PngParams::algorithm_options`] under the key `sigma`.
const DEFAULT_SIGMA: f64 = 1.0;

impl PngCostModel for SuniwardCostModel {
    fn id(&self) -> &'static str {
        "suniward"
    }

    fn description(&self) -> &'static str {
        "S-UNIWARD wavelet-relative distortion model (EURASIP JIS 2014)"
    }

    fn compute_cost(
        &self,
        pixels: &[u8],
        width: usize,
        height: usize,
        channels: usize,
        params: &PngParams,
    ) -> Vec<f64> {
        if width == 0
            || height == 0
            || pixels.is_empty()
            || pixels.len() < width * height * channels
        {
            return Vec::new();
        }
        let (w, h) = (width, height);
        let n = w * h;

        // One luminance plane from the class-masked channels: the same reduction
        // HILL uses, so switching models does not silently change which pixels
        // are considered textured.
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

        let sigma = params
            .model_option("sigma", DEFAULT_SIGMA)
            .max(f64::MIN_POSITIVE);
        let mut cost = vec![0.0f64; n];
        // Two w*h scratch buffers, reused across bands: `tmp` holds the
        // horizontal pass, `residual` the finished residual (then the
        // reciprocal in place).
        let mut tmp = vec![0.0f64; n];
        let mut residual = vec![0.0f64; n];

        for (f1, f2) in wavelet::bands() {
            residual_pass(&plane, w, h, &f1, &f2, &mut tmp, &mut residual);

            // 1 / (|R| + sigma), in place.
            for v in residual.iter_mut() {
                *v = 1.0 / (v.abs() + sigma);
            }

            // Suitability: convolve that with |F|, which is separable into
            // `|f1| ⊗ |f2|`. Accumulate straight into the cost map.
            suitability_pass(&residual, w, h, &f1, &f2, &mut tmp, &mut cost);
        }

        cost
    }
}

/// `R(y, x) = Σ_{a,b} f1[a] f2[b] · plane(y - a + HALF, x - b + HALF)`.
///
/// Separable: horizontal pass into `tmp`, then vertical into `out`. This is a
/// **convolution** (kernel applied reversed, matching `scipy.convolve2d` and
/// the stegolab/hstego references), which is what makes the suitability pass
/// below the exact adjoint: a unit delta at `p` produces
/// `R(p') = f1[y'-y+HALF]·f2[x'-x+HALF]`, so weighting `W(p')` with
/// `|f1|⊗|f2|` read at `p' = p + (a-HALF, b-HALF)` sums precisely
/// `ξ(p → p')` over the delta's response. Edge pixels clamp; zero padding
/// would fake "no texture" along the border and make the outermost ring look
/// specially expensive to change.
fn residual_pass(
    plane: &[f64],
    w: usize,
    h: usize,
    f1: &[f64; wavelet::TAPS],
    f2: &[f64; wavelet::TAPS],
    tmp: &mut [f64],
    out: &mut [f64],
) {
    for y in 0..h {
        let row = &plane[y * w..(y + 1) * w];
        let dst = &mut tmp[y * w..(y + 1) * w];
        for (x, d) in dst.iter_mut().enumerate() {
            let mut acc = 0.0;
            for (b, &cb) in f2.iter().enumerate() {
                let sx = (x as isize - b as isize + wavelet::HALF as isize).clamp(0, w as isize - 1)
                    as usize;
                acc += cb * row[sx];
            }
            *d = acc;
        }
    }
    out.fill(0.0);
    for (a, &ca) in f1.iter().enumerate() {
        if ca == 0.0 {
            continue;
        }
        for y in 0..h {
            let sy = (y as isize - a as isize + wavelet::HALF as isize).clamp(0, h as isize - 1)
                as usize;
            let src_row = &tmp[sy * w..(sy + 1) * w];
            let dst_row = &mut out[y * w..(y + 1) * w];
            for (d, &s) in dst_row.iter_mut().zip(src_row) {
                *d += ca * s;
            }
        }
    }
}

/// `out(y, x) += Σ_{a,b} |f1[a]| |f2[b]| · src(y + a - HALF, x + b - HALF)`.
///
/// The adjoint of [`residual_pass`]: because the residual is a convolution,
/// the response of a delta at `(y, x)` is the kernel read forward from that
/// point, so the suitability weights `|f1| ⊗ |f2|` applied at the *same*
/// `(a - HALF, b - HALF)` offsets sum `ξ(p → p')` over exactly the positions
/// the delta influences. Both passes must use opposite kernel orientations --
/// mirroring either one breaks the `ρ(p) = Σ ξ(p→p')/(|R(p')|+σ)` definition
/// and silently prices the wrong side of every edge.
fn suitability_pass(
    src: &[f64],
    w: usize,
    h: usize,
    f1: &[f64; wavelet::TAPS],
    f2: &[f64; wavelet::TAPS],
    tmp: &mut [f64],
    out: &mut [f64],
) {
    for y in 0..h {
        let row = &src[y * w..(y + 1) * w];
        let dst = &mut tmp[y * w..(y + 1) * w];
        for (x, d) in dst.iter_mut().enumerate() {
            let mut acc = 0.0;
            for (b, &cb) in f2.iter().enumerate() {
                let sx = (x as isize + b as isize - wavelet::HALF as isize).clamp(0, w as isize - 1)
                    as usize;
                acc += cb.abs() * row[sx];
            }
            *d = acc;
        }
    }
    for (a, &ca) in f1.iter().enumerate() {
        let abs_ca = ca.abs();
        if abs_ca == 0.0 {
            continue;
        }
        for y in 0..h {
            let sy = (y as isize + a as isize - wavelet::HALF as isize).clamp(0, h as isize - 1)
                as usize;
            let src_row = &tmp[sy * w..(sy + 1) * w];
            let dst_row = &mut out[y * w..(y + 1) * w];
            for (d, &s) in dst_row.iter_mut().zip(src_row) {
                *d += abs_ca * s;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> PngParams {
        PngParams::default()
    }

    /// Deterministic texture: a gradient plus pseudo-random noise.
    fn texture(w: usize, h: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(w * h * 3);
        let mut state = 0x9e37_79b9u32;
        for i in 0..h {
            for j in 0..w {
                for c in 0..3 {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    let base = ((i * 255 / h.max(1)) + (j * 255 / w.max(1))) / 2;
                    out.push(((base + ((state >> 24) & 0x1F) as usize + c * 3) % 256) as u8);
                }
            }
        }
        out
    }

    #[test]
    fn cost_map_has_the_right_shape_and_is_positive() {
        let (w, h) = (64usize, 48usize);
        let px = texture(w, h);
        let cost = SuniwardCostModel.compute_cost(&px, w, h, 3, &params());
        assert_eq!(cost.len(), w * h);
        assert!(
            cost.iter().all(|c| c.is_finite() && *c > 0.0),
            "every cost must be finite and positive"
        );
    }

    /// The defining property: a flat plane must be more expensive to change than
    /// a busy one. Without this the model is just a slow constant map.
    #[test]
    fn flat_areas_cost_more_than_texture() {
        let (w, h) = (64usize, 64usize);
        let mut px = vec![0u8; w * h * 3];
        // Left half: constant. Right half: heavy noise.
        let mut state = 0x1234_5678u32;
        for i in 0..h {
            for j in 0..w {
                let v = if j < w / 2 {
                    128u8
                } else {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    (state >> 24) as u8
                };
                let base = (i * w + j) * 3;
                px[base] = v;
                px[base + 1] = v;
                px[base + 2] = v;
            }
        }
        let cost = SuniwardCostModel.compute_cost(&px, w, h, 3, &params());

        // Interior columns only: the border ring is dominated by edge clamping.
        let mut flat = 0.0f64;
        let mut flat_n = 0usize;
        let mut busy = 0.0f64;
        let mut busy_n = 0usize;
        for i in 16..h - 16 {
            for j in 16..w - 16 {
                let c = cost[i * w + j];
                if j < w / 2 - 8 {
                    flat += c;
                    flat_n += 1;
                } else if j > w / 2 + 8 {
                    busy += c;
                    busy_n += 1;
                }
            }
        }
        let flat = flat / flat_n as f64;
        let busy = busy / busy_n as f64;
        assert!(
            flat > busy * 3.0,
            "flat areas must cost clearly more (flat {flat:.4e}, busy {busy:.4e})"
        );
    }

    /// The suitability pass must be the adjoint of the residual pass: the
    /// HPDF energy is front-loaded (taps 1..3 hold ~0.31/0.68/0.59, the tail
    /// is ~100x smaller), so a delta's residual lands on the opposite side of
    /// the delta depending on the kernel orientation. With the convolution
    /// residual (the reference convention), a vertical stripe at `x0` puts its
    /// wavelet energy at `x0-7..=x0-5`, and the big suitability taps of a
    /// pixel at `p` read `p-7..=p-5` -- so a stripe at `p+1` makes `p` cheap
    /// while a stripe at `p-11` barely moves its cost. The pre-fix code ran
    /// both passes in the same orientation, which mirrored this relationship
    /// and priced the wrong side of every edge; this test pins the correct
    /// one.
    #[test]
    fn suitability_reads_the_side_the_residual_lands_on() {
        let (w, h) = (96usize, 64usize);
        let probe_x = 40usize;
        let probe_idx = 32 * w + probe_x; // interior row

        let cost_at = |stripe_x: usize| {
            let mut px = vec![128u8; w * h];
            for row in 0..h {
                px[row * w + stripe_x] = 228;
            }
            let cost = SuniwardCostModel.compute_cost(&px, w, h, 1, &params());
            cost[probe_idx]
        };

        let near = cost_at(probe_x + 1);
        let far = cost_at(probe_x - 11);
        // Only the (l,h) band carries the asymmetry on a y-constant plane, so
        // the expected ratio is ~0.73 after the fix and ~1.34 with the mirrored
        // (pre-fix) orientation; 0.85 separates both with margin.
        assert!(
            near < far * 0.85,
            "a stripe whose residual lands under the probe's big taps must be clearly cheaper \
             (stripe@+1: {near:.6}, stripe@-11: {far:.6})"
        );
    }

    /// The engine ranks slots by this map and recomputes it on the stego, so a
    /// class-internal move must not change a single bit.
    #[test]
    fn cost_map_is_invariant_under_class_internal_moves() {
        let (w, h) = (64usize, 48usize);
        let cover = texture(w, h);
        let model = SuniwardCostModel;
        let params = params();

        let base_cover = model.compute_cost(&cover, w, h, 3, &params);

        let mut stego = cover.clone();
        let mut moved = 0usize;
        for i in 0..w * h {
            let idx = i * 3 + 1;
            let v = stego[idx];
            if !(8..=247).contains(&v) {
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
        assert!(moved > 100, "test needs real moves");

        let base_stego = model.compute_cost(&stego, w, h, 3, &params);
        for (i, (a, b)) in base_cover.iter().zip(base_stego.iter()).enumerate() {
            assert_eq!(
                a.to_bits(),
                b.to_bits(),
                "pixel {i}: cost changed after a class-internal move"
            );
        }
    }
}
