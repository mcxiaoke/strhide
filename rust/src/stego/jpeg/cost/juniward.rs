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
//! # Cost of the model, and how this implementation factorises it
//!
//! The naive sum is `Σ_{ky,kx} |ΔR[ky][kx]| · W[ky][kx]`, evaluated for *every*
//! one of the 63 AC coefficients of a block. `|ΔR|` happens to be an outer
//! product `|u_i| ⊗ |v_j|` (the DCT basis and the wavelet filters are both
//! separable), so the whole 63-coefficient sweep is one bilinear form on a
//! single shared 23x23 window of the weight plane:
//!
//! ```text
//! S[i][j] = u_iᵀ · P · v_j  =  u_iᵀ · (P · V)        P = weight window
//! ```
//!
//! Evaluating it as `T = P·V` then `Uᵀ·T` costs `23*8*23 + 8*8*23 = 5704`
//! multiply-adds instead of `63*23*23 = 33327`: 5.8x fewer, with the same
//! result up to float summation order. The rest of the win is mechanical: the
//! weight plane is kept pre-padded so the 23x23 gather is a straight
//! `copy_from_slice` (no per-pixel clamp), and windows are padded to 24 columns
//! so the inner products unroll into lanes the compiler can vectorise.
//!
//! The model is symmetric: `|ΔR|` is unchanged when the sign of the change
//! flips, so both directions cost the same and no [`JpegCostModel::direction_bias`]
//! is provided.

use rayon::prelude::*;

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
/// Width the support is rounded up to so the inner products unroll into whole
/// vectors. The spare lane is zero-filled by [`gather`] and contributes nothing.
const LANE: usize = 4;
const PAD: usize = SUPPORT.div_ceil(LANE) * LANE;
/// Padding the weight plane needs left/top of the block.
///
/// This is exactly `-SUPPORT_START`, which is what lets [`gather`] index the
/// padded plane with unshifted block coordinates.
const PAD_LO: usize = (-SUPPORT_START) as usize;
/// Padding right/bottom: `SUPPORT - N - PAD_LO`.
const PAD_HI: usize = SUPPORT - N - PAD_LO;
/// Blocks handed to one parallel task.
///
/// Large enough that the per-task dispatch and scratch setup amortise over the
/// sweep, small enough that the pool still balances on the tail. It also sets how
/// often the AVX2/scalar choice is made: once per task, not once per window.
const SWEEP: usize = 512;
/// Offset between a support index and the DCT-basis row it convolves with.
///
/// # Derivation
///
/// [`separable_residual`] evaluates `ΔR[y] = Σ_a f1[a]·Δplane[y + a - HALF]`, and
/// `Δplane` is non-zero only on rows `[0, N)` of the block. Row `ky` of the
/// gather window is the absolute row `y₀ + SUPPORT_START + ky`, so the basis row
/// it lands on is
///
/// ```text
/// (y₀ + SUPPORT_START + ky) + a - HALF - y₀
///     = ky + a + SUPPORT_START - HALF
///     = ky + a - (2·HALF - 1)
/// ```
///
/// Getting this offset wrong shifts the entire cost map by one block: the
/// weights would be read from the neighbourhood of a different block than the
/// one the coefficient belongs to.
const BASIS_SHIFT: isize = 2 * wavelet::HALF as isize - 1;

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
        let q: [f32; 64] = std::array::from_fn(|i| geometry.luma_q[i].max(1) as f32);

        // Picked once for the whole map: the AVX2 kernel is a type parameter, not
        // a function pointer, because the bilinear factorisation calls it
        // `PAD*8 + 63` times per block and an indirect call per window would cost
        // more than the multiply-adds it wraps.
        //
        // A seeded (reproducible) run stays on the scalar path: FMA fuses the
        // multiply-add and rounds once, the scalar path rounds twice, and that
        // last-bit difference can flip a near-tied trellis decision.
        #[cfg(target_arch = "x86_64")]
        let avx2 = !params.deterministic
            && std::arch::is_x86_feature_detected!("avx2")
            && std::arch::is_x86_feature_detected!("fma");
        #[cfg(not(target_arch = "x86_64"))]
        let avx2 = false;

        cost_map(
            &plane,
            pw,
            ph,
            &geometry.positions,
            &basis,
            &q,
            sigma,
            avx2,
            &mut costs,
        );

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

/// Accumulate the three-band distortion map into `costs`.
///
/// Parallel layout: the three bands run in sequence (three live weight planes
/// would triple the peak footprint, which is already ~400 MB per plane at
/// 100 MP), but inside a band the residual, the reciprocal plane and the block
/// sweep are all band-local and run on the pool.
///
/// Every stage is a pure function of the cover and writes only its own slice, so
/// the result is bit-identical to the single-threaded path — there is no
/// cross-block reduction whose order could change.
#[allow(clippy::too_many_arguments)]
fn cost_map(
    plane: &[f64],
    pw: usize,
    ph: usize,
    positions: &[(usize, usize)],
    basis: &[[f64; N]; N],
    q: &[f32; 64],
    sigma: f64,
    avx2: bool,
    costs: &mut [f64],
) {
    // One padded weight plane, allocated once and refilled per band: the
    // residual stays the only large temporary, so the working set is the same
    // regardless of how many bands there are.
    let (wp, hp) = (pw + PAD_LO + PAD_HI, ph + PAD_LO + PAD_HI);
    let mut weights = vec![0.0f32; wp * hp];

    for (f1, f2) in wavelet::bands() {
        let residual = separable_residual(plane, pw, ph, &f1, &f2);
        reciprocal_plane(&residual, pw, ph, wp, hp, sigma, &mut weights);
        let (u, v) = footprint(basis, &f1, &f2);
        let ctx = SweepCtx {
            weights: &weights,
            wp,
            u: &u,
            v: &v,
            q,
        };

        // `patch` and `mid` are per-worker scratch; `for_each_init` hands each
        // task its own pair instead of rebuilding one per block.
        costs
            .par_chunks_mut(SWEEP * 64)
            .zip(positions.par_chunks(SWEEP))
            .for_each_init(
                || {
                    (
                        [0.0f32; PAD * PAD],
                        // Transposed (`mid[j][ky]`, not `mid[ky][j]`): the second
                        // pass then walks both operands contiguously, which is
                        // what lets it vectorise.
                        [[0.0f32; PAD]; N],
                    )
                },
                |state, (chunk, chunk_positions)| {
                    let (patch, mid) = state;
                    #[cfg(target_arch = "x86_64")]
                    if avx2 {
                        // SAFETY: `avx2` mirrors the `is_x86_feature_detected!`
                        // check made once in `compute_cost`.
                        unsafe { sweep_avx2(chunk, chunk_positions, &ctx, patch, mid) };
                        return;
                    }
                    let _ = avx2;
                    sweep_scalar(chunk, chunk_positions, &ctx, patch, mid);
                },
            );
    }
}

/// Everything one sweep of [`SWEEP`] blocks reads, besides the scratch pair.
struct SweepCtx<'a> {
    weights: &'a [f32],
    wp: usize,
    u: &'a [[f32; PAD]; N],
    v: &'a [[f32; PAD]; N],
    q: &'a [f32; 64],
}

/// Evaluate `S = Uᵀ·(P·V)` for a batch of blocks, accumulating into `costs`.
///
/// `K` is the dot-product kernel; the callers below pick one and let it inline.
/// The batch is a whole parallel task, so dispatching here costs one branch per
/// [`SWEEP`] blocks rather than one per window.
#[inline(always)]
fn sweep_kernel<K: DotKernel>(
    costs: &mut [f64],
    positions: &[(usize, usize)],
    ctx: &SweepCtx<'_>,
    patch: &mut [f32; PAD * PAD],
    mid: &mut [[f32; PAD]; N],
) {
    let SweepCtx {
        weights,
        wp,
        u,
        v,
        q,
    } = *ctx;

    for (bi, &(br, bc)) in positions.iter().enumerate() {
        gather(weights, wp, br * N, bc * N, patch);
        let base = bi * 64;

        // T[j][ky] = Σ_kx patch[ky][kx] · |v_j|[kx]
        for ky in 0..PAD {
            let row = &patch[ky * PAD..ky * PAD + PAD];
            for (mid_j, v_j) in mid.iter_mut().zip(v.iter()) {
                mid_j[ky] = K::dot(row, v_j);
            }
        }

        // S[i][j] = Σ_ky |u_i|[ky] · T[j][ky]
        for (i, u_i) in u.iter().enumerate() {
            for (j, mid_j) in mid.iter().enumerate() {
                // DC never takes part in embedding; leaving it wet keeps the
                // cover digest stable.
                let k = i * N + j;
                if k == 0 {
                    continue;
                }
                let sum = K::dot(u_i, mid_j);
                // `q` scales the perturbation, and `sum` is already relative
                // distortion, so the paper's rho is q * sum.
                costs[base + k] += (q[k] * sum) as f64;
            }
        }
    }
}

fn sweep_scalar(
    costs: &mut [f64],
    positions: &[(usize, usize)],
    ctx: &SweepCtx<'_>,
    patch: &mut [f32; PAD * PAD],
    mid: &mut [[f32; PAD]; N],
) {
    sweep_kernel::<ScalarKernel>(costs, positions, ctx, patch, mid);
}

/// [`sweep_kernel`] specialised for AVX2 + FMA.
///
/// This thin wrapper exists only to establish the target features: the generic
/// kernel inlines into it, and so does [`Avx2Kernel::dot`], which is what lets
/// the intrinsics be emitted in the right context. It runs on a pool thread, so
/// the guarantee is purely about code generation — the runtime check in
/// `compute_cost` is what makes the instructions legal there.
///
/// # Safety
///
/// The caller must have confirmed `avx2` and `fma` via
/// `is_x86_feature_detected!`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
unsafe fn sweep_avx2(
    costs: &mut [f64],
    positions: &[(usize, usize)],
    ctx: &SweepCtx<'_>,
    patch: &mut [f32; PAD * PAD],
    mid: &mut [[f32; PAD]; N],
) {
    sweep_kernel::<Avx2Kernel>(costs, positions, ctx, patch, mid);
}

/// Dot product over a `PAD`-wide window.
trait DotKernel {
    fn dot(a: &[f32], b: &[f32]) -> f32;
}

/// Portable kernel: four independent accumulators break the dependency chain
/// even when the target has no FMA and only four-wide vectors.
struct ScalarKernel;

impl DotKernel for ScalarKernel {
    #[inline(always)]
    fn dot(a: &[f32], b: &[f32]) -> f32 {
        let mut acc = [0.0f32; LANE];
        let mut k = 0;
        while k + LANE <= PAD {
            acc[0] += a[k] * b[k];
            acc[1] += a[k + 1] * b[k + 1];
            acc[2] += a[k + 2] * b[k + 2];
            acc[3] += a[k + 3] * b[k + 3];
            k += LANE;
        }
        let mut tail = 0.0f32;
        while k < PAD {
            tail += a[k] * b[k];
            k += 1;
        }
        (acc[0] + acc[1]) + (acc[2] + acc[3]) + tail
    }
}

#[cfg(target_arch = "x86_64")]
struct Avx2Kernel;

#[cfg(target_arch = "x86_64")]
impl DotKernel for Avx2Kernel {
    #[inline(always)]
    fn dot(a: &[f32], b: &[f32]) -> f32 {
        // SAFETY: this impl is only instantiated from `cost_map_avx2`, which
        // carries `avx2,fma` and is only reachable behind the runtime check.
        unsafe { dot_avx2(a, b) }
    }
}

/// Eight-wide FMA dot product. `PAD` is a multiple of eight for the current
/// filter, so the scalar tail only runs if the wavelet taps ever change.
///
/// # Safety
///
/// Requires `avx2` and `fma`; `a` and `b` must each hold at least `PAD` lanes.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
unsafe fn dot_avx2(a: &[f32], b: &[f32]) -> f32 {
    use std::arch::x86_64::*;
    debug_assert!(a.len() >= PAD && b.len() >= PAD);

    let (pa, pb) = (a.as_ptr(), b.as_ptr());
    let mut acc = _mm256_setzero_ps();
    let mut k = 0;
    while k + 8 <= PAD {
        // SAFETY: the loop bound keeps `k + 8 <= PAD <= a.len() == b.len()`.
        unsafe {
            let va = _mm256_loadu_ps(pa.add(k));
            let vb = _mm256_loadu_ps(pb.add(k));
            acc = _mm256_fmadd_ps(va, vb, acc);
        }
        k += 8;
    }

    let lo = _mm256_castps256_ps128(acc);
    let hi = _mm256_extractf128_ps(acc, 1);
    let sum = _mm_add_ps(lo, hi);
    let sum = _mm_hadd_ps(sum, sum);
    let sum = _mm_hadd_ps(sum, sum);
    let mut total = _mm_cvtss_f32(sum);

    while k < PAD {
        // SAFETY: `k < PAD <= a.len() == b.len()`.
        total += unsafe { *a.get_unchecked(k) } * unsafe { *b.get_unchecked(k) };
        k += 1;
    }
    total
}

/// Wavelet residual of one band: `R[y][x] = Σ_{a,b} f1[a] f2[b] · plane[y+a-8][x+b-8]`.
///
/// The 2D filter is separable, so this runs as two 1D passes. Edge pixels clamp
/// instead of zero-padding: zero padding would fake "no texture" along the
/// border and make the outermost ring look artificially expensive to change.
///
/// Both passes are parallel over rows: a row of the output depends on one row of
/// the previous stage (the vertical pass only *reads* neighbouring rows), so
/// splitting by row never changes a single floating-point operation.
fn separable_residual(
    plane: &[f64],
    pw: usize,
    ph: usize,
    f1: &[f64; wavelet::TAPS],
    f2: &[f64; wavelet::TAPS],
) -> Vec<f64> {
    let mut horizontal = vec![0.0f64; pw * ph];
    horizontal
        .par_chunks_mut(pw)
        .enumerate()
        .for_each(|(y, out)| {
            let row = &plane[y * pw..(y + 1) * pw];
            for (x, dst) in out.iter_mut().enumerate() {
                let mut acc = 0.0;
                for (b, &cb) in f2.iter().enumerate() {
                    let sx = (x as isize + b as isize - wavelet::HALF as isize)
                        .clamp(0, pw as isize - 1) as usize;
                    acc += cb * row[sx];
                }
                *dst = acc;
            }
        });

    let mut out = vec![0.0f64; pw * ph];
    out.par_chunks_mut(pw).enumerate().for_each(|(y, dst)| {
        for (x, o) in dst.iter_mut().enumerate() {
            let mut acc = 0.0;
            for (a, &ca) in f1.iter().enumerate() {
                let sy = (y as isize + a as isize - wavelet::HALF as isize)
                    .clamp(0, ph as isize - 1) as usize;
                acc += ca * horizontal[sy * pw + x];
            }
            *o = acc;
        }
    });
    out
}

/// Reciprocal residual `1 / (|R| + sigma)`, written into a pre-padded plane.
///
/// The border is edge-replicated, matching the clamp [`separable_residual`]
/// applies, so [`gather`] can read a 23-wide window anywhere without a
/// per-element clamp. Only the interior costs a division; the border is copied.
///
/// Interior rows are independent (each writes its own row plus its left/right
/// edges), so they run in parallel. The top and bottom bands are replicated from
/// the first and last interior rows, hence they wait for the parallel part.
fn reciprocal_plane(
    residual: &[f64],
    pw: usize,
    ph: usize,
    wp: usize,
    hp: usize,
    sigma: f64,
    out: &mut [f32],
) {
    debug_assert_eq!(out.len(), wp * hp);

    out.par_chunks_mut(wp)
        .enumerate()
        .skip(PAD_LO)
        .take(ph)
        .for_each(|(y, row)| {
            let source = &residual[(y - PAD_LO) * pw..(y - PAD_LO) * pw + pw];
            for (o, &v) in row[PAD_LO..PAD_LO + pw].iter_mut().zip(source.iter()) {
                *o = (1.0 / (v.abs() + sigma)) as f32;
            }
            let first = row[PAD_LO];
            let last = row[PAD_LO + pw - 1];
            row[..PAD_LO].fill(first);
            row[PAD_LO + pw..PAD_LO + pw + PAD_HI].fill(last);
        });

    // Top and bottom bands as whole rows, which also fixes the corners.
    for y in 0..PAD_LO {
        out.copy_within(PAD_LO * wp..(PAD_LO + 1) * wp, y * wp);
    }
    for y in 0..PAD_HI {
        let from = (PAD_LO + ph - 1) * wp;
        out.copy_within(from..from + wp, (PAD_LO + ph + y) * wp);
    }
}

/// Copy the `SUPPORT x SUPPORT` reciprocal-residual window centred on the block
/// into `patch`, reading the pre-padded plane directly.
///
/// `y0`/`x0` are block origins in the original plane's coordinates. The padded
/// plane's origin sits `PAD_LO` rows/columns above and left of that, which is
/// exactly `-SUPPORT_START`, so the window starts at `y0` inside the padded
/// array. Columns and the final row past `SUPPORT` are zeroed so the padded dot
/// products stay exact; `|u|` and `|v|` are zero there by construction.
#[inline]
fn gather(weights: &[f32], wp: usize, y0: usize, x0: usize, patch: &mut [f32; PAD * PAD]) {
    for ky in 0..SUPPORT {
        let base = (y0 + ky) * wp + x0;
        patch[ky * PAD..ky * PAD + SUPPORT].copy_from_slice(&weights[base..base + SUPPORT]);
        patch[ky * PAD + SUPPORT] = 0.0;
    }
    patch[SUPPORT * PAD..].fill(0.0);
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
) -> ([[f32; PAD]; N], [[f32; PAD]; N]) {
    let mut u = [[0.0f32; PAD]; N];
    let mut v = [[0.0f32; PAD]; N];

    for (i, u_row) in u.iter_mut().enumerate() {
        for (ky, dst) in u_row.iter_mut().take(SUPPORT).enumerate() {
            let mut acc = 0.0f64;
            for (a, &ca) in f1.iter().enumerate() {
                let idx = ky as isize + a as isize - BASIS_SHIFT;
                if (0..N as isize).contains(&idx) {
                    acc += ca * basis[idx as usize][i];
                }
            }
            *dst = acc.abs() as f32;
        }
    }
    for (j, v_row) in v.iter_mut().enumerate() {
        for (kx, dst) in v_row.iter_mut().take(SUPPORT).enumerate() {
            let mut acc = 0.0f64;
            for (b, &cb) in f2.iter().enumerate() {
                let idx = kx as isize + b as isize - BASIS_SHIFT;
                if (0..N as isize).contains(&idx) {
                    acc += cb * basis[idx as usize][j];
                }
            }
            *dst = acc.abs() as f32;
        }
    }
    (u, v)
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
        let mut blocks = vec![[0i16; 64]; 4];
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

    /// The separable footprint must describe the *same* perturbation that
    /// [`separable_residual`] computes, including which rows and columns of the
    /// block it lands on.
    ///
    /// This is the regression guard for [`BASIS_SHIFT`]. With the offset at
    /// `SUPPORT_START` instead of `2*HALF - 1`, the footprint silently described
    /// a block eight pixels away from the one [`gather`] samples, and every cost
    /// was computed on the wrong neighbourhood.
    #[test]
    fn footprint_matches_the_real_residual() {
        let (pw, ph) = (48usize, 48usize);
        let (y0, x0) = (16usize, 16usize);
        let basis = precover::dct_basis();

        for (band, (f1, f2)) in wavelet::bands().iter().enumerate() {
            let (u, v) = footprint(&basis, f1, f2);
            for &(i, j) in &[(1usize, 0usize), (2usize, 3usize), (5usize, 6usize)] {
                // A single coefficient change: the block holds basis(i) ⊗ basis(j).
                let mut plane = vec![0.0f64; pw * ph];
                for r in 0..N {
                    for c in 0..N {
                        plane[(y0 + r) * pw + x0 + c] = basis[r][i] * basis[c][j];
                    }
                }
                let residual = separable_residual(&plane, pw, ph, f1, f2);

                let mut peak = 0.0f64;
                let mut worst = 0.0f64;
                for (ky, &u_ky) in u[i].iter().enumerate().take(SUPPORT) {
                    for (kx, &v_kx) in v[j].iter().enumerate().take(SUPPORT) {
                        let y = (y0 as isize + SUPPORT_START + ky as isize) as usize;
                        let x = (x0 as isize + SUPPORT_START + kx as isize) as usize;
                        let actual = residual[y * pw + x].abs() as f64;
                        let predicted = (u_ky * v_kx) as f64;
                        peak = peak.max(actual);
                        worst = worst.max((predicted - actual).abs());
                    }
                }
                assert!(
                    peak > 0.0,
                    "band {band} coeff ({i},{j}) produced no response"
                );
                assert!(
                    worst / peak < 1e-6,
                    "band {band} coeff ({i},{j}): footprint disagrees with the residual \
                     (peak {peak:e}, worst {worst:e})"
                );
            }
        }
    }

    /// Both dot kernels must agree to float noise. The AVX2 kernel is selected
    /// at runtime, so a divergence would silently make the cost map depend on
    /// which machine built the stego.
    #[test]
    fn dot_kernels_agree() {
        let mut a = [0.0f32; PAD];
        let mut b = [0.0f32; PAD];
        let mut s = 0x2545_f491u32;
        for (x, y) in a.iter_mut().zip(b.iter_mut()) {
            s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *x = (s >> 8) as f32 / 1e6 - 2.0;
            s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *y = (s >> 8) as f32 / 1e6 - 2.0;
        }

        let scalar = ScalarKernel::dot(&a, &b);
        assert!(scalar.is_finite() && scalar != 0.0);

        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("avx2") && std::arch::is_x86_feature_detected!("fma")
        {
            // SAFETY: both features were checked immediately above.
            let avx = unsafe { dot_avx2(&a, &b) };
            let tolerance = 1e-5 * scalar.abs();
            assert!(
                (scalar - avx).abs() <= tolerance,
                "kernels disagree: scalar {scalar}, avx2 {avx}"
            );
        }
    }

    /// The parallel sweep must be deterministic: every block owns its slice of
    /// `costs` and there is no cross-block reduction, so two runs have to agree
    /// bit for bit regardless of how the pool schedules them.
    #[test]
    fn cost_map_is_deterministic_across_runs() {
        let mut blocks = vec![[0i16; 64]; 64];
        for (bi, b) in blocks.iter_mut().enumerate() {
            for (k, v) in b.iter_mut().enumerate().skip(1) {
                *v = (((bi * 11 + k * 17) % 53) as i16) - 26;
            }
        }
        let coeffs = dct_io::JpegCoefficients {
            components: vec![dct_io::ComponentCoefficients { id: 1, blocks }],
        };
        let geometry = JpegGeometry {
            grid_w: 8,
            grid_h: 8,
            positions: (0..64).map(|bi| (bi / 8, bi % 8)).collect(),
            luma_q: [6u16; 64],
        };
        let params = JpegParams::default();
        let first = JuniwardCostModel.compute_cost(&coeffs, &geometry, &params);
        let second = JuniwardCostModel.compute_cost(&coeffs, &geometry, &params);
        assert_eq!(first.len(), second.len());
        for (i, (a, b)) in first.iter().zip(second.iter()).enumerate() {
            assert_eq!(a.to_bits(), b.to_bits(), "cost {i} differs between runs");
        }
    }

    /// On a textured carrier every cost must stay finite and inside the wet cap,
    /// and DC must always be exactly wet.
    #[test]
    fn textured_carrier_stays_inside_the_cap() {
        let mut blocks = vec![[0i16; 64]; 16];
        for (bi, b) in blocks.iter_mut().enumerate() {
            for (k, v) in b.iter_mut().enumerate().skip(1) {
                *v = (((bi * 7 + k * 13) % 41) as i16) - 20;
            }
        }
        let coeffs = dct_io::JpegCoefficients {
            components: vec![dct_io::ComponentCoefficients { id: 1, blocks }],
        };
        let geometry = JpegGeometry {
            grid_w: 4,
            grid_h: 4,
            positions: (0..16).map(|bi| (bi / 4, bi % 4)).collect(),
            luma_q: [4u16; 64],
        };
        let params = JpegParams::default();
        let costs = JuniwardCostModel.compute_cost(&coeffs, &geometry, &params);
        assert_eq!(costs.len(), 16 * 64);
        for (i, c) in costs.iter().enumerate() {
            assert!(c.is_finite(), "cost {i} is not finite");
            assert!(*c > 0.0, "cost {i} is not positive");
            assert!(*c <= params.wet_cost, "cost {i} exceeds the wet cap");
            if i % 64 == 0 {
                assert_eq!(*c, params.wet_cost, "DC {i} must be wet");
            }
        }
    }
}
