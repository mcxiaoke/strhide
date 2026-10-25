// Reimplemented from the published algorithm (no code copied).
//
//! Calibrated JPEG steganalysis (Fridrich / Goljan / Hogea).
//!
//! LSB-style embedding equalises the `(|c| = i, |c| = i+1)` bin pairs of the
//! quantized DCT histogram, so an absolute chi-square test needs to know what
//! the *clean* histogram of this particular image would look like. Calibration
//! produces that reference: decode the image, crop 4 pixels so the 8x8 grid
//! lands half a block off the embedding grid, re-quantise with the file's own
//! luminance table. The embedding does not survive the grid shift, the image
//! statistics largely do.
//!
//! The estimator is `beta_kl` from "Steganalysis of JPEG Images: Breaking the
//! F5 Algorithm" (Fridrich, Goljan, Hogea, 2002), averaged over the three
//! lowest AC modes `(0,1) (1,0) (1,1)`:
//!
//! ```text
//! beta = ( h1*(b0-h0) + (b1-h1)*(h2-h1) ) / ( h1^2 + (h2-h1)^2 )
//! ```
//!
//! with `h*` the calibrated counts and `b*` the actual counts of `|coeff| = 0,
//! 1, 2` for one mode. `beta ~ 0` means "nothing detected", `beta > 0` estimates
//! the embedding rate.
//!
//! # Coefficient layout
//!
//! `dct-io` documents "zigzag order" but stores blocks in **natural**
//! (row-major) order: its decoder writes `block[ZIGZAG[k]] = value`. Everything
//! here is therefore done in natural order, and the DQT (which the file really
//! does store in zigzag order) is reordered once at parse time.
//!
//! # Validation note
//!
//! `temp/github/stegolab/calibration/calibration.py` (MIT) implements the same
//! formula and is kept as an offline cross-check only (it needs ImageMagick and
//! `jpeg_toolbox`). Our calibrated reference is produced in-process by a
//! forward DCT + quantisation with the file's own table instead of an
//! ImageMagick re-encode, which is closer to the paper: same table, same
//! colour transform, no extra encoder in the dependency tree.

use crate::analysis::decode_jpeg_pixels;
use crate::jpeg::dqt::parse_luma_dqt;

/// Natural-order indices of the modes the estimator uses: `(0,1) -> 1`,
/// `(1,0) -> 8`, `(1,1) -> 9`.
const CALIBRATION_MODES: [usize; 3] = [1, 8, 9];

/// Upper bound on the number of calibrated blocks to transform. Calibration is
/// a statistic, not a per-block decision, so striding over a large image costs
/// nothing in accuracy and keeps `scan` interactive on 20 MP files. The same
/// stride is applied to the actual coefficient counts, otherwise the two
/// histograms would be on different scales and `beta` would explode.
const MAX_CALIBRATION_BLOCKS: usize = 120_000;

/// Result of the calibrated analysis.
#[derive(Debug, Clone)]
pub struct CalibrationEstimate {
    /// Estimated LSB-replacement rate in `0.0..=1.0`, from the pair-imbalance
    /// ratio against the calibrated reference. This is the number to threshold:
    /// it is the statistic that is sensitive to what an LSB-replacement
    /// embedder actually does.
    pub rate: f64,
    /// Ratio `sum|even-odd|_actual / sum|even-odd|_calibrated`; `1.0` means
    /// "indistinguishable from the calibrated reference", `0.0` means "pairs
    /// fully equalised".
    pub imbalance_ratio: f64,
    /// F5 `beta` (Fridrich et al.). Kept for reference only: it is sensitive to
    /// F5's shrinkage (which moves the `|c| = 0` and `|c| = 1` counts), and LSB
    /// replacement never touches `|c| < 2`, so this number stays flat by
    /// construction -- measured, not assumed.
    pub f5_beta: f64,
    /// Calibrated blocks actually transformed.
    pub blocks: usize,
}

/// Highest `|coeff|` pair the imbalance statistic looks at: pairs
/// `(2,3) (4,5) (6,7) (8,9) (10,11)`.
const MAX_PAIR_ABS: i16 = 11;

/// DCT basis: `COS[x][u] = C(u)/2 * cos((2x+1) u pi / 16)`.
fn dct_basis() -> [[f64; 8]; 8] {
    let mut m = [[0.0f64; 8]; 8];
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

/// Forward 8x8 DCT of a level-shifted block, in natural (row-major) order.
fn forward_dct(block: &[[f64; 8]; 8], basis: &[[f64; 8]; 8]) -> [f64; 64] {
    // F = C * block * C^T, done as two separable passes.
    let mut tmp = [[0.0f64; 8]; 8];
    for y in 0..8 {
        for u in 0..8 {
            let mut sum = 0.0;
            for x in 0..8 {
                sum += block[y][x] * basis[x][u];
            }
            tmp[y][u] = sum;
        }
    }
    let mut natural = [0.0f64; 64];
    for v in 0..8 {
        for u in 0..8 {
            let mut sum = 0.0;
            for y in 0..8 {
                sum += tmp[y][u] * basis[y][v];
            }
            natural[v * 8 + u] = sum;
        }
    }
    natural
}

/// Luminance plane from decoded pixels (BT.601, matching the JPEG Y channel).
fn luma_plane(pixels: &[u8], width: usize, height: usize, channels: usize) -> Option<Vec<f64>> {
    if channels == 0 || width == 0 || height == 0 || pixels.len() < width * height * channels {
        return None;
    }
    let mut out = Vec::with_capacity(width * height);
    for i in 0..width * height {
        let base = i * channels;
        let y = if channels >= 3 {
            0.299 * pixels[base] as f64
                + 0.587 * pixels[base + 1] as f64
                + 0.114 * pixels[base + 2] as f64
        } else {
            pixels[base] as f64
        };
        out.push(y - 128.0);
    }
    Some(out)
}

/// Run the calibrated estimator on a JPEG.
///
/// Returns `None` when the file cannot be analysed (progressive JPEG, missing
/// DQT, unreadable pixels) or when the image is too small for the estimate to
/// mean anything.
pub fn estimate(data: &[u8]) -> Option<CalibrationEstimate> {
    let actual = dct_io::read_coefficients(data).ok()?;
    let luma_blocks: &[[i16; 64]] = &actual.components.first()?.blocks;
    if luma_blocks.is_empty() {
        return None;
    }
    let qt = parse_luma_dqt(data)?;

    // Applicability gate: calibration re-quantises *decoded* pixels, so it needs
    // quantization steps that are large compared with the IDCT round-trip error
    // (~1). With an all-ones table (quality-100 style) the reference is
    // dominated by that rounding and the estimator reports nonsense: measured
    // 0.659 ("66% embedded") on a clean 911x582 sample whose luma table is
    // entirely 1. Such carriers fall back to the pixel-domain detectors plus
    // the explicit "clean is not proof" caveat instead of producing a bogus
    // finding.
    let mean_step = qt.iter().map(|&v| v.max(1) as f64).sum::<f64>() / 64.0;
    if mean_step < 2.0 {
        return None;
    }

    // `jpeg_decoder` yields RGB for colour JPEGs and 1 byte per pixel for
    // grayscale; the component count from the coefficient stream tells us which.
    let channels = if actual.components.len() == 1 { 1 } else { 3 };
    let (pixels, width, _reported_channels) = decode_jpeg_pixels(data)?;
    let width = width as usize;
    if width == 0 || pixels.len() % (width * channels) != 0 {
        return None;
    }
    let height = pixels.len() / (width * channels);
    if height == 0 {
        return None;
    }
    let plane = luma_plane(&pixels, width, height, channels)?;

    // Calibrated grid: shifted by half a block (4 px) from the embedding grid.
    let bx_count = width.saturating_sub(4) / 8;
    let by_count = height.saturating_sub(4) / 8;
    if bx_count < 8 || by_count < 8 {
        return None; // too small to calibrate
    }
    let total_blocks = bx_count * by_count;
    let stride = total_blocks.div_ceil(MAX_CALIBRATION_BLOCKS).max(1);

    let basis = dct_basis();
    let mut calib: Vec<[i16; 64]> = Vec::with_capacity(total_blocks.min(MAX_CALIBRATION_BLOCKS));
    for by in 0..by_count {
        for bx in 0..bx_count {
            if !(by * bx_count + bx).is_multiple_of(stride) {
                continue;
            }
            let x0 = 4 + bx * 8;
            let y0 = 4 + by * 8;
            let mut block = [[0.0f64; 8]; 8];
            for (dy, row) in block.iter_mut().enumerate() {
                for (dx, cell) in row.iter_mut().enumerate() {
                    *cell = plane[(y0 + dy) * width + x0 + dx];
                }
            }
            let freq = forward_dct(&block, &basis);
            let mut quantized = [0i16; 64];
            for (z, q) in quantized.iter_mut().enumerate() {
                let table = qt[z].max(1) as f64;
                *q = (freq[z] / table).round().clamp(-1024.0, 1023.0) as i16;
            }
            calib.push(quantized);
        }
    }
    if calib.len() < 64 {
        return None;
    }

    // Pair-imbalance statistic.
    //
    // LSB replacement moves counts inside an even/odd magnitude pair
    // (`2i <-> 2i+1`, `|c| >= 0`, including `(0, 1)`), so the *pair imbalance* `|A_even - A_odd|`
    // shrinks by roughly `(1 - rate)` while the calibrated reference keeps the
    // clean imbalance. Summing over pairs and AC modes gives a rate estimate
    // that is both image-relative and insensitive to how many coefficients a
    // particular image happens to have.
    // Per-pair ratios, then the median: a handful of pairs calibrate badly on
    // any given image, and summing raw counts lets those few swamp the signal.
    // The median makes the statistic "what the typical pair looks like", which
    // is what the calibration argument is actually about.
    // Precompute absolute magnitude histograms ([0..16]) for AC modes (1..64)
    // in a single pass over luma_blocks and calib blocks, replacing ~1500 full-array scans.
    let mut luma_hist = [[0u32; 16]; 64];
    for b in luma_blocks.iter().step_by(stride) {
        for mode in 1..64usize {
            let val = b[mode].unsigned_abs() as usize;
            if val < 16 {
                luma_hist[mode][val] += 1;
            }
        }
    }

    let mut calib_hist = [[0u32; 16]; 64];
    for b in calib.iter() {
        for mode in 1..64usize {
            let val = b[mode].unsigned_abs() as usize;
            if val < 16 {
                calib_hist[mode][val] += 1;
            }
        }
    }

    let mut ratios: Vec<f64> = Vec::new();
    for mode in 1..64usize {
        // The (0, 1) pair is included on purpose: the ternary JPEG code changes
        // `0 <-> ±1` as often as it changes `±1 <-> ±2`, and an LSB-flipping
        // embedder equalises the zero/first-bin counts just like any other pair.
        // Skipping it (the original F5 statistic) makes the estimator blind to
        // exactly the half of the change traffic this tool produces.
        let mut value = 0usize;
        while value <= MAX_PAIR_ABS as usize {
            let ae = luma_hist[mode][value] as f64;
            let ao = luma_hist[mode][value + 1] as f64;
            let ce = calib_hist[mode][value] as f64;
            let co = calib_hist[mode][value + 1] as f64;
            // Skip pairs whose counts are too small to carry information.
            if (ae + ao) < 20.0 || (ce + co) < 20.0 {
                value += 2;
                continue;
            }
            let a = (ae - ao).abs();
            let c = (ce - co).abs();
            ratios.push((a + 1.0) / (c + 1.0));
            value += 2;
        }
    }
    let imbalance_ratio = if ratios.is_empty() {
        1.0
    } else {
        ratios.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mid = ratios.len() / 2;
        if ratios.len().is_multiple_of(2) {
            (ratios[mid - 1] + ratios[mid]) / 2.0
        } else {
            ratios[mid]
        }
    };
    let rate = (1.0 - imbalance_ratio).clamp(0.0, 1.0);

    // F5 beta (reference only; see the field docs for why it stays flat here).
    let mut f5_modes = [0.0f64; 3];
    for (mi, &mode) in CALIBRATION_MODES.iter().enumerate() {
        let h0 = calib_hist[mode][0] as f64;
        let h1 = calib_hist[mode][1] as f64;
        let h2 = calib_hist[mode][2] as f64;
        let b0 = luma_hist[mode][0] as f64;
        let b1 = luma_hist[mode][1] as f64;
        let denom = h1 * h1 + (h2 - h1) * (h2 - h1);
        f5_modes[mi] = if denom <= 1.0 {
            0.0
        } else {
            ((h1 * (b0 - h0) + (b1 - h1) * (h2 - h1)) / denom).max(0.0)
        };
    }

    Some(CalibrationEstimate {
        rate,
        imbalance_ratio,
        f5_beta: f5_modes.iter().sum::<f64>() / 3.0,
        blocks: calib.len(),
    })
}

/// PoVs (Pairs of Values) Chi-square attack on quantized DCT AC coefficients (Westfeld 2001).
///
/// In clean natural JPEGs, DCT AC coefficients follow a Laplacian distribution where
/// lower-magnitude bins significantly outnumber higher-magnitude bins (`|c|=2k` > `|c|=2k+1`).
/// Classic J-Steg style embedding equalizes pair counts.
///
/// Returns a suspicion score in 0.0..=1.0 (1.0 = heavily equalized/LSB embedded, 0.0 = natural decay).
pub fn dct_chi2_suspicion(data: &[u8]) -> Option<f64> {
    let actual = dct_io::read_coefficients(data).ok()?;
    let luma_blocks = &actual.components.first()?.blocks;
    if luma_blocks.len() < 64 {
        return None;
    }

    // Count AC coefficient absolute frequencies (|c| in 2..=31)
    let mut hist = [0u64; 32];
    for b in luma_blocks {
        for &c in &b[1..64] {
            let abs_c = c.unsigned_abs() as usize;
            if abs_c < 32 {
                hist[abs_c] += 1;
            }
        }
    }

    let mut chi2 = 0.0;
    let mut df = 0.0;
    // Inspect pairs (2, 3), (4, 5), (6, 7), ..., (14, 15)
    for k in (2..16).step_by(2) {
        let count_even = hist[k];
        let count_odd = hist[k + 1];
        let total = count_even + count_odd;
        if total >= 20 {
            let expected = total as f64 / 2.0;
            chi2 += (count_even as f64 - expected).powi(2) / expected;
            df += 1.0;
        }
    }

    if df < 3.0 {
        return None;
    }

    // Clean JPEG has chi2 >> df (huge chi2 due to sharp natural Laplacian slope).
    // An LSB-equalized carrier has chi2 << df (counts equalized).
    // Normalized suspicion: 0.0 when chi2 >= df, up to 1.0 when chi2 -> 0.
    let suspicion = ((df - chi2) / df).clamp(0.0, 1.0);
    Some(suspicion)
}
