//! Spatial-domain statistics on decoded pixels (PNG carriers, 8-bit).
//!
//! Pixel decoding lives here too: the analysis feature must compile without the
//! `content-*` features, so it cannot reuse the stego domain's decoders.

use std::io::{Cursor, Read};

use super::{DetectorMetric, Finding, Severity};

// ---------------------------------------------------------------------------
// Track 2: content-domain statistics on decoded pixels (PNG only, 8-bit)
// ---------------------------------------------------------------------------

/// Minimal PNG decoder: de-zlib all IDAT chunks and undo scanline filtering,
/// returning a flat pixel byte buffer. Returns `None` for interlaced images,
/// non-8-bit depths, or anything that fails to parse — content stats are
/// strictly a bonus track, never a reason to fail the scan.
pub(super) fn decode_png_pixels(data: &[u8]) -> Option<(Vec<u8>, u32, usize)> {
    if data.len() < 8 || &data[..8] != b"\x89PNG\r\n\x1a\n" {
        return None;
    }
    let mut pos = 8usize;
    let mut width: u32 = 0;
    let mut height: u32 = 0;
    let mut bit_depth: u8 = 0;
    let mut color_type: u8 = 0;
    let mut idat: Vec<u8> = Vec::new();
    while pos + 8 <= data.len() {
        let len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let ty = &data[pos + 4..pos + 8];
        let body_start = pos + 8;
        let body_end = body_start.checked_add(len as usize)?;
        if body_end + 4 > data.len() {
            return None;
        }
        let body = &data[body_start..body_end];
        match ty {
            b"IHDR" => {
                if len < 13 {
                    return None;
                }
                width = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                height = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                bit_depth = body[8];
                color_type = body[9];
                if body[12] != 0 {
                    return None; // interlaced — skip
                }
            }
            b"IDAT" => idat.extend_from_slice(body),
            b"IEND" => break,
            _ => {}
        }
        pos = body_end + 4; // skip CRC
    }
    if bit_depth != 8 || width == 0 || height == 0 || idat.is_empty() {
        return None;
    }
    let channels: usize = match color_type {
        0 => 1,
        2 => 3,
        3 => 1,
        4 => 2,
        6 => 4,
        _ => return None,
    };
    let bpp = channels; // 8-bit
    let stride = width as usize * bpp;

    // The scan input is by definition untrusted, and a few hundred KiB of IDAT
    // can inflate to tens of gigabytes. IHDR states exactly how many bytes a
    // valid image produces, so bound the inflate by that and treat an overrun
    // as corruption instead of letting flate2 grow a Vec without limit.
    let expected = stride
        .checked_mul(height as usize)
        .and_then(|v| v.checked_add(height as usize))?; // +1 filter byte per row

    // Reject decompression bombs where declared geometry requires excessive memory.
    const MAX_INFLATE_EXPECTED: usize = 256 * 1024 * 1024; // 256 MiB
    if expected > MAX_INFLATE_EXPECTED {
        return None;
    }

    // Inflate.
    let mut z = flate2::read::ZlibDecoder::new(Cursor::new(&idat)).take(expected as u64 + 1);
    let mut raw = Vec::new();
    if z.read_to_end(&mut raw).is_err() {
        return None;
    }
    if raw.len() < expected {
        return None; // truncated
    }
    if raw.len() != expected {
        return None; // declared geometry does not match the stream: bomb or corrupt
    }

    // Undo filtering row by row.
    let mut out: Vec<u8> = Vec::with_capacity(stride * height as usize);
    let mut prev = vec![0u8; stride];
    let mut rp = 0usize;
    for _ in 0..height {
        let filter = raw[rp];
        rp += 1;
        let line = &raw[rp..rp + stride];
        rp += stride;
        let mut recon = vec![0u8; stride];
        for i in 0..stride {
            let a = if i >= bpp { recon[i - bpp] } else { 0 };
            let b = prev[i];
            let c = if i >= bpp { prev[i - bpp] } else { 0 };
            recon[i] = match filter {
                0 => line[i],
                1 => line[i].wrapping_add(a),
                2 => line[i].wrapping_add(b),
                3 => line[i].wrapping_add(((a as u16 + b as u16) / 2) as u8),
                4 => line[i].wrapping_add(paeth(a, b, c)),
                _ => return None,
            };
        }
        out.extend_from_slice(&recon);
        prev = recon;
    }
    Some((out, width, channels))
}

#[inline]
fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let (a, b, c) = (a as i32, b as i32, c as i32);
    let p = a + b - c;
    let pa = (p - a).abs();
    let pb = (p - b).abs();
    let pc = (p - c).abs();
    if pa <= pb && pa <= pc {
        a as u8
    } else if pb <= pc {
        b as u8
    } else {
        c as u8
    }
}

/// Decode a JPEG to a flat pixel buffer via `jpeg-decoder`.
///
/// The channel count comes from the decoder's own `PixelFormat`: hard-coding 3
/// assumed RGB and mis-scaled every downstream detector on a grayscale image
/// (the row width `width * 3` pointed past each real row, so the statistics were
/// computed on scrambled pixels and silently reported "clean").
pub(super) fn decode_jpeg_pixels(data: &[u8]) -> Option<(Vec<u8>, u32, usize)> {
    use jpeg_decoder::{Decoder, PixelFormat};
    // `jpeg-decoder` allocates from the geometry declared in the header, not
    // from the bytes it has read: a few-KB JPEG claiming 65535x65535 asks for
    // ~12 GiB. Limit the maximum decoded buffer size to 1 GiB to defend
    // against memory exhaustion on untrusted files (admits up to a 350 MP RGB frame).
    const MAX_DECODED_BYTES: usize = 1 << 30;
    let mut decoder = Decoder::new(std::io::Cursor::new(data));
    decoder.set_max_decoding_buffer_size(MAX_DECODED_BYTES);
    let pixels = decoder.decode().ok()?;
    let info = decoder.info()?;
    let channels = match info.pixel_format {
        PixelFormat::L8 => 1,
        PixelFormat::L16 => 2,
        PixelFormat::RGB24 => 3,
        PixelFormat::CMYK32 => 4,
    };
    if pixels.is_empty() {
        None
    } else {
        Some((pixels, info.width as u32, channels))
    }
}

// ---------------------------------------------------------------------------
// Content detectors
// ---------------------------------------------------------------------------

/// Weighted Stego-analysis (WS) for spatial LSB embedding with 8-neighbourhood context (Ker 2007).
///
/// Uses local filtering with both orthogonal and diagonal neighbours to predict cover pixel values,
/// balancing bipartite parity lattices, then estimates the LSB replacement rate alpha via weighted
/// covariance between prediction residuals and LSB flips.
fn ws_channel_stats(pixels: &[u8], width: usize, channels: usize, ch: usize) -> (f64, f64) {
    let stride = match width.checked_mul(channels) {
        Some(s) if s > 0 => s,
        _ => return (0.0, 0.0),
    };
    if pixels.len() < stride * 3 || width < 3 {
        return (0.0, 0.0);
    }
    let rows = (pixels.len() / stride).min(512);
    if rows < 3 {
        return (0.0, 0.0);
    }

    let mut numerator = 0.0f64;
    let mut denominator = 0.0f64;

    for r in 1..rows - 1 {
        let row_curr = r * stride;
        let row_prev = (r - 1) * stride;
        let row_next = (r + 1) * stride;

        for c in 1..width - 1 {
            let off = c * channels + ch;
            let p = pixels[row_curr + off] as f64;

            // Orthogonal neighbours (weight 2 each)
            let p_l = pixels[row_curr + off - channels] as f64;
            let p_r = pixels[row_curr + off + channels] as f64;
            let p_u = pixels[row_prev + off] as f64;
            let p_d = pixels[row_next + off] as f64;

            // Diagonal neighbours (weight 1 each, breaks bipartite checkerboard parity bias)
            let p_lu = pixels[row_prev + off - channels] as f64;
            let p_ru = pixels[row_prev + off + channels] as f64;
            let p_ld = pixels[row_next + off - channels] as f64;
            let p_rd = pixels[row_next + off + channels] as f64;

            let pred = (2.0 * (p_l + p_r + p_u + p_d) + (p_lu + p_ru + p_ld + p_rd)) / 12.0;
            let residual = p - pred;

            let var = 0.25
                * ((p_l - pred).powi(2)
                    + (p_r - pred).powi(2)
                    + (p_u - pred).powi(2)
                    + (p_d - pred).powi(2));
            let w = 1.0 / (1.0 + var).powi(2);

            let p_int = pixels[row_curr + off] as i32;
            let d = (p_int - (p_int ^ 1)) as f64;

            numerator += w * residual * d;
            denominator += w;
        }
    }

    (numerator, denominator)
}

#[allow(dead_code)]
fn ws_analysis(pixels: &[u8], width: u32, channels: usize) -> f64 {
    let width = width as usize;
    let eval_channels = color_channel_count(channels);
    let mut best_rate = 0.0f64;

    for ch in 0..eval_channels {
        let (numerator, denominator) = ws_channel_stats(pixels, width, channels, ch);
        if denominator > 0.0 {
            let alpha = (2.0 * numerator / denominator).clamp(0.0, 1.0);
            if alpha > best_rate {
                best_rate = alpha;
            }
        }
    }

    best_rate
}

/// Flag threshold for the three spatial rate estimators (RS / SPA / WS).
///
/// Calibrated, not inherited from the literature. The textbook 0.05 assumes a
/// clean cover whose histogram is well behaved; on real PNGs the same
/// estimators report 0.2-0.5 on *untouched* images (texture, saturation,
/// compression artifacts), which flagged 25-34% of a 216-cover corpus.
///
/// Measured on that corpus -- 160 DIV2K images plus 56 camera photos stored as PNG:
/// - clean covers: median 0.016-0.022, p90 0.13-0.22, max 0.42-0.73;
/// - the same covers with every LSB *replaced* (the rule these estimators
///   model): median 0.96-1.00;
/// - the same covers with 30% of LSBs replaced: median 0.26-0.37.
///
/// 0.70 keeps 1/216 covers above it per detector (0.5%) while still catching
/// 100% / 85% / 100% of full LSB-replacement carriers (WS / RS / SPA). Two
/// honest limits: a *partial* replacement below roughly half the pixels reads
/// 0.26-0.37 and is not flagged, and this project's own ternary `±1` matching
/// moves the estimates the other way (full load *lowers* them on 27/29
/// carriers), so a clean verdict says nothing about it.
const SPATIAL_RATE_THRESHOLD: f64 = 0.70;

/// Rows per spatial statistics slab.
///
/// Every spatial detector here assumes vertical adjacency (3x3 windows, sample
/// pairs), so a slab must be a *contiguous* run of rows: concatenating unrelated
/// bands would fabricate neighbour pairs that never existed and quietly bias the
/// estimate. Sampling is therefore done by running the detectors on a few
/// contiguous slabs and averaging, not by compacting rows into one buffer.
const SPATIAL_SLAB_ROWS: usize = 512;

/// Maximum pixel bytes per slab, so a very wide carrier does not turn one slab
/// into the whole image again.
const SPATIAL_SLAB_BYTES: usize = 4_000_000;

/// Contiguous row slabs covering the top, middle and bottom of the image.
///
/// The old code analysed `pixels[..4_000_000]` and then capped at 512 rows,
/// which on a 3106x4774 carrier meant the top 6.7% of the picture -- for a
/// landscape that is the sky, and the verdict followed it. Images too short to
/// split are analysed whole, which keeps small carriers on the old behaviour.
pub(super) fn spatial_slabs(pixels: &[u8], stride: usize) -> Vec<&[u8]> {
    if stride == 0 || pixels.len() < stride * 3 {
        return vec![pixels];
    }
    let total_rows = pixels.len() / stride;
    let rows = (SPATIAL_SLAB_BYTES / stride)
        .clamp(3, SPATIAL_SLAB_ROWS)
        .min(total_rows);
    if total_rows <= rows * 3 {
        return vec![&pixels[..total_rows * stride]];
    }
    let mid = (total_rows - rows) / 2;
    vec![
        &pixels[..rows * stride],
        &pixels[mid * stride..(mid + rows) * stride],
        &pixels[(total_rows - rows) * stride..],
    ]
}

/// Number of non-alpha colour/luma channels in an interleaved 8-bit buffer.
///
/// PNG colour types map to 1 (Gray), 2 (Gray+Alpha), 3 (RGB), 4 (RGBA). The
/// trailing channel of the alpha-bearing forms is transparency, not image
/// content: an opaque icon is almost all `255` (or all `0`), which would
/// otherwise dominate chi-square and make RS/SPA/WS report phantom embedding
/// in the alpha plane.
#[inline]
pub(super) fn color_channel_count(channels: usize) -> usize {
    match channels {
        1 | 2 => 1,
        3 | 4 => 3,
        other => other.min(3),
    }
}

pub(super) fn track_spatial_domain(
    pixels: &[u8],
    width: u32,
    channels: usize,
    findings: &mut Vec<Finding>,
    detectors: &mut Vec<DetectorMetric>,
) {
    if width == 0 || channels == 0 {
        return;
    }
    // Sample the whole height instead of the top of the image, and pool the
    // per-slab estimates by averaging: a payload spread over the carrier shows
    // up in every slab, while one anomalous band (sky, flat background) would
    // dominate a maximum.
    let stride = width as usize * channels;
    let slabs = spatial_slabs(pixels, stride);
    let color_channels = color_channel_count(channels);
    let mut hist = [0u64; 256];
    for slab in &slabs {
        for (idx, &b) in slab.iter().enumerate() {
            if idx % channels < color_channels {
                hist[b as usize] += 1;
            }
        }
    }

    let mut ws_rate = 0.0f64;
    let mut spa_rate = 0.0f64;
    for ch in 0..color_channels {
        let (mut num, mut den) = (0.0f64, 0.0f64);
        let (mut x, mut y, mut k, mut pairs) = (0i64, 0i64, 0i64, 0i64);
        for slab in &slabs {
            let (sn, sd) = ws_channel_stats(slab, width as usize, channels, ch);
            num += sn;
            den += sd;
            let (sx, sy, sk, sp) = spa_channel_stats(slab, width as usize, channels, ch);
            x += sx;
            y += sy;
            k += sk;
            pairs += sp;
        }
        if den > 0.0 {
            let r = (2.0 * num / den).clamp(0.0, 1.0);
            if r > ws_rate {
                ws_rate = r;
            }
        }
        let sr = solve_spa(x, y, k, pairs);
        if sr > spa_rate {
            spa_rate = sr;
        }
    }

    let (mut rs_sum, mut rs_n) = (0.0f64, 0usize);
    for slab in &slabs {
        if let Some(p) = rs_analysis(slab, width, channels) {
            rs_sum += p;
            rs_n += 1;
        }
    }
    let rs_rate = if rs_n > 0 {
        Some(rs_sum / rs_n as f64)
    } else {
        None
    };

    // 1. WS (Weighted Stego-analysis)
    if ws_rate > SPATIAL_RATE_THRESHOLD {
        findings.push(Finding {
            detector: "spatial:ws".into(),
            // Deliberately informational: WS over-reports on content-adaptive
            // embedding that keeps the visual statistics intact, and the scan
            // verdict is calibrated against that. The status is INFO to match,
            // instead of claiming ALERT while the verdict stays clean.
            severity: Severity::Info,
            detail: format!("Weighted Stego-analysis (WS) estimates LSB rate ~{ws_rate:.2}"),
        });
        detectors.push(DetectorMetric {
            name: "spatial:ws".into(),
            domain: "spatial".into(),
            status: "INFO".into(),
            metric: format!("rate: {ws_rate:.3}"),
            threshold: Some(format!("{SPATIAL_RATE_THRESHOLD:.3}")),
            detail: "prediction residual covariance elevated".into(),
        });
    } else {
        detectors.push(DetectorMetric {
            name: "spatial:ws".into(),
            domain: "spatial".into(),
            status: "PASS".into(),
            metric: format!("rate: {ws_rate:.3}"),
            threshold: Some(format!("{SPATIAL_RATE_THRESHOLD:.3}")),
            detail: "prediction residuals within normal bounds".into(),
        });
    }

    // 2. RS Analysis
    if let Some(rs_p) = rs_rate {
        if rs_p > SPATIAL_RATE_THRESHOLD {
            findings.push(Finding {
                detector: "rs-analysis".into(),
                severity: Severity::Suspicious,
                detail: format!("RS analysis estimates LSB embedding rate ~{rs_p:.2}"),
            });
            detectors.push(DetectorMetric {
                name: "spatial:rs".into(),
                domain: "spatial".into(),
                status: "ALERT".into(),
                metric: format!("rate: {rs_p:.3}"),
                threshold: Some(format!("{SPATIAL_RATE_THRESHOLD:.3}")),
                detail: "dual-mask flipping asymmetry".into(),
            });
        } else {
            detectors.push(DetectorMetric {
                name: "spatial:rs".into(),
                domain: "spatial".into(),
                status: "PASS".into(),
                metric: format!("rate: {rs_p:.3}"),
                threshold: Some(format!("{SPATIAL_RATE_THRESHOLD:.3}")),
                detail: "dual-mask symmetry preserved".into(),
            });
        }
    } else {
        detectors.push(DetectorMetric {
            name: "spatial:rs".into(),
            domain: "spatial".into(),
            status: "SKIPPED".into(),
            metric: "n/a".into(),
            threshold: Some(format!("{SPATIAL_RATE_THRESHOLD:.3}")),
            detail: "image geometry unsuitable for RS slab sampling".into(),
        });
    }

    // 3. SPA (Sample Pair Analysis)
    let spa_p = spa_rate;
    if spa_p > SPATIAL_RATE_THRESHOLD {
        findings.push(Finding {
            detector: "spa".into(),
            severity: Severity::Suspicious,
            detail: format!("Sample Pair Analysis (DWW) estimates embedding rate ~{spa_p:.2}"),
        });
        detectors.push(DetectorMetric {
            name: "spatial:spa".into(),
            domain: "spatial".into(),
            status: "ALERT".into(),
            metric: format!("rate: {spa_p:.3}"),
            threshold: Some(format!("{SPATIAL_RATE_THRESHOLD:.3}")),
            detail: "DWW sample pair trace deviation".into(),
        });
    } else {
        detectors.push(DetectorMetric {
            name: "spatial:spa".into(),
            domain: "spatial".into(),
            status: "PASS".into(),
            metric: format!("rate: {spa_p:.3}"),
            threshold: Some(format!("{SPATIAL_RATE_THRESHOLD:.3}")),
            detail: "sample pair trace counts normal".into(),
        });
    }

    // 4. Chi-square LSB attack (pooled histogram over every slab)
    let chi2_score = chi2_suspicion(&hist);
    if chi2_score > 0.5 {
        findings.push(Finding {
            detector: "chi2-lsb".into(),
            severity: Severity::Suspicious,
            detail: format!(
                "Chi-square LSB attack: pair histogram looks uniform (suspicion {chi2_score:.2}) \
                 - consistent with LSB embedding"
            ),
        });
        detectors.push(DetectorMetric {
            name: "spatial:chi2".into(),
            domain: "spatial".into(),
            status: "ALERT".into(),
            metric: format!("suspicion: {chi2_score:.3}"),
            threshold: Some("0.500".into()),
            detail: "LSB pair histogram artificially uniform".into(),
        });
    } else {
        detectors.push(DetectorMetric {
            name: "spatial:chi2".into(),
            domain: "spatial".into(),
            status: "PASS".into(),
            metric: format!("suspicion: {chi2_score:.3}"),
            threshold: Some("0.500".into()),
            detail: "LSB pair counts match natural distribution".into(),
        });
    }
}

#[allow(dead_code)]
fn track_content_domain(pixels: &[u8], width: u32, channels: usize, out: &mut Vec<Finding>) {
    let mut unused_detectors = Vec::new();
    track_spatial_domain(pixels, width, channels, out, &mut unused_detectors);
}

/// Westfeld & Pfitzmann 1999, Chi-square attack on LSB embedding.
///
/// Under LSB embedding, value pairs (2i, 2i+1) migrate toward equal counts.
/// We return how far the observed chi-square statistic is below the
/// expectation df (≈127 for 8-bit pixels), normalised to 0..1.
#[cfg(test)]
pub(super) fn chi2_lsb_suspicion(data: &[u8]) -> f64 {
    let mut hist = [0u64; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    chi2_suspicion(&hist)
}

/// [`chi2_lsb_suspicion`] over an already-built histogram.
///
/// Split out so the pooled histogram of several sampled slabs yields exactly
/// the same statistic as one pass over all of them would.
fn chi2_suspicion(hist: &[u64; 256]) -> f64 {
    let mut total_imbalance = 0.0;
    let mut count = 0.0;
    for i in (0..256).step_by(2) {
        let total = hist[i] + hist[i + 1];
        if total >= 8 {
            let diff = (hist[i] as f64 - hist[i + 1] as f64).abs();
            total_imbalance += diff / total as f64;
            count += 1.0;
        }
    }
    if count == 0.0 {
        return 0.0;
    }
    let avg_imbalance = total_imbalance / count;
    // When pair counts are equalized (LSB embedded), avg_imbalance -> 0, suspicion -> 1.0.
    // In clean natural images, local gradients cause natural imbalance, dropping suspicion to 0.0.
    (1.0 - avg_imbalance * 4.0).clamp(0.0, 1.0)
}

#[derive(Clone, Copy)]
pub(super) enum RsMask {
    Plus,
    Minus,
}

fn rs_window_smoothness(w: &[i32; 9]) -> i64 {
    let mut s = 0i64;
    for r in 0..2 {
        for c in 0..3 {
            s += (w[r * 3 + c] - w[(r + 1) * 3 + c]).unsigned_abs() as i64;
        }
    }
    for r in 0..3 {
        for c in 0..2 {
            s += (w[r * 3 + c] - w[r * 3 + c + 1]).unsigned_abs() as i64;
        }
    }
    s
}

pub(super) fn rs_difference(plane: &[i32], rows: usize, cols: usize, mask: RsMask) -> f64 {
    if rows < 4 || cols < 4 {
        return 0.0;
    }
    let (mut r_count, mut s_count, mut n) = (0i64, 0i64, 0i64);
    // A 3x3 window starting at `i` needs `i + 2 < rows`, so the last valid starting index is `rows - 3`.
    for i in 0..rows - 2 {
        for j in 0..cols - 2 {
            let mut w = [0i32; 9];
            for dr in 0..3 {
                for dc in 0..3 {
                    w[dr * 3 + dc] = plane[(i + dr) * cols + (j + dc)];
                }
            }
            let orig = rs_window_smoothness(&w);
            let mut f = w;
            f[4] = match mask {
                RsMask::Plus => w[4] ^ 1,
                RsMask::Minus => {
                    let x = w[4];
                    if x & 1 == 0 { x - 1 } else { x + 1 }
                }
            };
            n += 1;
            match rs_window_smoothness(&f).cmp(&orig) {
                std::cmp::Ordering::Greater => r_count += 1,
                std::cmp::Ordering::Less => s_count += 1,
                std::cmp::Ordering::Equal => {}
            }
        }
    }
    if n == 0 {
        return 0.0;
    }
    (r_count - s_count) as f64 / n as f64
}

fn aletheia_rs(plane: &[i32], rows: usize, cols: usize) -> f64 {
    let inverted: Vec<i32> = plane.iter().map(|&v| v ^ 1).collect();
    let d0 = rs_difference(plane, rows, cols, RsMask::Plus);
    let d1 = rs_difference(&inverted, rows, cols, RsMask::Plus);
    let n_d0 = rs_difference(plane, rows, cols, RsMask::Minus);
    let n_d1 = rs_difference(&inverted, rows, cols, RsMask::Minus);

    let a = 2.0 * (d1 + d0);
    let b = n_d0 - n_d1 - d1 - 3.0 * d0;
    let c = d0 - n_d0;
    if a.abs() < 1e-12 {
        return 0.0;
    }
    let disc = b * b - 4.0 * a * c;
    if disc < 0.0 {
        return 0.0;
    }
    let sq = disc.sqrt();
    let p0 = (-b + sq) / (2.0 * a);
    let p1 = (-b - sq) / (2.0 * a);
    let z = if p0.abs() < p1.abs() { p0 } else { p1 };
    if (z - 0.5).abs() < 1e-12 {
        return 0.0;
    }
    (z / (z - 0.5)).clamp(0.0, 1.0)
}

pub(super) fn rs_analysis(pixels: &[u8], width: u32, channels: usize) -> Option<f64> {
    let width = width as usize;
    let stride = width.checked_mul(channels)?;
    if stride == 0 || pixels.len() < stride * 4 || width < 4 {
        return None;
    }
    let rows = (pixels.len() / stride).min(512);
    let eval_channels = color_channel_count(channels);
    let mut best: Option<f64> = None;
    for ch in 0..eval_channels {
        let mut plane = Vec::with_capacity(rows * width);
        for row in 0..rows {
            let base = row * stride + ch;
            for col in 0..width {
                plane.push(pixels[base + col * channels] as i32);
            }
        }
        let score = aletheia_rs(&plane, rows, width);
        best = Some(best.map_or(score, |b: f64| b.max(score)));
    }
    // `Some(0.0)` is a valid estimate on a clean image: it means "no LSB
    // replacement detected", not "the geometry was unsuitable". Only a true
    // lack of samples returns `None`.
    best
}

fn spa_channel_stats(
    pixels: &[u8],
    width: usize,
    channels: usize,
    ch: usize,
) -> (i64, i64, i64, i64) {
    let stride = match width.checked_mul(channels) {
        Some(s) if s > 0 => s,
        _ => return (0, 0, 0, 0),
    };
    if pixels.len() < stride * 2 || width == 0 {
        return (0, 0, 0, 0);
    }
    let rows = (pixels.len() / stride).min(512);
    if rows < 2 {
        return (0, 0, 0, 0);
    }

    let mut x: i64 = 0;
    let mut y: i64 = 0;
    let mut k: i64 = 0;
    let mut pair_count: i64 = 0;
    for row in 0..rows - 1 {
        let top = row * stride;
        let bot = top + stride;
        for col in 0..width {
            let off = col * channels + ch;
            let r = pixels[top + off] as i32;
            let s = pixels[bot + off] as i32;
            pair_count += 1;
            let s_even = (s & 1) == 0;
            let r_lt = r < s;
            let r_gt = r > s;
            if (s_even && r_lt) || (!s_even && r_gt) {
                x += 1;
            }
            if (s_even && r_gt) || (!s_even && r_lt) {
                y += 1;
            }
            if (r & 0xFE) == (s & 0xFE) {
                k += 1;
            }
        }
    }
    (x, y, k, pair_count)
}

fn solve_spa(x: i64, y: i64, k: i64, pair_count: i64) -> f64 {
    if k == 0 || pair_count == 0 {
        return 0.0;
    }
    // DWW quadratic: a*beta^2 + b*beta + c = 0, alpha = 2*beta.
    let a = (2 * k) as f64;
    let b = (2 * (2 * x - pair_count)) as f64;
    let c = (y - x) as f64;
    let disc = b * b - 4.0 * a * c;
    let beta = if disc < 0.0 {
        -b / (2.0 * a)
    } else {
        (-b - disc.sqrt()) / (2.0 * a)
    };
    (2.0 * beta).clamp(0.0, 1.0)
}

/// Sample Pair Analysis (Dumitrescu, Wu & Wang 2003), faithful to the
/// Aletheia `spa_image` reference. Walks vertically adjacent pixel pairs,
/// accumulates the DWW trace-set counters (x, y, k), and solves the
/// quadratic for the LSB-replacement embedding rate alpha.
#[allow(dead_code)]
fn spa_estimate_dww(pixels: &[u8], width: u32, channels: usize) -> f64 {
    let width = width as usize;
    let eval_channels = color_channel_count(channels);
    let mut best = 0.0_f64;
    for ch in 0..eval_channels {
        let (x, y, k, pair_count) = spa_channel_stats(pixels, width, channels, ch);
        let alpha = solve_spa(x, y, k, pair_count);
        if alpha > best {
            best = alpha;
        }
    }
    best
}
