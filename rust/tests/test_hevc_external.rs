// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Independent validation of the HEVC Scheme C output with a *real* decoder.
//!
//! The in-tree `h265::Decoder` is also the recorder that produced the operation
//! journal the embedder replays, so the two can only ever prove that they agree
//! with each other. If the recorder misreads a syntax element, embedding and
//! extraction would still round-trip perfectly while the file is undecodable by
//! an actual player. This test uses `ffmpeg` as the outside oracle: it must
//! decode the stego carrier without a single error, its PSNR against the cover
//! must stay high, and — most importantly — both files must decode to the
//! **same geometry** with only a sparse set of visibly changed samples.
//!
//! ```text
//! cargo test --release --test test_hevc_external -- --ignored --nocapture
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use strhide::stego::hevc::{embed_hevc, probe_hevc_capacity};

const PASSWORD: &str = "ExternalValidationPassword#2026";

/// Minimum accepted PSNR (dB) between cover and stego frames. Flipping a
/// sparse set of transform-coefficient signs costs a fraction of a dB at
/// these rates; anything below this means the bitstream changed far more
/// than intended.
const MIN_PSNR_DB: f64 = 30.0;

/// A sample deviation of this many levels or more counts as "visibly
/// changed". Below it the difference is at most a rounding-level wobble.
const LARGE_DELTA: u8 = 16;

/// Upper bound on the fraction of samples that may deviate by more than
/// [`LARGE_DELTA`].
///
/// Measured on the local corpus at ~12% of capacity the observed values are
/// 1.2% .. 4.4%; the limit is set at 12% so the test catches a genuinely
/// damaged bitstream (where the deviation is not sparse at all) without
/// flaking on content that is simply busy.
const MAX_LARGE_FRACTION: f64 = 0.12;

/// Absolute ceiling on the single worst sample deviation.
///
/// 255 is the maximum possible value for an 8-bit sample, so this only
/// rejects a completely corrupted reconstruction. Measured maxima on the
/// local corpus are 51 .. 110.
const MAX_ABS_SAMPLE_DELTA: u8 = 200;

fn ffmpeg_available() -> bool {
    Command::new("ffmpeg")
        .arg("-version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn corpus_dir() -> Option<PathBuf> {
    let dir = std::env::var("STRHIDE_HEVC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("../temp/testhevc"));
    dir.is_dir().then_some(dir)
}

/// Decode both files with ffmpeg and return `(average PSNR, decoder complaints)`.
fn decode_and_compare(reference: &Path, candidate: &Path) -> Result<(f64, Vec<String>), String> {
    let out = Command::new("ffmpeg")
        .args(["-hide_banner", "-nostdin", "-i"])
        .arg(reference)
        .args(["-i"])
        .arg(candidate)
        .args(["-lavfi", "[0:v][1:v]psnr", "-f", "null", "-"])
        .output()
        .map_err(|e| format!("cannot run ffmpeg: {e}"))?;

    let log = String::from_utf8_lossy(&out.stderr).to_string();
    let noise: Vec<String> = log
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            // ffmpeg reports stream/decoder trouble on stderr; a clean decode
            // leaves only the PSNR summary and container chatter.
            [
                "error", "invalid", "corrupt", "missing", "truncat", "failed",
            ]
            .iter()
            .any(|needle| lower.contains(needle))
                && !lower.contains("psnr")
        })
        .map(str::to_string)
        .collect();

    let psnr = log
        .lines()
        .filter_map(|line| line.split("average:").nth(1))
        .filter_map(|tail| tail.split_whitespace().next())
        .filter_map(|value| value.parse::<f64>().ok())
        .next_back()
        .ok_or_else(|| format!("ffmpeg produced no PSNR summary:\n{log}"))?;

    Ok((psnr, noise))
}

/// Decode a file to raw YUV420p and return the raw plane bytes.
///
/// Comparing the *decoded pixels* (not just a PSNR summary) is a much
/// stronger statement than a single aggregate number: it proves that both
/// files decode to the same geometry — same frame count, same dimensions —
/// and that the per-sample deviation stays inside a tight bound. A PSNR
/// average can hide a handful of catastrophically wrong pixels.
fn decode_raw_yuv(path: &Path) -> Result<Vec<u8>, String> {
    let out = Command::new("ffmpeg")
        .args(["-hide_banner", "-nostdin", "-loglevel", "error", "-i"])
        .arg(path)
        .args(["-f", "rawvideo", "-pix_fmt", "yuv420p", "-"])
        .output()
        .map_err(|e| format!("cannot run ffmpeg: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ffmpeg failed to decode {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(out.stdout)
}

/// Result of a pixel-level comparison between cover and stego frames.
struct PixelDiff {
    /// Largest absolute deviation of any single sample.
    max_abs_diff: u8,
    /// Fraction of samples that differ by more than [`LARGE_DELTA`].
    ///
    /// This is the metric that matters perceptually. Flipping a transform
    /// coefficient sign perturbs the reconstructed residual, and the inverse
    /// transform plus deblocking spreads that perturbation over the whole
    /// transform block — so *many* samples may move by one LSB. What must
    /// stay small is the fraction of samples that move by a **visible**
    /// amount.
    large_fraction: f64,
}

fn compare_pixels(cover: &[u8], stego: &[u8]) -> Result<PixelDiff, String> {
    if cover.len() != stego.len() {
        return Err(format!(
            "decoded size mismatch: cover {} bytes, stego {} bytes \
             (different frame count or dimensions)",
            cover.len(),
            stego.len()
        ));
    }
    if cover.is_empty() {
        return Err("decoded no samples at all".to_string());
    }
    let mut max_abs_diff = 0u8;
    let mut large = 0usize;
    for (a, b) in cover.iter().zip(stego.iter()) {
        let d = a.abs_diff(*b);
        if d > max_abs_diff {
            max_abs_diff = d;
        }
        if d > LARGE_DELTA {
            large += 1;
        }
    }
    Ok(PixelDiff {
        max_abs_diff,
        large_fraction: large as f64 / cover.len() as f64,
    })
}

#[test]
#[ignore = "requires ffmpeg on PATH and the local testhevc corpus"]
fn stego_carriers_decode_in_ffmpeg_with_high_psnr() {
    if !ffmpeg_available() {
        eprintln!("[SKIP] ffmpeg not found on PATH");
        return;
    }
    let Some(dir) = corpus_dir() else {
        eprintln!("[SKIP] testhevc corpus not found");
        return;
    };

    let mut checked = 0usize;
    let mut skipped = 0usize;

    for name in [
        "test.heic",
        "IMG_5887.HEIC",
        "IMG_1904.HEIC",
        "IMG_0874.HEIC",
        "IMG_1842.HEIC",
    ] {
        let cover_path = dir.join(name);
        if !cover_path.exists() {
            continue;
        }
        let cover = fs::read(&cover_path).expect("read cover");
        let capacity = match probe_hevc_capacity(&cover) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[SKIP] {name}: not a Scheme C carrier ({e})");
                skipped += 1;
                continue;
            }
        };
        // ~12% of capacity: a representative "real" payload rather than a
        // capacity stress. The PSNR floor below is what separates a genuine
        // sign-flip embedding from a mangled bitstream.
        let payload_len = (capacity / 8).clamp(512, 64 * 1024);
        let payload = vec![0xA5u8; payload_len];

        let stego = embed_hevc(&cover, &payload, Some(PASSWORD)).expect("embed");

        let stego_path = std::env::temp_dir().join(format!(
            "strhide-hevc-ext-{}-{name}.heic",
            std::process::id()
        ));
        fs::write(&stego_path, &stego).expect("write stego carrier");

        let result = decode_and_compare(&cover_path, &stego_path);
        let (psnr, complaints) = result.unwrap_or_else(|e| panic!("{name}: {e}"));

        // Pixel-level equivalence: the two files must decode to the very same
        // geometry, and the deviation must stay small in absolute terms.
        let cover_raw = decode_raw_yuv(&cover_path).unwrap_or_else(|e| panic!("{name}: {e}"));
        let stego_raw = decode_raw_yuv(&stego_path).unwrap_or_else(|e| panic!("{name}: {e}"));
        let diff = compare_pixels(&cover_raw, &stego_raw).unwrap_or_else(|e| panic!("{name}: {e}"));

        let _ = fs::remove_file(&stego_path);

        assert!(
            complaints.is_empty(),
            "{name}: ffmpeg complained while decoding the stego carrier:\n{}",
            complaints.join("\n")
        );
        assert!(
            psnr >= MIN_PSNR_DB,
            "{name}: cover/stego PSNR {psnr:.2} dB is below the {MIN_PSNR_DB:.0} dB floor"
        );
        assert!(
            diff.max_abs_diff <= MAX_ABS_SAMPLE_DELTA,
            "{name}: a decoded sample moved by {} (limit {}), which is more than a \
             coefficient-sign flip should ever cause",
            diff.max_abs_diff,
            MAX_ABS_SAMPLE_DELTA
        );
        assert!(
            diff.large_fraction <= MAX_LARGE_FRACTION,
            "{name}: {:.4} of all decoded samples moved by more than {LARGE_DELTA} \
             (limit {:.4}) — the change is not sparse enough to be a sign flip",
            diff.large_fraction,
            MAX_LARGE_FRACTION
        );
        println!(
            "[OK] {name}: payload {payload_len} B of {capacity} B, ffmpeg clean, \
             PSNR {psnr:.2} dB, {:.4} samples moved > {LARGE_DELTA} (max |d| = {})",
            diff.large_fraction, diff.max_abs_diff
        );
        checked += 1;
    }

    assert!(
        checked > 0,
        "no carrier was validated ({skipped} skipped) — the corpus or ffmpeg is missing"
    );
}
