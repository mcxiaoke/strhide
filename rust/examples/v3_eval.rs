// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Phase 3 measurement harness for the JPEG V3 parameters.
//!
//! Sweeps the two embed-side knobs a user can tune — STC constraint height `h`
//! and the slot budget — over a corpus of JPEG photos, and reports per
//! configuration: the resolved group size `u`, wall-clock embed time, changed
//! coefficients, PSNR against the cover, and file-size growth.
//!
//! ```text
//! cargo run --release --example v3_eval -- [N_IMAGES] [PAYLOAD_BYTES]
//! ```
//!
//! Reads `../temp/images/jpg` (override with `STRHIDE_CORPUS`). The results are
//! recorded in `docs/stc_v3_phase3_eval_20261021.md`; re-run this after changing
//! the cost model or the legality rules, since every number there is a
//! measurement, not an estimate.

use std::path::PathBuf;
use std::time::Instant;

use strhide::stego::format::DEFAULT_JPEG_FORMAT;
use strhide::stego::jpeg::cost::UerdCostModel;
use strhide::stego::jpeg::engine::{embed_jpeg, extract_jpeg, layout_for_payload};
use strhide::stego::params::{ExtractParams, JpegParams};

const PASSWORD: &str = "v3-eval-password";

/// `(h, slot_budget)` grid: the plan's parameter sweep.
const GRID: [(u8, usize); 6] = [
    (6, 400_000),
    (7, 800_000),
    (8, 400_000),
    (8, 800_000),
    (8, 1_200_000),
    (10, 800_000),
];

fn corpus_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("STRHIDE_CORPUS") {
        return PathBuf::from(dir);
    }
    PathBuf::from("../temp/images/jpg")
}

fn decode_pixels(bytes: &[u8]) -> Option<(Vec<u8>, jpeg_decoder::PixelFormat)> {
    let mut decoder = jpeg_decoder::Decoder::new(std::io::Cursor::new(bytes));
    let pixels = decoder.decode().ok()?;
    let info = decoder.info()?;
    Some((pixels, info.pixel_format))
}

fn psnr(a: &[u8], b: &[u8]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return f64::NAN;
    }
    let mse: f64 = a
        .iter()
        .zip(b.iter())
        .map(|(&x, &y)| {
            let d = x as f64 - y as f64;
            d * d
        })
        .sum::<f64>()
        / a.len() as f64;
    if mse == 0.0 {
        f64::INFINITY
    } else {
        10.0 * (255.0 * 255.0 / mse).log10()
    }
}

fn incompressible(len: usize, seed: u64) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ seed;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

#[derive(Default)]
struct Agg {
    n: usize,
    ms: f64,
    flips: f64,
    psnr: f64,
    growth: f64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let limit: usize = args.next().and_then(|v| v.parse().ok()).unwrap_or(8);
    let payload_len: usize = args.next().and_then(|v| v.parse().ok()).unwrap_or(4096);

    let dir = corpus_dir();
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("jpg"))
        })
        .collect();
    files.sort();
    files.truncate(limit);
    if files.is_empty() {
        return Err(format!("no JPEGs in {}", dir.display()).into());
    }

    println!(
        "# V3 evaluation: {} images, {payload_len} B payload\n",
        files.len()
    );
    println!("| h | budget | u | embed ms | flips | PSNR dB | size growth |");
    println!("| ---: | ---: | ---: | ---: | ---: | ---: | ---: |");

    for &(h, budget) in &GRID {
        let mut agg = Agg::default();
        let mut u = 0u8;
        for (i, path) in files.iter().enumerate() {
            let cover = std::fs::read(path)?;
            let payload = incompressible(payload_len, 17 + i as u64);
            let params = JpegParams {
                stc_h: h,
                slot_budget: Some(budget),
                ..JpegParams::default()
            };
            if let Ok(layout) = layout_for_payload(&cover, &payload, &params, &DEFAULT_JPEG_FORMAT)
            {
                u = layout.u;
            }
            let started = Instant::now();
            let Ok(stego) = embed_jpeg(
                &cover,
                &payload,
                Some(PASSWORD),
                None,
                &DEFAULT_JPEG_FORMAT,
                &params,
                strhide::stego::SafetyPolicy::default(),
                &UerdCostModel,
                strhide::stego::Freshness::Random,
            ) else {
                continue;
            };
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            let recovered = extract_jpeg(
                &stego,
                Some(PASSWORD),
                None,
                &DEFAULT_JPEG_FORMAT,
                &ExtractParams::default(),
            )?;
            assert_eq!(recovered, payload, "roundtrip failed for {path:?}");

            let before = dct_io::read_coefficients(&cover)?;
            let after = dct_io::read_coefficients(&stego)?;
            let flips: usize = before.components[0]
                .blocks
                .iter()
                .zip(after.components[0].blocks.iter())
                .map(|(a, b)| a.iter().zip(b.iter()).filter(|(x, y)| x != y).count())
                .sum();
            let psnr_value = match (decode_pixels(&cover), decode_pixels(&stego)) {
                (Some((pa, fa)), Some((pb, fb))) if fa == fb => psnr(&pa, &pb),
                _ => f64::NAN,
            };

            agg.n += 1;
            agg.ms += elapsed;
            agg.flips += flips as f64;
            agg.psnr += psnr_value;
            agg.growth += 100.0 * (stego.len() as f64 - cover.len() as f64) / cover.len() as f64;
        }
        let n = agg.n.max(1) as f64;
        println!(
            "| {h} | {budget} | {u} | {:.0} | {:.0} | {:.2} | {:+.2}% |",
            agg.ms / n,
            agg.flips / n,
            agg.psnr / n,
            agg.growth / n
        );
    }
    Ok(())
}
