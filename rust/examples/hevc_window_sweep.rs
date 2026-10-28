// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! HEVC Streaming Window Sweep Benchmark.
//!
//! Evaluates:
//! 1. Slice Scan Latency Curve (50, 100, 200, 400, 800, 1200, 1600, 2400 slices)
//! 2. Quality (PSNR) vs Speed Trade-off under different Sparsity Window Factors
//!    (1.0x, 1.5x, 2.0x, 2.5x, 3.0x, 4.0x) on real 1080p big HEVC videos.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use strhide::core::control::Control;
use strhide::core::payload::Payload;
use strhide::stego::format::DEFAULT_HEVC_FORMAT;
use strhide::stego::hevc::{
    apply_hevc_patches, bench_scan_slices, embed_hevc_patches_with_factor, extract_hevc,
};
use strhide::stego::{Freshness, SafetyPolicy};

fn run_ffmpeg_psnr(
    stego_path: &Path,
    carrier_path: &Path,
    frames: usize,
    log_path: &Path,
) -> (f64, f64, usize) {
    if log_path.exists() {
        let _ = fs::remove_file(log_path);
    }
    let stats_arg = format!(
        "psnr=stats_file={}",
        log_path.to_str().unwrap().replace('\\', "/")
    );
    let status = Command::new("ffmpeg")
        .args([
            "-v",
            "error",
            "-i",
            stego_path.to_str().unwrap(),
            "-i",
            carrier_path.to_str().unwrap(),
            "-vframes",
            &frames.to_string(),
            "-lavfi",
            &stats_arg,
            "-f",
            "null",
            "-",
        ])
        .status();

    if status.is_err() || !log_path.exists() {
        return (0.0, 0.0, 0);
    }

    let content = fs::read_to_string(log_path).unwrap_or_default();
    let mut modified_psnrs = Vec::new();
    for line in content.lines() {
        if let Some(pos) = line.find("psnr_avg:") {
            let part = &line[pos + 9..];
            let token = part.split_whitespace().next().unwrap_or("");
            if let Some(val) = token.parse::<f64>().ok().filter(|v| v.is_finite()) {
                modified_psnrs.push(val);
            }
        }
    }

    if modified_psnrs.is_empty() {
        return (999.0, 999.0, 0);
    }

    let avg = modified_psnrs.iter().sum::<f64>() / modified_psnrs.len() as f64;
    let min = modified_psnrs.iter().copied().fold(f64::INFINITY, f64::min);
    (avg, min, modified_psnrs.len())
}

fn test_carrier(carrier_path_str: &str) {
    let carrier_path = Path::new(carrier_path_str);
    if !carrier_path.is_file() {
        eprintln!("[SKIP] Carrier not found: {carrier_path_str}");
        return;
    }
    let carrier_name = carrier_path.file_name().unwrap().to_str().unwrap();
    let carrier_bytes = fs::read(carrier_path).expect("read carrier");
    let file_size_mb = carrier_bytes.len() as f64 / 1024.0 / 1024.0;

    println!("\n================================================================================");
    println!("Carrier: {} ({:.2} MB)", carrier_name, file_size_mb);
    println!("================================================================================");

    // Part 1: Slice Scanning Latency Curve
    println!("\n--- Part 1: Slice Scan Latency Curve ---");
    println!(
        "{:>8} | {:>10} | {:>10} | {:>12} | {:>12} | {:>10}",
        "Slices", "Read (ms)", "Full (ms)", "Band0 Slots", "Total Slots", "Equiv. Sec"
    );
    println!("{:-<76}", "");

    let slice_counts = [50, 100, 200, 400, 800, 1200, 1600, 2400];
    for &n in &slice_counts {
        let stats_bits = bench_scan_slices(&carrier_bytes, n, false).expect("scan bits");
        let stats_full = bench_scan_slices(&carrier_bytes, n, true).expect("scan full");

        let read_ms = stats_bits.elapsed_micros as f64 / 1000.0;
        let full_ms = stats_full.elapsed_micros as f64 / 1000.0;
        let equiv_sec = n as f64 / 24.0; // approx 24 fps

        println!(
            "{:>8} | {:>10.2} | {:>10.2} | {:>12} | {:>12} | {:>9.1}s",
            n, read_ms, full_ms, stats_full.band0_slots, stats_full.total_slots, equiv_sec
        );
    }

    // Part 2: Sparsity Window Factor Trade-off (PSNR vs Time)
    println!("\n--- Part 2: Window Factor vs PSNR & Latency Trade-off ---");
    let test_payload_sizes = [(16 * 1024, "16 KiB"), (64 * 1024, "64 KiB")];

    let factors = [1.0, 1.5, 2.0, 2.5, 3.0, 4.0];
    let temp_dir = PathBuf::from("temp/window_sweep");
    let _ = fs::create_dir_all(&temp_dir);
    let log_path = temp_dir.join("psnr_tmp.log");
    let password = "StrHide-Window-Sweep-Pwd";

    for (p_size, p_label) in test_payload_sizes {
        println!("\n[Payload: {} ({} bytes)]", p_label, p_size);
        println!(
            "{:>6} | {:>8} | {:>9} | {:>10} | {:>9} | {:>10} | {:>10} | {:>8}",
            "Factor",
            "Slices",
            "Patches",
            "Embed(ms)",
            "Extr(ms)",
            "Avg PSNR",
            "Min PSNR",
            "ModFrame"
        );
        println!("{:-<86}", "");

        let payload_raw = vec![0x5A; p_size];
        let payload = Payload::bytes(&payload_raw);

        for &factor in &factors {
            let t_embed = Instant::now();
            let (patches, _cap, _stats) = embed_hevc_patches_with_factor(
                &carrier_bytes,
                &payload,
                Some(password),
                None,
                &DEFAULT_HEVC_FORMAT,
                Freshness::Random,
                SafetyPolicy::default(),
                &Control::none(),
                factor,
            )
            .expect("embed failed");
            let embed_ms = t_embed.elapsed().as_secs_f64() * 1000.0;

            let mut stego_bytes = carrier_bytes.clone();
            apply_hevc_patches(&mut stego_bytes, &patches);
            let patches_count = patches.len();

            let t_extract = Instant::now();
            let extracted = extract_hevc(
                &stego_bytes,
                Some(password),
                None,
                &DEFAULT_HEVC_FORMAT,
                &Control::none(),
            )
            .expect("extract failed");
            let extract_ms = t_extract.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(extracted, payload_raw, "extracted payload bit mismatch");

            // Measure PSNR with FFmpeg on first 400 frames
            let stego_file =
                temp_dir.join(format!("stego_{}_{}.mp4", p_size, (factor * 10.0) as u32));
            fs::write(&stego_file, &stego_bytes).expect("write stego");

            let (avg_psnr, min_psnr, mod_frames) =
                run_ffmpeg_psnr(&stego_file, carrier_path, 400, &log_path);

            let _ = fs::remove_file(&stego_file);

            println!(
                "{:>6.1}x | {:>8} | {:>9} | {:>10.1} | {:>9.1} | {:>9.2}dB | {:>9.2}dB | {:>8}",
                factor,
                patches_count, // each patch is a modified slice
                patches.len(),
                embed_ms,
                extract_ms,
                avg_psnr,
                min_psnr,
                mod_frames
            );
        }
    }
}

fn main() {
    let carriers = ["temp/bighevc/anime-a.mp4", "temp/bighevc/anime-b.mp4"];

    for c in carriers {
        test_carrier(c);
    }
}
