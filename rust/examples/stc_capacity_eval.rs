// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Comprehensive batch evaluation of matrix coding layers (Hamming vs STC u=1,2,3)
//! across carrier capacities, payload ratios, distortion, and detection risk.
//!
//! Output is written to CSV files for statistical analysis and threshold discovery:
//! - `temp/stc_eval_results_png.csv`
//! - `temp/stc_eval_results_jpg.csv`

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use rayon::prelude::*;

use strhide::analysis::scan_file;
use strhide::stego::jpeg::cost::UerdCostModel;
use strhide::stego::jpeg::engine::{embed_jpeg, extract_jpeg, probe_jpeg_capacity};
use strhide::stego::jpeg::geometry::geometry_for_carrier;
use strhide::stego::params::{JpegParams, SpatialParams, StegoCodec};
use strhide::stego::spatial::cost::HillCostModel;
use strhide::stego::spatial::engine::{
    decode_png, embed_spatial, extract_spatial, probe_spatial_capacity,
};
use strhide::stego::traits::{JpegCostModel, SpatialCostModel};

const RATIOS: [f64; 7] = [0.10, 0.25, 0.50, 0.75, 0.90, 1.25, 1.75];
const CODECS: [(&str, StegoCodec, u8); 4] = [
    ("hamming", StegoCodec::Hamming, 0),
    ("stc_u1", StegoCodec::Stc, 1),
    ("stc_u2", StegoCodec::Stc, 2),
    ("stc_u3", StegoCodec::Stc, 3),
];
const TEST_PASSWORD: &str = "StcEvalPassw0rd!";

fn generate_deterministic_payload(len: usize, seed_val: u64) -> Vec<u8> {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&seed_val.to_le_bytes());
    seed[8..16].copy_from_slice(&(len as u64).to_le_bytes());
    let mut rng = StdRng::from_seed(seed);
    let mut buf = vec![0u8; len];
    rng.fill(&mut buf[..]);
    buf
}

fn eval_png(png_paths: &[PathBuf], out_csv: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "\n=== Starting PNG Evaluation on {} images ===",
        png_paths.len()
    );
    let file = File::create(out_csv)?;
    let writer = Arc::new(Mutex::new(BufWriter::new(file)));

    {
        let mut w = writer.lock().unwrap();
        writeln!(
            w,
            "carrier,format,w,h,available_slots,c_hamming,payload_bytes,ratio,slot_ratio,codec,u,\
             status,flips,flips_per_bit,sum_rho,rho_per_bit,embed_ms,extract_ms,verify_ok,\
             base_risk,stego_risk,delta_risk"
        )?;
        w.flush()?;
    }

    let progress = AtomicUsize::new(0);
    let total_tasks = png_paths.len() * RATIOS.len() * CODECS.len();
    let task_id_counter = AtomicUsize::new(0);

    png_paths.par_iter().for_each(|path| {
        let carrier_name = path.file_name().unwrap().to_string_lossy().to_string();
        let carrier_bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[ERROR] Read {}: {e}", path.display());
                return;
            }
        };

        // Probe capacity and decode cover
        let default_spatial = SpatialParams::default();
        let cap = match probe_spatial_capacity(&carrier_bytes, &HillCostModel, &default_spatial) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[SKIP] Capacity probe failed on {}: {e}", carrier_name);
                return;
            }
        };
        let c_hamming = cap.max_raw_payload_bytes;
        let available_slots = cap.available_slots;

        let image = match decode_png(&carrier_bytes) {
            Ok(img) => img,
            Err(e) => {
                eprintln!("[SKIP] Decode PNG failed on {}: {e}", carrier_name);
                return;
            }
        };
        let w = image.width as usize;
        let h = image.height as usize;
        let channel_offset = if image.channels >= 3 { 1 } else { 0 };

        // Baseline cost map for distortion calculation
        let costs = HillCostModel.compute_cost(&image.pixels, w, h, image.channels, &default_spatial);

        // Baseline scan risk
        let base_report = scan_file(path).ok();
        let base_risk = base_report.map(|r| r.risk_score).unwrap_or(0);

        for &ratio in &RATIOS {
            let payload_len = ((c_hamming as f64 * ratio).round() as usize).max(1);
            let payload = generate_deterministic_payload(payload_len, 42);
            let needed_bits = payload_len * 8;
            let slot_ratio = available_slots as f64 / needed_bits as f64;

            for &(codec_name, codec, u) in &CODECS {
                let curr_prog = progress.fetch_add(1, Ordering::Relaxed) + 1;
                let tid = task_id_counter.fetch_add(1, Ordering::Relaxed);
                let tmp_stego_path = std::env::temp_dir().join(format!("eval_stego_{tid}.png"));

                let params = SpatialParams {
                    codec,
                    stc_u: u.max(1),
                    ..SpatialParams::default()
                };

                let started_embed = Instant::now();
                let embed_res = embed_spatial(
                    &carrier_bytes,
                    &payload,
                    Some(TEST_PASSWORD),
                    None,
                    &HillCostModel,
                    &params,
                );
                let embed_ms = started_embed.elapsed().as_millis();

                match embed_res {
                    Err(e) => {
                        let err_str = e.to_string();
                        let status = if err_str.contains("Carrier capacity exceeded") {
                            "CAPACITY_EXCEEDED"
                        } else {
                            "ERROR"
                        };
                        let mut csv = writer.lock().unwrap();
                        let _ = writeln!(
                            csv,
                            "{carrier_name},PNG,{w},{h},{available_slots},{c_hamming},{payload_len},{ratio:.2},{slot_ratio:.3},{codec_name},{u},\
                             {status},NA,NA,NA,NA,{embed_ms},NA,NA,{base_risk},NA,NA"
                        );
                        let _ = csv.flush();
                    }
                    Ok(stego_bytes) => {
                        // Write temporary file for black-box scan
                        let _ = std::fs::write(&tmp_stego_path, &stego_bytes);
                        let scan_rep = scan_file(&tmp_stego_path).ok();
                        let stego_risk = scan_rep.map(|r| r.risk_score).unwrap_or(0);
                        let delta_risk = stego_risk as i32 - base_risk as i32;
                        let _ = std::fs::remove_file(&tmp_stego_path);

                        // Extract verification
                        let started_ext = Instant::now();
                        let ext_res = extract_spatial(
                            &stego_bytes,
                            Some(TEST_PASSWORD),
                            None,
                            &HillCostModel,
                            &SpatialParams::default(),
                        );
                        let extract_ms = started_ext.elapsed().as_millis();
                        let verify_ok = match ext_res {
                            Ok(recovered) => recovered == payload,
                            Err(_) => false,
                        };

                        // Compute flips and distortion
                        let (mut flips, mut sum_rho) = (0usize, 0.0f64);
                        if let Ok(after) = decode_png(&stego_bytes) {
                            for y in 0..h {
                                for x in 0..w {
                                    let idx = y * w + x;
                                    let at = idx * image.channels + channel_offset;
                                    if image.pixels[at] != after.pixels[at] {
                                        flips += 1;
                                        sum_rho += costs[idx];
                                    }
                                }
                            }
                        }

                        let flips_per_bit = flips as f64 / needed_bits as f64;
                        let rho_per_bit = sum_rho / needed_bits as f64;

                        let mut csv = writer.lock().unwrap();
                        let _ = writeln!(
                            csv,
                            "{carrier_name},PNG,{w},{h},{available_slots},{c_hamming},{payload_len},{ratio:.2},{slot_ratio:.3},{codec_name},{u},\
                             OK,{flips},{flips_per_bit:.4},{sum_rho:.4e},{rho_per_bit:.4},{embed_ms},{extract_ms},{verify_ok},\
                             {base_risk},{stego_risk},{delta_risk}"
                        );
                        let _ = csv.flush();
                    }
                }

                if curr_prog.is_multiple_of(50) || curr_prog == total_tasks {
                    println!("[PNG Progress] {curr_prog}/{total_tasks} evaluated");
                }
            }
        }
    });

    println!("[PNG Done] Output written to {}", out_csv.display());
    Ok(())
}

fn eval_jpeg(jpg_paths: &[PathBuf], out_csv: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "\n=== Starting JPEG Evaluation on {} images ===",
        jpg_paths.len()
    );
    let file = File::create(out_csv)?;
    let writer = Arc::new(Mutex::new(BufWriter::new(file)));

    {
        let mut w = writer.lock().unwrap();
        writeln!(
            w,
            "carrier,format,w,h,available_slots,c_hamming,payload_bytes,ratio,slot_ratio,codec,u,\
             status,flips,flips_per_bit,sum_rho,rho_per_bit,embed_ms,extract_ms,verify_ok,\
             base_risk,stego_risk,delta_risk"
        )?;
        w.flush()?;
    }

    let progress = AtomicUsize::new(0);
    let total_tasks = jpg_paths.len() * RATIOS.len() * CODECS.len();
    let task_id_counter = AtomicUsize::new(0);

    jpg_paths.par_iter().for_each(|path| {
        let carrier_name = path.file_name().unwrap().to_string_lossy().to_string();
        let carrier_bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[ERROR] Read {}: {e}", path.display());
                return;
            }
        };

        let default_jpeg = JpegParams::default();
        let cap = match probe_jpeg_capacity(&carrier_bytes, &UerdCostModel, &default_jpeg) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[SKIP] JPEG capacity probe failed on {}: {e}", carrier_name);
                return;
            }
        };
        let c_hamming = cap.max_raw_payload_bytes;
        let available_slots = cap.available_slots;

        let orig_coeffs = match dct_io::read_coefficients(&carrier_bytes) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[SKIP] Read DCT coefficients failed on {}: {e:?}", carrier_name);
                return;
            }
        };
        if orig_coeffs.components.is_empty() {
            return;
        }

        let geom = match geometry_for_carrier(
            &carrier_bytes,
            0,
            orig_coeffs.components[0].blocks.len(),
        ) {
            Ok(g) => g,
            Err(e) => {
                eprintln!("[SKIP] Geometry failed on {}: {e:?}", carrier_name);
                return;
            }
        };

        let costs = UerdCostModel.compute_cost(&orig_coeffs, &geom, &default_jpeg);
        let info = match dct_io::inspect(&carrier_bytes) {
            Ok(i) => i,
            Err(_) => return,
        };
        let (w, h) = (info.width as usize, info.height as usize);

        let base_report = scan_file(path).ok();
        let base_risk = base_report.map(|r| r.risk_score).unwrap_or(0);

        for &ratio in &RATIOS {
            let payload_len = ((c_hamming as f64 * ratio).round() as usize).max(1);
            let payload = generate_deterministic_payload(payload_len, 42);
            let needed_bits = payload_len * 8;
            let slot_ratio = available_slots as f64 / needed_bits as f64;

            for &(codec_name, codec, u) in &CODECS {
                let curr_prog = progress.fetch_add(1, Ordering::Relaxed) + 1;
                let tid = task_id_counter.fetch_add(1, Ordering::Relaxed);
                let tmp_stego_path = std::env::temp_dir().join(format!("eval_stego_{tid}.jpg"));

                let params = JpegParams {
                    codec,
                    stc_u: u.max(1),
                    ..JpegParams::default()
                };

                let started_embed = Instant::now();
                let embed_res = embed_jpeg(
                    &carrier_bytes,
                    &payload,
                    Some(TEST_PASSWORD),
                    None,
                    &UerdCostModel,
                    &params,
                );
                let embed_ms = started_embed.elapsed().as_millis();

                match embed_res {
                    Err(e) => {
                        let err_str = e.to_string();
                        let status = if err_str.contains("Carrier capacity exceeded") {
                            "CAPACITY_EXCEEDED"
                        } else {
                            "ERROR"
                        };
                        let mut csv = writer.lock().unwrap();
                        let _ = writeln!(
                            csv,
                            "{carrier_name},JPEG,{w},{h},{available_slots},{c_hamming},{payload_len},{ratio:.2},{slot_ratio:.3},{codec_name},{u},\
                             {status},NA,NA,NA,NA,{embed_ms},NA,NA,{base_risk},NA,NA"
                        );
                        let _ = csv.flush();
                    }
                    Ok(stego_bytes) => {
                        let _ = std::fs::write(&tmp_stego_path, &stego_bytes);
                        let scan_rep = scan_file(&tmp_stego_path).ok();
                        let stego_risk = scan_rep.map(|r| r.risk_score).unwrap_or(0);
                        let delta_risk = stego_risk as i32 - base_risk as i32;
                        let _ = std::fs::remove_file(&tmp_stego_path);

                        let started_ext = Instant::now();
                        let ext_res = extract_jpeg(
                            &stego_bytes,
                            Some(TEST_PASSWORD),
                            None,
                            &UerdCostModel,
                            &JpegParams::default(),
                        );
                        let extract_ms = started_ext.elapsed().as_millis();
                        let verify_ok = match ext_res {
                            Ok(recovered) => recovered == payload,
                            Err(_) => false,
                        };

                        let (mut flips, mut sum_rho) = (0usize, 0.0f64);
                        if let Ok(stego_coeffs) = dct_io::read_coefficients(&stego_bytes)
                            && !stego_coeffs.components.is_empty()
                        {
                            let orig_blocks = &orig_coeffs.components[0].blocks;
                            let stego_blocks = &stego_coeffs.components[0].blocks;
                            for bi in 0..orig_blocks.len().min(stego_blocks.len()) {
                                for k in 0..64 {
                                    if orig_blocks[bi][k] != stego_blocks[bi][k] {
                                        flips += 1;
                                        let cost_idx = bi * 64 + k;
                                        if cost_idx < costs.len() {
                                            sum_rho += costs[cost_idx];
                                        }
                                    }
                                }
                            }
                        }

                        let flips_per_bit = flips as f64 / needed_bits as f64;
                        let rho_per_bit = sum_rho / needed_bits as f64;

                        let mut csv = writer.lock().unwrap();
                        let _ = writeln!(
                            csv,
                            "{carrier_name},JPEG,{w},{h},{available_slots},{c_hamming},{payload_len},{ratio:.2},{slot_ratio:.3},{codec_name},{u},\
                             OK,{flips},{flips_per_bit:.4},{sum_rho:.4e},{rho_per_bit:.4},{embed_ms},{extract_ms},{verify_ok},\
                             {base_risk},{stego_risk},{delta_risk}"
                        );
                        let _ = csv.flush();
                    }
                }

                if curr_prog.is_multiple_of(50) || curr_prog == total_tasks {
                    println!("[JPEG Progress] {curr_prog}/{total_tasks} evaluated");
                }
            }
        }
    });

    println!("[JPEG Done] Output written to {}", out_csv.display());
    Ok(())
}

fn collect_images(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file()
                && p.extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case(ext))
                    .unwrap_or(false)
            {
                files.push(p);
            }
        }
    }
    files.sort();
    files
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let format = args.get(1).map(String::as_str).unwrap_or("both");
    let limit: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

    let png_dir = PathBuf::from("../temp/images/png");
    let jpg_dir = PathBuf::from("../temp/images/jpg");
    let out_png = PathBuf::from("../temp/stc_eval_results_png.csv");
    let out_jpg = PathBuf::from("../temp/stc_eval_results_jpg.csv");

    println!("STC Capacity Evaluation Harness");
    println!("Format mode: {format}, Limit: {limit}");

    if format == "png" || format == "both" {
        let mut pngs = collect_images(&png_dir, "png");
        if limit > 0 && limit < pngs.len() {
            pngs.truncate(limit);
        }
        eval_png(&pngs, &out_png)?;
    }

    if format == "jpg" || format == "both" {
        let mut jpgs = collect_images(&jpg_dir, "jpg");
        if limit > 0 && limit < jpgs.len() {
            jpgs.truncate(limit);
        }
        eval_jpeg(&jpgs, &out_jpg)?;
    }

    println!("\nAll evaluations complete!");
    Ok(())
}
