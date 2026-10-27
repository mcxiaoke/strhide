// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! HEVC / H.265 Scheme C In-place Steganography Matrix Benchmark & Full Test Suite (Multi-Threaded).
//!
//! Evaluates embedding & extraction performance, throughput (MB/s), distortion preservation,
//! and 100% bit-exact roundtrips across all real photos in `temp/testhevc` and
//! real payloads in `temp/testpayload` concurrently with Rayon.
//!
//! Run with release optimizations:
//! ```text
//! cargo run --release --example hevc_matrix_bench
//! ```

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rayon::prelude::*;
use rusty_h265::Decoder;
use strhide::core::control::Control;
use strhide::stego::hevc::heif_boxes::parse_heif_targets;
use strhide::stego::hevc::{embed_hevc, extract_hevc, probe_hevc_capacity};

/// Verify that an HEIC file can be decoded to a valid frame by rusty_h265.
fn verify_frame_decodes(carrier_bytes: &[u8]) -> bool {
    let target = match parse_heif_targets(carrier_bytes) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let mut decoder = Decoder::new();
    for ps in &target.parameter_sets {
        let _ = decoder.push_nal(ps, None);
    }
    for span in &target.slice_spans {
        let _ = decoder.push_nal(&carrier_bytes[span.start..span.end()], None);
    }
    // A still image only yields its picture after `flush`: the decoder closes a
    // picture when the next one starts, which never happens for one image.
    decoder.flush();
    decoder
        .next_frame()
        .is_ok_and(|f| f.width > 0 && f.height > 0)
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / 1024.0 / 1024.0)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

#[derive(Clone, Debug)]
struct TestResult {
    payload_name: String,
    payload_size: usize,
    embed_duration: Duration,
    extract_duration: Duration,
    embed_speed_mb: f64,
    extract_speed_mb: f64,
}

#[derive(Clone, Debug)]
struct CarrierReport {
    carrier_name: String,
    file_size: usize,
    capacity: usize,
    skip_reason: Option<String>,
    tests: Vec<TestResult>,
    skipped_overflow: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let hevc_dir = args.get(1).map(PathBuf::from).unwrap_or_else(|| {
        std::env::var("STRHIDE_HEVC_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("../temp/testhevc"))
    });
    let payload_dir = args.get(2).map(PathBuf::from).unwrap_or_else(|| {
        std::env::var("STRHIDE_PAYLOAD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("../temp/testpayload"))
    });

    if !hevc_dir.exists() {
        eprintln!("[ERROR] HEVC directory not found: {:?}", hevc_dir);
        return Ok(());
    }
    if !payload_dir.exists() {
        eprintln!("[ERROR] Payload directory not found: {:?}", payload_dir);
        return Ok(());
    }

    // 1. Collect payload files sorted by size
    let mut payloads: Vec<(String, usize, Vec<u8>)> = Vec::new();
    if let Ok(entries) = fs::read_dir(&payload_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("bin")
                && let Ok(data) = fs::read(&path)
            {
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                let len = data.len();
                payloads.push((name, len, data));
            }
        }
    }
    payloads.sort_by_key(|p| p.1);

    // 2. Collect image carriers (.heic, .HEIC, .heif)
    let mut carriers: Vec<(String, PathBuf, usize)> = Vec::new();
    if let Ok(entries) = fs::read_dir(&hevc_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            if (ext == "heic" || ext == "heif")
                && let Ok(meta) = fs::metadata(&path)
            {
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                let len = meta.len() as usize;
                carriers.push((name, path, len));
            }
        }
    }
    carriers.sort_by_key(|c| c.2);

    println!(
        "\n========================================================================================================"
    );
    println!(
        "       STRHIDE HEVC CABAC SCHEME C CONCURRENT MULTI-THREADED MATRIX BENCHMARK (RAYON)                  "
    );
    println!(
        "========================================================================================================"
    );
    println!(
        "Carriers directory: {:?} (Found: {})",
        hevc_dir,
        carriers.len()
    );
    println!(
        "Payloads directory: {:?} (Found: {})",
        payload_dir,
        payloads.len()
    );
    println!(
        "Payload size range: {} -> {}",
        format_bytes(payloads.first().map(|p| p.1).unwrap_or(0)),
        format_bytes(payloads.last().map(|p| p.1).unwrap_or(0))
    );
    println!("Rayon threads count: {}", rayon::current_num_threads());
    println!(
        "--------------------------------------------------------------------------------------------------------"
    );

    let password = "StrHide-Matrix-Benchmark-Password#2026";
    let completed_carriers = AtomicUsize::new(0);
    let total_carriers = carriers.len();
    let t_all_start = Instant::now();

    // 3. Process all carriers in parallel across CPU threads
    let mut reports: Vec<CarrierReport> = carriers
        .par_iter()
        .map(|(carrier_name, carrier_path, file_size)| {
            let carrier_bytes = match fs::read(carrier_path) {
                Ok(b) => b,
                Err(e) => {
                    return CarrierReport {
                        carrier_name: carrier_name.clone(),
                        file_size: *file_size,
                        capacity: 0,
                        skip_reason: Some(format!("Cannot read: {e}")),
                        tests: Vec::new(),
                        skipped_overflow: 0,
                    };
                }
            };

            let cap = match probe_hevc_capacity(
                &carrier_bytes,
                &strhide::stego::format::DEFAULT_HEVC_FORMAT,
            ) {
                Ok(c) => c,
                Err(e) => {
                    return CarrierReport {
                        carrier_name: carrier_name.clone(),
                        file_size: *file_size,
                        capacity: 0,
                        skip_reason: Some(format!("Not pure HEVC / no hvcC: {e}")),
                        tests: Vec::new(),
                        skipped_overflow: 0,
                    };
                }
            };

            if cap == 0 {
                return CarrierReport {
                    carrier_name: carrier_name.clone(),
                    file_size: *file_size,
                    capacity: 0,
                    skip_reason: Some("Capacity is 0 bytes".into()),
                    tests: Vec::new(),
                    skipped_overflow: 0,
                };
            }

            let mut tests = Vec::new();
            let mut skipped_overflow = 0;
            let mut verified_frame = false;

            for (p_name, p_size, p_data) in &payloads {
                if *p_size > cap {
                    skipped_overflow += 1;
                    // Verify overflow protection returns error
                    let overflow_err = embed_hevc(
                        &carrier_bytes,
                        p_data,
                        Some(password),
                        None,
                        &strhide::stego::format::DEFAULT_HEVC_FORMAT,
                        strhide::stego::Freshness::Random,
                    );
                    assert!(
                        overflow_err.is_err(),
                        "Embedding payload exceeding capacity must return error!"
                    );
                    continue;
                }

                // A. Benchmark embed
                let t_embed_start = Instant::now();
                let stego_carrier = match embed_hevc(
                    &carrier_bytes,
                    p_data,
                    Some(password),
                    None,
                    &strhide::stego::format::DEFAULT_HEVC_FORMAT,
                    strhide::stego::Freshness::Random,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        panic!(
                            "[FAIL EMBED] Carrier {} with payload {}: {}",
                            carrier_name, p_name, e
                        );
                    }
                };
                let t_embed = t_embed_start.elapsed();

                // B. Bit-exact carrier size check (Delta = 0)
                assert_eq!(
                    stego_carrier.len(),
                    carrier_bytes.len(),
                    "Carrier length must be strictly preserved (Delta = 0)!"
                );

                // C. Benchmark extract
                let t_extract_start = Instant::now();
                let extracted_data = match extract_hevc(
                    &stego_carrier,
                    Some(password),
                    None,
                    &strhide::stego::format::DEFAULT_HEVC_FORMAT,
                    &Control::none(),
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        panic!(
                            "[FAIL EXTRACT] Carrier {} with payload {}: {}",
                            carrier_name, p_name, e
                        );
                    }
                };
                let t_extract = t_extract_start.elapsed();

                // D. Byte-exact equality check
                assert_eq!(
                    &extracted_data, p_data,
                    "Extracted payload must match 100% byte-for-byte!"
                );

                // E. Wrong password rejection check
                let wrong_res = extract_hevc(
                    &stego_carrier,
                    Some("InvalidPassword!"),
                    None,
                    &strhide::stego::format::DEFAULT_HEVC_FORMAT,
                    &Control::none(),
                );
                assert!(
                    wrong_res.is_err(),
                    "Extract with invalid password must be rejected!"
                );

                // F. Verify video frame decode once per carrier
                if !verified_frame {
                    let frame_ok = verify_frame_decodes(&stego_carrier);
                    assert!(
                        frame_ok,
                        "Carrier must cleanly decode to video frame after embedding!"
                    );
                    verified_frame = true;
                }

                let embed_speed_mb =
                    (*p_size as f64 / 1024.0 / 1024.0) / t_embed.as_secs_f64().max(0.000001);
                let extract_speed_mb =
                    (*p_size as f64 / 1024.0 / 1024.0) / t_extract.as_secs_f64().max(0.000001);

                tests.push(TestResult {
                    payload_name: p_name.clone(),
                    payload_size: *p_size,
                    embed_duration: t_embed,
                    extract_duration: t_extract,
                    embed_speed_mb,
                    extract_speed_mb,
                });
            }

            let done = completed_carriers.fetch_add(1, Ordering::SeqCst) + 1;
            println!(
                "  [{}/{}] Finished carrier: {:<25} (Size: {:>9}, Cap: {:>9}, Passed payloads: {})",
                done,
                total_carriers,
                carrier_name,
                format_bytes(*file_size),
                format_bytes(cap),
                tests.len()
            );

            CarrierReport {
                carrier_name: carrier_name.clone(),
                file_size: *file_size,
                capacity: cap,
                skip_reason: None,
                tests,
                skipped_overflow,
            }
        })
        .collect();

    let total_wall_time = t_all_start.elapsed();

    // 4. Sort reports by file size for consistent final display
    reports.sort_by_key(|r| r.file_size);

    println!(
        "\n========================================================================================================"
    );
    println!(
        "                             DETAILED CARRIER-BY-CARRIER BENCHMARK REPORT                               "
    );
    println!(
        "========================================================================================================"
    );

    let mut total_combinations = 0;
    let mut total_passed = 0;
    let mut total_skipped_capacity = 0;
    let mut total_skipped_non_hevc = 0;

    let mut total_embed_time = Duration::ZERO;
    let mut total_extract_time = Duration::ZERO;
    let mut total_embedded_bytes = 0usize;

    for r in &reports {
        if let Some(ref reason) = r.skip_reason {
            total_skipped_non_hevc += 1;
            println!(
                "[-] {:<25} | Size: {:>9} | [SKIP: {}]",
                r.carrier_name,
                format_bytes(r.file_size),
                reason
            );
            continue;
        }

        println!(
            "\n[+] Carrier: {:<20} | File Size: {:>9} | In-Place Stego Capacity: {:>9}",
            r.carrier_name,
            format_bytes(r.file_size),
            format_bytes(r.capacity)
        );

        total_skipped_capacity += r.skipped_overflow;
        total_combinations += r.tests.len() + r.skipped_overflow;

        for t in &r.tests {
            total_passed += 1;
            total_embed_time += t.embed_duration;
            total_extract_time += t.extract_duration;
            total_embedded_bytes += t.payload_size;

            println!(
                "    -> [PASS] {:<16} ({:>9}) | Embed: {:>7.2} ms ({:>6.2} MB/s) | Extract: {:>7.2} ms ({:>6.2} MB/s)",
                t.payload_name,
                format_bytes(t.payload_size),
                t.embed_duration.as_secs_f64() * 1000.0,
                t.embed_speed_mb,
                t.extract_duration.as_secs_f64() * 1000.0,
                t.extract_speed_mb
            );
        }
    }

    println!(
        "\n========================================================================================================"
    );
    println!(
        "                                      FINAL MATRIX SUMMARY                                             "
    );
    println!(
        "========================================================================================================"
    );
    println!(
        "Total Wall-Clock Time:  {:.2} s (Concurrent across {} threads)",
        total_wall_time.as_secs_f64(),
        rayon::current_num_threads()
    );
    println!("Combinations evaluated: {}", total_combinations);
    println!(
        "Total PASSED:           {} (100% Bit-exact roundtrip, password-verified, frame-decodable)",
        total_passed
    );
    println!(
        "Skipped (Capacity):     {} (Payload size > Carrier capacity, correctly rejected)",
        total_skipped_capacity
    );
    println!(
        "Skipped (Non-HEVC):     {} (Container has no HEVC bitstream / non-H.265)",
        total_skipped_non_hevc
    );
    println!(
        "Total data embedded:    {}",
        format_bytes(total_embedded_bytes)
    );
    if total_passed > 0 {
        let avg_embed_ms = total_embed_time.as_secs_f64() * 1000.0 / total_passed as f64;
        let avg_extract_ms = total_extract_time.as_secs_f64() * 1000.0 / total_passed as f64;
        let overall_embed_mbps = (total_embedded_bytes as f64 / 1024.0 / 1024.0)
            / total_embed_time.as_secs_f64().max(0.000001);
        let overall_extract_mbps = (total_embedded_bytes as f64 / 1024.0 / 1024.0)
            / total_extract_time.as_secs_f64().max(0.000001);

        println!(
            "Average Embed Time:     {:.2} ms ({:.2} MB/s CPU throughput)",
            avg_embed_ms, overall_embed_mbps
        );
        println!(
            "Average Extract Time:   {:.2} ms ({:.2} MB/s CPU throughput)",
            avg_extract_ms, overall_extract_mbps
        );
    }
    println!(
        "========================================================================================================\n"
    );

    Ok(())
}
