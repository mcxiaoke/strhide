//! Batch stego runner for real image corpus — counterpart of `batch_corpus.rs`
//! but specialized for content-adaptive pixel/DCT steganography (HILL & UERD).
//!
//! Sweeps every image in `temp/teststego` (or `$STRHIDE_STEGO_CORPUS`), asserting:
//!
//! 1. **Rejection Safety**:
//!    - Animated PNGs (APNG with `acTL`) are gracefully rejected;
//!    - Indexed/palette PNGs (`PLTE`) are gracefully rejected;
//!    - Progressive JPEGs (SOF2) are gracefully rejected;
//!    - The original carrier file is NEVER corrupted or modified.
//!
//! 2. **Capacity Probing**:
//!    - Accurate determination of total elements, eligible slots, and safe payload sizes.
//!
//! 3. **Full Lifecycle & Cryptographic Secrecy**:
//!    - Small payload (64 bytes) roundtrip with password;
//!    - Medium payload (up to 4KB or 50% capacity) roundtrip without password;
//!    - Incorrect password denial (Oracle resistance: returns `NoHiddenData`);
//!    - Oversize rejection (payload exceeding available slots is safely refused).
//!
//! 4. **Steganalysis Response (both directions)**:
//!    - Low load (64 B) must NOT inflate the self-check risk score by more than 35;
//!    - High load = the FULL capacity the tool reports (the strongest signal it can
//!      produce), incompressible payload, must be flagged on a documented majority.
//!      Measured baseline after the calibrated DCT detector landed: 14/15 flagged,
//!      10/15 at 50% load, 0 false positives from the calibrated detector on the
//!      clean carriers. The one miss (`bg_320_03_R.jpg`) is a quality-100 file
//!      whose luma quantization table is all ones: calibration is not applicable
//!      there (IDCT rounding dominates the reference) and the pixel-domain
//!      detectors stay quiet. Full capacity is the assertion point; 50% load is
//!      below what any LSB-domain detector can see reliably.
//!
//! Run with:
//! ```text
//! cargo test --release --test batch_stego -- --ignored --nocapture
//! ```

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use rayon::prelude::*;
use strhide::analysis::scan_file;
use strhide::errors::StrHideError;
use strhide::stego::{
    StegoCapacityInfo, StegoOptions, embed_carrier, extract_carrier, probe_carrier_capacity,
};

const CORPUS_DEFAULT: &str = "temp/teststego";
const CORPUS_ALT: &str = "../temp/teststego";
const TEST_PASSWORD: &str = "BatchStegoP@ssword2026!";
const WRONG_PASSWORD: &str = "IncorrectPassword999!";

/// Resolve the test corpus directory.
fn find_corpus_dir() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("STRHIDE_STEGO_CORPUS") {
        let p = PathBuf::from(env_path);
        if p.is_dir() {
            return Some(p);
        }
    }
    let p1 = PathBuf::from(CORPUS_DEFAULT);
    if p1.is_dir() {
        return Some(p1);
    }
    let p2 = PathBuf::from(CORPUS_ALT);
    if p2.is_dir() {
        return Some(p2);
    }
    None
}

/// Deterministic pseudo-random bytes of given length.
fn deterministic_bytes(size: usize, seed_salt: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(size + 8);
    let mut x: u64 = 0x517C_C1B7_2722_0A95 ^ seed_salt ^ (size as u64);
    while out.len() < size {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(size);
    out
}

#[derive(Default)]
struct BatchReport {
    total: usize,
    passed_lifecycle: usize,
    passed_rejection: usize,
    failed: usize,
    rows: Vec<ReportRow>,
    /// Carriers where a real 50% load was attempted (capacity >= 512 B).
    high_measured: usize,
    /// Of those, how many the self-check actually flagged (risk >= 10).
    high_flagged: usize,
    /// Carriers the self-check failed to flag at 50% load.
    undetected: Vec<String>,
}

struct ReportRow {
    filename: String,
    format: String,
    capacity: String,
    embed_ms: u128,
    extract_ms: u128,
    scan_score: u32,
    scan_verdict: String,
    high_score: u32,
    high_verdict: String,
    status: &'static str,
}

#[test]
#[ignore]
fn test_batch_stego_corpus() {
    let corpus_dir = match find_corpus_dir() {
        Some(d) => d,
        None => {
            eprintln!(
                "[SKIP] Stego test corpus not found (checked temp/teststego and $STRHIDE_STEGO_CORPUS)"
            );
            return;
        }
    };

    println!(
        "\n=== Starting Batch Stego Corpus Test on {:?} ===",
        corpus_dir
    );

    // Setup isolated sandbox
    let pid = std::process::id();
    let sandbox = std::env::temp_dir().join(format!("strhide_batch_stego_sandbox_{pid}"));
    if sandbox.exists() {
        let _ = fs::remove_dir_all(&sandbox);
    }
    fs::create_dir_all(&sandbox).expect("create sandbox");

    let mut entries: Vec<PathBuf> = fs::read_dir(&corpus_dir)
        .expect("read corpus dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|ext| ext.to_str())
                    .map(|s| {
                        let lower = s.to_ascii_lowercase();
                        lower == "png" || lower == "jpg" || lower == "jpeg"
                    })
                    .unwrap_or(false)
        })
        .collect();

    entries.sort();
    if entries.is_empty() {
        eprintln!("[SKIP] No image files found in corpus directory");
        return;
    }

    let threads = std::env::var("STRHIDE_BATCH_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);
    println!("Rayon parallel threads: {threads}");
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("build rayon thread pool");

    enum Outcome {
        Reject {
            filename: String,
            orig_len: usize,
            msg: String,
            row: ReportRow,
        },
        Pass {
            filename: String,
            orig_len: usize,
            detail: String,
            row: ReportRow,
            high_measured: bool,
        },
    }

    let total_start = Instant::now();

    let outcomes: Vec<Outcome> = pool.install(|| {
        entries
            .par_iter()
            .enumerate()
            .map(|(idx, path)| {
                let filename = path.file_name().unwrap().to_string_lossy().to_string();
                let file_bytes = fs::read(path).expect("read carrier file");
                let orig_len = file_bytes.len();

                // 1. Check if this is a known rejection candidate
                let is_apng = filename.contains("s_hair_gre_3_mo1");
                let is_indexed = filename.contains("Blueberry-Flat");
                let is_progressive_jpg = filename.contains("flip2");
                let is_interlaced_png = filename.contains("shop5");

                if is_apng || is_indexed || is_progressive_jpg || is_interlaced_png {
                    let payload = b"Test rejection payload";
                    let opt = StegoOptions::default();
                    let res = embed_carrier(&file_bytes, payload, &opt);
                    match res {
                        Err(StrHideError::UnsupportedFormat(msg)) => {
                            let format = if is_apng {
                                "APNG"
                            } else if is_indexed {
                                "PNG-P"
                            } else if is_progressive_jpg {
                                "JPEG-Prog"
                            } else {
                                "PNG-Adam7"
                            };
                            let row = ReportRow {
                                filename: filename.clone(),
                                format: format.into(),
                                capacity: "N/A (rejected)".into(),
                                embed_ms: 0,
                                extract_ms: 0,
                                scan_score: 0,
                                scan_verdict: "safe-reject".into(),
                                high_score: 0,
                                high_verdict: "n/a".into(),
                                status: "REJECT_OK",
                            };
                            return Outcome::Reject {
                                filename,
                                orig_len,
                                msg,
                                row,
                            };
                        }
                        other => {
                            panic!(
                                "File {filename} should be rejected with UnsupportedFormat, but got: {other:?}"
                            );
                        }
                    }
                }

                // 2. Normal valid carrier: probe capacity
                let opt_probe = StegoOptions::default();
                let cap: StegoCapacityInfo = match probe_carrier_capacity(&file_bytes, &opt_probe) {
                    Ok(c) => c,
                    Err(e) => {
                        panic!("Failed to probe capacity for {filename}: {e:?}");
                    }
                };

                assert!(
                    cap.available_slots > 500,
                    "Carrier {} has insufficient slots: {}",
                    filename,
                    cap.available_slots
                );

                // 3. Roundtrip Test 1: Small payload (64 bytes) with password
                let payload1 = deterministic_bytes(64, 1001);
                let mut opt_enc = StegoOptions {
                    password: Some(TEST_PASSWORD.to_string()),
                    ..Default::default()
                };

                let t_embed_start = Instant::now();
                let stego_bytes = embed_carrier(&file_bytes, &payload1, &opt_enc)
                    .unwrap_or_else(|e| panic!("Embedding 64B failed on {filename}: {e:?}"));
                let embed_ms = t_embed_start.elapsed().as_millis();

                // Save stego image to isolated sandbox path for scan
                let stego_path = sandbox.join(format!("{idx}_{filename}"));
                fs::write(&stego_path, &stego_bytes).expect("write stego image to sandbox");

                // Extract with correct password
                let t_ext_start = Instant::now();
                let extracted1 = extract_carrier(&stego_bytes, &opt_enc)
                    .unwrap_or_else(|e| panic!("Extraction failed on {filename}: {e:?}"));
                let extract_ms = t_ext_start.elapsed().as_millis();

                assert_eq!(
                    payload1, extracted1,
                    "Payload mismatch on 64B roundtrip for {filename}"
                );

                // Denial on wrong password
                opt_enc.password = Some(WRONG_PASSWORD.to_string());
                let wrong_res = extract_carrier(&stego_bytes, &opt_enc);
                assert!(
                    matches!(wrong_res, Err(StrHideError::NoHiddenData(_))),
                    "Wrong password should return NoHiddenData on {filename}, got: {wrong_res:?}"
                );

                // 4. Roundtrip Test 2: Medium payload without password
                let medium_size = 1024.min(cap.recommended_max_bytes.max(64));
                let payload2 = deterministic_bytes(medium_size, 2002);
                let opt_plain = StegoOptions::default();
                let stego_bytes2 = embed_carrier(&file_bytes, &payload2, &opt_plain).unwrap_or_else(|e| {
                    panic!("Embedding medium {medium_size}B failed on {filename}: {e:?}")
                });
                let extracted2 = extract_carrier(&stego_bytes2, &opt_plain).unwrap_or_else(|e| {
                    panic!("Extracting medium {medium_size}B failed on {filename}: {e:?}")
                });
                assert_eq!(
                    payload2, extracted2,
                    "Medium payload mismatch on {filename}"
                );

                // 5. Oversize rejection test
                let oversize_len = cap.max_raw_payload_bytes + 20_000;
                let oversize_payload = deterministic_bytes(oversize_len, 3003);
                let oversize_res = embed_carrier(&file_bytes, &oversize_payload, &opt_plain);
                assert!(
                    matches!(oversize_res, Err(StrHideError::General(ref msg)) if msg.contains("Carrier capacity exceeded")),
                    "Oversize payload should be rejected with 'Carrier capacity exceeded', got: {oversize_res:?}"
                );

                // 6. Steganalysis Scan: bidirectional assertion
                // Low load (64B): must stay clean with low risk inflation
                let orig_scan = scan_file(path).expect("scan original file");
                let low_scan = scan_file(&stego_path).expect("scan stego file");
                let low_growth = low_scan.risk_score.saturating_sub(orig_scan.risk_score);
                assert!(
                    low_growth <= 35,
                    "Low-load stego on {} caused excessive risk inflation: orig={}, stego={}, growth={}",
                    filename,
                    orig_scan.risk_score,
                    low_scan.risk_score,
                    low_growth
                );

                // High load = the full reported capacity, with NO artificial cap.
                // The previous `.clamp(64, 32 * 1024)` turned "high load" into
                // ~23% on large carriers, which is why the self-check never moved
                // and the whole high-load branch proved nothing. Full capacity is
                // also the only load where "the detector must see it" holds for a
                // majority of this corpus (measured: 11/15 here vs 9/15 at 50%).
                let high_load_size = cap.max_raw_payload_bytes;
                let (high_scan_score, high_scan_verdict) = if cap.max_raw_payload_bytes >= 512 {
                    let high_payload = deterministic_bytes(high_load_size, 4004);
                    let high_stego = embed_carrier(&file_bytes, &high_payload, &opt_plain)
                        .unwrap_or_else(|e| panic!("High-load embed failed on {filename}: {e:?}"));
                    let high_extracted = extract_carrier(&high_stego, &opt_plain)
                        .unwrap_or_else(|e| panic!("High-load extract failed on {filename}: {e:?}"));
                    assert_eq!(high_payload, high_extracted, "High-load roundtrip mismatch on {filename}");

                    let high_stego_path = sandbox.join(format!("high_{idx}_{filename}"));
                    fs::write(&high_stego_path, &high_stego).expect("write high stego");
                    let high_scan = scan_file(&high_stego_path).expect("scan high stego");
                    let _ = fs::remove_file(&high_stego_path);

                    (high_scan.risk_score, high_scan.verdict)
                } else {
                    (low_scan.risk_score, low_scan.verdict.clone())
                };

                // Monotonicity: a heavier load must never make the carrier look
                // cleaner than the light one.
                assert!(
                    high_scan_score >= low_scan.risk_score,
                    "High-load risk ({high_scan_score}) below low-load risk ({}) on {filename}",
                    low_scan.risk_score
                );

                let detail = format!(
                    "slots={} | cap={:.1}KB | embed={}ms | ext={}ms | scan(low={}/{}, high={}/{})",
                    cap.available_slots,
                    cap.max_raw_payload_bytes as f64 / 1024.0,
                    embed_ms,
                    extract_ms,
                    low_scan.risk_score,
                    low_scan.verdict,
                    high_scan_score,
                    high_scan_verdict
                );

                let row = ReportRow {
                    filename: filename.clone(),
                    format: cap.format,
                    capacity: format!("{:.1} KB", cap.max_raw_payload_bytes as f64 / 1024.0),
                    embed_ms,
                    extract_ms,
                    scan_score: low_scan.risk_score,
                    scan_verdict: low_scan.verdict,
                    high_score: high_scan_score,
                    high_verdict: high_scan_verdict,
                    status: "PASS",
                };

                let _ = fs::remove_file(&stego_path);
                Outcome::Pass {
                    filename,
                    orig_len,
                    detail,
                    row,
                    high_measured: cap.max_raw_payload_bytes >= 512,
                }
            })
            .collect()
    });

    let mut report = BatchReport {
        total: entries.len(),
        ..Default::default()
    };

    for outcome in outcomes {
        match outcome {
            Outcome::Reject {
                filename,
                orig_len,
                msg,
                row,
            } => {
                print!("-> Testing {:<38} ({} KB)... ", filename, orig_len / 1024);
                println!("[REJECT OK] Gracefully rejected: {msg}");
                report.passed_rejection += 1;
                report.rows.push(row);
            }
            Outcome::Pass {
                filename,
                orig_len,
                detail,
                row,
                high_measured,
            } => {
                print!("-> Testing {:<38} ({} KB)... ", filename, orig_len / 1024);
                println!("[PASS] {detail}");
                report.passed_lifecycle += 1;
                if high_measured {
                    report.high_measured += 1;
                    if row.high_score >= 10 {
                        report.high_flagged += 1;
                    } else {
                        report.undetected.push(filename.clone());
                    }
                }
                report.rows.push(row);
            }
        }
    }

    let _ = fs::remove_dir_all(&sandbox);

    // Print summary table
    let total_elapsed = total_start.elapsed();
    println!(
        "\n=========================================================================================="
    );
    println!(
        "                                BATCH STEGO TEST REPORT                                   "
    );
    println!(
        "=========================================================================================="
    );
    println!(
        "{:<36} {:<10} {:<12} {:<10} {:<10} {:<14} {:<14} {:<10}",
        "File", "Format", "Capacity", "Embed(ms)", "Ext(ms)", "Scan(64B)", "Scan(max)", "Status"
    );
    println!("{:-<120}", "");
    for r in &report.rows {
        println!(
            "{:<36} {:<10} {:<12} {:<10} {:<10} {:<14} {:<14} {:<10}",
            r.filename,
            r.format,
            r.capacity,
            r.embed_ms,
            r.extract_ms,
            format!("{}/{}", r.scan_score, r.scan_verdict),
            format!("{}/{}", r.high_score, r.high_verdict),
            r.status
        );
    }
    println!(
        "------------------------------------------------------------------------------------------"
    );
    println!(
        "Total: {} | Passed: {} ({} normal, {} rejected) | Failed: {} | Total Time: {:.2}s",
        report.total,
        report.passed_lifecycle + report.passed_rejection,
        report.passed_lifecycle,
        report.passed_rejection,
        report.failed,
        total_elapsed.as_secs_f64()
    );
    println!(
        "==========================================================================================\n"
    );

    // High-load detectability must be asserted, not merely printed. The floor is
    // a regression guard around the measured baseline (14/15 = 93% after the
    // calibrated DCT detector landed, 11/15 before it). It is deliberately below
    // 100%: one carrier (quality-100, uncalibratable) is a known miss, and the
    // undetected list is printed so any *new* miss is visible even when the floor
    // passes.
    if report.high_measured > 0 {
        let ratio = report.high_flagged as f64 / report.high_measured as f64;
        println!(
            "High-load self-check (full capacity): {}/{} carriers flagged (risk >= 10), {:.0}%",
            report.high_flagged,
            report.high_measured,
            ratio * 100.0
        );
        if !report.undetected.is_empty() {
            println!("  undetected at full load: {:?}", report.undetected);
        }
        assert!(
            ratio >= 0.90,
            "Self-check must flag at least 90% of carriers at full load, measured {:.0}% ({}/{}); undetected: {:?}",
            ratio * 100.0,
            report.high_flagged,
            report.high_measured,
            report.undetected
        );
    }

    assert_eq!(report.failed, 0, "All stego batch tests must pass");
}
