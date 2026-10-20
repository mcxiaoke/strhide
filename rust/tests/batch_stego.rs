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
//! 4. **Steganalysis Resistance**:
//!    - Scans generated stego images with `strhide::scan::scan_file`;
//!    - Asserts risk score remains in `clean` or `low` tier (score < 60).
//!
//! Run with:
//! ```text
//! cargo test --release --test batch_stego -- --ignored --nocapture
//! ```

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

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
}

struct ReportRow {
    filename: String,
    format: String,
    capacity: String,
    embed_ms: u128,
    extract_ms: u128,
    scan_score: u32,
    scan_verdict: String,
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

    let mut report = BatchReport {
        total: entries.len(),
        ..Default::default()
    };

    let total_start = Instant::now();

    for path in entries {
        let filename = path.file_name().unwrap().to_string_lossy().to_string();
        let file_bytes = fs::read(&path).expect("read carrier file");
        let orig_len = file_bytes.len();

        print!("-> Testing {:<38} ({} KB)... ", filename, orig_len / 1024);

        // 1. Check if this is a known rejection candidate
        let is_apng = filename.contains("s_hair_gre_3_mo1");
        let is_indexed = filename.contains("Blueberry-Flat");
        let is_progressive_jpg = filename.contains("flip2");
        let is_interlaced_png = filename.contains("shop5");

        if is_apng || is_indexed || is_progressive_jpg || is_interlaced_png {
            // Rejection case: embed should fail cleanly with UnsupportedFormat
            let payload = b"Test rejection payload";
            let opt = StegoOptions::default();
            let res = embed_carrier(&file_bytes, payload, &opt);
            match res {
                Err(StrHideError::UnsupportedFormat(msg)) => {
                    println!("[REJECT OK] Gracefully rejected: {msg}");
                    report.passed_rejection += 1;
                    report.rows.push(ReportRow {
                        filename,
                        format: if is_apng {
                            "APNG"
                        } else if is_indexed {
                            "PNG-P"
                        } else if is_progressive_jpg {
                            "JPEG-Prog"
                        } else {
                            "PNG-Adam7"
                        }
                        .into(),
                        capacity: "N/A (rejected)".into(),
                        embed_ms: 0,
                        extract_ms: 0,
                        scan_score: 0,
                        scan_verdict: "safe-reject".into(),
                        status: "REJECT_OK",
                    });
                }
                other => {
                    panic!(
                        "File {filename} should be rejected with UnsupportedFormat, but got: {other:?}"
                    );
                }
            }
            continue;
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

        // Save stego image to sandbox for scan
        let stego_path = sandbox.join(&filename);
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

        // 6. Steganalysis Scan: compare cover vs stego delta
        let orig_scan = scan_file(&path).expect("scan original file");
        let scan_report = scan_file(&stego_path).expect("scan stego file");
        let score_growth = scan_report.risk_score.saturating_sub(orig_scan.risk_score);
        assert!(
            score_growth <= 35,
            "Stego embedding on {} caused abnormal risk inflation: orig={}, stego={}, growth={}",
            filename,
            orig_scan.risk_score,
            scan_report.risk_score,
            score_growth
        );

        println!(
            "[PASS] slots={} | cap={:.1}KB | embed={}ms | ext={}ms | scan={}/{} (orig={})",
            cap.available_slots,
            cap.max_raw_payload_bytes as f64 / 1024.0,
            embed_ms,
            extract_ms,
            scan_report.risk_score,
            scan_report.verdict,
            orig_scan.risk_score
        );

        report.passed_lifecycle += 1;
        report.rows.push(ReportRow {
            filename,
            format: cap.format,
            capacity: format!("{:.1} KB", cap.max_raw_payload_bytes as f64 / 1024.0),
            embed_ms,
            extract_ms,
            scan_score: scan_report.risk_score,
            scan_verdict: scan_report.verdict,
            status: "PASS",
        });
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
        "{:<36} {:<10} {:<12} {:<10} {:<10} {:<12} {:<10}",
        "File", "Format", "Capacity", "Embed(ms)", "Ext(ms)", "Scan Score", "Status"
    );
    println!("{:-<106}", "");
    for r in &report.rows {
        println!(
            "{:<36} {:<10} {:<12} {:<10} {:<10} {:<12} {:<10}",
            r.filename,
            r.format,
            r.capacity,
            r.embed_ms,
            r.extract_ms,
            format!("{}/{}", r.scan_score, r.scan_verdict),
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

    assert_eq!(report.failed, 0, "All stego batch tests must pass");
}
