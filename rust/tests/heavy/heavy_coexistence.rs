//! Bidirectional dual-domain coexistence tests (Parallel / Multi-threaded).
//!
//! Verifies that for formats supporting both domains (JPEG, PNG, HEIC, HEVC/MP4, WAV),
//! content-domain (media stego) and structure-domain (container envelope) can coexist
//! losslessly and independently, and both payloads can be fully extracted regardless
//! of injection order (Content-first vs Structure-first).
//!
//! Run with:
//! ```text
//! cargo test --release --test heavy_tests heavy_dual_domain_coexistence_matrix -- --ignored --nocapture
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rand::RngExt;
use rand::seq::SliceRandom;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use strhide::core::commit::FileTarget;
use strhide::core::payload::Payload;
use strhide::errors::StrHideError;
use strhide::facade::{DualOptions, StrHide};
use strhide::formats::sniff::{FileFormat, sniff_file};
use strhide::stego::io::extract_carrier_file_payload;
use strhide::stego::{EmbedOptions, ExtractOptions, ProbeOptions, SafetyLevel, SafetyPolicy};
use strhide::structure::{PayloadSource, ReadOptions, WriteOptions};

/// Helper to compute SHA-256 hex string.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Locate root `testdata` folder.
fn locate_testdata_dir() -> Option<PathBuf> {
    if let Ok(val) = std::env::var("STRHIDE_TESTDATA_DIR") {
        let p = PathBuf::from(val);
        if p.is_dir() {
            return Some(p);
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest_dir.parent().map(|p| p.join("testdata")),
        Some(PathBuf::from("testdata")),
        Some(PathBuf::from("../testdata")),
    ];
    candidates.into_iter().flatten().find(|cand| cand.is_dir())
}

/// Scratch directory inside system temp for isolating test artifacts.
fn scratch_subdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "strhide_coexist_{}_{}_{}",
        std::process::id(),
        name,
        rand::random::<u32>()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Definition of a carrier format family in `testdata`.
struct FormatSpec {
    name: &'static str,
    subdir: &'static str,
    extensions: &'static [&'static str],
    is_matching_format: fn(FileFormat) -> bool,
}

const FORMAT_SPECS: &[FormatSpec] = &[
    FormatSpec {
        name: "JPEG",
        subdir: "jpg",
        extensions: &["jpg", "jpeg"],
        is_matching_format: |f| matches!(f, FileFormat::Jpeg),
    },
    FormatSpec {
        name: "PNG",
        subdir: "png",
        extensions: &["png"],
        is_matching_format: |f| matches!(f, FileFormat::Png),
    },
    FormatSpec {
        name: "HEIC",
        subdir: "heic",
        extensions: &["heic"],
        is_matching_format: |f| matches!(f, FileFormat::Heif),
    },
    FormatSpec {
        name: "HEVC",
        subdir: "hevc",
        extensions: &["mp4", "mov", "mkv"],
        // Structure and stego coexistence requires containerized video.
        is_matching_format: |f| matches!(f, FileFormat::Mp4 | FileFormat::Mkv),
    },
    FormatSpec {
        name: "WAV",
        subdir: "audio",
        extensions: &["wav"],
        is_matching_format: |f| matches!(f, FileFormat::Wav),
    },
];

/// Sample metadata candidate.
#[derive(Debug, Clone)]
struct CarrierCandidate {
    path: PathBuf,
    file_size: u64,
    stego_capacity: usize,
}

/// Discovers files in `testdata/<subdir>` and randomly picks 2 samples with different sizes.
fn pick_two_different_sized_samples(
    testdata_root: &Path,
    spec: &FormatSpec,
    engine: &StrHide,
) -> Vec<CarrierCandidate> {
    let target_dir = testdata_root.join(spec.subdir);
    if !target_dir.is_dir() {
        eprintln!(
            "[WARN] Subdirectory '{}' not found in testdata",
            spec.subdir
        );
        return Vec::new();
    }

    let mut candidates = Vec::new();
    let entries = match fs::read_dir(&target_dir) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("[WARN] Failed to read '{}': {err}", target_dir.display());
            return Vec::new();
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        if !spec.extensions.contains(&ext.as_str()) {
            continue;
        }

        // Sniff format
        let sniffed = match sniff_file(&path) {
            Ok(Some(fmt)) => fmt,
            _ => continue,
        };
        if !(spec.is_matching_format)(sniffed) {
            continue;
        }

        // Check stego capacity under Balanced safety policy: must be >= 32 bytes
        let cap_info = match engine.stego().probe_file(
            &path,
            &ProbeOptions::default()
                .with_safety_policy(SafetyPolicy::default().with_level(SafetyLevel::Balanced)),
        ) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if cap_info.recommended_max_bytes < 32 {
            continue;
        }

        let file_size = match entry.metadata() {
            Ok(m) => m.len(),
            Err(_) => continue,
        };

        candidates.push(CarrierCandidate {
            path,
            file_size,
            stego_capacity: cap_info.recommended_max_bytes,
        });
    }

    if candidates.is_empty() {
        eprintln!(
            "[WARN] No suitable carriers with stego capacity >= 32 B found in '{}'",
            target_dir.display()
        );
        return Vec::new();
    }

    let mut rng = rand::rng();
    candidates.shuffle(&mut rng);

    if candidates.len() == 1 {
        return candidates;
    }

    // Pick first candidate
    let first = candidates[0].clone();
    // Find second candidate with different size if possible
    let second = candidates
        .iter()
        .skip(1)
        .find(|c| c.file_size != first.file_size)
        .cloned()
        .unwrap_or_else(|| candidates[1].clone());

    vec![first, second]
}

/// Injection order enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectionOrder {
    /// Content domain first, then Structure domain.
    ContentThenStructure,
    /// Structure domain first, then Content domain.
    StructureThenContent,
}

impl InjectionOrder {
    fn label(self) -> &'static str {
        match self {
            Self::ContentThenStructure => "Content -> Structure",
            Self::StructureThenContent => "Structure -> Content",
        }
    }
}

/// One coexistence test scenario job.
#[derive(Clone)]
struct CoexistenceJob {
    format_name: &'static str,
    candidate: CarrierCandidate,
    order: InjectionOrder,
    content_pct: f64,
    struct_size: usize,
    case_id: usize,
}

/// Executes one coexistence test case on a single carrier copy.
fn run_single_coexistence_case(
    engine: &StrHide,
    job: &CoexistenceJob,
    scratch: &Path,
) -> Result<(usize, f64), String> {
    let candidate = &job.candidate;
    let file_stem = candidate
        .path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("sample");
    let ext = candidate
        .path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("tmp");
    let work_file = scratch.join(format!("{file_stem}_case{}.{ext}", job.case_id));
    fs::copy(&candidate.path, &work_file)
        .map_err(|e| format!("Failed to copy sample to work_file: {e}"))?;

    // Calculate content payload length
    let content_len = ((candidate.stego_capacity as f64) * job.content_pct).floor() as usize;
    let content_len = content_len.max(16).min(candidate.stego_capacity);

    // Generate random non-compressible payloads
    let mut rng = rand::rng();
    let mut content_payload_bytes = vec![0u8; content_len];
    rng.fill(&mut content_payload_bytes[..]);
    let content_payload_hash = sha256_hex(&content_payload_bytes);
    let content_payload = Payload::bytes(&content_payload_bytes);

    let mut struct_payload_bytes = vec![0u8; job.struct_size];
    rng.fill(&mut struct_payload_bytes[..]);
    let struct_payload_hash = sha256_hex(&struct_payload_bytes);

    // Independent passwords for clear security domain separation
    let pass_content = format!("PassContent_Coexist_{}_{content_len}", job.case_id);
    let pass_struct = format!("PassStruct_Coexist_{}_{}", job.case_id, job.struct_size);

    let start_time = Instant::now();

    // ─────────────────────── Perform injections according to order ───────────────────────
    match job.order {
        InjectionOrder::ContentThenStructure => {
            // Step 1: Content domain embed (in-place)
            let embed_target = FileTarget {
                output_path: None,
                backup: false,
                preserve_time: false,
                overwrite: true,
            };
            let embed_opts = EmbedOptions::default()
                .with_password(&pass_content)
                .with_safety_policy(SafetyPolicy::default().with_level(SafetyLevel::Balanced));
            engine
                .stego()
                .embed_file(&work_file, &content_payload, &embed_opts, &embed_target)
                .map_err(|e| format!("[{}] Step 1 embed failed: {e}", job.order.label()))?;

            // Step 2: Structure domain write (in-place)
            let write_opts = WriteOptions::default()
                .with_password(&pass_struct)
                .with_backup(false);
            engine
                .structure()
                .write_file(
                    &work_file,
                    PayloadSource::Bytes(&struct_payload_bytes),
                    &write_opts,
                )
                .map_err(|e| format!("[{}] Step 2 write failed: {e}", job.order.label()))?;
        }
        InjectionOrder::StructureThenContent => {
            // Step 1: Structure domain write (in-place)
            let write_opts = WriteOptions::default()
                .with_password(&pass_struct)
                .with_backup(false);
            engine
                .structure()
                .write_file(
                    &work_file,
                    PayloadSource::Bytes(&struct_payload_bytes),
                    &write_opts,
                )
                .map_err(|e| format!("[{}] Step 1 write failed: {e}", job.order.label()))?;

            // Step 2: Content domain embed (in-place)
            let embed_target = FileTarget {
                output_path: None,
                backup: false,
                preserve_time: false,
                overwrite: true,
            };
            let embed_opts = EmbedOptions::default()
                .with_password(&pass_content)
                .with_safety_policy(SafetyPolicy::default().with_level(SafetyLevel::Balanced));
            engine
                .stego()
                .embed_file(&work_file, &content_payload, &embed_opts, &embed_target)
                .map_err(|e| format!("[{}] Step 2 embed failed: {e}", job.order.label()))?;
        }
    }

    let inject_duration = start_time.elapsed();

    // ─────────────────────── Verification: Extract both domains ───────────────────────
    // 1. Extract Structure domain payload
    let read_opts = ReadOptions::default().with_password(&pass_struct);
    let read_res = engine
        .structure()
        .read_file(&work_file, &read_opts)
        .map_err(|e| format!("[{}] Extract structure failed: {e}", job.order.label()))?;
    if read_res.data.len() != job.struct_size {
        return Err(format!(
            "Structure payload length mismatch: got {}, expected {}",
            read_res.data.len(),
            job.struct_size
        ));
    }
    if sha256_hex(&read_res.data) != struct_payload_hash {
        return Err("Structure payload SHA-256 hash mismatch".into());
    }

    // 2. Extract Content domain payload
    let extract_opts = ExtractOptions::default().with_password(&pass_content);
    let extracted_content =
        extract_carrier_file_payload(&work_file, &extract_opts, &engine.dialect().stego)
            .map_err(|e| format!("[{}] Extract content failed: {e}", job.order.label()))?;
    if extracted_content.as_bytes().len() != content_len {
        return Err(format!(
            "Content payload length mismatch: got {}, expected {content_len}",
            extracted_content.as_bytes().len()
        ));
    }
    if sha256_hex(extracted_content.as_bytes()) != content_payload_hash {
        return Err("Content payload SHA-256 hash mismatch".into());
    }

    // 3. Dual inspection check
    let diag = engine
        .inspect_any(
            &work_file,
            &DualOptions {
                password: Some(&pass_content),
                ..Default::default()
            },
        )
        .map_err(|e| format!("inspect_any failed: {e}"))?;
    if !diag.structure.has_hidden_data {
        return Err("Structure hidden data was not detected in inspect_any".into());
    }
    if !diag.content.as_ref().is_some_and(|c| c.has_hidden_data) {
        return Err("Content hidden data was not detected in inspect_any".into());
    }

    // 4. Cross-domain password isolation checks
    let wrong_struct_res = engine.structure().read_file(
        &work_file,
        &ReadOptions::default().with_password(&pass_content),
    );
    if wrong_struct_res.is_ok() {
        return Err("Structure extraction with wrong password unexpectedly succeeded".into());
    }

    let wrong_content_res = extract_carrier_file_payload(
        &work_file,
        &ExtractOptions::default().with_password(&pass_struct),
        &engine.dialect().stego,
    );
    if !matches!(wrong_content_res, Err(StrHideError::NoHiddenData(_))) {
        return Err(format!(
            "Content extraction with wrong password should return NoHiddenData, got: {wrong_content_res:?}"
        ));
    }

    let _ = fs::remove_file(&work_file);
    Ok((content_len, inject_duration.as_secs_f64() * 1000.0))
}

#[test]
#[ignore = "requires testdata/ corpus: run with cargo test heavy_dual_domain_coexistence_matrix -- --ignored --nocapture"]
pub fn heavy_dual_domain_coexistence_matrix() {
    let testdata_dir = locate_testdata_dir().unwrap_or_else(|| {
        panic!("testdata directory not found (jpg/png/heic/hevc/audio); set STRHIDE_TESTDATA_DIR")
    });

    let thread_count = std::env::var("STRHIDE_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get().min(8))
                .unwrap_or(8)
        });

    println!("\n================================================================================");
    println!("  STRHIDE HEAVY DUAL-DOMAIN COEXISTENCE TEST MATRIX (PARALLEL)");
    println!("  Corpus root: {}", testdata_dir.display());
    println!("  Concurrency: {thread_count} worker threads");
    println!("  Content ratios: 0.2 (20%), 0.6 (60%)");
    println!("  Structure sizes: 128 KiB (131072 B), 1 MiB (1048576 B)");
    println!("  Orders: Content-first AND Structure-first");
    println!("================================================================================\n");

    let engine = StrHide::new();
    let scratch = scratch_subdir("heavy_dual_domain_parallel");

    let content_percentages = [0.2f64, 0.6f64];
    let struct_sizes = [128 * 1024usize, 1024 * 1024usize];
    let orders = [
        InjectionOrder::ContentThenStructure,
        InjectionOrder::StructureThenContent,
    ];

    let mut all_jobs: Vec<CoexistenceJob> = Vec::new();
    let mut total_tested_carriers = 0usize;
    let mut case_counter = 0usize;

    for spec in FORMAT_SPECS {
        println!(
            "--------------------------------------------------------------------------------"
        );
        println!("▶ Format Family: {}", spec.name);

        let samples = pick_two_different_sized_samples(&testdata_dir, spec, &engine);
        if samples.is_empty() {
            println!("  [SKIP] No valid samples for format {}", spec.name);
            continue;
        }

        println!(
            "  Discovered & Randomly Selected {} sample(s):",
            samples.len()
        );
        for (idx, sample) in samples.iter().enumerate() {
            println!(
                "    Sample #{}: {} ({:.2} MB, stego cap: {} B)",
                idx + 1,
                sample
                    .path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy(),
                sample.file_size as f64 / (1024.0 * 1024.0),
                sample.stego_capacity
            );
        }

        for candidate in &samples {
            total_tested_carriers += 1;
            for &pct in &content_percentages {
                for &s_size in &struct_sizes {
                    for &order in &orders {
                        case_counter += 1;
                        all_jobs.push(CoexistenceJob {
                            format_name: spec.name,
                            candidate: candidate.clone(),
                            order,
                            content_pct: pct,
                            struct_size: s_size,
                            case_id: case_counter,
                        });
                    }
                }
            }
        }
    }

    let total_jobs = all_jobs.len();
    assert!(
        total_tested_carriers > 0,
        "no carriers with >= 32 B stego capacity were found in {}; nothing was tested",
        testdata_dir.display()
    );
    assert!(total_jobs > 0, "no coexistence scenarios were generated");
    println!(
        "\n  Generated {total_jobs} scenarios across {total_tested_carriers} carriers. Dispatching to thread pool...\n"
    );

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .expect("Failed to build rayon ThreadPool");

    let done_counter = AtomicUsize::new(0);
    let failures: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let total_start = Instant::now();

    pool.install(|| {
        all_jobs.par_iter().for_each(|job| {
            let file_name = job
                .candidate
                .path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            match run_single_coexistence_case(&engine, job, &scratch) {
                Ok((content_len, elapsed_ms)) => {
                    let done = done_counter.fetch_add(1, Ordering::Relaxed) + 1;
                    println!(
                        "  [{:>2}/{:<2}] {:<5} | {:<20} | {:<21} | C: {:7} B ({:2}%) | S: {:7} B | {:6.1} ms",
                        done,
                        total_jobs,
                        job.format_name,
                        file_name,
                        job.order.label(),
                        content_len,
                        (job.content_pct * 100.0) as u32,
                        job.struct_size,
                        elapsed_ms
                    );
                }
                Err(err) => {
                    let done = done_counter.fetch_add(1, Ordering::Relaxed) + 1;
                    let err_msg = format!(
                        "[{done}/{total_jobs}] FAILED on {} [{}] (Case #{}): {err}",
                        file_name,
                        job.order.label(),
                        job.case_id
                    );
                    eprintln!("  ❌ {err_msg}");
                    failures.lock().unwrap().push(err_msg);
                }
            }
        });
    });

    let _ = fs::remove_dir_all(&scratch);

    let total_elapsed = total_start.elapsed().as_secs_f64();
    let fails = failures.into_inner().unwrap();

    println!("\n================================================================================");
    println!("  HEAVY DUAL-DOMAIN COEXISTENCE TEST MATRIX COMPLETE (PARALLEL)");
    println!("  Total Carriers Tested: {total_tested_carriers}");
    println!("  Total Scenarios Run:   {total_jobs}");
    println!("  Passed:                {}", total_jobs - fails.len());
    println!("  Failed:                {}", fails.len());
    println!("  Concurrency:           {thread_count} worker threads");
    println!("  Total Elapsed Time:    {total_elapsed:.2}s");
    println!("================================================================================\n");

    if !fails.is_empty() {
        panic!(
            "Coexistence test encountered {} failure(s):\n{}",
            fails.len(),
            fails.join("\n")
        );
    }
}
