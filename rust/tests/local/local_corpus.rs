//! Corpus-level batch runner — Rust counterpart of Python
//! `python/tests/batch_test_runner.py`.
//!
//! Different tool from [`real_samples`](self): that one pins six fixed samples
//! to one format each, this one sweeps **every** file of a local corpus through
//! the full lifecycle and asserts the three promises on each of them:
//!
//! 1. **rejection** — carriers the policy must refuse (APK, Authenticode-signed
//!    PE, …) are refused by the *writer* and left byte-identical;
//! 2. **plaintext** — write → verify(L1/L2/L3) → read → remove → SHA-256 equal;
//! 3. **encrypted** — same, plus a wrong password must yield `Password` and
//!    removal must still work without the password (structural restore);
//! 4. **stealth** — same, plus `inspect` must report `is_stealth`, and removal
//!    needs the password (the magic is derived from it).
//!
//! Every mode is swept over [`SIZE_CASES`], four payload sizes at the boundaries
//! that matter to strategy selection and envelope framing: `<100 B` (an
//! envelope dominated by its own header/trailer), `>512 B`, `>4 KiB` (beyond
//! the few-KB zero-value padding runs `pe_slack` can use) and `>100 KiB`
//! (beyond what `pe_codebits` and small slack runs can absorb, so `auto` must
//! fall back instead of failing). The injected bytes are a deterministic
//! pseudo-random stream, so a truncation or block swap in the payload path
//! cannot pass the byte-for-byte comparison.
//!
//! Ignored by default: the corpus (`temp/testfiles`, ~135 MB) is local and
//! uncommitted, and a full sweep rewrites a copy of every file once per mode
//! and per payload size.
//!
//! ```text
//! cargo test --release --test batch_corpus -- --ignored --nocapture
//! STRHIDE_CORPUS=/path/to/corpus cargo test --release --test batch_corpus -- --ignored --nocapture
//! ```
//!
//! Every carrier is copied into a per-run temp directory first; the corpus is
//! never modified.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use rayon::prelude::*;
use strhide::crypto::compute_file_sha256;
use strhide::errors::StrHideError;
use strhide::structure::rejection::run_all_rejection_checks;
use strhide::structure::{
    PayloadSource, ReadOptions, RestoreOptions, WriteOptions, inspect_carrier, read_carrier,
    remove_carrier, verify_carrier, write_carrier,
};

const ENC_PASSWORD: &str = "P@ssw0rd!Secure_2026";
const STEALTH_PASSWORD: &str = "StealthPassword!2026";

/// One payload size in the sweep. `label` is only used in output and scratch
/// file names; `bytes` is the exact payload length.
#[derive(Clone, Copy)]
struct SizeCase {
    label: &'static str,
    bytes: usize,
}

/// The four required buckets: `<100 B`, `>512 B`, `>4 KiB`, `>100 KiB`.
const SIZE_CASES: [SizeCase; 4] = [
    SizeCase {
        label: "101B",
        bytes: 101,
    },
    SizeCase {
        label: "603B",
        bytes: 603,
    },
    SizeCase {
        label: "4K",
        bytes: 4005,
    },
    SizeCase {
        label: "128K",
        bytes: 128 * 1024 + 5,
    },
];

/// Deterministic payload of exactly `size` bytes.
///
/// xorshift64 rather than a repeating byte pattern: identical bytes would make
/// a swapped or duplicated 8-byte block invisible to the payload comparison.
fn payload_bytes(size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size + 8);
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15 ^ size as u64;
    while out.len() < size {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(size);
    out
}

// --------------------------------------------------------------------------- harness

struct Report {
    passed: usize,
    total: usize,
    failures: Vec<String>,
}

impl Report {
    fn new() -> Self {
        Self {
            passed: 0,
            total: 0,
            failures: Vec::new(),
        }
    }

    /// Records one case. `Ok(detail)` passes, `Err(detail)` fails.
    fn record(&mut self, file: &str, mode: &str, elapsed: f32, outcome: Result<String, String>) {
        self.total += 1;
        match outcome {
            Ok(detail) => {
                self.passed += 1;
                println!("  [PASS] [{mode:<12}] {file}  {detail}  ({elapsed:.2}s)");
            }
            Err(detail) => {
                println!("  [FAIL] [{mode:<12}] {file}  {detail}");
                self.failures.push(format!("{file} [{mode}]: {detail}"));
            }
        }
    }
}

fn corpus_dir() -> Option<PathBuf> {
    if let Some(custom) = std::env::var_os("STRHIDE_CORPUS") {
        let dir = PathBuf::from(custom);
        return dir.is_dir().then_some(dir);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest.parent()?.join("temp").join("testfiles");
    dir.is_dir().then_some(dir)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strhide_batch_{}_{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn copy_carrier(src: &Path, dir: &Path, prefix: &str) -> Result<PathBuf, String> {
    let name = src
        .file_name()
        .ok_or_else(|| "carrier without a file name".to_string())?
        .to_string_lossy()
        .to_string();
    let dst = dir.join(format!("{prefix}_{name}"));
    fs::copy(src, &dst).map_err(|e| format!("copy failed: {e}"))?;
    Ok(dst)
}

fn verify_all_levels(carrier: &Path, password: Option<&str>) -> Result<(), String> {
    let v = verify_carrier(carrier, password).map_err(|e| format!("verify: {e}"))?;
    for (label, status) in [
        ("L1 host", &v.level1_host),
        ("L2 envelope", &v.level2_envelope),
        ("L3 crypto", &v.level3_crypto),
    ] {
        if !status.ok {
            return Err(format!("{label} failed: {}", status.detail));
        }
    }
    Ok(())
}

fn hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn assert_restored(carrier: &Path, expected: &[u8; 32], mode: &str) -> Result<(), String> {
    let sha = compute_file_sha256(carrier).map_err(|e| format!("hash after {mode}: {e}"))?;
    if sha != *expected {
        return Err(format!(
            "restore SHA mismatch after {mode}: {} != {}",
            hex(&sha),
            hex(expected)
        ));
    }
    Ok(())
}

fn assert_payload(actual: &[u8], expected: &[u8], mode: &str) -> Result<(), String> {
    if actual != expected {
        return Err(format!(
            "{mode} payload mismatch: got {} bytes, expected {}",
            actual.len(),
            expected.len()
        ));
    }
    Ok(())
}

// --------------------------------------------------------------------------- modes

/// Carriers the policy must refuse, and which must stay untouched.
fn rejection_case(src: &Path, dir: &Path, reason: &str) -> Result<String, String> {
    let carrier = copy_carrier(src, dir, "rej")?;
    let before = compute_file_sha256(&carrier).map_err(|e| e.to_string())?;
    let opts = WriteOptions {
        password: Some("123"),
        backup: false,
        ..Default::default()
    };
    match write_carrier(&carrier, PayloadSource::Text("payload"), &opts) {
        Err(StrHideError::Rejection(msg)) | Err(StrHideError::UnsupportedFormat(msg)) => {
            let after = compute_file_sha256(&carrier).map_err(|e| e.to_string())?;
            if after != before {
                return Err("rejected carrier was modified on disk".into());
            }
            Ok(format!("rejected ({reason}): {}", first_line(&msg)))
        }
        Err(e) => Err(format!("unexpected error kind: {e}")),
        Ok(w) => Err(format!(
            "write succeeded but must be rejected (strategy {})",
            w.strategy
        )),
    }
}

fn plain_mode(
    src: &Path,
    dir: &Path,
    orig_sha: &[u8; 32],
    case: SizeCase,
    payload: &[u8],
) -> Result<String, String> {
    let carrier = copy_carrier(src, dir, &format!("plain{}", case.label))?;
    let opts = WriteOptions {
        password: None,
        backup: false,
        ..Default::default()
    };
    let w = write_carrier(&carrier, PayloadSource::Bytes(payload), &opts)
        .map_err(|e| format!("write: {e}"))?;

    verify_all_levels(&carrier, None)?;

    let r = read_carrier(
        &carrier,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .map_err(|e| format!("read: {e}"))?;
    assert_payload(&r.data, payload, "plaintext")?;

    remove_carrier(
        &carrier,
        &RestoreOptions {
            output_path: None,
            password: None,
            backup: false,
            overwrite: false,
            ..Default::default()
        },
    )
    .map_err(|e| format!("remove: {e}"))?;
    assert_restored(&carrier, orig_sha, "remove")?;
    Ok(format!(
        "format={:<5} strategy={:<14} ube={}B",
        w.format, w.strategy, w.ube_size
    ))
}

fn encrypted_mode(
    src: &Path,
    dir: &Path,
    orig_sha: &[u8; 32],
    case: SizeCase,
    payload: &[u8],
) -> Result<String, String> {
    let carrier = copy_carrier(src, dir, &format!("enc{}", case.label))?;
    let opts = WriteOptions {
        password: Some(ENC_PASSWORD),
        backup: false,
        ..Default::default()
    };
    let w = write_carrier(&carrier, PayloadSource::Bytes(payload), &opts)
        .map_err(|e| format!("write: {e}"))?;

    verify_all_levels(&carrier, Some(ENC_PASSWORD))?;

    // A wrong password must be a clean Password error, never garbage output.
    match read_carrier(
        &carrier,
        &ReadOptions {
            output_path: None,
            password: Some("WrongPassword!"),
            overwrite: false,
            ..Default::default()
        },
    ) {
        Err(StrHideError::Password(_)) => {}
        Err(e) => return Err(format!("wrong password gave an unexpected error: {e}")),
        Ok(_) => return Err("wrong password was accepted".into()),
    }
    if read_carrier(
        &carrier,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .is_ok()
    {
        return Err("encrypted payload was readable without a password".into());
    }

    let r = read_carrier(
        &carrier,
        &ReadOptions {
            output_path: None,
            password: Some(ENC_PASSWORD),
            overwrite: false,
            ..Default::default()
        },
    )
    .map_err(|e| format!("read: {e}"))?;
    assert_payload(&r.data, payload, "encrypted")?;

    // Structural restore needs no password: the envelope header carries the
    // boundaries and the payload itself is never decrypted.
    remove_carrier(
        &carrier,
        &RestoreOptions {
            output_path: None,
            password: None,
            backup: false,
            overwrite: false,
            ..Default::default()
        },
    )
    .map_err(|e| format!("remove: {e}"))?;
    assert_restored(&carrier, orig_sha, "remove")?;
    Ok(format!(
        "format={:<5} strategy={:<14} ube={}B",
        w.format, w.strategy, w.ube_size
    ))
}

fn stealth_mode(
    src: &Path,
    dir: &Path,
    orig_sha: &[u8; 32],
    case: SizeCase,
    payload: &[u8],
) -> Result<String, String> {
    let carrier = copy_carrier(src, dir, &format!("stl{}", case.label))?;
    let opts = WriteOptions {
        password: Some(STEALTH_PASSWORD),
        stealth: true,
        backup: false,
        ..Default::default()
    };
    let w = write_carrier(&carrier, PayloadSource::Bytes(payload), &opts)
        .map_err(|e| format!("write: {e}"))?;

    let inspected =
        inspect_carrier(&carrier, Some(STEALTH_PASSWORD)).map_err(|e| format!("inspect: {e}"))?;
    if inspected.is_stealth != Some(true) {
        return Err(format!(
            "inspect must report is_stealth=true, got {:?}",
            inspected.is_stealth
        ));
    }

    let r = read_carrier(
        &carrier,
        &ReadOptions {
            output_path: None,
            password: Some(STEALTH_PASSWORD),
            overwrite: false,
            ..Default::default()
        },
    )
    .map_err(|e| format!("read: {e}"))?;
    assert_payload(&r.data, payload, "stealth")?;

    remove_carrier(
        &carrier,
        &RestoreOptions {
            output_path: None,
            password: Some(STEALTH_PASSWORD),
            backup: false,
            overwrite: false,
            ..Default::default()
        },
    )
    .map_err(|e| format!("remove: {e}"))?;
    assert_restored(&carrier, orig_sha, "remove")?;
    Ok(format!(
        "format={:<5} strategy={:<14} ube={}B",
        w.format, w.strategy, w.ube_size
    ))
}

fn first_line(msg: &str) -> String {
    msg.lines().next().unwrap_or("").to_string()
}

// --------------------------------------------------------------------------- test

#[test]
#[ignore = "corpus sweep over temp/testfiles: run with --release --test batch_corpus -- --ignored --nocapture"]
fn local_batch_corpus_all_modes() {
    let Some(corpus) = corpus_dir() else {
        eprintln!(
            "[SKIP] corpus directory not found (set STRHIDE_CORPUS to point at one); \
             nothing was tested"
        );
        return;
    };

    let mut files: Vec<PathBuf> = fs::read_dir(&corpus)
        .expect("read corpus dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();

    println!("\n=======================================================");
    println!(
        "Batch corpus: {} files in {}",
        files.len(),
        corpus.display()
    );
    println!(
        "Payload sizes: {}",
        SIZE_CASES
            .iter()
            .map(|c| format!("{} ({}B)", c.label, c.bytes))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("=======================================================\n");

    let payloads: Vec<Vec<u8>> = SIZE_CASES.iter().map(|c| payload_bytes(c.bytes)).collect();

    let threads = std::env::var("STRHIDE_BATCH_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);
    println!("Rayon parallel threads: {threads}");
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("build thread pool");

    struct FileOutcome {
        idx: usize,
        name: String,
        size_mb: f64,
        records: Vec<(&'static str, f32, Result<String, String>)>,
    }

    let dir = scratch("run");

    let file_outcomes: Vec<FileOutcome> = pool.install(|| {
        files
            .par_iter()
            .enumerate()
            .map(|(idx, src)| {
                let name = src
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                let size_mb =
                    fs::metadata(src).map(|m| m.len()).unwrap_or(0) as f64 / (1024.0 * 1024.0);
                let file_scratch = dir.join(format!("file_{idx}"));
                let _ = fs::create_dir_all(&file_scratch);

                let mut records = Vec::new();

                // 1. Policy rejection
                if let Err(e) = run_all_rejection_checks(src, src) {
                    let reason = match e {
                        StrHideError::Rejection(m) => m,
                        other => other.to_string(),
                    };
                    let t0 = Instant::now();
                    let outcome = rejection_case(src, &file_scratch, &first_line(&reason));
                    records.push(("reject", t0.elapsed().as_secs_f32(), outcome));
                    let _ = fs::remove_dir_all(&file_scratch);
                    return FileOutcome {
                        idx,
                        name,
                        size_mb,
                        records,
                    };
                }

                // 2..4. Full lifecycle in the three supported secrecy modes
                let orig_sha = match compute_file_sha256(src) {
                    Ok(sha) => sha,
                    Err(e) => {
                        records.push(("hash", 0.0, Err(format!("source hash: {e}"))));
                        let _ = fs::remove_dir_all(&file_scratch);
                        return FileOutcome {
                            idx,
                            name,
                            size_mb,
                            records,
                        };
                    }
                };

                type ModeFn =
                    fn(&Path, &Path, &[u8; 32], SizeCase, &[u8]) -> Result<String, String>;
                for (mode, run) in [
                    ("plain", plain_mode as ModeFn),
                    ("encrypt", encrypted_mode as ModeFn),
                    ("stealth", stealth_mode as ModeFn),
                ] {
                    for (case, payload) in SIZE_CASES.iter().zip(payloads.iter()) {
                        let t0 = Instant::now();
                        let outcome = run(src, &file_scratch, &orig_sha, *case, payload);
                        let label: &'static str = match (mode, case.label) {
                            ("plain", "101B") => "plain:101B",
                            ("plain", "603B") => "plain:603B",
                            ("plain", "4K") => "plain:4K",
                            ("plain", "128K") => "plain:128K",
                            ("encrypt", "101B") => "encrypt:101B",
                            ("encrypt", "603B") => "encrypt:603B",
                            ("encrypt", "4K") => "encrypt:4K",
                            ("encrypt", "128K") => "encrypt:128K",
                            ("stealth", "101B") => "stealth:101B",
                            ("stealth", "603B") => "stealth:603B",
                            ("stealth", "4K") => "stealth:4K",
                            ("stealth", "128K") => "stealth:128K",
                            _ => "unknown",
                        };
                        records.push((label, t0.elapsed().as_secs_f32(), outcome));
                    }
                }

                let _ = fs::remove_dir_all(&file_scratch);
                FileOutcome {
                    idx,
                    name,
                    size_mb,
                    records,
                }
            })
            .collect()
    });

    let mut report = Report::new();
    for outcome in file_outcomes {
        println!(
            "[{:02}/{:02}] {} ({:.2} MB)",
            outcome.idx + 1,
            files.len(),
            outcome.name,
            outcome.size_mb
        );
        for (label, elapsed, res) in outcome.records {
            report.record(&outcome.name, label, elapsed, res);
        }
    }

    let _ = fs::remove_dir_all(&dir);

    println!("\n=======================================================");
    println!(
        "Batch corpus completed: {}/{} passed ({:.1}%)",
        report.passed,
        report.total,
        (report.passed as f64 / report.total.max(1) as f64) * 100.0
    );
    println!("=======================================================\n");

    assert!(
        report.failures.is_empty(),
        "{} of {} batch cases failed:\n{}",
        report.failures.len(),
        report.total,
        report.failures.join("\n")
    );
}
