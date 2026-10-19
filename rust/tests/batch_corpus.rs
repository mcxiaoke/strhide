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
//! Ignored by default: the corpus (`temp/testfiles`, ~135 MB) is local and
//! uncommitted, and a full sweep rewrites a copy of every file four times.
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

use strhide::crypto::compute_file_sha256;
use strhide::engine::{
    PayloadSource, WriteOptions, inspect_carrier, read_carrier, remove_carrier, verify_carrier,
    write_carrier,
};
use strhide::errors::StrHideError;
use strhide::rejection::run_all_rejection_checks;

const PLAIN_SECRET: &str = "Batch corpus plaintext payload 2026";
const ENC_PASSWORD: &str = "P@ssw0rd!Secure_2026";
const ENC_SECRET: &str = "Batch corpus encrypted payload 2026";
const STEALTH_PASSWORD: &str = "StealthPassword!2026";
const STEALTH_SECRET: &str = "Batch corpus stealth payload 2026";

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
                println!("  [PASS] [{mode:<7}] {file}  {detail}  ({elapsed:.2}s)");
            }
            Err(detail) => {
                println!("  [FAIL] [{mode:<7}] {file}  {detail}");
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

fn plain_mode(src: &Path, dir: &Path, orig_sha: &[u8; 32]) -> Result<String, String> {
    let carrier = copy_carrier(src, dir, "plain")?;
    let opts = WriteOptions {
        password: None,
        backup: false,
        ..Default::default()
    };
    let w = write_carrier(&carrier, PayloadSource::Text(PLAIN_SECRET), &opts)
        .map_err(|e| format!("write: {e}"))?;

    verify_all_levels(&carrier, None)?;

    let r = read_carrier(&carrier, None, None).map_err(|e| format!("read: {e}"))?;
    if r.data != PLAIN_SECRET.as_bytes() {
        return Err("plaintext payload mismatch".into());
    }

    remove_carrier(&carrier, None, None, false).map_err(|e| format!("remove: {e}"))?;
    assert_restored(&carrier, orig_sha, "remove")?;
    Ok(format!("format={:<5} strategy={}", w.format, w.strategy))
}

fn encrypted_mode(src: &Path, dir: &Path, orig_sha: &[u8; 32]) -> Result<String, String> {
    let carrier = copy_carrier(src, dir, "enc")?;
    let opts = WriteOptions {
        password: Some(ENC_PASSWORD),
        backup: false,
        ..Default::default()
    };
    let w = write_carrier(&carrier, PayloadSource::Text(ENC_SECRET), &opts)
        .map_err(|e| format!("write: {e}"))?;

    verify_all_levels(&carrier, Some(ENC_PASSWORD))?;

    // A wrong password must be a clean Password error, never garbage output.
    match read_carrier(&carrier, None, Some("WrongPassword!")) {
        Err(StrHideError::Password(_)) => {}
        Err(e) => return Err(format!("wrong password gave an unexpected error: {e}")),
        Ok(_) => return Err("wrong password was accepted".into()),
    }
    if read_carrier(&carrier, None, None).is_ok() {
        return Err("encrypted payload was readable without a password".into());
    }

    let r = read_carrier(&carrier, None, Some(ENC_PASSWORD)).map_err(|e| format!("read: {e}"))?;
    if r.data != ENC_SECRET.as_bytes() {
        return Err("encrypted payload mismatch".into());
    }

    // Structural restore needs no password: the envelope header carries the
    // boundaries and the payload itself is never decrypted.
    remove_carrier(&carrier, None, None, false).map_err(|e| format!("remove: {e}"))?;
    assert_restored(&carrier, orig_sha, "remove")?;
    Ok(format!("format={:<5} strategy={}", w.format, w.strategy))
}

fn stealth_mode(src: &Path, dir: &Path, orig_sha: &[u8; 32]) -> Result<String, String> {
    let carrier = copy_carrier(src, dir, "stl")?;
    let opts = WriteOptions {
        password: Some(STEALTH_PASSWORD),
        stealth: true,
        backup: false,
        ..Default::default()
    };
    let w = write_carrier(&carrier, PayloadSource::Text(STEALTH_SECRET), &opts)
        .map_err(|e| format!("write: {e}"))?;

    let inspected =
        inspect_carrier(&carrier, Some(STEALTH_PASSWORD)).map_err(|e| format!("inspect: {e}"))?;
    if inspected.is_stealth != Some(true) {
        return Err(format!(
            "inspect must report is_stealth=true, got {:?}",
            inspected.is_stealth
        ));
    }

    let r =
        read_carrier(&carrier, None, Some(STEALTH_PASSWORD)).map_err(|e| format!("read: {e}"))?;
    if r.data != STEALTH_SECRET.as_bytes() {
        return Err("stealth payload mismatch".into());
    }

    remove_carrier(&carrier, None, Some(STEALTH_PASSWORD), false)
        .map_err(|e| format!("remove: {e}"))?;
    assert_restored(&carrier, orig_sha, "remove")?;
    Ok(format!("format={:<5} strategy={}", w.format, w.strategy))
}

fn first_line(msg: &str) -> String {
    msg.lines().next().unwrap_or("").to_string()
}

// --------------------------------------------------------------------------- test

#[test]
#[ignore = "corpus sweep over temp/testfiles: run with --release --test batch_corpus -- --ignored --nocapture"]
fn batch_corpus_all_modes() {
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
    println!("=======================================================\n");

    let dir = scratch("run");
    let mut report = Report::new();

    for (idx, src) in files.iter().enumerate() {
        let name = src
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let size_mb = fs::metadata(src).map(|m| m.len()).unwrap_or(0) as f64 / (1024.0 * 1024.0);
        println!(
            "[{:02}/{:02}] {name} ({size_mb:.2} MB)",
            idx + 1,
            files.len()
        );

        // 1. Policy rejection (APK, signed PE, ...). Checked exactly like the
        //    writer does, so the expectation can never drift from the code.
        if let Err(e) = run_all_rejection_checks(src) {
            let reason = match e {
                StrHideError::Rejection(m) => m,
                other => other.to_string(),
            };
            let t0 = Instant::now();
            let outcome = rejection_case(src, &dir, &first_line(&reason));
            report.record(&name, "reject", t0.elapsed().as_secs_f32(), outcome);
            continue;
        }

        // 2..4. Full lifecycle in the three supported secrecy modes.
        let orig_sha = match compute_file_sha256(src) {
            Ok(sha) => sha,
            Err(e) => {
                report.record(&name, "hash", 0.0, Err(format!("source hash: {e}")));
                continue;
            }
        };

        for (mode, run) in [
            (
                "plain",
                plain_mode as fn(&Path, &Path, &[u8; 32]) -> Result<String, String>,
            ),
            (
                "encrypt",
                encrypted_mode as fn(&Path, &Path, &[u8; 32]) -> Result<String, String>,
            ),
            (
                "stealth",
                stealth_mode as fn(&Path, &Path, &[u8; 32]) -> Result<String, String>,
            ),
        ] {
            let t0 = Instant::now();
            let outcome = run(src, &dir, &orig_sha);
            report.record(&name, mode, t0.elapsed().as_secs_f32(), outcome);
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
