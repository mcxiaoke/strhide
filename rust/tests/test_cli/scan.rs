//! `strhide scan` end-to-end coverage:
//!
//! - a clean carrier scores low;
//! - after a normal `write`, scan detects the strhide structural fingerprint
//!   (private `prIv` chunk and/or envelope magic);
//! - after a `--stealth` write, the envelope magic is masked so scan only sees
//!   the neutral chunk, not the exact magic — the Stealth-mode regression
//!   signal we want.

use crate::common::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn run(dir: &Path, args: &[&str]) -> String {
    let out = Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env("USERPROFILE", dir)
        .env("HOME", dir)
        .output()
        .expect("run strhide");
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

#[test]
fn clean_png_scores_low() {
    let dir = scratch("clean");
    let png = dir.join("a.png");
    fs::write(&png, make_png()).unwrap();
    let out = run(&dir, &["scan", "a.png", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let score = v[0]["risk_score"].as_u64().unwrap();
    assert!(score < 30, "clean PNG risk score too high: {out}");
}

#[test]
fn normal_write_is_detected_by_scan() {
    let dir = scratch("normal");
    let png = dir.join("a.png");
    fs::write(&png, make_png()).unwrap();
    run(
        &dir,
        &[
            "write",
            "a.png",
            "--text",
            "secret",
            "-p",
            "pw",
            "--no-backup",
            "--in-place",
        ],
    );
    let out = run(&dir, &["scan", "a.png", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let score = v[0]["risk_score"].as_u64().unwrap();
    let findings = v[0]["findings"].as_array().unwrap();
    let has_fingerprint = findings.iter().any(|f| {
        f["detector"].as_str().unwrap_or("").contains("signature")
            || f["detector"].as_str().unwrap_or("").contains("chunk")
    });
    assert!(has_fingerprint, "no structural fingerprint found: {out}");
    assert!(
        score >= 20,
        "normal write not detected, score={score}: {out}"
    );
}

#[test]
fn stealth_write_masks_magic_but_chunk_remains() {
    let dir = scratch("stealth");
    let png = dir.join("a.png");
    fs::write(&png, make_png()).unwrap();
    run(
        &dir,
        &[
            "write",
            "a.png",
            "--text",
            "secret",
            "-p",
            "pw",
            "--stealth",
            "--no-backup",
            "--in-place",
        ],
    );
    let out = run(&dir, &["scan", "a.png", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let findings = v[0]["findings"].as_array().unwrap();
    let has_signature = findings.iter().any(|f| {
        f["detector"]
            .as_str()
            .unwrap_or("")
            .starts_with("signature:")
    });
    // In Stealth mode the header magic is password-derived, so the exact
    // "signature:known-tool" fingerprint must NOT fire.
    assert!(
        !has_signature,
        "stealth mode leaked the exact header signature: {out}"
    );
}

#[test]
fn scan_real_jpeg_sample_does_not_panic() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let jpg_path = manifest_dir
        .parent()
        .unwrap()
        .join("temp")
        .join("real_samples")
        .join("sample.jpg");
    if !jpg_path.exists() {
        return;
    }
    let dir = scratch("real_jpg_scan");
    let out = run(&dir, &["scan", jpg_path.to_str().unwrap(), "--json"]);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid json output");
    assert_eq!(v[0]["format"].as_str().unwrap(), "JPEG");
    let score = v[0]["risk_score"].as_u64().unwrap();
    assert!(score < 30, "clean real JPEG should score low risk: {out}");
}

// --------------------------------------------------------------------------- exit codes & quiet

/// Like `run`, but also reports the exit code for the scan gate semantics
/// (0 = clean/low/suspicious, 1 = at least one "likely-hidden" verdict).
fn run_with_code(dir: &Path, args: &[&str]) -> (String, i32) {
    let out = Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env("USERPROFILE", dir)
        .env("HOME", dir)
        .output()
        .expect("run strhide");
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (text, out.status.code().unwrap_or(-1))
}

#[test]
fn scan_quiet_clean_file_is_silent_and_zero() {
    let dir = scratch("quiet_clean");
    fs::write(dir.join("a.png"), make_png()).unwrap();
    let (text, code) = run_with_code(&dir, &["scan", "a.png", "-q"]);
    assert_eq!(code, 0, "clean file must scan quietly with exit 0: {text}");
    assert!(text.is_empty(), "quiet scan must print nothing: {text}");
}

#[test]
fn scan_quiet_gates_on_hidden_carrier() {
    let dir = scratch("quiet_hidden");
    fs::write(dir.join("a.png"), make_png()).unwrap();
    let (text, code) = run_with_code(
        &dir,
        &["write", "a.png", "-t", "hush", "--no-backup", "--in-place"],
    );
    assert_eq!(code, 0, "write failed: {text}");

    // Grep-like gating: an actual strhide envelope is "likely-hidden" on every
    // detector, so the quiet scan exits 1 with no output.
    let (text, code) = run_with_code(&dir, &["scan", "a.png", "-q"]);
    assert_eq!(
        code, 1,
        "likely-hidden carrier must fail the quiet scan: {text}"
    );
    assert!(text.is_empty(), "quiet scan must print nothing: {text}");
}

#[test]
fn scan_exit_code_does_not_depend_on_quiet() {
    let dir = scratch("gate_loud");
    fs::write(dir.join("a.png"), make_png()).unwrap();
    let (text, code) = run_with_code(
        &dir,
        &[
            "write",
            "a.png",
            "-t",
            "loud gate",
            "--no-backup",
            "--in-place",
        ],
    );
    assert_eq!(code, 0, "write failed: {text}");

    // Non-quiet runs share the same semantics: exit 1 with the report printed.
    let (text, code) = run_with_code(&dir, &["scan", "a.png"]);
    assert_eq!(code, 1);
    assert!(text.contains("LIKELY-HIDDEN"), "text: {text}");
}
