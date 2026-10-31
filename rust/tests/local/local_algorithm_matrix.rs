//! Local (ignored) algorithm matrix: every PNG/JPEG carrier × every cost model.
//!
//! The default suite uses the two corpora under `temp/teststego` and
//! `temp/testhighres`, embeds a small deterministic payload with each
//! algorithm the container supports, extracts it back through the
//! self-describing path, and (for JPEG) asserts that DC never changes.
//!
//! Run with:
//! ```text
//! cargo test --release --test local_tests local_all_algorithms -- --ignored --nocapture
//! ```
//!
//! Environment knobs:
//! * `STRHIDE_ALGO_MATRIX_DIRS` — `;`-separated corpus directories.
//! * `STRHIDE_ALGO_MATRIX_ONLY` — comma-separated algorithm names.
//! * `STRHIDE_ALGO_MATRIX_MAX_MP` — skip carriers above this megapixel count
//!   (`0` = no limit, the default; useful for a quick pass over huge files).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use strhide::core::payload::Payload;
use strhide::errors::StrHideError;
use strhide::stego::{
    EmbedOptions, JpegAlgorithm, JpegParams, PngParams, SpatialAlgorithm, StegoTuning,
    embed_carrier, extract_carrier,
};

const PASSWORD: &str = "AlgorithmMatrix#2026";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn corpus_dirs() -> Vec<PathBuf> {
    let root = repo_root();
    if let Ok(raw) = std::env::var("STRHIDE_ALGO_MATRIX_DIRS") {
        let dirs: Vec<PathBuf> = raw
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                let path = PathBuf::from(s);
                if path.is_absolute() {
                    path
                } else {
                    root.join(path)
                }
            })
            .collect();
        if !dirs.is_empty() {
            return dirs;
        }
    }
    vec![root.join("temp/teststego"), root.join("temp/testhighres")]
}

fn algorithm_filter() -> Vec<String> {
    std::env::var("STRHIDE_ALGO_MATRIX_ONLY")
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn max_megapixels() -> f64 {
    std::env::var("STRHIDE_ALGO_MATRIX_MAX_MP")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(0.0)
}

fn algorithms_for(path: &Path) -> Vec<(&'static str, StegoTuning)> {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("png") => vec![
            (
                "hill",
                StegoTuning::Png {
                    model: SpatialAlgorithm::Hill,
                    params: PngParams::default(),
                },
            ),
            (
                "suniward",
                StegoTuning::Png {
                    model: SpatialAlgorithm::Suniward,
                    params: PngParams::default(),
                },
            ),
            (
                "mipod",
                StegoTuning::Png {
                    model: SpatialAlgorithm::Mipod,
                    params: PngParams::default(),
                },
            ),
        ],
        Some("jpg") | Some("jpeg") => vec![
            (
                "uerd",
                StegoTuning::Jpeg {
                    model: JpegAlgorithm::Uerd,
                    params: JpegParams::default(),
                },
            ),
            (
                "juniward",
                StegoTuning::Jpeg {
                    model: JpegAlgorithm::Juniward,
                    params: JpegParams::default(),
                },
            ),
            (
                "jmipod",
                StegoTuning::Jpeg {
                    model: JpegAlgorithm::Jmipod,
                    params: JpegParams::default(),
                },
            ),
        ],
        _ => Vec::new(),
    }
}

/// Deterministic payload, unique per (file, algorithm).
fn payload_for(path: &Path, algorithm: &str) -> Vec<u8> {
    let mut state = 0x517C_C1B7_2722_0A95u64;
    for byte in path.to_string_lossy().bytes().chain(algorithm.bytes()) {
        state ^= byte as u64;
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
    }
    let mut out = Vec::with_capacity(64);
    while out.len() < 64 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(64);
    out
}

/// Read PNG IHDR dimensions without decoding scanlines.
fn png_dimensions(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.len() < 24 || &bytes[..8] != b"\x89PNG\r\n\x1a\n" || &bytes[12..16] != b"IHDR" {
        return None;
    }
    let w = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
    let h = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]) as usize;
    Some((w, h))
}

fn megapixels(path: &Path, bytes: &[u8]) -> Option<f64> {
    let (w, h) = match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("png") => png_dimensions(bytes)?,
        Some("jpg") | Some("jpeg") => {
            let info = dct_io::inspect(bytes).ok()?;
            (info.width as usize, info.height as usize)
        }
        _ => return None,
    };
    Some(w as f64 * h as f64 / 1_000_000.0)
}

#[test]
#[ignore]
pub fn local_all_algorithms_png_jpeg_matrix() {
    let dirs = corpus_dirs();
    let only = algorithm_filter();
    let max_mp = max_megapixels();

    let mut images: Vec<PathBuf> = Vec::new();
    for dir in &dirs {
        if !dir.is_dir() {
            eprintln!("[WARN] corpus directory missing: {}", dir.display());
            continue;
        }
        let mut found: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.extension().and_then(|e| e.to_str()).is_some_and(|s| {
                        matches!(s.to_ascii_lowercase().as_str(), "png" | "jpg" | "jpeg")
                    })
            })
            .collect();
        found.sort();
        images.extend(found);
    }
    if images.is_empty() {
        eprintln!("[SKIP] no PNG/JPEG carriers found in {:?}", dirs);
        return;
    }

    println!(
        "\n=== Algorithm matrix: {} images from {:?} | filter {:?} | max_mp {} ===",
        images.len(),
        dirs,
        only,
        if max_mp > 0.0 {
            max_mp.to_string()
        } else {
            "unlimited".into()
        }
    );

    let mut passed = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    let mut skipped_rows: Vec<String> = Vec::new();
    let mut failure_rows: Vec<String> = Vec::new();
    let started = Instant::now();

    for path in &images {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                failed += 1;
                failure_rows.push(format!("{}: read failed: {e}", path.display()));
                continue;
            }
        };
        if max_mp > 0.0
            && let Some(mp) = megapixels(path, &bytes)
            && mp > max_mp
        {
            skipped += 1;
            skipped_rows.push(format!(
                "{}: {mp:.1} MP above STRHIDE_ALGO_MATRIX_MAX_MP",
                path.display()
            ));
            continue;
        }

        let algs = algorithms_for(path);
        if algs.is_empty() {
            continue;
        }
        let is_jpeg = !path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("png"));

        for (algorithm, tuning) in algs {
            if !only.is_empty() && !only.iter().any(|name| name == algorithm) {
                continue;
            }
            let payload = payload_for(path, algorithm);
            let opts = EmbedOptions {
                tuning: tuning.clone(),
                password: Some(PASSWORD),
                ..Default::default()
            };

            let t0 = Instant::now();
            let stego = match embed_carrier(&bytes, &Payload::bytes(&payload), &opts) {
                Ok(stego) => stego,
                Err(StrHideError::UnsupportedFormat(message)) => {
                    skipped += 1;
                    skipped_rows.push(format!(
                        "{} [{algorithm}]: unsupported carrier ({message})",
                        path.file_name().unwrap().to_string_lossy()
                    ));
                    continue;
                }
                Err(error) => {
                    failed += 1;
                    failure_rows.push(format!(
                        "{} [{algorithm}]: embed failed: {error}",
                        path.display()
                    ));
                    continue;
                }
            };
            let embed_s = t0.elapsed().as_secs_f64();

            let t1 = Instant::now();
            let recovered = match extract_carrier(&stego, &opts.extract_options()) {
                Ok(payload) => payload,
                Err(error) => {
                    failed += 1;
                    failure_rows.push(format!(
                        "{} [{algorithm}]: extract failed: {error}",
                        path.display()
                    ));
                    continue;
                }
            };
            let extract_s = t1.elapsed().as_secs_f64();

            if recovered != payload {
                failed += 1;
                failure_rows.push(format!(
                    "{} [{algorithm}]: payload mismatch ({} vs {} bytes)",
                    path.display(),
                    payload.len(),
                    recovered.len()
                ));
                continue;
            }

            if is_jpeg {
                let before = dct_io::read_coefficients(&bytes);
                let after = dct_io::read_coefficients(&stego);
                match (before, after) {
                    (Ok(before), Ok(after)) => {
                        let dc_changed = before.components[0]
                            .blocks
                            .iter()
                            .zip(after.components[0].blocks.iter())
                            .any(|(b, a)| b[0] != a[0]);
                        if dc_changed {
                            failed += 1;
                            failure_rows.push(format!(
                                "{} [{algorithm}]: DC coefficient changed",
                                path.display()
                            ));
                            continue;
                        }
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        failed += 1;
                        failure_rows.push(format!(
                            "{} [{algorithm}]: coefficient read failed: {e}",
                            path.display()
                        ));
                        continue;
                    }
                }
            }

            passed += 1;
            println!(
                "[{passed:>3}] PASS {:<40} {:<9} embed {embed_s:.2}s extract {extract_s:.2}s",
                path.file_name().unwrap().to_string_lossy(),
                algorithm
            );
        }
    }

    let elapsed = started.elapsed();
    println!("\n{}", "=".repeat(100));
    println!(
        "TOTAL PASS {passed} | SKIP {skipped} | FAIL {failed} | elapsed {:.1}s",
        elapsed.as_secs_f64()
    );
    if !skipped_rows.is_empty() {
        println!("\nSkipped:");
        for row in &skipped_rows {
            println!("  {row}");
        }
    }
    if !failure_rows.is_empty() {
        println!("\nFailures:");
        for row in &failure_rows {
            println!("  {row}");
        }
    }
    println!("{}\n", "=".repeat(100));

    assert_eq!(failed, 0, "algorithm matrix must have no failures");
    assert!(
        passed > 0,
        "algorithm matrix must round-trip at least one carrier"
    );
}
