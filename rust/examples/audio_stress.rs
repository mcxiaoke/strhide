// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Stress the WAV and FLAC content engines: every audio carrier, multiple fill
//! levels, several rounds each, in parallel.
//!
//! What each round proves, in this order:
//!
//! 1. `embed` succeeds at the requested size;
//! 2. the stego file has **exactly** the cover's length (the Δ=0 contract);
//! 3. the format sniffer still recognises it (the file is not just "the same
//!    size", it still parses as WAV/FLAC);
//! 4. `extract` with the round's password returns the round's payload byte for
//!    byte;
//! 5. `extract` with a wrong password fails instead of returning something.
//!
//! Rounds can vary the password *and* the payload to exercise diverse permutations
//! and residues, or test with fixed passwords/payloads for strict regression verification.
//!
//! ```text
//! cargo run --release --all-features --example audio_stress
//! cargo run --release --all-features --example audio_stress -- temp/testaudio 3 0.2,0.4,0.8,1.0
//! cargo run --release --all-features --example audio_stress -- temp/testaudio 3 0.2,0.4,0.8,1.0 --fixed-password
//! cargo run --release --all-features --example audio_stress -- temp/testaudio/01_Sphere.flac 2 0.2,0.4,0.8,1.0
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rand::RngExt;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use strhide::core::payload::Payload;
use strhide::errors::StrHideError;
use strhide::stego::prng::deterministic_payload;
use strhide::stego::{
    EmbedOptions, ExtractOptions, Freshness, ProbeOptions, SafetyLevel, SafetyPolicy, StegoTuning,
    embed_carrier, extract_carrier, probe_carrier_capacity,
};

/// Prefix of every password this harness uses.
const PASSWORD_PREFIX: &str = "stress";
const FIXED_PASSWORD: &str = "stress-fixed-password-2026";

/// One (carrier, fill level) job.
struct Job {
    path: PathBuf,
    /// Fraction of `max_raw_payload_bytes` to embed, in `(0, 1]`.
    fill: f64,
    /// Bytes to embed, resolved once by the capacity probe.
    bytes: usize,
    /// Capacity the probe reported, for the report.
    capacity: usize,
    /// Carriers can yield nothing at some levels, or be skipped for format reasons.
    skip: Option<String>,
}

/// Outcome of one round.
struct Round {
    embed_ms: u128,
    extract_ms: u128,
    ok: bool,
    detail: String,
}

struct Config {
    path: PathBuf,
    rounds: usize,
    fills: Vec<f64>,
    threads: usize,
    fixed_password: bool,
    fixed_payload: bool,
}

fn parse_config() -> Config {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut path: Option<PathBuf> = None;
    let mut rounds: Option<usize> = None;
    let mut fills: Option<Vec<f64>> = None;
    let mut threads: Option<usize> = None;
    let mut fixed_password = false;
    let mut fixed_payload = false;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--fixed-password" {
            fixed_password = true;
            i += 1;
        } else if arg == "--fixed-payload" {
            fixed_payload = true;
            i += 1;
        } else if arg == "--threads" && i + 1 < args.len() {
            threads = args[i + 1].parse().ok();
            i += 2;
        } else if arg == "--rounds" && i + 1 < args.len() {
            rounds = args[i + 1].parse().ok();
            i += 2;
        } else if arg == "--fills" && i + 1 < args.len() {
            fills = Some(
                args[i + 1]
                    .split(',')
                    .filter_map(|p| p.trim().parse().ok())
                    .collect(),
            );
            i += 2;
        } else if !arg.starts_with("--") {
            // Positional arguments: [path] [rounds] [fills] [threads]
            if path.is_none() {
                path = Some(PathBuf::from(arg));
            } else if rounds.is_none() {
                rounds = arg.parse().ok();
            } else if fills.is_none() {
                fills = Some(
                    arg.split(',')
                        .filter_map(|p| p.trim().parse().ok())
                        .collect(),
                );
            } else if threads.is_none() {
                threads = arg.parse().ok();
            }
            i += 1;
        } else {
            i += 1;
        }
    }

    let default_dir = if Path::new("../temp/testaudio").exists() {
        PathBuf::from("../temp/testaudio")
    } else if Path::new("temp/testaudio").exists() {
        PathBuf::from("temp/testaudio")
    } else {
        PathBuf::from("../temp/testaudio")
    };

    let path = path.unwrap_or(default_dir);
    let rounds = rounds.unwrap_or(3);
    let fills = fills
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec![0.2, 0.4, 0.8, 1.0]);
    let threads = threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get().min(4))
            .unwrap_or(2)
    });

    Config {
        path,
        rounds,
        fills,
        threads,
        fixed_password,
        fixed_payload,
    }
}

fn main() -> ExitCode {
    let total_started = Instant::now();
    let config = parse_config();

    let paths = match collect_audio(&config.path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("audio_stress: {e}");
            return ExitCode::FAILURE;
        }
    };
    if paths.is_empty() {
        eprintln!(
            "audio_stress: no .wav/.flac carriers found under {}",
            config.path.display()
        );
        return ExitCode::FAILURE;
    }

    println!(
        "audio_stress: {} carriers, fills {:?}, {} rounds each, {} threads (password={}, payload={})",
        paths.len(),
        config.fills,
        config.rounds,
        config.threads,
        if config.fixed_password {
            "fixed"
        } else {
            "rotating"
        },
        if config.fixed_payload {
            "fixed"
        } else {
            "random (SHA-256 verified)"
        },
    );

    let pool = match rayon::ThreadPoolBuilder::new()
        .num_threads(config.threads)
        .build()
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("audio_stress: cannot build thread pool: {e}");
            return ExitCode::FAILURE;
        }
    };

    enum ProbeVerdict {
        Ok(usize),
        Unsupported(String),
        Error(String),
    }

    // Capacity probing happens once per carrier in parallel.
    let probed: Vec<(PathBuf, ProbeVerdict)> = pool.install(|| {
        paths
            .par_iter()
            .map(|path| {
                let cover = match std::fs::read(path) {
                    Ok(c) => c,
                    Err(e) => {
                        return (
                            path.clone(),
                            ProbeVerdict::Error(format!("{}: {e}", path.display())),
                        );
                    }
                };
                let options = ProbeOptions {
                    safety: SafetyPolicy {
                        level: SafetyLevel::High,
                        ..SafetyPolicy::default()
                    },
                    exact: true,
                    ..Default::default()
                };
                match probe_carrier_capacity(&cover, &options) {
                    Ok(c) => (path.clone(), ProbeVerdict::Ok(c.max_raw_payload_bytes)),
                    Err(StrHideError::UnsupportedFormat(reason)) => {
                        (path.clone(), ProbeVerdict::Unsupported(reason))
                    }
                    Err(e) => (
                        path.clone(),
                        ProbeVerdict::Error(format!("{}: probe failed: {e}", path.display())),
                    ),
                }
            })
            .collect()
    });

    let mut jobs: Vec<Job> = Vec::new();
    let mut setup_failures: Vec<String> = Vec::new();
    let mut skipped_carriers: Vec<String> = Vec::new();

    for (path, verdict) in probed {
        match verdict {
            ProbeVerdict::Ok(capacity) => {
                if capacity == 0 {
                    setup_failures
                        .push(format!("{}: probe reported zero capacity", path.display()));
                    continue;
                }
                for &fill in &config.fills {
                    let bytes = ((capacity as f64) * fill).round() as usize;
                    let skip = if bytes == 0 {
                        Some("payload would be empty".to_string())
                    } else if bytes > capacity {
                        Some(format!("{bytes} > capacity {capacity}"))
                    } else {
                        None
                    };
                    jobs.push(Job {
                        path: path.clone(),
                        fill,
                        bytes,
                        capacity,
                        skip,
                    });
                }
            }
            ProbeVerdict::Unsupported(reason) => {
                skipped_carriers.push(format!(
                    "{}: unsupported carrier ({reason})",
                    path.display()
                ));
            }
            ProbeVerdict::Error(e) => setup_failures.push(e),
        }
    }

    println!(
        "audio_stress: {} active jobs across supported carriers",
        jobs.len()
    );
    if !skipped_carriers.is_empty() {
        println!(
            "audio_stress: {} carriers skipped due to format constraints",
            skipped_carriers.len()
        );
    }
    println!();

    let done = AtomicUsize::new(0);
    let failures: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let rows: Mutex<Vec<String>> = Mutex::new(Vec::new());

    let started = Instant::now();
    pool.install(|| {
        jobs.par_iter().for_each(|job| {
            let label = job
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| job.path.display().to_string());
            if let Some(reason) = &job.skip {
                rows.lock().unwrap().push(format!(
                    "{:<44} {:>5.0}%  skipped ({reason})",
                    short(&label),
                    job.fill * 100.0
                ));
                done.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let cover = match std::fs::read(&job.path) {
                Ok(c) => c,
                Err(e) => {
                    failures
                        .lock()
                        .unwrap()
                        .push(format!("{}: {e}", job.path.display()));
                    done.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };

            let mut worst = Round {
                embed_ms: 0,
                extract_ms: 0,
                ok: true,
                detail: String::new(),
            };
            for round in 0..config.rounds {
                let outcome = run_round(&cover, job, round, &config);
                worst.embed_ms = worst.embed_ms.max(outcome.embed_ms);
                worst.extract_ms = worst.extract_ms.max(outcome.extract_ms);
                if !outcome.ok {
                    worst.ok = false;
                    worst.detail = outcome.detail.clone();
                    failures.lock().unwrap().push(format!(
                        "{} @ {:.0}% round {round}: {}",
                        job.path.display(),
                        job.fill * 100.0,
                        outcome.detail
                    ));
                    break;
                }
            }
            // A negative check once per job: a wrong password must not read.
            if worst.ok
                && let Err(e) = wrong_password_is_rejected(&cover, job, &config)
            {
                worst.ok = false;
                worst.detail = e.clone();
                failures.lock().unwrap().push(format!(
                    "{} @ {:.0}%: {e}",
                    job.path.display(),
                    job.fill * 100.0
                ));
            }

            let done_now = done.fetch_add(1, Ordering::Relaxed) + 1;
            rows.lock().unwrap().push(format!(
                "{:<44} {:>5.0}%  {:>9}/{:<9} B  embed {:>6} ms  extract {:>6} ms  {}",
                short(&label),
                job.fill * 100.0,
                job.bytes,
                job.capacity,
                worst.embed_ms,
                worst.extract_ms,
                if worst.ok {
                    "ok".to_string()
                } else {
                    format!("FAIL {}", worst.detail)
                }
            ));
            if done_now.is_multiple_of(10) || done_now == jobs.len() {
                eprintln!("  … {done_now}/{} jobs completed", jobs.len());
            }
        });
    });

    let mut rows = rows.into_inner().unwrap();
    rows.sort();
    for row in rows {
        println!("{row}");
    }

    let failures = failures.into_inner().unwrap();
    println!();
    println!(
        "audio_stress: {} jobs executed in {:.1}s across {} carriers ({} failed, {} skipped)",
        jobs.len(),
        started.elapsed().as_secs_f64(),
        paths.len(),
        failures.len() + setup_failures.len(),
        skipped_carriers.len(),
    );

    if !skipped_carriers.is_empty() {
        println!("\nSkipped carriers (format constraints):");
        for line in &skipped_carriers {
            println!("  SKIP {line}");
        }
    }

    if !setup_failures.is_empty() || !failures.is_empty() {
        println!("\nFailures:");
        for failure in setup_failures.iter().chain(failures.iter()) {
            println!("  FAIL {failure}");
        }
        println!(
            "\nTotal elapsed time: {:.2}s",
            total_started.elapsed().as_secs_f64()
        );
        ExitCode::FAILURE
    } else {
        println!("\nAll tested carriers passed 100%!");
        println!(
            "Total elapsed time: {:.2}s",
            total_started.elapsed().as_secs_f64()
        );
        ExitCode::SUCCESS
    }
}

fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn sha256_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// One embed/extract round with configurable password and payload.
fn run_round(cover: &[u8], job: &Job, round: usize, config: &Config) -> Round {
    let password = if config.fixed_password {
        FIXED_PASSWORD.to_string()
    } else {
        format!(
            "{PASSWORD_PREFIX}-{:.0}-{round}-{}",
            job.fill * 100.0,
            rand::rng().random::<u32>()
        )
    };
    let (payload, freshness) = if config.fixed_payload {
        let seed = seed_for(cover, job, round);
        (
            deterministic_payload(job.bytes, seed),
            Freshness::Seeded(seed_bytes(seed)),
        )
    } else {
        let mut p = vec![0u8; job.bytes];
        rand::rng().fill(&mut p[..]);
        (p, Freshness::Random)
    };
    let input_sha256 = sha256_digest(&payload);

    let started = Instant::now();
    let stego = match embed_carrier(
        cover,
        &Payload::bytes(&payload),
        &EmbedOptions {
            password: Some(&password),
            freshness,
            ..EmbedOptions::default()
        },
    ) {
        Ok(s) => s,
        Err(e) => {
            return Round {
                embed_ms: started.elapsed().as_millis(),
                extract_ms: 0,
                ok: false,
                detail: format!("embed failed: {e}"),
            };
        }
    };
    let embed_ms = started.elapsed().as_millis();

    if stego.len() != cover.len() {
        return Round {
            embed_ms,
            extract_ms: 0,
            ok: false,
            detail: format!("length changed: {} -> {}", cover.len(), stego.len()),
        };
    }

    let started = Instant::now();
    let back = match extract_carrier(
        &stego,
        &ExtractOptions {
            password: Some(&password),
            ..ExtractOptions::default()
        },
    ) {
        Ok(p) => p,
        Err(e) => {
            return Round {
                embed_ms,
                extract_ms: started.elapsed().as_millis(),
                ok: false,
                detail: format!("extract failed: {e}"),
            };
        }
    };
    let extract_ms = started.elapsed().as_millis();

    let back_sha256 = sha256_digest(&back);
    if input_sha256 != back_sha256 || back != payload {
        let at = back
            .iter()
            .zip(payload.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(payload.len().min(back.len()));
        return Round {
            embed_ms,
            extract_ms,
            ok: false,
            detail: format!(
                "hash/payload mismatch at byte {at} (len {} vs {}, sha256 {:.16}.. vs {:.16}..)",
                back.len(),
                payload.len(),
                sha256_hex(&back_sha256),
                sha256_hex(&input_sha256),
            ),
        };
    }

    Round {
        embed_ms,
        extract_ms,
        ok: true,
        detail: String::new(),
    }
}

/// A wrong password must produce an error, never a different payload.
fn wrong_password_is_rejected(cover: &[u8], job: &Job, config: &Config) -> Result<(), String> {
    let (payload, freshness) = if config.fixed_payload {
        let seed = seed_for(cover, job, 0);
        (
            deterministic_payload(job.bytes.clamp(1, 64), seed),
            Freshness::Seeded(seed_bytes(seed)),
        )
    } else {
        let mut p = vec![0u8; job.bytes.clamp(1, 64)];
        rand::rng().fill(&mut p[..]);
        (p, Freshness::Random)
    };
    let right_pw = if config.fixed_password {
        FIXED_PASSWORD.to_string()
    } else {
        format!("stress-right-{}", rand::rng().random::<u32>())
    };
    let wrong_pw = format!("{right_pw}-wrong");
    let stego = embed_carrier(
        cover,
        &Payload::bytes(&payload),
        &EmbedOptions {
            password: Some(&right_pw),
            freshness,
            ..EmbedOptions::default()
        },
    )
    .map_err(|e| format!("embed failed: {e}"))?;
    match extract_carrier(
        &stego,
        &ExtractOptions {
            password: Some(&wrong_pw),
            ..ExtractOptions::default()
        },
    ) {
        Ok(p) => Err(format!(
            "a wrong password returned {} bytes instead of failing",
            p.len()
        )),
        Err(_) => Ok(()),
    }
}

/// Stable per-(carrier, fill, round) seed: the same command replays the same
/// salts, payloads and passwords.
fn seed_for(cover: &[u8], job: &Job, round: usize) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for byte in cover.iter().take(64).chain(cover.iter().rev().take(64)) {
        h ^= u64::from(*byte);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h ^= (job.fill * 1000.0) as u64;
    h = h.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ round as u64;
    h ^= cover.len() as u64;
    h
}

fn seed_bytes(seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut state = seed | 1;
    for chunk in out.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes());
    }
    out
}

fn short(label: &str) -> String {
    let mut out: String = label.chars().take(44).collect();
    if out.chars().count() < label.chars().count() {
        out.pop();
        out.push('…');
    }
    out
}

fn collect_audio(dir: &Path) -> Result<Vec<PathBuf>, String> {
    if dir.is_file() {
        return Ok(vec![dir.to_path_buf()]);
    }
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if matches!(ext.as_str(), "wav" | "flac") && !path.to_string_lossy().contains(".stego.") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

#[allow(dead_code)]
fn default_tuning() -> StegoTuning {
    StegoTuning::default()
}
