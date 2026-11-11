// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Shared harness for the `*_stress` examples.
//!
//! The four stress binaries (JPEG, PNG, HEVC, audio) used to carry four copies
//! of the same ~550 lines: argument parsing, capacity probing, job fan-out,
//! round execution, wrong-password check, reporting and hashing. Only the
//! carrier collection, tuning and format assertions are format-specific, so
//! those live behind [`StressCase`] and everything else is here.
//!
//! Invariants this harness owns (do not re-implement them per format):
//!
//! 1. embed succeeds at the requested size with the selected tuning;
//! 2. the format-specific [`StressCase::check_stego`] accepts the container;
//! 3. extract with the round password returns the payload byte for byte
//!    (SHA-256 compared, first differing byte reported);
//! 4. extract with a wrong password fails instead of returning bytes;
//! 5. the same command replays the same salts, payloads and passwords.

// This module is included once per stress binary via `#[path]`, and each
// format uses a different subset of the helpers (image harnesses need tuning,
// video/audio do not). Without this, every binary would warn about the helpers
// its siblings use.
#![allow(dead_code)]

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
use strhide::formats::FileFormat;
use strhide::stego::prng::deterministic_payload;
use strhide::stego::{
    EmbedOptions, ExtractOptions, Freshness, ProbeOptions, SafetyLevel, SafetyPolicy, StegoTuning,
    embed_carrier, extract_carrier, probe_carrier_capacity,
};

use super::init_stress_logger;

/// Parsed command line shared by every stress harness.
pub struct Args {
    pub path: Option<PathBuf>,
    pub rounds: usize,
    pub fills: Vec<f64>,
    pub threads: Option<usize>,
    pub fixed_password: bool,
    pub fixed_payload: bool,
    /// Raw `--algorithms` value; only algorithm-carrying formats consume it.
    pub algorithm_spec: Option<String>,
}

impl Args {
    pub fn parse() -> Self {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        let mut parsed = Self {
            path: None,
            rounds: 3,
            fills: vec![0.2, 0.4, 0.8, 1.0],
            threads: None,
            fixed_password: false,
            fixed_payload: false,
            algorithm_spec: None,
        };
        let mut rounds: Option<usize> = None;
        let mut fills: Option<Vec<f64>> = None;
        let mut threads: Option<usize> = None;

        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            if arg == "--fixed-password" {
                parsed.fixed_password = true;
                i += 1;
            } else if arg == "--fixed-payload" {
                parsed.fixed_payload = true;
                i += 1;
            } else if arg == "--threads" && i + 1 < args.len() {
                threads = args[i + 1].parse().ok();
                i += 2;
            } else if arg == "--rounds" && i + 1 < args.len() {
                rounds = args[i + 1].parse().ok();
                i += 2;
            } else if arg == "--fills" && i + 1 < args.len() {
                fills = Some(parse_fills(&args[i + 1]));
                i += 2;
            } else if (arg == "--algorithms" || arg == "--algo") && i + 1 < args.len() {
                parsed.algorithm_spec = Some(args[i + 1].clone());
                i += 2;
            } else if !arg.starts_with("--") {
                // Positional arguments: [path] [rounds] [fills] [threads]
                if parsed.path.is_none() {
                    parsed.path = Some(PathBuf::from(arg));
                } else if rounds.is_none() {
                    rounds = arg.parse().ok();
                } else if fills.is_none() {
                    fills = Some(parse_fills(arg));
                } else if threads.is_none() {
                    threads = arg.parse().ok();
                }
                i += 1;
            } else {
                i += 1;
            }
        }

        if let Some(rounds) = rounds {
            parsed.rounds = rounds;
        }
        if let Some(fills) = fills.filter(|v| !v.is_empty()) {
            parsed.fills = fills;
        }
        parsed.threads = threads;
        parsed
    }
}

fn parse_fills(raw: &str) -> Vec<f64> {
    raw.split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect()
}

/// One (carrier, algorithm, fill level) job.
pub struct Job<A> {
    pub path: PathBuf,
    pub algorithm: A,
    /// Fraction of the capacity to embed, in `(0, 1]`.
    pub fill: f64,
    pub bytes: usize,
    pub capacity: usize,
    pub skip: Option<String>,
}

/// Outcome of one round.
#[derive(Default)]
struct Round {
    embed_ms: u128,
    extract_ms: u128,
    ok: bool,
    detail: String,
}

enum ProbeVerdict {
    Ok(usize),
    Unsupported(String),
    Error(String),
}

/// What a format-specific stress binary must supply.
pub trait StressCase: Sync {
    type Algorithm: Clone + Send + Sync;

    /// Harness name, used for logging and the log-file prefix.
    fn name(&self) -> &'static str;
    fn password_prefix(&self) -> &'static str;
    fn fixed_password(&self) -> &'static str;

    fn default_algorithms(&self) -> Vec<Self::Algorithm>;

    /// Parse `--algorithms`; returning `None` ignores the flag (formats whose
    /// algorithm is implied by the carrier).
    fn parse_algorithms(&self, _names: &[String]) -> Option<Vec<Self::Algorithm>> {
        None
    }

    fn algorithm_id(&self, _algorithm: &Self::Algorithm) -> &'static str {
        ""
    }

    /// Whether labels, failure messages and passwords carry `[algorithm]`.
    fn labels_algorithm(&self) -> bool {
        true
    }

    /// Resolve the carriers for an explicit path or the format's default roots.
    fn collect(&self, path: Option<&Path>) -> Result<Vec<PathBuf>, String>;

    /// Capacity to fill against. Some formats report a stricter recommended
    /// ceiling that the writer enforces, so this must be format-specific.
    fn probe(&self, cover: &[u8], algorithm: &Self::Algorithm) -> Result<usize, StrHideError>;

    /// Bytes to embed for a fill fraction.
    fn bytes_for_fill(&self, capacity: usize, fill: f64) -> usize {
        ((capacity as f64) * fill).round() as usize
    }

    fn embed(
        &self,
        cover: &[u8],
        payload: &[u8],
        password: &str,
        freshness: Freshness,
        algorithm: &Self::Algorithm,
    ) -> Result<Vec<u8>, StrHideError>;

    /// Format contract: return the sniffed format for [`Self::post_extract`].
    fn check_stego(&self, cover_len: usize, stego: &[u8]) -> Result<Option<FileFormat>, String>;

    /// Extra check after a successful round (e.g. HEIF still decodes).
    fn post_extract(&self, _sniffed: Option<FileFormat>, _stego: &[u8]) -> Result<(), String> {
        Ok(())
    }

    /// Label column width; video/audio labels are shorter without `[algo]`.
    fn short_width(&self) -> usize {
        44
    }

    /// Whether the deterministic seed mixes in the algorithm id. Image
    /// harnesses do; video/audio have no algorithm to mix.
    fn seed_includes_algorithm(&self) -> bool {
        true
    }

    /// Default worker count when `--threads` is absent.
    fn default_threads(&self) -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get().min(8))
            .unwrap_or(8)
    }
}

/// Run a stress harness to completion and return the process exit code.
pub fn run<C: StressCase>(case: &C) -> ExitCode {
    let total_started = Instant::now();
    let args = Args::parse();
    let log_path = init_stress_logger(case.name());
    log::info!("{}: log file -> {}", case.name(), log_path.display());

    let algorithms = args
        .algorithm_spec
        .as_deref()
        .map(split_names)
        .and_then(|names| case.parse_algorithms(&names))
        .unwrap_or_else(|| case.default_algorithms());

    let paths = match case.collect(args.path.as_deref()) {
        Ok(paths) => paths,
        Err(e) => {
            log::error!("{}: {e}", case.name());
            return ExitCode::FAILURE;
        }
    };
    if paths.is_empty() {
        log::error!("{}: no carriers found", case.name());
        return ExitCode::FAILURE;
    }

    let threads = args.threads.unwrap_or_else(|| case.default_threads());

    if case.labels_algorithm() {
        let names: Vec<&'static str> = algorithms.iter().map(|a| case.algorithm_id(a)).collect();
        log::info!(
            "{}: {} carriers, algorithms {:?}, fills {:?}, {} rounds each, {} threads (password={}, payload={})",
            case.name(),
            paths.len(),
            names,
            args.fills,
            args.rounds,
            threads,
            if args.fixed_password {
                "fixed"
            } else {
                "rotating"
            },
            if args.fixed_payload {
                "fixed"
            } else {
                "random (SHA-256 verified)"
            },
        );
    } else {
        log::info!(
            "{}: {} carriers, fills {:?}, {} rounds each, {} threads (password={}, payload={})",
            case.name(),
            paths.len(),
            args.fills,
            args.rounds,
            threads,
            if args.fixed_password {
                "fixed"
            } else {
                "rotating"
            },
            if args.fixed_payload {
                "fixed"
            } else {
                "random (SHA-256 verified)"
            },
        );
    }

    let pool = match rayon::ThreadPoolBuilder::new().num_threads(threads).build() {
        Ok(pool) => pool,
        Err(e) => {
            log::error!("{}: cannot build thread pool: {e}", case.name());
            return ExitCode::FAILURE;
        }
    };

    let mut tasks = Vec::new();
    for path in &paths {
        for algorithm in &algorithms {
            tasks.push((path.clone(), algorithm.clone()));
        }
    }

    let probed: Vec<(PathBuf, C::Algorithm, ProbeVerdict)> = pool.install(|| {
        tasks
            .par_iter()
            .map(|(path, algorithm)| {
                let cover = match std::fs::read(path) {
                    Ok(cover) => cover,
                    Err(e) => {
                        return (
                            path.clone(),
                            algorithm.clone(),
                            ProbeVerdict::Error(format!("{}: {e}", path.display())),
                        );
                    }
                };
                match case.probe(&cover, algorithm) {
                    Ok(capacity) => (path.clone(), algorithm.clone(), ProbeVerdict::Ok(capacity)),
                    Err(StrHideError::UnsupportedFormat(reason)) => (
                        path.clone(),
                        algorithm.clone(),
                        ProbeVerdict::Unsupported(reason),
                    ),
                    Err(e) => (
                        path.clone(),
                        algorithm.clone(),
                        ProbeVerdict::Error(format!("{}: probe failed: {e}", path.display())),
                    ),
                }
            })
            .collect()
    });

    let mut jobs: Vec<Job<C::Algorithm>> = Vec::new();
    let mut setup_failures: Vec<String> = Vec::new();
    let mut skipped_carriers: Vec<String> = Vec::new();

    for (path, algorithm, verdict) in probed {
        let label = label(case, &path, &algorithm);
        match verdict {
            ProbeVerdict::Ok(capacity) => {
                if capacity == 0 {
                    setup_failures.push(format!("{label}: probe reported zero capacity"));
                    continue;
                }
                for &fill in &args.fills {
                    let bytes = case.bytes_for_fill(capacity, fill);
                    let skip = if bytes == 0 {
                        Some("payload would be empty".to_string())
                    } else if bytes > capacity {
                        Some(format!("{bytes} > capacity {capacity}"))
                    } else {
                        None
                    };
                    jobs.push(Job {
                        path: path.clone(),
                        algorithm: algorithm.clone(),
                        fill,
                        bytes,
                        capacity,
                        skip,
                    });
                }
            }
            ProbeVerdict::Unsupported(reason) => {
                skipped_carriers.push(format!("{label}: unsupported carrier ({reason})"));
            }
            ProbeVerdict::Error(e) => setup_failures.push(e),
        }
    }

    log::info!(
        "{}: {} active jobs across supported carriers",
        case.name(),
        jobs.len()
    );
    if !skipped_carriers.is_empty() {
        log::info!(
            "{}: {} carrier/algorithm combinations skipped due to format constraints",
            case.name(),
            skipped_carriers.len()
        );
    }
    log::info!("");

    let done = AtomicUsize::new(0);
    let failures: Mutex<Vec<String>> = Mutex::new(Vec::new());

    let started = Instant::now();
    pool.install(|| {
        jobs.par_iter().for_each(|job| {
            let job_label = label(case, &job.path, &job.algorithm);
            if let Some(reason) = &job.skip {
                let done_now = done.fetch_add(1, Ordering::Relaxed) + 1;
                log::info!(
                    "[{:>3}/{:<3}] {:<width$} {:>5.0}%  skipped ({reason})",
                    done_now,
                    jobs.len(),
                    short(&job_label, case.short_width()),
                    job.fill * 100.0,
                    width = case.short_width(),
                );
                return;
            }
            let cover = match std::fs::read(&job.path) {
                Ok(cover) => cover,
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
                ok: true,
                ..Round::default()
            };
            for round in 0..args.rounds {
                let outcome = run_round(case, &args, &cover, job, round);
                worst.embed_ms = worst.embed_ms.max(outcome.embed_ms);
                worst.extract_ms = worst.extract_ms.max(outcome.extract_ms);
                if !outcome.ok {
                    worst.ok = false;
                    worst.detail = outcome.detail.clone();
                    failures.lock().unwrap().push(format!(
                        "{job_label} @ {:.0}% round {round}: {}",
                        job.fill * 100.0,
                        outcome.detail
                    ));
                    break;
                }
            }
            // A negative check once per job: a wrong password must not read.
            if worst.ok
                && let Err(e) = wrong_password_is_rejected(case, &args, &cover, job)
            {
                worst.ok = false;
                worst.detail = e.clone();
                failures
                    .lock()
                    .unwrap()
                    .push(format!("{job_label} @ {:.0}%: {e}", job.fill * 100.0));
            }

            let done_now = done.fetch_add(1, Ordering::Relaxed) + 1;
            log::info!(
                "[{:>3}/{:<3}] {:<width$} {:>5.0}%  {:>9}/{:<9} B  embed {:>6} ms  extract {:>6} ms  {}",
                done_now,
                jobs.len(),
                short(&job_label, case.short_width()),
                job.fill * 100.0,
                job.bytes,
                job.capacity,
                worst.embed_ms,
                worst.extract_ms,
                if worst.ok {
                    "ok".to_string()
                } else {
                    format!("FAIL {}", worst.detail)
                },
                width = case.short_width(),
            );
        });
    });

    let failures = failures.into_inner().unwrap();
    log::info!("");
    log::info!(
        "{}: {} jobs executed in {:.1}s across {} carriers ({} failed, {} skipped)",
        case.name(),
        jobs.len(),
        started.elapsed().as_secs_f64(),
        paths.len(),
        failures.len() + setup_failures.len(),
        skipped_carriers.len(),
    );

    if !skipped_carriers.is_empty() {
        log::info!("\nSkipped carriers (format constraints):");
        for line in &skipped_carriers {
            log::info!("  SKIP {line}");
        }
    }

    if !setup_failures.is_empty() || !failures.is_empty() {
        log::info!("\nFailures:");
        for failure in setup_failures.iter().chain(failures.iter()) {
            log::info!("  FAIL {failure}");
        }
        log::info!(
            "\nTotal elapsed time: {:.2}s",
            total_started.elapsed().as_secs_f64()
        );
        log::info!("Log saved to: {}", log_path.display());
        ExitCode::FAILURE
    } else {
        log::info!("\nAll tested carriers passed 100%!");
        log::info!(
            "Total elapsed time: {:.2}s",
            total_started.elapsed().as_secs_f64()
        );
        log::info!("Log saved to: {}", log_path.display());
        ExitCode::SUCCESS
    }
}

fn split_names(raw: &str) -> Vec<String> {
    raw.split(',').map(|s| s.trim().to_string()).collect()
}

fn label<C: StressCase>(case: &C, path: &Path, algorithm: &C::Algorithm) -> String {
    let file = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    if case.labels_algorithm() {
        format!("{} [{}]", file, case.algorithm_id(algorithm))
    } else {
        file
    }
}

fn password_for<C: StressCase>(
    case: &C,
    args: &Args,
    job: &Job<C::Algorithm>,
    round: usize,
) -> String {
    if args.fixed_password {
        return case.fixed_password().to_string();
    }
    if case.labels_algorithm() {
        format!(
            "{}-{}-{:.0}-{round}-{}",
            case.password_prefix(),
            case.algorithm_id(&job.algorithm),
            job.fill * 100.0,
            rand::rng().random::<u32>()
        )
    } else {
        format!(
            "{}-{:.0}-{round}-{}",
            case.password_prefix(),
            job.fill * 100.0,
            rand::rng().random::<u32>()
        )
    }
}

fn payload_for<C: StressCase>(
    case: &C,
    args: &Args,
    cover: &[u8],
    job: &Job<C::Algorithm>,
    bytes: usize,
    round: usize,
) -> (Vec<u8>, Freshness) {
    if args.fixed_payload {
        let seed = seed_for(case, cover, job.fill, round, &job.algorithm);
        (
            deterministic_payload(bytes, seed),
            Freshness::Seeded(seed_bytes(seed)),
        )
    } else {
        let mut payload = vec![0u8; bytes];
        rand::rng().fill(&mut payload[..]);
        (payload, Freshness::Random)
    }
}

/// One embed/extract round with configurable password and payload.
fn run_round<C: StressCase>(
    case: &C,
    args: &Args,
    cover: &[u8],
    job: &Job<C::Algorithm>,
    round: usize,
) -> Round {
    let password = password_for(case, args, job, round);
    let (payload, freshness) = payload_for(case, args, cover, job, job.bytes, round);
    let input_sha256 = sha256_digest(&payload);

    let started = Instant::now();
    let stego = match case.embed(cover, &payload, &password, freshness, &job.algorithm) {
        Ok(stego) => stego,
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

    let sniffed = match case.check_stego(cover.len(), &stego) {
        Ok(sniffed) => sniffed,
        Err(detail) => {
            return Round {
                embed_ms,
                extract_ms: 0,
                ok: false,
                detail,
            };
        }
    };

    let started = Instant::now();
    let back = match extract_carrier(&stego, &ExtractOptions::default().with_password(&password)) {
        Ok(payload) => payload,
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

    if let Err(detail) = case.post_extract(sniffed, &stego) {
        return Round {
            embed_ms,
            extract_ms,
            ok: false,
            detail,
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
fn wrong_password_is_rejected<C: StressCase>(
    case: &C,
    args: &Args,
    cover: &[u8],
    job: &Job<C::Algorithm>,
) -> Result<(), String> {
    let (payload, freshness) = payload_for(case, args, cover, job, job.bytes.clamp(1, 64), 0);
    let right_pw = if args.fixed_password {
        case.fixed_password().to_string()
    } else {
        format!(
            "{}-right-{}",
            case.password_prefix(),
            rand::rng().random::<u32>()
        )
    };
    let wrong_pw = format!("{right_pw}-wrong");
    let stego = case
        .embed(cover, &payload, &right_pw, freshness, &job.algorithm)
        .map_err(|e| format!("embed failed: {e}"))?;
    match extract_carrier(&stego, &ExtractOptions::default().with_password(&wrong_pw)) {
        Ok(payload) => Err(format!(
            "a wrong password returned {} bytes instead of failing",
            payload.len()
        )),
        Err(_) => Ok(()),
    }
}

pub fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn sha256_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Stable per-(carrier, fill, round) seed: the same command replays the same
/// salts, payloads and passwords.
fn seed_for<C: StressCase>(
    case: &C,
    cover: &[u8],
    fill: f64,
    round: usize,
    algorithm: &C::Algorithm,
) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for byte in cover.iter().take(64).chain(cover.iter().rev().take(64)) {
        h ^= u64::from(*byte);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h ^= (fill * 1000.0) as u64;
    h = h.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ round as u64;
    h ^= cover.len() as u64;
    if case.seed_includes_algorithm() {
        h ^= (case.algorithm_id(algorithm).len() as u64) << 32;
    }
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

fn short(label: &str, width: usize) -> String {
    let mut out: String = label.chars().take(width).collect();
    if out.chars().count() < label.chars().count() {
        out.pop();
        out.push('…');
    }
    out
}

/// Build the probe options every format shares (High tier, exact scan).
pub fn probe_options<'a>() -> ProbeOptions<'a> {
    ProbeOptions::default()
        .with_safety_policy(SafetyPolicy::default().with_level(SafetyLevel::High))
        .with_exact(true)
}

/// Probe with a format-specific tuning, returning the raw capacity ceiling.
pub fn probe_with_tuning(cover: &[u8], tuning: StegoTuning) -> Result<usize, StrHideError> {
    let options = probe_options().with_tuning(tuning);
    probe_carrier_capacity(cover, &options).map(|c| c.max_raw_payload_bytes)
}

/// Embed with a format-specific tuning.
pub fn embed_with_tuning(
    cover: &[u8],
    payload: &[u8],
    password: &str,
    freshness: Freshness,
    tuning: StegoTuning,
) -> Result<Vec<u8>, StrHideError> {
    embed_carrier(
        cover,
        &Payload::bytes(payload),
        &EmbedOptions::default()
            .with_password(password)
            .with_freshness(freshness)
            .with_tuning(tuning),
    )
}

/// Embed with only the shared credential/freshness options.
pub fn embed_plain(
    cover: &[u8],
    payload: &[u8],
    password: &str,
    freshness: Freshness,
) -> Result<Vec<u8>, StrHideError> {
    embed_carrier(
        cover,
        &Payload::bytes(payload),
        &EmbedOptions::default()
            .with_password(password)
            .with_freshness(freshness),
    )
}

/// Recursively collect carriers with the given extensions, skipping `.stego.`
/// outputs and descending into `<dir>/<subdir>` once when the top level is empty.
pub fn collect_by_ext(
    dir: &Path,
    extensions: &[&str],
    subdir: Option<&str>,
) -> Result<Vec<PathBuf>, String> {
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
        if extensions.contains(&ext.as_str()) && !path.to_string_lossy().contains(".stego.") {
            out.push(path);
        }
    }
    if out.is_empty()
        && let Some(subdir) = subdir
    {
        let nested = dir.join(subdir);
        if nested.is_dir() {
            return collect_by_ext(&nested, extensions, None);
        }
    }
    out.sort();
    Ok(out)
}

/// First existing path among `candidates`.
pub fn first_existing(candidates: &[&str]) -> PathBuf {
    candidates
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(candidates[0]))
}
