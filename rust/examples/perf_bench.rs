// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Release performance baseline harness (both domains).
//!
//! ```text
//! cargo build --release --all-features --example perf_bench
//! ./target/release/examples/perf_bench --domain structure --reps 20 --warmup 2 \
//!     --out ../temp/bench/results/structure.json
//! ```
//!
//! Design notes (see `docs/PERF_BENCHMARK_PLAN_20261107.md`):
//!
//! - Every timed call goes through the **in-memory** byte APIs, i.e. the same
//!   engine / envelope / AEAD path the CLI uses, minus filesystem I/O. Disk
//!   overhead is measured separately (`--io`) so it never pollutes the main
//!   table.
//! - Payloads are incompressible SplitMix64 output with a fixed seed, so the
//!   structure domain's `CompressionStrategy::Auto` degenerates to "stored"
//!   every time instead of depending on how compressible the sample happens to be.
//! - Content-domain writes use `Freshness::Seeded`, making salt/nonce (and thus
//!   the whole embedding) reproducible; reads only need the password.
//! - Statistics are computed after the timed loop, never inside it. When the
//!   coefficient of variation exceeds 10 %, a trimmed mean (drop one min and one
//!   max) is reported alongside the raw mean.

use std::collections::HashMap;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use strhide::core::commit::FileTarget;
use strhide::core::payload::Payload;
use strhide::params::LocalParams;
use strhide::stego::io::{embed_carrier_file, extract_carrier_file_payload};
use strhide::stego::params::StegoProfile;
use strhide::stego::{
    EmbedOptions, ExtractOptions, Freshness, HevcMode, HevcParams, JpegAlgorithm, JpegParams,
    PngParams, ProbeOptions, SafetyEnforcement, SafetyLevel, SpatialAlgorithm, StegoTuning,
    embed_carrier, extract_carrier, probe_carrier_capacity,
};
use strhide::structure::{
    PayloadSource, ReadOptions, StructureProfile, WriteOptions, read_carrier, read_carrier_bytes,
    remove_carrier_bytes, write_carrier_bytes, write_carrier_with,
};

// ── Fixed benchmark constants ─────────────────────────────────────────────

const PASSWORD: &str = "strhide-bench-v1";

/// 32-byte content-domain embedding seed (`5eed00..01`).
const SEED: [u8; 32] = [
    0x5e, 0xed, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// 32-byte file key used only by the KDF-split experiment (skips PBKDF2).
const FILE_KEY: [u8; 32] = [
    0xa5, 0x5a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
];

const STRUCTURE_SIZES: [usize; 5] = [
    4 * 1024,
    64 * 1024,
    256 * 1024,
    1024 * 1024,
    4 * 1024 * 1024,
];
const CONTENT_SIZES: [usize; 4] = [1024, 8 * 1024, 32 * 1024, 128 * 1024];

const KIB: usize = 1024;

// ── Carrier tables ────────────────────────────────────────────────────────

struct StructureCarrier {
    id: &'static str,
    family: &'static str,
    file: &'static str,
    ext: &'static str,
}

const STRUCTURE_CARRIERS: [StructureCarrier; 9] = [
    StructureCarrier {
        id: "png",
        family: "PNG",
        file: "png_baseline.png",
        ext: "png",
    },
    StructureCarrier {
        id: "jpeg",
        family: "JPEG",
        file: "jpg_baseline.jpg",
        ext: "jpg",
    },
    StructureCarrier {
        id: "webp",
        family: "WebP",
        file: "webp_baseline.webp",
        ext: "webp",
    },
    StructureCarrier {
        id: "wav",
        family: "WAV",
        file: "wav_baseline.wav",
        ext: "wav",
    },
    StructureCarrier {
        id: "mp4",
        family: "MP4",
        file: "mp4_baseline.mp4",
        ext: "mp4",
    },
    StructureCarrier {
        id: "mkv",
        family: "MKV",
        file: "mkv_baseline.mkv",
        ext: "mkv",
    },
    StructureCarrier {
        id: "zip",
        family: "ZIP",
        file: "zip_baseline.zip",
        ext: "zip",
    },
    StructureCarrier {
        id: "pdf",
        family: "PDF",
        file: "pdf_baseline.pdf",
        ext: "pdf",
    },
    StructureCarrier {
        id: "pe",
        family: "PE",
        file: "pe_baseline.exe",
        ext: "exe",
    },
];

/// One (carrier, algorithm) pair. The content domain's algorithms differ by a
/// large factor in cost, so the matrix is per-algorithm rather than per-format.
struct ContentScenario {
    id: &'static str,
    family: &'static str,
    file: &'static str,
    algorithm: &'static str,
    tuning: fn() -> StegoTuning,
    sizes: &'static [usize],
    note: &'static str,
}

fn tuning_png_hill() -> StegoTuning {
    StegoTuning::Png {
        model: SpatialAlgorithm::Hill,
        params: PngParams::default(),
    }
}
fn tuning_png_suniward() -> StegoTuning {
    StegoTuning::Png {
        model: SpatialAlgorithm::Suniward,
        params: PngParams::default(),
    }
}
fn tuning_png_mipod() -> StegoTuning {
    StegoTuning::Png {
        model: SpatialAlgorithm::Mipod,
        params: PngParams::default(),
    }
}
fn tuning_jpeg_uerd() -> StegoTuning {
    StegoTuning::Jpeg {
        model: JpegAlgorithm::Uerd,
        params: JpegParams::default(),
    }
}
fn tuning_jpeg_juniward() -> StegoTuning {
    StegoTuning::Jpeg {
        model: JpegAlgorithm::Juniward,
        params: JpegParams::default(),
    }
}
fn tuning_jpeg_jmipod() -> StegoTuning {
    StegoTuning::Jpeg {
        model: JpegAlgorithm::Jmipod,
        params: JpegParams::default(),
    }
}
fn tuning_hevc() -> StegoTuning {
    StegoTuning::Hevc {
        mode: HevcMode::Auto,
        params: HevcParams::default(),
    }
}
fn tuning_auto() -> StegoTuning {
    StegoTuning::Auto
}

const ALL_SIZES: &[usize] = &CONTENT_SIZES;
/// FLAC residual capacity tops out well below 128 KiB on a ~20 MiB file, so the
/// audio-lossless row is documented at three tiers (see the benchmark plan §5).
const FLAC_SIZES: &[usize] = &[1024, 8 * 1024, 32 * 1024];
/// The only FLAC carrier in the corpus that can physically hold 128 KiB is the
/// 58 MiB Hi-Res track, at 92 % of its physical limit, and one embed costs
/// ~15 s. It is measured separately (carrier switch, per the plan's §5 rule).
const FLAC_128K_SIZES: &[usize] = &[128 * 1024];

const CONTENT_SCENARIOS: [ContentScenario; 11] = [
    ContentScenario {
        id: "png_hill",
        family: "PNG",
        file: "png_content_12mp.png",
        algorithm: "hill",
        tuning: tuning_png_hill,
        sizes: ALL_SIZES,
        note: "3000x4000 RGB, HILL (default spatial)",
    },
    ContentScenario {
        id: "png_suniward",
        family: "PNG",
        file: "png_content_12mp.png",
        algorithm: "suniward",
        tuning: tuning_png_suniward,
        sizes: ALL_SIZES,
        note: "3000x4000 RGB, S-UNIWARD",
    },
    ContentScenario {
        id: "png_mipod",
        family: "PNG",
        file: "png_content_12mp.png",
        algorithm: "mipod",
        tuning: tuning_png_mipod,
        sizes: ALL_SIZES,
        note: "3000x4000 RGB, MiPOD",
    },
    ContentScenario {
        id: "jpeg_uerd",
        family: "JPEG",
        file: "jpg_content_22mp.jpg",
        algorithm: "uerd",
        tuning: tuning_jpeg_uerd,
        sizes: ALL_SIZES,
        note: "5760x3840, UERD (default DCT)",
    },
    ContentScenario {
        id: "jpeg_juniward",
        family: "JPEG",
        file: "jpg_content_22mp.jpg",
        algorithm: "juniward",
        tuning: tuning_jpeg_juniward,
        sizes: ALL_SIZES,
        note: "5760x3840, J-UNIWARD (scalar path under a fixed seed)",
    },
    ContentScenario {
        id: "jpeg_jmipod",
        family: "JPEG",
        file: "jpg_content_22mp.jpg",
        algorithm: "jmipod",
        tuning: tuning_jpeg_jmipod,
        sizes: ALL_SIZES,
        note: "5760x3840, J-MiPOD",
    },
    ContentScenario {
        id: "hevc_mp4",
        family: "HEVC-MP4",
        file: "hevc_video.mp4",
        algorithm: "hevc_cabac",
        tuning: tuning_hevc,
        sizes: ALL_SIZES,
        note: "1920x1080@60, 3.3 s, CABAC Scheme C",
    },
    ContentScenario {
        id: "heic",
        family: "HEIC",
        file: "heic_image.heic",
        algorithm: "hevc_cabac",
        tuning: tuning_hevc,
        sizes: ALL_SIZES,
        note: "4032x3024, CABAC Scheme C (still image)",
    },
    ContentScenario {
        id: "wav_pcm",
        family: "WAV",
        file: "wav_content.wav",
        algorithm: "wav_pcm",
        tuning: tuning_auto,
        sizes: ALL_SIZES,
        note: "47 MiB PCM 16-bit, audio STC h8/u3",
    },
    ContentScenario {
        id: "flac_residual",
        family: "FLAC",
        file: "flac_content.flac",
        algorithm: "flac_residual",
        tuning: tuning_auto,
        sizes: FLAC_SIZES,
        note: "21 MiB FLAC, residual-domain STC (128 KiB exceeds capacity)",
    },
    ContentScenario {
        id: "flac128",
        family: "FLAC",
        file: "flac_content_58m.flac",
        algorithm: "flac_residual",
        tuning: tuning_auto,
        sizes: FLAC_128K_SIZES,
        note: "58 MiB FLAC, 128 KiB at 92 % of the physical limit (carrier switch)",
    },
];

// ── Payload generation ────────────────────────────────────────────────────

/// Deterministic, incompressible payload (SplitMix64 stream, truncated).
fn payload_for(size: usize) -> Vec<u8> {
    let mut state: u64 = 42;
    let mut out = Vec::with_capacity(size + 8);
    while out.len() < size {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        out.extend_from_slice(&z.to_le_bytes());
    }
    out.truncate(size);
    out
}

// ── Statistics ────────────────────────────────────────────────────────────

struct Stats {
    n: usize,
    mean: f64,
    median: f64,
    p95: f64,
    stddev: f64,
    cv: f64,
    min: f64,
    max: f64,
    trimmed_mean: f64,
    trimmed: bool,
}

fn compute_stats(samples: &[f64]) -> Stats {
    let n = samples.len();
    let mean = samples.iter().sum::<f64>() / n as f64;
    let var = if n > 1 {
        samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64
    } else {
        0.0
    };
    let stddev = var.sqrt();
    let cv = if mean > 0.0 { stddev / mean } else { 0.0 };

    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let median = if n.is_multiple_of(2) {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    };
    let rank = ((0.95 * n as f64).ceil() as usize).clamp(1, n);
    let p95 = sorted[rank - 1];

    let trimmed = cv > 0.10 && n >= 5;
    let trimmed_mean = if trimmed {
        sorted[1..n - 1].iter().sum::<f64>() / (n - 2) as f64
    } else {
        mean
    };

    Stats {
        n,
        mean,
        median,
        p95,
        stddev,
        cv,
        min: sorted[0],
        max: sorted[n - 1],
        trimmed_mean,
        trimmed,
    }
}

fn stats_json(s: &Stats, samples: &[f64]) -> Value {
    json!({
        "n": s.n,
        "mean_ms": s.mean,
        "median_ms": s.median,
        "p95_ms": s.p95,
        "stddev_ms": s.stddev,
        "cv": s.cv,
        "min_ms": s.min,
        "max_ms": s.max,
        "trimmed_mean_ms": s.trimmed_mean,
        "trimmed": s.trimmed,
        "samples_ms": samples,
    })
}

// ── Timing helper ─────────────────────────────────────────────────────────

fn timed<T>(f: impl FnOnce() -> T) -> (T, f64) {
    let t0 = Instant::now();
    let value = f();
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    (black_box(value), ms)
}

// ── Structure domain ──────────────────────────────────────────────────────

fn structure_cell(
    dir: &Path,
    carrier: &StructureCarrier,
    payload_size: usize,
    payload: &[u8],
    reps: usize,
    warmup: usize,
) -> Value {
    let cell_id = format!("structure/{}", carrier.id);
    let path = dir.join(carrier.file);
    let cover = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return json!({
                "id": cell_id,
                "status": "error",
                "payload_bytes": payload_size,
                "error": format!("read {}: {err}", path.display()),
            });
        }
    };

    let profile = StructureProfile::default();
    let local = LocalParams::default();
    let mut opts = WriteOptions::default();
    opts.password = Some(PASSWORD);
    opts.backup = false;

    let mut strategy = String::new();
    let mut strategy_note: Option<String> = None;
    let mut ube_size = 0u64;
    let mut stego_bytes = 0u64;

    // Warmup: also where a strategy/capacity failure surfaces first.
    for _ in 0..warmup {
        let (stego, wrote) = match write_carrier_bytes(
            &cover,
            PayloadSource::Bytes(payload),
            &opts,
            &local,
            &profile,
        ) {
            Ok(pair) => pair,
            Err(err) => {
                return json!({
                    "id": cell_id,
                    "status": "error",
                    "payload_bytes": payload_size,
                    "error": format!("warmup write: {err}"),
                });
            }
        };
        strategy = wrote.strategy.to_string();
        strategy_note = wrote.strategy_note.clone();
        ube_size = wrote.ube_size;
        stego_bytes = stego.len() as u64;
        if let Err(err) = read_carrier_bytes(&stego, Some(PASSWORD), &profile) {
            return json!({
                "id": cell_id,
                "status": "error",
                "payload_bytes": payload_size,
                "error": format!("warmup read: {err}"),
            });
        }
    }

    // Correctness gate (untimed): payload round-trip + bit-exact restore.
    let verify = (|| -> Result<(), String> {
        let (stego, _) = write_carrier_bytes(
            &cover,
            PayloadSource::Bytes(payload),
            &opts,
            &local,
            &profile,
        )
        .map_err(|e| e.to_string())?;
        let read =
            read_carrier_bytes(&stego, Some(PASSWORD), &profile).map_err(|e| e.to_string())?;
        if read.data.as_slice() != payload {
            return Err("payload mismatch after read".into());
        }
        let (restored, _) =
            remove_carrier_bytes(&stego, Some(PASSWORD), &profile).map_err(|e| e.to_string())?;
        if restored != cover {
            return Err("restore is not bit-exact".into());
        }
        Ok(())
    })();

    if let Err(err) = verify {
        return json!({
            "id": cell_id,
            "status": "fail",
            "payload_bytes": payload_size,
            "error": err,
        });
    }

    let mut write_ms = Vec::with_capacity(reps);
    let mut read_ms = Vec::with_capacity(reps);

    for _ in 0..reps {
        let ((stego, _wrote), w) = timed(|| {
            write_carrier_bytes(
                &cover,
                PayloadSource::Bytes(payload),
                &opts,
                &local,
                &profile,
            )
            .expect("write failed mid-run")
        });
        let (read, r) = timed(|| {
            read_carrier_bytes(&stego, Some(PASSWORD), &profile).expect("read failed mid-run")
        });
        if read.data.as_slice() != payload {
            return json!({
                "id": cell_id,
                "status": "fail",
                "payload_bytes": payload_size,
                "error": "payload mismatch mid-run",
            });
        }
        write_ms.push(w);
        read_ms.push(r);
    }

    let ws = compute_stats(&write_ms);
    let rs = compute_stats(&read_ms);

    json!({
        "id": cell_id,
        "status": "ok",
        "domain": "structure",
        "carrier_id": carrier.id,
        "carrier_family": carrier.family,
        "carrier_file": carrier.file,
        "carrier_bytes": cover.len(),
        "payload_bytes": payload_size,
        "reps": reps,
        "write": stats_json(&ws, &write_ms),
        "read": stats_json(&rs, &read_ms),
        "meta": {
            "strategy": strategy,
            "strategy_note": strategy_note,
            "ube_size": ube_size,
            "stego_bytes": stego_bytes,
            "envelope_overhead": ube_size.saturating_sub(payload_size as u64),
            "kdf": "pbkdf2-hmac-sha256 100000 (structure)",
        },
    })
}

// ── Structure domain: file-API overhead ───────────────────────────────────

fn structure_io_cell(
    dir: &Path,
    io_dir: &Path,
    carrier: &StructureCarrier,
    payload_size: usize,
    payload: &[u8],
    reps: usize,
) -> Value {
    let src = dir.join(carrier.file);
    let tmp = io_dir.join(format!("io_{}.{}", carrier.id, carrier.ext));

    let mut opts = WriteOptions::default();
    opts.password = Some(PASSWORD);
    opts.backup = false;
    let mut ropts = ReadOptions::default();
    ropts.password = Some(PASSWORD);

    let mut write_ms = Vec::with_capacity(reps);
    let mut read_ms = Vec::with_capacity(reps);

    for _ in 0..reps {
        // Reset the working copy outside the timed region.
        if let Err(err) = std::fs::copy(&src, &tmp) {
            return json!({ "id": format!("structure_io/{}", carrier.id), "status": "error",
                           "error": format!("copy carrier: {err}") });
        }
        let (written, wt) = timed(|| {
            write_carrier_with(
                &tmp,
                PayloadSource::Bytes(payload),
                &opts,
                &LocalParams::default(),
                &StructureProfile::default(),
            )
        });
        if let Err(err) = written {
            let _ = std::fs::remove_file(&tmp);
            return json!({ "id": format!("structure_io/{}", carrier.id), "status": "error",
                           "error": format!("write: {err}") });
        }
        let (read, rt) = timed(|| read_carrier(&tmp, &ropts));
        match read {
            Ok(read) => {
                if read.data.as_slice() != payload {
                    let _ = std::fs::remove_file(&tmp);
                    return json!({ "id": format!("structure_io/{}", carrier.id), "status": "fail",
                                   "error": "payload mismatch" });
                }
            }
            Err(err) => {
                let _ = std::fs::remove_file(&tmp);
                return json!({ "id": format!("structure_io/{}", carrier.id), "status": "error",
                               "error": format!("read: {err}") });
            }
        }
        write_ms.push(wt);
        read_ms.push(rt);
    }
    let _ = std::fs::remove_file(&tmp);

    json!({
        "id": format!("structure_io/{}", carrier.id),
        "status": "ok",
        "carrier_id": carrier.id,
        "payload_bytes": payload_size,
        "reps": reps,
        "write": stats_json(&compute_stats(&write_ms), &write_ms),
        "read": stats_json(&compute_stats(&read_ms), &read_ms),
    })
}

// ── Structure domain: compression cost (compressible payload) ─────────────

/// The main structure table uses incompressible payloads, so
/// `CompressionStrategy::Auto` never actually compresses. This cell measures
/// the other half of the story: a 4 MiB all-zero payload, which deflate turns
/// into a few kilobytes, and therefore costs CPU instead of container bytes.
fn structure_compress_cell(
    dir: &Path,
    carrier: &StructureCarrier,
    payload_size: usize,
    reps: usize,
) -> Value {
    let cell_id = format!("structure_compress/{}", carrier.id);
    let path = dir.join(carrier.file);
    let cover = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return json!({ "id": cell_id, "status": "error", "error": format!("read: {err}") });
        }
    };
    let payload = vec![0u8; payload_size];
    let profile = StructureProfile::default();
    let local = LocalParams::default();
    let mut opts = WriteOptions::default();
    opts.password = Some(PASSWORD);
    opts.backup = false;

    let mut write_ms = Vec::with_capacity(reps);
    let mut read_ms = Vec::with_capacity(reps);
    let mut ube_size = 0u64;

    for _ in 0..reps {
        let ((stego, wrote), w) = timed(|| {
            write_carrier_bytes(
                &cover,
                PayloadSource::Bytes(&payload),
                &opts,
                &local,
                &profile,
            )
            .expect("write failed")
        });
        let (read, r) =
            timed(|| read_carrier_bytes(&stego, Some(PASSWORD), &profile).expect("read failed"));
        if read.data.as_slice() != payload.as_slice() {
            return json!({ "id": cell_id, "status": "fail", "error": "payload mismatch" });
        }
        ube_size = wrote.ube_size;
        write_ms.push(w);
        read_ms.push(r);
    }

    json!({
        "id": cell_id,
        "status": "ok",
        "carrier_id": carrier.id,
        "payload_bytes": payload_size,
        "payload_kind": "all-zero (highly compressible)",
        "reps": reps,
        "write": stats_json(&compute_stats(&write_ms), &write_ms),
        "read": stats_json(&compute_stats(&read_ms), &read_ms),
        "meta": { "ube_size": ube_size, "compression": "Auto -> deflate" },
    })
}

// ── Content domain ────────────────────────────────────────────────────────

fn embed_options(tuning: StegoTuning, level: SafetyLevel) -> EmbedOptions<'static> {
    EmbedOptions::default()
        .with_password(PASSWORD)
        .with_freshness(Freshness::Seeded(SEED))
        .with_tuning(tuning)
        .with_safety(level, SafetyEnforcement::Advisory)
}

/// The official default is `High`/`Advisory`. Some carriers (short HEVC clips,
/// small FLAC files) cannot hold the larger tiers even in advisory mode: the
/// engine's slot math refuses instead of writing an over-sparse carrier. Per the
/// benchmark plan §5 that case drops one tier to `Balanced` and records it,
/// rather than dropping the cell.
fn resolve_level(
    cover: &[u8],
    payload: &[u8],
    tuning: StegoTuning,
) -> (SafetyLevel, Option<String>) {
    match embed_carrier(
        cover,
        &Payload::bytes(payload),
        &embed_options(tuning.clone(), SafetyLevel::High),
    ) {
        Ok(_) => (SafetyLevel::High, None),
        Err(err) => {
            let msg = err.to_string();
            if msg.contains("capacity insufficient") {
                match embed_carrier(
                    cover,
                    &Payload::bytes(payload),
                    &embed_options(tuning, SafetyLevel::Balanced),
                ) {
                    Ok(_) => (
                        SafetyLevel::Balanced,
                        Some(format!(
                            "High tier refused by the engine ({msg}); measured at Balanced"
                        )),
                    ),
                    Err(err2) => (SafetyLevel::High, Some(format!("unfittable: {err2}"))),
                }
            } else {
                (SafetyLevel::High, Some(format!("embed failed: {msg}")))
            }
        }
    }
}

fn capacity_summary(carrier: &[u8], tuning: StegoTuning) -> Value {
    let opts = ProbeOptions::default().with_tuning(tuning);
    match probe_carrier_capacity(carrier, &opts) {
        Ok(cap) => json!({
            "algorithm": cap.algorithm,
            "total_elements": cap.total_elements,
            "available_slots": cap.available_slots,
            "max_raw_payload_bytes": cap.max_raw_payload_bytes,
            "recommended_max_bytes": cap.recommended_max_bytes,
            "tier_limits": cap.tier_limits,
            "safety_level": cap.safety_level,
            "estimated_change_rate": cap.estimated_change_rate,
            "is_estimated": cap.is_estimated,
        }),
        Err(err) => json!({ "error": err.to_string() }),
    }
}

fn content_cell(
    dir: &Path,
    scenario: &ContentScenario,
    payload_size: usize,
    payload: &[u8],
    reps: usize,
    warmup: usize,
) -> Value {
    let cell_id = format!("content/{}", scenario.id);
    let path = dir.join(scenario.file);
    let cover = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return json!({
                "id": cell_id,
                "status": "error",
                "payload_bytes": payload_size,
                "error": format!("read {}: {err}", path.display()),
            });
        }
    };

    let capacity = capacity_summary(&cover, (scenario.tuning)());

    // Capacity gate: an over-capacity payload is a documented skip, not a failure.
    if let Some(max_raw) = capacity
        .get("max_raw_payload_bytes")
        .and_then(Value::as_u64)
        && payload_size as u64 > max_raw
    {
        return json!({
            "id": cell_id,
            "status": "skip",
            "payload_bytes": payload_size,
            "capacity": capacity,
            "error": format!(
                "payload {payload_size} B exceeds the carrier's physical capacity {max_raw} B"
            ),
        });
    }

    let (level, level_note) = resolve_level(&cover, payload, (scenario.tuning)());
    if let Some(note) = &level_note
        && (note.starts_with("unfittable") || note.starts_with("embed failed"))
    {
        return json!({
            "id": cell_id,
            "status": "skip",
            "payload_bytes": payload_size,
            "capacity": capacity,
            "error": note,
        });
    }

    let embed_opts = embed_options((scenario.tuning)(), level);
    let extract_opts = ExtractOptions::default().with_password(PASSWORD);

    for _ in 0..warmup {
        let stego = match embed_carrier(&cover, &Payload::bytes(payload), &embed_opts) {
            Ok(s) => s,
            Err(err) => {
                return json!({
                    "id": cell_id,
                    "status": "error",
                    "payload_bytes": payload_size,
                    "capacity": capacity,
                    "error": format!("warmup embed: {err}"),
                });
            }
        };
        if let Err(err) = extract_carrier(&stego, &extract_opts) {
            return json!({
                "id": cell_id,
                "status": "error",
                "payload_bytes": payload_size,
                "capacity": capacity,
                "error": format!("warmup extract: {err}"),
            });
        }
    }

    let mut write_ms = Vec::with_capacity(reps);
    let mut read_ms = Vec::with_capacity(reps);
    let mut stego_bytes = 0u64;

    for i in 0..reps {
        let (stego, w) = timed(|| {
            embed_carrier(&cover, &Payload::bytes(payload), &embed_opts)
                .expect("embed failed mid-run")
        });
        let (data, r) =
            timed(|| extract_carrier(&stego, &extract_opts).expect("extract failed mid-run"));
        if data.as_slice() != payload {
            return json!({
                "id": cell_id,
                "status": "fail",
                "payload_bytes": payload_size,
                "capacity": capacity,
                "error": "payload mismatch mid-run",
            });
        }
        stego_bytes = stego.len() as u64;
        write_ms.push(w);
        read_ms.push(r);
        // Long cells (e.g. 58 MiB FLAC) take minutes; emit progress inside the
        // loop so a stopped run is distinguishable from a hung one. stderr is
        // unbuffered, and this line is outside the timed region.
        if (i + 1) % 5 == 0 || i + 1 == reps {
            eprintln!(
                "  [progress] {} @ {} B  {}/{}  last {:.0} ms / {:.0} ms",
                scenario.id,
                payload_size,
                i + 1,
                reps,
                w,
                r
            );
        }
    }
    let mut warnings: Vec<String> = Vec::new();
    if let Some(rec) = capacity
        .get("recommended_max_bytes")
        .and_then(Value::as_u64)
        && payload_size as u64 > rec
    {
        warnings.push(format!(
            "payload {payload_size} B exceeds the High-tier recommendation {rec} B \
                 (Advisory: written, SafetyThresholdExceeded expected)"
        ));
    }

    json!({
        "id": cell_id,
        "status": "ok",
        "domain": "content",
        "carrier_id": scenario.id,
        "carrier_family": scenario.family,
        "carrier_file": scenario.file,
        "algorithm": scenario.algorithm,
        "carrier_note": scenario.note,
        "carrier_bytes": cover.len(),
        "payload_bytes": payload_size,
        "reps": reps,
        "write": stats_json(&compute_stats(&write_ms), &write_ms),
        "read": stats_json(&compute_stats(&read_ms), &read_ms),
        "capacity": capacity,
        "meta": {
            "stego_bytes": stego_bytes,
            "kdf": "pbkdf2-hmac-sha256 200000 (content L1)",
            "freshness": "Seeded",
            "safety_level": format!("{level:?}"),
            "level_note": level_note,
            "warnings": warnings,
        },
    })
}

/// Same carrier/payload without PBKDF2 (`Credential::FileKey`) to separate the
/// KDF cost from the engine cost. Not part of the main table.
fn content_kdf_split(dir: &Path, scenario: &ContentScenario, payload: &[u8], reps: usize) -> Value {
    let cell_id = format!("content_kdf/{}", scenario.id);
    let path = dir.join(scenario.file);
    let cover = match std::fs::read(&path) {
        Ok(b) => b,
        Err(err) => {
            return json!({ "id": cell_id, "status": "error", "error": err.to_string() });
        }
    };
    let embed_opts = EmbedOptions::default()
        .with_key(&FILE_KEY)
        .with_freshness(Freshness::Seeded(SEED))
        .with_tuning((scenario.tuning)());
    let extract_opts = ExtractOptions::default().with_key(&FILE_KEY);

    let mut write_ms = Vec::with_capacity(reps);
    let mut read_ms = Vec::with_capacity(reps);
    for _ in 0..reps {
        let (stego, w) = timed(|| {
            embed_carrier(&cover, &Payload::bytes(payload), &embed_opts).expect("embed failed")
        });
        let (data, r) = timed(|| extract_carrier(&stego, &extract_opts).expect("extract failed"));
        if data.as_slice() != payload {
            return json!({ "id": cell_id, "status": "fail", "error": "payload mismatch" });
        }
        write_ms.push(w);
        read_ms.push(r);
    }

    json!({
        "id": cell_id,
        "status": "ok",
        "carrier_id": scenario.id,
        "algorithm": scenario.algorithm,
        "payload_bytes": payload.len(),
        "reps": reps,
        "write": stats_json(&compute_stats(&write_ms), &write_ms),
        "read": stats_json(&compute_stats(&read_ms), &read_ms),
    })
}

/// Content-domain file API at one payload size (I/O + atomic commit overhead).
fn content_io_cell(
    dir: &Path,
    io_dir: &Path,
    scenario: &ContentScenario,
    payload: &[u8],
    reps: usize,
) -> Value {
    let cell_id = format!("content_io/{}", scenario.id);
    let src = dir.join(scenario.file);
    let out = io_dir.join(format!("out_{}", scenario.file));
    let level = resolve_level(
        &std::fs::read(&src).unwrap_or_default(),
        payload,
        (scenario.tuning)(),
    )
    .0;
    let embed_opts = embed_options((scenario.tuning)(), level);
    let extract_opts = ExtractOptions::default().with_password(PASSWORD);
    let target = FileTarget::new()
        .with_output_path(&out)
        .with_backup(false)
        .with_overwrite(true);

    let mut write_ms = Vec::with_capacity(reps);
    let mut read_ms = Vec::with_capacity(reps);
    for _ in 0..reps {
        let (res, wt) = timed(|| {
            embed_carrier_file(
                &src,
                &Payload::bytes(payload),
                &embed_opts,
                &StegoProfile::default(),
                &target,
            )
        });
        if let Err(err) = res {
            let _ = std::fs::remove_file(&out);
            return json!({ "id": cell_id, "status": "error",
                           "error": format!("embed_file: {err}") });
        }
        let (res, rt) =
            timed(|| extract_carrier_file_payload(&out, &extract_opts, &StegoProfile::default()));
        match res {
            Ok(p) => {
                if p.data.as_ref() != payload {
                    let _ = std::fs::remove_file(&out);
                    return json!({ "id": cell_id, "status": "fail", "error": "payload mismatch" });
                }
            }
            Err(err) => {
                let _ = std::fs::remove_file(&out);
                return json!({ "id": cell_id, "status": "error",
                               "error": format!("extract_file: {err}") });
            }
        }
        write_ms.push(wt);
        read_ms.push(rt);
    }
    let _ = std::fs::remove_file(&out);

    json!({
        "id": cell_id,
        "status": "ok",
        "carrier_id": scenario.id,
        "algorithm": scenario.algorithm,
        "payload_bytes": payload.len(),
        "reps": reps,
        "write": stats_json(&compute_stats(&write_ms), &write_ms),
        "read": stats_json(&compute_stats(&read_ms), &read_ms),
    })
}

/// Persist every completed cell, so an interrupted run still leaves usable
/// data. The final document overwrites this file when the run finishes.
fn checkpoint(out: &Path, domain: &str, cells: &[Value]) {
    let partial = json!({
        "schema": "strhide-perf-bench/1",
        "partial": true,
        "domain": domain,
        "cells": cells,
    });
    if let Ok(text) = serde_json::to_string_pretty(&partial) {
        let _ = std::fs::write(out.with_extension("partial.json"), text);
    }
}

// ── Runner ────────────────────────────────────────────────────────────────

struct Args {
    domain: String,
    reps: usize,
    warmup: usize,
    out: PathBuf,
    carriers: PathBuf,
    io: bool,
    only: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        domain: "all".into(),
        reps: 20,
        warmup: 2,
        out: PathBuf::from("../temp/bench/results/bench.json"),
        carriers: PathBuf::from("../temp/bench/carriers"),
        io: false,
        only: None,
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let value = |idx: usize| -> Result<String, String> {
            argv.get(idx + 1)
                .cloned()
                .ok_or_else(|| format!("{} needs a value", argv[idx]))
        };
        match argv[i].as_str() {
            "--domain" => {
                args.domain = value(i)?;
                i += 2;
            }
            "--reps" => {
                args.reps = value(i)?.parse().map_err(|e| format!("--reps: {e}"))?;
                i += 2;
            }
            "--warmup" => {
                args.warmup = value(i)?.parse().map_err(|e| format!("--warmup: {e}"))?;
                i += 2;
            }
            "--out" => {
                args.out = PathBuf::from(value(i)?);
                i += 2;
            }
            "--carriers" => {
                args.carriers = PathBuf::from(value(i)?);
                i += 2;
            }
            "--only" => {
                args.only = Some(value(i)?);
                i += 2;
            }
            "--io" => {
                args.io = true;
                i += 1;
            }
            "-h" | "--help" => {
                return Err(
                    "usage: perf_bench [--domain structure|content|all] [--reps N] \
                            [--warmup N] [--out FILE] [--carriers DIR] [--io] [--only ID]"
                        .into(),
                );
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(args)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };

    let io_dir = args
        .out
        .parent()
        .map(|p| p.join("io"))
        .unwrap_or_else(|| PathBuf::from("../temp/bench/io"));
    std::fs::create_dir_all(&io_dir)?;
    if let Some(parent) = args.out.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut payloads: HashMap<usize, Vec<u8>> = HashMap::new();
    for &size in STRUCTURE_SIZES.iter().chain(CONTENT_SIZES.iter()) {
        payloads.insert(size, payload_for(size));
    }

    let started = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut cells: Vec<Value> = Vec::new();

    let run_structure = args.domain == "structure" || args.domain == "all";
    let run_content = args.domain == "content" || args.domain == "all";

    if run_structure {
        for carrier in STRUCTURE_CARRIERS.iter() {
            for &size in STRUCTURE_SIZES.iter() {
                if let Some(only) = &args.only
                    && !format!("structure/{}", carrier.id).contains(only.as_str())
                {
                    continue;
                }
                let payload = &payloads[&size];
                eprintln!("[start] structure/{} @ {} B", carrier.id, size);
                let t0 = Instant::now();
                let cell = structure_cell(
                    &args.carriers,
                    carrier,
                    size,
                    payload,
                    args.reps,
                    args.warmup,
                );
                eprintln!(
                    "[structure]    {:<5} {:>9} B  {:<5}  {:.1}s",
                    carrier.id,
                    size,
                    cell["status"].as_str().unwrap_or("?"),
                    t0.elapsed().as_secs_f64()
                );
                cells.push(cell);
                checkpoint(&args.out, &args.domain, &cells);
            }
        }

        if args.io {
            let size = 256 * KIB;
            let payload = &payloads[&size];
            for carrier in STRUCTURE_CARRIERS.iter() {
                if let Some(only) = &args.only
                    && !format!("structure/{}", carrier.id).contains(only.as_str())
                {
                    continue;
                }
                let cell = structure_io_cell(&args.carriers, &io_dir, carrier, size, payload, 5);
                eprintln!(
                    "[structure-io] {:<5} {}",
                    carrier.id,
                    cell["status"].as_str().unwrap_or("?")
                );
                cells.push(cell);
                checkpoint(&args.out, &args.domain, &cells);
            }
        }

        // Compression cost, measured on one representative carrier.
        if args.only.is_none() || args.only.as_deref() == Some("png") {
            let cell =
                structure_compress_cell(&args.carriers, &STRUCTURE_CARRIERS[0], 4 * 1024 * 1024, 5);
            eprintln!(
                "[structure-compress] png  {}",
                cell["status"].as_str().unwrap_or("?")
            );
            cells.push(cell);
            checkpoint(&args.out, &args.domain, &cells);
        }
    }

    if run_content {
        for scenario in CONTENT_SCENARIOS.iter() {
            for &size in scenario.sizes.iter() {
                if let Some(only) = &args.only
                    && !format!("content/{}", scenario.id).contains(only.as_str())
                {
                    continue;
                }
                let payload = &payloads[&size];
                eprintln!("[start] content/{} @ {} B", scenario.id, size);
                let t0 = Instant::now();
                let cell = content_cell(
                    &args.carriers,
                    scenario,
                    size,
                    payload,
                    args.reps,
                    args.warmup,
                );
                eprintln!(
                    "[content]      {:<14} {:>7} B  {:<5}  {:.1}s",
                    scenario.id,
                    size,
                    cell["status"].as_str().unwrap_or("?"),
                    t0.elapsed().as_secs_f64()
                );
                cells.push(cell);
                checkpoint(&args.out, &args.domain, &cells);
            }

            if let Some(only) = &args.only
                && !format!("content/{}", scenario.id).contains(only.as_str())
            {
                continue;
            }

            // KDF split at the 8 KiB tier (5 samples, off the main table).
            let payload = &payloads[&(8 * KIB)];
            let cell = content_kdf_split(&args.carriers, scenario, payload, 5);
            eprintln!(
                "[content-kdf]  {:<14} {}",
                scenario.id,
                cell["status"].as_str().unwrap_or("?")
            );
            cells.push(cell);
            checkpoint(&args.out, &args.domain, &cells);

            if args.io {
                let payload = &payloads[&(32 * KIB)];
                let cell = content_io_cell(&args.carriers, &io_dir, scenario, payload, 5);
                eprintln!(
                    "[content-io]   {:<14} {}",
                    scenario.id,
                    cell["status"].as_str().unwrap_or("?")
                );
                cells.push(cell);
                checkpoint(&args.out, &args.domain, &cells);
            }
        }
    }

    let finished = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);

    let doc = json!({
        "schema": "strhide-perf-bench/1",
        "crate_version": env!("CARGO_PKG_VERSION"),
        "domain": args.domain,
        "reps": args.reps,
        "warmup": args.warmup,
        "started_unix": started,
        "finished_unix": finished,
        "available_parallelism": threads,
        "constants": {
            "password": PASSWORD,
            "seed_hex": "5eed000000000000000000000000000000000000000000000000000000000001",
            "payload_generator": "splitmix64(state=42, inc=0x9E3779B97F4A7C15)",
            "structure_sizes": STRUCTURE_SIZES,
            "content_sizes": CONTENT_SIZES,
        },
        "cells": cells,
    });

    std::fs::write(&args.out, serde_json::to_string_pretty(&doc)?)?;
    eprintln!("wrote {}", args.out.display());
    Ok(())
}
