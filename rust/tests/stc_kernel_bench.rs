// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Pure-function STC kernel benchmark: no JPEG, no CLI, no file I/O.
//!
//! One case = one full `u = 3` embed of a ~200 KB payload (4.8M slots, 256
//! states, ~2.45G trellis transitions), so a single run already averages over
//! billions of inner iterations. Each case is repeated `STRHIDE_BENCH_RUNS`
//! times after a discarded warm-up and reported as min / median / mean so a
//! busy machine cannot be mistaken for a regression.
//!
//! ```text
//! cargo test --release --test stc_kernel_bench -- --ignored --nocapture
//! ```
//!
//! Environment knobs:
//! * `STRHIDE_BENCH_BITS` — payload bits (default 1_600_000, ~200 KB)
//! * `STRHIDE_BENCH_RUNS` — timed repetitions (default 5)
//! * `STRHIDE_BENCH_U`    — group sizes, comma separated (default 3)

use std::time::Instant;
use strhide::stego::coding::{Move, StcTrellis};

/// SplitMix64: deterministic, identical on every host.
fn splitmix64(state: u64) -> u64 {
    let mut z = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// One synthetic embed workload, sized `n` elements.
struct Workload {
    vals: Vec<u8>,
    moves: Vec<Move>,
    rp: Vec<f64>,
    rm: Vec<f64>,
    message: Vec<u8>,
}

impl Workload {
    fn new(n: usize, bits: usize, seed: u64) -> Self {
        let mut s = seed;
        let mut next = || {
            s = splitmix64(s);
            s
        };
        let mut vals = Vec::with_capacity(n);
        let mut moves = Vec::with_capacity(n);
        let mut rp = Vec::with_capacity(n);
        let mut rm = Vec::with_capacity(n);
        for _ in 0..n {
            // Parity carrier exactly as the JPEG engine builds it: 2 or 3.
            vals.push(2 | (next() & 1) as u8);
            // Real carriers are a few percent one-directional (|c| = 1023 or an
            // over-optimised Huffman symbol).
            moves.push(match next() % 25 {
                0 => Move::PlusOnly,
                1 => Move::MinusOnly,
                _ => Move::Both,
            });
            // UERD-like cost spread: 0.02 .. 10, long tail towards cheap slots.
            let r = (next() % 1000) as f64 / 999.0;
            let base = 0.02 * (500.0f64).powf(r);
            rp.push(base);
            rm.push(base * 0.9);
        }
        let message: Vec<u8> = (0..bits.div_ceil(8))
            .map(|_| (next() & 0xFF) as u8)
            .collect();
        Self {
            vals,
            moves,
            rp,
            rm,
            message,
        }
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_list_u(name: &str, default: &[u8]) -> Vec<u8> {
    match std::env::var(name) {
        Ok(v) => v
            .split(',')
            .filter_map(|t| t.trim().parse::<u8>().ok())
            .collect(),
        Err(_) => default.to_vec(),
    }
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let k = s.len() / 2;
    if s.len().is_multiple_of(2) {
        (s[k - 1] + s[k]) / 2.0
    } else {
        s[k]
    }
}

#[test]
#[ignore = "benchmark: run explicitly with --release --ignored --nocapture"]
fn bench_stc_kernel() {
    let bits = env_usize("STRHIDE_BENCH_BITS", 1_600_000);
    let runs = env_usize("STRHIDE_BENCH_RUNS", 5).max(1);
    let us = env_list_u("STRHIDE_BENCH_U", &[3]);
    let h = 8u8;

    println!(
        "\n=== STC kernel: {bits} payload bits ({:.1} KB), h={h}, {runs} timed runs ===",
        bits as f64 / 8.0 / 1024.0
    );

    for &u in &us {
        let trellis = StcTrellis::from_seed_grouped(0x5EED_1234, h, u).unwrap();
        let n = u as usize * (bits + h as usize - 1);
        let w = Workload::new(n, bits, 0xC0FF_EE00 ^ u as u64);
        let mut deltas = vec![0i8; n];
        let states = 1usize << ((h as usize - 1) + usize::from(u > 1));
        let transitions = n as f64 * states as f64 * 2.0;

        // Discarded warm-up: first touch of `deltas`, page faults, caches.
        let flips = trellis
            .embed_with_deltas(&w.vals, &w.moves, &w.rp, &w.rm, &w.message, &mut deltas)
            .unwrap();

        let distortion: f64 = deltas
            .iter()
            .enumerate()
            .map(|(j, &d)| match d {
                0 => 0.0,
                d if d > 0 => w.rp[j],
                _ => w.rm[j],
            })
            .sum();

        // Verify the syndrome once: a faster kernel must stay correct.
        let mut stego = w.vals.clone();
        for (v, &d) in stego.iter_mut().zip(deltas.iter()) {
            *v = (*v as i16 + d as i16) as u8;
        }
        let ok = trellis
            .extract(&stego, bits)
            .iter()
            .zip(w.message.iter())
            .all(|(a, b)| a == b);

        let mut times = Vec::with_capacity(runs);
        for _ in 0..runs {
            let t0 = Instant::now();
            let f = trellis
                .embed_with_deltas(&w.vals, &w.moves, &w.rp, &w.rm, &w.message, &mut deltas)
                .unwrap();
            times.push(t0.elapsed().as_secs_f64() * 1000.0);
            assert_eq!(f, flips, "flip count must be deterministic");
        }

        let min = times.iter().cloned().fold(f64::INFINITY, f64::min);
        let med = median(&times);
        let mean = times.iter().sum::<f64>() / times.len() as f64;
        let var = times.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / times.len() as f64;

        println!("\nu={u}  slots={n}  states={states}  transitions={transitions:.3e}");
        println!(
            "  runs(ms) : {}",
            times
                .iter()
                .map(|t| format!("{t:.0}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!(
            "  min {min:.0} | median {med:.0} | mean {mean:.0} +- {:.1} (cv {:.1}%)",
            var.sqrt(),
            var.sqrt() / mean * 100.0
        );
        println!(
            "  median: {:.2} Mslot/s, {:.3} ns/transition, {:.3} ns/bit",
            n as f64 / (med / 1000.0) / 1e6,
            med * 1e6 / transitions,
            med * 1e6 / bits as f64
        );
        println!(
            "  quality : {:.4} flips/bit, {:.5} distortion/bit, roundtrip {}",
            flips as f64 / bits as f64,
            distortion / bits as f64,
            if ok { "ok" } else { "FAIL" }
        );
        assert!(ok, "u={u}: syndrome mismatch");
    }
    println!();
}

/// Fisher-Yates cost on the grid size a 24 MP carrier produces.
#[test]
#[ignore = "benchmark: run explicitly with --release --ignored --nocapture"]
fn bench_permute_full_grid() {
    let n = env_usize("STRHIDE_BENCH_GRID", 23_600_000);
    let runs = env_usize("STRHIDE_BENCH_RUNS", 5).max(1);
    let seed = [0x42u8; 32];
    let mut times = Vec::with_capacity(runs);
    for _ in 0..=runs {
        let mut idx: Vec<u32> = (0..n as u32).collect();
        let t0 = Instant::now();
        strhide::stego::prng::permute_indices(&mut idx, &seed);
        times.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    times.remove(0); // warm-up
    let med = median(&times);
    println!(
        "\n=== Permute {n} indices ===\n  runs(ms) : {}\n  min {:.0} | median {med:.0} | {:.1} Mindex/s (median)\n",
        times
            .iter()
            .map(|t| format!("{t:.0}"))
            .collect::<Vec<_>>()
            .join(", "),
        times.iter().cloned().fold(f64::INFINITY, f64::min),
        n as f64 / (med / 1000.0) / 1e6
    );
}
