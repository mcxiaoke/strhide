// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Pure algorithmic benchmark for Syndrome Trellis Code (STC) kernel.
//!
//! Run with:
//! ```text
//! cargo test --release --test stc_perf -- --nocapture
//! ```

use std::time::Instant;
use strhide::stego::coding::{Move, StcTrellis};

#[test]
fn bench_stc_kernel_pure_performance() {
    let scenarios = [
        ("Small (4 KB payload, 64k slots, u=2)", 64_000, 2, 4096),
        (
            "Medium (32 KB payload, 500k slots, u=2)",
            500_000,
            2,
            32_768,
        ),
        (
            "Large (128 KB payload, 2M slots, u=2)",
            2_000_000,
            2,
            128_000,
        ),
        (
            "Massive (200 KB payload, 1.6M slots, u=1)",
            1_600_000,
            1,
            200_000,
        ),
    ];

    println!("\n================ STC KERNEL BENCHMARK ================");
    for &(name, n_slots, u, _payload_len) in &scenarios {
        let h = 8u8;
        let trellis = StcTrellis::from_seed_grouped(0x1234_5678, h, u).unwrap();
        let message_bits = trellis.message_bits(n_slots);
        let message = vec![0xAAu8; message_bits.div_ceil(8)];
        let vals = vec![128u8; n_slots];
        let moves = vec![Move::Both; n_slots];
        let mut deltas = vec![0i8; n_slots];

        let t0 = Instant::now();
        let _ = trellis
            .embed_with_cost_fn(&vals, &moves, |_| (1.0, 1.0), &message, &mut deltas)
            .unwrap();
        let elapsed = t0.elapsed();

        let throughput = (n_slots as f64 / 1_000_000.0) / elapsed.as_secs_f64();
        println!(
            "{:<42} | {:>7.2} ms | {:>6.2} Mslots/s",
            name,
            elapsed.as_secs_f64() * 1000.0,
            throughput
        );
    }
    println!("======================================================\n");
}
