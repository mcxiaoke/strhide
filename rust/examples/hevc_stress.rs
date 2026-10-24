// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Stability stress: embed / extract the same carrier+payload many times.
//!
//! The AES-GCM nonce is random, so every round exercises a different STC flip
//! pattern. Any `embed` error, length drift, payload mismatch or frame decode
//! failure is reported.
//!
//! ```text
//! cargo run --release --example hevc_stress -- ../temp/testhevc/IMG_7547.HEIC ../temp/testpayload/payload-16k.bin 40
//! ```

use std::fs;

use rust_h265::decoder::Decoder;
use rust_h265::nal::parse_nal;
use strhide::stego::hevc::heif_boxes::parse_heif_targets;
use strhide::stego::hevc::{embed_hevc, extract_hevc, probe_hevc_capacity};

fn frame_decodes(carrier: &[u8]) -> bool {
    let Ok(target) = parse_heif_targets(carrier) else {
        return false;
    };
    let mut decoder = Decoder::new();
    for ps in &target.parameter_sets {
        if let Some(unit) = parse_nal(ps) {
            let _ = decoder.decode_nal(&unit);
        }
    }
    for span in &target.slice_spans {
        if let Some(unit) = parse_nal(&carrier[span.start..span.end()])
            && let Ok(Some(frame)) = decoder.decode_nal(&unit)
            && frame.width > 0
            && frame.height > 0
        {
            return true;
        }
    }
    false
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let carrier_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "../temp/testhevc/IMG_7547.HEIC".into());
    let payload_path = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "../temp/testpayload/payload-16k.bin".into());
    let rounds: usize = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);

    let carrier = fs::read(&carrier_path)?;
    let payload = fs::read(&payload_path)?;
    let password = "StrHide-Matrix-Benchmark-Password#2026";
    let cap = probe_hevc_capacity(&carrier, &strhide::stego::format::DEFAULT_HEVC_FORMAT)?;
    println!(
        "{carrier_path} ({} B, cap {cap} B) <- {payload_path} ({} B) x {rounds}",
        carrier.len(),
        payload.len()
    );
    assert!(cap >= payload.len(), "payload exceeds capacity");

    let mut failures = 0usize;
    for round in 0..rounds {
        let stego = match embed_hevc(
            &carrier,
            &payload,
            Some(password),
            None,
            &strhide::stego::format::DEFAULT_HEVC_FORMAT,
            strhide::stego::Freshness::Random,
        ) {
            Ok(s) => s,
            Err(e) => {
                failures += 1;
                println!("  round {round}: EMBED FAILED: {e}");
                continue;
            }
        };
        if stego.len() != carrier.len() {
            failures += 1;
            println!(
                "  round {round}: LENGTH DRIFT {} -> {}",
                carrier.len(),
                stego.len()
            );
            continue;
        }
        match extract_hevc(
            &stego,
            Some(password),
            None,
            &strhide::stego::format::DEFAULT_HEVC_FORMAT,
        ) {
            Ok(got) if got == payload => {}
            Ok(got) => {
                failures += 1;
                println!(
                    "  round {round}: PAYLOAD MISMATCH ({} vs {} bytes)",
                    got.len(),
                    payload.len()
                );
                continue;
            }
            Err(e) => {
                failures += 1;
                println!("  round {round}: EXTRACT FAILED: {e}");
                continue;
            }
        }
        if !frame_decodes(&stego) {
            failures += 1;
            println!("  round {round}: FRAME DECODE FAILED");
            continue;
        }
        println!("  round {round}: ok");
    }
    println!("failures: {failures}/{rounds}");
    if failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}
