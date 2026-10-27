// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Compare the matrix-coding layers on a real carrier.
//!
//! The review asked for four numbers before STC is ever allowed to become the
//! default (see `docs/stc_coding_design_20261021.md`): change count,
//! cost-weighted distortion, detection score and wall-clock time. This binary
//! produces the first two and the timing; the detection score comes from
//! `strhide scan` on the files it writes.
//!
//! ```text
//! cargo run --release --example codec_bench -- carrier.png payload.bin [password]
//! ```
//!
//! Every run uses the same payload, password and carrier, so the only
//! difference is the coding layer. Hamming is what production does today, which
//! makes it the baseline the STC rows have to beat. The STC rows differ only in
//! the group size `u` (elements per syndrome row).

use std::time::Instant;

use strhide::core::control::Control;
use strhide::stego::params::{PngParams, StegoCodec};
use strhide::stego::png::cost::HillCostModel;
use strhide::stego::png::engine::{decode_png, embed_png, extract_png};
use strhide::stego::traits::PngCostModel;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let carrier_path = args
        .get(1)
        .ok_or("usage: codec_bench <carrier.png> <payload-file> [password]")?;
    let payload_path = args
        .get(2)
        .ok_or("usage: codec_bench <carrier.png> <payload-file> [password]")?;
    let password = args.get(3).map(String::as_str);

    let carrier = std::fs::read(carrier_path)?;
    let payload = std::fs::read(payload_path)?;
    let image = decode_png(&carrier)?;
    let w = image.width as usize;
    let h = image.height as usize;
    let channel_offset = if image.channels >= 3 { 1 } else { 0 };

    // The cost map is the one HILL assigns to the *cover*; it is what every
    // codec uses, so summing it over the modified slots is an apples-to-apples
    // distortion number.
    let costs =
        HillCostModel.compute_cost(&image.pixels, w, h, image.channels, &PngParams::default());

    println!(
        "carrier: {carrier_path} ({}x{}, {} channels), payload: {} bytes ({} bits)",
        image.width,
        image.height,
        image.channels,
        payload.len(),
        payload.len() * 8
    );
    println!(
        "{:<10} {:>3} {:>8} {:>10} {:>14} {:>8} {:>7} {:>5}",
        "codec", "u", "flips", "flips/bit", "sum(rho)", "rho/bit", "ms", "bytes"
    );

    let mut runs: Vec<(String, u8)> = vec![("Hamming".into(), 0)];
    for u in 1..=3u8 {
        runs.push(("Stc".into(), u));
    }

    for (codec, u) in runs {
        let params = PngParams {
            codec: if codec == "Stc" {
                StegoCodec::Stc
            } else {
                StegoCodec::Hamming
            },
            stc_u: u.max(1),
            ..PngParams::default()
        };
        let started = Instant::now();
        let stego = match embed_png(
            &carrier,
            &payload,
            password,
            None,
            &strhide::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            strhide::stego::SafetyPolicy::default(),
            strhide::stego::Freshness::Random,
            &Control::none(),
        ) {
            Ok(s) => s,
            Err(e) => {
                println!("{codec:<10} {u:>3}   -- {e}");
                continue;
            }
        };
        let elapsed = started.elapsed();

        let after = decode_png(&stego)?;
        let (mut flips, mut weighted) = (0usize, 0.0f64);
        for y in 0..h {
            for x in 0..w {
                let idx = y * w + x;
                let at = idx * image.channels + channel_offset;
                if image.pixels[at] != after.pixels[at] {
                    flips += 1;
                    weighted += costs[idx];
                }
            }
        }

        let recovered = extract_png(
            &stego,
            password,
            None,
            &strhide::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &PngParams::default(),
            &Control::none(),
        )?;
        let ok = recovered == payload;
        let bits = payload.len() * 8;

        println!(
            "{:<10} {:>3} {:>8} {:>10.4} {:>14.3e} {:>8.4} {:>7} {:>5}{}",
            codec,
            u,
            flips,
            flips as f64 / bits as f64,
            weighted,
            weighted / bits as f64,
            elapsed.as_millis(),
            stego.len(),
            if ok { "" } else { "  EXTRACT FAILED" }
        );

        let out = format!("codec-bench-{}-u{u}.png", codec.to_lowercase());
        std::fs::write(&out, &stego)?;
        println!("           -> {out}");
    }

    Ok(())
}
