// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Compare the two matrix-coding layers on a real carrier.
//!
//! The review asked for four numbers before STC is ever allowed to become the
//! default (see `docs/stc_coding_design_20261021.md` §8.5): change count,
//! cost-weighted distortion, detection score and wall-clock time. This binary
//! produces the first two and the timing; the detection score comes from
//! `strhide scan` on the files it writes.
//!
//! ```text
//! cargo run --release --example codec_bench -- carrier.png payload.bin
//! ```
//!
//! Both embeds use the same payload, password and carrier, so the only
//! difference is the coding layer. The Hamming run is what production does
//! today, which makes it the baseline the STC numbers have to beat.

use std::time::Instant;

use strhide::stego::params::{SpatialParams, StegoCodec};
use strhide::stego::spatial::cost::HillCostModel;
use strhide::stego::spatial::engine::{decode_png, embed_spatial, extract_spatial};
use strhide::stego::traits::SpatialCostModel;

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

    // The cost map is the one HILL assigns to the *cover*; it is what both
    // codecs use, so summing it over the modified slots is an apples-to-apples
    // distortion number.
    let costs = HillCostModel.compute_cost(
        &image.pixels,
        w,
        h,
        image.channels,
        &SpatialParams::default(),
    );

    println!(
        "carrier: {carrier_path} ({}x{}, {} channels), payload: {} bytes",
        image.width,
        image.height,
        image.channels,
        payload.len()
    );
    println!(
        "{:<8} {:>8} {:>10} {:>14} {:>10} {:>6}",
        "codec", "flips", "ok", "sum(rho)", "ms", "bytes"
    );

    for codec in [StegoCodec::Hamming, StegoCodec::Stc] {
        let params = SpatialParams {
            codec,
            ..SpatialParams::default()
        };
        let started = Instant::now();
        let stego = embed_spatial(&carrier, &payload, password, &HillCostModel, &params)?;
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

        let recovered =
            extract_spatial(&stego, password, &HillCostModel, &SpatialParams::default())?;
        let ok = recovered == payload;

        println!(
            "{:<8} {:>8} {:>10} {:>14.2} {:>10} {:>6}",
            format!("{codec:?}"),
            flips,
            if ok { "yes" } else { "NO" },
            weighted,
            elapsed.as_millis(),
            stego.len()
        );

        let out = format!("codec-bench-{}.png", format!("{codec:?}").to_lowercase());
        std::fs::write(&out, &stego)?;
        println!("         -> {out}");
    }

    Ok(())
}
