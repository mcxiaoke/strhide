// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! MiPOD as the third spatial cost model.
//!
//! Two properties matter:
//!
//! 1. **It plugs in.** Selecting it by name must reach the engine, produce a
//!    valid carrier whose feature word declares `mipod`, and extract back
//!    through the default options.
//! 2. **It is content-adaptive.** Flat regions must cost clearly more than
//!    textured ones, or the model is just a slower HILL.

use strhide::core::payload::Payload;
use strhide::stego::{
    EmbedOptions, ExtractOptions, PngParams, SpatialAlgorithm, StegoTuning, embed_carrier,
    extract_carrier,
};

/// Deterministic high-frequency texture, so the carrier is embeddable.
fn texture_png(w: u32, h: u32) -> Vec<u8> {
    let mut pixels = Vec::with_capacity((w * h * 3) as usize);
    for y in 0..h {
        for x in 0..w {
            pixels.push(((x * 17) ^ (y * 31) ^ ((x + y) * 7)) as u8);
            pixels.push(((x * 23 + y * 19) % 256) as u8);
            pixels.push(((x * 13) ^ (y * 29)) as u8);
        }
    }
    strhide::stego::png::encode_png(&strhide::stego::png::RawImage {
        width: w,
        height: h,
        channels: 3,
        pixels,
        chunks: Vec::new(),
        idat_sizes: Vec::new(),
        row_filters: Vec::new(),
        idat_info: None,
        tail: Vec::new(),
    })
    .expect("encode png")
}

fn payload() -> Vec<u8> {
    let mut out = Vec::with_capacity(1024);
    let mut state = 0x1234_abcd_u32;
    for _ in 0..1024 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.push((state >> 16) as u8);
    }
    out
}

fn mipod_options() -> EmbedOptions<'static> {
    EmbedOptions {
        tuning: StegoTuning::Png {
            model: SpatialAlgorithm::Mipod,
            params: PngParams::default(),
        },
        ..Default::default()
    }
}

/// Read the feature word through the same cost-free header layout the
/// extractor uses.
fn read_feature_word(png: &[u8]) -> strhide::stego::header::FeatureWord {
    use strhide::stego::png::decode_png;
    use strhide::stego::png::engine::{SPATIAL_ELIGIBLE_MAX, SPATIAL_ELIGIBLE_MIN};

    let img = decode_png(png).expect("decode png");
    let (w, h, ch) = (img.width as usize, img.height as usize, img.channels);
    let off = if ch >= 3 { 1 } else { 0 };
    let mut eligible: Vec<usize> = (0..w * h)
        .filter(|&i| {
            (SPATIAL_ELIGIBLE_MIN..=SPATIAL_ELIGIBLE_MAX).contains(&img.pixels[i * ch + off])
        })
        .collect();
    strhide::stego::prng::permute_prefix(
        &mut eligible,
        strhide::stego::header::V2_TOTAL_HEADER_SLOTS,
        &strhide::stego::envelope::derive_header_perm_seed(None, None),
    );
    let slots = &eligible[..strhide::stego::header::V2_TOTAL_HEADER_SLOTS];
    let mut bytes = [0u8; 32];
    for (byte_i, slot) in bytes.iter_mut().zip(slots[256..512].chunks(8)) {
        let mut b = 0u8;
        for &s in slot {
            b = (b << 1) | (img.pixels[s * ch + off] & 1);
        }
        *byte_i = b;
    }
    strhide::stego::header::FeatureWord::decode(&bytes).expect("decode feature word")
}

#[test]
fn mipod_carrier_roundtrips_and_declares_itself() {
    let png = texture_png(96, 96);
    let payload = payload();
    let stego =
        embed_carrier(&png, &Payload::bytes(&payload), &mipod_options()).expect("embed with MiPOD");
    assert_ne!(stego, png, "the carrier must change");

    let fw = read_feature_word(&stego);
    assert_eq!(
        strhide::stego::png::registry::spatial_name_from_wire_id(fw.algorithm_id),
        Some("mipod"),
        "the carrier must declare the model that actually wrote it"
    );

    // Extraction must follow the carrier's declaration, not the caller's guess.
    let back = extract_carrier(&stego, &ExtractOptions::default()).expect("extract");
    assert_eq!(back, payload);
}

#[test]
fn mipod_cost_map_separates_flat_from_textured_regions() {
    use strhide::stego::png::cost::MipodCostModel;
    use strhide::stego::traits::PngCostModel;

    let (w, h) = (32usize, 32usize);
    let mut pixels = vec![128u8; w * h];
    for y in 0..h {
        for x in w / 2..w {
            pixels[y * w + x] = if (x + y) % 2 == 0 { 200 } else { 56 };
        }
    }
    let costs = MipodCostModel.compute_cost(&pixels, w, h, 1, &PngParams::default());
    let flat = costs[16 * w + 4];
    let textured = costs[16 * w + 24];
    assert!(
        flat > textured * 2.0,
        "flat region cost ({flat}) must clearly exceed textured ({textured})"
    );
}
