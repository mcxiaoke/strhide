// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! A PNG carrier must be able to name its own cost model.
//!
//! The header used to be placed on the *cost-ranked* candidate set, so finding
//! it required already knowing which algorithm wrote the body -- while the
//! algorithm was not stored anywhere in the carrier. Extraction therefore
//! depended on an out-of-band choice, and "pluggable spatial algorithms" was
//! only a compile-time property.
//!
//! The fix has two halves, pinned separately here:
//!
//! 1. the header layout is a pure function of pixels + credentials (cost-free),
//!    so it can be read before the model is known;
//! 2. the feature word carries the model's wire id, and extraction follows the
//!    carrier's declaration rather than the caller's guess.

use strhide::stego::png::engine::{SPATIAL_ELIGIBLE_MAX, SPATIAL_ELIGIBLE_MIN};
use strhide::stego::png::{RawImage, decode_png, encode_png};
use strhide::stego::registry::CostModelRegistry;
use strhide::stego::traits::PngCostModel;
use strhide::stego::{PngParams, StegoOptions, embed_carrier, extract_carrier};

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
    encode_png(&RawImage {
        width: w,
        height: h,
        channels: 3,
        pixels,
        chunks: Vec::new(),
        idat_sizes: Vec::new(),
        row_filters: Vec::new(),
        idat_info: None,
    })
    .expect("encode png")
}

/// Recompute the header layout from first principles -- eligible pixels in
/// ascending order, keyed permutation, no cost map anywhere. Independent of the
/// engine so the test can catch a regression rather than follow it.
fn cost_free_header_slots(png: &[u8]) -> Vec<usize> {
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
    eligible[..strhide::stego::header::V2_TOTAL_HEADER_SLOTS].to_vec()
}

fn read_feature_word(png: &[u8]) -> strhide::stego::header::FeatureWord {
    let img = decode_png(png).expect("decode png");
    let ch = img.channels;
    let off = if ch >= 3 { 1 } else { 0 };
    let slots = cost_free_header_slots(png);
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

/// A model that is wrong on purpose: a flat cost map (so a different ranking)
/// and a different identity. If the extractor preferred the caller's model over
/// the carrier's declaration, extraction would desynchronise and fail.
struct ImpostorModel;

impl PngCostModel for ImpostorModel {
    fn id(&self) -> &'static str {
        "impostor"
    }

    fn description(&self) -> &'static str {
        "deliberately wrong cost model"
    }

    fn compute_cost(
        &self,
        _pixels: &[u8],
        width: usize,
        height: usize,
        _channels: usize,
        _params: &PngParams,
    ) -> Vec<f64> {
        vec![1.0f64; width * height]
    }
}

#[test]
fn the_carrier_declares_which_model_wrote_it() {
    let png = texture_png(96, 96);
    let stego = embed_carrier(&png, b"self-describing", &StegoOptions::default()).expect("embed");

    let fw = read_feature_word(&stego);
    assert_eq!(
        CostModelRegistry::spatial_name_from_wire_id(fw.algorithm_id),
        Some("hill"),
        "the feature word must name the model that wrote the body"
    );
}

#[test]
fn extraction_follows_the_carrier_not_the_caller() {
    let png = texture_png(96, 96);
    let payload = b"the declaration wins over the caller";
    let stego = embed_carrier(&png, payload, &StegoOptions::default()).expect("embed");

    // The caller asks for a model that has nothing to do with this carrier.
    let got = strhide::stego::png::engine::extract_png(
        &stego,
        None,
        None,
        &strhide::stego::format::OFFICIAL_PNG_FORMAT,
        &ImpostorModel,
        &PngParams::default(),
    )
    .expect("extraction must use the carrier's declared model");
    assert_eq!(got, payload);
}

#[test]
fn unknown_algorithm_id_is_reported_as_no_payload() {
    // An id this build does not know means "written by a newer tool". It must
    // collapse into the same generic failure as a wrong password instead of
    // falling back to the default model and decoding noise.
    assert!(CostModelRegistry::spatial_model_from_wire_id(0).is_none());
    assert!(CostModelRegistry::spatial_model_from_wire_id(200).is_none());
}

/// The real payoff: write with a non-default model, read back with nothing
/// declared. Without the header carrying the algorithm id this is impossible --
/// the extractor would rank slots with HILL's cost map and desynchronise.
#[test]
fn a_suniward_carrier_extracts_while_the_caller_defaults_to_hill() {
    let png = texture_png(96, 96);
    let payload = b"written by suniward, read by hill defaults";

    let write = StegoOptions {
        algorithm: Some("suniward".into()),
        ..Default::default()
    };
    let stego = embed_carrier(&png, payload, &write).expect("embed with S-UNIWARD");

    let fw = read_feature_word(&stego);
    assert_eq!(
        CostModelRegistry::spatial_name_from_wire_id(fw.algorithm_id),
        Some("suniward"),
        "the carrier must declare the model that actually wrote it"
    );

    // Extraction with the default options: `algorithm` is None, so the caller
    // offers HILL. The carrier's declaration must win.
    let got = extract_carrier(&stego, &StegoOptions::default())
        .expect("extraction must follow the carrier, not the default model");
    assert_eq!(got, payload);

    // And naming a *different* model explicitly must not change the outcome.
    let read = StegoOptions {
        algorithm: Some("hill".into()),
        ..Default::default()
    };
    assert_eq!(
        extract_carrier(&stego, &read).expect("explicit hill"),
        payload
    );
}

#[test]
fn non_default_exclusion_rate_extracts_with_default_options() {
    let png = texture_png(96, 96);
    let payload = b"written with non-default exclusion rate 0.45";

    let write = StegoOptions {
        png_params: PngParams {
            exclusion_percentile: 0.45,
            ..Default::default()
        },
        ..Default::default()
    };
    let stego = embed_carrier(&png, payload, &write).expect("embed with exclusion rate 0.45");

    let fw = read_feature_word(&stego);
    assert_eq!(fw.exclusion_permille, 450);

    // Extraction with default options (exclusion_percentile = 0.30).
    // The self-describing exclusion_permille must be respected so slot ranking synchronises.
    let got = extract_carrier(&stego, &StegoOptions::default())
        .expect("extraction must use carrier's exclusion_permille");
    assert_eq!(got, payload);
}
