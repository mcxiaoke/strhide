// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! J-UNIWARD as the second JPEG cost model.
//!
//! Two properties matter, and they are different in kind:
//!
//! 1. **It plugs in.** Selecting it by name must reach the engine, produce a
//!    valid carrier, and extract back. JPEG extraction is cost-free by design,
//!    so it must work without knowing the algorithm at all -- that is what makes
//!    a new JPEG model a purely additive change.
//! 2. **It is texture-adaptive.** The whole point of a wavelet-relative cost is
//!    that flat blocks cost more to change than busy ones. If that ordering is
//!    absent the model is just a slower UERD.

use std::time::Instant;

use strhide::core::payload::Payload;
use strhide::stego::jpeg::cost::{JuniwardCostModel, UerdCostModel};
use strhide::stego::jpeg::geometry::geometry_for_carrier;
use strhide::stego::traits::JpegCostModel;
use strhide::stego::{
    EmbedOptions, ExtractOptions, JpegAlgorithm, JpegParams, StegoTuning, embed_carrier,
    extract_carrier,
};

const COVER: &[u8] = include_bytes!("../assets/small.jpg");

fn payload() -> Vec<u8> {
    let mut out = Vec::with_capacity(2048);
    let mut state = 0x1234_abcd_u32;
    for _ in 0..2048 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.push((state >> 16) as u8);
    }
    out
}

fn options(algorithm: Option<&str>) -> EmbedOptions<'static> {
    EmbedOptions {
        tuning: match algorithm {
            None => StegoTuning::Auto,
            Some(name) => StegoTuning::Jpeg {
                model: JpegAlgorithm::from_name(name).expect("a known JPEG model"),
                params: JpegParams::default(),
            },
        },
        ..Default::default()
    }
}

#[test]
fn juniward_carrier_roundtrips_without_naming_the_algorithm() {
    let payload = payload();
    let stego = embed_carrier(COVER, &Payload::bytes(&payload), &options(Some("juniward")))
        .expect("embed with J-UNIWARD");
    assert_ne!(stego, COVER, "the carrier must change");

    // Extraction must not need the algorithm: the JPEG slot set is geometric
    // and keyed, so a new cost model cannot affect it.
    let back = extract_carrier(&stego, &ExtractOptions::default())
        .expect("extract without naming a model");
    assert_eq!(back, payload);
}

#[test]
fn juniward_leaves_the_cover_digest_and_dc_alone() {
    // The model must not embed into DC: the body slot grid excludes it, but a
    // cost model that priced DC as cheap could tempt a future rule change.
    let payload = payload();
    let stego =
        embed_carrier(COVER, &Payload::bytes(&payload), &options(Some("juniward"))).expect("embed");

    let before = dct_io::read_coefficients(COVER).expect("cover coefficients");
    let after = dct_io::read_coefficients(&stego).expect("stego coefficients");
    for (b, a) in before.components[0]
        .blocks
        .iter()
        .zip(after.components[0].blocks.iter())
    {
        assert_eq!(b[0], a[0], "DC must never change");
    }
}

/// Flat blocks must be more expensive to modify than busy ones.
///
/// Block energy is measured the way UERD does (sum of `|c| * Q` over AC), which
/// is an independent statistic from J-UNIWARD's wavelet residual -- so this is
/// not testing the model against itself.
#[test]
fn juniward_costs_more_in_flat_blocks() {
    let coeffs = dct_io::read_coefficients(COVER).expect("coefficients");
    let geometry =
        geometry_for_carrier(COVER, 0, coeffs.components[0].blocks.len()).expect("geometry");
    let params = JpegParams::default();

    let t0 = Instant::now();
    let costs = JuniwardCostModel.compute_cost(&coeffs, &geometry, &params);
    let elapsed = t0.elapsed();
    eprintln!(
        "J-UNIWARD cost over {} blocks took {:.3}s",
        coeffs.components[0].blocks.len(),
        elapsed.as_secs_f64()
    );

    let q: [f64; 64] = std::array::from_fn(|i| geometry.luma_q[i] as f64);
    let mut flat_sum = 0.0f64;
    let mut flat_n = 0usize;
    let mut busy_sum = 0.0f64;
    let mut busy_n = 0usize;

    for (bi, block) in coeffs.components[0].blocks.iter().enumerate() {
        let energy: f64 = (1..64).map(|k| (block[k].abs() & !1) as f64 * q[k]).sum();
        // Per-coefficient mean cost of this block, so block size cannot bias it.
        let mut block_cost = 0.0f64;
        for k in 1..64 {
            block_cost += costs[bi * 64 + k];
        }
        let mean = block_cost / 63.0;
        if energy == 0.0 {
            flat_sum += mean;
            flat_n += 1;
        } else if energy > 2000.0 {
            busy_sum += mean;
            busy_n += 1;
        }
    }

    assert!(flat_n > 50, "need flat blocks to compare, got {flat_n}");
    assert!(busy_n > 50, "need busy blocks to compare, got {busy_n}");
    let flat = flat_sum / flat_n as f64;
    let busy = busy_sum / busy_n as f64;
    eprintln!("flat mean cost {flat:.6e}, busy mean cost {busy:.6e}");
    assert!(
        flat > busy * 2.0,
        "flat blocks must be clearly more expensive (flat {flat:.3e}, busy {busy:.3e})"
    );
}

/// The two models must not rank the same blocks cheapest, otherwise adding
/// J-UNIWARD would buy nothing but a slower embed.
#[test]
fn juniward_and_uerd_disagree_about_where_to_embed() {
    let coeffs = dct_io::read_coefficients(COVER).expect("coefficients");
    let geometry =
        geometry_for_carrier(COVER, 0, coeffs.components[0].blocks.len()).expect("geometry");
    let params = JpegParams::default();

    let jw = JuniwardCostModel.compute_cost(&coeffs, &geometry, &params);
    let ue = UerdCostModel.compute_cost(&coeffs, &geometry, &params);
    assert_eq!(jw.len(), ue.len());

    // Compare the cheapest 10%: a real disagreement shows up as a low overlap.
    let n = jw.len();
    let k = n / 10;
    let mut jw_idx: Vec<usize> = (0..n).collect();
    let mut ue_idx: Vec<usize> = (0..n).collect();
    jw_idx.sort_unstable_by(|&a, &b| jw[a].total_cmp(&jw[b]));
    ue_idx.sort_unstable_by(|&a, &b| ue[a].total_cmp(&ue[b]));

    let jw_set: std::collections::HashSet<usize> = jw_idx[..k].iter().copied().collect();
    let overlap = ue_idx[..k].iter().filter(|i| jw_set.contains(i)).count();
    let ratio = overlap as f64 / k as f64;
    eprintln!(
        "cheapest-10% overlap between J-UNIWARD and UERD: {:.3}",
        ratio
    );
    assert!(
        ratio < 0.9,
        "the two models pick nearly the same slots ({ratio:.3}); the second model adds nothing"
    );
}
