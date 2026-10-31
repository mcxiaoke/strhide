// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! J-MiPOD as the third JPEG cost model.
//!
//! 1. **It plugs in.** Selecting it by name must reach the engine, produce a
//!    valid carrier, and extract back without naming the algorithm: JPEG
//!    extraction is cost-free by design, which is what makes a new JPEG model
//!    a purely additive change.
//! 2. **It is content-adaptive and DC-safe.** Flat blocks cost more than busy
//!    ones, and DC is never modified.

use strhide::core::payload::Payload;
use strhide::stego::jpeg::cost::JmipodCostModel;
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
fn jmipod_carrier_roundtrips_without_naming_the_algorithm() {
    let payload = payload();
    let stego = embed_carrier(COVER, &Payload::bytes(&payload), &options(Some("jmipod")))
        .expect("embed with J-MiPOD");
    assert_ne!(stego, COVER, "the carrier must change");

    let back = extract_carrier(&stego, &ExtractOptions::default())
        .expect("extract without naming a model");
    assert_eq!(back, payload);
}

#[test]
fn jmipod_leaves_dc_alone() {
    let payload = payload();
    let stego =
        embed_carrier(COVER, &Payload::bytes(&payload), &options(Some("jmipod"))).expect("embed");

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
/// Block energy is measured as `sum |c| * Q` over AC, an independent statistic
/// from J-MiPOD's propagated variance.
#[test]
fn jmipod_costs_more_in_flat_blocks() {
    let coeffs = dct_io::read_coefficients(COVER).expect("coefficients");
    let geometry =
        geometry_for_carrier(COVER, 0, coeffs.components[0].blocks.len()).expect("geometry");
    let params = JpegParams::default();
    let costs = JmipodCostModel.compute_cost(&coeffs, &geometry, &params);
    assert_eq!(costs.len(), coeffs.components[0].blocks.len() * 64);

    let q: [f64; 64] = std::array::from_fn(|i| geometry.luma_q[i] as f64);
    let mut flat_sum = 0.0f64;
    let mut flat_n = 0usize;
    let mut busy_sum = 0.0f64;
    let mut busy_n = 0usize;

    for (bi, block) in coeffs.components[0].blocks.iter().enumerate() {
        let energy: f64 = (1..64).map(|k| (block[k].abs() & !1) as f64 * q[k]).sum();
        let mean: f64 = (1..64).map(|k| costs[bi * 64 + k]).sum::<f64>() / 63.0;
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
    assert!(
        flat > busy * 2.0,
        "flat blocks must be clearly more expensive (flat {flat:.3e}, busy {busy:.3e})"
    );
}

/// Every AC coefficient must carry a finite, non-negative price and DC must be
/// priced wet (the engine also excludes it geometrically).
#[test]
fn jmipod_prices_all_ac_coefficients() {
    let coeffs = dct_io::read_coefficients(COVER).expect("coefficients");
    let geometry =
        geometry_for_carrier(COVER, 0, coeffs.components[0].blocks.len()).expect("geometry");
    let params = JpegParams::default();
    let costs = JmipodCostModel.compute_cost(&coeffs, &geometry, &params);
    for (bi, _) in coeffs.components[0].blocks.iter().enumerate() {
        assert_eq!(costs[bi * 64], params.wet_cost, "DC must be wet");
        for k in 1..64 {
            let c = costs[bi * 64 + k];
            assert!(c.is_finite() && c >= 0.0, "block {bi} k={k}: {c}");
            assert!(c < params.wet_cost, "AC coefficients must stay embeddable");
        }
    }
}
