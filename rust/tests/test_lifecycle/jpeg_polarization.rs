// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Cost polarization (`JpegParams::polarize_weight`) end-to-end behaviour.
//!
//! Two things have to hold:
//!
//! 1. **Correctness** -- the polarization path is embed-side only, so turning it
//!    on must not disturb extraction. The carrier must still round-trip.
//! 2. **Effect** -- the point of the feature is that moves go *towards* the
//!    precover estimate. If turning it on did not shift the move distribution,
//!    the feature would be dead code that still costs a decompress-denoise-
//!    recompress round trip.
//!
//! The second check is statistical, not exact: every embed draws a fresh random
//! salt, so slot sets differ between runs and a per-coefficient comparison is
//! meaningless. Aggregated over the whole payload the sign of the shift is well
//! defined.

use strhide::stego::StegoOptions;
use strhide::stego::jpeg::cost::precover;
use strhide::stego::jpeg::geometry::geometry_for_carrier;
use strhide::stego::{embed_carrier, extract_carrier};

const COVER: &[u8] = include_bytes!("../assets/small.jpg");

/// 4 KiB of deterministic, poorly compressible payload: large enough that the
/// move counts carry a signal, small enough to stay well inside capacity.
fn payload() -> Vec<u8> {
    let mut out = Vec::with_capacity(4096);
    let mut state = 0x5eed_1234u32;
    for _ in 0..4096 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.push((state >> 16) as u8);
    }
    out
}

fn options(polarize_weight: f64) -> StegoOptions {
    let mut opts = StegoOptions::default();
    opts.jpeg_params.polarize_weight = polarize_weight;
    opts
}

/// Aggregate move statistics of one embed, measured against the cover's bias.
struct MoveStats {
    toward: usize,
    away: usize,
}

impl MoveStats {
    fn fraction(&self) -> f64 {
        let total = self.toward + self.away;
        if total == 0 {
            0.0
        } else {
            self.toward as f64 / total as f64
        }
    }
}

/// Count, over every coefficient that moved, whether the move followed the bias.
fn measure(cover: &[u8], stego: &[u8]) -> MoveStats {
    let cover_coeffs = dct_io::read_coefficients(cover).expect("read cover");
    let stego_coeffs = dct_io::read_coefficients(stego).expect("read stego");
    let geometry = geometry_for_carrier(cover, 0, cover_coeffs.components[0].blocks.len())
        .expect("cover geometry");
    let bias = precover::bias(&cover_coeffs, &geometry, 0.0).expect("bias");

    let mut stats = MoveStats { toward: 0, away: 0 };
    for (bi, (a, b)) in cover_coeffs.components[0]
        .blocks
        .iter()
        .zip(stego_coeffs.components[0].blocks.iter())
        .enumerate()
    {
        for k in 1..64 {
            let delta = b[k] as i32 - a[k] as i32;
            if delta == 0 {
                continue;
            }
            let sign = bias[bi * 64 + k];
            if sign == 0 {
                continue;
            }
            if (delta > 0) == (sign > 0) {
                stats.toward += 1;
            } else {
                stats.away += 1;
            }
        }
    }
    stats
}

#[test]
fn polarized_embed_still_roundtrips() {
    let payload = payload();
    let opts = options(0.65);
    let stego = embed_carrier(COVER, &payload, &opts).expect("polarized embed");
    assert_ne!(stego, COVER, "the carrier must change");
    let back = extract_carrier(&stego, &opts).expect("extract");
    assert_eq!(back, payload, "polarization is embed-side only");
}

#[test]
fn polarization_shifts_moves_towards_the_estimate() {
    let payload = payload();

    let plain = embed_carrier(COVER, &payload, &options(1.0)).expect("symmetric embed");
    let polarized = embed_carrier(COVER, &payload, &options(0.65)).expect("polarized embed");

    let baseline = measure(COVER, &plain);
    let treated = measure(COVER, &polarized);

    eprintln!(
        "moves towards the precover estimate: symmetric {:.4} ({} / {}), polarized {:.4} ({} / {})",
        baseline.fraction(),
        baseline.toward,
        baseline.toward + baseline.away,
        treated.fraction(),
        treated.toward,
        treated.toward + treated.away
    );

    assert!(
        baseline.toward + baseline.away > 1000,
        "need a meaningful number of moves, got {}",
        baseline.toward + baseline.away
    );
    assert!(
        treated.toward + treated.away > 1000,
        "need a meaningful number of moves, got {}",
        treated.toward + treated.away
    );

    assert!(
        treated.fraction() > baseline.fraction(),
        "polarization must raise the share of moves that follow the precover estimate \
         (symmetric {:.4}, polarized {:.4})",
        baseline.fraction(),
        treated.fraction()
    );
    assert!(
        treated.fraction() > 0.5,
        "polarized moves should lean towards the estimate, got {:.4}",
        treated.fraction()
    );
}

#[test]
fn polarization_is_disabled_by_default() {
    // The documented default is 1.0 = off. If it silently became something else,
    // every JPEG embed would start paying for the precover round trip.
    assert_eq!(
        strhide::stego::params::JpegParams::default().polarize_weight,
        1.0
    );
}

#[test]
fn weight_above_one_is_rejected() {
    // Above 1 the weight would penalize the preferred direction, inverting the
    // setting's meaning. It must fail loudly instead.
    let opts = options(1.5);
    let err = embed_carrier(COVER, b"x", &opts).expect_err("weight 1.5 must be rejected");
    assert!(
        err.to_string().contains("polarize_weight"),
        "error should name the parameter, got: {err}"
    );
}
