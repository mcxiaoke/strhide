// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Temporary diagnostic: where do HEVC carrier slots actually go?
//!
//! Decodes every VCL NAL of a carrier with the observer attached (no frame-type
//! gate, no dedup) and reports slot counts per `nal_unit_type`, plus how many
//! slots the engine's own rules (Tier A gate, EPB-prone substream exclusion)
//! would drop. Read-only; used to size the capacity gap between video and still
//! carriers.
//!
//! ```text
//! cargo run --release --example hevc_capacity_diag -- <carrier> [...]
//! ```

use std::collections::BTreeMap;
use std::time::Instant;

use rusty_h265::Decoder;
use rusty_h265::ctu::Ablate;
use strhide::stego::hevc::heif_boxes::parse_heif_targets;
use strhide::stego::hevc::mp4_boxes::parse_mp4_targets;
use strhide::stego::hevc::slot::{BinOp, CabacRecorder};
use strhide::stego::hevc::sniff::{
    HevcCarrierKind, NAL_RADL_N, NAL_RASL_N, NAL_STSA_N, NAL_TRAIL_N, NAL_TSA_N, sniff_hevc_carrier,
};

fn is_non_reference_vcl(nal_type: u8) -> bool {
    matches!(
        nal_type,
        NAL_TRAIL_N | NAL_TSA_N | NAL_STSA_N | NAL_RADL_N | NAL_RASL_N
    )
}

fn drain_frames(decoder: &mut Decoder) {
    while decoder.next_frame().is_ok() {}
}

#[derive(Default, Clone, Copy)]
struct Stat {
    slices: usize,
    bytes: usize,
    sign_slots: usize,
    sign_slots_absorbed: usize,
    decision_bins: usize,
    bypass_other: usize,
    substreams: usize,
    excluded_subs: usize,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: hevc_capacity_diag <carrier> [...]");
        std::process::exit(2);
    }
    for path in &args {
        diag(path);
    }
}

fn diag(path: &str) {
    let carrier = std::fs::read(path).expect("read carrier");
    let kind = sniff_hevc_carrier(&carrier).expect("sniff carrier");
    let (parameter_sets, slice_spans) = match kind {
        HevcCarrierKind::Mp4Container => {
            let t = parse_mp4_targets(&carrier).expect("parse mp4");
            (t.parameter_sets, t.slice_spans)
        }
        HevcCarrierKind::HeifContainer => {
            let t = parse_heif_targets(&carrier).expect("parse heif");
            (t.parameter_sets, t.slice_spans)
        }
        HevcCarrierKind::AnnexBStream => {
            eprintln!("{path}: only MP4/HEIF containers are supported by this probe");
            return;
        }
    };

    let t0 = Instant::now();
    let mut decoder = Decoder::new();
    decoder.ablate = Ablate {
        mc: true,
        intra: true,
        residual: true,
    };
    for ps in &parameter_sets {
        let _ = decoder.push_nal(ps, None);
    }

    let mut per_type: BTreeMap<u8, Stat> = BTreeMap::new();
    let mut skipped = 0usize;
    let mut failures = 0usize;

    for span in &slice_spans {
        let slice_bytes = &carrier[span.start..span.end()];
        if slice_bytes.len() < 2 {
            continue;
        }
        let nal_type = (slice_bytes[0] >> 1) & 0x3F;
        let mut rec = CabacRecorder::with_slice(0, 0);
        match decoder.decode_nal_with_observer(slice_bytes, &mut rec) {
            Err(_) => {
                failures += 1;
                drain_frames(&mut decoder);
                continue;
            }
            Ok(_) if rec.substreams.is_empty() => {
                skipped += 1;
                drain_frames(&mut decoder);
                continue;
            }
            Ok(_) => {}
        }
        drain_frames(&mut decoder);

        let rbsp = rusty_h265::nal::unescape(&slice_bytes[2..]).data;
        let mut excluded = Vec::new();
        if rec.substreams.len() > 1 {
            for sub in &rec.substreams {
                if sub.rbsp_byte_start <= sub.rbsp_byte_end
                    && sub.rbsp_byte_end <= rbsp.len()
                    && rbsp[sub.rbsp_byte_start..sub.rbsp_byte_end]
                        .windows(3)
                        .any(|w| w[0] == 0 && w[1] == 0 && w[2] <= 3)
                {
                    excluded.push(sub.substream_idx);
                }
            }
        }
        let absorbed = rec
            .slots
            .iter()
            .filter(|s| !excluded.contains(&s.substream_idx))
            .count();

        let e = per_type.entry(nal_type).or_default();
        e.slices += 1;
        e.bytes += slice_bytes.len();
        e.sign_slots += rec.slots.len();
        e.sign_slots_absorbed += absorbed;
        e.bypass_other += rec
            .ops
            .iter()
            .filter(|op| matches!(op, BinOp::Bypass { slot_idx: None, .. }))
            .count();
        e.decision_bins += rec
            .ops
            .iter()
            .filter(|op| matches!(op, BinOp::Decision { .. }))
            .count();
        e.substreams += rec.substreams.len();
        e.excluded_subs += excluded.len();
    }

    let elapsed = t0.elapsed().as_secs_f64();
    println!("\n=== {path} ===");
    println!(
        "file {} bytes, {} slices recorded, {skipped} skipped by decoder, {failures} decode errors, {elapsed:.2}s",
        carrier.len(),
        per_type.values().map(|s| s.slices).sum::<usize>(),
    );
    println!(
        "{:>4} {:>8} {:>7} {:>12} {:>12} {:>10} {:>10} {:>10} {:>8}",
        "type",
        "name",
        "slices",
        "bytes",
        "signSlots",
        "absorbed",
        "decision",
        "bypassOth",
        "slot/KB"
    );
    let mut total = Stat::default();
    let mut tier_a = Stat::default();
    for (t, s) in &per_type {
        println!(
            "{:>4} {:>8} {:>7} {:>12} {:>12} {:>12} {:>10} {:>10} {:>8.0}",
            t,
            nal_name(*t),
            s.slices,
            s.bytes,
            s.sign_slots,
            s.sign_slots_absorbed,
            s.decision_bins,
            s.bypass_other,
            s.sign_slots_absorbed as f64 / (s.bytes as f64 / 1024.0).max(1e-9),
        );
        total.slices += s.slices;
        total.bytes += s.bytes;
        total.sign_slots += s.sign_slots;
        total.sign_slots_absorbed += s.sign_slots_absorbed;
        total.decision_bins += s.decision_bins;
        total.bypass_other += s.bypass_other;
        total.substreams += s.substreams;
        total.excluded_subs += s.excluded_subs;
        if is_non_reference_vcl(*t) {
            tier_a.slices += s.slices;
            tier_a.bytes += s.bytes;
            tier_a.sign_slots += s.sign_slots;
            tier_a.sign_slots_absorbed += s.sign_slots_absorbed;
        }
    }
    println!(
        "ALL  slices={} bytes={} signSlots={} absorbed={} decision={} bypassOther={} excludedSubs={}",
        total.slices,
        total.bytes,
        total.sign_slots,
        total.sign_slots_absorbed,
        total.decision_bins,
        total.bypass_other,
        total.excluded_subs
    );
    println!(
        "TIER-A(non-ref only) slices={} bytes={} signSlots={} absorbed={} -> {:.1}% of all sign slots",
        tier_a.slices,
        tier_a.bytes,
        tier_a.sign_slots,
        tier_a.sign_slots_absorbed,
        100.0 * tier_a.sign_slots as f64 / total.sign_slots.max(1) as f64
    );
    println!(
        "gate loss: {} slots ({:.1}%), EPB sub exclusion: {} slots",
        total.sign_slots - tier_a.sign_slots,
        100.0 * (total.sign_slots - tier_a.sign_slots) as f64 / total.sign_slots.max(1) as f64,
        total.sign_slots - total.sign_slots_absorbed
    );
}

fn nal_name(t: u8) -> &'static str {
    match t {
        0 => "TRAIL_N",
        1 => "TRAIL_R",
        2 => "TSA_N",
        3 => "TSA_R",
        4 => "STSA_N",
        5 => "STSA_R",
        6 => "RADL_N",
        7 => "RADL_R",
        8 => "RASL_N",
        9 => "RASL_R",
        16 => "BLA_W_LP",
        17 => "BLA_W_RADL",
        18 => "BLA_N_LP",
        19 => "IDR_W_RADL",
        20 => "IDR_N_LP",
        21 => "CRA_NUT",
        _ => "?",
    }
}
