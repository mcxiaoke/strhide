// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Verification script for Improvement 3: HEVC capacity probe sampling accuracy & speedup.

use std::fs;
use std::path::Path;
use std::time::Instant;

use rusty_h265::Decoder;
use rusty_h265::ctu::Ablate;
use strhide::stego::hevc::mp4_boxes::parse_mp4_targets;
use strhide::stego::hevc::slot::CabacRecorder;
use strhide::stego::hevc::sniff::{
    NAL_RADL_N, NAL_RASL_N, NAL_STSA_N, NAL_TRAIL_N, NAL_TSA_N, sniff_hevc_carrier,
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

#[derive(Clone, Copy)]
struct ProbeStats {
    recorded_slots: usize,
    recorded_slices: usize,
    total_selectable: usize,
    sampled_bytes: usize,
    total_selectable_bytes: usize,
    elapsed_ms: u128,
}

fn run_probe_stats(carrier: &[u8], max_recorded_slices: Option<usize>) -> Option<ProbeStats> {
    let t0 = Instant::now();
    let target = parse_mp4_targets(carrier).ok()?;
    let mut decoder = Decoder::new();
    decoder.ablate = Ablate {
        mc: true,
        intra: true,
        residual: true,
    };

    for ps in &target.parameter_sets {
        let _ = decoder.push_nal(ps, None);
    }

    let mut candidates = Vec::with_capacity(target.slice_spans.len());
    for span in &target.slice_spans {
        let slice_bytes = &carrier[span.start..span.end()];
        if slice_bytes.len() >= 2 {
            let b0 = slice_bytes[0];
            let nal_type = (b0 >> 1) & 0x3F;
            candidates.push((span.start..span.end(), nal_type, slice_bytes.len()));
        }
    }

    let has_non_reference = candidates.iter().any(|(_, t, _)| is_non_reference_vcl(*t));
    let total_selectable = candidates
        .iter()
        .filter(|(_, t, _)| !has_non_reference || is_non_reference_vcl(*t))
        .count();
    let total_selectable_bytes: usize = candidates
        .iter()
        .filter(|(_, t, _)| !has_non_reference || is_non_reference_vcl(*t))
        .map(|(_, _, len)| *len)
        .sum();

    let mut recorded_slices = 0usize;
    let mut recorded_slots = 0usize;
    let mut sampled_bytes = 0usize;

    for (range, nal_type, len) in &candidates {
        let slice_bytes = &carrier[range.clone()];
        let is_sel = !has_non_reference || is_non_reference_vcl(*nal_type);
        if !is_sel {
            let _ = decoder.push_nal(slice_bytes, None);
            drain_frames(&mut decoder);
            continue;
        }

        if max_recorded_slices.is_some_and(|limit| recorded_slices >= limit) {
            break;
        }

        let mut recorder = CabacRecorder::with_slice(recorded_slices, 0);
        let decoded = decoder.decode_nal_with_observer(slice_bytes, &mut recorder);
        drain_frames(&mut decoder);

        if decoded.is_ok() && !recorder.substreams.is_empty() {
            recorded_slots += recorder.slots.len();
            recorded_slices += 1;
            sampled_bytes += *len;
        }
    }

    let elapsed_ms = t0.elapsed().as_millis();
    Some(ProbeStats {
        recorded_slots,
        recorded_slices,
        total_selectable,
        sampled_bytes,
        total_selectable_bytes,
        elapsed_ms,
    })
}

fn main() {
    let test_dir = Path::new("temp/testhevc");
    if !test_dir.is_dir() {
        eprintln!("Directory {:?} not found", test_dir);
        return;
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(test_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        if ext == "mp4" || ext == "mov" {
            files.push(path);
        }
    }
    files.sort();

    println!("# HEVC 采样容量估算实测误差对比报告\n");
    println!(
        "| 文件名 | 选录帧数 | 全扫槽数 | 全扫耗时 | 100帧加权 | 10%动态加权 (100..500) | 10%耗时 | 20%动态加权 (100..1000) | 20%耗时 |"
    );
    println!("|:---|---:|---:|---:|---:|---:|---:|---:|---:|");

    for file in &files {
        let Ok(data) = fs::read(file) else { continue };
        if sniff_hevc_carrier(&data).is_none() {
            continue;
        }

        let Some(full) = run_probe_stats(&data, None) else {
            continue;
        };

        if full.recorded_slots == 0 || full.total_selectable == 0 {
            continue;
        }

        // Sampling fixed 100
        let s100 = run_probe_stats(&data, Some(100));

        // Dynamic 10% (clamp 100..500)
        let dyn10_count = ((full.total_selectable as f64 * 0.10).round() as usize).clamp(100, 500);
        let s_dyn10 = if dyn10_count == 100 {
            s100
        } else {
            run_probe_stats(&data, Some(dyn10_count))
        };

        // Dynamic 20% (clamp 100..1000)
        let dyn20_count = ((full.total_selectable as f64 * 0.20).round() as usize).clamp(100, 1000);
        let s_dyn20 = if dyn20_count == 100 {
            s100
        } else if dyn20_count == dyn10_count {
            s_dyn10
        } else {
            run_probe_stats(&data, Some(dyn20_count))
        };

        let err_bw = |s: Option<ProbeStats>| -> (String, String) {
            match s {
                Some(st) if st.recorded_slices > 0 && st.sampled_bytes > 0 => {
                    let est_bw = (st.recorded_slots as f64 / st.sampled_bytes as f64)
                        * st.total_selectable_bytes as f64;
                    let err = (est_bw - full.recorded_slots as f64).abs()
                        / full.recorded_slots as f64
                        * 100.0;
                    (
                        format!("{:.1}%", err),
                        format!("{:.2}s", st.elapsed_ms as f64 / 1000.0),
                    )
                }
                _ => ("-".into(), "-".into()),
            }
        };

        let (err_100, _) = err_bw(s100);
        let (err_d10, t_d10) = err_bw(s_dyn10);
        let (err_d20, t_d20) = err_bw(s_dyn20);

        let name = file.file_name().unwrap().to_string_lossy();
        println!(
            "| {} | {} | {} | {:.2}s | {} | {} | {} | {} | {} |",
            name,
            full.total_selectable,
            full.recorded_slots,
            full.elapsed_ms as f64 / 1000.0,
            err_100,
            err_d10,
            t_d10,
            err_d20,
            t_d20,
        );
    }
}
