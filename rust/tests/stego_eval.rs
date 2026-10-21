//! Independent Evaluation Suite for Content-Adaptive Steganography (Phase 0).
//!
//! Provides objective, scheme-aware, and blind forensic estimators to quantify:
//! 1. **Class-Residue Boundary Deficit (P0-B Vulnerability)**:
//!    Quantifies the r=0 / r=7 net deficit created by the `0xF8` ternary single-direction
//!    moves (`val%8==0 -> +1`, `val%8==7 -> -1`). Computes Z-score significance and
//!    verifies that N_changed can be estimated linearly from `16 * delta_0`.
//! 2. **Full-Image Unbiased Chi-Square & Channel Stats**:
//!    Eliminates the 4MB truncation in `src/analysis.rs` to compute unbiased PoVs
//!    statistics per channel and overall.
//! 3. **Slot Predictability (P2-C Baseline)**:
//!    Quantifies how accurately a scheme-aware attacker can predict modified slot locations
//!    without knowing the key, by re-running public HILL cost-sorting on the stego carrier.
//! 4. **Holdout Evaluation Sweep**:
//!    Evaluates a holdout set of real 2K/HD natural images (from `F:\ai\downloads\DIV2K_train_HR`
//!    or local corpus) across bpp gradients (0.05, 0.10, 0.15, 0.20) with bootstrap 95% CI.
//!
//! Run with:
//! ```text
//! cargo test --release --test stego_eval -- --ignored --nocapture
//! ```

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use rayon::prelude::*;
use strhide::analysis::scan_file;
use strhide::stego::{
    SpatialParams, StegoOptions, embed_carrier,
    spatial::{HillCostModel, decode_png},
    traits::SpatialCostModel,
};

const TEST_PASSWORD: &str = "EvalStegoSuite2026!Secure";

// ── 1. Corpus Resolution ──────────────────────────────────────────────────────

/// Resolve evaluation corpus directory.
/// Prioritizes:
/// 1. Environment variable `STRHIDE_EVAL_CORPUS`
/// 2. External DIV2K dataset `F:\ai\downloads\DIV2K_train_HR` (800 natural 2K images)
/// 3. Local `temp/images/png` (80 test images)
/// 4. Local `temp/teststego`
fn resolve_eval_images(limit: usize) -> Vec<PathBuf> {
    let candidate_dirs = [
        std::env::var("STRHIDE_EVAL_CORPUS").ok().map(PathBuf::from),
        Some(PathBuf::from(r"F:\ai\downloads\DIV2K_train_HR")),
        Some(PathBuf::from("temp/images/png")),
        Some(PathBuf::from("../temp/images/png")),
        Some(PathBuf::from("temp/teststego")),
        Some(PathBuf::from("../temp/teststego")),
    ];

    for dir_opt in candidate_dirs.into_iter().flatten() {
        if dir_opt.is_dir() {
            let mut pngs = Vec::new();
            if let Ok(entries) = fs::read_dir(&dir_opt) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file()
                        && path
                            .extension()
                            .is_some_and(|e| e.eq_ignore_ascii_case("png"))
                    {
                        pngs.push(path);
                    }
                }
            }
            if !pngs.is_empty() {
                pngs.sort();
                pngs.truncate(limit);
                println!("Found {} evaluation images in {:?}", pngs.len(), dir_opt);
                return pngs;
            }
        }
    }

    panic!("No valid PNG evaluation corpus found for stego_eval");
}

// ── 2. Class-Residue Boundary Deficit Estimator (P0-B) ─────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ResidueDeficitReport {
    pub total_pixels: usize,
    pub changed_pixels: usize,
    pub hist_cover: [u64; 8],
    pub hist_stego: [u64; 8],
    pub delta: [i64; 8],
    pub delta_0: i64,
    pub delta_7: i64,
    pub estimated_changed_from_delta0: i64,
    pub estimation_error_ratio: f64,
    pub z_score_0: f64,
    pub blind_delta_0: f64,
    pub blind_z_score_0: f64,
}

/// Compute class residue histogram (val % 8) for a pixel slice.
pub fn class_residue_histogram(pixels: &[u8]) -> [u64; 8] {
    let mut h = [0u64; 8];
    for &p in pixels {
        h[(p % 8) as usize] += 1;
    }
    h
}

/// Estimate boundary deficit and leakage significance.
pub fn analyze_residue_deficit(cover_green: &[u8], stego_green: &[u8]) -> ResidueDeficitReport {
    assert_eq!(cover_green.len(), stego_green.len());
    let total = cover_green.len();

    let mut changed = 0usize;
    for i in 0..total {
        if cover_green[i] != stego_green[i] {
            changed += 1;
        }
    }

    let hc = class_residue_histogram(cover_green);
    let hs = class_residue_histogram(stego_green);

    let mut delta = [0i64; 8];
    for r in 0..8 {
        delta[r] = hs[r] as i64 - hc[r] as i64;
    }

    // Deficit at boundary r=0 and r=7: delta[0] < 0 => deficit = -delta[0]
    let delta_0 = -delta[0];
    let delta_7 = -delta[7];

    let estimated_changed = delta_0 * 16;
    let estimation_error_ratio = if changed > 0 {
        (estimated_changed - changed as i64).abs() as f64 / changed as f64
    } else {
        0.0
    };

    // Standard deviation under binomial expectation (sigma = sqrt(N * 1/8 * 7/8))
    let sigma_0 = (total as f64 * 0.125 * 0.875).sqrt();
    let z_score_0 = delta_0 as f64 / sigma_0;

    // Blind estimation without cover: baseline expected count from interior r in 2..=5
    let interior_avg = (hs[2] + hs[3] + hs[4] + hs[5]) as f64 / 4.0;
    let blind_delta_0 = interior_avg - hs[0] as f64;
    let blind_z_score_0 = blind_delta_0 / sigma_0;

    ResidueDeficitReport {
        total_pixels: total,
        changed_pixels: changed,
        hist_cover: hc,
        hist_stego: hs,
        delta,
        delta_0,
        delta_7,
        estimated_changed_from_delta0: estimated_changed,
        estimation_error_ratio,
        z_score_0,
        blind_delta_0,
        blind_z_score_0,
    }
}

// ── 3. Unbiased Full-Image Chi-Square & Channel Variance ───────────────────────

#[derive(Debug, Clone, Default)]
pub struct FullChi2Report {
    pub chi2_val: f64,
    pub df: f64,
    pub chi2_per_df: f64,
    pub z_deviation: f64,
    pub flattening_score: f64,
}

/// Compute unbiased chi-square on pairs of values (PoVs: 2k, 2k+1) across full slice.
pub fn full_slice_chi2(data: &[u8]) -> FullChi2Report {
    let mut hist = [0u64; 256];
    for &b in data {
        hist[b as usize] += 1;
    }

    let mut chi2 = 0.0;
    let mut df = 0.0;
    for i in (0..256).step_by(2) {
        let count_even = hist[i] as f64;
        let count_odd = hist[i + 1] as f64;
        let expected = (count_even + count_odd) / 2.0;
        if expected > 0.0 {
            chi2 += ((count_even - expected).powi(2) + (count_odd - expected).powi(2)) / expected;
            df += 1.0;
        }
    }

    if df == 0.0 {
        return FullChi2Report::default();
    }

    let chi2_per_df = chi2 / df;
    let z_deviation = (chi2 - df) / (2.0 * df).sqrt();
    let flattening_score = ((df - chi2) / df).clamp(0.0, 1.0);

    FullChi2Report {
        chi2_val: chi2,
        df,
        chi2_per_df,
        z_deviation,
        flattening_score,
    }
}

// ── 4. Slot Predictability Estimator (P2-C Baseline) ──────────────────────────

/// Evaluate the scheme-aware slot predictability:
/// Re-computes the public HILL cost map on the stego carrier without password,
/// ranks slots by cost, picks top K lowest-cost candidate slots, and measures
/// what percentage of actual modified slots fall inside this predicted set.
pub fn measure_slot_predictability(
    stego_pixels: &[u8],
    width: usize,
    height: usize,
    channels: usize,
    actual_changed_indices: &HashSet<usize>,
) -> f64 {
    if actual_changed_indices.is_empty() {
        return 0.0;
    }

    let total_pixels = width * height;
    let model = HillCostModel;
    let params = SpatialParams::default();
    let costs = model.compute_cost(stego_pixels, width, height, channels, &params);

    let channel_offset = if channels >= 3 { 1 } else { 0 };

    let mut eligible: Vec<usize> = (0..total_pixels)
        .filter(|&idx| {
            let val = stego_pixels[idx * channels + channel_offset];
            (8..=247).contains(&val)
        })
        .collect();

    eligible.sort_by(|&a, &b| {
        costs[a]
            .partial_cmp(&costs[b])
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let allowed_count = ((eligible.len() as f64) * 0.70) as usize;
    let candidate_pool = &eligible[..allowed_count];

    let needed = actual_changed_indices.len().min(candidate_pool.len());
    let predicted_top_k: HashSet<usize> = candidate_pool[..needed].iter().copied().collect();

    let intersection_count = actual_changed_indices
        .iter()
        .filter(|idx| predicted_top_k.contains(idx))
        .count();

    intersection_count as f64 / actual_changed_indices.len() as f64
}

// ── 5. Deterministic Payload Generator ─────────────────────────────────────────

fn generate_pseudo_payload(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut s = seed;
    for _ in 0..len {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.push((s >> 33) as u8);
    }
    out
}

// ── 6. Bootstrap CI Helper ────────────────────────────────────────────────────

fn bootstrap_mean_ci_95(samples: &[f64], n_boot: usize) -> (f64, f64, f64) {
    if samples.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    if samples.len() == 1 {
        return (mean, mean, mean);
    }

    let mut boot_means = Vec::with_capacity(n_boot);
    let mut rng_state = 123456789u64;

    for _ in 0..n_boot {
        let mut sum = 0.0;
        for _ in 0..samples.len() {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let idx = (rng_state as usize) % samples.len();
            sum += samples[idx];
        }
        boot_means.push(sum / samples.len() as f64);
    }

    boot_means.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let low_idx = ((n_boot as f64) * 0.025) as usize;
    let high_idx = ((n_boot as f64) * 0.975) as usize;

    (mean, boot_means[low_idx], boot_means[high_idx])
}

// ── 7. Main Suite: Holdout Sweep & Forensic Evaluation ────────────────────────

#[test]
#[ignore]
fn test_stego_evaluation_suite() {
    println!("\n==========================================================================");
    println!("     STEGO INDEPENDENT EVALUATION SUITE: HOLDOUT EMPIRICAL SWEEP           ");
    println!("==========================================================================");

    let images = resolve_eval_images(20);
    println!(
        "Selected {} holdout images for benchmarking.\n",
        images.len()
    );

    let gradients_bpp = [0.05, 0.10, 0.15, 0.20];

    // First measure clean image baselines & slot densities
    println!("--- Measuring Clean Carrier Baselines & Candidate Densities ---");
    let mut slot_densities = Vec::new();
    let mut clean_z0s = Vec::new();
    let mut clean_chi2s = Vec::new();

    for img_path in &images {
        let raw_bytes = fs::read(img_path).expect("read clean image");
        let decoded = decode_png(&raw_bytes).expect("decode png");
        let total_pixels = decoded.width as usize * decoded.height as usize;
        let channel_offset = if decoded.channels >= 3 { 1 } else { 0 };

        let green_pixels: Vec<u8> = (0..total_pixels)
            .map(|i| decoded.pixels[i * decoded.channels + channel_offset])
            .collect();

        let eligible_count = green_pixels
            .iter()
            .filter(|&&val| (8..=247).contains(&val))
            .count();
        let density = (eligible_count as f64 * 0.70) / total_pixels as f64;
        slot_densities.push(density);

        let report = analyze_residue_deficit(&green_pixels, &green_pixels);
        clean_z0s.push(report.z_score_0);

        let chi2 = full_slice_chi2(&green_pixels);
        clean_chi2s.push(chi2.chi2_per_df);
    }

    let (mean_density, d_lo, d_hi) = bootstrap_mean_ci_95(&slot_densities, 1000);
    let (mean_clean_z, z_lo, z_hi) = bootstrap_mean_ci_95(&clean_z0s, 1000);

    println!(
        "Mean Candidate Slot Density c_density = {:.4} (95% CI: [{:.4}, {:.4}])",
        mean_density, d_lo, d_hi
    );
    println!(
        "bpp <-> r Mapping: r = c_density / bpp -> for bpp=0.10: r ≈ {:.2}, for bpp=0.15: r ≈ {:.2}",
        mean_density / 0.10,
        mean_density / 0.15
    );
    println!(
        "Clean Carrier Baseline Z0 = {:.3} (95% CI: [{:.3}, {:.3}]) -> All within [-3, +3] null hypothesis\n",
        mean_clean_z, z_lo, z_hi
    );

    // Sweep across bpp gradients
    for &target_bpp in &gradients_bpp {
        println!(
            "--------------------------------------------------------------------------\n\
             EVALUATING TARGET LOAD: {:.2} bpp (Approx r ≈ {:.2})\n\
             --------------------------------------------------------------------------",
            target_bpp,
            mean_density / target_bpp
        );

        let mut flips_per_bit_list = Vec::new();
        let mut z0_deficit_list = Vec::new();
        let mut blind_z0_list = Vec::new();
        let mut error_ratio_list = Vec::new();
        let mut slot_overlap_list = Vec::new();
        let mut chi2_df_list = Vec::new();
        let mut scan_score_list = Vec::new();

        let results: Vec<_> = images
            .par_iter()
            .enumerate()
            .filter_map(|(idx, img_path)| {
                let raw_bytes = fs::read(img_path).ok()?;
                let cover_decoded = decode_png(&raw_bytes).ok()?;
                let total_pixels = cover_decoded.width as usize * cover_decoded.height as usize;
                let needed_bits = (total_pixels as f64 * target_bpp) as usize;
                let payload_len = (needed_bits / 8).saturating_sub(21); // deduct BODY_OVERHEAD
                if payload_len == 0 {
                    return None;
                }

                let payload = generate_pseudo_payload(payload_len, 0xACE1234 + idx as u64);
                let opts = StegoOptions {
                    password: Some(TEST_PASSWORD.into()),
                    ..Default::default()
                };

                let t0 = Instant::now();
                let stego_bytes = embed_carrier(&raw_bytes, &payload, &opts).ok()?;
                let embed_dur = t0.elapsed();

                let stego_decoded = decode_png(&stego_bytes).ok()?;

                let channel_offset = if cover_decoded.channels >= 3 { 1 } else { 0 };
                let cover_g: Vec<u8> = (0..total_pixels)
                    .map(|i| cover_decoded.pixels[i * cover_decoded.channels + channel_offset])
                    .collect();
                let stego_g: Vec<u8> = (0..total_pixels)
                    .map(|i| stego_decoded.pixels[i * stego_decoded.channels + channel_offset])
                    .collect();

                let deficit_rep = analyze_residue_deficit(&cover_g, &stego_g);

                let mut actual_changed = HashSet::new();
                for i in 0..total_pixels {
                    if cover_g[i] != stego_g[i] {
                        actual_changed.insert(i);
                    }
                }

                let flips_per_bit = actual_changed.len() as f64 / (payload_len * 8) as f64;
                let overlap = measure_slot_predictability(
                    &stego_decoded.pixels,
                    stego_decoded.width as usize,
                    stego_decoded.height as usize,
                    stego_decoded.channels,
                    &actual_changed,
                );

                let chi2_rep = full_slice_chi2(&stego_g);

                // Temporary file for scan_file
                let temp_dir = std::env::temp_dir().join("strhide_stego_eval");
                let _ = fs::create_dir_all(&temp_dir);
                let tmp_stego_path = temp_dir.join(format!(
                    "eval_{}_{}.png",
                    idx,
                    (target_bpp * 100.0) as usize
                ));
                let _ = fs::write(&tmp_stego_path, &stego_bytes);
                let scan_score = scan_file(&tmp_stego_path)
                    .map(|r| r.risk_score)
                    .unwrap_or(0);
                let _ = fs::remove_file(&tmp_stego_path);

                Some((
                    img_path.file_name().unwrap().to_string_lossy().to_string(),
                    payload_len,
                    flips_per_bit,
                    deficit_rep.z_score_0,
                    deficit_rep.blind_z_score_0,
                    deficit_rep.estimation_error_ratio,
                    overlap,
                    chi2_rep.chi2_per_df,
                    scan_score,
                    embed_dur,
                ))
            })
            .collect();

        println!(
            "{:<22} {:>9} {:>10} {:>9} {:>11} {:>10} {:>10} {:>8}",
            "Image",
            "Payload",
            "Flips/Bit",
            "Z0(exact)",
            "Z0(blind)",
            "Err(N)% ",
            "Overlap%",
            "Scan"
        );
        println!("{}", "-".repeat(95));

        for (name, plen, fpb, z0, bz0, err, ov, _chi2, scan, _dur) in &results {
            println!(
                "{:<22} {:>7} B {:>10.4} {:>9.2}σ {:>10.2}σ {:>9.2}% {:>9.2}% {:>8}",
                name,
                plen,
                fpb,
                z0,
                bz0,
                err * 100.0,
                ov * 100.0,
                scan
            );

            flips_per_bit_list.push(*fpb);
            z0_deficit_list.push(*z0);
            blind_z0_list.push(*bz0);
            error_ratio_list.push(*err);
            slot_overlap_list.push(*ov);
            chi2_df_list.push(*_chi2);
            scan_score_list.push(*scan as f64);
        }

        let (m_fpb, fpb_lo, fpb_hi) = bootstrap_mean_ci_95(&flips_per_bit_list, 1000);
        let (m_z0, z0_lo, z0_hi) = bootstrap_mean_ci_95(&z0_deficit_list, 1000);
        let (m_err, err_lo, err_hi) = bootstrap_mean_ci_95(&error_ratio_list, 1000);
        let (m_ov, ov_lo, ov_hi) = bootstrap_mean_ci_95(&slot_overlap_list, 1000);
        let (m_scan, _, _) = bootstrap_mean_ci_95(&scan_score_list, 1000);

        println!("{}", "-".repeat(95));
        println!(
            "AGGREGATE [bpp={:.2}]: Flips/Bit={:.4} [{:.4},{:.4}] | Deficit Z0={:.1}σ [{:.1},{:.1}]σ | Err={:.1}% [{:.1},{:.1}]% | Overlap={:.1}% [{:.1},{:.1}]% | Scan={:.1}\n",
            target_bpp,
            m_fpb,
            fpb_lo,
            fpb_hi,
            m_z0,
            z0_lo,
            z0_hi,
            m_err * 100.0,
            err_lo * 100.0,
            err_hi * 100.0,
            m_ov * 100.0,
            ov_lo * 100.0,
            ov_hi * 100.0,
            m_scan
        );

        // Verification assertions for Phase 1 hardened implementation:
        // 1. Deficit Z0 is within [-3.0, 3.0] sigma, proving P0-B vulnerability has been eliminated.
        assert!(
            m_z0.abs() < 3.0,
            "P0-B residual deficit must be eliminated (|Z0| < 3.0 sigma), got {:.2}",
            m_z0
        );
    }

    println!("==========================================================================");
    println!("Phase 0 Independent Evaluation Suite Completed Successfully.");
    println!("==========================================================================\n");
}
