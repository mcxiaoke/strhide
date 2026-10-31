//! Fisher-information → additive STC cost conversion shared by MiPOD and
//! J-MiPOD.
//!
//! # Model
//!
//! Cover elements are modelled as independent zero-mean Gaussians with
//! variance `sigma_n^2`; a ternary `±1` change with probability `beta_n`
//! each makes the detectability proportional to `sum beta_n^2 * I_n`, with
//! Fisher information `I_n = 2 / sigma_n^4`. Minimising it under the
//! payload constraint `sum H3(beta_n) = R` gives the stationarity condition
//!
//! ```text
//! ln((1 - 2 beta_n) / beta_n) = x_n * beta_n,   x_n = scale * I_n
//! ```
//!
//! and the additive STC cost `rho_n = ln(1/beta_n - 2)` is exactly the left
//! side. Substituting `rho` removes `beta` from the equation:
//!
//! ```text
//! h(rho) = rho * (exp(rho) + 2) = x
//! ```
//!
//! `h` is strictly increasing and convex on `rho >= 0`, and
//! `rho0 = ln(1 + x)` always lies to the right of the root
//! (`h(ln(1+x)) = ln(1+x)(3+x) >= x`). Newton from the right therefore
//! converges monotonically for every `x` in `[0, 1e300]`, with **no clamping
//! of beta or rho**. That matters twice:
//!
//! * no cost plateaus: `rho` is strictly increasing in `I`, so the slot
//!   ordering is independent of the payload the `scale` was calibrated for
//!   (a PNG extractor may therefore rebuild the ranking without knowing the
//!   embedder's reference rate);
//! * no `beta = 1/3` singularity handling and no `x > 1e11` branch that
//!   silently returns a wrong root.
//!
//! The scale is the unique root of `sum H3 = R`; the total entropy is
//! strictly decreasing in `t = ln(scale)`, so it is bracketed and refined
//! with the Illinois variant of regula falsi.

use rayon::prelude::*;

/// Largest `x` handled: `exp(690) ~ 1e300`, so `rho <= ~690` and all
/// intermediate `exp(rho)` values stay finite.
const LOG_X_MAX: f64 = 690.0;

/// `ln(3)`, the ternary entropy maximum per element (nats). `std` only has
/// `LN_2` / `LN_10`.
const LN_3: f64 = 1.098_612_288_668_109_8;

/// Elements per deterministic reduction chunk. Fixed so the entropy sum is
/// bit-identical regardless of the Rayon thread count.
const REDUCTION_CHUNK: usize = 4096;

/// Solve `rho * (exp(rho) + 2) = x` for the unique `rho >= 0`.
///
/// Monotone Newton started at `ln(1 + x)`, i.e. always on the right of the
/// root. Non-positive or NaN inputs map to `rho = 0` (beta = 1/3).
pub(crate) fn solve_rho(x: f64) -> f64 {
    if x.is_nan() || x <= 0.0 {
        return 0.0;
    }
    let x = x.min(1e300);
    let mut rho = (1.0 + x).ln();
    for _ in 0..32 {
        let e = rho.exp();
        let f = rho * (e + 2.0) - x;
        let df = e * (1.0 + rho) + 2.0;
        let next = (rho - f / df).max(0.0);
        if (next - rho).abs() <= 1e-14 * (1.0 + next) {
            rho = next;
            break;
        }
        rho = next;
    }
    rho
}

/// `beta = 1 / (exp(rho) + 2)` (test helper).
#[cfg(test)]
#[inline]
pub(crate) fn beta_from_rho(rho: f64) -> f64 {
    1.0 / (rho.exp() + 2.0)
}

/// Ternary entropy `H3(beta) = -2 beta ln beta - (1 - 2 beta) ln(1 - 2 beta)`
/// in nats, evaluated through `rho` to avoid cancellation near `beta = 1/3`.
#[inline]
pub(crate) fn ternary_entropy_nats(rho: f64) -> f64 {
    if rho <= 0.0 {
        return LN_3;
    }
    // beta = exp(-L), 1 - 2 beta = exp(-Lm), with L = rho + Lm and
    // Lm = ln(1 + 2 exp(-rho)).
    let lm = (2.0 * (-rho).exp()).ln_1p();
    let l = rho + lm;
    let beta = (-l).exp();
    let p0 = (-lm).exp();
    2.0 * beta * l + p0 * lm
}

/// Sum of ternary entropies (nats) at `scale = exp(t)`.
///
/// Inactive elements (`log_fi` non-finite) contribute nothing. The reduction
/// is deterministic: each fixed-size chunk is summed sequentially, and the
/// per-chunk sums are accumulated in index order.
fn total_entropy_nats(log_fi: &[f64], t: f64) -> f64 {
    let chunk_sums: Vec<f64> = log_fi
        .par_chunks(REDUCTION_CHUNK)
        .map(|chunk| {
            let mut sum = 0.0f64;
            for &lg in chunk {
                if !lg.is_finite() {
                    continue;
                }
                let x = (t + lg).min(LOG_X_MAX).exp();
                sum += ternary_entropy_nats(solve_rho(x));
            }
            sum
        })
        .collect();
    chunk_sums.iter().sum()
}

/// Convert a Fisher-information map into additive STC costs.
///
/// `target_bits` is the reference payload in bits (not nats). Elements with
/// `fisher <= 0` or non-finite values are inactive: they contribute no
/// entropy to the calibration and receive cost `0.0` (the caller decides
/// what an inactive element costs, e.g. J-MiPOD marks DC wet).
///
/// The returned cost `rho_n` is a strictly increasing function of
/// `fisher[n]`, so two calibrations at different `target_bits` produce the
/// same slot ordering. Costs are finite (at most ~691 for any representable
/// input) and non-negative.
pub(crate) fn fisher_to_costs(mut fisher: Vec<f64>, target_bits: f64) -> Vec<f64> {
    let n = fisher.len();
    if n == 0 {
        return fisher;
    }

    // The map is transformed in place: a separate log map plus a separate
    // cost map would triple the working set on 100 MP carriers.
    fisher.par_iter_mut().for_each(|f| {
        *f = if f.is_finite() && *f > 0.0 {
            f.ln()
        } else {
            f64::NEG_INFINITY
        };
    });
    let log_fi: &[f64] = &fisher;

    let active = log_fi.iter().filter(|v| v.is_finite()).count();
    if active == 0 || target_bits <= 0.0 || !target_bits.is_finite() {
        // Nothing to spread: all elements are equivalent.
        fisher.iter_mut().for_each(|v| *v = 0.0);
        return fisher;
    }

    let max_log = log_fi
        .iter()
        .filter(|v| v.is_finite())
        .fold(f64::NEG_INFINITY, |a, &b| a.max(b));
    let min_log = log_fi
        .iter()
        .filter(|v| v.is_finite())
        .fold(f64::INFINITY, |a, &b| a.min(b));

    // Payload in nats, clamped just below the ternary capacity.
    let capacity = active as f64 * LN_3;
    let target = (target_bits * std::f64::consts::LN_2).min(capacity * 0.999);
    if target <= 0.0 {
        fisher.iter_mut().for_each(|v| *v = 0.0);
        return fisher;
    }

    // Bracket t = ln(scale). total(t) is strictly decreasing in t.
    let mut t_lo = -max_log - 30.0;
    let mut f_lo = total_entropy_nats(log_fi, t_lo) - target;
    let mut guard = 0;
    while f_lo <= 0.0 && guard < 100 {
        t_lo -= 10.0;
        f_lo = total_entropy_nats(log_fi, t_lo) - target;
        guard += 1;
    }
    if f_lo <= 0.0 {
        // Unreachable after the capacity clamp, but never return a bogus root.
        fisher.iter_mut().for_each(|v| *v = 0.0);
        return fisher;
    }

    let mut t_hi = -min_log + 5.0;
    let mut f_hi = total_entropy_nats(log_fi, t_hi) - target;
    let mut guard = 0;
    while f_hi >= 0.0 && guard < 100 && t_hi < LOG_X_MAX - max_log {
        t_hi += 10.0;
        f_hi = total_entropy_nats(log_fi, t_hi) - target;
        guard += 1;
    }
    if f_hi >= 0.0 {
        fisher.iter_mut().for_each(|v| *v = 0.0);
        return fisher;
    }

    // Illinois (modified regula falsi) on a guaranteed bracket.
    let tol = 1e-12 * target.max(1.0);
    let mut a = t_lo;
    let mut b = t_hi;
    let mut fa = f_lo;
    let mut fb = f_hi;
    let mut side = 0i8;
    let mut t = 0.5 * (a + b);
    for _ in 0..80 {
        let c = if (fb - fa).abs() > 0.0 {
            (a * fb - b * fa) / (fb - fa)
        } else {
            0.5 * (a + b)
        };
        let c = if c > a.min(b) && c < a.max(b) {
            c
        } else {
            0.5 * (a + b)
        };
        let fc = total_entropy_nats(log_fi, c) - target;
        t = c;
        if fc.abs() <= tol || (b - a).abs() <= 1e-14 * (1.0 + a.abs().max(b.abs())) {
            break;
        }
        if fc * fb > 0.0 {
            b = c;
            fb = fc;
            if side == -1 {
                fa *= 0.5;
            }
            side = -1;
        } else {
            a = c;
            fa = fc;
            if side == 1 {
                fb *= 0.5;
            }
            side = 1;
        }
    }

    // log(Fisher) -> rho, in place.
    fisher.par_iter_mut().for_each(|lg| {
        *lg = if !lg.is_finite() {
            0.0
        } else {
            let x = (t + *lg).min(LOG_X_MAX).exp();
            solve_rho(x)
        };
    });
    fisher
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `h(rho) = x` must hold to double precision across the whole domain,
    /// including the `x = 1` point that broke the previous beta-solver.
    #[test]
    fn rho_equation_holds_across_the_domain() {
        let xs = [
            1e-300, 1e-30, 1e-12, 1e-6, 0.01, 0.1, 0.999999, 1.0, 1.000001, 1.001, 2.0, 10.0,
            100.0, 1e4, 1e8, 1e12, 1e30, 1e100, 1e300,
        ];
        for &x in &xs {
            let rho = solve_rho(x);
            assert!(rho >= 0.0 && rho.is_finite(), "x={x}: rho={rho}");
            let h = rho * (rho.exp() + 2.0);
            let err = (h - x).abs() / x.max(1.0);
            assert!(err < 1e-12, "x={x}: h={h}, relative error {err}");
            let beta = beta_from_rho(rho);
            assert!(
                beta > 0.0 && beta <= 1.0 / 3.0 + 1e-15,
                "x={x}: beta={beta}"
            );
            let lhs = ((1.0 - 2.0 * beta) / beta).ln();
            assert!(
                ((lhs - x * beta).abs()) < 1e-9,
                "x={x}: beta equation residual {}",
                (lhs - x * beta).abs()
            );
        }
    }

    #[test]
    fn entropy_matches_the_direct_formula() {
        for &rho in &[0.0, 1e-9, 0.01, 0.1, 0.5, 1.0, 10.0, 50.0, 200.0, 600.0] {
            let beta = beta_from_rho(rho);
            let direct = if beta <= 1e-300 || beta >= 0.5 {
                0.0
            } else {
                -2.0 * beta * beta.ln() - (1.0 - 2.0 * beta) * (1.0 - 2.0 * beta).ln()
            };
            let stable = ternary_entropy_nats(rho);
            if beta > 1e-12 {
                assert!(
                    (stable - direct).abs() / direct.abs().max(1.0) < 1e-12,
                    "rho={rho}: {stable} vs {direct}"
                );
            }
            assert!((0.0..=LN_3 + 1e-15).contains(&stable));
        }
    }

    /// Costs are strictly monotone in Fisher information and independent of
    /// the calibration payload, which is what lets PNG extraction re-rank
    /// slots without knowing the embed-time reference rate.
    #[test]
    fn ordering_is_independent_of_the_calibration_payload() {
        let mut fisher = Vec::new();
        let mut state = 0x1234_5678u64;
        for _ in 0..4096 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let var = 0.01 + (state % 10_000) as f64 / 100.0;
            fisher.push(2.0 / (var * var));
        }
        let cheap = fisher_to_costs(fisher.clone(), 0.05 * fisher.len() as f64);
        let medium = fisher_to_costs(fisher.clone(), 0.20 * fisher.len() as f64);
        let dense = fisher_to_costs(fisher.clone(), 0.80 * fisher.len() as f64);

        let mut idx: Vec<usize> = (0..fisher.len()).collect();
        idx.sort_unstable_by(|&a, &b| fisher[a].total_cmp(&fisher[b]));
        for costs in [&cheap, &medium, &dense] {
            for w in idx.windows(2) {
                assert!(
                    costs[w[0]] <= costs[w[1]],
                    "costs must follow Fisher order: {} > {}",
                    costs[w[0]],
                    costs[w[1]]
                );
            }
            assert!(costs.iter().all(|c| c.is_finite() && *c >= 0.0));
        }
        assert!(
            cheap.iter().sum::<f64>() > medium.iter().sum::<f64>(),
            "a lower reference payload must produce more expensive costs"
        );
    }

    #[test]
    fn calibration_meets_the_target_entropy() {
        let fisher: Vec<f64> = (1..=2048)
            .map(|i| 2.0 / ((0.01 + i as f64 / 2048.0 * 100.0).powi(2)))
            .collect();
        let target_bits = 0.20 * fisher.len() as f64;
        let costs = fisher_to_costs(fisher, target_bits);
        // Recover beta from rho and sum the entropy.
        let achieved: f64 = costs
            .iter()
            .map(|&rho| ternary_entropy_nats(rho))
            .sum::<f64>()
            / std::f64::consts::LN_2;
        let rel = (achieved - target_bits).abs() / target_bits;
        assert!(rel < 1e-6, "achieved {achieved} bits, target {target_bits}");
    }

    #[test]
    fn inactive_elements_are_free_and_zero_payload_is_safe() {
        let fisher = vec![1.0, 0.0, f64::NAN, 2.0];
        let costs = fisher_to_costs(fisher, 1.0);
        assert_eq!(costs[1], 0.0);
        assert_eq!(costs[2], 0.0);
        assert!(costs.iter().all(|c| c.is_finite() && *c >= 0.0));
        assert!(
            costs[0] > 0.0 && costs[3] > 0.0,
            "active elements are priced"
        );
        let zero = fisher_to_costs(vec![1.0, 2.0], 0.0);
        assert_eq!(zero, vec![0.0, 0.0]);
    }
}
