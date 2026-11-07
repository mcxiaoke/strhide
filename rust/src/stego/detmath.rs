//! Deterministic elementary functions for the cost pipeline.
//!
//! `exp`, `ln`, `ln_1p` and `cos` are only used to build distortion costs, but
//! those costs decide which pixels carry the payload, so a 1-ulp difference
//! between two libms can move the payload elsewhere (see
//! `cost_calibration::quantize_cost` for the measurement).
//!
//! These functions use **only** IEEE-754 `+ - * /` plus bit-level
//! `frexp`/`ldexp`, a fixed evaluation order and a fixed term count. The result
//! is therefore a pure function of the input bits: any language that follows
//! the same steps lands on the same doubles regardless of its libm. Accuracy is
//! a couple of ulp -- worse than a good libm and irrelevant here, because the
//! contract is reproducibility, not correct rounding.
//!
//! `scripts/detmath/` holds Go and Python ports; the three must agree bit for
//! bit. `tests` pins a digest of the outputs so a change cannot slip through.

/// `ln 2` as a correctly rounded hi/lo pair (~75 significant bits).
///
/// `LN2_HI` carries 33 significant bits with the low 20 bits of the mantissa
/// zeroed (`0x3FE6_2E42_FEE0_0000`). Consequently, for any integer `|k| < 2^20`,
/// the floating-point multiplication `kf * LN2_HI` is strictly exact with zero
/// rounding error. `LN2_LO` compensates the remaining tail so `(x - k*LN2_HI) - k*LN2_LO`
/// eliminates catastrophic cancellation during range reduction.
const LN2_HI: f64 = 6.931_471_803_691_238e-1;
const LN2_LO: f64 = 1.908_214_929_270_587_7e-10;
const INV_LN2: f64 = std::f64::consts::LOG2_E;

/// `pi/2` in three words (~139 significant bits, classical fdlibm constants).
///
/// The first word carries 33 significant bits with mantissa low 20 bits zeroed
/// (`0x3FF9_21FB_5440_0000`), so `n * PIO2_1` is exact with zero rounding error
/// for every `|n| < 2^20` (~1.05e6). The subsequent words `PIO2_2` and `PIO2_3`
/// provide 53 and 53 bits of precision respectively, ensuring high precision
/// even though `x - n*pi/2` cancels catastrophically.
const PIO2_1: f64 = 1.570_796_326_734_125_6;
const PIO2_2: f64 = 6.077_100_506_303_966e-11;
const PIO2_3: f64 = 2.022_266_248_795_951e-21;
const TWO_OVER_PI: f64 = 0.636_619_772_367_581_3;
/// `sqrt(2)`, the `ln` reduction cut.
const SQRT2: f64 = std::f64::consts::SQRT_2;

/// Domain bounds for `exp(x)`:
/// - `EXP_HI`: `ln(f64::MAX) ~= 709.7827`. Inputs above this overflow to `+inf`.
/// - `EXP_LO`: `ln(2^-1074) ~= -745.1332` (smallest subnormal double). Inputs below
///   this underflow completely to `0.0`.
const EXP_HI: f64 = 709.782_712_893_384;
const EXP_LO: f64 = -745.133_219_101_941_1;

/// `1/k!` for k = 1..=14 (`exp` on `|r| <= ln2/2 ~= 0.34657`).
/// The first truncated term is `r^15 / 15! <= 1.07e-19`, well below double precision
/// machine epsilon (~2.22e-16).
const EXP_C: [f64; 14] = [
    1.0,
    0.5,
    1.0 / 6.0,
    1.0 / 24.0,
    1.0 / 120.0,
    1.0 / 720.0,
    1.0 / 5040.0,
    1.0 / 40320.0,
    1.0 / 362880.0,
    1.0 / 3628800.0,
    1.0 / 39916800.0,
    1.0 / 479001600.0,
    1.0 / 6227020800.0,
    1.0 / 87178291200.0,
];

/// `sin` coefficients: `sin(r) = r * (1 + z*(c1 + z*(c2 + ...)))`, `z = r*r`.
/// Alternating terms `(-1)^((k-1)/2) / k!` through `r^17`: on `|r| <= pi/4 ~= 0.7854`
/// the truncation `r^19 / 19!` is ~7.7e-20.
const SIN_C: [f64; 8] = [
    -1.0 / 6.0,
    1.0 / 120.0,
    -1.0 / 5040.0,
    1.0 / 362880.0,
    -1.0 / 39916800.0,
    1.0 / 6227020800.0,
    -1.0 / 1307674368000.0,
    1.0 / 355687428096000.0,
];

/// `cos` coefficients: `cos(r) = 1 + z*(d1 + z*(d2 + ...))`.
/// Alternating terms `(-1)^(k/2) / k!` through `r^16`: on `|r| <= pi/4 ~= 0.7854`
/// the truncation `r^18 / 18!` is ~2.9e-18.
const COS_C: [f64; 8] = [
    -0.5,
    1.0 / 24.0,
    -1.0 / 720.0,
    1.0 / 40320.0,
    -1.0 / 3628800.0,
    1.0 / 479001600.0,
    -1.0 / 87178291200.0,
    1.0 / 20922789888000.0,
];

/// `y * 2^k` by exponent-field addition, split so no intermediate overflows.
///
/// - `0x7FE0_0000_0000_0000` is `2^1023` (biased exponent 2046 - 1023).
/// - `0x0010_0000_0000_0000` is `2^-1022` (smallest normal positive power, exponent 1 - 1023).
/// - After looping, `k` is bounded in `[-1022, 1023]`, so `1023 + k` lands in `[1, 2046]`,
///   forming a valid normal IEEE-754 exponent field.
#[inline]
fn ldexp(y: f64, mut k: i32) -> f64 {
    let mut y = y;
    while k > 1023 {
        y *= f64::from_bits(0x7FE0_0000_0000_0000); // 2^1023
        k -= 1023;
    }
    while k < -1022 {
        y *= f64::from_bits(0x0010_0000_0000_0000); // 2^-1022
        k += 1022;
    }
    y * f64::from_bits(((1023 + k) as u64) << 52)
}

/// `x = m * 2^e` with `m` in `[0.5, 1)`.
///
/// - Subnormals have exponent field `0`. Multiplying by `0x4350_0000_0000_0000` (`2^54`)
///   lifts the 52-bit mantissa into the normal range without subnormal truncation.
/// - `0x800F_FFFF_FFFF_FFFF` isolates the sign bit and the 52-bit mantissa.
/// - `0x3FE0_0000_0000_0000` injects biased exponent 1022 (`2^-1 = 0.5`), placing `m`
///   in `[-1.0, -0.5] U [0.5, 1.0)`.
#[inline]
fn frexp(x: f64) -> (f64, i32) {
    let bits = x.to_bits();
    let exp = ((bits >> 52) & 0x7FF) as i32;
    if exp == 0 {
        if x == 0.0 {
            return (0.0, 0);
        }
        // Subnormal: lift into the normal range first.
        let (m, e) = frexp(x * f64::from_bits(0x4350_0000_0000_0000)); // 2^54
        return (m, e - 54);
    }
    (
        f64::from_bits((bits & 0x800F_FFFF_FFFF_FFFF) | 0x3FE0_0000_0000_0000),
        exp - 1022,
    )
}

/// Nearest integer, ties away from zero (no libm, no rounding mode dependency).
#[inline]
fn round_i32(x: f64) -> i32 {
    if x >= 0.0 {
        (x + 0.5) as i32
    } else {
        (x - 0.5) as i32
    }
}

/// `exp(x)`.
pub fn exp(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if x > EXP_HI {
        return f64::INFINITY;
    }
    if x < EXP_LO {
        return 0.0;
    }
    let k = round_i32(x * INV_LN2);
    let kf = k as f64;
    let r = (x - kf * LN2_HI) - kf * LN2_LO;

    let mut p = EXP_C[13];
    let mut i = 12usize;
    while i > 0 {
        p = EXP_C[i] + r * p;
        i -= 1;
    }
    p = EXP_C[0] + r * p;
    ldexp(1.0 + r * p, k)
}

/// `ln(x)`; `-inf` at 0, NaN below it.
pub fn ln(x: f64) -> f64 {
    if x.is_nan() || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return f64::NEG_INFINITY;
    }
    if x.is_infinite() {
        return f64::INFINITY;
    }
    let (mut m, mut e) = frexp(x);
    m *= 2.0;
    e -= 1;
    if m > SQRT2 {
        m *= 0.5;
        e += 1;
    }
    // ln(m) = 2*atanh(s), s = (m-1)/(m+1), |s| <= 0.1716.
    let s = (m - 1.0) / (m + 1.0);
    let z = s * s;
    // atanh series through z^10/21: truncation ~1e-17 on `|z| <= 0.03`.
    let mut p = 1.0 / 23.0;
    let mut d = 21.0;
    while d > 1.0 {
        p = 1.0 / d + z * p;
        d -= 2.0;
    }
    p = 1.0 + z * p;
    let ln_m = 2.0 * s * p;
    let ef = e as f64;
    ef * LN2_HI + (ef * LN2_LO + ln_m)
}

/// `ln(1 + x)`.
pub fn ln_1p(x: f64) -> f64 {
    if x.is_nan() || x < -1.0 {
        return f64::NAN;
    }
    if x == -1.0 {
        return f64::NEG_INFINITY;
    }
    if x.abs() < 0.0625 {
        // Alternating series: 12 terms leave ~1e-19 relative error here.
        let mut term = x;
        let mut sum = 0.0;
        let mut n = 1.0;
        while n <= 12.0 {
            let odd = ((n as i32) & 1) == 1;
            sum += if odd { term / n } else { -(term / n) };
            term *= x;
            n += 1.0;
        }
        return sum;
    }
    ln(1.0 + x)
}

/// `sin(r)` for `|r| <= pi/4`.
#[inline]
fn sin_small(r: f64) -> f64 {
    let z = r * r;
    let mut p = SIN_C[SIN_C.len() - 1];
    let mut i = SIN_C.len() - 2;
    while i > 0 {
        p = SIN_C[i] + z * p;
        i -= 1;
    }
    p = SIN_C[0] + z * p;
    r * (1.0 + z * p)
}

/// `cos(r)` for `|r| <= pi/4`.
#[inline]
fn cos_small(r: f64) -> f64 {
    let z = r * r;
    let mut q = COS_C[COS_C.len() - 1];
    let mut i = COS_C.len() - 2;
    while i > 0 {
        q = COS_C[i] + z * q;
        i -= 1;
    }
    q = COS_C[0] + z * q;
    1.0 + z * q
}

/// `log2(x)`.
///
/// Only used to turn `epsilon` into the header's exponent field, where the
/// result is immediately rounded to an integer -- so sharing `ln`'s
/// determinism is enough, and a last-bit difference from libm's `log2` cannot
/// change the stored `k` unless it lands exactly on a half-integer.
pub fn log2(x: f64) -> f64 {
    if x.is_nan() || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return f64::NEG_INFINITY;
    }
    if x.is_infinite() {
        return f64::INFINITY;
    }
    ln(x) * std::f64::consts::LOG2_E
}

/// `cos(x)`.
///
/// # Domain and Overflow Boundaries
/// - **Intended Domain**: Assumes `|x| < 2^20 ~= 1.05e6`. Within this range,
///   `n * PIO2_1` is strictly exact with zero floating-point rounding error.
/// - **Extreme Input Overflow**: If `|x| >= 2^31 * (pi/2) ~= 3.37e9`, `x * TWO_OVER_PI`
///   exceeds the range of `i32`, causing integer cast saturation in Rust (and implementation-
///   defined cast truncation in Go).
/// - **Precision Degradation**: For `2^20 <= |x| < 3.37e9`, `n * PIO2_1` is no longer
///   exact, leading to gradual loss of reduction accuracy.
/// - **Pipeline Scope**: In `strhide`, `cos` is exclusively called to compute 8x8 DCT basis
///   matrices (`x = pi * k * (2a + 1) / 16 <= pi`), which strictly remains in `[0, pi]`,
///   far below any reduction or integer cast boundary.
/// - **Quadrant Selection**: Uses two's complement bitwise `n & 3`, which correctly yields
///   mathematical `(n mod 4 + 4) mod 4` even for negative integers.
pub fn cos(x: f64) -> f64 {
    if !x.is_finite() {
        return f64::NAN;
    }
    let n = round_i32(x * TWO_OVER_PI);
    let nf = n as f64;
    // Three-word reduction: the first product is exact, the rest are tiny.
    let r = ((x - nf * PIO2_1) - nf * PIO2_2) - nf * PIO2_3;
    match n & 3 {
        0 => cos_small(r),
        1 => -sin_small(r),
        2 => -cos_small(r),
        _ => sin_small(r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Accuracy is a sanity bound, not a contract: the contract is that the
    /// three implementations agree bit for bit (checked by
    /// `scripts/detmath/compare.sh`).
    #[test]
    fn stays_close_to_the_platform_libm() {
        for i in -400..=400 {
            let x = i as f64 / 3.0;
            let got = exp(x);
            let want = x.exp();
            if want.is_finite() && want > 0.0 {
                assert!(
                    ((got - want) / want).abs() < 8e-16,
                    "exp({x}) = {got}, libm {want}"
                );
            }
            let y = x.abs() + 1e-9;
            let gl = ln(y);
            let wl = y.ln();
            assert!(
                (gl - wl).abs() <= 8e-16 * wl.abs().max(1.0),
                "ln({y}) = {gl}, libm {wl}"
            );
            let gc = cos(x);
            let wc = x.cos();
            assert!((gc - wc).abs() < 8e-16, "cos({x}) = {gc}, libm {wc}");
        }
        for x in [1e-300, 1e-9, 0.5, 1.0, 2.0, 10.0, 1e10, 1e300] {
            let (gl, wl) = (ln(x), x.ln());
            assert!((gl - wl).abs() <= 8e-16 * wl.abs().max(1.0), "ln({x})");
        }
        assert!((ln_1p(1e-12) - 1e-12f64.ln_1p()).abs() < 1e-24);
    }

    /// Digest of the outputs for a fixed input grid. The Go and Python ports
    /// must produce the same numbers; `scripts/detmath/compare.sh` diffs them.
    fn digest(which: u8) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        let mut push = |v: f64| {
            for b in v.to_bits().to_le_bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        };
        match which {
            0 => {
                for i in -240..=240 {
                    push(exp(i as f64 * 0.37));
                }
                for i in 0..120 {
                    push(exp(1e-6 * i as f64));
                }
            }
            1 => {
                for i in 1..=400 {
                    push(ln(i as f64 * 0.71));
                }
                for i in 0..60 {
                    push(ln(1e-12 * (i as f64 + 1.0)));
                }
            }
            2 => {
                for k in 0..9 {
                    for a in 0..9 {
                        push(cos(
                            std::f64::consts::PI * k as f64 * (2 * a + 1) as f64 / 18.0
                        ));
                    }
                }
            }
            3 => {
                for i in 0..200 {
                    push(ln_1p(i as f64 * 0.003));
                }
            }
            _ => {
                for k in 1..=60 {
                    push(log2(2f64.powi(-k)));
                }
                for i in 1..=200 {
                    push(log2(i as f64 * 0.37));
                }
            }
        }
        h
    }

    #[test]
    fn output_digests_are_pinned() {
        assert_eq!(digest(0), PINNED[0], "exp digest moved");
        assert_eq!(digest(1), PINNED[1], "ln digest moved");
        assert_eq!(digest(2), PINNED[2], "cos digest moved");
        assert_eq!(digest(3), PINNED[3], "ln_1p digest moved");
        assert_eq!(digest(4), PINNED[4], "log2 digest moved");
    }

    /// Pinned so a change to the arithmetic cannot slip through: the Go and
    /// Python ports in `scripts/detmath/` carry the same four numbers.
    const PINNED: [u64; 5] = [
        0x6810_7bf8_71d5_3df2, // exp
        0x6021_ef64_db0e_27ef, // ln
        0x55f3_c5ac_b971_153a, // cos
        0x23e6_e71d_ccf6_9b20, // ln_1p
        0xd97b_86f5_8ee1_dfba, // log2
    ];
}
