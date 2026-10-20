// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Syndrome-Trellis Codes (STC) — the encoding layer above the cost models.
//!
//! Implements the convolutional "syndrome trellis" of T. Filler, J. Judas and
//! J. Fridrich, *Minimizing Additive Distortion in Steganography Using
//! Syndrome-Trellis Codes* (IEEE TIFS 2011). A message is embedded by finding
//! the stego LSB vector `x` of minimal additive distortion subject to
//! `H x = m`, where `H` is a banded parity-check matrix derived from the
//! stego key.
//!
//! # Matrix layout
//!
//! `H` has `m = n - h + 1` rows and `n` columns; column `j` contributes the
//! `h`-bit pattern `ĥ` to rows `j-h+1 ..= j`, i.e. `H[i][j] = ĥ[j-i]` for
//! `0 <= j-i < h`. The syndrome of a bit vector `x` is therefore
//!
//! ```text
//! s[i] = XOR over d in 0..h of (h_hat[d] & x[i + d])
//! ```
//!
//! `ĥ` must have its lowest and highest bits set: the highest bit is the
//! current column's influence on the row being finalised (without it some
//! syndrome values are unreachable), and the lowest keeps the newest state bit
//! meaningful.
//!
//! # Cost model
//!
//! Each element may keep its value or move by `±1`, so the distortion is
//! additive over a ternary alphabet with **asymmetric** `rho_plus` /
//! `rho_minus`. Legality is supplied by the caller through [`Move`]: the
//! spatial engine forbids the move that would leave the pixel's eight-value
//! class, the JPEG engine forbids the move that would create a zero
//! coefficient. An illegal direction is simply not offered to the trellis.
//!
//! # Extraction
//!
//! No cost map and no trellis are needed: the receiver recomputes `s = H x`
//! over the stego LSBs. Only the element ordering and `ĥ` have to match.
//!
//! # Complexity
//!
//! `O(n · 2^(h-1) · 2)` time and `n · 2^(h-1)` bits of backtracking memory.
//! `h = 8` (128 states) is the default: `h = 10` is ~4x slower and ~4x larger.

use crate::errors::StrHideError;
use crate::stego::coding::Move;

/// Default constraint height. 128 states, ~2·10^8 transitions for a 600k-slot
/// carrier — around a second in release builds.
pub const DEFAULT_STC_H: u8 = 8;

/// Supported range for `h`. Below 4 the code loses too much efficiency; above
/// 10 the state vector and the backtracking bitmap get expensive.
pub const MIN_STC_H: u8 = 4;
pub const MAX_STC_H: u8 = 10;

/// One embedding trellis: `h` plus the `h`-bit generator row `ĥ`.
///
/// Both ends must build the identical trellis; it is derived from the stego
/// secret and is deliberately *not* public — a known `H` lets an attacker
/// compute the syndrome of any candidate change set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StcTrellis {
    h: u8,
    /// `ĥ` in the low `h` bits, bit `d` == `ĥ[d]`.
    pattern: u32,
    /// `ĥ` with the bit order reversed inside the low `h` bits: column `j`'s
    /// contribution mask when `x_j` is odd.
    reversed: u32,
}

/// What a column did with its element, packed into 2 bits for backtracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Keep = 0,
    Plus = 1,
    Minus = 2,
}

impl Kind {
    fn from_bits(v: u8) -> Self {
        match v {
            1 => Kind::Plus,
            2 => Kind::Minus,
            _ => Kind::Keep,
        }
    }
}

/// Cheapest way to reach one LSB parity for a single element.
#[derive(Debug, Clone, Copy)]
struct ParityOption {
    best: Option<(f64, Kind)>,
}

impl ParityOption {
    fn empty() -> Self {
        Self { best: None }
    }

    fn offer(&mut self, cost: f64, kind: Kind) {
        if cost.is_infinite() {
            return;
        }
        match self.best {
            Some((c, _)) if c <= cost => {}
            _ => self.best = Some((cost, kind)),
        }
    }
}

/// Cheapest way to reach each LSB parity (`0` and `1`) for one element.
fn parity_options(y: u8, mv: Move, rho_plus: f64, rho_minus: f64) -> [ParityOption; 2] {
    let mut opts = [ParityOption::empty(), ParityOption::empty()];
    // Keeping the value always reaches its own parity at zero cost.
    opts[(y & 1) as usize].offer(0.0, Kind::Keep);

    let flipped = ((y & 1) ^ 1) as usize;
    match mv {
        Move::PlusOnly => opts[flipped].offer(rho_plus, Kind::Plus),
        Move::MinusOnly => opts[flipped].offer(rho_minus, Kind::Minus),
        Move::Both => {
            opts[flipped].offer(rho_plus, Kind::Plus);
            opts[flipped].offer(rho_minus, Kind::Minus);
        }
    }
    opts
}

#[inline]
fn message_bit(message: &[u8], idx: usize) -> usize {
    ((message[idx / 8] >> (7 - (idx % 8))) & 1) as usize
}

impl StcTrellis {
    /// Build a trellis from a 64-bit key seed.
    ///
    /// The caller derives `seed` from the stego secret and the per-embed salt,
    /// so two embeds with the same password use different matrices. The lowest
    /// and highest pattern bits are forced to 1; see the module docs for why.
    pub fn from_seed(seed: u64, h: u8) -> Result<Self, StrHideError> {
        validate_h(h)?;
        let mask = (1u32 << h) - 1;
        let mut pattern = (seed as u32) & mask;
        pattern |= 1;
        pattern |= 1 << (h - 1);
        let mut reversed = 0u32;
        for d in 0..h {
            if (pattern >> d) & 1 == 1 {
                reversed |= 1 << (h - 1 - d);
            }
        }
        Ok(Self {
            h,
            pattern,
            reversed,
        })
    }

    pub fn h(&self) -> u8 {
        self.h
    }

    /// Number of message bits carried by `n` elements.
    pub fn message_bits(&self, n: usize) -> usize {
        n.saturating_sub(self.h as usize - 1)
    }

    /// Number of elements needed to carry `bits` message bits.
    pub fn slots_for(&self, bits: usize) -> usize {
        if bits == 0 {
            0
        } else {
            bits + self.h as usize - 1
        }
    }

    /// Recompute the syndrome of the element LSBs (`H x`), MSB-first packed.
    ///
    /// `bits_out` is clamped to `n - h + 1`; padded bits in the last byte are 0.
    pub fn extract(&self, vals: &[u8], bits_out: usize) -> Vec<u8> {
        let bits = bits_out.min(self.message_bits(vals.len()));
        let mut out = vec![0u8; bits.div_ceil(8)];
        for (i, byte) in out.iter_mut().enumerate() {
            let first = i * 8;
            let last = (first + 8).min(bits);
            for bit in first..last {
                let mut s = 0u8;
                for d in 0..self.h as usize {
                    if (self.pattern >> d) & 1 == 1 {
                        s ^= vals[bit + d] & 1;
                    }
                }
                if s != 0 {
                    *byte |= 1 << (7 - (bit % 8));
                }
            }
        }
        out
    }

    /// Embed `message` (MSB-first packed) into `vals`, returning the number of
    /// modified elements.
    ///
    /// `vals.len()` must equal `message_bits + h - 1`. The message is a byte
    /// slice, so its bit count can exceed the matrix's row count by up to 7
    /// padding bits; those trailing bits are ignored (they are not covered by
    /// `H`). Anything more is a caller error rather than silent truncation.
    pub fn embed(
        &self,
        vals: &mut [u8],
        moves: &[Move],
        rho_plus: &[f64],
        rho_minus: &[f64],
        message: &[u8],
    ) -> Result<usize, StrHideError> {
        let n = vals.len();
        let m = self.message_bits(n);
        let bits = message.len() * 8;
        if bits < m || bits - m >= 8 {
            return Err(StrHideError::General(format!(
                "STC message size mismatch: {bits} bits for {n} elements (h={}), expected {m}",
                self.h
            )));
        }
        if moves.len() < n || rho_plus.len() < n || rho_minus.len() < n {
            return Err(StrHideError::General(
                "STC cost/legality arrays disagree with the element count".into(),
            ));
        }
        if n == 0 {
            return Ok(0);
        }

        let h = self.h as usize;
        let states = 1usize << (h - 1);
        let low_mask = (1usize << (h - 1)) - 1;
        let shift_mask = (1usize << (h - 2)) - 1;
        let inf = f64::INFINITY;
        // Column `j`'s contribution to row `j-h+1+d` is `ĥ[h-1-d] & x_j`, so the
        // low `h-1` bits of the mask are `ĥ` reversed and the top bit (row `j`)
        // is `ĥ[0]`.
        let rev = self.reversed as usize;
        let rev_top = (rev >> (h - 1)) & 1;

        let mut cost = vec![0.0f64; states];
        let mut next = vec![inf; states];
        // Two bits per (column, state): 4 decisions per byte.
        let mut back = vec![0u8; (n * states).div_ceil(4)];

        for j in 0..n {
            next.iter_mut().for_each(|c| *c = inf);
            let opts = parity_options(vals[j], moves[j], rho_plus[j], rho_minus[j]);

            // The row finalised by this column, or None before the first one.
            let row = j as isize - (h as isize - 1);
            let want = if row >= 0 {
                message_bit(message, row as usize)
            } else {
                0
            };

            for (state, &base) in cost.iter().enumerate().take(states) {
                if base.is_infinite() {
                    continue;
                }
                for (parity, opt) in opts.iter().enumerate() {
                    let Some((dcost, kind)) = opt.best else {
                        continue;
                    };
                    let c_low = if parity == 1 { rev & low_mask } else { 0 };
                    let c_top = if parity == 1 { rev_top } else { 0 };
                    let combined = state ^ c_low;
                    if row >= 0 && (combined & 1) != want {
                        continue;
                    }
                    let new_state = (combined >> 1) | (c_top << (h - 2));
                    let nc = base + dcost;
                    if nc < next[new_state] {
                        next[new_state] = nc;
                        let idx = j * states + new_state;
                        let shift = (idx & 3) * 2;
                        back[idx >> 2] =
                            (back[idx >> 2] & !(0b11 << shift)) | ((kind as u8) << shift);
                    }
                }
            }

            std::mem::swap(&mut cost, &mut next);
        }

        // Every matrix row is finalised; the trailing `h-1` state bits describe
        // rows past the matrix and are unconstrained, so take the cheapest.
        let mut best_state = usize::MAX;
        let mut best_cost = inf;
        for (state, &c) in cost.iter().enumerate() {
            if c < best_cost {
                best_cost = c;
                best_state = state;
            }
        }
        if best_state == usize::MAX {
            return Err(StrHideError::General(
                "STC embedding has no feasible solution for this message".into(),
            ));
        }

        let mut state = best_state;
        let mut flips = 0usize;
        for j in (0..n).rev() {
            let idx = j * states + state;
            let kind = Kind::from_bits((back[idx >> 2] >> ((idx & 3) * 2)) & 0b11);
            let y = vals[j];
            let new_val = match kind {
                Kind::Keep => y,
                Kind::Plus => y + 1,
                Kind::Minus => y - 1,
            };
            if new_val != y {
                flips += 1;
            }
            vals[j] = new_val;

            // Invert the forward transition.
            let row = j as isize - (h as isize - 1);
            let want = if row >= 0 {
                message_bit(message, row as usize)
            } else {
                0
            };
            let c_low = if (new_val & 1) == 1 {
                rev & low_mask
            } else {
                0
            };
            let combined = ((state & shift_mask) << 1) | want;
            state = combined ^ c_low;
        }

        Ok(flips)
    }
}

/// Validate an STC constraint height at the API boundary.
pub fn validate_h(h: u8) -> Result<(), StrHideError> {
    if !(MIN_STC_H..=MAX_STC_H).contains(&h) {
        return Err(StrHideError::General(format!(
            "STC constraint height must be in {}..={}, got {h}",
            MIN_STC_H, MAX_STC_H
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::coding::{SPATIAL_CLASS, spatial_move};

    fn asym_costs(n: usize) -> (Vec<f64>, Vec<f64>) {
        let plus = (0..n).map(|i| 1.0 + (i % 5) as f64 * 0.5).collect();
        let minus = (0..n).map(|i| 1.0 + (i % 7) as f64 * 0.25).collect();
        (plus, minus)
    }

    /// Compare only the first `bits` bits: the extracted buffer is padded with
    /// zero bits up to a byte boundary, the source message is not.
    fn bits_equal(got: &[u8], want: &[u8], bits: usize) -> bool {
        (0..bits).all(|b| message_bit(got, b) == message_bit(want, b))
    }

    /// Immutable context for the brute-force oracle.
    struct Oracle<'a> {
        t: &'a StcTrellis,
        vals: &'a [u8],
        moves: &'a [Move],
        rp: &'a [f64],
        rm: &'a [f64],
        message: &'a [u8],
        bits: usize,
    }

    impl Oracle<'_> {
        /// Enumerate every legal candidate from slot `i` onward, keeping the
        /// cheapest one whose syndrome matches the message.
        fn walk(&self, i: usize, cur: &mut [u8], cost: f64, best: &mut f64) {
            if i == self.vals.len() {
                if cost >= *best {
                    return; // prune: additive costs only grow
                }
                let syn = self.t.extract(cur, self.bits);
                if bits_equal(&syn, self.message, self.bits) {
                    *best = cost;
                }
                return;
            }
            let y = self.vals[i];
            let upward = match self.moves[i] {
                Move::Both | Move::PlusOnly => Some(self.rp[i]),
                Move::MinusOnly => None,
            };
            let downward = match self.moves[i] {
                Move::Both | Move::MinusOnly => Some(self.rm[i]),
                Move::PlusOnly => None,
            };
            // Keep first, so `cur[i]` is already correct when we recurse.
            self.walk(i + 1, cur, cost, best);
            for (delta, step) in [(1i16, upward), (-1i16, downward)] {
                let Some(step) = step else { continue };
                cur[i] = (y as i16 + delta) as u8;
                self.walk(i + 1, cur, cost + step, best);
            }
            cur[i] = y;
        }
    }

    /// Minimum additive cost over all `3^n` candidates satisfying `H x = m`.
    fn brute_force_min_cost(
        t: &StcTrellis,
        vals: &[u8],
        moves: &[Move],
        rp: &[f64],
        rm: &[f64],
        message: &[u8],
    ) -> f64 {
        let oracle = Oracle {
            t,
            vals,
            moves,
            rp,
            rm,
            message,
            bits: t.message_bits(vals.len()),
        };
        let mut best = f64::INFINITY;
        let mut cur = vals.to_vec();
        oracle.walk(0, &mut cur, 0.0, &mut best);
        best
    }

    #[test]
    fn trellis_shape_and_syndrome_match_the_formula() {
        let t = StcTrellis::from_seed(0xDEAD_BEEF, 4).unwrap();
        let n = 12;
        assert_eq!(t.message_bits(n), n - 3);
        assert_eq!(t.slots_for(9), 12);

        let vals: Vec<u8> = (0..n).map(|i| if i % 3 == 0 { 1 } else { 0 }).collect();
        let got = t.extract(&vals, t.message_bits(n));
        for i in 0..t.message_bits(n) {
            let mut want = 0u8;
            for d in 0..4 {
                if (t.pattern >> d) & 1 == 1 {
                    want ^= vals[i + d] & 1;
                }
            }
            assert_eq!(message_bit(&got, i) as u8, want, "syndrome bit {i}");
        }
    }

    #[test]
    fn embed_matches_exhaustive_optimum_and_round_trips() {
        for (seed, h) in [(1u64, 4u8), (0x1234_5678, 4), (0xABCD, 5)] {
            let t = StcTrellis::from_seed(seed, h).unwrap();
            let n = if h == 4 { 12 } else { 10 };
            let vals: Vec<u8> = (0..n).map(|i| 40 + (i % 8) as u8).collect();
            let moves: Vec<Move> = vals.iter().map(|&v| spatial_move(v)).collect();
            let (rp, rm) = asym_costs(n);
            let bits = t.message_bits(n);
            let message: Vec<u8> = (0..bits.div_ceil(8))
                .map(|i| 0x5Au8.wrapping_mul(i as u8 + 1))
                .collect();

            let mut stego = vals.clone();
            let flips = t.embed(&mut stego, &moves, &rp, &rm, &message).unwrap();
            assert!(
                bits_equal(&t.extract(&stego, bits), &message, bits),
                "h={h}: roundtrip mismatch"
            );

            for (&a, &b) in vals.iter().zip(stego.iter()) {
                assert!(a.abs_diff(b) <= 1, "move too large: {a} -> {b}");
                assert_eq!(
                    a & !(SPATIAL_CLASS - 1),
                    b & !(SPATIAL_CLASS - 1),
                    "class left: {a} -> {b}"
                );
            }

            let achieved: f64 = vals
                .iter()
                .zip(stego.iter())
                .enumerate()
                .map(|(i, (&a, &b))| match b.cmp(&a) {
                    std::cmp::Ordering::Equal => 0.0,
                    std::cmp::Ordering::Greater => rp[i],
                    std::cmp::Ordering::Less => rm[i],
                })
                .sum();
            let optimum = brute_force_min_cost(&t, &vals, &moves, &rp, &rm, &message);
            assert!(
                (achieved - optimum).abs() < 1e-9,
                "h={h}, seed={seed}: STC cost {achieved} != exhaustive optimum {optimum}"
            );
            assert_eq!(
                flips,
                vals.iter()
                    .zip(stego.iter())
                    .filter(|(a, b)| a != b)
                    .count()
            );
        }
    }

    #[test]
    fn wet_direction_is_never_used() {
        let t = StcTrellis::from_seed(7, 4).unwrap();
        let n = 24;
        // Every element sits in the middle of its class, so both directions are
        // legal and `rho_minus = inf` can only be honoured by choosing `+1`.
        // (A class-ceiling value here would freeze that column entirely and the
        // trellis could legitimately report "no feasible solution".)
        let vals: Vec<u8> = (0..n).map(|i| 41 + (i % 6) as u8).collect();
        let moves: Vec<Move> = vals.iter().map(|&v| spatial_move(v)).collect();
        assert!(moves.iter().all(|&m| m == Move::Both));
        let rp = vec![1.0f64; n];
        let rm = vec![f64::INFINITY; n];
        let bits = t.message_bits(n);
        let message: Vec<u8> = (0..bits.div_ceil(8)).map(|i| 0xA5u8 ^ i as u8).collect();

        let mut stego = vals.clone();
        t.embed(&mut stego, &moves, &rp, &rm, &message).unwrap();
        for (&a, &b) in vals.iter().zip(stego.iter()) {
            assert!(b >= a, "wet direction was used: {a} -> {b}");
        }
        assert!(bits_equal(&t.extract(&stego, bits), &message, bits));
    }

    #[test]
    fn message_size_mismatch_and_bad_h_are_rejected() {
        let t = StcTrellis::from_seed(3, 4).unwrap();
        let mut vals = vec![40u8; 12];
        let moves = vec![Move::Both; 12];
        let rp = vec![1.0; 12];
        let rm = vec![1.0; 12];
        assert!(t.embed(&mut vals, &moves, &rp, &rm, b"toolong!!").is_err());
        assert!(StcTrellis::from_seed(1, MAX_STC_H + 1).is_err());
        assert!(StcTrellis::from_seed(1, MIN_STC_H - 1).is_err());
    }
}
