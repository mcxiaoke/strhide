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
//! Elements are split into consecutive **groups** of `u`, and group `g` owns
//! one syndrome row. An element `j` (`g = j/u`, `s = j%u`) contributes the
//! `h`-bit column vector `cols[s]` to rows `g .. g+h-1`, so rows overlap `h`
//! groups deep:
//!
//! ```text
//! s[g] = XOR over d in 0..h of (cols[s][d] & x[g*u + s])
//! ```
//!
//! `u = 1` reduces to the classic one-row-per-element code (`m = n-h+1`), the
//! form the module shipped with. `u > 1` gives `m = n/u - h + 1` message bits
//! per `n` elements, i.e. a relative payload of about `1/u`, at the cost of a
//! proportional capacity loss. Decoding is still a single forward pass.
//!
//! Every column vector has its lowest and highest bits set: the highest bit is
//! that element's influence on the row the group is about to finalise (without
//! it some parities are unreachable), and the lowest keeps the newest state bit
//! meaningful. Within a group the `u` vectors are linearly independent, so the
//! group's `u` elements can steer the syndrome independently instead of
//! collapsing into a single XOR.
//!
//! # Cost model
//!
//! Each element may keep its value or move by `±1`, so the distortion is
//! additive over a ternary alphabet with **asymmetric** `rho_plus` /
//! `rho_minus`. Legality is supplied by the caller through [`Move`]: the
//! spatial engine forbids the move that would leave the pixel's eight-value
//! class, the JPEG engine only blocks the one direction that would overflow the
//! baseline AC range (`|c| = 1023`), plus -- for carriers whose Huffman table is
//! over-optimised -- the direction whose `(run, category)` symbol is missing
//! from that table. An illegal direction is simply not offered.
//!
//! # Extraction
//!
//! No cost map and no trellis are needed: the receiver recomputes `s = H x`
//! over the stego LSBs. Only the element ordering, `u`, `h` and the column
//! vectors have to match.
//!
//! # Complexity
//!
//! `O(n · 2^(h-1+[u>1]) · 2)` time and `n · 2^(h-1+[u>1])` bits of
//! backtracking memory. `u > 1` needs one extra state bit (the row the group
//! is still accumulating), i.e. twice the states of `u = 1`.
//!
//! # Group size beyond `h`
//!
//! The original construction capped `u` at `h` and required the group's column
//! vectors to be linearly independent. Neither is necessary: every column has
//! its top bit forced to 1, so *each* element can steer the row its group is
//! about to finalise, and correlated columns only reduce the number of distinct
//! state transitions, not their reachability. Dropping both lets the JPEG engine
//! spread one payload bit over up to `KERNEL_MAX_U` = 64
//! elements, which is where the change-rate win comes from.

use crate::errors::StrHideError;
use crate::stego::coding::Move;

/// Default constraint height. 128 states, ~2·10^8 transitions for a 600k-slot
/// carrier — around a second in release builds.
pub const DEFAULT_STC_H: u8 = 8;

/// Supported range for `h`. Below 4 the code loses too much efficiency; above
/// 10 the state vector and the backtracking bitmap get expensive.
pub const MIN_STC_H: u8 = 4;
pub const MAX_STC_H: u8 = 10;

/// Largest group size the *spatial* header can express (two spare bits).
///
/// `u = 1` is the classic code; `u > 1` trades capacity for a lower change
/// rate. The spatial codec id has room for three values, so that engine stays
/// at `u <= 3`; the JPEG V3 superblock carries `u` in a full byte and uses
/// `KERNEL_MAX_U` instead.
pub const MAX_STC_U: u8 = 3;

/// Largest group size the kernel supports (the JPEG superblock field width).
///
/// Beyond 64 the state vector and the backtracking bitmap grow linearly while
/// the change-rate gain flattens out.
pub const KERNEL_MAX_U: u8 = 64;

/// One embedding trellis: `h`, the group size `u`, and the per-position column
/// vectors `cols[0..u]`.
///
/// Both ends must build the identical trellis; it is derived from the stego
/// secret and is deliberately *not* public — a known `H` lets an attacker
/// compute the syndrome of any candidate change set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StcTrellis {
    h: u8,
    u: u8,
    /// `cols[s]` holds, in its low `h` bits, the column vector of position `s`
    /// inside a group: bit `d` is that element's contribution to row `g+d`.
    cols: Vec<u32>,
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

/// Cheapest way to *flip* one element's LSB parity.
///
/// Keeping the value always reaches its own parity at zero cost, so a column
/// only ever chooses between "keep" and "flip". Which of the two carries the
/// column XOR is decided by the *cover* parity, never by the state, so the flip
/// direction is an element-level constant -- that is what lets the backtracking
/// bitmap store a single bit per (column, state).
#[derive(Debug, Clone, Copy)]
struct Flip {
    /// Infinite when no legal direction flips the parity (both `rho` infinite).
    cost: f64,
    kind: Kind,
}

#[inline]
fn flip_option(mv: Move, rho_plus: f64, rho_minus: f64) -> Flip {
    // Ties keep `Plus`, matching the `<=` in the old `ParityOption::offer`.
    let (cost, kind) = match mv {
        Move::PlusOnly => (rho_plus, Kind::Plus),
        Move::MinusOnly => (rho_minus, Kind::Minus),
        Move::Both => {
            if rho_plus <= rho_minus {
                (rho_plus, Kind::Plus)
            } else {
                (rho_minus, Kind::Minus)
            }
        }
    };
    Flip { cost, kind }
}

#[inline]
fn message_bit(message: &[u8], idx: usize) -> usize {
    ((message[idx / 8] >> (7 - (idx % 8))) & 1) as usize
}

/// splitmix64: a tiny deterministic mixer, so the column vectors depend only on
/// the caller's seed and never on a platform RNG.
#[inline]
fn splitmix64(state: u64) -> u64 {
    let mut z = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Reverse the low `h` bits of `x`.
#[inline]
fn reverse_low_bits(x: u32, h: u8) -> u32 {
    let mut out = 0u32;
    for d in 0..h {
        if (x >> d) & 1 == 1 {
            out |= 1 << (h - 1 - d);
        }
    }
    out
}

/// Run one trellis column.
///
/// The column is written destination-first: destination `i` has at most one
/// source per parity, read at `base(i)` for "keep" and `base(i) ^ col_mask` for
/// "flip". Expressing it that way removes the two things the old source-ordered
/// form paid for on every state: a data-dependent branch (the candidates are now
/// a branch-free select) and a read-modify-write of `next` (both candidates read
/// the *previous* column, which this column never writes).
///
/// `base(i)` is the identity for an accumulating column, and the group shift with
/// the message bit folded in for a deciding one, so `DECIDE` is a compile-time
/// constant and the two shapes compile to separate, unswitched loops.
///
/// `TWO_WAY` says whether an element really has a choice:
///
/// * `u > 1` — the state carries the "extra" bit of row `g+h-1`, the destination
///   drops it, and both parities reach the same destination from different
///   sources, so the column is a genuine two-way min.
/// * `u = 1` — there is no extra bit, so the destination's top bit holds the
///   element's *post-move parity* instead. That bit fixes whether the element
///   flipped, so each destination has exactly one source: the column is a plain
///   permutation plus a constant. (This is why `u = 1` has a 0.5 change rate and
///   buys no coding gain -- it is a `(1,1)` parity code, not a trellis search.)
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn transfer_column<const DECIDE: bool, const TWO_WAY: bool>(
    states: usize,
    state_mask: usize,
    want: usize,
    parity_bit: u32,
    col_mask: usize,
    cover_parity: usize,
    flip_cost: f64,
    cost: &[f64],
    next: &mut [f64],
    bits: &mut [u64],
) {
    // A deciding column with an extra bit halves the reachable set; without one
    // the destination's top bit is parity information, so it stays full width.
    let dests = if DECIDE && TWO_WAY {
        states >> 1
    } else {
        states
    };
    // "Keep" lands on the cover parity, so it applies the column XOR exactly
    // when that parity is 1; "flip" lands on the other parity.
    let (xor_keep, xor_flip) = if cover_parity == 1 {
        (col_mask, 0)
    } else {
        (0, col_mask)
    };

    if TWO_WAY && flip_cost.is_finite() {
        for (w, slot) in bits.iter_mut().enumerate() {
            let lo = w * 64;
            if lo >= dests {
                // Trailing words of a shortened column (a deciding column with
                // an extra bit only fills half the bitmap).
                *slot = 0;
                continue;
            }
            let hi = (lo + 64).min(dests);
            let mut acc = 0u64;
            for (off, out) in next[lo..hi].iter_mut().enumerate() {
                let i = lo + off;
                let base = if DECIDE {
                    ((i << 1) | want) & state_mask
                } else {
                    i
                };
                let keep = cost[base ^ xor_keep];
                let flip = cost[base ^ xor_flip] + flip_cost;
                let take = flip < keep;
                acc |= u64::from(take) << (i & 63);
                *out = if take { flip } else { keep };
            }
            *slot = acc;
        }
    } else if TWO_WAY {
        // No legal direction flips the parity: the column is a pure state
        // transfer, every element keeps its value, so the decisions stay 0.
        for (w, slot) in bits.iter_mut().enumerate() {
            let lo = w * 64;
            if lo >= dests {
                // Trailing words of a shortened column (a deciding column with
                // an extra bit only fills half the bitmap).
                *slot = 0;
                continue;
            }
            let hi = (lo + 64).min(dests);
            for (off, out) in next[lo..hi].iter_mut().enumerate() {
                let i = lo + off;
                let base = if DECIDE {
                    ((i << 1) | want) & state_mask
                } else {
                    i
                };
                *out = cost[base ^ xor_keep];
            }
            *slot = 0;
        }
    } else {
        // `u = 1`: the destination dictates the parity, hence the direction.
        for (w, slot) in bits.iter_mut().enumerate() {
            let lo = w * 64;
            if lo >= dests {
                // Trailing words of a shortened column (a deciding column with
                // an extra bit only fills half the bitmap).
                *slot = 0;
                continue;
            }
            let hi = (lo + 64).min(dests);
            let mut acc = 0u64;
            for (off, out) in next[lo..hi].iter_mut().enumerate() {
                let i = lo + off;
                let base = ((i << 1) | want) & state_mask;
                let parity = (i >> parity_bit) & 1;
                let src = if parity == 1 { base ^ col_mask } else { base };
                let step = if parity == cover_parity {
                    0.0
                } else {
                    flip_cost
                };
                *out = cost[src] + step;
                acc |= ((parity ^ cover_parity) as u64) << (i & 63);
            }
            *slot = acc;
        }
    }

    if DECIDE && TWO_WAY {
        // The states whose top bit would describe a row past this group are
        // unreachable from here on.
        next[dests..states].fill(f64::INFINITY);
    }
}

impl StcTrellis {
    /// Build a single-row-per-element trellis (`u = 1`) from a 64-bit seed.
    ///
    /// The caller derives `seed` from the stego secret and the per-embed salt,
    /// so two embeds with the same password use different matrices.
    pub fn from_seed(seed: u64, h: u8) -> Result<Self, StrHideError> {
        Self::from_seed_grouped(seed, h, 1)
    }

    /// Build a trellis whose `u` columns share one syndrome row (`u = 1` is the
    /// classic form). The caller must pass the same `u` on both ends — the JPEG
    /// superblock and the spatial header both carry it.
    ///
    /// `u` may exceed `h`: see the module docs for why the top bit alone makes
    /// every element able to steer its group's row. Identical vectors inside one
    /// group are skipped while enough distinct patterns remain (a `u=2` group of
    /// two equal vectors embeds at twice the change rate), so the derivation is
    /// no longer the raw splitmix stream for the second and later columns.
    pub fn from_seed_grouped(seed: u64, h: u8, u: u8) -> Result<Self, StrHideError> {
        validate_h(h)?;
        validate_u_wide(u)?;

        let mask = (1u32 << h) - 1;
        let pattern = |idx: u64| {
            let mut x = (splitmix64(seed.wrapping_add(idx)) as u32) & mask;
            // The low and high bits are forced: see the module docs.
            x |= 1;
            x |= 1 << (h - 1);
            reverse_low_bits(x, h)
        };
        // Only the `h - 2` free bits can distinguish columns; past that many
        // columns a duplicate cannot be avoided.
        let distinct_patterns = 1u64 << (h - 2);
        let mut cols = Vec::with_capacity(u as usize);
        for s in 0..u as u64 {
            let mut idx = s;
            let mut col = pattern(idx);
            while (cols.len() as u64) < distinct_patterns && cols.contains(&col) {
                idx = idx.wrapping_add(u as u64);
                col = pattern(idx);
            }
            cols.push(col);
        }

        Ok(Self { h, u, cols })
    }

    pub fn h(&self) -> u8 {
        self.h
    }

    pub fn u(&self) -> u8 {
        self.u
    }

    /// Number of message bits carried by `n` elements.
    ///
    /// `n` is expected to be a multiple of `u`; a remainder is rounded down, so
    /// callers that ask for `slots_for(bits)` back always get the exact value.
    pub fn message_bits(&self, n: usize) -> usize {
        (n / self.u as usize).saturating_sub(self.h as usize - 1)
    }

    /// Number of elements needed to carry `bits` message bits.
    pub fn slots_for(&self, bits: usize) -> usize {
        if bits == 0 {
            0
        } else {
            self.u as usize * (bits + self.h as usize - 1)
        }
    }

    /// Recompute the syndrome of the element LSBs (`H x`), MSB-first packed.
    ///
    /// `bits_out` is clamped to `n/u - h + 1`; padded bits in the last byte
    /// are 0.
    pub fn extract(&self, vals: &[u8], bits_out: usize) -> Vec<u8> {
        let n = vals.len();
        let h = self.h as usize;
        let bits = bits_out.min(self.message_bits(n));
        let mut out = vec![0u8; bits.div_ceil(8)];
        if bits == 0 {
            return out;
        }

        for b in 0..bits {
            // Byte b of the message is row b + (h-1): the first h-1 rows are
            // the trellis warm-up and carry no message bit.
            if self.row_syndrome(vals, b + (h - 1)) != 0 {
                out[b / 8] |= 1 << (7 - (b % 8));
            }
        }
        out
    }

    /// Syndrome value of one matrix row: the XOR of every element whose column
    /// vector sets the bit for that row.
    ///
    /// Row `r` is owned by group `r` and is also touched by the `h-1` groups
    /// before it, so the element window is `[(r-h+1)*u, (r+1)*u)`.
    #[inline]
    fn row_syndrome(&self, vals: &[u8], row: usize) -> u8 {
        let u = self.u as usize;
        let h = self.h as usize;
        let mut s = 0u8;
        for g in row.saturating_sub(h - 1)..=row {
            let d = row - g;
            for (si, &col) in self.cols.iter().enumerate().take(u) {
                if (col >> d) & 1 == 1 {
                    s ^= vals[g * u + si] & 1;
                }
            }
        }
        s
    }

    /// Embed `message` (MSB-first packed) into `vals`, returning the number of
    /// modified elements.
    ///
    /// Thin wrapper over [`Self::embed_with_deltas`]: solve once, then apply the
    /// `-1 / 0 / +1` decisions to `vals`.
    pub fn embed(
        &self,
        vals: &mut [u8],
        moves: &[Move],
        rho_plus: &[f64],
        rho_minus: &[f64],
        message: &[u8],
    ) -> Result<usize, StrHideError> {
        let mut deltas = vec![0i8; vals.len()];
        let flips =
            self.embed_with_deltas(vals, moves, rho_plus, rho_minus, message, &mut deltas)?;
        for (val, &delta) in vals.iter_mut().zip(deltas.iter()) {
            if delta != 0 {
                *val = (*val as i16 + delta as i16) as u8;
            }
        }
        Ok(flips)
    }

    /// Solve `H x = m` and report every element's `-1 / 0 / +1` decision.
    ///
    /// The trellis works on parity carriers, but a DCT coefficient is an `i16`
    /// that must be *moved* rather than assigned a parity. `deltas[j]` is
    /// exactly that move for element `j`; `vals` is left untouched so the
    /// caller can apply the delta to the real coefficient.
    ///
    /// `vals.len()` must equal `slots_for(message bits)`, i.e. a multiple of
    /// `u`. The message is a byte slice, so its bit count can exceed the
    /// matrix's row count by up to 7 padding bits; those trailing bits are
    /// ignored (they are not covered by `H`). Anything more is a caller error
    /// rather than silent truncation.
    pub fn embed_with_deltas(
        &self,
        vals: &[u8],
        moves: &[Move],
        rho_plus: &[f64],
        rho_minus: &[f64],
        message: &[u8],
        deltas: &mut [i8],
    ) -> Result<usize, StrHideError> {
        let n = vals.len();
        if moves.len() < n || rho_plus.len() < n || rho_minus.len() < n {
            return Err(StrHideError::General(
                "STC cost/legality arrays disagree with the element count".into(),
            ));
        }
        self.embed_with_cost_fn(
            vals,
            moves,
            |j| (rho_plus[j], rho_minus[j]),
            message,
            deltas,
        )
    }

    /// Flexible STC embedding where costs are generated via a closure or lookup function.
    ///
    /// Avoids preallocating hundreds of megabytes of `f64` arrays on large carriers.
    pub fn embed_with_cost_fn<F>(
        &self,
        vals: &[u8],
        moves: &[Move],
        mut cost_fn: F,
        message: &[u8],
        deltas: &mut [i8],
    ) -> Result<usize, StrHideError>
    where
        F: FnMut(usize) -> (f64, f64),
    {
        let n = vals.len();
        let u = self.u as usize;
        let h = self.h as usize;
        let m = self.message_bits(n);
        let bits = message.len() * 8;
        if bits < m || bits - m >= 8 {
            return Err(StrHideError::General(format!(
                "STC message size mismatch: {bits} bits for {n} elements (h={}, u={}), expected {m}",
                self.h, self.u
            )));
        }
        if moves.len() < n {
            return Err(StrHideError::General(
                "STC moves array disagrees with the element count".into(),
            ));
        }
        if deltas.len() < n {
            return Err(StrHideError::General(
                "STC delta buffer is shorter than the element count".into(),
            ));
        }
        if n == 0 {
            return Ok(0);
        }
        if !n.is_multiple_of(u) {
            return Err(StrHideError::General(format!(
                "STC element count {n} is not a multiple of the group size u={u}"
            )));
        }

        // `u = 1` is a `(1,1)` parity code, not a search: the `h-1` warm-up rows
        // plus the message rows pin down every one of the `n` elements, so the
        // trellis has exactly one live state per column and the solution is
        // unique. The cost map cannot move a single flip -- it only chooses the
        // `+1`/`-1` direction -- so walking the chain is `O(n)` instead of
        // `O(n * 2^(h-1))` and produces bit-identical deltas.
        if u == 1 {
            let col = self.cols[0] as usize;
            let low_mask = (1usize << (h - 1)) - 1;
            let col_low = col & low_mask;
            let col_top = (col >> (h - 1)) & 1;
            let mut state = 0usize;
            let mut flips = 0usize;
            for j in 0..n {
                let (rp, rm) = cost_fn(j);
                let flip = flip_option(moves[j], rp, rm);
                let cover_parity = (vals[j] & 1) as usize;
                let row = j as isize - (h as isize - 1);
                let want = if row >= 0 {
                    message_bit(message, row as usize)
                } else {
                    0
                };
                // Exactly one of the two branches satisfies the row constraint:
                // the one whose post-move parity is `want ^ (state & 1)`.
                let parity = want ^ (state & 1);
                if parity != cover_parity {
                    if !flip.cost.is_finite() {
                        return Err(StrHideError::TrellisInfeasible {
                            cause: crate::errors::TrellisCause::DeadElement,
                            detail: format!(
                                "no legal element direction exists for element {j}, which must change parity"
                            ),
                        });
                    }
                    deltas[j] = if matches!(flip.kind, Kind::Plus) {
                        1
                    } else {
                        -1
                    };
                    flips += 1;
                } else {
                    deltas[j] = 0;
                }
                state = if parity == 1 {
                    ((state ^ col_low) >> 1) | (col_top << (h - 2))
                } else {
                    state >> 1
                };
            }
            return Ok(flips);
        }

        // State: `h-1` bits covering rows `g .. g+h-2`, plus — only when a group
        // spans several elements — one extra bit for row `g+h-1`, which the
        // rest of the group is still adding to.
        let store_extra = u > 1;
        let state_bits = (h - 1) + usize::from(store_extra);
        let states = 1usize << state_bits;
        let state_mask = states - 1;
        let low_mask = (1usize << (h - 1)) - 1;
        let extra_shift = h - 1;
        let inf = f64::INFINITY;

        let mut cost = vec![inf; states];
        cost[0] = 0.0;
        let mut next = vec![inf; states];
        // One bit per (column, state): 1 = this element's parity was flipped.
        //
        // Which *direction* that flip takes is an element-level constant -- both
        // `+1` and `-1` flip the parity, so the cheaper legal one wins no matter
        // what the state is. Storing the direction per element instead of per
        // state halves the bitmap and keeps the inner loop at one bit per state.
        let words_per_col = states.div_ceil(64);
        let mut back = vec![0u64; n * words_per_col];
        let mut flip_kinds = vec![Kind::Keep as u8; n];
        #[cfg(target_arch = "x86_64")]
        let avx2 = std::arch::is_x86_feature_detected!("avx2") && n >= 64;

        for j in 0..n {
            let g = j / u;
            let s = j % u;
            // The column vector *is* the state-XOR mask: its bit `d` is this
            // element's contribution to row `g+d`, and the state is indexed by
            // exactly those rows. For `u = 1` the top bit belongs to a row the
            // state does not carry, hence the mask.
            let col_mask = (self.cols[s] as usize) & state_mask;
            let (rp, rm) = cost_fn(j);
            let flip = flip_option(moves[j], rp, rm);
            flip_kinds[j] = flip.kind as u8;
            let cover_parity = (vals[j] & 1) as usize;

            let col_back = &mut back[j * words_per_col..(j + 1) * words_per_col];
            // Accumulating columns are two thirds of the work at u = 3 and are
            // the ones a vector kernel can serve without any index gymnastics.
            #[cfg(target_arch = "x86_64")]
            if s + 1 != u && avx2 {
                // SAFETY: `avx2` is `is_x86_feature_detected!("avx2")`, checked
                // once for the whole embed.
                unsafe {
                    accumulate_xor_avx2(
                        states,
                        col_mask,
                        flip.cost,
                        cover_parity == 0,
                        &cost,
                        &mut next,
                        col_back,
                    );
                }
                std::mem::swap(&mut cost, &mut next);
                continue;
            }
            if s + 1 == u {
                let row = g as isize - (h as isize - 1);
                let want = if row >= 0 {
                    message_bit(message, row as usize)
                } else {
                    0
                };
                let parity_bit = state_bits as u32 - 1;
                if store_extra {
                    transfer_column::<true, true>(
                        states,
                        state_mask,
                        want,
                        parity_bit,
                        col_mask,
                        cover_parity,
                        flip.cost,
                        &cost,
                        &mut next,
                        col_back,
                    );
                } else {
                    transfer_column::<true, false>(
                        states,
                        state_mask,
                        want,
                        parity_bit,
                        col_mask,
                        cover_parity,
                        flip.cost,
                        &cost,
                        &mut next,
                        col_back,
                    );
                }
            } else {
                transfer_column::<false, true>(
                    states,
                    state_mask,
                    0,
                    state_bits as u32 - 1,
                    col_mask,
                    cover_parity,
                    flip.cost,
                    &cost,
                    &mut next,
                    col_back,
                );
            }

            std::mem::swap(&mut cost, &mut next);
        }

        // Every matrix row is finalised; a trailing partial group leaves the
        // remaining state bits describing rows past the matrix, so take the
        // cheapest.
        let mut best_state = usize::MAX;
        let mut best_cost = inf;
        for (state, &c) in cost.iter().enumerate() {
            if c < best_cost {
                best_cost = c;
                best_state = state;
            }
        }
        if best_state == usize::MAX {
            // Not a retryable condition: re-seeding would leave the extractor
            // unable to know which round was used, i.e. it would brick the
            // carrier. It can only happen when a caller hands over an element
            // with no legal direction at all (both `rho` values infinite).
            return Err(StrHideError::TrellisInfeasible {
                cause: crate::errors::TrellisCause::DeadGroup,
                detail: "a group has no legal element (both directions illegal for every element)"
                    .into(),
            });
        }

        let mut state = best_state;
        let mut flips = 0usize;
        for j in (0..n).rev() {
            // `state` is the state *after* column `j`, which is exactly the
            // destination index the forward pass just wrote.
            let flipped = (back[j * words_per_col + (state >> 6)] >> (state & 63)) & 1 == 1;
            let delta: i8 = if flipped {
                match Kind::from_bits(flip_kinds[j]) {
                    Kind::Keep => 0,
                    Kind::Plus => 1,
                    Kind::Minus => -1,
                }
            } else {
                0
            };
            if delta != 0 {
                flips += 1;
            }
            deltas[j] = delta;
            let new_val = (vals[j] as i16 + delta as i16) as u8;

            // Invert the forward transition: undo the group shift first, then
            // the column XOR.
            let g = j / u;
            let s = j % u;
            let col = self.cols[s] as usize;
            let col_low = col & low_mask;
            let col_top = (col >> (h - 1)) & 1;
            let parity = (new_val & 1) == 1;

            let nst = state & low_mask;
            let nex = if store_extra { state >> extra_shift } else { 0 };
            let (st1, ex1) = if s == u - 1 {
                let row = g as isize - (h as isize - 1);
                let want = if row >= 0 {
                    message_bit(message, row as usize)
                } else {
                    0
                };
                let st1 = ((nst & ((1usize << (h - 2)) - 1)) << 1) | want;
                let ex1 = (nst >> (h - 2)) & 1;
                (st1, ex1)
            } else {
                (nst, nex)
            };
            let st = if parity { st1 ^ col_low } else { st1 };
            let extra = if parity { ex1 ^ col_top } else { ex1 };
            state = if store_extra {
                st | (extra << extra_shift)
            } else {
                st
            };
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

/// Validate a group size for the spatial codec, whose header has two bits.
pub fn validate_u(u: u8) -> Result<(), StrHideError> {
    if !(1..=MAX_STC_U).contains(&u) {
        return Err(StrHideError::General(format!(
            "STC group size must be in 1..={MAX_STC_U}, got {u}"
        )));
    }
    Ok(())
}

/// Validate a group size for the JPEG superblock, which carries a full byte.
pub fn validate_u_wide(u: u8) -> Result<(), StrHideError> {
    if !(1..=KERNEL_MAX_U).contains(&u) {
        return Err(StrHideError::General(format!(
            "STC group size must be in 1..={KERNEL_MAX_U}, got {u}"
        )));
    }
    Ok(())
}

/// AVX2 kernel for an accumulating column (`u > 1`, `s < u-1`).
///
/// Both candidates of a destination differ only by the state XOR, and XOR by a
/// column vector is a *bit-flip permutation*: for four consecutive destinations
/// `i..i+4` the four sources `(i+k) ^ d` are exactly one aligned four-double
/// block at `i ^ (d & !3)`, shuffled inside the block by `k ^ (d & 3)`. So the
/// "gather" that stops LLVM from vectorising this loop becomes one aligned load
/// plus one `vpermq`, and the min/select becomes `vcmppd` + `vblendvpd`, with
/// `vmovmskpd` producing the four decision bits in one instruction.
///
/// `keep_plain` says whether the *keep* candidate is the un-XORed one, which is
/// just `cover_parity == 0`: keeping the value lands on the cover parity, and
/// only parity 1 applies the column XOR.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn accumulate_xor_avx2(
    states: usize,
    d: usize,
    flip_cost: f64,
    keep_plain: bool,
    cost: &[f64],
    next: &mut [f64],
    bits: &mut [u64],
) {
    use std::arch::x86_64::*;

    // SAFETY: the caller checked `is_x86_feature_detected!("avx2")`, and every
    // load/store below stays inside `cost` / `next` / `bits`: `i < states`,
    // `(i ^ block) + 3 < states` because the XOR of two `states`-bounded indices
    // is `states`-bounded and `states` is a multiple of four.
    unsafe {
        let lane_xor = d & 3;
        // Lane permutation inside a four-double block: lane `j` <- lane `j ^ (d & 3)`.
        let mut idx_words = [0i32; 8];
        for j in 0..4 {
            let src = ((j ^ lane_xor) * 2) as i32;
            idx_words[2 * j] = src;
            idx_words[2 * j + 1] = src + 1;
        }
        let idx = _mm256_loadu_si256(idx_words.as_ptr() as *const __m256i);
        let cf = _mm256_set1_pd(flip_cost);
        let block = d & !3usize;

        for (w, slot) in bits.iter_mut().enumerate() {
            let lo = w * 64;
            if lo >= states {
                *slot = 0;
                continue;
            }
            let hi = (lo + 64).min(states);
            let mut acc = 0u64;
            let mut i = lo;
            while i + 4 <= hi {
                let plain = _mm256_loadu_pd(cost.as_ptr().add(i));
                let raw = _mm256_loadu_pd(cost.as_ptr().add(i ^ block));
                let permuted = if lane_xor == 0 {
                    raw
                } else {
                    _mm256_castsi256_pd(_mm256_permutevar8x32_epi32(_mm256_castpd_si256(raw), idx))
                };
                let (keep, flip) = if keep_plain {
                    (plain, _mm256_add_pd(permuted, cf))
                } else {
                    (permuted, _mm256_add_pd(plain, cf))
                };
                let take = _mm256_cmp_pd::<_CMP_LT_OQ>(flip, keep);
                _mm256_storeu_pd(next.as_mut_ptr().add(i), _mm256_blendv_pd(keep, flip, take));
                acc |= (_mm256_movemask_pd(take) as u64) << (i & 63);
                i += 4;
            }
            // The tail is never longer than three states and never happens for a
            // power-of-two column, but keep the scalar path so the kernel stays
            // correct if that ever changes.
            while i < hi {
                let keep = cost[i ^ if keep_plain { 0 } else { d }];
                let flip = cost[i ^ if keep_plain { d } else { 0 }] + flip_cost;
                let take = flip < keep;
                next[i] = if take { flip } else { keep };
                acc |= u64::from(take) << (i & 63);
                i += 1;
            }
            *slot = acc;
        }
    }
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
    }

    impl Oracle<'_> {
        /// Every row of `H` must hold: the warm-up rows decode as zero (the
        /// encoder constrains them too) and the rest carry the message. Row
        /// `h - 1` is the *first* message row (message bit 0, see `extract`),
        /// so the warm-up rows are exactly `0..h-1`.
        fn matches(&self, cur: &[u8]) -> bool {
            let groups = self.vals.len() / self.t.u() as usize;
            let h = self.t.h() as usize;
            (0..groups).all(|row| {
                let want = if row + 1 >= h {
                    message_bit(self.message, row - (h - 1))
                } else {
                    0
                };
                self.t.row_syndrome(cur, row) as usize == want
            })
        }

        /// Enumerate every legal candidate from slot `i` onward, keeping the
        /// cheapest one whose syndrome matches the message.
        fn walk(&self, i: usize, cur: &mut [u8], cost: f64, best: &mut f64) {
            if i == self.vals.len() {
                if cost >= *best {
                    return; // prune: additive costs only grow
                }
                if self.matches(cur) {
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
        };
        let mut best = f64::INFINITY;
        let mut cur = vals.to_vec();
        oracle.walk(0, &mut cur, 0.0, &mut best);
        best
    }

    /// Achieved cost of a concrete cover/stego pair.
    fn achieved_cost(vals: &[u8], stego: &[u8], rp: &[f64], rm: &[f64]) -> f64 {
        vals.iter()
            .zip(stego.iter())
            .enumerate()
            .map(|(i, (&a, &b))| match b.cmp(&a) {
                std::cmp::Ordering::Equal => 0.0,
                std::cmp::Ordering::Greater => rp[i],
                std::cmp::Ordering::Less => rm[i],
            })
            .sum()
    }

    #[test]
    fn trellis_shape_and_syndrome_match_the_formula() {
        let t = StcTrellis::from_seed(0xDEAD_BEEF, 4).unwrap();
        let n = 12;
        assert_eq!(t.message_bits(n), n - 3);
        assert_eq!(t.slots_for(9), 12);

        let vals: Vec<u8> = (0..n).map(|i| if i % 3 == 0 { 1 } else { 0 }).collect();
        // `extract` clamps to `n/u - h + 1` bits, so ask for the maximum and
        // compare every bit against the documented formula.
        let got = t.extract(&vals, t.message_bits(n));
        for b in 0..t.message_bits(n) {
            let row = b + 3;
            let mut want = 0u8;
            for g in (row - 3)..=row {
                let d = row - g;
                for si in 0..t.u() as usize {
                    if (t.cols[si] >> d) & 1 == 1 {
                        want ^= vals[g * t.u() as usize + si] & 1;
                    }
                }
            }
            assert_eq!(message_bit(&got, b) as u8, want, "syndrome bit {b}");
        }
    }

    /// `u > 1` must reproduce the same syndrome formula: group `g` owns row
    /// `g`, and the message bit `b` is read from row `b + h - 1`.
    #[test]
    fn grouped_trellis_shape_and_syndrome_match_the_formula() {
        for (u, h) in [(2u8, 4u8), (3, 4), (2, 6), (3, 8)] {
            let t = StcTrellis::from_seed_grouped(0x1234_ABCD, h, u).unwrap();
            assert_eq!(t.u(), u);
            let groups = 24usize;
            let n = groups * u as usize;
            assert_eq!(t.message_bits(n), groups - (h as usize - 1));
            assert_eq!(t.slots_for(t.message_bits(n)), n);

            let vals: Vec<u8> = (0..n).map(|i| (i * 5 % 8) as u8).collect();
            let got = t.extract(&vals, t.message_bits(n));
            for b in 0..t.message_bits(n) {
                let row = b + (h as usize - 1);
                let mut want = 0u8;
                for g in (row - (h as usize - 1))..=row {
                    let d = row - g;
                    for si in 0..u as usize {
                        if (t.cols[si] >> d) & 1 == 1 {
                            want ^= vals[g * u as usize + si] & 1;
                        }
                    }
                }
                assert_eq!(message_bit(&got, b) as u8, want, "u={u} h={h} bit {b}");
            }
        }
    }

    #[test]
    fn embed_matches_exhaustive_optimum_and_round_trips() {
        for (seed, h, u) in [
            (1u64, 4u8, 1u8),
            (0x1234_5678, 4, 1),
            (0xABCD, 5, 1),
            (7, 4, 2),
            (0xFEED, 4, 2),
            (0x9999, 4, 3),
        ] {
            let t = StcTrellis::from_seed_grouped(seed, h, u).unwrap();
            let n = if h == 4 { 12 } else { 10 };
            let vals: Vec<u8> = (0..n).map(|i| 40 + (i % 8) as u8).collect();
            let moves: Vec<Move> = vals.iter().map(|&v| spatial_move(v)).collect();
            let (rp, rm) = asym_costs(n);
            let bits = t.message_bits(n);
            // 0xA5 puts a 1 in the first message bit. The oracle's warm-row
            // boundary used to be off by one, constraining row h-1 to zero
            // while the embedder writes message bit 0 there; a leading 0x5A
            // byte masked that discrepancy for years.
            let message: Vec<u8> = (0..bits.div_ceil(8))
                .map(|i| 0xA5u8.wrapping_mul(i as u8 + 1))
                .collect();

            let mut stego = vals.clone();
            let flips = t.embed(&mut stego, &moves, &rp, &rm, &message).unwrap();
            assert!(
                bits_equal(&t.extract(&stego, bits), &message, bits),
                "h={h} u={u}: roundtrip mismatch"
            );

            for (&a, &b) in vals.iter().zip(stego.iter()) {
                assert!(a.abs_diff(b) <= 1, "move too large: {a} -> {b}");
                assert_eq!(
                    a & !(SPATIAL_CLASS - 1),
                    b & !(SPATIAL_CLASS - 1),
                    "class left: {a} -> {b}"
                );
            }

            let achieved = achieved_cost(&vals, &stego, &rp, &rm);
            let optimum = brute_force_min_cost(&t, &vals, &moves, &rp, &rm, &message);
            assert!(
                (achieved - optimum).abs() < 1e-9,
                "h={h} u={u} seed={seed}: STC cost {achieved} != exhaustive optimum {optimum}"
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
        for u in [1u8, 2] {
            let t = StcTrellis::from_seed_grouped(7, 4, u).unwrap();
            let n = 24;
            // Every element sits in the middle of its class, so both directions
            // are legal and `rho_minus = inf` can only be honoured by choosing
            // `+1`.
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
                assert!(b >= a, "u={u}: wet direction was used: {a} -> {b}");
            }
            assert!(bits_equal(&t.extract(&stego, bits), &message, bits));
        }
    }

    /// The whole point of `u > 1`: at the same number of elements it changes
    /// strictly fewer of them than the `u = 1` code, because each change is
    /// amortised over `u` elements.
    #[test]
    fn larger_groups_lower_the_change_rate() {
        let n = 960;
        let mut rates = Vec::new();
        for u in [1u8, 2, 3] {
            let t = StcTrellis::from_seed_grouped(0x5EED, 8, u).unwrap();
            let vals: Vec<u8> = (0..n).map(|i| 40 + (i % 8) as u8).collect();
            let moves: Vec<Move> = vals.iter().map(|&v| spatial_move(v)).collect();
            let rp = vec![1.0f64; n];
            let rm = vec![1.0f64; n];
            let bits = t.message_bits(n);
            let message: Vec<u8> = (0..bits.div_ceil(8)).map(|i| (i * 37) as u8).collect();

            let mut stego = vals.clone();
            t.embed(&mut stego, &moves, &rp, &rm, &message).unwrap();
            let flips = vals
                .iter()
                .zip(stego.iter())
                .filter(|(a, b)| a != b)
                .count();
            rates.push(flips as f64 / n as f64);
        }
        assert!(
            rates[1] < rates[0] * 0.85,
            "u=2 must cut the change rate by >15%: {rates:?}"
        );
        assert!(
            rates[2] < rates[1],
            "u=3 must beat u=2 on the same element budget: {rates:?}"
        );
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
        assert!(StcTrellis::from_seed_grouped(1, 8, 0).is_err());
        assert!(StcTrellis::from_seed_grouped(1, 8, KERNEL_MAX_U + 1).is_err());
        // `u > h` is legal now: every column carries the top bit, so each
        // element can steer the row its group finalises.
        assert!(StcTrellis::from_seed_grouped(1, 4, 5).is_ok());
        assert!(StcTrellis::from_seed_grouped(1, 4, KERNEL_MAX_U).is_ok());
        // The spatial header still only has room for three values.
        assert!(validate_u(0).is_err());
        assert!(validate_u(MAX_STC_U + 1).is_err());
        assert!(validate_u_wide(0).is_err());
        assert!(validate_u_wide(KERNEL_MAX_U).is_ok());
        assert!(validate_u_wide(KERNEL_MAX_U + 1).is_err());
    }

    /// The delta report must be exactly "stego value minus cover value", and
    /// `embed` must be nothing but that delta applied.
    #[test]
    fn deltas_match_the_updated_values_for_wide_groups() {
        for (h, u) in [(8u8, 1u8), (8, 2), (8, 6), (6, 24), (4, 64)] {
            let t = StcTrellis::from_seed_grouped(0x1234_5678, h, u).unwrap();
            let n = 960usize;
            assert_eq!(n % u as usize, 0);
            let cover: Vec<u8> = (0..n).map(|i| 2 + ((i * 7) % 2) as u8).collect();
            let vals = cover.clone();
            let moves = vec![Move::Both; n];
            let (rp, rm) = asym_costs(n);
            let bits = t.message_bits(n);
            let message: Vec<u8> = (0..bits.div_ceil(8))
                .map(|i| (i as u8).wrapping_mul(41))
                .collect();

            let mut deltas = vec![0i8; n];
            let flips = t
                .embed_with_deltas(&vals, &moves, &rp, &rm, &message, &mut deltas)
                .unwrap();

            let mut stego = vals.clone();
            let flips2 = t.embed(&mut stego, &moves, &rp, &rm, &message).unwrap();
            assert_eq!(flips, flips2, "h={h} u={u}");
            for i in 0..n {
                assert_eq!(
                    stego[i] as i16,
                    vals[i] as i16 + deltas[i] as i16,
                    "h={h} u={u} slot {i}"
                );
                assert!(deltas[i].abs() <= 1);
            }
            assert_eq!(
                flips,
                deltas.iter().filter(|&&d| d != 0).count(),
                "h={h} u={u}: flip count"
            );
            assert!(
                bits_equal(&t.extract(&stego, bits), &message, bits),
                "h={h} u={u}: roundtrip"
            );
            // `vals` is an input only: `embed_with_deltas` must not touch it.
            assert_eq!(vals, cover);
        }
    }

    /// `u = 64` with hostile inputs: flat covers, one legal direction only,
    /// saturated costs. The plan's claim is that none of these needs a retry,
    /// because every element can always reach both parities.
    #[test]
    fn extreme_costs_never_need_a_retry() {
        let (h, u) = (8u8, KERNEL_MAX_U);
        let t = StcTrellis::from_seed_grouped(0xABCD_1234, h, u).unwrap();
        let n = 64 * 30;
        let bits = t.message_bits(n);
        let message: Vec<u8> = (0..bits.div_ceil(8)).map(|i| 0xFFu8 ^ i as u8).collect();

        for case in 0..10 {
            let vals: Vec<u8> = (0..n)
                .map(|i| match case % 5 {
                    // The flattest possible cover: one parity everywhere.
                    0 => 2,
                    1 => 3,
                    2 => {
                        if i % 2 == 0 {
                            2
                        } else {
                            3
                        }
                    }
                    3 => 2 | (((i as u32).wrapping_mul(2654435761) >> 13) & 1) as u8,
                    // Long runs, so whole groups share a parity.
                    _ => 2 | ((i / 37) & 1) as u8,
                })
                .collect();
            let moves: Vec<Move> = (0..n)
                .map(|i| match case % 3 {
                    0 => Move::Both,
                    1 => Move::PlusOnly,
                    _ => {
                        if i % 2 == 0 {
                            Move::MinusOnly
                        } else {
                            Move::Both
                        }
                    }
                })
                .collect();
            let rp: Vec<f64> = (0..n)
                .map(|i| if i % 11 == 0 { 1e13 } else { 0.01 })
                .collect();
            let rm: Vec<f64> = (0..n)
                .map(|i| if i % 13 == 0 { 1e13 } else { 0.02 })
                .collect();

            let mut deltas = vec![0i8; n];
            let flips = t
                .embed_with_deltas(&vals, &moves, &rp, &rm, &message, &mut deltas)
                .unwrap_or_else(|e| panic!("case {case}: no solution: {e}"));
            assert!(flips > 0, "case {case}: nothing changed");

            let mut stego = vals.clone();
            for (v, &d) in stego.iter_mut().zip(deltas.iter()) {
                *v = (*v as i16 + d as i16) as u8;
            }
            assert!(
                bits_equal(&t.extract(&stego, bits), &message, bits),
                "case {case}"
            );
            for (i, &mv) in moves.iter().enumerate() {
                match mv {
                    Move::PlusOnly => assert!(deltas[i] >= 0, "case {case}: -1 on a +only slot"),
                    Move::MinusOnly => assert!(deltas[i] <= 0, "case {case}: +1 on a -only slot"),
                    Move::Both => {}
                }
            }
        }
    }

    /// A cover whose elements have no legal direction at all cannot satisfy a
    /// non-zero syndrome: report it instead of silently changing nothing.
    #[test]
    fn fully_illegal_cover_is_an_error_not_a_silent_noop() {
        let t = StcTrellis::from_seed_grouped(7, 8, 4).unwrap();
        let n = 64;
        let vals = vec![2u8; n];
        let moves = vec![Move::Both; n];
        let rp = vec![f64::INFINITY; n];
        let rm = vec![f64::INFINITY; n];
        let bits = t.message_bits(n);
        let message = vec![0xFFu8; bits.div_ceil(8)];
        let mut deltas = vec![0i8; n];
        assert!(
            t.embed_with_deltas(&vals, &moves, &rp, &rm, &message, &mut deltas)
                .is_err()
        );
    }

    /// A seed whose raw splitmix stream repeats a column inside a group must not
    /// collapse that group: two identical vectors under `u = 2` embed at the
    /// `u = 1` change rate, i.e. twice the cost per bit. These seeds are the
    /// ones that collided before the derivation skipped duplicates, and the
    /// collapse is what made the spatial group-size test flake about once per
    /// 64 random salts.
    #[test]
    fn grouped_columns_never_collapse_a_group() {
        let n = 960;
        let vals: Vec<u8> = (0..n).map(|i| 40 + (i % 8) as u8).collect();
        let moves: Vec<Move> = vals.iter().map(|&v| spatial_move(v)).collect();
        let rp = vec![1.0f64; n];
        let rm = vec![1.0f64; n];

        for seed in [0x5EEDu64, 105, 119, 155, 168, 222, 226] {
            let mut rates = Vec::new();
            for u in [1u8, 2, 3] {
                let t = StcTrellis::from_seed_grouped(seed, 8, u).unwrap();
                let bits = t.message_bits(n);
                let message: Vec<u8> = (0..bits.div_ceil(8)).map(|i| (i * 37) as u8).collect();
                let mut stego = vals.clone();
                t.embed(&mut stego, &moves, &rp, &rm, &message).unwrap();
                let flips = vals
                    .iter()
                    .zip(stego.iter())
                    .filter(|(a, b)| a != b)
                    .count();
                rates.push(flips as f64 / n as f64);
            }
            assert!(
                rates[1] < rates[0] * 0.85,
                "seed={seed}: u=2 must cut the change rate: {rates:?}"
            );
            assert!(
                rates[2] < rates[1],
                "seed={seed}: u=3 must beat u=2: {rates:?}"
            );
        }
    }

    /// A group whose elements cannot be laid out (n not a multiple of u) is a
    /// caller error, not a silent truncation.
    #[test]
    fn non_multiple_element_count_is_rejected() {
        let t = StcTrellis::from_seed_grouped(5, 4, 2).unwrap();
        let mut vals = vec![40u8; 11];
        let moves = vec![Move::Both; 11];
        let rp = vec![1.0; 11];
        let rm = vec![1.0; 11];
        assert!(t.embed(&mut vals, &moves, &rp, &rm, &[0u8; 4]).is_err());
    }
}
