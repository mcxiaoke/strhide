//! V3 slot contract and payload layout.
//!
//! # The slot contract
//!
//! ```text
//! Grid      = { (bi, k) | 0 <= bi < block_count, k_min <= k <= k_max }
//! HdrSlots  = permute(Grid, header_seed)[0 .. sb_slots + ext_slots]
//! BodyGrid  = Grid \ HdrSlots
//! BodySlots = permute(BodyGrid, perm_seed)[0 .. u * (bits + h - 1)]
//! ```
//!
//! Three invariants make both ends agree without ever looking at a coefficient
//! value:
//!
//! 1. **Values do not participate.** `Grid` and `BodySlots` depend only on the
//!    block count and the key. The single exception is the cover digest over DC
//!    coefficients, which is used as the *KDF salt* for the header location --
//!    and DC never takes part in embedding, so it is identical before and after.
//! 2. **Header first.** The body grid is the grid minus the header slots; if the
//!    two sets overlapped, a coefficient would be written twice and the body
//!    syndrome would disagree with the cover values the trellis solved on.
//! 3. **A truncated tail is fine.** `BodySlots` takes the first `n` of the
//!    permutation and drops the rest: a key-uniform random subsample, not a
//!    value-ranked one. It costs capacity, never reproducibility.
//!
//! # Implementation contract (prevents "unit test passes, another process
//! fails")
//!
//! * Slots are flat indices `idx = bi * slots_per_block + (k - k_min)`.
//! * `BodyGrid` is built with a `bool` bitset in ascending index order.
//!   **Never** with `HashSet`/`HashMap`: Rust's default hasher is seeded per
//!   process, so set iteration order differs between runs and desynchronises the
//!   Fisher-Yates sequence.
//! * Any function in this module is a pure function of its arguments.

use crate::errors::StrHideError;
use crate::stego::coding::{KERNEL_MAX_U, MAX_STC_H, MIN_STC_H};
use crate::stego::format::GridRule;

/// Resolved layout of one embedding: how many slots the header takes, which
/// group size the body uses, and how many body slots are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// Grid size (`block_count * slots_per_block`).
    pub n_total: usize,
    /// Slots occupied by the superblock plus the extension area.
    pub hdr_n: usize,
    /// Grid slots left for the body (`n_total - hdr_n`).
    pub body_grid_len: usize,
    /// Group size written into the superblock.
    pub u: u8,
    /// Body slots actually written (`u * (bits + h - 1)`).
    pub body_n: usize,
    /// Payload bits (`8 * ciphertext_len`).
    pub bits: usize,
}

/// Resolve the body layout for `bits` payload bits.
///
/// `u` is the largest group size that keeps the trellis within `slot_budget`
/// transitions *and* inside the body grid. Larger `u` spreads one bit over more
/// slots, which lowers the change rate; the ceiling is
/// `KERNEL_MAX_U` because beyond that the extra states only add
/// search cost.
///
/// `slot_budget` is an embed-side performance knob, never part of the wire
/// format: the extractor trusts the `u` in the superblock and only checks range
/// and capacity.
pub fn compute(
    n_total: usize,
    hdr_n: usize,
    bits: usize,
    h: u8,
    slot_budget: usize,
) -> Result<Layout, StrHideError> {
    if !(MIN_STC_H..=MAX_STC_H).contains(&h) {
        return Err(StrHideError::General(format!(
            "STC constraint height must be in {MIN_STC_H}..={MAX_STC_H}, got {h}"
        )));
    }
    if n_total <= hdr_n {
        return Err(StrHideError::General(format!(
            "Capacity exceeded: header needs {hdr_n} slots, the grid only has {n_total}"
        )));
    }
    let body_grid_len = n_total - hdr_n;
    if bits == 0 {
        return Ok(Layout {
            n_total,
            hdr_n,
            body_grid_len,
            u: 1,
            body_n: 0,
            bits,
        });
    }

    let window = bits + h as usize - 1;
    let u_capacity = body_grid_len / window;
    if u_capacity == 0 {
        return Err(StrHideError::General(format!(
            "Capacity exceeded: need {window} slots for {bits} payload bits (h={h}), have {body_grid_len}"
        )));
    }
    let u_budget = (slot_budget / window).clamp(1, KERNEL_MAX_U as usize);
    let u = u_capacity.min(u_budget).min(KERNEL_MAX_U as usize) as u8;
    let body_n = u as usize * window;
    debug_assert!(body_n <= body_grid_len);
    debug_assert_eq!((body_n / u as usize) - (h as usize - 1), bits);

    Ok(Layout {
        n_total,
        hdr_n,
        body_grid_len,
        u,
        body_n,
        bits,
    })
}

/// Largest payload bits a body grid can carry: the `u = 1` bound.
///
/// `u = 1` is the extreme-capacity end of the trade-off, so this is a hard
/// ceiling rather than a recommendation.
pub fn max_payload_bits(body_grid_len: usize, h: u8) -> usize {
    body_grid_len.saturating_sub(h as usize - 1)
}

/// All grid slots in ascending flat-index order.
///
/// This is the canonical order every permutation in the pipeline starts from;
/// deriving it from anything but the block count and the grid rule would make
/// the two ends disagree.
pub fn grid_indices(block_count: usize, rule: GridRule) -> Vec<u32> {
    let per_block = rule.slots_per_block();
    let mut out = Vec::with_capacity(block_count * per_block);
    for bi in 0..block_count {
        let base = (bi * per_block) as u32;
        for s in 0..per_block {
            out.push(base + s as u32);
        }
    }
    out
}

/// `Grid \ HdrSlots`, still in ascending flat-index order.
///
/// Operates on a bitset over the full coefficient space (`block_count * 64`)
/// so the result order is exactly `grid`'s order.
pub fn body_grid(grid: &[u32], hdr: &[u32], block_count: usize) -> Vec<u32> {
    let mut is_header = vec![false; block_count * 64];
    for &idx in hdr {
        is_header[idx as usize] = true;
    }
    grid.iter()
        .copied()
        .filter(|&idx| !is_header[idx as usize])
        .collect()
}

/// Flat slot index -> `(block, coefficient index)`.
pub fn slot_to_coeff(idx: u32, rule: GridRule) -> (usize, usize) {
    let per_block = rule.slots_per_block();
    let idx = idx as usize;
    (idx / per_block, idx % per_block + rule.k_min as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift: no dependency on `rand`, and reproducible.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn range(&mut self, lo: usize, hi: usize) -> usize {
            lo + (self.next() % (hi - lo) as u64) as usize
        }
    }

    #[test]
    fn layout_matches_the_1920x1280_reference_table() {
        // 4:2:0 1920x1280 -> 38,400 blocks -> 2,419,200 grid slots.
        let n_total = 38_400 * 63;
        assert_eq!(n_total, 2_419_200);
        let hdr_n = 718;
        for (payload, expect_u, expect_n) in [
            (4096usize, 24u8, 790_632usize),
            (16384, 6, 787_482),
            (65536, 1, 524_463),
        ] {
            let bits = 8 * (payload + 21);
            let layout = compute(n_total, hdr_n, bits, 8, 800_000).unwrap();
            assert_eq!(layout.bits, bits);
            assert_eq!(layout.u, expect_u, "payload {payload}");
            assert_eq!(layout.body_n, expect_n, "payload {payload}");
            assert_eq!(
                layout.body_n,
                layout.u as usize * (layout.bits + 7),
                "exact fill"
            );
            assert!(layout.body_n <= layout.body_grid_len);
        }
    }

    #[test]
    fn layout_is_a_pure_function_of_its_inputs() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..1000 {
            let n_total = rng.range(64, 3_000_000);
            let hdr_n = rng.range(1, (n_total / 4).max(2));
            let bits = rng.range(1, (n_total / 2).max(2));
            let h = rng.range(4, 11) as u8;
            let budget = rng.range(1, 2_000_000);

            let a = compute(n_total, hdr_n, bits, h, budget);
            let b = compute(n_total, hdr_n, bits, h, budget);
            // Errors carry a message, so compare the discriminants instead of
            // the whole `Result`.
            assert_eq!(
                a.as_ref().ok(),
                b.as_ref().ok(),
                "compute must be deterministic"
            );

            let Ok(layout) = a else { continue };
            assert!((1..=KERNEL_MAX_U).contains(&layout.u));
            assert_eq!(layout.body_grid_len, n_total - hdr_n);
            assert!(layout.body_n <= layout.body_grid_len);
            assert_eq!(layout.body_n % layout.u as usize, 0);
            assert_eq!((layout.body_n / layout.u as usize) - (h as usize - 1), bits);
        }
    }

    #[test]
    fn insufficient_capacity_is_an_error_not_a_panic() {
        let err = compute(1000, 718, 100_000, 8, 800_000).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Capacity exceeded"), "{msg}");
        assert!(msg.contains("need"), "{msg}");

        // Header alone does not fit.
        assert!(compute(700, 718, 10, 8, 800_000).is_err());
        // Bad height.
        assert!(compute(100_000, 718, 100, 3, 800_000).is_err());
    }

    #[test]
    fn slot_budget_caps_the_group_size_but_capacity_caps_it_more() {
        // Room for u=24 by capacity, budget only allows u=4.
        let bits = 8 * (4096 + 21);
        let n = 38_400 * 63;
        let tight = compute(n, 718, bits, 8, 4 * (bits + 7)).unwrap();
        assert_eq!(tight.u, 4);
        let default_budget = compute(n, 718, bits, 8, 800_000).unwrap();
        assert_eq!(default_budget.u, 24);
        assert!(default_budget.body_n <= default_budget.body_grid_len);
        // The kernel ceiling caps the group size even with an unlimited budget.
        let roomy = compute(n, 718, bits, 8, usize::MAX).unwrap();
        assert_eq!(roomy.u, KERNEL_MAX_U);

        // A small carrier caps `u` below the budget-derived value.
        let n_small = 63 * 1200;
        let small = compute(n_small, 718, bits, 8, 800_000).unwrap();
        assert_eq!(small.u as usize, (n_small - 718) / (bits + 7));
        assert!(small.u < 24);
    }

    #[test]
    fn grid_and_body_grid_are_ordered_and_disjoint() {
        let rule = GridRule::ALL_AC;
        let grid = grid_indices(3, rule);
        assert_eq!(grid.len(), 3 * 63);
        assert_eq!(grid[0], 0);
        assert_eq!(slot_to_coeff(0, rule), (0, 1));
        assert_eq!(slot_to_coeff(62, rule), (0, 63));
        assert_eq!(slot_to_coeff(63, rule), (1, 1));
        assert!(grid.windows(2).all(|w| w[0] < w[1]), "ascending");

        let hdr: Vec<u32> = vec![0, 5, 63, 100];
        let body = body_grid(&grid, &hdr, 3);
        assert_eq!(body.len(), grid.len() - hdr.len());
        for h in &hdr {
            assert!(!body.contains(h));
        }
        assert!(body.windows(2).all(|w| w[0] < w[1]), "ascending");
        // Same input, same output -- across calls and (because there is no
        // hashing here) across processes.
        assert_eq!(body, body_grid(&grid, &hdr, 3));
    }

    #[test]
    fn narrow_grid_rule_maps_indices_correctly() {
        let rule = GridRule {
            k_min: 5,
            k_max: 12,
        };
        assert_eq!(rule.slots_per_block(), 8);
        let grid = grid_indices(2, rule);
        assert_eq!(
            grid,
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        assert_eq!(slot_to_coeff(0, rule), (0, 5));
        assert_eq!(slot_to_coeff(7, rule), (0, 12));
        assert_eq!(slot_to_coeff(8, rule), (1, 5));
    }

    #[test]
    fn max_payload_bits_is_the_u_equals_one_bound() {
        let bits = max_payload_bits(2_418_482, 8);
        // A budget that only allows one slot per bit is the u = 1 case.
        let layout = compute(2_419_200, 718, bits, 8, bits + 7).unwrap();
        assert_eq!(layout.u, 1);
        assert_eq!(layout.body_n, bits + 7);
        assert!(layout.body_n <= layout.body_grid_len);
        // One more bit does not fit at u = 1.
        assert!(compute(2_419_200, 718, bits + 8, 8, usize::MAX).is_err());
    }
}
