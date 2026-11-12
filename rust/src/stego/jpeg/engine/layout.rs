//! JPEG DCT carrier slot layout and delta application.

use dct_io::JpegCoefficients;
use sha2::{Digest, Sha256};

use crate::errors::StrHideError;
use crate::stego::coding::Move;
use crate::stego::format::JpegFormatProfile;
use crate::stego::jpeg::dht::{self, AcSymbolSet};
use crate::stego::jpeg::v3_layout;

/// Everything both ends derive from the carrier alone.
pub(crate) struct CoverFrame {
    /// Blocks of the payload component (Y).
    pub(crate) block_count: usize,
    /// Total candidate AC grid slots.
    pub(super) n_total: usize,
    /// SHA-256 over the block/component counts and every DC coefficient.
    pub(super) digest: [u8; 32],
}

impl CoverFrame {
    pub(crate) fn read(fmt: &JpegFormatProfile, coeffs: &JpegCoefficients) -> Self {
        let block_count = coeffs.components[0].blocks.len();
        let n_total = block_count * fmt.grid_rule.slots_per_block();
        Self {
            block_count,
            n_total,
            digest: cover_digest(fmt, coeffs),
        }
    }

    pub(super) fn n_total(&self) -> usize {
        self.n_total
    }
}

/// `SHA-256(tag || u32 block_count || u32 component_count || all DC coefficients)`.
///
/// DC is never an embedding target, so this is identical before and after
/// embedding and can salt the KDF that locates the header. That the digest must
/// stay stable is exactly why `grid_rule` may never include `k = 0`.
pub(super) fn cover_digest(fmt: &JpegFormatProfile, coeffs: &JpegCoefficients) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(fmt.cover_digest_tag);
    let block_count = coeffs.components.first().map_or(0, |c| c.blocks.len());
    hasher.update((block_count as u32).to_be_bytes());
    hasher.update((coeffs.components.len() as u32).to_be_bytes());
    for component in &coeffs.components {
        for block in &component.blocks {
            // i16 big-endian, sign included: the digest must distinguish
            // -1 from 1 and 256 from 1.
            hasher.update(block[0].to_be_bytes());
        }
    }
    hasher.finalize().into()
}

/// Carrier identity mixed into the L1 PBKDF2 salt.
///
/// Only immutable metadata: the cover digest is computed from DC coefficients,
/// which the DCT grid never modifies. Embedding therefore cannot move the salt,
/// and probe/extract derive the same locator keys.
pub(crate) fn jpeg_pre_salt(fmt: &JpegFormatProfile, cover: &CoverFrame) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(fmt.cover_digest_tag);
    hasher.update(b"jpeg-v4");
    hasher.update(cover.digest);
    hasher.finalize().into()
}

/// Parity carrier handed to the trellis: LSB 0 -> 2, LSB 1 -> 3.
///
/// Using 2/3 instead of 0/1 means "flip the parity" is always a `±1` move the
/// kernel can represent, and the callback never has to think about `u8`
/// overflow. The real direction is applied to the `i16` coefficient afterwards.
#[inline]
pub(super) fn parity_carrier(coeff: i16) -> u8 {
    2 | (coeff & 1) as u8
}

/// Which `±1` directions keep the coefficient inside the baseline AC range.
#[inline]
pub(super) fn ternary_legal(coeff: i16) -> Move {
    match (coeff < 1023, coeff > -1023) {
        (true, true) => Move::Both,
        (true, false) => Move::PlusOnly,
        (false, true) => Move::MinusOnly,
        // Unreachable: `c < 1023 && c <= -1023` has no solution.
        _ => Move::Both,
    }
}

/// Per-slot arrays the trellis needs.
pub(super) struct SlotPlan {
    pub(super) vals: Vec<u8>,
    pub(super) moves: Vec<Move>,
    pub(super) sparse_overrides: Option<Vec<(f64, f64)>>,
}

/// Multiplier applied to a zero insertion when its zero run already contains
/// another candidate slot. Finite on purpose: see `plan_slots`.
pub(super) const CROSS_ZERO_REPEAT_PENALTY: f64 = 1_000.0;

/// Cache of [`dht::BlockZigzagState`] for one slot set.
///
/// A dense vector is fastest when the slot set touches a large fraction of the
/// blocks (the body). The header and extension area touch only a few hundred
/// slots, so a sparse map avoids allocating one state per block.
pub(super) enum BlockStateCache {
    Dense(Vec<Option<dht::BlockZigzagState>>),
    Sparse(std::collections::HashMap<usize, dht::BlockZigzagState>),
}

impl BlockStateCache {
    pub(super) fn new(block_count: usize, slot_count: usize) -> Self {
        if slot_count.saturating_mul(4) >= block_count {
            Self::Dense(vec![None; block_count])
        } else {
            Self::Sparse(std::collections::HashMap::new())
        }
    }

    #[inline]
    pub(super) fn state(&mut self, bi: usize, block: &[i16; 64]) -> &dht::BlockZigzagState {
        match self {
            Self::Dense(states) => {
                states[bi].get_or_insert_with(|| dht::BlockZigzagState::from_block(block))
            }
            Self::Sparse(states) => states
                .entry(bi)
                .or_insert_with(|| dht::BlockZigzagState::from_block(block)),
        }
    }
}

/// Build the trellis inputs for one slot set.
///
/// `table` is `None` for a complete Huffman table (the fast path: zero per-slot
/// cost buffer allocation), otherwise custom cross-zero costs are tracked in overrides.
#[allow(clippy::too_many_arguments)]
pub(super) fn plan_slots(
    coeffs: &JpegCoefficients,
    slots: &[u32],
    rule: crate::stego::format::GridRule,
    costs: &[f64],
    directions: Option<&[i8]>,
    table: Option<&AcSymbolSet>,
    wet_cost: f64,
    polarize_weight: f64,
) -> SlotPlan {
    let blocks = &coeffs.components[0].blocks;
    let mut plan = SlotPlan {
        vals: Vec::with_capacity(slots.len()),
        moves: Vec::with_capacity(slots.len()),
        sparse_overrides: table.map(|_| Vec::with_capacity(slots.len())),
    };

    let mut state_cache = table.map(|_| BlockStateCache::new(blocks.len(), slots.len()));

    // Price repeated zero insertions in the same zero run out of reach without
    // hard-locking them. A hard lock (one cross-zero per block) leaves smooth
    // blocks with almost no movable slots, which makes an h=8, u>=3 trellis
    // infeasible. A finite but large multiplier keeps every slot reachable while
    // strongly preferring runs that are not already crowded.
    //
    // The same pass records which coefficients are slots, so an insertion can
    // also verify the shifted symbol for every category the following
    // coefficient may take (see `can_move_with_slots`).
    //
    // Skipped for tiny slot sets (the 746-slot header): the dense bitsets would
    // cost more than the collision they prevent, and the header trellis is small.
    let (multi_run, slot_mask): (Option<Vec<u64>>, Option<Vec<u64>>) =
        if table.is_some() && slots.len() >= 4096 {
            let cache = state_cache.as_mut().expect("table implies a state cache");
            let mut seen = vec![0u64; blocks.len()];
            let mut multi = vec![0u64; blocks.len()];
            let mut masks = vec![0u64; blocks.len()];
            for &idx in slots {
                let (bi, k) = v3_layout::slot_to_coeff(idx, rule);
                masks[bi] |= 1u64 << dht::ZZ_POS[k] as usize;
                if blocks[bi][k] != 0 {
                    continue;
                }
                let state = cache.state(bi, &blocks[bi]);
                let bit = 1u64 << state.run_key(k);
                if seen[bi] & bit != 0 {
                    multi[bi] |= bit;
                } else {
                    seen[bi] |= bit;
                }
            }
            (Some(multi), Some(masks))
        } else {
            (None, None)
        };

    for &idx in slots {
        let (bi, k) = v3_layout::slot_to_coeff(idx, rule);
        let coeff = blocks[bi][k];
        let legal = ternary_legal(coeff);
        let mut allow_plus = matches!(legal, Move::Both | Move::PlusOnly);
        let mut allow_minus = matches!(legal, Move::Both | Move::MinusOnly);
        let mut cross_cost = wet_cost;
        let block_slots = slot_mask.as_ref().map(|m| m[bi]);

        // A move that crosses zero (`0 <-> ±1`) changes the zero pattern of the
        // block, hence the run of later coefficients: checked via `can_move`.
        let crosses_zero_plus = coeff == 0 || coeff == -1;
        let crosses_zero_minus = coeff == 0 || coeff == 1;

        if let Some(table) = table {
            let state = state_cache
                .as_mut()
                .expect("table implies a state cache")
                .state(bi, &blocks[bi]);

            if let Some(multi) = multi_run.as_ref() {
                let run_bit = 1u64 << state.run_key(k);
                if multi[bi] & run_bit != 0 {
                    cross_cost = wet_cost * CROSS_ZERO_REPEAT_PENALTY;
                }
            }

            // Over-optimised tables: never erase a non-zero coefficient. The
            // other direction (`±1 -> ±2`) stays open, so the slot is not
            // locked outright, and every zero-run wall survives. This removes
            // the dominant cause of post-hoc "missing symbol" failures:
            // two runs merging into a longer run whose (run, category) symbol
            // the table does not define.
            if coeff == 1 {
                allow_minus = false;
            } else if coeff == -1 {
                allow_plus = false;
            }

            if allow_plus && !state.can_move_with_slots(k, coeff + 1, table, block_slots) {
                allow_plus = false;
            }
            if allow_minus && !state.can_move_with_slots(k, coeff - 1, table, block_slots) {
                allow_minus = false;
            }
        }

        // Symmetric UERD cost, then the per-direction split. The bias says
        // which move is the less visible one; the model's preferred direction
        // is discounted by `polarize_weight`, the other keeps the full cost.
        let base = costs[bi * 64 + k].min(wet_cost);
        let (base_plus, base_minus) = match directions {
            Some(bias) if bias[bi * 64 + k] > 0 => (base * polarize_weight, base),
            Some(bias) if bias[bi * 64 + k] < 0 => (base, base * polarize_weight),
            _ => (base, base),
        };
        let mv = match (allow_plus, allow_minus) {
            (true, true) => Move::Both,
            (true, false) => Move::PlusOnly,
            (false, true) => Move::MinusOnly,
            // Both directions closed by the table: the element can only keep its
            // value (reachable, since a legal direction is priced, not removed,
            // everywhere else).
            (false, false) => Move::Both,
        };

        if let Some(ref mut overrides) = plan.sparse_overrides {
            let plus_cost = if !allow_plus {
                f64::INFINITY
            } else if crosses_zero_plus {
                cross_cost
            } else {
                base_plus
            };
            let minus_cost = if !allow_minus {
                f64::INFINITY
            } else if crosses_zero_minus {
                cross_cost
            } else {
                base_minus
            };
            overrides.push((plus_cost, minus_cost));
        }

        plan.vals.push(parity_carrier(coeff));
        plan.moves.push(mv);
    }
    plan
}

/// Apply `-1/0/+1` deltas to the coefficients of one slot set.
pub(super) fn apply_deltas(
    blocks: &mut [[i16; 64]],
    slots: &[u32],
    deltas: &[i8],
    rule: crate::stego::format::GridRule,
) -> Result<(), StrHideError> {
    for (&idx, &delta) in slots.iter().zip(deltas.iter()) {
        if delta == 0 {
            continue;
        }
        let (bi, k) = v3_layout::slot_to_coeff(idx, rule);
        let before = blocks[bi][k];
        let updated = before as i32 + delta as i32;
        // Legality forbids *growing* past ±1023, but the cover itself may
        // legally carry category 11-15 magnitudes (a custom Huffman table can
        // define them), and shrinking such a coefficient stays above 1023.
        // Only flag a move that grows beyond ±1023.
        if updated.abs() > 1023 && updated.abs() >= before.unsigned_abs() as i32 {
            return Err(StrHideError::CorruptedData(
                "AC coefficient grew past the baseline range".into(),
            ));
        }
        blocks[bi][k] = updated as i16;
    }
    Ok(())
}
