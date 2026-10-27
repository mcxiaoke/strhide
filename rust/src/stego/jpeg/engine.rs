//! JPEG DCT-domain steganographic embedding and extraction (V3).
//!
//! # The shape of the code
//!
//! The slot set is a *geometric* fact: every AC position of every block, ordered
//! by flat index, permuted with a key. Neither end ever filters by coefficient
//! value, so the extractor needs no cost map, no ranking and no threshold -- it
//! reads parities and rebuilds the same sequence from the key alone.
//!
//! ```text
//! Grid      = { (bi, k) | k in grid_rule }
//! HdrSlots  = permute(Grid, header_seed)[0 .. 718 + n_ext]
//! BodyGrid  = Grid \ HdrSlots
//! BodySlots = permute(BodyGrid, perm_seed)[0 .. u * (bits + h - 1)]
//! ```
//!
//! The header (44-byte superblock + optional TLV area) is located by a seed
//! derived from `SuiteKDF(password, cover_digest)`, so reading it costs a full
//! KDF: a wrong password cannot be rejected cheaply, and the structural checks
//! that follow are not a fast oracle.
//!
//! # Ternary matching and write-back
//!
//! The trellis works on parity carriers (`2`/`3`), but a coefficient is an
//! `i16`. [`StcTrellis::embed_with_deltas`] therefore returns one `-1/0/+1` per
//! slot and the engine applies exactly that to the coefficient, which lets a
//! single coefficient both keep its magnitude relationship with its neighbours
//! and land on the cheapest side.
//!
//! Legality has one hard bound -- `|c| = 1023` cannot grow, because
//! `category(1024) == 11` is outside the baseline AC table -- plus, for carriers
//! whose Huffman table is over-optimised, the directions whose `(run, category)`
//! symbol is missing from that table.

use dct_io::JpegCoefficients;
use sha2::{Digest, Sha256};

use crate::core::control::{Control, Stage};
use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::stego::StegoCapacityInfo;
use crate::stego::coding::{Move, StcTrellis};
use crate::stego::envelope::{
    BODY_OVERHEAD, Freshness, HEADER_OVERHEAD, build_plaintext, build_plaintext_bytes,
    encrypt_with_aad, unpack_envelope_parts,
};
use crate::stego::format::{
    JpegFormatProfile, body_keys, derive_master, extension_stc_seed, header_perm_seed,
    header_stc_seed, stc_seed,
};
use crate::stego::jpeg::dht::{self, AcSymbolSet};
use crate::stego::jpeg::header_v3::{
    CODEC_TERNARY_STC, COMPONENT_Y, ENVELOPE_LEN_MAX, SUPERBLOCK_BYTES, Superblock, TLV_CRITICAL,
    encode_extension, parse_extension,
};
use crate::stego::jpeg::v3_layout::{self, Layout};
use crate::stego::options::{StegoHeaderInfo, StegoVerifyResult, VerifyLevel};
use crate::stego::params::{ExtractParams, JpegParams};
use crate::stego::prng::{ChaCha12Stream, fisher_yates_prefix_from, permute_prefix};
use crate::stego::traits::JpegCostModel;

/// Map a dct_io error to StrHideError.
fn map_dct_error(e: dct_io::DctError) -> StrHideError {
    let err_str = e.to_string();
    if err_str.contains("SOF2") || err_str.to_lowercase().contains("progressive") {
        return StrHideError::UnsupportedFormat(
            "Progressive JPEG (SOF2) is not supported for content-adaptive DCT steganography; please convert to baseline JPEG or use 'strhide write' for structural hiding".into(),
        );
    }
    // The progressive check above already covers this arm's SOF2/progressive
    // test; repeating it here was a dead branch.
    match e {
        dct_io::DctError::Unsupported(msg) => {
            StrHideError::UnsupportedFormat(format!("Unsupported JPEG variant: {msg}"))
        }
        _ => StrHideError::CorruptedData(format!("Corrupt JPEG coefficient stream: {e}")),
    }
}

/// Safety caps for the JPEG decode/allocation path.
///
/// `MAX_JPEG_MCU_COUNT` mirrors `dct-io 0.1.1`; it is checked here as well so the
/// capacity probe and the embedder reject the same carriers for the same reason.
/// `MAX_JPEG_TOTAL_BLOCKS` is a forward-compatible cap a decoder fork would
/// enforce (six 8x8 blocks per MCU); it is checked here too so a future decoder
/// change cannot make the probe and the embedder disagree.
const MAX_JPEG_MCU_COUNT: usize = 1_048_576;
const MAX_JPEG_TOTAL_BLOCKS: usize = 6_291_456;
/// Whole-pipeline working-set ceiling: coefficients + UERD costs + slot grid +
/// the working copy. The trellis bitmap is checked separately once the layout is
/// known (its size depends on the payload). 8 GiB admits a full-capacity 100 MP
/// baseline grid (about 5.4 GiB) while still rejecting pathological 200+ MP
/// allocations; the uncounted per-block state/slot-mask temporaries are about
/// 0.3 GiB at that size.
const MAX_PIPELINE_BYTES: u64 = 8 << 30;
/// Per-block estimate for the arrays that exist for every carrier:
/// coefficients (128 B), UERD costs (512 B), slot grid (252 B), work copy (128 B).
const PIPELINE_BYTES_PER_BLOCK: u64 = 128 + 512 + 63 * 4 + 128;
const PIPELINE_FIXED_BYTES: u64 = 64 << 20;

/// Carrier metadata plus the cheap resource estimate, shared by embed, extract
/// and probe so all three paths agree on what the carrier can do.
struct CarrierPreflight {
    info: dct_io::JpegInfo,
    base_bytes: u64,
}

fn preflight_jpeg(carrier_bytes: &[u8]) -> Result<CarrierPreflight, StrHideError> {
    let info = dct_io::inspect(carrier_bytes).map_err(map_dct_error)?;
    if info.components.is_empty() {
        return Err(StrHideError::UnsupportedFormat(
            "JPEG has no image components".into(),
        ));
    }
    let max_h = info
        .components
        .iter()
        .map(|c| c.h_samp as usize)
        .max()
        .unwrap_or(1)
        .max(1);
    let max_v = info
        .components
        .iter()
        .map(|c| c.v_samp as usize)
        .max()
        .unwrap_or(1)
        .max(1);
    let mcu_cols = (info.width as usize).div_ceil(max_h * 8);
    let mcu_rows = (info.height as usize).div_ceil(max_v * 8);
    let mcu_count = mcu_cols.checked_mul(mcu_rows).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unsupported JPEG variant: image dimensions overflow the MCU count".into(),
        )
    })?;
    if mcu_count > MAX_JPEG_MCU_COUNT {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported JPEG variant: image too large ({mcu_count} MCUs; max {MAX_JPEG_MCU_COUNT})"
        )));
    }
    let total_blocks: usize = info.components.iter().map(|c| c.block_count).sum();
    if total_blocks > MAX_JPEG_TOTAL_BLOCKS {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported JPEG variant: image too large ({total_blocks} 8x8 blocks; max {MAX_JPEG_TOTAL_BLOCKS})"
        )));
    }
    let base_bytes =
        PIPELINE_FIXED_BYTES.saturating_add(total_blocks as u64 * PIPELINE_BYTES_PER_BLOCK);
    if base_bytes > MAX_PIPELINE_BYTES {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported JPEG variant: image needs about {} MiB of working memory; the {} MiB budget would be exceeded",
            base_bytes >> 20,
            MAX_PIPELINE_BYTES >> 20
        )));
    }
    Ok(CarrierPreflight { info, base_bytes })
}

/// Backtracking-bitmap size for a body of `body_n` slots at height `h`.
fn estimate_backtrack_bytes(body_n: usize, h: u8) -> u64 {
    let states = 1u64 << h.min(10);
    let words_per_col = states.div_ceil(64);
    body_n as u64 * words_per_col * 8
}

fn check_pipeline_budget(base_bytes: u64, body_n: usize, h: u8) -> Result<(), StrHideError> {
    let total = base_bytes.saturating_add(estimate_backtrack_bytes(body_n, h));
    if total > MAX_PIPELINE_BYTES {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported JPEG variant: this payload needs about {} MiB of working memory; the {} MiB budget would be exceeded",
            total >> 20,
            MAX_PIPELINE_BYTES >> 20
        )));
    }
    Ok(())
}

/// Optional tracing enabled with `STRHIDE_STEGO_TRACE=1`.
///
/// Deliberately stderr-only and off by default: the library has no logging
/// dependency, and the matrix script is the main consumer.
fn trace(msg: &str) {
    if std::env::var_os("STRHIDE_STEGO_TRACE").is_some() {
        eprintln!("[stego] {msg}");
    }
}

/// Everything both ends derive from the carrier alone.
struct CoverFrame {
    /// Blocks of the payload component (Y).
    block_count: usize,
    /// Total candidate AC grid slots.
    n_total: usize,
    /// SHA-256 over the block/component counts and every DC coefficient.
    digest: [u8; 32],
}

impl CoverFrame {
    fn read(fmt: &JpegFormatProfile, coeffs: &JpegCoefficients) -> Self {
        let block_count = coeffs.components[0].blocks.len();
        let n_total = block_count * fmt.grid_rule.slots_per_block();
        Self {
            block_count,
            n_total,
            digest: cover_digest(fmt, coeffs),
        }
    }

    fn n_total(&self) -> usize {
        self.n_total
    }
}

/// `SHA-256(tag || u32 block_count || u32 component_count || all DC coefficients)`.
///
/// DC is never an embedding target, so this is identical before and after
/// embedding and can salt the KDF that locates the header. That the digest must
/// stay stable is exactly why `grid_rule` may never include `k = 0`.
fn cover_digest(fmt: &JpegFormatProfile, coeffs: &JpegCoefficients) -> [u8; 32] {
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

/// Parity carrier handed to the trellis: LSB 0 -> 2, LSB 1 -> 3.
///
/// Using 2/3 instead of 0/1 means "flip the parity" is always a `±1` move the
/// kernel can represent, and the callback never has to think about `u8`
/// overflow. The real direction is applied to the `i16` coefficient afterwards.
#[inline]
fn parity_carrier(coeff: i16) -> u8 {
    2 | (coeff & 1) as u8
}

/// Which `±1` directions keep the coefficient inside the baseline AC range.
#[inline]
fn ternary_legal(coeff: i16) -> Move {
    match (coeff < 1023, coeff > -1023) {
        (true, true) => Move::Both,
        (true, false) => Move::PlusOnly,
        (false, true) => Move::MinusOnly,
        // Unreachable: `c < 1023 && c <= -1023` has no solution.
        _ => Move::Both,
    }
}

/// Per-slot arrays the trellis needs.
struct SlotPlan {
    vals: Vec<u8>,
    moves: Vec<Move>,
    sparse_overrides: Option<Vec<(f64, f64)>>,
}

/// Multiplier applied to a zero insertion when its zero run already contains
/// another candidate slot. Finite on purpose: see `plan_slots`.
const CROSS_ZERO_REPEAT_PENALTY: f64 = 1_000.0;

/// Cache of [`dht::BlockZigzagState`] for one slot set.
///
/// A dense vector is fastest when the slot set touches a large fraction of the
/// blocks (the body). The header and extension area touch only a few hundred
/// slots, so a sparse map avoids allocating one state per block.
enum BlockStateCache {
    Dense(Vec<Option<dht::BlockZigzagState>>),
    Sparse(std::collections::HashMap<usize, dht::BlockZigzagState>),
}

impl BlockStateCache {
    fn new(block_count: usize, slot_count: usize) -> Self {
        if slot_count.saturating_mul(4) >= block_count {
            Self::Dense(vec![None; block_count])
        } else {
            Self::Sparse(std::collections::HashMap::new())
        }
    }

    #[inline]
    fn state(&mut self, bi: usize, block: &[i16; 64]) -> &dht::BlockZigzagState {
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
fn plan_slots(
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
fn apply_deltas(
    blocks: &mut [[i16; 64]],
    slots: &[u32],
    deltas: &[i8],
    rule: crate::stego::format::GridRule,
) {
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
        debug_assert!(
            updated.abs() <= 1023 || updated.abs() < before.unsigned_abs() as i32,
            "AC coefficient grew past the baseline range"
        );
        blocks[bi][k] = updated as i16;
    }
}

/// Everything the two attempts share.
struct EmbedContext<'a> {
    fmt: &'a JpegFormatProfile,
    suite: &'a crate::stego::format::CipherSuite,
    params: &'a JpegParams,
    cover: &'a CoverFrame,
    costs: &'a [f64],
    /// Per-coefficient directional bias from the cost model, `None` when the
    /// model has no preference (symmetric costs). Embed-side only.
    directions: Option<&'a [i8]>,
    table: Option<&'a AcSymbolSet>,
    password: &'a str,
    domain: Option<&'a str>,
    /// Working-set estimate from [`preflight_jpeg`], before the trellis bitmap.
    base_bytes: u64,
    /// Source of the salt and nonce for each attempt.
    freshness: Freshness,
    /// Cover+payload binding for seeded freshness, precomputed once per embed
    /// (see [`Freshness::seeded_binding`]); stable across retry attempts.
    fresh_binding: [u8; 64],
    /// Capacity safety policy for the enforced-tier gate.
    safety: crate::stego::params::SafetyPolicy,
    payload: &'a Payload<'a>,
}

/// Number of salt values tried when a Huffman-limited block cannot be encoded.
///
/// Only the *missing symbol* failure is retried, and retrying is invisible to the
/// extractor: the salt and nonce live in the (AAD-protected) superblock and are
/// read back from it, so a new salt is simply a different valid carrier. The
/// trellis seed and the slot set are re-derived from that salt, which is what
/// changes the outcome.
///
/// Six rather than three: even at `u = 3` an over-optimised carrier has a
/// per-attempt chance of producing an unencodable cross-zero chain (the
/// residual of defence 2 -- measured 1m at `u = 3` still failed on a 100 MP
/// carrier), and each attempt is a full embed. Six turns a per-attempt
/// failure rate of roughly a third into a per-run one of about one in
/// twenty.
const EMBED_ATTEMPTS: usize = 6;

/// A failed attempt: the error, plus whether a fresh salt could change it.
struct Attempt {
    error: StrHideError,
    retryable: bool,
}

impl From<StrHideError> for Attempt {
    fn from(error: StrHideError) -> Self {
        Self {
            error,
            retryable: false,
        }
    }
}

/// Embed a payload into a JPEG carrier with content-adaptive DCT steganography.
///
/// The complete expert entry: format identity, cost model, tuning parameters
/// and salt/nonce source are all explicit. `secret` is the resolved credential
/// (explicit password, else the profile's private stego secret, else `None` for
/// the official public constant); `domain` isolates the HKDF derivation.
///
/// `Freshness::Seeded` makes the output byte-identical for the same carrier,
/// payload, secret and seed. Pair it with `params.deterministic = true` so the
/// cost map stays on the scalar kernel; [`crate::stego::embed_carrier`] does
/// that automatically.
///
/// # Over-optimised Huffman tables
///
/// A table that only defines the symbols the *cover* needed cannot always encode
/// the stego version: a move can need another symbol, and a move that crosses
/// zero also shifts the runs of later coefficients in the same block -- a chain
/// no slot-level test can predict. Three defences, in order:
///
/// 0. the body layout keeps a grouped trellis (`u >= 3`) so the search can
///    route around dead slots and cross-zero chains at all -- see
///    [`grouped_body_budget`](crate::stego::params::grouped_body_budget);
/// 1. moves within the non-zero range whose `(run, category)` is missing are
///    closed, and cross-zero moves are priced at the wet cost so the trellis only
///    uses them when a whole group window has nothing else;
/// 2. [`first_missing_symbol`](dht::first_missing_symbol) replays every touched
///    block after the fact. A failure there is retried with a fresh salt (which
///    re-draws the slot order and the header bits); if every attempt fails, the
///    embed reports the symbol and says what to do, instead of letting `dct-io`
///    raise a bare `CorruptEntropy`.
#[allow(clippy::too_many_arguments)]
pub fn embed_jpeg<'a>(
    carrier_bytes: &[u8],
    payload: impl Into<Payload<'a>>,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &JpegFormatProfile,
    params: &JpegParams,
    safety: crate::stego::params::SafetyPolicy,
    cost_model: &dyn JpegCostModel,
    freshness: Freshness,
    control: &Control<'_>,
) -> Result<Vec<u8>, StrHideError> {
    let payload = payload.into();
    fmt.validate()?;
    params.validate()?;
    control.stage(Stage::Decode);
    control.check()?;
    let suite = fmt.suite(params.cipher_suite).ok_or_else(|| {
        StrHideError::UnsupportedVersion(format!(
            "Cipher suite {} is not implemented by this build (known: {:?})",
            params.cipher_suite,
            fmt.suites.iter().map(|s| s.id).collect::<Vec<_>>()
        ))
    })?;

    let preflight = preflight_jpeg(carrier_bytes)?;
    let coeffs = dct_io::read_coefficients(carrier_bytes).map_err(map_dct_error)?;
    if coeffs.components.is_empty() {
        return Err(StrHideError::UnsupportedFormat(
            "JPEG has no image components".into(),
        ));
    }
    let cover = CoverFrame::read(fmt, &coeffs);

    // Costs are an embed-side concept only: extraction never computes them.
    let geometry = crate::stego::jpeg::geometry::geometry_for_carrier(
        carrier_bytes,
        0,
        coeffs.components[0].blocks.len(),
    )
    .map_err(map_dct_error)?;
    let costs = cost_model.compute_cost(&coeffs, &geometry, params);
    // Checkpoint after the cost map; the trellis solve is the last long phase
    // and there is no safe way to stop it half-way that the reader could see.
    control.check()?;
    control.stage(Stage::Solve);
    if costs.len() != cover.block_count * 64 {
        return Err(StrHideError::General("JPEG cost dimension mismatch".into()));
    }

    // Directional bias (cost polarization). Embed-side only: extraction never
    // computes costs, so a model may base this on cover information that the
    // extractor could not reproduce. `None` keeps the symmetric path.
    let directions = cost_model.direction_bias(&coeffs, &geometry, params);
    if let Some(bias) = directions.as_ref()
        && bias.len() != costs.len()
    {
        return Err(StrHideError::General(
            "JPEG direction bias dimension mismatch".into(),
        ));
    }

    // A complete table needs no per-slot symbol work; anything else takes the
    // slow path (~1% of real files).
    let table = dht::luma_ac_symbols(carrier_bytes).filter(|t| !t.is_complete());
    let ctx = EmbedContext {
        fmt,
        suite,
        params,
        cover: &cover,
        costs: &costs,
        directions: directions.as_deref(),
        table: table.as_ref(),
        password: secret
            .filter(|s| !s.is_empty())
            .unwrap_or(crate::stego::envelope::PUBLIC_DEFAULT_SECRET),
        domain,
        base_bytes: preflight.base_bytes,
        freshness,
        fresh_binding: Freshness::seeded_binding(carrier_bytes, payload.as_bytes()),
        safety,
        payload: &payload,
    };
    let mut work = coeffs.clone();
    let mut last_error = None;
    for attempt_idx in 1..=EMBED_ATTEMPTS {
        // Checkpoint per attempt: embed_once ends in dct_io::write_coefficients,
        // past which the output exists and stopping would only waste the work.
        control.check()?;
        control.stage(Stage::Encode);
        let mut applied: Vec<(u32, i8)> = Vec::new();
        match embed_once(
            carrier_bytes,
            &mut work,
            &mut applied,
            &ctx,
            attempt_idx as u32,
        ) {
            Ok(bytes) => {
                trace(&format!("attempt {attempt_idx}/{EMBED_ATTEMPTS} ok"));
                return Ok(bytes);
            }
            Err(attempt) => {
                trace(&format!(
                    "attempt {attempt_idx}/{EMBED_ATTEMPTS} retryable={} error={}",
                    attempt.retryable, attempt.error
                ));
                rollback(&mut work, &applied, fmt);
                last_error = Some(attempt.error);
                if !attempt.retryable {
                    break;
                }
            }
        }
    }
    Err(last_error.expect("embed_jpeg always runs at least one attempt"))
}

/// One full embedding pass over `work` (re-serialised against `carrier_bytes`).
///
/// Every coefficient change is appended to `applied` so the caller can restore
/// the original coefficients after a failed attempt. The header, extension area
/// and body share the same log, so a failure in a later stage cannot leave an
/// earlier stage's changes behind.
fn embed_once(
    carrier_bytes: &[u8],
    work: &mut JpegCoefficients,
    applied: &mut Vec<(u32, i8)>,
    ctx: &EmbedContext<'_>,
    attempt: u32,
) -> Result<Vec<u8>, Attempt> {
    let fmt = ctx.fmt;
    let params = ctx.params;
    let cover = ctx.cover;
    let suite = ctx.suite;
    let safety = ctx.safety;
    let n_total = cover.n_total();

    // Header geometry: the extension area first, because it decides how many
    // slots the header takes away from the body.
    let extension_area = encode_extension(&params.extensions)?;
    let ext_bytes = extension_area.len();
    if ext_bytes > u16::MAX as usize {
        return Err(Attempt::from(StrHideError::General(format!(
            "Extension area of {ext_bytes} bytes exceeds the 16-bit header field"
        ))));
    }
    let hdr_n = fmt.header_slots(ext_bytes);
    if n_total <= hdr_n {
        return Err(Attempt::from(StrHideError::General(format!(
            "Capacity exceeded: header needs {hdr_n} slots, the carrier grid has {n_total}"
        ))));
    }

    // Envelope: the plaintext length fixes the header field, which in turn is
    // the AAD, so encryption has to wait until the superblock is final.
    let total_coeffs = cover.block_count * 64;

    let plaintext = build_plaintext(ctx.payload)?;
    let ciphertext_len = plaintext.len() + suite.tag_len();
    let envelope_len = HEADER_OVERHEAD + ciphertext_len;
    if envelope_len as u64 > ENVELOPE_LEN_MAX as u64 {
        return Err(Attempt::from(StrHideError::General(format!(
            "Envelope of {envelope_len} bytes exceeds the 26-bit header length field"
        ))));
    }
    let bits = ciphertext_len * 8;

    let master = derive_master(suite, ctx.password, &cover.digest)?;
    let hdr_seed = header_perm_seed(fmt, &master, ctx.domain);

    // Single working buffer for the carrier AC grid (eliminates 336 MB of redundant Vec clones).
    let mut slots_buf = v3_layout::grid_indices(cover.block_count, fmt.grid_rule);
    permute_prefix(&mut slots_buf, hdr_n, &hdr_seed);
    let hdr_slots = slots_buf[..hdr_n].to_vec();

    // Reconstruct body grid in-place into the same allocated buffer!
    v3_layout::fill_body_grid(&mut slots_buf, &hdr_slots, cover.block_count, fmt.grid_rule);
    let body_grid_len = slots_buf.len();

    let effective_budget = params.effective_slot_budget(body_grid_len);
    let mut layout = v3_layout::compute(n_total, hdr_n, bits, params.stc_h, effective_budget)?;

    // An over-optimised Huffman table closes some directions outright (dead
    // slots) and makes cross-zero moves land on symbols the table lacks.
    // `u = 1` is a `(1,1)` parity code -- the solution is unique, so neither
    // can be routed around: one dead slot in the used set fails the embed
    // outright, and the forced ~50% change rate makes unencodable cross-zero
    // chains. Which one hits is a per-salt lottery (0/9 measured at `u = 1`,
    // 4/10 at `u = 2`, 10/10 at `u = 3`, 24 MP carrier, 512 KiB payload), so
    // `u = 2` is not offered either. Require `u = 3` whenever the carrier's
    // table is incomplete and the trellis fits; refuse early when it does
    // not, instead of burning seconds of work to lose a coin flip.
    if ctx.table.is_some() && layout.u < 3 {
        match crate::stego::params::grouped_body_budget(
            body_grid_len,
            bits,
            params.stc_h,
            effective_budget,
        ) {
            Some(budget) => {
                layout = v3_layout::compute(n_total, hdr_n, bits, params.stc_h, budget)?;
            }
            None => {
                return Err(Attempt {
                    error: StrHideError::UnsupportedFormat(
                        "This JPEG's Huffman table is over-optimised: it cannot encode the modifications required for this payload size. Please reduce payload or re-save the carrier with a standard (Annex K) table.".into(),
                    ),
                    retryable: false,
                });
            }
        }
    }

    check_pipeline_budget(ctx.base_bytes, layout.body_n, params.stc_h)?;

    // Safety tier: advisory (warn upstream) or enforced bpp ceiling.
    if safety.is_enforced() {
        let max = enforced_payload_limit(total_coeffs, body_grid_len, safety);
        if ctx.payload.len() > max {
            let bpp = (ctx.payload.len() * 8) as f64 / total_coeffs as f64;
            return Err(Attempt::from(StrHideError::General(format!(
                "Payload ({} bytes, bpp {:.4}) exceeds safety threshold ({} bytes, bpp <= {:.2}) for tier '{}'",
                ctx.payload.len(),
                bpp,
                max,
                safety.level.bpp_limit(),
                safety.level.as_str(),
            ))));
        }
    }

    let salt = ctx.freshness.salt(attempt, &ctx.fresh_binding);
    let nonce = ctx.freshness.nonce(attempt, &ctx.fresh_binding);
    let superblock = Superblock {
        version_major: fmt.format_major,
        version_minor: fmt.format_minor,
        flags: 0,
        salt,
        nonce,
        envelope_len: envelope_len as u32,
        suite_id: suite.id,
        codec_id: CODEC_TERNARY_STC,
        h: params.stc_h,
        u: layout.u,
        components_mask: COMPONENT_Y,
        ext_bytes: ext_bytes as u16,
    };
    let superblock_bytes = superblock.encode();

    let (enc_key, perm_seed) = body_keys(fmt, &master, &salt, ctx.domain);
    let ciphertext = encrypt_with_aad(suite, &enc_key, &nonce, &superblock_bytes, &plaintext)?;
    debug_assert_eq!(ciphertext.len(), ciphertext_len);

    let mut touched = vec![false; cover.block_count];

    // 1) Superblock: 352 bits through STC(sb_h, sb_u).
    if let Err(e) = embed_slots(
        &mut *work,
        &hdr_slots[..fmt.superblock_slots()],
        fmt,
        ctx.costs,
        ctx.directions,
        ctx.table,
        params,
        header_stc_seed(fmt, &hdr_seed, ctx.domain),
        fmt.sb_h,
        fmt.sb_u,
        &superblock_bytes,
        &mut touched,
        applied,
    ) {
        if ctx.table.is_some()
            && matches!(
                e,
                StrHideError::TrellisInfeasible {
                    cause: crate::errors::TrellisCause::DeadElement
                        | crate::errors::TrellisCause::DeadGroup,
                    ..
                }
            )
        {
            return Err(Attempt {
                error: StrHideError::UnsupportedFormat(
                    "This JPEG's Huffman table is over-optimised: it cannot encode the modifications required for this carrier. Please re-save the carrier with a standard (Annex K) table.".into(),
                ),
                retryable: false,
            });
        }
        return Err(Attempt::from(e));
    }

    // 2) Extension area: 8 bits per declared byte through STC(ext_h, ext_u).
    if ext_bytes > 0 {
        embed_slots(
            &mut *work,
            &hdr_slots[fmt.superblock_slots()..hdr_n],
            fmt,
            ctx.costs,
            ctx.directions,
            ctx.table,
            params,
            extension_stc_seed(fmt, &hdr_seed, ctx.domain),
            fmt.ext_h,
            fmt.ext_u,
            &extension_area,
            &mut touched,
            applied,
        )?;
    }

    // 3) Body: the ciphertext, over a keyed permutation of the body grid.
    permute_prefix(&mut slots_buf, layout.body_n, &perm_seed);
    slots_buf.truncate(layout.body_n);
    if let Err(e) = embed_slots(
        &mut *work,
        &slots_buf,
        fmt,
        ctx.costs,
        ctx.directions,
        ctx.table,
        params,
        stc_seed(fmt, &perm_seed, &salt),
        params.stc_h,
        layout.u,
        &ciphertext,
        &mut touched,
        applied,
    ) {
        if ctx.table.is_some()
            && matches!(
                e,
                StrHideError::TrellisInfeasible {
                    cause: crate::errors::TrellisCause::DeadElement
                        | crate::errors::TrellisCause::DeadGroup,
                    ..
                }
            )
        {
            return Err(Attempt {
                error: StrHideError::UnsupportedFormat(
                    "This JPEG's Huffman table is over-optimised: it cannot encode the modifications required for this payload size. Please reduce payload or re-save the carrier with a standard (Annex K) table.".into(),
                ),
                retryable: false,
            });
        }
        return Err(Attempt::from(e));
    }

    if let Some(table) = ctx.table
        && let Some((symbol, block, bad_blocks)) = missing_symbol_stats(&*work, &touched, table)
    {
        trace(&format!(
            "missing symbol {} in block {block}; {bad_blocks} bad block(s)",
            dht::describe_symbol(symbol)
        ));
        return Err(Attempt {
            error: dht::missing_symbol_error(symbol),
            retryable: true,
        });
    }

    dct_io::write_coefficients(carrier_bytes, &*work)
        .map_err(map_dct_error)
        .map_err(Into::into)
}

/// First missing symbol among the touched blocks, plus the block index and the
/// total number of bad blocks.
fn missing_symbol_stats(
    coeffs: &JpegCoefficients,
    touched: &[bool],
    table: &AcSymbolSet,
) -> Option<(u8, usize, usize)> {
    let mut first: Option<(u8, usize)> = None;
    let mut bad_blocks = 0usize;
    for (bi, block) in coeffs.components[0].blocks.iter().enumerate() {
        if !touched[bi] {
            continue;
        }
        if let Some(symbol) = dht::first_missing_symbol(block, table) {
            bad_blocks += 1;
            if first.is_none() {
                first = Some((symbol, bi));
            }
        }
    }
    first.map(|(symbol, block)| (symbol, block, bad_blocks))
}

/// One STC pass over one slot set.
#[allow(clippy::too_many_arguments)]
fn embed_slots(
    coeffs: &mut JpegCoefficients,
    slots: &[u32],
    fmt: &JpegFormatProfile,
    costs: &[f64],
    directions: Option<&[i8]>,
    table: Option<&AcSymbolSet>,
    params: &JpegParams,
    seed: u64,
    h: u8,
    u: u8,
    message: &[u8],
    touched: &mut [bool],
    applied: &mut Vec<(u32, i8)>,
) -> Result<(), StrHideError> {
    if slots.is_empty() {
        return Ok(());
    }
    let plan = plan_slots(
        coeffs,
        slots,
        fmt.grid_rule,
        costs,
        directions,
        table,
        params.wet_cost,
        params.polarize_weight,
    );
    let trellis = StcTrellis::from_seed_grouped(seed, h, u)?;
    let mut deltas = vec![0i8; slots.len()];
    let wet_cost = params.wet_cost;
    let polarize_weight = params.polarize_weight;
    let rule = fmt.grid_rule;
    trellis.embed_with_cost_fn(
        &plan.vals,
        &plan.moves,
        |j| {
            if let Some(ref overrides) = plan.sparse_overrides {
                overrides[j]
            } else {
                let (bi, k) = v3_layout::slot_to_coeff(slots[j], rule);
                let base = costs[bi * 64 + k].min(wet_cost);
                match directions {
                    Some(bias) if bias[bi * 64 + k] > 0 => (base * polarize_weight, base),
                    Some(bias) if bias[bi * 64 + k] < 0 => (base, base * polarize_weight),
                    _ => (base, base),
                }
            }
        },
        message,
        &mut deltas,
    )?;

    for (&idx, &delta) in slots.iter().zip(deltas.iter()) {
        if delta != 0 {
            let (bi, _) = v3_layout::slot_to_coeff(idx, fmt.grid_rule);
            touched[bi] = true;
            applied.push((idx, delta));
        }
    }
    apply_deltas(
        &mut coeffs.components[0].blocks,
        slots,
        &deltas,
        fmt.grid_rule,
    );
    Ok(())
}

/// Undo every recorded delta, newest first.
///
/// The three embed stages (superblock, extension area, body) append to the same
/// log, so this restores the exact coefficients the attempt started from.
fn rollback(coeffs: &mut JpegCoefficients, applied: &[(u32, i8)], fmt: &JpegFormatProfile) {
    let blocks = &mut coeffs.components[0].blocks;
    for &(idx, delta) in applied.iter().rev() {
        let (bi, k) = v3_layout::slot_to_coeff(idx, fmt.grid_rule);
        blocks[bi][k] = (blocks[bi][k] as i32 - delta as i32) as i16;
    }
}

/// Payload ceiling for the enforced safety tier.
fn enforced_payload_limit(
    total_coeffs: usize,
    body_slots: usize,
    safety: crate::stego::params::SafetyPolicy,
) -> usize {
    let bpp_bits = (total_coeffs as f64 * safety.level.bpp_limit()).floor() as usize;
    let ratio_bits = (body_slots as f64 / safety.level.target_ratio()).floor() as usize;
    (bpp_bits.min(ratio_bits) / 8).saturating_sub(BODY_OVERHEAD)
}

/// Extract a payload from a V3 JPEG carrier.
///
/// The signature deliberately carries no cost model: everything the decoder
/// needs (slot set, `u`, `h`, salt, nonce) comes from the key and the header.
pub fn extract_jpeg(
    carrier_bytes: &[u8],
    password: Option<&str>,
    domain: Option<&str>,
    fmt: &JpegFormatProfile,
    extract: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    fmt.validate()?;
    preflight_jpeg(carrier_bytes)?;
    let coeffs = dct_io::read_coefficients(carrier_bytes).map_err(map_dct_error)?;
    control.check()?;
    if coeffs.components.is_empty() {
        return Err(StrHideError::NoHiddenData("JPEG has no components".into()));
    }
    let cover = CoverFrame::read(fmt, &coeffs);
    let n_total = cover.n_total();
    let no_hidden = || StrHideError::NoHiddenData("No valid payload found".into());

    let password = password
        .filter(|s| !s.is_empty())
        .unwrap_or(crate::stego::envelope::PUBLIC_DEFAULT_SECRET);

    // The slot grid depends on the cover alone, so it is built once and copied
    // back into the working buffer for every trial suite. Rebuilding it per
    // trial (as this loop used to) re-ran the same double loop for a buffer that
    // is immediately permuted in place anyway.
    let grid_template = v3_layout::grid_indices(cover.block_count, fmt.grid_rule);
    let mut slots_buf = grid_template.clone();

    // Trial enumeration: ascending suite id, one KDF per attempt. A wrong
    // password and a non-carrier both end here, with the same error.
    for suite in fmt.suites {
        control.check()?;
        if !extract.allows_suite(suite.id) {
            continue;
        }
        if suite.cost() > extract.max_pbkdf2_iterations {
            continue;
        }
        let Ok(master) = derive_master(suite, password, &cover.digest) else {
            continue;
        };
        let hdr_seed = header_perm_seed(fmt, &master, domain);

        // Reset and reuse the single preallocated working buffer: `clear` keeps
        // the capacity, so this is a memcpy rather than a rebuild.
        slots_buf.clear();
        slots_buf.extend_from_slice(&grid_template);

        // The header prefix is at least the superblock plus the minimum
        // extension area (746 slots with the default profile). `ext_bytes` is
        // unknown until the superblock is read, so shuffle that minimum first
        // and, if the declared extension is larger, continue the same RNG
        // stream. A forward prefix shuffle only swaps `i` with an index in
        // `[i, n)`, so positions below `i` stay final across the continuation.
        let sb_n = fmt.superblock_slots();
        if slots_buf.len() < sb_n {
            continue;
        }
        let hdr_min = fmt.header_slots(0);
        let mut hdr_rng = ChaCha12Stream::from_seed(&hdr_seed);
        fisher_yates_prefix_from(&mut slots_buf, 0, hdr_min, &mut hdr_rng);

        let Some(superblock) = read_superblock(&coeffs, &slots_buf[..sb_n], fmt, &hdr_seed, domain)
        else {
            continue;
        };
        if superblock.validate_against(fmt, suite.id).is_err() {
            continue;
        }
        if superblock.codec_id != CODEC_TERNARY_STC {
            // Reserved for Hamming; no v1 writer produces it.
            continue;
        }

        let ext_bytes = superblock.ext_bytes as usize;
        let hdr_n = fmt.header_slots(ext_bytes);
        if hdr_n > n_total {
            continue;
        }
        if hdr_n > hdr_min {
            fisher_yates_prefix_from(&mut slots_buf, hdr_min, hdr_n, &mut hdr_rng);
        }
        let hdr_slots = slots_buf[..hdr_n].to_vec();

        let ext_slots = &hdr_slots[sb_n..hdr_n];
        let extension_area = if ext_bytes > 0 {
            let Some(area) = read_bits(
                &coeffs,
                ext_slots,
                fmt.grid_rule,
                extension_stc_seed(fmt, &hdr_seed, domain),
                fmt.ext_h,
                fmt.ext_u,
                8 * ext_bytes,
            ) else {
                continue;
            };
            area
        } else {
            Vec::new()
        };

        let ciphertext_len = superblock.ciphertext_len();
        let bits = ciphertext_len * 8;

        // Reconstruct body grid in-place into the same working buffer!
        v3_layout::fill_body_grid(&mut slots_buf, &hdr_slots, cover.block_count, fmt.grid_rule);
        let body_grid_len = slots_buf.len();
        let window = bits + superblock.h as usize - 1;
        let Some(body_n) = window.checked_mul(superblock.u as usize) else {
            continue;
        };
        if body_n > body_grid_len {
            continue;
        }
        let (enc_key, perm_seed) = body_keys(fmt, &master, &superblock.salt, domain);
        permute_prefix(&mut slots_buf, body_n, &perm_seed);
        slots_buf.truncate(body_n);
        let Some(ciphertext) = read_bits(
            &coeffs,
            &slots_buf,
            fmt.grid_rule,
            stc_seed(fmt, &perm_seed, &superblock.salt),
            superblock.h,
            superblock.u,
            bits,
        ) else {
            continue;
        };
        if ciphertext.len() != ciphertext_len {
            continue;
        }

        let aad = superblock.encode();
        let payload =
            match unpack_envelope_parts(suite, &enc_key, &superblock.nonce, &aad, &ciphertext) {
                Ok(payload) => payload,
                Err(StrHideError::CorruptedData(message)) => {
                    // The AEAD passed, so this really is our carrier; a bad
                    // field inside the plaintext is a genuine defect, not a
                    // wrong guess.
                    return Err(StrHideError::CorruptedData(message));
                }
                Err(StrHideError::UnsupportedVersion(message)) => {
                    return Err(StrHideError::UnsupportedVersion(message));
                }
                Err(_) => continue,
            };

        // The payload decrypted, so this carrier is ours with certainty. Only
        // now is it safe to report precise problems with the extension area
        // instead of folding them into "no payload here" -- doing it earlier
        // would turn structural checks into a cheap password oracle.
        if ext_bytes > 0 {
            let records = parse_extension(&extension_area)?;
            for (type_id, _) in &records {
                if type_id & TLV_CRITICAL != 0 {
                    return Err(StrHideError::UnsupportedVersion(format!(
                        "Carrier uses critical extension type {type_id:#04x}, which this build does not implement"
                    )));
                }
            }
        }
        return Ok(payload);
    }

    Err(no_hidden())
}

/// Read and structurally validate the superblock.
fn read_superblock(
    coeffs: &JpegCoefficients,
    slots: &[u32],
    fmt: &JpegFormatProfile,
    hdr_seed: &[u8; 32],
    domain: Option<&str>,
) -> Option<Superblock> {
    let bits = read_bits(
        coeffs,
        slots,
        fmt.grid_rule,
        header_stc_seed(fmt, hdr_seed, domain),
        fmt.sb_h,
        fmt.sb_u,
        fmt.superblock_bits(),
    )?;
    if bits.len() < SUPERBLOCK_BYTES {
        return None;
    }
    let mut raw = [0u8; SUPERBLOCK_BYTES];
    raw.copy_from_slice(&bits[..SUPERBLOCK_BYTES]);
    Superblock::decode(&raw).ok()
}

/// Run one STC pass in extraction mode: read the slot parities and return the
/// message bits.
fn read_bits(
    coeffs: &JpegCoefficients,
    slots: &[u32],
    rule: crate::stego::format::GridRule,
    seed: u64,
    h: u8,
    u: u8,
    bits: usize,
) -> Option<Vec<u8>> {
    let blocks = &coeffs.components[0].blocks;
    let vals: Vec<u8> = slots
        .iter()
        .map(|&idx| {
            let (bi, k) = v3_layout::slot_to_coeff(idx, rule);
            (blocks[bi][k] & 1) as u8
        })
        .collect();
    let trellis = StcTrellis::from_seed_grouped(seed, h, u).ok()?;
    if trellis.slots_for(bits) > vals.len() {
        return None;
    }
    let mut out = trellis.extract(&vals, bits);
    out.truncate(bits.div_ceil(8));
    Some(out)
}

/// Inspect JPEG for V3 superblock and stego metadata without solving trellis.
pub fn inspect_jpeg(
    carrier_bytes: &[u8],
    password: Option<&str>,
    domain: Option<&str>,
    fmt: &JpegFormatProfile,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    control.check()?;
    fmt.validate()?;
    let preflight = match preflight_jpeg(carrier_bytes) {
        Ok(p) => p,
        Err(e) => {
            return Ok(StegoHeaderInfo {
                format: "JPEG".into(),
                has_hidden_data: false,
                algorithm: None,
                codec: None,
                envelope_len: None,
                payload_len: None,
                media_info: None,
                note: Some(format!("Preflight failed: {e}")),
            });
        }
    };
    control.check()?;
    let media_info = Some(format!(
        "{}x{}",
        preflight.info.width, preflight.info.height
    ));
    let mut empty_info = StegoHeaderInfo::empty("JPEG");
    empty_info.media_info = media_info.clone();

    let coeffs = match dct_io::read_coefficients(carrier_bytes) {
        Ok(c) => c,
        Err(_) => return Ok(empty_info),
    };
    if coeffs.components.is_empty() {
        return Ok(empty_info);
    }
    control.check()?;
    let cover = CoverFrame::read(fmt, &coeffs);

    let password = password
        .filter(|s| !s.is_empty())
        .unwrap_or(crate::stego::envelope::PUBLIC_DEFAULT_SECRET);

    let grid_template = v3_layout::grid_indices(cover.block_count, fmt.grid_rule);
    let mut slots_buf = grid_template.clone();

    for suite in fmt.suites {
        control.check()?;
        let Ok(master) = derive_master(suite, password, &cover.digest) else {
            continue;
        };
        let hdr_seed = header_perm_seed(fmt, &master, domain);
        slots_buf.clear();
        slots_buf.extend_from_slice(&grid_template);

        let sb_n = fmt.superblock_slots();
        if slots_buf.len() < sb_n {
            continue;
        }
        let hdr_min = fmt.header_slots(0);
        let mut hdr_rng = ChaCha12Stream::from_seed(&hdr_seed);
        fisher_yates_prefix_from(&mut slots_buf, 0, hdr_min, &mut hdr_rng);

        let Some(superblock) = read_superblock(&coeffs, &slots_buf[..sb_n], fmt, &hdr_seed, domain)
        else {
            continue;
        };
        if superblock.validate_against(fmt, suite.id).is_err() {
            continue;
        }
        if superblock.codec_id != CODEC_TERNARY_STC {
            continue;
        }

        return Ok(StegoHeaderInfo {
            format: "JPEG".into(),
            has_hidden_data: true,
            algorithm: Some("UERD/J-UNIWARD".into()),
            codec: Some(format!(
                "Ternary STC (h={}, u={})",
                superblock.h, superblock.u
            )),
            envelope_len: Some(superblock.envelope_len as usize),
            payload_len: None,
            media_info,
            note: None,
        });
    }

    Ok(empty_info)
}

/// Three-level diagnostic verification for JPEG carriers.
pub fn verify_jpeg(
    carrier_bytes: &[u8],
    password: Option<&str>,
    domain: Option<&str>,
    fmt: &JpegFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    control.check()?;
    let mut levels = Vec::new();

    // Level 1: Container & DCT Coeffs Parse
    let (info, coeffs) = match preflight_jpeg(carrier_bytes).and_then(|p| {
        dct_io::read_coefficients(carrier_bytes)
            .map_err(map_dct_error)
            .map(|c| (p.info, c))
    }) {
        Ok((info, c)) => {
            levels.push(VerifyLevel::pass(
                1,
                format!(
                    "JPEG structure & DCT scan valid ({}x{}, {} blocks)",
                    info.width,
                    info.height,
                    c.components
                        .first()
                        .map(|comp| comp.blocks.len())
                        .unwrap_or(0)
                ),
            ));
            (info, c)
        }
        Err(e) => {
            levels.push(VerifyLevel::fail(
                1,
                "JPEG DCT coefficients decode",
                e.to_string(),
            ));
            levels.push(VerifyLevel::fail(
                2,
                "Stego superblock",
                "Skipped due to level 1 failure",
            ));
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                "Skipped due to level 1 failure",
            ));
            return Ok(StegoVerifyResult::new("JPEG", levels));
        }
    };
    let _ = (info, coeffs);
    control.check()?;

    // Level 2: Superblock inspection
    let header_info = inspect_jpeg(carrier_bytes, password, domain, fmt, control)?;
    if !header_info.has_hidden_data {
        levels.push(VerifyLevel::fail(
            2,
            "Stego superblock",
            "No valid V3 superblock found (or wrong password)",
        ));
        levels.push(VerifyLevel::fail(
            3,
            "Payload decryption",
            "No superblock to extract payload from",
        ));
        return Ok(StegoVerifyResult::new("JPEG", levels));
    }
    levels.push(VerifyLevel::pass(
        2,
        format!(
            "Stego superblock valid (codec: {}, envelope: {} B)",
            header_info.codec.as_deref().unwrap_or("unknown"),
            header_info.envelope_len.unwrap_or(0),
        ),
    ));
    control.check()?;

    // Level 3: Payload Decryption & AEAD Authenticity
    match extract_jpeg(carrier_bytes, password, domain, fmt, limits, control) {
        Ok(payload) => {
            let desc = match payload.name() {
                Some(name) => format!(
                    "Payload decrypted & verified ({} bytes, filename: '{}')",
                    payload.len(),
                    name
                ),
                None => format!(
                    "Payload decrypted & verified ({} bytes, raw/text)",
                    payload.len()
                ),
            };
            levels.push(VerifyLevel::pass(3, desc));
        }
        Err(e) => {
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                format!("Decryption or authentication failed: {e}"),
            ));
        }
    }

    Ok(StegoVerifyResult::new("JPEG", levels))
}

/// Probe the embedding capacity of a JPEG carrier.
///
/// The complete expert entry: `safety_level` picks the tier `recommended_max_bytes`
/// is derived from, `fmt` supplies the grid geometry the budget is measured
/// against.
pub fn probe_jpeg_capacity(
    carrier_bytes: &[u8],
    cost_model: &dyn JpegCostModel,
    params: &JpegParams,
    safety_level: crate::stego::SafetyLevel,
    fmt: &JpegFormatProfile,
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    fmt.validate()?;
    params.validate()?;
    control.check()?;
    let preflight = preflight_jpeg(carrier_bytes)?;
    let info = preflight.info;
    let geom = crate::stego::jpeg::geometry::component_geometry(&info, 0, 0);
    let block_count = geom.grid_w * geom.grid_h;
    let n_total = block_count * fmt.grid_rule.slots_per_block();
    let ext_bytes = encode_extension(&params.extensions)?.len();
    let hdr_n = fmt.header_slots(ext_bytes);
    if n_total <= hdr_n {
        return Err(StrHideError::General(format!(
            "Capacity exceeded: header needs {hdr_n} slots, the carrier grid has {n_total}"
        )));
    }
    let body_slots = n_total - hdr_n;

    // The physical ceiling is `u = 1`; `u` grows from there as the payload
    // shrinks, so this is the largest payload that fits at all.
    let mut max_bits = v3_layout::max_payload_bits(body_slots, params.stc_h);
    let mut max_raw_is_grouped = false;
    // ... unless the carrier's Huffman table is over-optimised. `u = 1` then
    // has no routing freedom around dead slots and cross-zero chains, and
    // `u = 2` still fails often enough to be a coin flip at these loads, so
    // the embedder requires `u = 3` (`embed_once`) and the grouped bound is
    // the real ceiling. Reporting the geometric one here would advertise a
    // capacity that always fails.
    if dht::luma_ac_symbols(carrier_bytes).is_some_and(|t| !t.is_complete()) {
        let room = body_slots.min(crate::stego::params::max_grouped_backtrack_slots(
            params.stc_h,
        ));
        let grouped_bits = (room / 3).saturating_sub(params.stc_h as usize - 1);
        if grouped_bits < max_bits {
            max_bits = grouped_bits;
            max_raw_is_grouped = true;
        }
    }
    let max_ciphertext_bytes = max_bits / 8;
    let max_raw_payload_bytes = max_ciphertext_bytes.saturating_sub(BODY_OVERHEAD);

    let total_coeffs = block_count * 64;
    let effective_budget = params.effective_slot_budget(body_slots);

    let bpp_bits = (total_coeffs as f64 * safety_level.bpp_limit()).floor() as usize;
    let ratio_bits = (body_slots as f64 / safety_level.target_ratio()).floor() as usize;
    let recommended_max_bytes = (bpp_bits.min(ratio_bits) / 8).saturating_sub(BODY_OVERHEAD);

    // Report the change rate of the group size the recommended payload would
    // actually use, which is what the user sees if they follow the advice.
    let recommended_bits = (recommended_max_bytes + BODY_OVERHEAD) * 8;
    let u = v3_layout::compute(
        n_total,
        hdr_n,
        recommended_bits,
        params.stc_h,
        effective_budget,
    )
    .map(|layout| layout.u)
    .unwrap_or(1);

    Ok(StegoCapacityInfo {
        format: "JPEG".into(),
        algorithm: cost_model.id().into(),
        total_elements: total_coeffs,
        available_slots: body_slots,
        max_raw_payload_bytes,
        max_raw_is_grouped,
        recommended_max_bytes,
        estimated_change_rate: crate::stego::coding::expected_stc_change_rate(u),
        safety_level: safety_level.as_str().into(),
        safety_bpp_limit: safety_level.bpp_limit(),
        is_estimated: false,
        media_info: Some(format!("{}x{}", info.width, info.height)),
    })
}

/// Layout information for diagnostics and tests: the resolved group size and
/// body slot count for a given payload.
///
/// Takes the payload bytes, not just its length: [`build_plaintext`] deflates
/// the payload whenever that is smaller, and the ciphertext length (plaintext +
/// AEAD tag, the suite comes from `params.cipher_suite`) is what actually
/// decides `u`. A length-only API reported the layout of an uncompressed
/// envelope -- exactly the case where the real writer picks a larger `u`.
pub fn layout_for_payload(
    carrier_bytes: &[u8],
    payload: &[u8],
    params: &JpegParams,
    fmt: &JpegFormatProfile,
) -> Result<Layout, StrHideError> {
    fmt.validate()?;
    params.validate()?;
    let suite = fmt.suite(params.cipher_suite).ok_or_else(|| {
        StrHideError::UnsupportedVersion(format!(
            "Cipher suite {} is not implemented by this build (known: {:?})",
            params.cipher_suite,
            fmt.suites.iter().map(|s| s.id).collect::<Vec<_>>()
        ))
    })?;
    let preflight = preflight_jpeg(carrier_bytes)?;
    let coeffs = dct_io::read_coefficients(carrier_bytes).map_err(map_dct_error)?;
    if coeffs.components.is_empty() {
        return Err(StrHideError::UnsupportedFormat(
            "JPEG has no image components".into(),
        ));
    }
    let block_count = coeffs.components[0].blocks.len();
    let n_total = block_count * fmt.grid_rule.slots_per_block();
    let ext_bytes = encode_extension(&params.extensions)?.len();
    let hdr_n = fmt.header_slots(ext_bytes);
    let plaintext = build_plaintext_bytes(payload)?;
    let ciphertext_len = plaintext.len() + suite.tag_len();
    let body_slots = n_total.saturating_sub(hdr_n);
    let effective_budget = params.effective_slot_budget(body_slots);
    let bits = ciphertext_len * 8;
    // Same grouped floor the embedder applies: report the layout the embed
    // will actually use, not the one the distortion heuristic alone picks.
    let budget = if dht::luma_ac_symbols(carrier_bytes).is_some_and(|t| !t.is_complete()) {
        crate::stego::params::grouped_body_budget(body_slots, bits, params.stc_h, effective_budget)
            .ok_or_else(|| {
                StrHideError::UnsupportedFormat(
                    "This JPEG's Huffman table is over-optimised: it cannot encode the modifications required for this payload size. Please reduce payload or re-save the carrier with a standard (Annex K) table.".into(),
                )
            })?
    } else {
        effective_budget
    };
    let layout = v3_layout::compute(n_total, hdr_n, bits, params.stc_h, budget)?;
    check_pipeline_budget(preflight.base_bytes, layout.body_n, params.stc_h)?;
    Ok(layout)
}
