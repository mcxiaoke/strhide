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

use crate::errors::StrHideError;
use crate::stego::StegoCapacityInfo;
use crate::stego::coding::{Move, StcTrellis};
use crate::stego::envelope::{
    BODY_OVERHEAD, HEADER_OVERHEAD, build_plaintext, encrypt_with_aad, random_nonce, random_salt,
    unpack_envelope_parts,
};
use crate::stego::format::{
    DEFAULT_FORMAT, FormatProfile, body_keys, derive_master, extension_stc_seed, header_perm_seed,
    header_stc_seed, stc_seed,
};
use crate::stego::jpeg::dht::{self, AcSymbolSet};
use crate::stego::jpeg::header_v3::{
    CODEC_TERNARY_STC, COMPONENT_Y, ENVELOPE_LEN_MAX, SUPERBLOCK_BYTES, Superblock, TLV_CRITICAL,
    encode_extension, parse_extension,
};
use crate::stego::jpeg::v3_layout::{self, Layout};
use crate::stego::params::{ExtractParams, JpegParams, SafetyEnforcement};
use crate::stego::prng::permute_indices;
use crate::stego::traits::JpegCostModel;

/// Map a dct_io error to StrHideError.
fn map_dct_error(e: dct_io::DctError) -> StrHideError {
    let err_str = e.to_string();
    if err_str.contains("SOF2") || err_str.to_lowercase().contains("progressive") {
        return StrHideError::UnsupportedFormat(
            "Progressive JPEG (SOF2) is not supported for content-adaptive DCT steganography; please convert to baseline JPEG or use 'strhide write' for structural hiding".into(),
        );
    }
    match e {
        dct_io::DctError::Unsupported(msg) => {
            if msg.contains("SOF2") || msg.to_lowercase().contains("progressive") {
                StrHideError::UnsupportedFormat(
                    "Progressive JPEG (SOF2) is not supported for content-adaptive DCT steganography; please convert to baseline JPEG or use 'strhide write' for structural hiding".into(),
                )
            } else {
                StrHideError::UnsupportedFormat(format!("Unsupported JPEG variant: {msg}"))
            }
        }
        _ => StrHideError::CorruptedData(format!("Corrupt JPEG coefficient stream: {e}")),
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
    fn read(fmt: &FormatProfile, coeffs: &JpegCoefficients) -> Self {
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
fn cover_digest(fmt: &FormatProfile, coeffs: &JpegCoefficients) -> [u8; 32] {
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
///
/// Note: On standard carriers (complete Huffman table), costs are read directly
/// on demand from `costs`, saving ~224 MB of preallocated `Vec<f64>` heap buffers.
struct SlotPlan {
    vals: Vec<u8>,
    moves: Vec<Move>,
    sparse_overrides: Option<Vec<(f64, f64)>>,
}

/// Build the trellis inputs for one slot set.
///
/// `table` is `None` for a complete Huffman table (the fast path: zero per-slot
/// cost buffer allocation), otherwise custom cross-zero costs are tracked in overrides.
fn plan_slots(
    coeffs: &JpegCoefficients,
    slots: &[u32],
    rule: crate::stego::format::GridRule,
    costs: &[f64],
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

    let mut block_runs: Vec<Option<[u8; 64]>> = if table.is_some() {
        vec![None; blocks.len()]
    } else {
        Vec::new()
    };

    for &idx in slots {
        let (bi, k) = v3_layout::slot_to_coeff(idx, rule);
        let coeff = blocks[bi][k];
        let legal = ternary_legal(coeff);
        let mut allow_plus = matches!(legal, Move::Both | Move::PlusOnly);
        let mut allow_minus = matches!(legal, Move::Both | Move::MinusOnly);

        // A move that crosses zero (`0 <-> ±1`) changes the zero pattern of the
        // block, hence the run of later coefficients: checked via `can_encode_move`.
        let crosses_zero_plus = coeff == 0 || coeff == -1;
        let crosses_zero_minus = coeff == 0 || coeff == 1;

        if let Some(table) = table {
            let runs = match block_runs[bi] {
                Some(r) => r,
                None => {
                    let r = dht::zero_runs(&blocks[bi]);
                    block_runs[bi] = Some(r);
                    r
                }
            };

            if crosses_zero_plus {
                if allow_plus && !dht::can_encode_move(&blocks[bi], k, coeff + 1, table) {
                    allow_plus = false;
                }
            } else if allow_plus && !direction_encodable(table, &runs, k, coeff + 1) {
                allow_plus = false;
            }

            if crosses_zero_minus {
                if allow_minus && !dht::can_encode_move(&blocks[bi], k, coeff - 1, table) {
                    allow_minus = false;
                }
            } else if allow_minus && !direction_encodable(table, &runs, k, coeff - 1) {
                allow_minus = false;
            }
        }

        let base = costs[bi * 64 + k].min(wet_cost);
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
                wet_cost
            } else {
                base
            };
            let minus_cost = if !allow_minus {
                f64::INFINITY
            } else if crosses_zero_minus {
                wet_cost
            } else {
                base * polarize_weight
            };
            overrides.push((plus_cost, minus_cost));
        }

        plan.vals.push(parity_carrier(coeff));
        plan.moves.push(mv);
    }
    plan
}

/// Whether a `±1` move to `value` needs a symbol the table defines.
///
/// Returns `true` for structural moves (value 0) so they are not closed here.
fn direction_encodable(table: &AcSymbolSet, runs: &[u8; 64], k: usize, value: i16) -> bool {
    let category = dht::category(value);
    if category == 0 {
        return true;
    }
    table.has((runs[k] << 4) | category)
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
        let updated = blocks[bi][k] as i32 + delta as i32;
        debug_assert!(
            updated.abs() <= 1023,
            "AC coefficient left the baseline range"
        );
        blocks[bi][k] = updated as i16;
    }
}

/// Everything the two attempts share.
struct EmbedContext<'a> {
    fmt: &'a FormatProfile,
    suite: &'a crate::stego::format::CipherSuite,
    params: &'a JpegParams,
    cover: &'a CoverFrame,
    costs: &'a [f64],
    table: Option<&'a AcSymbolSet>,
    password: &'a str,
    domain: Option<&'a str>,
}

/// Number of salt values tried when a Huffman-limited block cannot be encoded.
///
/// Only the *missing symbol* failure is retried, and retrying is invisible to the
/// extractor: the salt and nonce live in the (AAD-protected) superblock and are
/// read back from it, so a new salt is simply a different valid carrier. The
/// trellis seed and the slot set are re-derived from that salt, which is what
/// changes the outcome.
const EMBED_ATTEMPTS: usize = 3;

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

/// Embed a payload into a JPEG carrier with V3 ternary STC.
///
/// # Over-optimised Huffman tables
///
/// A table that only defines the symbols the *cover* needed cannot always encode
/// the stego version: a move can need another symbol, and a move that crosses
/// zero also shifts the runs of later coefficients in the same block -- a chain
/// no slot-level test can predict. Two defences, in order:
///
/// 1. moves within the non-zero range whose `(run, category)` is missing are
///    closed, and cross-zero moves are priced at the wet cost so the trellis only
///    uses them when a whole group window has nothing else;
/// 2. [`first_missing_symbol`](dht::first_missing_symbol) replays every touched
///    block after the fact. A failure there is retried with a fresh salt (which
///    re-draws the slot order and the header bits); if every attempt fails, the
///    embed reports the symbol and says what to do, instead of letting `dct-io`
///    raise a bare `CorruptEntropy`.
#[allow(clippy::too_many_arguments)]
pub fn embed_jpeg(
    carrier_bytes: &[u8],
    payload: &[u8],
    password: Option<&str>,
    domain: Option<&str>,
    fmt: &FormatProfile,
    params: &JpegParams,
    cost_model: &dyn JpegCostModel,
) -> Result<Vec<u8>, StrHideError> {
    fmt.validate()?;
    params.validate()?;
    let suite = fmt.suite(params.cipher_suite).ok_or_else(|| {
        StrHideError::UnsupportedVersion(format!(
            "Cipher suite {} is not implemented by this build (known: {:?})",
            params.cipher_suite,
            fmt.suites.iter().map(|s| s.id).collect::<Vec<_>>()
        ))
    })?;

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
    if costs.len() != cover.block_count * 64 {
        return Err(StrHideError::General("JPEG cost dimension mismatch".into()));
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
        table: table.as_ref(),
        password: password
            .filter(|s| !s.is_empty())
            .unwrap_or(crate::stego::envelope::PUBLIC_DEFAULT_SECRET),
        domain,
    };
    let mut last_error = None;
    for _ in 0..EMBED_ATTEMPTS {
        match embed_once(carrier_bytes, &coeffs, payload, &ctx) {
            Ok(bytes) => return Ok(bytes),
            Err(attempt) => {
                last_error = Some(attempt.error);
                if !attempt.retryable {
                    break;
                }
            }
        }
    }
    Err(last_error.expect("embed_jpeg always runs at least one attempt"))
}

/// One full embedding pass over `coeffs` (which are re-serialised against
/// `carrier_bytes`).
fn embed_once(
    carrier_bytes: &[u8],
    coeffs: &JpegCoefficients,
    payload: &[u8],
    ctx: &EmbedContext<'_>,
) -> Result<Vec<u8>, Attempt> {
    let mut work = coeffs.clone();
    let fmt = ctx.fmt;
    let params = ctx.params;
    let cover = ctx.cover;
    let suite = ctx.suite;
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

    let plaintext = build_plaintext(payload)?;
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
    permute_indices(&mut slots_buf, &hdr_seed);
    let hdr_slots = slots_buf[..hdr_n].to_vec();

    // Reconstruct body grid in-place into the same allocated buffer!
    v3_layout::fill_body_grid(&mut slots_buf, &hdr_slots, cover.block_count, fmt.grid_rule);
    let body_grid_len = slots_buf.len();

    let effective_budget = params.effective_slot_budget(body_grid_len);
    let layout = v3_layout::compute(n_total, hdr_n, bits, params.stc_h, effective_budget)?;

    // Safety tier: advisory (warn upstream) or enforced bpp ceiling.
    if params.safety_enforcement == SafetyEnforcement::Enforced {
        let max = enforced_payload_limit(total_coeffs, body_grid_len, params);
        if payload.len() > max {
            let bpp = (payload.len() * 8) as f64 / total_coeffs as f64;
            return Err(Attempt::from(StrHideError::General(format!(
                "Payload ({} bytes, bpp {:.4}) exceeds safety threshold ({} bytes, bpp <= {:.2}) for tier '{}'",
                payload.len(),
                bpp,
                max,
                params.safety_level.bpp_limit(),
                params.safety_level.as_str(),
            ))));
        }
    }

    let salt = random_salt();
    let nonce = random_nonce();
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
        &mut work,
        &hdr_slots[..fmt.superblock_slots()],
        fmt,
        ctx.costs,
        ctx.table,
        params,
        header_stc_seed(fmt, &hdr_seed, ctx.domain),
        fmt.sb_h,
        fmt.sb_u,
        &superblock_bytes,
        &mut touched,
    ) {
        if ctx.table.is_some() && e.to_string().contains("no legal element") {
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
            &mut work,
            &hdr_slots[fmt.superblock_slots()..hdr_n],
            fmt,
            ctx.costs,
            ctx.table,
            params,
            extension_stc_seed(fmt, &hdr_seed, ctx.domain),
            fmt.ext_h,
            fmt.ext_u,
            &extension_area,
            &mut touched,
        )?;
    }

    // 3) Body: the ciphertext, over a keyed permutation of the body grid.
    permute_indices(&mut slots_buf, &perm_seed);
    slots_buf.truncate(layout.body_n);
    if let Err(e) = embed_slots(
        &mut work,
        &slots_buf,
        fmt,
        ctx.costs,
        ctx.table,
        params,
        stc_seed(fmt, &perm_seed, &salt),
        params.stc_h,
        layout.u,
        &ciphertext,
        &mut touched,
    ) {
        if ctx.table.is_some() && e.to_string().contains("no legal element") {
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
        && let Some(symbol) = first_missing_symbol(&work, &touched, table)
    {
        return Err(Attempt {
            error: dht::missing_symbol_error(symbol),
            retryable: true,
        });
    }

    dct_io::write_coefficients(carrier_bytes, &work)
        .map_err(map_dct_error)
        .map_err(Into::into)
}

/// First missing symbol among the touched blocks, if any.
fn first_missing_symbol(
    coeffs: &JpegCoefficients,
    touched: &[bool],
    table: &AcSymbolSet,
) -> Option<u8> {
    for (bi, block) in coeffs.components[0].blocks.iter().enumerate() {
        if !touched[bi] {
            continue;
        }
        if let Some(symbol) = dht::first_missing_symbol(block, table) {
            return Some(symbol);
        }
    }
    None
}

/// One STC pass over one slot set.
#[allow(clippy::too_many_arguments)]
fn embed_slots(
    coeffs: &mut JpegCoefficients,
    slots: &[u32],
    fmt: &FormatProfile,
    costs: &[f64],
    table: Option<&AcSymbolSet>,
    params: &JpegParams,
    seed: u64,
    h: u8,
    u: u8,
    message: &[u8],
    touched: &mut [bool],
) -> Result<(), StrHideError> {
    if slots.is_empty() {
        return Ok(());
    }
    let plan = plan_slots(
        coeffs,
        slots,
        fmt.grid_rule,
        costs,
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
                (base, base * polarize_weight)
            }
        },
        message,
        &mut deltas,
    )?;

    for (&idx, &delta) in slots.iter().zip(deltas.iter()) {
        if delta != 0 {
            let (bi, _) = v3_layout::slot_to_coeff(idx, fmt.grid_rule);
            touched[bi] = true;
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

/// Payload ceiling for the enforced safety tier.
fn enforced_payload_limit(total_coeffs: usize, body_slots: usize, params: &JpegParams) -> usize {
    let bpp_bits = (total_coeffs as f64 * params.safety_level.bpp_limit()).floor() as usize;
    let ratio_bits = (body_slots as f64 / params.safety_level.target_ratio()).floor() as usize;
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
    fmt: &FormatProfile,
    extract: &ExtractParams,
) -> Result<Vec<u8>, StrHideError> {
    fmt.validate()?;
    let coeffs = dct_io::read_coefficients(carrier_bytes).map_err(map_dct_error)?;
    if coeffs.components.is_empty() {
        return Err(StrHideError::NoHiddenData("JPEG has no components".into()));
    }
    let cover = CoverFrame::read(fmt, &coeffs);
    let n_total = cover.n_total();
    let no_hidden = || StrHideError::NoHiddenData("No valid payload found".into());

    let password = password
        .filter(|s| !s.is_empty())
        .unwrap_or(crate::stego::envelope::PUBLIC_DEFAULT_SECRET);

    let mut slots_buf = v3_layout::grid_indices(cover.block_count, fmt.grid_rule);

    // Trial enumeration: ascending suite id, one KDF per attempt. A wrong
    // password and a non-carrier both end here, with the same error.
    for suite in fmt.suites {
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

        // Reset and reuse the single preallocated working buffer
        let per_block = fmt.grid_rule.slots_per_block();
        slots_buf.clear();
        for bi in 0..cover.block_count {
            let base = (bi * per_block) as u32;
            for s in 0..per_block {
                slots_buf.push(base + s as u32);
            }
        }
        permute_indices(&mut slots_buf, &hdr_seed);

        let sb_n = fmt.superblock_slots();
        if slots_buf.len() < sb_n {
            continue;
        }
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
        permute_indices(&mut slots_buf, &perm_seed);
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
    fmt: &FormatProfile,
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

/// Probe capacity of a JPEG carrier.
pub fn probe_jpeg_capacity(
    carrier_bytes: &[u8],
    cost_model: &dyn JpegCostModel,
    params: &JpegParams,
    safety_level: crate::stego::SafetyLevel,
) -> Result<StegoCapacityInfo, StrHideError> {
    probe_capacity_with_format(
        carrier_bytes,
        cost_model,
        params,
        safety_level,
        &DEFAULT_FORMAT,
    )
}

/// [`probe_jpeg_capacity`] for a non-default [`FormatProfile`].
pub fn probe_capacity_with_format(
    carrier_bytes: &[u8],
    cost_model: &dyn JpegCostModel,
    params: &JpegParams,
    safety_level: crate::stego::SafetyLevel,
    fmt: &FormatProfile,
) -> Result<StegoCapacityInfo, StrHideError> {
    fmt.validate()?;
    params.validate()?;
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
    if n_total <= hdr_n {
        return Err(StrHideError::General(format!(
            "Capacity exceeded: header needs {hdr_n} slots, the carrier grid has {n_total}"
        )));
    }
    let body_slots = n_total - hdr_n;

    // The physical ceiling is `u = 1`; `u` grows from there as the payload
    // shrinks, so this is the largest payload that fits at all.
    let max_bits = v3_layout::max_payload_bits(body_slots, params.stc_h);
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
        recommended_max_bytes,
        estimated_change_rate: crate::stego::coding::expected_stc_change_rate(u),
        safety_level: safety_level.as_str().into(),
        safety_bpp_limit: safety_level.bpp_limit(),
    })
}

/// Layout information for diagnostics and tests: the resolved group size and
/// body slot count for a given payload length.
pub fn layout_for_payload(
    carrier_bytes: &[u8],
    payload_len: usize,
    params: &JpegParams,
    fmt: &FormatProfile,
) -> Result<Layout, StrHideError> {
    fmt.validate()?;
    params.validate()?;
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
    let ciphertext_len = payload_len + 5 + 16;
    let body_slots = n_total.saturating_sub(hdr_n);
    let effective_budget = params.effective_slot_budget(body_slots);
    v3_layout::compute(
        n_total,
        hdr_n,
        ciphertext_len * 8,
        params.stc_h,
        effective_budget,
    )
}
