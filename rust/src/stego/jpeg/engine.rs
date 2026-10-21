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
    /// Grid slots in ascending flat-index order.
    grid: Vec<u32>,
    /// SHA-256 over the block/component counts and every DC coefficient.
    digest: [u8; 32],
}

impl CoverFrame {
    fn read(fmt: &FormatProfile, coeffs: &JpegCoefficients) -> Self {
        let block_count = coeffs.components[0].blocks.len();
        let grid = v3_layout::grid_indices(block_count, fmt.grid_rule);
        Self {
            block_count,
            grid,
            digest: cover_digest(fmt, coeffs),
        }
    }

    fn n_total(&self) -> usize {
        self.grid.len()
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

/// Per-slot arrays the trellis needs, plus the blocks they touch.
struct SlotPlan {
    vals: Vec<u8>,
    moves: Vec<Move>,
    rho_plus: Vec<f64>,
    rho_minus: Vec<f64>,
}

/// Build the trellis inputs for one slot set.
///
/// `table` is `None` for a complete Huffman table (the fast path: no per-slot
/// symbol work at all), otherwise the missing directions are closed by an
/// infinite cost.
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
        rho_plus: Vec::with_capacity(slots.len()),
        rho_minus: Vec::with_capacity(slots.len()),
    };

    let mut last_block = usize::MAX;
    let mut runs = [0u8; 64];

    for &idx in slots {
        let (bi, k) = v3_layout::slot_to_coeff(idx, rule);
        let coeff = blocks[bi][k];
        let legal = ternary_legal(coeff);
        let mut allow_plus = matches!(legal, Move::Both | Move::PlusOnly);
        let mut allow_minus = matches!(legal, Move::Both | Move::MinusOnly);

        // A move that crosses zero (`0 <-> ±1`) changes the zero pattern of the
        // block, hence the run of later coefficients: no slot-level test can
        // predict it, only the block-level replay in `first_missing_symbol`.
        let crosses_zero_plus = coeff == 0 || coeff == -1;
        let crosses_zero_minus = coeff == 0 || coeff == 1;

        if let Some(table) = table {
            if last_block != bi {
                runs = dht::zero_runs(&blocks[bi]);
                last_block = bi;
            }
            // Crossing zero moves are left to the replay; a move within the
            // non-zero range has a symbol that can be checked here and now.
            if !crosses_zero_plus && !direction_encodable(table, &runs, k, coeff + 1) {
                allow_plus = false;
            }
            if !crosses_zero_minus && !direction_encodable(table, &runs, k, coeff - 1) {
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
        // On an over-optimised table a cross-zero move is priced at the wet cost
        // rather than banned: banning it dead-ends any group window that has no
        // non-zero coefficient at all, which is common on sparse carriers.
        let plus_cost = if !allow_plus {
            f64::INFINITY
        } else if table.is_some() && crosses_zero_plus {
            wet_cost
        } else {
            base
        };
        let minus_cost = if !allow_minus {
            f64::INFINITY
        } else if table.is_some() && crosses_zero_minus {
            wet_cost
        } else {
            base * polarize_weight
        };
        plan.vals.push(parity_carrier(coeff));
        plan.moves.push(mv);
        plan.rho_plus.push(plus_cost);
        plan.rho_minus.push(minus_cost);
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
///    block after the fact. If that finds a symbol the table lacks, the embed
///    fails with a diagnostic that names the symbol and says what to do, instead
///    of letting `dct-io` raise a bare `CorruptEntropy`.
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
        password: password.unwrap_or(crate::stego::envelope::PUBLIC_DEFAULT_SECRET),
        domain,
    };
    embed_once(carrier_bytes, &coeffs, payload, &ctx)
}

/// One full embedding pass over `coeffs` (which are re-serialised against
/// `carrier_bytes`).
fn embed_once(
    carrier_bytes: &[u8],
    coeffs: &JpegCoefficients,
    payload: &[u8],
    ctx: &EmbedContext<'_>,
) -> Result<Vec<u8>, StrHideError> {
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
        return Err(StrHideError::General(format!(
            "Extension area of {ext_bytes} bytes exceeds the 16-bit header field"
        )));
    }
    let hdr_n = fmt.header_slots(ext_bytes);
    if n_total <= hdr_n {
        return Err(StrHideError::General(format!(
            "Capacity exceeded: header needs {hdr_n} slots, the carrier grid has {n_total}"
        )));
    }

    // Envelope: the plaintext length fixes the header field, which in turn is
    // the AAD, so encryption has to wait until the superblock is final.
    let plaintext = build_plaintext(payload)?;
    let ciphertext_len = plaintext.len() + suite.tag_len();
    let envelope_len = HEADER_OVERHEAD + ciphertext_len;
    if envelope_len as u64 > ENVELOPE_LEN_MAX as u64 {
        return Err(StrHideError::General(format!(
            "Envelope of {envelope_len} bytes exceeds the 26-bit header length field"
        )));
    }
    let bits = ciphertext_len * 8;

    let master = derive_master(suite, ctx.password, &cover.digest)?;
    let hdr_seed = header_perm_seed(fmt, &master, ctx.domain);
    let mut hdr_slots = cover.grid.clone();
    permute_indices(&mut hdr_slots, &hdr_seed);
    hdr_slots.truncate(hdr_n);

    let body_grid = v3_layout::body_grid(&cover.grid, &hdr_slots, cover.block_count);
    let layout = v3_layout::compute(n_total, hdr_n, bits, params.stc_h, params.slot_budget)?;

    // Safety tier: advisory (warn upstream) or enforced bpp ceiling.
    if params.safety_enforcement == SafetyEnforcement::Enforced {
        let max = enforced_payload_limit(n_total, body_grid.len(), params);
        if payload.len() > max {
            let bpp = (payload.len() * 8) as f64 / (cover.block_count * 64) as f64;
            return Err(StrHideError::General(format!(
                "Payload ({} bytes, bpp {:.4}) exceeds safety threshold ({} bytes, bpp <= {:.2}) for tier '{}'",
                payload.len(),
                bpp,
                max,
                params.safety_level.bpp_limit(),
                params.safety_level.as_str(),
            )));
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
    embed_slots(
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
    )?;

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
    let mut body_slots = body_grid;
    permute_indices(&mut body_slots, &perm_seed);
    body_slots.truncate(layout.body_n);
    embed_slots(
        &mut work,
        &body_slots,
        fmt,
        ctx.costs,
        ctx.table,
        params,
        stc_seed(fmt, &perm_seed, &salt),
        params.stc_h,
        layout.u,
        &ciphertext,
        &mut touched,
    )?;

    if let Some(table) = ctx.table
        && let Some(symbol) = first_missing_symbol(&work, &touched, table)
    {
        return Err(dht::missing_symbol_error(symbol));
    }

    dct_io::write_coefficients(carrier_bytes, &work).map_err(map_dct_error)
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
    trellis.embed_with_deltas(
        &plan.vals,
        &plan.moves,
        &plan.rho_plus,
        &plan.rho_minus,
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

    let password = password.unwrap_or(crate::stego::envelope::PUBLIC_DEFAULT_SECRET);

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
        let mut hdr_slots = cover.grid.clone();
        permute_indices(&mut hdr_slots, &hdr_seed);

        let sb_n = fmt.superblock_slots();
        if hdr_slots.len() < sb_n {
            continue;
        }
        let Some(superblock) = read_superblock(&coeffs, &hdr_slots[..sb_n], fmt, &hdr_seed, domain)
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
        hdr_slots.truncate(hdr_n);

        // Extension TLV area. An unknown critical record is *not* a "no payload
        // here" condition: the header authenticated, this build is just older
        // than the carrier.
        if ext_bytes > 0 {
            let ext_slots = &hdr_slots[sb_n..hdr_n];
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
            let Ok(records) = parse_extension(&area) else {
                continue;
            };
            for (type_id, _) in &records {
                if type_id & TLV_CRITICAL != 0 {
                    return Err(StrHideError::UnsupportedVersion(format!(
                        "Carrier uses critical extension type {type_id:#04x}, which this build does not implement"
                    )));
                }
            }
        }

        let ciphertext_len = superblock.ciphertext_len();
        let bits = ciphertext_len * 8;
        let body_grid = v3_layout::body_grid(&cover.grid, &hdr_slots, cover.block_count);
        let window = bits + superblock.h as usize - 1;
        let body_n = superblock.u as usize * window;
        if body_n > body_grid.len() {
            continue;
        }
        let (enc_key, perm_seed) = body_keys(fmt, &master, &superblock.salt, domain);
        let mut body_slots = body_grid;
        permute_indices(&mut body_slots, &perm_seed);
        body_slots.truncate(body_n);
        let Some(ciphertext) = read_bits(
            &coeffs,
            &body_slots,
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
        match unpack_envelope_parts(suite, &enc_key, &superblock.nonce, &aad, &ciphertext) {
            Ok(payload) => return Ok(payload),
            Err(StrHideError::CorruptedData(message)) => {
                // The AEAD passed, so this really is our carrier; a bad field
                // inside the plaintext is a genuine defect, not a wrong guess.
                return Err(StrHideError::CorruptedData(message));
            }
            Err(_) => continue,
        }
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
        params.slot_budget,
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
    let coeffs = dct_io::read_coefficients(carrier_bytes).map_err(map_dct_error)?;
    let block_count = coeffs.components[0].blocks.len();
    let n_total = block_count * fmt.grid_rule.slots_per_block();
    let ext_bytes = encode_extension(&params.extensions)?.len();
    let hdr_n = fmt.header_slots(ext_bytes);
    let ciphertext_len = payload_len + 5 + 16;
    v3_layout::compute(
        n_total,
        hdr_n,
        ciphertext_len * 8,
        params.stc_h,
        params.slot_budget,
    )
}
