//! JPEG DCT steganographic embedding pipeline.

use dct_io::JpegCoefficients;

use crate::core::control::{Control, Stage};
use crate::core::crypto::{CipherSuiteId, Credential};
use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::stego::StegoCapacityInfo;
use crate::stego::coding::StcTrellis;
use crate::stego::envelope::{Freshness, build_plaintext, build_v4_aad_with, encrypt_v4_with_aad};
use crate::stego::format::{
    JpegFormatProfile, derive_l2_locator_keys, derive_l3_session_keys, derive_locator_master,
};
use crate::stego::header::{
    CONTENT_ENVELOPE_VERSION, FLAG_EXT_CRITICAL, FLAG_EXT_PRESENT, HEADER_LEN_MAX, MAX_EXT_BYTES,
    TLV_CRITICAL, Tlv, encode_extension_for_write, parse_extension,
};
use crate::stego::jpeg::dht::{self, AcSymbolSet};
use crate::stego::jpeg::header_v4::{CODEC_TERNARY_STC, JpegSuperblockV4};
use crate::stego::jpeg::v3_layout;
use crate::stego::params::JpegParams;
use crate::stego::prng::permute_prefix;
use crate::stego::traits::JpegCostModel;

use super::capacity::{
    build_jpeg_capacity_info, check_pipeline_budget, enforced_payload_limit, preflight_jpeg,
};
use super::layout::{CoverFrame, apply_deltas, jpeg_pre_salt, plan_slots};
use super::{JPEG_FORMAT_ID, map_dct_error, trace};

struct EmbedContext<'a> {
    fmt: &'a JpegFormatProfile,
    suite: CipherSuiteId,
    params: &'a JpegParams,
    cover: &'a CoverFrame,
    costs: &'a [f64],
    /// Per-coefficient directional bias from the cost model, `None` when the
    /// model has no preference (symmetric costs). Embed-side only.
    directions: Option<&'a [i8]>,
    table: Option<&'a AcSymbolSet>,
    /// L1 locator master and the L2 keys derived from it.
    master: [u8; 32],
    locate_seed: [u8; 32],
    header_stc_seed: u64,
    ext_stc_seed: u64,
    domain: Option<&'a str>,
    /// Encoded extension TLV area, shared by probe and embed.
    extension: Vec<u8>,
    /// Working-set estimate from [`preflight_jpeg`], before the trellis bitmap.
    base_bytes: u64,
    /// Source of the salt and nonce for each attempt.
    freshness: Freshness,
    /// Cover+payload`+format+extension` binding for seeded freshness, computed
    /// once per embed. The attempt index is folded in separately, so retries
    /// never reuse a nonce.
    fresh_binding: Vec<u8>,
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
///    `crate::stego::params::grouped_body_budget`;
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
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    fmt: &JpegFormatProfile,
    params: &JpegParams,
    safety: crate::stego::params::SafetyPolicy,
    cost_model: &dyn JpegCostModel,
    freshness: Freshness,
    control: &Control<'_>,
) -> Result<Vec<u8>, StrHideError> {
    embed_jpeg_with_stats(
        carrier_bytes,
        payload,
        cred,
        domain,
        suite_id,
        extensions,
        fmt,
        params,
        safety,
        cost_model,
        freshness,
        control,
    )
    .map(|(bytes, _, _)| bytes)
}

/// Embed a payload into a JPEG carrier and return modified bytes, embed statistics, and capacity info.
#[allow(clippy::too_many_arguments)]
pub(crate) fn embed_jpeg_with_stats<'a>(
    carrier_bytes: &[u8],
    payload: impl Into<Payload<'a>>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    fmt: &JpegFormatProfile,
    params: &JpegParams,
    safety: crate::stego::params::SafetyPolicy,
    cost_model: &dyn JpegCostModel,
    freshness: Freshness,
    control: &Control<'_>,
) -> Result<(Vec<u8>, crate::stego::EmbedStats, StegoCapacityInfo), StrHideError> {
    let payload = payload.into();
    fmt.validate()?;
    params.validate()?;
    control.stage(Stage::Decode);
    control.check()?;
    let suite = CipherSuiteId::from_u16(suite_id).ok_or_else(|| {
        StrHideError::UnsupportedVersion(format!(
            "Cipher suite {suite_id} is not implemented by this build"
        ))
    })?;
    let extension = encode_extension_for_write(extensions)?;
    if extension.len() > MAX_EXT_BYTES {
        return Err(StrHideError::General(format!(
            "Extension area is {} bytes, the maximum is {MAX_EXT_BYTES}",
            extension.len()
        )));
    }

    let preflight = preflight_jpeg(carrier_bytes)?;
    let coeffs = dct_io::read_coefficients(carrier_bytes).map_err(map_dct_error)?;
    if coeffs.components.is_empty() {
        return Err(StrHideError::UnsupportedFormat(
            "JPEG has no image components".into(),
        ));
    }
    let cover = CoverFrame::read(fmt, &coeffs);

    log::info!(
        target: "stego::jpeg",
        "embed_jpeg: image {}x{}, payload {} B",
        preflight.info.width,
        preflight.info.height,
        payload.as_bytes().len()
    );

    // Costs are an embed-side concept only: extraction never computes them.
    let geometry = crate::stego::jpeg::geometry::geometry_for_carrier(
        carrier_bytes,
        0,
        coeffs.components[0].blocks.len(),
    )
    .map_err(map_dct_error)?;
    control.stage(Stage::CostMap);
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

    // L1/L2 are carrier-derived and suite-independent; the suite only selects
    // the AEAD and the L3 session keys.
    let pre_salt = jpeg_pre_salt(fmt, &cover);
    let master = derive_locator_master(cred, domain, fmt.cipher, &pre_salt)?;
    let locator = derive_l2_locator_keys(&master, fmt.cipher, b"strhide-v4-hdr-magic", domain)?;
    let fresh_binding = Freshness::seeded_binding(
        carrier_bytes,
        payload.as_bytes(),
        JPEG_FORMAT_ID,
        &extension,
    );

    let ctx = EmbedContext {
        fmt,
        suite,
        params,
        cover: &cover,
        costs: &costs,
        directions: directions.as_deref(),
        table: table.as_ref(),
        master,
        locate_seed: locator.locate_seed,
        header_stc_seed: locator.header_stc_seed,
        ext_stc_seed: locator.ext_stc_seed,
        domain,
        extension,
        base_bytes: preflight.base_bytes,
        freshness,
        fresh_binding,
        safety,
        payload: &payload,
    };
    let capacity_info = build_jpeg_capacity_info(
        &preflight.info,
        preflight.base_bytes,
        table.is_some(),
        cost_model,
        params,
        safety.level,
        fmt,
        &ctx.extension,
    )?;
    // `work` is the only mutable coefficient view: failed attempts are undone
    // in place by `rollback(work, applied)`, and nothing reads the pristine
    // original after costs/directions were built, so the second full copy was
    // dead weight (128 B per coded block, ~150 MB on a 50 MP 4:2:0 image).
    let mut work = coeffs;
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
                trace(format_args!("attempt {attempt_idx}/{EMBED_ATTEMPTS} ok"));
                let stats = crate::stego::EmbedStats {
                    modified_slots: applied.len(),
                    total_candidate_slots: cover.n_total,
                };
                return Ok((bytes, stats, capacity_info));
            }
            Err(attempt) => {
                trace(format_args!(
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
    let safety = ctx.safety;
    let n_total = cover.n_total();

    // Header geometry: the extension area first, because it decides how many
    // slots the header takes away from the body.
    let extension_area = &ctx.extension;
    let ext_bytes = extension_area.len();
    let hdr_n = fmt.header_slots(ext_bytes);
    if n_total <= hdr_n {
        return Err(Attempt::from(StrHideError::PayloadTooLarge(format!(
            "Capacity exceeded: header needs {hdr_n} slots, the carrier grid has {n_total}"
        ))));
    }

    // Envelope: the plaintext length fixes the header field, which in turn is
    // the AAD, so encryption has to wait until the superblock is final.
    let total_coeffs = cover.block_count * 64;

    let plaintext = build_plaintext(ctx.payload)?;
    let ciphertext_len = plaintext.len() + ctx.suite.tag_len();
    // V4 `body_len` is the ciphertext length including the AEAD tag; there is
    // no legacy salt/nonce prefix in the body any more.
    if ciphertext_len > HEADER_LEN_MAX as usize {
        return Err(Attempt::from(StrHideError::General(format!(
            "Envelope of {ciphertext_len} bytes exceeds the {HEADER_LEN_MAX}-byte header length field"
        ))));
    }
    let bits = ciphertext_len * 8;

    // Single working buffer for the carrier AC grid (eliminates 336 MB of redundant Vec clones).
    let mut slots_buf = v3_layout::grid_indices(cover.block_count, fmt.grid_rule);
    permute_prefix(&mut slots_buf, hdr_n, &ctx.locate_seed);
    let hdr_slots = slots_buf[..hdr_n].to_vec();
    let superblock_slots = fmt.superblock_slots();

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
                    error: StrHideError::PayloadTooLarge(
                        "Payload too large for this carrier: its over-optimised Huffman table forces a less dense encoding (u >= 3) and the payload does not fit. Reduce the payload or re-save the carrier with a standard (Annex K) table.".into(),
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
            return Err(Attempt::from(StrHideError::SafetyThreshold {
                tier: safety.level,
                required_bytes: ctx.payload.len(),
                available_bytes: max,
            }));
        }
    }

    // Attempts are zero-based for freshness so a retry always derives a fresh
    // salt and nonce even with `Freshness::Seeded`.
    let attempt = attempt.saturating_sub(1);
    let salt = ctx.freshness.salt(attempt, &ctx.fresh_binding);
    let nonce = ctx.freshness.nonce(attempt, &ctx.fresh_binding);
    let flags = if ext_bytes == 0 {
        0
    } else if parse_extension(extension_area)
        .map(|records| records.iter().any(|(t, _)| t & TLV_CRITICAL != 0))
        .unwrap_or(false)
    {
        FLAG_EXT_PRESENT | FLAG_EXT_CRITICAL
    } else {
        FLAG_EXT_PRESENT
    };
    let superblock = JpegSuperblockV4 {
        version: CONTENT_ENVELOPE_VERSION,
        flags,
        salt,
        nonce,
        body_len: ciphertext_len as u32,
        suite_id: ctx.suite.as_u16(),
        codec_id: CODEC_TERNARY_STC,
        stc_h: params.stc_h,
        stc_u: layout.u,
        ext_len: ext_bytes as u8,
    };
    let superblock_bytes = superblock.encode();

    // The extension area is authenticated too: a bit flip there must break the
    // AEAD even when the (untrusted) CRC is recomputed.
    let aad = build_v4_aad_with(
        fmt.cipher.aad_prefix,
        JPEG_FORMAT_ID,
        &superblock_bytes,
        extension_area,
    );
    let session = derive_l3_session_keys(fmt.cipher, ctx.suite, &ctx.master, &salt, ctx.domain)?;
    let ciphertext = encrypt_v4_with_aad(ctx.suite, &session.enc_key, &nonce, &aad, &plaintext)?;
    debug_assert_eq!(ciphertext.len(), ciphertext_len);

    let mut touched = vec![false; cover.block_count];

    // 1) Superblock: 352 bits through STC(sb_h, sb_u).
    if let Err(e) = embed_slots(
        &mut *work,
        &hdr_slots[..superblock_slots],
        fmt,
        ctx.costs,
        ctx.directions,
        ctx.table,
        params,
        ctx.header_stc_seed,
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
            &hdr_slots[superblock_slots..hdr_n],
            fmt,
            ctx.costs,
            ctx.directions,
            ctx.table,
            params,
            ctx.ext_stc_seed,
            fmt.ext_h,
            fmt.ext_u,
            extension_area,
            &mut touched,
            applied,
        )?;
    }

    // 3) Body: the ciphertext, over a keyed permutation of the body grid.
    permute_prefix(&mut slots_buf, layout.body_n, &session.perm_seed);
    slots_buf.truncate(layout.body_n);
    if let Err(e) = embed_slots(
        &mut *work,
        &slots_buf,
        fmt,
        ctx.costs,
        ctx.directions,
        ctx.table,
        params,
        session.stc_seed,
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
        trace(format_args!(
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
    )?;
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
