//! Embedding: the write pipeline that turns a payload into NAL byte patches.
//!
//! The entry points build the envelope, solve the three STC regions (header,
//! extension, body), re-encode the touched slices and retry with excluded slots
//! until the flip set is emulation-prevention safe. Applying the patches to the
//! carrier is the last step, so every public entry reaches the same validated
//! output.

use std::collections::{BTreeMap, HashSet};

use rayon::prelude::*;

use crate::core::control::{Control, Stage};
use crate::core::crypto::{CipherSuiteId, Credential};
use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::stego::coding::{Move, StcTrellis};
use crate::stego::envelope::{Freshness, build_plaintext, build_v4_aad_with, encrypt_v4_with_aad};
use crate::stego::format::{
    HevcFormatProfile, derive_l2_locator_keys, derive_l3_session_keys, derive_locator_master,
};
use crate::stego::header::{
    CONTENT_ENVELOPE_VERSION, FLAG_EXT_CRITICAL, FLAG_EXT_PRESENT, Tlv, encode_extension_for_write,
};
use crate::stego::hevc::mkv_boxes::refresh_mkv_crcs;
use crate::stego::hevc::sniff::{HevcCarrierKind, sniff_hevc_carrier};
use crate::stego::{SafetyLevel, SafetyPolicy, StegoCapacityInfo};

use super::capacity::{build_hevc_capacity_info, enforce_safety, probe_hevc_pool};
use super::record::{record_carrier_state, record_carrier_state_with_capacity};
use super::reencode::{SliceReencodeOutcome, reencode_slice};
use super::scan::{Capture, PoolProfile, derive_carrier_digest};
use super::support::{
    EpbConflict, FORBIDDEN_SLOT_SURCHARGE, HEVC_FORMAT_ID, MAX_EMBED_ROUNDS, StopCondition,
    band_positions, extension_len, get_body_slot_indices, has_critical_tlv, hevc_session_salt,
    hevc_window_target_slots, legacy_credential,
};
use crate::stego::hevc::superblock::{
    HEVC_EXT_STC_H, HEVC_EXT_STC_U, HEVC_SUPERBLOCK_MIN_SLOTS, HEVC_SUPERBLOCK_POOL_SLOTS,
    HevcSuperblockV4, hevc_header_slots, superblock_positions,
};

/// Embed a payload into an HEVC/HEIC carrier using content-adaptive sign-bit steganography.
///
/// The complete expert entry. `secret` is the resolved credential (explicit
/// password, else the profile's private stego secret, else `None` for the
/// official public constant); `domain` isolates the HKDF derivation; `fmt` is
/// the wire-format identity; `freshness` supplies the nonce (`Seeded` makes
/// the output reproducible for the same inputs); `safety` is the full policy,
/// so `Enforced` blocks an over-tier payload instead of only warning.
/// An in-place modification patch for an HEVC carrier: `(byte_range, replacement_nal_bytes)`.
pub type HevcCarrierPatch = (std::ops::Range<usize>, Vec<u8>);

/// Check that every patch fits the carrier it will be applied to.
///
/// The patch list is produced by the HEVC scanner itself, so a mismatch here
/// means an engine invariant broke. Validating before the copy keeps that
/// internal failure a normal error instead of a slice-index panic, which
/// `panic = "abort"` would turn into process termination.
pub(super) fn validate_hevc_patches(
    carrier_len: usize,
    patches: &[HevcCarrierPatch],
) -> Result<(), StrHideError> {
    for (index, (span, re_nal)) in patches.iter().enumerate() {
        if span.start > span.end || span.end > carrier_len || re_nal.len() != span.len() {
            return Err(StrHideError::General(format!(
                "HEVC patch {index} does not fit the carrier: span {span:?}, {} replacement bytes, carrier {carrier_len} bytes",
                re_nal.len()
            )));
        }
    }
    Ok(())
}

/// Apply in-place NAL patches to a mutable carrier buffer.
///
/// Panics on a patch whose span falls outside `carrier` or whose replacement
/// length differs from the span length; callers that build patches dynamically
/// must verify them first (`validate_hevc_patches`). The production embed path
/// does exactly that, so this panic is reachable only for direct misuse.
pub fn apply_hevc_patches(carrier: &mut [u8], patches: &[HevcCarrierPatch]) {
    for (span, re_nal) in patches {
        debug_assert!(
            span.start <= span.end && span.end <= carrier.len() && re_nal.len() == span.len(),
            "HEVC patch {span:?} does not fit the {} byte carrier",
            carrier.len()
        );
        carrier[span.clone()].copy_from_slice(re_nal);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn embed_hevc_with_info(
    carrier: &[u8],
    payload: &Payload<'_>,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
) -> Result<(Vec<u8>, StegoCapacityInfo, crate::stego::EmbedStats), StrHideError> {
    embed_hevc_with_info_v4(
        carrier,
        payload,
        legacy_credential(secret)?,
        domain,
        fmt.cipher.default_suite.as_u16(),
        &[],
        fmt,
        freshness,
        safety,
        control,
    )
}

/// Credential-aware embed with the full V4 options.
#[allow(clippy::too_many_arguments)]
pub fn embed_hevc_with_info_v4(
    carrier: &[u8],
    payload: &Payload<'_>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
) -> Result<(Vec<u8>, StegoCapacityInfo, crate::stego::EmbedStats), StrHideError> {
    let (patches, capacity_info, stats) = embed_hevc_patches_v4(
        carrier, payload, cred, domain, suite_id, extensions, fmt, freshness, safety, control,
    )?;
    let mut out_carrier = carrier.to_vec();
    validate_hevc_patches(out_carrier.len(), &patches)?;
    apply_hevc_patches(&mut out_carrier, &patches);

    // A Matroska muxer covers every finalised element with a CRC-32; the
    // patches above invalidate any checksum that covers a modified block.
    // Refresh here, on the single in-memory entry every caller reaches, so a
    // direct library user gets the same valid file as `MkvEngine` did.
    if sniff_hevc_carrier(carrier) == Some(HevcCarrierKind::MkvContainer) {
        refresh_mkv_crcs(carrier, &mut out_carrier).map_err(|e| {
            StrHideError::CorruptedData(format!("MKV checksum refresh failed: {e}"))
        })?;
    }

    Ok((out_carrier, capacity_info, stats))
}

/// Embed a payload into an HEVC carrier and return in-place NAL delta patches.
///
/// This avoids cloning or mutating the entire carrier in memory, allowing zero-heap-overhead
/// streaming commit to disk via `commit_carrier_patches`.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(crate) fn embed_hevc_patches(
    carrier: &[u8],
    payload: &Payload<'_>,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
) -> Result<
    (
        Vec<HevcCarrierPatch>,
        StegoCapacityInfo,
        crate::stego::EmbedStats,
    ),
    StrHideError,
> {
    embed_hevc_patches_with_factor(
        carrier, payload, secret, domain, fmt, freshness, safety, control, 1.0,
    )
}

/// Credential-aware patch embed with the full V4 options.
#[allow(clippy::too_many_arguments)]
pub(crate) fn embed_hevc_patches_v4(
    carrier: &[u8],
    payload: &Payload<'_>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
) -> Result<
    (
        Vec<HevcCarrierPatch>,
        StegoCapacityInfo,
        crate::stego::EmbedStats,
    ),
    StrHideError,
> {
    embed_hevc_patches_with_factor_v4(
        carrier, payload, cred, domain, suite_id, extensions, fmt, freshness, safety, control, 1.0,
    )
}

#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn embed_hevc_patches_with_factor(
    carrier: &[u8],
    payload: &Payload<'_>,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
    window_factor: f64,
) -> Result<
    (
        Vec<HevcCarrierPatch>,
        StegoCapacityInfo,
        crate::stego::EmbedStats,
    ),
    StrHideError,
> {
    embed_hevc_patches_with_factor_v4(
        carrier,
        payload,
        legacy_credential(secret)?,
        domain,
        fmt.cipher.default_suite.as_u16(),
        &[],
        fmt,
        freshness,
        safety,
        control,
        window_factor,
    )
}

#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn embed_hevc_patches_with_factor_v4(
    carrier: &[u8],
    payload: &Payload<'_>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
    window_factor: f64,
) -> Result<
    (
        Vec<HevcCarrierPatch>,
        StegoCapacityInfo,
        crate::stego::EmbedStats,
    ),
    StrHideError,
> {
    if payload.is_empty() {
        return Err(StrHideError::General("Cannot embed empty payload".into()));
    }
    let suite = CipherSuiteId::from_u16(suite_id).ok_or_else(|| {
        StrHideError::UnsupportedVersion(format!("Unknown content cipher suite id {suite_id}"))
    })?;
    let ext_len = extension_len(extensions)?;
    let extension = encode_extension_for_write(extensions)?;

    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;

    // 1. Calculate required capacity and stream window
    let plaintext = build_plaintext(payload)?;
    let body_msg_len = plaintext.len() + suite.tag_len();
    let body_needed_slots = StcTrellis::slots_for_params(body_msg_len * 8, fmt.stc_h, fmt.stc_u);
    let hdr_slots = hevc_header_slots(ext_len);
    let non_ref_fraction = safety.level.video_budget().non_ref_fraction;
    let factor = if window_factor > 1.0 {
        window_factor
    } else if kind == HevcCarrierKind::HeifContainer {
        1.0
    } else {
        (1.0 / non_ref_fraction).max(1.0)
    };
    let desired_body_slots = ((body_needed_slots as f64) * factor).ceil() as usize;
    // The writer must decode at least as many slots as the reader's first pass
    // (`StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS)`). Both sides derive
    // the header permutation from `pool_size = recorded_slots.min(POOL_SLOTS)`;
    // a smaller write window would place the header over a different pool size
    // and make small payloads unreadable on large carriers.
    let target_slots = hevc_window_target_slots(hdr_slots, desired_body_slots);

    control.stage(Stage::Decode);
    // MP4 keeps the sampled probe as the capacity contract; every other
    // container reports exact slots, so the window pass can count the rest of
    // the carrier itself and skip the second full decode.
    let exact_capacity = kind != HevcCarrierKind::Mp4Container;
    let record = if exact_capacity {
        record_carrier_state_with_capacity(
            carrier,
            kind,
            Capture::Full,
            StopCondition::TargetSlots(target_slots),
            control,
        )?
    } else {
        record_carrier_state(
            carrier,
            kind,
            Capture::Full,
            StopCondition::TargetSlots(target_slots),
            control,
        )?
    };
    control.check()?;
    control.stage(Stage::Solve);
    let pool = PoolProfile::from_record(&record);
    // Capacity is a property of the whole carrier, not of the write window:
    // `TargetSlots` deliberately stops recording once the payload needs are
    // met, so building the report from `pool` under-reports by the ratio of
    // carrier capacity to the window (measured 112x on a 12 MB MKV). Reuse the
    // same pool the probe uses instead of inventing a second estimator.
    //
    // A record whose slot count stayed below `target_slots` cannot have hit the
    // early stop, so it already covers the whole carrier and needs no second
    // decode pass. The same is true when the recording pass kept counting after
    // the stop (`capacity_band_counts` is whole-carrier by construction).
    let capacity_pool;
    let capacity_source =
        if record.capacity_band_counts.is_some() || record.total_slots() < target_slots {
            &pool
        } else {
            capacity_pool = probe_hevc_pool(carrier, kind, false, control)?;
            &capacity_pool
        };
    let capacity_info =
        build_hevc_capacity_info(carrier, kind, fmt, capacity_source, ext_len, safety.level)?;

    enforce_safety(
        payload.len(),
        capacity_info.recommended_max_bytes,
        capacity_info.max_raw_payload_bytes,
        safety,
    )?;

    let slice_contexts = record.slice_contexts;
    let all_slots = record.all_slots;
    let total_slots = all_slots.len();
    let pool_size = total_slots.min(HEVC_SUPERBLOCK_POOL_SLOTS);

    if pool_size < hdr_slots || total_slots < hdr_slots + body_needed_slots {
        return Err(StrHideError::PayloadTooLarge(format!(
            "HEVC carrier capacity exceeded: needed at least {} slots, but carrier only has {}",
            hdr_slots + body_needed_slots,
            total_slots
        )));
    }

    // A container that only ever holds video is a video carrier regardless of
    // how many pictures it has; an Annex-B stream or a HEIF still is judged by
    // the picture count.
    let is_video = matches!(
        kind,
        HevcCarrierKind::Mp4Container | HevcCarrierKind::MkvContainer
    ) || record.pictures > 1;
    if is_video && total_slots < hdr_slots + desired_body_slots {
        let current_tier = safety.level.as_str();
        let hint = match safety.level {
            SafetyLevel::Paranoid => {
                "carrier capacity insufficient for paranoid tier (0.1 budget); try '--safety high' (0.2) or '--safety balanced' (0.4)"
            }
            SafetyLevel::High => {
                "carrier capacity insufficient for default high tier (0.2 budget); try '--safety balanced' (0.4)"
            }
            SafetyLevel::Balanced => {
                "carrier capacity insufficient for balanced tier (0.4 budget); payload is too large for this carrier"
            }
        };
        return Err(StrHideError::General(format!(
            "HEVC capacity insufficient for tier '{current_tier}': needed {needed} slots ({factor:.1}x sparsity), carrier only has {available} slots. Hint: {hint}",
            needed = hdr_slots + desired_body_slots,
            available = total_slots,
        )));
    }

    // 2. L1/L2 locator, session keys and keyed slot plans
    let cover_digest = derive_carrier_digest(carrier, &record.digest_inputs, fmt);
    let master = derive_locator_master(cred, domain, fmt.cipher, &cover_digest)?;
    let locator = derive_l2_locator_keys(&master, fmt.cipher, fmt.magic_label, domain)?;

    let fresh_binding =
        Freshness::seeded_binding(carrier, payload.as_bytes(), HEVC_FORMAT_ID, &extension);
    let nonce_bytes = freshness.nonce(0, &fresh_binding);
    let session = derive_l3_session_keys(
        fmt.cipher,
        suite,
        &master,
        &hevc_session_salt(fmt.session_salt_label, &nonce_bytes),
        domain,
    )?;

    let header_positions = superblock_positions(pool_size, &locator.locate_seed, ext_len);
    let (body_band0, body_band1) = get_body_slot_indices(
        total_slots,
        pool_size,
        &header_positions,
        &record.slice_slot_ranges,
    );
    let body_bands = vec![
        0..body_band0.len(),
        body_band0.len()..(body_band0.len() + body_band1.len()),
    ];
    let mut all_body_indices = body_band0;
    all_body_indices.extend(body_band1);
    let body_positions_rel = band_positions(&body_bands, body_needed_slots, &session.perm_seed);
    let body_positions: Vec<usize> = body_positions_rel
        .into_iter()
        .map(|rel| all_body_indices[rel])
        .collect();

    // 3. Prepare Superblock, extension area and AEAD ciphertext
    let window_slices = u16::try_from(slice_contexts.len()).map_err(|_| {
        StrHideError::UnsupportedFormat(format!(
            "HEVC carrier has {} slices, exceeding the superblock window slice limit (65535)",
            slice_contexts.len()
        ))
    })?;

    let flags = (if ext_len > 0 { FLAG_EXT_PRESENT } else { 0 })
        | (if has_critical_tlv(extensions) {
            FLAG_EXT_CRITICAL
        } else {
            0
        });
    let body_len = u32::try_from(body_msg_len).map_err(|_| {
        StrHideError::General("HEVC payload exceeds the 32-bit body length field".into())
    })?;
    let sb = HevcSuperblockV4 {
        magic: locator.magic4,
        version: CONTENT_ENVELOPE_VERSION,
        flags,
        stc_u: fmt.stc_u,
        window_slices,
        ext_len: ext_len as u8,
        suite_id,
        body_len,
        nonce: nonce_bytes,
    };
    let sb_bytes = sb.encode();
    let aad = build_v4_aad_with(fmt.cipher.aad_prefix, HEVC_FORMAT_ID, &sb_bytes, &extension);
    let ciphertext = encrypt_v4_with_aad(suite, &session.enc_key, &nonce_bytes, &aad, &plaintext)?;

    let sb_trellis =
        StcTrellis::from_seed_grouped(locator.header_stc_seed, HEVC_EXT_STC_H, HEVC_EXT_STC_U)?;
    let ext_trellis =
        StcTrellis::from_seed_grouped(locator.ext_stc_seed, HEVC_EXT_STC_H, HEVC_EXT_STC_U)?;
    let body_trellis = StcTrellis::from_seed_grouped(session.stc_seed, fmt.stc_h, fmt.stc_u)?;
    let base_positions = &header_positions[..HEVC_SUPERBLOCK_MIN_SLOTS];
    let ext_positions = &header_positions[HEVC_SUPERBLOCK_MIN_SLOTS..];

    let mut forbidden: HashSet<usize> = HashSet::new();
    let mut bad_substreams: HashSet<(usize, usize)> = HashSet::new();

    for round in 0..MAX_EMBED_ROUNDS {
        control.check()?;

        // 3a. Solve Superblock STC
        let mut sb_cover_bits = Vec::with_capacity(base_positions.len());
        let mut sb_costs = Vec::with_capacity(base_positions.len());
        let mut sb_moves = Vec::with_capacity(base_positions.len());
        for &pos in base_positions {
            let slot = &all_slots[pos];
            sb_cover_bits.push(slot.original_bit);
            sb_costs.push(if forbidden.contains(&pos) {
                slot.cost as f64 + FORBIDDEN_SLOT_SURCHARGE
            } else {
                slot.cost as f64
            });
            sb_moves.push(if slot.original_bit == 0 {
                Move::PlusOnly
            } else {
                Move::MinusOnly
            });
        }
        let mut sb_deltas = vec![0i8; base_positions.len()];
        if let Err(e) = sb_trellis.embed_with_deltas(
            &sb_cover_bits,
            &sb_moves,
            &sb_costs,
            &sb_costs,
            &sb_bytes,
            &mut sb_deltas,
        ) {
            if round == 0 {
                return Err(e);
            }
            return Err(StrHideError::TrellisInfeasible {
                cause: crate::errors::TrellisCause::ExhaustedSlots,
                detail: format!(
                    "HEVC Superblock STC exhausted usable slots after {round} round(s) ({} slot(s) excluded): {e}",
                    forbidden.len()
                ),
            });
        }

        // 3a-bis. Solve the extension TLV area STC (keyed by the L2 ext seed)
        let mut ext_cover_bits = Vec::with_capacity(ext_positions.len());
        let mut ext_costs = Vec::with_capacity(ext_positions.len());
        let mut ext_moves = Vec::with_capacity(ext_positions.len());
        for &pos in ext_positions {
            let slot = &all_slots[pos];
            ext_cover_bits.push(slot.original_bit);
            ext_costs.push(if forbidden.contains(&pos) {
                slot.cost as f64 + FORBIDDEN_SLOT_SURCHARGE
            } else {
                slot.cost as f64
            });
            ext_moves.push(if slot.original_bit == 0 {
                Move::PlusOnly
            } else {
                Move::MinusOnly
            });
        }
        let mut ext_deltas = vec![0i8; ext_positions.len()];
        if ext_len > 0
            && let Err(e) = ext_trellis.embed_with_deltas(
                &ext_cover_bits,
                &ext_moves,
                &ext_costs,
                &ext_costs,
                &extension,
                &mut ext_deltas,
            )
        {
            if round == 0 {
                return Err(e);
            }
            return Err(StrHideError::TrellisInfeasible {
                cause: crate::errors::TrellisCause::ExhaustedSlots,
                detail: format!(
                    "HEVC extension area STC exhausted usable slots after {round} round(s) ({} slot(s) excluded): {e}",
                    forbidden.len()
                ),
            });
        }

        // 3b. Solve Body STC using cost closure (zero-allocation for body_costs)
        let mut body_cover_bits = Vec::with_capacity(body_positions.len());
        let mut body_moves = Vec::with_capacity(body_positions.len());
        for &pos in &body_positions {
            let slot = &all_slots[pos];
            body_cover_bits.push(slot.original_bit);
            body_moves.push(if slot.original_bit == 0 {
                Move::PlusOnly
            } else {
                Move::MinusOnly
            });
        }
        let mut body_deltas = vec![0i8; body_positions.len()];
        if let Err(e) = body_trellis.embed_with_cost_fn(
            &body_cover_bits,
            &body_moves,
            |j| {
                let pos = body_positions[j];
                let cost = if forbidden.contains(&pos) {
                    all_slots[pos].cost as f64 + FORBIDDEN_SLOT_SURCHARGE
                } else {
                    all_slots[pos].cost as f64
                };
                (cost, cost)
            },
            &ciphertext,
            &mut body_deltas,
        ) {
            if round == 0 {
                return Err(e);
            }
            return Err(StrHideError::TrellisInfeasible {
                cause: crate::errors::TrellisCause::ExhaustedSlots,
                detail: format!(
                    "HEVC Body STC exhausted usable slots after {round} round(s) ({} slot(s) excluded): {e}",
                    forbidden.len()
                ),
            });
        }

        let mut flips_per_slice: BTreeMap<usize, Vec<(usize, usize)>> = BTreeMap::new();
        for (i, &delta) in sb_deltas.iter().enumerate() {
            if delta != 0 {
                let global_slot_idx = base_positions[i];
                let slot = &all_slots[global_slot_idx];
                flips_per_slice
                    .entry(slot.slice_idx as usize)
                    .or_default()
                    .push((slot.op_idx as usize, global_slot_idx));
            }
        }
        for (i, &delta) in ext_deltas.iter().enumerate() {
            if delta != 0 {
                let global_slot_idx = ext_positions[i];
                let slot = &all_slots[global_slot_idx];
                flips_per_slice
                    .entry(slot.slice_idx as usize)
                    .or_default()
                    .push((slot.op_idx as usize, global_slot_idx));
            }
        }
        for (i, &delta) in body_deltas.iter().enumerate() {
            if delta != 0 {
                let global_slot_idx = body_positions[i];
                let slot = &all_slots[global_slot_idx];
                flips_per_slice
                    .entry(slot.slice_idx as usize)
                    .or_default()
                    .push((slot.op_idx as usize, global_slot_idx));
            }
        }
        for entries in flips_per_slice.values_mut() {
            entries.sort_unstable_by_key(|(op_idx, _)| *op_idx);
        }

        // 3c. Re-encode every touched slice in parallel using rayon (including journal fidelity checks)
        let mut conflicts: Vec<EpbConflict> = Vec::new();
        let mut reencoded_slices = Vec::new();

        let slice_items: Vec<(usize, &Vec<(usize, usize)>)> = flips_per_slice
            .iter()
            .map(|(&idx, entries)| (idx, entries))
            .collect();

        control.stage_sized(Stage::Encode, slice_items.len() as u64);

        let outcomes: Result<Vec<SliceReencodeOutcome>, StrHideError> = slice_items
            .into_par_iter()
            .map(|(slice_idx, flipped_entries)| {
                control.check()?;
                let ctx = slice_contexts.get(slice_idx).ok_or_else(|| {
                    StrHideError::General(format!(
                        "HEVC slice index {slice_idx} has no recorded context"
                    ))
                })?;
                Ok(reencode_slice(slice_idx, ctx, flipped_entries))
            })
            .collect();
        let outcomes = outcomes?;

        for outcome in outcomes {
            match outcome {
                SliceReencodeOutcome::Success { span, re_nal } => {
                    reencoded_slices.push((span, re_nal));
                }
                SliceReencodeOutcome::Conflict(c) => {
                    conflicts.extend(c);
                }
                SliceReencodeOutcome::BadSubstream(slice_idx, sub_idx) => {
                    bad_substreams.insert((slice_idx, sub_idx));
                }
                SliceReencodeOutcome::LengthError(msg) => {
                    return Err(StrHideError::General(msg));
                }
            }
        }

        let mut had_bad_substream = false;
        for &pos in header_positions.iter().chain(body_positions.iter()) {
            let slot = &all_slots[pos];
            if bad_substreams.contains(&(slot.slice_idx as usize, slot.substream_idx as usize))
                && forbidden.insert(pos)
            {
                had_bad_substream = true;
            }
        }
        if had_bad_substream {
            continue;
        }

        if conflicts.is_empty() && reencoded_slices.len() == flips_per_slice.len() {
            let modified_slots = sb_deltas.iter().filter(|&&d| d != 0).count()
                + ext_deltas.iter().filter(|&&d| d != 0).count()
                + body_deltas.iter().filter(|&&d| d != 0).count();
            let stats = crate::stego::EmbedStats {
                modified_slots,
                total_candidate_slots: total_slots,
            };
            return Ok((reencoded_slices, capacity_info, stats));
        }

        // 3c. Exclude the slots whose flipped bits sit next to a disturbed
        //     window. A bypass bin owns one codeword bit but its carry can
        //     rewrite the neighbouring bytes, so widen the radius every round.
        let radius = 8usize << round.min(3);
        let mut progress = 0usize;
        for (window, trace) in &conflicts {
            let lo = window.saturating_sub(radius);
            let hi = window + radius;
            for &(global, byte_lo, byte_hi) in trace {
                if global < total_slots
                    && byte_hi >= lo
                    && byte_lo <= hi
                    && forbidden.insert(global)
                {
                    progress += 1;
                }
            }
        }

        if progress == 0 {
            // The carry travelled further than any traced flip: exclude the
            // closest flip that precedes the window so the next round cannot
            // stall on the same conflict.
            for (window, trace) in &conflicts {
                if let Some(&(global, _, _)) = trace
                    .iter()
                    .filter(|(_, _, byte_hi)| *byte_hi <= *window)
                    .max_by_key(|(_, _, byte_hi)| *byte_hi)
                    && global < total_slots
                    && forbidden.insert(global)
                {
                    progress += 1;
                }
            }
        }

        if progress == 0 {
            // `conflicts` can be empty here when a BadSubstream hit a substream
            // whose slots were all excluded in an earlier round: the slice
            // failed to re-encode, yet there is no EPB trace to point at.
            // Report that explicitly instead of indexing `conflicts[0]`.
            if conflicts.is_empty() {
                return Err(StrHideError::General(format!(
                    "HEVC stego cannot resolve a substream whose slots were already excluded \
                     (round {round}, {} slot(s) forbidden)",
                    forbidden.len()
                )));
            }
            return Err(StrHideError::General(format!(
                "HEVC stego cannot localize the emulation-prevention conflict at RBSP byte {}",
                conflicts[0].0
            )));
        }
    }

    Err(StrHideError::General(format!(
        "HEVC stego cannot settle on an EPB-safe flip set within {MAX_EMBED_ROUNDS} rounds"
    )))
}

fn embed_hevc_payload(
    carrier: &[u8],
    payload: &Payload<'_>,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
) -> Result<Vec<u8>, StrHideError> {
    embed_hevc_with_info(
        carrier,
        payload,
        secret,
        domain,
        fmt,
        freshness,
        SafetyPolicy::new(),
        &Control::none(),
    )
    .map(|(bytes, _, _)| bytes)
}

/// Embed a payload into an HEVC/HEIC carrier using content-adaptive sign-bit steganography.
///
/// Wrapper around [`embed_hevc_with_info`] discarding the structured capacity metadata.
pub fn embed_hevc(
    carrier: &[u8],
    payload: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
) -> Result<Vec<u8>, StrHideError> {
    embed_hevc_payload(
        carrier,
        &Payload::bytes(payload),
        secret,
        domain,
        fmt,
        freshness,
    )
}
