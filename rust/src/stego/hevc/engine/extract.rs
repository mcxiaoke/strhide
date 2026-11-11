//! Extraction: locate the V4 header, authenticate it, then read the body.
//!
//! The header read is shared with inspect and erify, because all three
//! must derive the same locator keys and report the same verdict for a wrong
//! password and a tampered header.

use crate::core::control::Control;
use crate::core::crypto::{CipherSuiteId, Credential};
use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::stego::coding::StcTrellis;
use crate::stego::envelope::{build_v4_aad_with, unpack_v4_envelope_parts};
use crate::stego::format::{
    HevcFormatProfile, derive_l2_locator_keys, derive_l3_session_keys, derive_locator_master,
};
use crate::stego::header::{FLAG_EXT_CRITICAL, parse_extension, validate_ext_critical_flag};
use crate::stego::hevc::sniff::{HevcCarrierKind, sniff_hevc_carrier};
use crate::stego::hevc::superblock::{
    HEVC_EXT_STC_H, HEVC_EXT_STC_U, HEVC_SUPERBLOCK_BYTES, HEVC_SUPERBLOCK_MIN_SLOTS,
    HEVC_SUPERBLOCK_POOL_SLOTS, HevcSuperblockV4, hevc_extension_slots, hevc_header_slots,
    superblock_positions,
};
use crate::stego::params::ExtractParams;

use super::record::record_carrier_state;
use super::scan::{Capture, CarrierRecord, DigestInputs, derive_carrier_digest};
use super::support::{
    HEVC_FORMAT_ID, StopCondition, band_positions, check_l1_floor, get_body_slot_indices,
    hevc_session_salt, legacy_credential, tags_have_critical,
};

/// Extract hidden payload from an HEVC/HEIC carrier.
pub fn extract_hevc(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    extract_hevc_v4(
        carrier,
        legacy_credential(secret)?,
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// Credential-aware extraction with explicit policy limits.
pub fn extract_hevc_v4(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    control.check()?;
    check_l1_floor(&cred, limits)?;
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;

    // 1. First stage: scan up to HEVC_SUPERBLOCK_POOL_SLOTS to read the header.
    let sb_record = record_carrier_state(
        carrier,
        kind,
        Capture::Bits,
        StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
        control,
    )?;
    extract_hevc_from_sb_record_v4(carrier, kind, sb_record, cred, domain, fmt, limits, control)
}

#[allow(clippy::too_many_arguments)]
fn extract_hevc_from_sb_record(
    carrier: &[u8],
    kind: HevcCarrierKind,
    sb_record: CarrierRecord,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    extract_hevc_from_sb_record_v4(
        carrier,
        kind,
        sb_record,
        legacy_credential(secret)?,
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// The header half of an extraction: everything read and validated before any
/// body slot is touched.
pub(super) struct HevcHeaderRead {
    pub(super) sb: HevcSuperblockV4,
    pub(super) sb_bytes: [u8; HEVC_SUPERBLOCK_BYTES],
    pub(super) header_positions: Vec<usize>,
    pub(super) extension: Vec<u8>,
    pub(super) extension_tags: Vec<u8>,
    pub(super) session: crate::stego::format::SessionKeys,
}

/// Locate, decode and validate the V4 header (base + extension).
///
/// Order matters and is the same for `extract`, `inspect` and `verify`:
/// CRC/version/magic → structural bounds → extension TLV → `validate_header`
/// (suite/body_len/header slots) → L3 session keys. Every failure is folded to
/// `NoHiddenData` so a wrong password and a tampered header are indistinguishable.
pub(super) fn read_hevc_header_v4(
    carrier: &[u8],
    record: &CarrierRecord,
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
) -> Result<Option<HevcHeaderRead>, StrHideError> {
    let total_slots = record.total_slots();
    let pool_size = total_slots.min(HEVC_SUPERBLOCK_POOL_SLOTS);
    if pool_size < HEVC_SUPERBLOCK_MIN_SLOTS {
        return Ok(None);
    }

    let cover_digest = derive_carrier_digest(carrier, &record.digest_inputs, fmt);
    let master = derive_locator_master(cred, domain, fmt.cipher, &cover_digest)
        .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;
    let locator = derive_l2_locator_keys(&master, fmt.cipher, fmt.magic_label, domain)
        .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;

    let base_positions = superblock_positions(pool_size, &locator.locate_seed, 0);
    let sb_bits: Vec<u8> = base_positions
        .iter()
        .map(|&p| record.raw_slot_bit(p))
        .collect();
    let sb_trellis =
        StcTrellis::from_seed_grouped(locator.header_stc_seed, HEVC_EXT_STC_H, HEVC_EXT_STC_U)
            .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;
    let sb_raw = sb_trellis.extract(&sb_bits, HEVC_SUPERBLOCK_BYTES * 8);
    if sb_raw.len() < HEVC_SUPERBLOCK_BYTES {
        return Ok(None);
    }
    let mut sb_bytes = [0u8; HEVC_SUPERBLOCK_BYTES];
    sb_bytes.copy_from_slice(&sb_raw[..HEVC_SUPERBLOCK_BYTES]);

    let Ok(sb) = HevcSuperblockV4::decode(&sb_bytes, locator.magic4) else {
        return Ok(None);
    };

    let header_slots = hevc_header_slots(sb.ext_len as usize);
    if header_slots > pool_size || header_slots > total_slots {
        return Ok(None);
    }
    if limits
        .validate_header(sb.suite_id, sb.body_len, header_slots, total_slots)
        .is_err()
    {
        return Ok(None);
    }

    let ext_bytes = sb.ext_len as usize;
    let header_positions = superblock_positions(pool_size, &locator.locate_seed, ext_bytes);
    let ext_slots = hevc_extension_slots(ext_bytes);
    let mut extension = Vec::new();
    let mut extension_tags = Vec::new();
    if ext_slots > 0 {
        let ext_positions = &header_positions[HEVC_SUPERBLOCK_MIN_SLOTS..];
        let ext_bits: Vec<u8> = ext_positions
            .iter()
            .map(|&p| record.raw_slot_bit(p))
            .collect();
        let ext_trellis =
            StcTrellis::from_seed_grouped(locator.ext_stc_seed, HEVC_EXT_STC_H, HEVC_EXT_STC_U)
                .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;
        // The trellis message is the extension *bytes*, not the slot count.
        extension = ext_trellis.extract(&ext_bits, ext_bytes * 8);
        if extension.len() < ext_bytes {
            return Ok(None);
        }
        let tlvs = parse_extension(&extension)
            .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;
        extension_tags = tlvs.iter().map(|(tag, _)| *tag).collect();
    }
    // The flag and the TLVs must agree before any caller trusts the header.
    validate_ext_critical_flag(sb.flags, &extension)
        .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;

    let suite = CipherSuiteId::from_u16(sb.suite_id)
        .ok_or_else(|| StrHideError::NoHiddenData("No valid payload found".into()))?;
    let session = derive_l3_session_keys(
        fmt.cipher,
        suite,
        &master,
        &hevc_session_salt(fmt.session_salt_label, &sb.nonce),
        domain,
    )
    .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;

    Ok(Some(HevcHeaderRead {
        sb,
        sb_bytes,
        header_positions,
        extension,
        extension_tags,
        session,
    }))
}

#[allow(clippy::too_many_arguments)]
fn extract_hevc_from_sb_record_v4(
    carrier: &[u8],
    _kind: HevcCarrierKind,
    sb_record: CarrierRecord,
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    control.check()?;
    check_l1_floor(&cred, limits)?;
    let no_data = || StrHideError::NoHiddenData("No valid payload found".into());

    let header =
        read_hevc_header_v4(carrier, &sb_record, cred, domain, fmt, limits)?.ok_or_else(no_data)?;
    extract_hevc_with_header(carrier, _kind, sb_record, &header, fmt, limits, control)
}

/// Body extraction over an already-read, policy-checked V4 header.
///
/// `verify` reads the header for its level-2 verdict and then needs the same
/// header for level 3; re-deriving it would pay the 200k-iteration L1 twice for
/// one request (plan M-14).
#[allow(clippy::too_many_arguments)]
pub(super) fn extract_hevc_with_header(
    carrier: &[u8],
    kind: HevcCarrierKind,
    sb_record: CarrierRecord,
    header: &HevcHeaderRead,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    let no_data = || StrHideError::NoHiddenData("No valid payload found".into());

    // 2. Second stage: read the Body, but only after the header passed policy.
    let w0 = header.sb.window_slices as usize;
    let body_record = if sb_record.recorded_slices >= w0 {
        sb_record
    } else {
        record_carrier_state(
            carrier,
            kind,
            Capture::Bits,
            StopCondition::TargetSlices(w0),
            control,
        )?
    };

    let total_window_slots = body_record.total_slots();
    let pool_size = total_window_slots.min(HEVC_SUPERBLOCK_POOL_SLOTS);
    if pool_size < header.header_positions.len() {
        return Err(no_data());
    }
    let (body_band0, body_band1) = get_body_slot_indices(
        total_window_slots,
        pool_size,
        &header.header_positions,
        &body_record.slice_slot_ranges,
    );

    let body_trellis =
        StcTrellis::from_seed_grouped(header.session.stc_seed, fmt.stc_h, header.sb.stc_u)?;
    let body_msg_len = header.sb.body_len as usize;
    let body_needed_slots = body_trellis.slots_for(body_msg_len * 8);

    let available_body_slots = body_band0.len() + body_band1.len();
    if available_body_slots < body_needed_slots {
        return Err(no_data());
    }

    let body_bands = vec![
        0..body_band0.len(),
        body_band0.len()..(body_band0.len() + body_band1.len()),
    ];
    let mut all_body_indices = body_band0;
    all_body_indices.extend(body_band1);
    let body_positions_rel =
        band_positions(&body_bands, body_needed_slots, &header.session.perm_seed);
    let body_bits: Vec<u8> = body_positions_rel
        .into_iter()
        .map(|rel| body_record.raw_slot_bit(all_body_indices[rel]))
        .collect();

    let ciphertext = body_trellis.extract(&body_bits, body_msg_len * 8);
    if ciphertext.len() < body_msg_len {
        return Err(no_data());
    }
    let ciphertext = &ciphertext[..body_msg_len];

    let aad = build_v4_aad_with(
        fmt.cipher.aad_prefix,
        HEVC_FORMAT_ID,
        &header.sb_bytes,
        &header.extension,
    );
    let suite = CipherSuiteId::from_u16(header.sb.suite_id).ok_or_else(no_data)?;
    let payload = unpack_v4_envelope_parts(
        suite,
        &header.session.enc_key,
        &header.sb.nonce,
        &aad,
        ciphertext,
        limits,
    )?;

    // Critical extension TLVs are only meaningful after AEAD proved the header
    // is authentic; an unknown critical tag means this build cannot honour the
    // carrier's contract.
    let flag_critical = header.sb.flags & FLAG_EXT_CRITICAL != 0;
    let has_critical = tags_have_critical(&header.extension_tags);
    if flag_critical != has_critical || has_critical {
        return Err(no_data());
    }

    Ok(payload)
}

#[allow(dead_code)]
fn extract_hevc_record(
    carrier: &[u8],
    record: &CarrierRecord,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;
    extract_hevc_from_sb_record(
        carrier,
        kind,
        CarrierRecord {
            slice_contexts: record.slice_contexts.clone(),
            all_slots: record.all_slots.clone(),
            band_bits: record.band_bits.clone(),
            bands: record.bands.clone(),
            pictures: record.pictures,
            band_pictures: record.band_pictures,
            digest_inputs: match &record.digest_inputs {
                DigestInputs::ParameterSets { parameter_sets } => DigestInputs::ParameterSets {
                    parameter_sets: parameter_sets.clone(),
                },
                DigestInputs::AnnexB { spans } => DigestInputs::AnnexB {
                    spans: spans.clone(),
                },
            },
            recorded_slices: record.recorded_slices,
            raw_bits: record.raw_bits.clone(),
            slice_slot_ranges: record.slice_slot_ranges.clone(),
            capacity_band_counts: record.capacity_band_counts,
        },
        secret,
        domain,
        fmt,
        control,
    )
}
