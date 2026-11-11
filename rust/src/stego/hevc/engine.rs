//! HEVC / H.265 In-place CABAC Bypass Steganography Engine (Scheme C).
//!
//! Provides zero bitrate expansion (Δ = 0), content-adaptive distortion-minimized
//! steganographic embedding and extraction directly within H.265/HEVC bitstreams.

use crate::core::control::Control;
use crate::core::crypto::{CONTENT_L1_PBKDF2_ITERATIONS, CipherSuiteId, Credential};
use crate::core::media::MediaInfo;
use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::stego::coding::StcTrellis;
use crate::stego::envelope::{build_v4_aad_with, unpack_v4_envelope_parts};
use crate::stego::format::{
    HevcFormatProfile, derive_l2_locator_keys, derive_l3_session_keys, derive_locator_master,
};
use crate::stego::header::{FLAG_EXT_CRITICAL, parse_extension, validate_ext_critical_flag};
use crate::stego::hevc::slot::{CabacRecorder, RecordMode};
use crate::stego::hevc::sniff::{HevcCarrierKind, NAL_SPS_NUT, sniff_hevc_carrier};
use crate::stego::options::{StegoHeaderInfo, StegoVerifyResult, VerifyLevel};
use crate::stego::params::ExtractParams;
use rusty_h265::Decoder;
use rusty_h265::ctu::Ablate;

#[cfg(test)]
pub(crate) use super::superblock::HEVC_HEADER_SLOTS_MAX;
#[cfg(test)]
pub(crate) use super::superblock::HEVC_MAX_EXT_BYTES;
#[cfg(test)]
use super::superblock::HEVC_V4_CRC_SPAN;
use super::superblock::hevc_header_slots;
pub(crate) use super::superblock::{
    HEVC_EXT_STC_H, HEVC_EXT_STC_U, HEVC_SUPERBLOCK_BYTES, HEVC_SUPERBLOCK_MIN_SLOTS,
    hevc_extension_slots, superblock_positions,
};
pub use super::superblock::{HEVC_SUPERBLOCK_POOL_SLOTS, HevcSuperblockV4};
#[cfg(test)]
use crate::stego::SafetyPolicy;
#[cfg(test)]
use crate::stego::envelope::BODY_OVERHEAD;
#[cfg(test)]
use crate::stego::envelope::{Freshness, build_plaintext, encrypt_v4_with_aad};
#[cfg(test)]
use crate::stego::header::{CONTENT_ENVELOPE_VERSION, FLAG_EXT_PRESENT};
#[cfg(test)]
use crate::stego::hevc::sniff::{NAL_RASL_N, NAL_RASL_R, NAL_TRAIL_N, NAL_TSA_N};
#[cfg(test)]
use capacity::enforce_safety;
#[cfg(test)]
use embed::validate_hevc_patches;
#[cfg(test)]
use scan::{BAND_NON_REFERENCE, BAND_REFERENCE, BitPacker, bit_at};
#[cfg(test)]
use scan::{active_parameter_sets, is_non_reference_vcl};
#[cfg(test)]
use std::collections::HashSet;
#[cfg(test)]
use support::hevc_max_raw_payload;
#[cfg(test)]
use support::hevc_window_target_slots;

mod capacity;
mod embed;
mod layout;
mod record;
mod reencode;
mod scan;
mod support;

use capacity::sps_dimensions;
pub use capacity::{
    extract_hevc_dimensions, probe_hevc_capacity, probe_hevc_capacity_ext, probe_hevc_capacity_info,
};
pub use embed::{
    HevcCarrierPatch, apply_hevc_patches, embed_hevc, embed_hevc_patches_with_factor,
    embed_hevc_with_info, embed_hevc_with_info_v4,
};
pub(crate) use embed::{embed_hevc_patches, embed_hevc_patches_v4};

pub use layout::EmbedPeakEstimate;
pub(crate) use layout::{EMBED_WINDOW_GOPS, embed_window_bytes, estimate_embed_peak_bytes};
use record::record_carrier_state;
pub use record::{ScanStats, bench_scan_slices};
use scan::{
    Capture, CarrierRecord, DigestInputs, SlotSink, absorb_recorder, derive_carrier_digest,
    drain_frames, is_irap, owned_parameter_sets, picture_band,
};
use support::{
    HEVC_FORMAT_ID, StopCondition, band_positions, check_l1_floor, get_body_slot_indices,
    hevc_session_salt, legacy_credential, nal_header_fields, nal_rbsp, tags_have_critical,
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
struct HevcHeaderRead {
    sb: HevcSuperblockV4,
    sb_bytes: [u8; HEVC_SUPERBLOCK_BYTES],
    header_positions: Vec<usize>,
    extension: Vec<u8>,
    extension_tags: Vec<u8>,
    session: crate::stego::format::SessionKeys,
}

/// Locate, decode and validate the V4 header (base + extension).
///
/// Order matters and is the same for `extract`, `inspect` and `verify`:
/// CRC/version/magic → structural bounds → extension TLV → `validate_header`
/// (suite/body_len/header slots) → L3 session keys. Every failure is folded to
/// `NoHiddenData` so a wrong password and a tampered header are indistinguishable.
fn read_hevc_header_v4(
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
fn extract_hevc_with_header(
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

/// Inspect HEVC carrier for steganographic header using an already recorded carrier state.
#[allow(clippy::too_many_arguments)]
fn inspect_hevc_record(
    carrier: &[u8],
    kind: HevcCarrierKind,
    record: &CarrierRecord,
    media_info: Option<MediaInfo>,
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    control.check()?;
    let media_info = media_info.or_else(|| {
        let (width, height) = extract_hevc_dimensions(carrier).unwrap_or((0, 0));
        if width > 0 && height > 0 {
            Some(MediaInfo::new(width, height))
        } else {
            None
        }
    });
    let mut empty_info = StegoHeaderInfo::empty(kind.label());
    empty_info.media_info = media_info;

    if check_l1_floor(&cred, limits).is_err() {
        log::debug!(
            target: "stego::inspect",
            "hevc inspect skipped: level-1 key derivation exceeds the configured PBKDF2 budget"
        );
        return Ok(empty_info);
    }
    let header = match read_hevc_header_v4(carrier, record, cred, domain, fmt, limits) {
        Ok(Some(header)) => header,
        // "No header here" is the normal answer for a clean carrier and must
        // stay silent; only a failure to *read* one is worth a record.
        Ok(None) => return Ok(empty_info),
        Err(e) => {
            log::debug!(
                target: "stego::inspect",
                "hevc header read failed for {}: {e}",
                kind.label()
            );
            return Ok(empty_info);
        }
    };

    Ok(hevc_header_info(kind, &header, media_info).unwrap_or(empty_info))
}

/// Header report shared by `inspect` and `verify`.
fn hevc_header_info(
    kind: HevcCarrierKind,
    header: &HevcHeaderRead,
    media_info: Option<MediaInfo>,
) -> Option<StegoHeaderInfo> {
    let _suite = CipherSuiteId::from_u16(header.sb.suite_id)?;
    // Plaintext length is unknowable prior to decryption due to variable compression,
    // optional filename micro-headers, and AEAD overhead. Report `None` until decrypted.
    Some(StegoHeaderInfo {
        format: kind.label().to_string(),
        has_hidden_data: true,
        algorithm: Some("HEVC-CABAC-InPlace".into()),
        codec: Some(format!("STC (h=7, u={})", header.sb.stc_u)),
        envelope_len: Some(
            HEVC_SUPERBLOCK_BYTES + header.extension.len() + header.sb.body_len as usize,
        ),
        payload_len: None,
        media_info,
        note: None,
    })
}

/// Inspect HEVC carrier for steganographic header.
#[allow(dead_code)]
pub(crate) fn inspect_hevc(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    inspect_hevc_v4(
        carrier,
        legacy_credential(secret)?,
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// Credential-aware inspection with explicit policy limits.
pub(crate) fn inspect_hevc_v4(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    control.check()?;
    let kind = match sniff_hevc_carrier(carrier) {
        Some(k) => k,
        None => return Ok(StegoHeaderInfo::empty("HEVC")),
    };

    let (width, height) = extract_hevc_dimensions(carrier).unwrap_or((0, 0));
    let media_info = if width > 0 && height > 0 {
        Some(MediaInfo::new(width, height))
    } else {
        None
    };
    let mut empty_info = StegoHeaderInfo::empty(kind.label());
    empty_info.media_info = media_info;

    let record = match record_carrier_state(
        carrier,
        kind,
        Capture::Bits,
        StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
        control,
    ) {
        Ok(r) => r,
        Err(e) => {
            // Reaching a carrier that sniffs as HEVC and then fails to record
            // its structure is a parse failure, not "nothing hidden".
            log::debug!(
                target: "stego::inspect",
                "hevc carrier record failed for {}: {e}",
                kind.label()
            );
            return Ok(empty_info);
        }
    };
    inspect_hevc_record(
        carrier, kind, &record, media_info, cred, domain, fmt, limits, control,
    )
}

/// Prefix of a sample the streaming has-inter probe reads. Every VCL NAL that
/// identifies a picture sits at or near the sample start (AUD/SEI prefixes are
/// a few hundred bytes), so 1 MiB is enough without materialising a 64 MiB
/// sample just to classify it.
const HAS_INTER_PREFIX_BYTES: usize = 1024 * 1024;

/// Does the sample prefix contain a non-IRAP VCL NAL?
///
/// Walks the length-prefixed NALs exactly like `collect_sample_slice_spans`
/// (VCL only, forbidden bit clear, non-zero temporal id) but stops at the first
/// incomplete NAL instead of rejecting the prefix as truncated.
fn sample_prefix_has_inter(prefix: &[u8], length_size: usize) -> bool {
    if !(1..=4).contains(&length_size) {
        return false;
    }
    let mut pos = 0usize;
    while pos + length_size <= prefix.len() {
        let nal_len = match length_size {
            1 => prefix[pos] as usize,
            2 => u16::from_be_bytes([prefix[pos], prefix[pos + 1]]) as usize,
            3 => {
                ((prefix[pos] as usize) << 16)
                    | ((prefix[pos + 1] as usize) << 8)
                    | prefix[pos + 2] as usize
            }
            _ => u32::from_be_bytes([
                prefix[pos],
                prefix[pos + 1],
                prefix[pos + 2],
                prefix[pos + 3],
            ]) as usize,
        };
        let nal_start = pos + length_size;
        if nal_start + 2 > prefix.len() {
            return false;
        }
        let b0 = prefix[nal_start];
        let b1 = prefix[nal_start + 1];
        let nal_type = (b0 >> 1) & 0x3F;
        if nal_type <= 31 && (b0 & 0x80) == 0 && (b1 & 0x07) > 0 && !is_irap(nal_type) {
            return true;
        }
        let Some(nal_end) = nal_start.checked_add(nal_len) else {
            return false;
        };
        if nal_end > prefix.len() {
            return false;
        }
        pos = nal_end;
    }
    false
}

/// Stream-inspect an MP4 carrier directly from disk using Seek + Read, so peak
/// memory stays bounded by the `moov` (<= 32 MiB) plus one sample
/// (<= `MAX_HEVC_SAMPLE_BYTES`) even for multi-gigabyte video files.
#[allow(dead_code)]
pub(crate) fn inspect_hevc_mp4_file(
    carrier_path: &std::path::Path,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    inspect_hevc_mp4_file_v4(
        carrier_path,
        legacy_credential(secret)?,
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// Credential-aware streaming MP4 inspection with explicit policy limits.
pub(crate) fn inspect_hevc_mp4_file_v4(
    carrier_path: &std::path::Path,
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    use std::io::{Read, Seek, SeekFrom};
    control.check()?;

    let mut file = std::fs::File::open(carrier_path)?;
    let file_len = file.metadata()?.len() as usize;

    let mut pos: u64 = 0;
    let mut moov_box: Option<(u64, usize)> = None;
    while pos + 8 <= file_len as u64 {
        file.seek(SeekFrom::Start(pos))?;
        let mut header = [0u8; 8];
        if file.read_exact(&mut header).is_err() {
            break;
        }
        let size32 = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let tag = [header[4], header[5], header[6], header[7]];
        let (header_len, total_size) = if size32 == 1 {
            let mut s64 = [0u8; 8];
            if file.read_exact(&mut s64).is_err() {
                break;
            }
            (16u64, u64::from_be_bytes(s64))
        } else if size32 == 0 {
            (8u64, (file_len as u64) - pos)
        } else {
            (8u64, size32 as u64)
        };
        if total_size < header_len
            || pos
                .checked_add(total_size)
                .is_none_or(|e| e > file_len as u64)
        {
            break;
        }
        if &tag == b"moov" {
            moov_box = Some((pos, total_size as usize));
            break;
        }
        pos += total_size;
    }

    let (moov_pos, moov_size) = match moov_box {
        Some(b) => b,
        None => return Ok(StegoHeaderInfo::empty("MP4/HEVC")),
    };

    if moov_size > 32 * 1024 * 1024 {
        return Err(StrHideError::UnsupportedFormat(
            "MP4 moov box exceeds 32 MiB".into(),
        ));
    }

    file.seek(SeekFrom::Start(moov_pos))?;
    let mut moov_bytes = vec![0u8; moov_size];
    file.read_exact(&mut moov_bytes)?;

    let target = match crate::stego::hevc::mp4_boxes::parse_moov_target(&moov_bytes, file_len) {
        Ok(t) => t,
        Err(e) => {
            // The moov box was located and read; failing to parse its targets
            // is a malformed container, not an empty carrier.
            log::debug!(
                target: "stego::inspect",
                "mp4 moov target parse failed: {e}"
            );
            return Ok(StegoHeaderInfo::empty("MP4/HEVC"));
        }
    };

    let mut media_info = None;
    for ps in &target.parameter_sets {
        if ps.len() > 2
            && (ps[0] >> 1) & 0x3F == NAL_SPS_NUT
            && let Some(dims) = sps_dimensions(&nal_rbsp(ps))
        {
            let base = MediaInfo::new(dims.0, dims.1);
            media_info = Some(match (target.fps, target.duration_secs) {
                (Some(fps), Some(sec)) if sec > 0.0 => {
                    let bps = (file_len as f64 * 8.0) / sec;
                    base.with_video(
                        fps as f32,
                        (sec * 1000.0).round() as u64,
                        bps.round() as u64,
                    )
                }
                _ => base,
            });
            break;
        }
    }

    let mut empty_info = StegoHeaderInfo::empty("MP4/HEVC");
    empty_info.media_info = media_info;

    // Detect if this MP4 stream contains inter-coded frames (P/B). When has_inter is true,
    // IDR/IRAP frames are excluded from the superblock pool to protect prediction stability.
    let mut has_inter = false;
    for &(sample_offset, sample_size) in &target.samples {
        if sample_size < target.length_size + 2 || sample_offset + sample_size > file_len {
            continue;
        }
        // Same ceiling as `parse_mp4_targets`: samples the byte-level path
        // skips must not influence `has_inter` here either.
        if sample_size <= crate::stego::hevc::mp4_boxes::MAX_HEVC_SAMPLE_BYTES {
            let prefix_len = sample_size.min(HAS_INTER_PREFIX_BYTES);
            let mut hdr_buf = vec![0u8; prefix_len];
            if file.seek(SeekFrom::Start(sample_offset as u64)).is_ok()
                && file.read_exact(&mut hdr_buf).is_ok()
                && sample_prefix_has_inter(&hdr_buf, target.length_size)
            {
                has_inter = true;
                break;
            }
        }
    }

    let mut decoder = Decoder::new();
    decoder.skip_loop_filters = true;
    decoder.ablate = Ablate {
        mc: true,
        intra: true,
        residual: true,
    };
    for ps in &target.parameter_sets {
        let _ = decoder.push_nal(ps, None);
    }
    let parameter_sets = owned_parameter_sets(&target.parameter_sets);

    let mut sink = SlotSink::new(Capture::Bits);
    let mut recorded_slices = 0usize;
    let mut slice_idx = 0usize;

    for &(sample_offset, sample_size) in &target.samples {
        control.check()?;
        if sample_size < 4 || sample_offset + sample_size > file_len {
            continue;
        }
        if sample_size > crate::stego::hevc::mp4_boxes::MAX_HEVC_SAMPLE_BYTES {
            // Same ceiling the byte-level recorder applies, so the slot pool is
            // rebuilt from the same set of samples.
            continue;
        }
        file.seek(SeekFrom::Start(sample_offset as u64))?;
        let mut sample_buf = vec![0u8; sample_size];
        if file.read_exact(&mut sample_buf).is_err() {
            continue;
        }

        let mut spans = Vec::new();
        if crate::stego::hevc::mp4_boxes::collect_sample_slice_spans(
            &sample_buf,
            0,
            sample_size,
            target.length_size,
            &mut spans,
        )
        .is_err()
        {
            continue;
        }

        for span in spans {
            let slice_bytes = &sample_buf[span.start..span.end()];
            if slice_bytes.len() < 2 {
                continue;
            }
            let (nal_type, _, _) = nal_header_fields(slice_bytes);
            let Some(band) = picture_band(nal_type, has_inter) else {
                let _ = decoder.push_nal(slice_bytes, None);
                drain_frames(&mut decoder);
                continue;
            };

            let mut recorder = CabacRecorder::with_slice_mode(slice_idx, band, RecordMode::Slots);
            let decoded = decoder.decode_nal_with_observer(slice_bytes, &mut recorder);
            drain_frames(&mut decoder);
            if decoded.is_ok() && !recorder.substreams.is_empty() {
                let rbsp = nal_rbsp(slice_bytes);
                if absorb_recorder(&mut recorder, &rbsp, &mut sink) {
                    recorded_slices += 1;
                    slice_idx += 1;
                    let current_slots = sink.counts[0] + sink.counts[1];
                    if current_slots >= HEVC_SUPERBLOCK_POOL_SLOTS {
                        break;
                    }
                }
            }
        }

        let current_slots = sink.counts[0] + sink.counts[1];
        if current_slots >= HEVC_SUPERBLOCK_POOL_SLOTS {
            break;
        }
    }

    let total_slots = sink.counts[0] + sink.counts[1];
    if total_slots < HEVC_SUPERBLOCK_MIN_SLOTS {
        return Ok(empty_info);
    }

    let SlotSink {
        counts,
        band_bits,
        raw_bits,
        raw_slots,
        slice_slot_ranges,
        ..
    } = sink;
    let band0_len = counts[0];
    let [band0_bits, band1_bits] = band_bits;
    let bands = vec![0..band0_len, band0_len..total_slots];

    let record = CarrierRecord {
        slice_contexts: Vec::new(),
        all_slots: raw_slots,
        band_bits: [band0_bits.bytes, band1_bits.bytes],
        bands,
        pictures: target.picture_count,
        band_pictures: [target.picture_count, 0],
        digest_inputs: DigestInputs::ParameterSets { parameter_sets },
        recorded_slices,
        raw_bits: raw_bits.bytes,
        slice_slot_ranges,
        capacity_band_counts: None,
    };

    inspect_hevc_record(
        &[],
        HevcCarrierKind::Mp4Container,
        &record,
        media_info,
        cred,
        domain,
        fmt,
        limits,
        control,
    )
}

/// Three-level diagnostic verification for HEVC carriers.
#[allow(dead_code)]
pub(crate) fn verify_hevc(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    verify_hevc_v4(
        carrier,
        legacy_credential(secret)?,
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// Credential-aware three-level verification with explicit policy limits.
pub(crate) fn verify_hevc_v4(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    control.check()?;
    let mut levels = Vec::new();
    let format_name = sniff_hevc_carrier(carrier).map_or("HEVC", |k| k.label());

    let kind = match sniff_hevc_carrier(carrier) {
        Some(k) => k,
        None => {
            levels.push(VerifyLevel::fail(
                1,
                "HEVC container format",
                "Unrecognized HEVC carrier",
            ));
            levels.push(VerifyLevel::fail(
                2,
                "Stego header",
                "Skipped due to level 1 failure",
            ));
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                "Skipped due to level 1 failure",
            ));
            return Ok(StegoVerifyResult::new(format_name, levels));
        }
    };

    let record = match record_carrier_state(
        carrier,
        kind,
        Capture::Bits,
        StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
        control,
    ) {
        Ok(rec) => {
            levels.push(VerifyLevel::pass(
                1,
                format!(
                    "HEVC bitstream and CABAC slots valid ({} slots)",
                    rec.total_slots()
                ),
            ));
            rec
        }
        Err(e) => {
            levels.push(VerifyLevel::fail(1, "HEVC bitstream parse", e.to_string()));
            levels.push(VerifyLevel::fail(
                2,
                "Stego header",
                "Skipped due to level 1 failure",
            ));
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                "Skipped due to level 1 failure",
            ));
            return Ok(StegoVerifyResult::new(format_name, levels));
        }
    };
    control.check()?;

    // The V4 L1 cost is fixed; a policy below it must fail with a policy
    // verdict, not "wrong password" (plan §4.2), and it must not pay PBKDF2.
    if matches!(cred, Credential::Password(_))
        && limits.max_pbkdf2_iterations < CONTENT_L1_PBKDF2_ITERATIONS
    {
        levels.push(VerifyLevel::fail(
            2,
            "Stego header",
            format!(
                "PBKDF2 iteration limit {} is below the V4 L1 cost {}",
                limits.max_pbkdf2_iterations, CONTENT_L1_PBKDF2_ITERATIONS
            ),
        ));
        levels.push(VerifyLevel::fail(
            3,
            "Payload decryption",
            "Skipped due to level 2 policy failure",
        ));
        return Ok(StegoVerifyResult::new(format_name, levels));
    }

    // One header read serves both level 2 and level 3: re-deriving it in the
    // extract step paid the 200k-iteration L1 twice for one request (M-14).
    let media_info = {
        let (width, height) = extract_hevc_dimensions(carrier).unwrap_or((0, 0));
        if width > 0 && height > 0 {
            Some(MediaInfo::new(width, height))
        } else {
            None
        }
    };
    let header = match read_hevc_header_v4(carrier, &record, cred, domain, fmt, limits) {
        Ok(Some(header)) => header,
        // Split from the `Err` arm on purpose: reporting "wrong password" for
        // a carrier the reader could not parse sends the user chasing a
        // credential that was never the problem.
        Ok(None) => {
            levels.push(VerifyLevel::fail(
                2,
                "Stego header",
                "No valid HEVC stego signature found (or wrong password)",
            ));
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                "No stego header to extract payload from",
            ));
            return Ok(StegoVerifyResult::new(format_name, levels));
        }
        Err(e) => {
            log::debug!(target: "stego::verify", "hevc header read failed: {e}");
            levels.push(VerifyLevel::fail(
                2,
                "Stego header",
                format!("Stego header could not be read: {e}"),
            ));
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                "Skipped because the header could not be read",
            ));
            return Ok(StegoVerifyResult::new(format_name, levels));
        }
    };
    let Some(header_info) = hevc_header_info(kind, &header, media_info) else {
        levels.push(VerifyLevel::fail(
            2,
            "Stego header",
            "No valid HEVC stego signature found (or wrong password)",
        ));
        levels.push(VerifyLevel::fail(
            3,
            "Payload decryption",
            "No stego header to extract payload from",
        ));
        return Ok(StegoVerifyResult::new(format_name, levels));
    };
    levels.push(VerifyLevel::pass(
        2,
        format!(
            "Stego header valid (payload: {} B, total: {} B)",
            header_info.payload_len.unwrap_or(0),
            header_info.envelope_len.unwrap_or(0),
        ),
    ));
    control.check()?;

    match extract_hevc_with_header(carrier, kind, record, &header, fmt, limits, control) {
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

    Ok(StegoVerifyResult::new(format_name, levels))
}

#[cfg(test)]
#[path = "tests/capture_tests.rs"]
mod capture_tests;

#[cfg(test)]
#[path = "tests/dialect_tests.rs"]
mod dialect_tests;

/// Regression tests for the safety-policy gate: verify that `--enforce-safety`
/// blocks appropriately on the HEVC path.
#[cfg(test)]
#[path = "tests/safety_policy_tests.rs"]
mod safety_policy_tests;

#[cfg(test)]
#[path = "tests/annex_b_parameter_set_tests.rs"]
mod annex_b_parameter_set_tests;

/// Regression test: the writer's decode window must never fall below the
/// reader's fixed `HEVC_SUPERBLOCK_POOL_SLOTS` header pool.
#[cfg(test)]
#[path = "tests/window_tests.rs"]
mod window_tests;

#[cfg(test)]
#[path = "tests/v4_superblock_tests.rs"]
mod v4_superblock_tests;

#[cfg(test)]
#[path = "tests/mkv_crc_tests.rs"]
mod mkv_crc_tests;
