//! JPEG DCT steganographic extraction pipeline.

use dct_io::JpegCoefficients;

use crate::core::control::{Control, Stage};
use crate::core::crypto::{CipherSuiteId, Credential};
use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::stego::coding::{MAX_STC_H, StcTrellis};
use crate::stego::envelope::{build_v4_aad_with, unpack_v4_envelope_parts};
use crate::stego::format::{
    JpegFormatProfile, derive_l2_locator_keys, derive_l3_session_keys, derive_locator_master,
};
use crate::stego::header::{
    CONTENT_ENVELOPE_VERSION, TLV_CRITICAL, parse_extension, validate_ext_critical_flag,
};
use crate::stego::jpeg::header_v4::{CODEC_TERNARY_STC, JpegSuperblockV4, SUPERBLOCK_BYTES};
use crate::stego::jpeg::v3_layout;
use crate::stego::params::ExtractParams;
use crate::stego::prng::{ChaCha12Stream, fisher_yates_prefix_from, permute_prefix};

use super::capacity::{
    PIPELINE_BYTES_PER_BLOCK, PIPELINE_FIXED_BYTES, check_pipeline_budget, preflight_jpeg,
};
use super::layout::{CoverFrame, jpeg_pre_salt};
use super::{JPEG_FORMAT_ID, map_dct_error};

/// Extract a payload from a V4 JPEG carrier.
///
/// The signature deliberately carries no cost model: everything the decoder
/// needs (slot set, `u`, `h`, salt, nonce) comes from the key and the header.
pub fn extract_jpeg(
    carrier_bytes: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &JpegFormatProfile,
    extract: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    fmt.validate()?;
    control.stage(Stage::Decode);
    preflight_jpeg(carrier_bytes)?;
    let coeffs = dct_io::read_coefficients(carrier_bytes).map_err(map_dct_error)?;
    control.check()?;
    extract_jpeg_from(&coeffs, cred, domain, fmt, extract, control, None)
}

/// Body of [`extract_jpeg`] over already-decoded DCT coefficients.
///
/// `matched` carries the `(suite id, master key)` an earlier
/// [`inspect_jpeg_from`] already derived, so `verify_jpeg` pays a single DCT
/// decode and a single KDF instead of three and two.
#[allow(clippy::too_many_arguments)]
pub(super) fn extract_jpeg_from(
    coeffs: &JpegCoefficients,
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &JpegFormatProfile,
    extract: &ExtractParams,
    control: &Control<'_>,
    matched: Option<[u8; 32]>,
) -> Result<Payload<'static>, StrHideError> {
    let no_hidden = || StrHideError::NoHiddenData("No valid payload found".into());
    if coeffs.components.is_empty() {
        return Err(no_hidden());
    }
    // A password below the V4 floor is rejected before any PBKDF2 work.
    if matches!(cred, Credential::Password(_))
        && extract.max_pbkdf2_iterations < crate::crypto::CONTENT_L1_PBKDF2_ITERATIONS
    {
        return Err(no_hidden());
    }
    control.check()?;
    let cover = CoverFrame::read(fmt, coeffs);
    let n_total = cover.n_total();

    let pre_salt = jpeg_pre_salt(fmt, &cover);
    let master = match matched {
        Some(master) => master,
        None => {
            derive_locator_master(cred, domain, fmt.cipher, &pre_salt).map_err(|_| no_hidden())?
        }
    };
    let locator = derive_l2_locator_keys(&master, fmt.cipher, b"strhide-v4-hdr-magic", domain)
        .map_err(|_| no_hidden())?;

    // The grid depends on the cover alone; the header prefix shuffle is driven
    // by the locator seed.
    let mut slots_buf = v3_layout::grid_indices(cover.block_count, fmt.grid_rule);
    let sb_n = fmt.superblock_slots();
    if slots_buf.len() < sb_n {
        return Err(no_hidden());
    }
    let hdr_min = fmt.header_slots(0);
    let mut hdr_rng = ChaCha12Stream::from_seed(&locator.locate_seed);
    fisher_yates_prefix_from(&mut slots_buf, 0, hdr_min, &mut hdr_rng);

    let superblock =
        read_superblock(coeffs, &slots_buf[..sb_n], fmt, &locator).ok_or_else(no_hidden)?;
    if superblock.version & 0xF0 != CONTENT_ENVELOPE_VERSION & 0xF0
        || superblock.codec_id != CODEC_TERNARY_STC
    {
        return Err(no_hidden());
    }
    let ext_bytes = superblock.ext_len as usize;
    let hdr_n = fmt.header_slots(ext_bytes);
    if hdr_n > n_total {
        return Err(no_hidden());
    }
    if hdr_n > hdr_min {
        fisher_yates_prefix_from(&mut slots_buf, hdr_min, hdr_n, &mut hdr_rng);
    }
    let hdr_slots = slots_buf[..hdr_n].to_vec();

    let extension_area = if ext_bytes > 0 {
        read_bits(
            coeffs,
            &hdr_slots[sb_n..hdr_n],
            fmt.grid_rule,
            locator.ext_stc_seed,
            fmt.ext_h,
            fmt.ext_u,
            8 * ext_bytes,
        )
        .ok_or_else(no_hidden)?
    } else {
        Vec::new()
    };
    // Extension TLVs are authenticated by the AEAD as well, so a malformed or
    // unknown-critical area must never surface as anything but "no payload".
    let extension_ok = extension_area.is_empty() || parse_extension(&extension_area).is_ok();
    let has_critical_ext = !extension_area.is_empty()
        && parse_extension(&extension_area)
            .map(|records| records.iter().any(|(t, _)| t & TLV_CRITICAL != 0))
            .unwrap_or(true);

    // Authenticated header fields gate the body slot computation.
    let suite = CipherSuiteId::from_u16(superblock.suite_id).ok_or_else(no_hidden)?;
    if !extract.allows_suite(superblock.suite_id) {
        return Err(no_hidden());
    }
    extract
        .validate_header(superblock.suite_id, superblock.body_len, hdr_n, n_total)
        .map_err(|_| no_hidden())?;

    let bits = superblock.body_len as usize * 8;
    v3_layout::fill_body_grid(&mut slots_buf, &hdr_slots, cover.block_count, fmt.grid_rule);
    let body_grid_len = slots_buf.len();
    let Some(window) = bits.checked_add(superblock.stc_h as usize - 1) else {
        return Err(no_hidden());
    };
    let Some(body_n) = window.checked_mul(superblock.stc_u as usize) else {
        return Err(no_hidden());
    };
    if body_n > body_grid_len || superblock.stc_h > MAX_STC_H {
        return Err(no_hidden());
    }
    // Enforce the same pipeline budget checks during extraction to prevent unbounded memory allocation.
    let total_blocks: usize = coeffs.components.iter().map(|c| c.blocks.len()).sum();
    let base_bytes =
        PIPELINE_FIXED_BYTES.saturating_add(total_blocks as u64 * PIPELINE_BYTES_PER_BLOCK);
    check_pipeline_budget(base_bytes, body_n, superblock.stc_h)?;
    let session = derive_l3_session_keys(fmt.cipher, suite, &master, &superblock.salt, domain)
        .map_err(|_| no_hidden())?;
    permute_prefix(&mut slots_buf, body_n, &session.perm_seed);
    slots_buf.truncate(body_n);
    let ciphertext = read_bits(
        coeffs,
        &slots_buf,
        fmt.grid_rule,
        session.stc_seed,
        superblock.stc_h,
        superblock.stc_u,
        bits,
    )
    .ok_or_else(no_hidden)?;
    if ciphertext.len() != superblock.body_len as usize {
        return Err(no_hidden());
    }

    let aad = build_v4_aad_with(
        fmt.cipher.aad_prefix,
        JPEG_FORMAT_ID,
        &superblock.encode(),
        &extension_area,
    );
    let payload = unpack_v4_envelope_parts(
        suite,
        &session.enc_key,
        &superblock.nonce,
        &aad,
        &ciphertext,
        extract,
    )?;

    // Ensure extension TLVs are known and critical flags match extension contents.
    if !extension_ok
        || has_critical_ext
        || validate_ext_critical_flag(superblock.flags, &extension_area).is_err()
    {
        return Err(no_hidden());
    }
    Ok(payload)
}

/// Read and structurally validate the superblock.
pub(crate) fn read_superblock(
    coeffs: &JpegCoefficients,
    slots: &[u32],
    fmt: &JpegFormatProfile,
    locator: &crate::stego::format::HeaderLocatorKeys,
) -> Option<JpegSuperblockV4> {
    let bits = read_bits(
        coeffs,
        slots,
        fmt.grid_rule,
        locator.header_stc_seed,
        fmt.sb_h,
        fmt.sb_u,
        fmt.superblock_bits(),
    )?;
    if bits.len() < SUPERBLOCK_BYTES {
        return None;
    }
    let mut raw = [0u8; SUPERBLOCK_BYTES];
    raw.copy_from_slice(&bits[..SUPERBLOCK_BYTES]);
    JpegSuperblockV4::decode(&raw).ok()
}

/// Run one STC pass in extraction mode: read the slot parities and return the
/// message bits.
pub(crate) fn read_bits(
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
