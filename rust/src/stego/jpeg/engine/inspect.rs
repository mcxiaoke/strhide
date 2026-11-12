//! JPEG DCT inspection and verification pipeline.

use dct_io::JpegCoefficients;

use crate::core::control::Control;
use crate::core::crypto::Credential;
use crate::core::media::MediaInfo;
use crate::errors::StrHideError;
use crate::stego::format::{JpegFormatProfile, derive_l2_locator_keys, derive_locator_master};
use crate::stego::header::{
    CONTENT_ENVELOPE_VERSION, TLV_CRITICAL, parse_extension, validate_ext_critical_flag,
};
use crate::stego::jpeg::header_v4::CODEC_TERNARY_STC;
use crate::stego::jpeg::v3_layout;
use crate::stego::options::{StegoHeaderInfo, StegoVerifyResult, VerifyLevel};
use crate::stego::params::ExtractParams;
use crate::stego::prng::{ChaCha12Stream, fisher_yates_prefix_from};

use super::capacity::preflight_jpeg;
use super::extract::{extract_jpeg_from, read_bits, read_superblock};
use super::layout::{CoverFrame, jpeg_pre_salt};
use super::map_dct_error;

/// Inspect a JPEG for the V4 superblock and stego metadata without solving trellis.
///
/// Carries the same `limits` as [`extract_jpeg`] on purpose: inspecting under a
/// tightened policy used to report `has_hidden_data = true` for a carrier the
/// extractor then refused, and it paid the full PBKDF2 cost first.
pub(crate) fn inspect_jpeg(
    carrier_bytes: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &JpegFormatProfile,
    limits: &ExtractParams,
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
    let media_info = Some(MediaInfo::new(
        u32::from(preflight.info.width),
        u32::from(preflight.info.height),
    ));
    let coeffs = match dct_io::read_coefficients(carrier_bytes) {
        Ok(c) => c,
        Err(e) => {
            // Preflight just succeeded, so the coefficient reader failing here
            // is a real anomaly rather than "no envelope". The sibling
            // preflight arm above already reports its reason through `note`;
            // this one used to drop it.
            log::debug!(target: "stego::inspect", "jpeg coefficient read failed: {e}");
            let mut empty_info = StegoHeaderInfo::empty("JPEG");
            empty_info.media_info = media_info;
            empty_info.note = Some(format!("Coefficient read failed: {e}"));
            return Ok(empty_info);
        }
    };
    Ok(inspect_jpeg_from(&coeffs, media_info, cred, domain, fmt, limits, control)?.info)
}

/// Header result plus the locator master needed to decrypt level 3.
struct JpegInspection {
    info: StegoHeaderInfo,
    master: Option<[u8; 32]>,
}

/// Superblock inspection over already-decoded DCT coefficients.
#[allow(clippy::too_many_arguments)]
fn inspect_jpeg_from(
    coeffs: &JpegCoefficients,
    media_info: Option<MediaInfo>,
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &JpegFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<JpegInspection, StrHideError> {
    let mut empty_info = StegoHeaderInfo::empty("JPEG");
    empty_info.media_info = media_info;
    if coeffs.components.is_empty() {
        return Ok(JpegInspection {
            info: empty_info,
            master: None,
        });
    }
    // The V4 L1 cost is fixed, and the extractor refuses a policy that cannot
    // pay it *before* any PBKDF2 work. Inspect has to refuse at the same point,
    // or it reports a payload nobody can read after burning the 200k rounds.
    if matches!(cred, Credential::Password(_))
        && limits.max_pbkdf2_iterations < crate::crypto::CONTENT_L1_PBKDF2_ITERATIONS
    {
        return Ok(JpegInspection {
            info: empty_info,
            master: None,
        });
    }
    control.check()?;
    let cover = CoverFrame::read(fmt, coeffs);
    let pre_salt = jpeg_pre_salt(fmt, &cover);
    let Ok(master) = derive_locator_master(cred, domain, fmt.cipher, &pre_salt) else {
        return Ok(JpegInspection {
            info: empty_info,
            master: None,
        });
    };
    let Ok(locator) = derive_l2_locator_keys(&master, fmt.cipher, b"strhide-v4-hdr-magic", domain)
    else {
        return Ok(JpegInspection {
            info: empty_info,
            master: None,
        });
    };

    let mut slots_buf = v3_layout::grid_indices(cover.block_count, fmt.grid_rule);
    let sb_n = fmt.superblock_slots();
    if slots_buf.len() < sb_n {
        return Ok(JpegInspection {
            info: empty_info,
            master: None,
        });
    }
    let hdr_min = fmt.header_slots(0);
    let mut hdr_rng = ChaCha12Stream::from_seed(&locator.locate_seed);
    fisher_yates_prefix_from(&mut slots_buf, 0, hdr_min, &mut hdr_rng);

    let Some(superblock) = read_superblock(coeffs, &slots_buf[..sb_n], fmt, &locator) else {
        return Ok(JpegInspection {
            info: empty_info,
            master: None,
        });
    };
    if superblock.version & 0xF0 != CONTENT_ENVELOPE_VERSION & 0xF0
        || superblock.codec_id != CODEC_TERNARY_STC
    {
        return Ok(JpegInspection {
            info: empty_info,
            master: None,
        });
    }
    let ext_bytes = superblock.ext_len as usize;
    let hdr_n = fmt.header_slots(ext_bytes);
    if hdr_n > cover.n_total() {
        return Ok(JpegInspection {
            info: empty_info,
            master: None,
        });
    }
    // The same policy gate `extract_jpeg_from` applies, in the same order and
    // before the extension area is read: inspect and extract must never
    // disagree about whether one carrier holds a readable payload.
    if !limits.allows_suite(superblock.suite_id)
        || limits
            .validate_header(
                superblock.suite_id,
                superblock.body_len,
                hdr_n,
                cover.n_total(),
            )
            .is_err()
    {
        return Ok(JpegInspection {
            info: empty_info,
            master: None,
        });
    }
    if hdr_n > hdr_min {
        fisher_yates_prefix_from(&mut slots_buf, hdr_min, hdr_n, &mut hdr_rng);
    }
    let extension_area = if ext_bytes > 0 {
        match read_bits(
            coeffs,
            &slots_buf[sb_n..hdr_n],
            fmt.grid_rule,
            locator.ext_stc_seed,
            fmt.ext_h,
            fmt.ext_u,
            8 * ext_bytes,
        ) {
            Some(area) => area,
            None => {
                empty_info.note = Some("Extension area is unreadable".into());
                return Ok(JpegInspection {
                    info: empty_info,
                    master: None,
                });
            }
        }
    } else {
        Vec::new()
    };
    // Ensure inspect enforces identical flag/TLV validation as extraction.
    if validate_ext_critical_flag(superblock.flags, &extension_area).is_err() {
        empty_info.note = Some("Critical-extension flag does not match the TLVs".into());
        return Ok(JpegInspection {
            info: empty_info,
            master: None,
        });
    }
    if ext_bytes > 0 {
        match parse_extension(&extension_area) {
            Ok(records) => {
                if let Some((type_id, _)) = records.iter().find(|(t, _)| t & TLV_CRITICAL != 0) {
                    empty_info.note = Some(format!(
                        "Carrier uses critical extension type {type_id:#04x}, which this build does not implement"
                    ));
                    return Ok(JpegInspection {
                        info: empty_info,
                        master: None,
                    });
                }
            }
            Err(_) => {
                empty_info.note = Some("Malformed extension area".into());
                return Ok(JpegInspection {
                    info: empty_info,
                    master: None,
                });
            }
        }
    }

    Ok(JpegInspection {
        info: StegoHeaderInfo {
            format: "JPEG".into(),
            has_hidden_data: true,
            algorithm: Some("UERD/J-UNIWARD/J-MiPOD".into()),
            codec: Some(format!(
                "Ternary STC (h={}, u={})",
                superblock.stc_h, superblock.stc_u
            )),
            envelope_len: Some(superblock.body_len as usize),
            payload_len: None,
            media_info,
            note: None,
        },
        master: Some(master),
    })
}

/// Three-level diagnostic verification for JPEG carriers.
pub(crate) fn verify_jpeg(
    carrier_bytes: &[u8],
    cred: Credential<'_>,
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
    control.check()?;

    // The V4 L1 cost is fixed; a policy below it fails before the header read.
    if matches!(cred, Credential::Password(_))
        && limits.max_pbkdf2_iterations < crate::crypto::CONTENT_L1_PBKDF2_ITERATIONS
    {
        levels.push(VerifyLevel::fail(
            2,
            "Stego superblock",
            format!(
                "PBKDF2 iteration limit {} is below the V4 L1 cost {}",
                limits.max_pbkdf2_iterations,
                crate::crypto::CONTENT_L1_PBKDF2_ITERATIONS
            ),
        ));
        levels.push(VerifyLevel::fail(
            3,
            "Payload decryption",
            "Skipped due to level 2 policy failure",
        ));
        return Ok(StegoVerifyResult::new("JPEG", levels));
    }

    // Level 2: Superblock inspection, reusing the DCT decode from level 1.
    let inspection = inspect_jpeg_from(
        &coeffs,
        Some(MediaInfo::new(
            u32::from(info.width),
            u32::from(info.height),
        )),
        cred,
        domain,
        fmt,
        limits,
        control,
    )?;
    let header_info = &inspection.info;
    if !header_info.has_hidden_data {
        levels.push(VerifyLevel::fail(
            2,
            "Stego superblock",
            header_info
                .note
                .clone()
                .unwrap_or_else(|| "No valid V4 superblock found (or wrong password)".into()),
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

    // Level 3: Payload Decryption & AEAD Authenticity. The matched suite and
    // master come from level 2, so no second KDF is paid here.
    match extract_jpeg_from(
        &coeffs,
        cred,
        domain,
        fmt,
        limits,
        control,
        inspection.master,
    ) {
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
