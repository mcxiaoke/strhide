//! Verification: three diagnostic levels over one header read.
//!
//! Level 1 proves the bitstream parses, level 2 proves the header is authentic
//! for this credential, level 3 decrypts the body. The header read is shared
//! with extraction so the 200k-iteration L1 is paid once per request.

use crate::core::control::Control;
use crate::core::crypto::{CONTENT_L1_PBKDF2_ITERATIONS, Credential};
use crate::core::media::MediaInfo;
use crate::errors::StrHideError;
use crate::stego::format::HevcFormatProfile;
use crate::stego::hevc::sniff::sniff_hevc_carrier;
use crate::stego::hevc::superblock::HEVC_SUPERBLOCK_POOL_SLOTS;
use crate::stego::options::{StegoVerifyResult, VerifyLevel};
use crate::stego::params::ExtractParams;

use super::capacity::extract_hevc_dimensions;
use super::extract::{extract_hevc_with_header, read_hevc_header_v4};
use super::inspect::hevc_header_info;
use super::record::record_carrier_state;
use super::scan::Capture;
use super::support::{StopCondition, legacy_credential};

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
