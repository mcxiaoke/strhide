//! Spatial domain inspection and verification pipeline (PNG).

use crate::core::control::Control;
use crate::core::crypto::Credential;
use crate::core::media::MediaInfo;
use crate::errors::StrHideError;
use crate::stego::options::{StegoHeaderInfo, StegoVerifyResult, VerifyLevel};
use crate::stego::params::ExtractParams;

use super::codec::{RawImage, decode_png};
use super::extract::{
    OpenedPngHeaderError, PngKeys, extract_png_with_keys, l1_allowed, open_png_header, png_keys,
};

/// Inspect PNG for stego header and self-describing metadata without decoding body.
pub(crate) fn inspect_png(
    carrier_bytes: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    control.check()?;
    let image = match decode_png(carrier_bytes) {
        Ok(img) => img,
        Err(e) => {
            return Ok(StegoHeaderInfo {
                format: "PNG".into(),
                has_hidden_data: false,
                algorithm: None,
                codec: None,
                envelope_len: None,
                payload_len: None,
                media_info: None,
                note: Some(format!("Decode failed: {e}")),
            });
        }
    };
    control.check()?;
    inspect_png_image(&image, cred, domain, spatial, limits, control)
}

/// Header inspection for an already-decoded image.
///
/// `verify_png` and `inspect_png` share this so the PNG decode runs once.
pub(super) fn inspect_png_image(
    image: &RawImage,
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    if !l1_allowed(&cred, limits) {
        let mut empty = StegoHeaderInfo::empty("PNG");
        empty.media_info = Some(MediaInfo::new(image.width, image.height));
        return Ok(empty);
    }
    let keys = png_keys(image, cred, domain, spatial)?;
    inspect_png_with_keys(image, &keys, limits, control)
}

/// Header inspection over a pre-derived L1/L2 key set.
pub(super) fn inspect_png_with_keys(
    image: &RawImage,
    keys: &PngKeys,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    control.check()?;
    let media_info = Some(MediaInfo::new(image.width, image.height));
    let mut empty_info = StegoHeaderInfo::empty("PNG");
    empty_info.media_info = media_info;

    let opened = match open_png_header(image, &keys.locator, limits) {
        Ok(opened) => opened,
        Err(OpenedPngHeaderError::HeaderSlotsShort {
            carrier_slots,
            needed,
        }) => {
            // The pool length was checked inside the bootstrap, so a short read
            // means the slot mapping disagrees with the image — an anomaly, not
            // the "no header here" answer every clean PNG gives below.
            log::debug!(
                target: "stego::inspect",
                "png header slots could not be read (pool {} slots, need {})",
                carrier_slots,
                needed
            );
            empty_info.note = Some(format!(
                "Header slots could not be read: pool has {carrier_slots} slots, the header needs {needed}"
            ));
            return Ok(empty_info);
        }
        Err(OpenedPngHeaderError::Rejected) => return Ok(empty_info),
    };
    let header = opened.header;

    let algo_name = crate::stego::png::registry::spatial_model_from_wire_id(header.algorithm_id)
        .map(|m| m.id().to_string())
        .unwrap_or_else(|| format!("Unknown(0x{:02x})", header.algorithm_id));
    let codec = match header.codec_id {
        0 => "Hamming".to_string(),
        1 => format!("Stc (h={}, u={})", header.stc_h, header.stc_u),
        other => format!("Unknown({other})"),
    };

    Ok(StegoHeaderInfo {
        format: "PNG".into(),
        has_hidden_data: true,
        algorithm: Some(algo_name),
        codec: Some(codec),
        envelope_len: Some(header.body_len as usize),
        payload_len: None,
        media_info,
        note: None,
    })
}

/// Three-level diagnostic verification for PNG carriers.
pub(crate) fn verify_png(
    carrier_bytes: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    control.check()?;
    let mut levels = Vec::new();

    // Level 1: Container & Decode
    let image = match decode_png(carrier_bytes) {
        Ok(img) => {
            levels.push(VerifyLevel::pass(
                1,
                format!(
                    "PNG structure valid ({}x{}, {} channels)",
                    img.width, img.height, img.channels
                ),
            ));
            img
        }
        Err(e) => {
            levels.push(VerifyLevel::fail(1, "PNG structure decode", e.to_string()));
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
            return Ok(StegoVerifyResult::new("PNG", levels));
        }
    };
    control.check()?;

    // The L1 cost is fixed by V4; a policy that cannot pay it must fail before
    // the header read so the report says "policy", not "wrong password".
    if matches!(cred, Credential::Password(_))
        && limits.max_pbkdf2_iterations < crate::crypto::CONTENT_L1_PBKDF2_ITERATIONS
    {
        levels.push(VerifyLevel::fail(
            2,
            "Stego header",
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
        return Ok(StegoVerifyResult::new("PNG", levels));
    }

    // Level 2 and 3 share one L1/L2 derivation: `verify` is one user request,
    // so it must not pay the 200k-iteration L1 twice (plan M-14).
    let keys = png_keys(&image, cred, domain, spatial)?;
    let header_info = inspect_png_with_keys(&image, &keys, limits, control)?;
    if !header_info.has_hidden_data {
        levels.push(VerifyLevel::fail(
            2,
            "Stego header",
            "No valid V4 stego header found (or wrong password)",
        ));
        levels.push(VerifyLevel::fail(
            3,
            "Payload decryption",
            "No stego header to extract payload from",
        ));
        return Ok(StegoVerifyResult::new("PNG", levels));
    }
    levels.push(VerifyLevel::pass(
        2,
        format!(
            "Stego header valid (algorithm: {}, codec: {}, envelope: {} B)",
            header_info.algorithm.as_deref().unwrap_or("unknown"),
            header_info.codec.as_deref().unwrap_or("unknown"),
            header_info.envelope_len.unwrap_or(0),
        ),
    ));
    control.check()?;

    // Level 3: Payload Decryption & AEAD Authenticity
    let model = crate::stego::options::SpatialAlgorithm::default().model();
    let params = crate::stego::params::PngParams::default();
    match extract_png_with_keys(
        &image, &keys, domain, spatial, &*model, &params, limits, control,
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

    Ok(StegoVerifyResult::new("PNG", levels))
}
