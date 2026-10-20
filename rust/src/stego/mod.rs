//! Content-adaptive steganography module (HILL, UERD, LSB/DCT Matching).
//!
//! Fully decoupled from the structure-domain container hiding pipeline (write/read/restore).
//! Provides unified `embed_carrier` and `extract_carrier` entry points with automatic
//! format sniffing and extensible algorithm selection.

pub mod coding;
pub mod envelope;
pub mod jpeg;
pub mod params;
pub mod prng;
pub mod registry;
pub mod spatial;
pub mod traits;

pub use params::{JpegParams, SpatialParams, StegoCodec, StegoOptions};
pub use registry::CostModelRegistry;

use crate::errors::StrHideError;
use crate::params::Profile;

/// Automatically sniff carrier format and embed payload using content-adaptive steganography.
///
/// Uses the official dialect (no private secret). Call
/// [`embed_carrier_with_profile`] when a private
/// [`Profile`] must be honoured.
pub fn embed_carrier(
    carrier_bytes: &[u8],
    payload: &[u8],
    options: &StegoOptions,
) -> Result<Vec<u8>, StrHideError> {
    embed_carrier_with_profile(carrier_bytes, payload, options, &Profile::default())
}

/// [`embed_carrier`] with an explicit private-dialect [`Profile`].
///
/// The profile only supplies the no-password secret
/// ([`Profile::stego_secret`]); an explicit
/// [`StegoOptions::password`] still wins. A carrier embedded under a private
/// secret is unreadable with the official profile -- and fails as
/// `NoHiddenData`, not as a distinguishable error.
pub fn embed_carrier_with_profile(
    carrier_bytes: &[u8],
    payload: &[u8],
    options: &StegoOptions,
    profile: &Profile,
) -> Result<Vec<u8>, StrHideError> {
    // Validate the whole option set up front: a bad window size must surface as
    // a configuration error, not as a panic deep inside the HILL convolution or
    // as an opaque "no capacity" later.
    options.spatial_params.validate()?;
    options.jpeg_params.validate()?;

    // Private dialect resolution happens exactly once, here: a configured
    // secret is indistinguishable from a user password downstream, which is
    // what keeps the two engine families byte-compatible.
    let secret = options.secret(profile);

    if carrier_bytes.len() >= 2 && &carrier_bytes[..2] == b"\xFF\xD8" {
        // JPEG format
        let model =
            CostModelRegistry::get_jpeg_model(options.algorithm.as_deref()).ok_or_else(|| {
                StrHideError::General(format!(
                    "Unknown or incompatible JPEG stego algorithm: {:?}",
                    options.algorithm
                ))
            })?;
        jpeg::embed_jpeg(
            carrier_bytes,
            payload,
            secret,
            &*model,
            &options.jpeg_params,
        )
    } else if carrier_bytes.len() >= 8 && &carrier_bytes[..8] == b"\x89PNG\r\n\x1a\n" {
        // PNG format
        let model = CostModelRegistry::get_spatial_model(options.algorithm.as_deref()).ok_or_else(
            || {
                StrHideError::General(format!(
                    "Unknown or incompatible spatial stego algorithm: {:?}",
                    options.algorithm
                ))
            },
        )?;
        spatial::embed_spatial(
            carrier_bytes,
            payload,
            secret,
            &*model,
            &options.spatial_params,
        )
    } else {
        Err(StrHideError::UnsupportedFormat(
            "Content-adaptive steganography requires a PNG or JPEG image carrier".into(),
        ))
    }
}

/// Automatically sniff carrier format and extract payload using content-adaptive steganography.
///
/// Uses the official dialect. Call [`extract_carrier_with_profile`] when the
/// carrier was embedded under a private [`Profile`].
pub fn extract_carrier(
    carrier_bytes: &[u8],
    options: &StegoOptions,
) -> Result<Vec<u8>, StrHideError> {
    extract_carrier_with_profile(carrier_bytes, options, &Profile::default())
}

/// [`extract_carrier`] with an explicit private-dialect [`Profile`].
///
/// A profile mismatch is reported as `NoHiddenData`, identical to a wrong
/// password, so no oracle tells the caller which of the two was wrong.
pub fn extract_carrier_with_profile(
    carrier_bytes: &[u8],
    options: &StegoOptions,
    profile: &Profile,
) -> Result<Vec<u8>, StrHideError> {
    options.spatial_params.validate()?;
    options.jpeg_params.validate()?;

    let secret = options.secret(profile);

    if carrier_bytes.len() >= 2 && &carrier_bytes[..2] == b"\xFF\xD8" {
        // JPEG format
        let model =
            CostModelRegistry::get_jpeg_model(options.algorithm.as_deref()).ok_or_else(|| {
                StrHideError::General(format!(
                    "Unknown or incompatible JPEG stego algorithm: {:?}",
                    options.algorithm
                ))
            })?;
        jpeg::extract_jpeg(carrier_bytes, secret, &*model, &options.jpeg_params)
    } else if carrier_bytes.len() >= 8 && &carrier_bytes[..8] == b"\x89PNG\r\n\x1a\n" {
        // PNG format
        let model = CostModelRegistry::get_spatial_model(options.algorithm.as_deref()).ok_or_else(
            || {
                StrHideError::General(format!(
                    "Unknown or incompatible spatial stego algorithm: {:?}",
                    options.algorithm
                ))
            },
        )?;
        spatial::extract_spatial(carrier_bytes, secret, &*model, &options.spatial_params)
    } else {
        Err(StrHideError::UnsupportedFormat(
            "Content-adaptive steganography requires a PNG or JPEG image carrier".into(),
        ))
    }
}

/// Capacity information for content-adaptive steganography.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StegoCapacityInfo {
    pub format: String,
    pub algorithm: String,
    /// Total cover elements (pixels for PNG, coefficients for JPEG), header
    /// slots included. Useful as a "how big is the cover" number only.
    pub total_elements: usize,
    /// Slots actually available to the payload: candidate slots minus the 256
    /// slots consumed by the envelope header. This is the number a user should
    /// compare against a payload size -- before it was reported inclusive of the
    /// header, which made "available slots" and "max payload" look inconsistent.
    pub available_slots: usize,
    pub max_raw_payload_bytes: usize,
    pub recommended_max_bytes: usize,
    /// Expected modified slots per embedded payload bit under the matrix
    /// coding in use (0.2917 for the default Hamming k=3, 0.5 for plain LSB
    /// replacement). Tail bits embedded 1:1 push the true rate slightly
    /// higher.
    pub estimated_change_rate: f64,
}

/// Automatically sniff carrier format and probe embedding capacity.
///
/// Takes neither a [`Profile`] nor a password on purpose: the header budget is a
/// fixed 256 slots and the body budget is the candidate count, so the answer is
/// the same for every dialect. (Revisit this if the slot layout ever becomes
/// cost-dependent rather than secret-dependent.)
pub fn probe_carrier_capacity(
    carrier_bytes: &[u8],
    options: &StegoOptions,
) -> Result<StegoCapacityInfo, StrHideError> {
    options.spatial_params.validate()?;
    options.jpeg_params.validate()?;

    if carrier_bytes.len() >= 2 && &carrier_bytes[..2] == b"\xFF\xD8" {
        let model =
            CostModelRegistry::get_jpeg_model(options.algorithm.as_deref()).ok_or_else(|| {
                StrHideError::General(format!(
                    "Unknown or incompatible JPEG stego algorithm: {:?}",
                    options.algorithm
                ))
            })?;
        jpeg::probe_jpeg_capacity(carrier_bytes, &*model, &options.jpeg_params)
    } else if carrier_bytes.len() >= 8 && &carrier_bytes[..8] == b"\x89PNG\r\n\x1a\n" {
        let model = CostModelRegistry::get_spatial_model(options.algorithm.as_deref()).ok_or_else(
            || {
                StrHideError::General(format!(
                    "Unknown or incompatible spatial stego algorithm: {:?}",
                    options.algorithm
                ))
            },
        )?;
        spatial::probe_spatial_capacity(carrier_bytes, &*model, &options.spatial_params)
    } else {
        Err(StrHideError::UnsupportedFormat(
            "Content-adaptive steganography requires a PNG or JPEG image carrier".into(),
        ))
    }
}
