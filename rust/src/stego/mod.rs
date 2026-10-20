//! Content-adaptive steganography module (HILL, UERD, LSB/DCT Matching).
//!
//! Fully decoupled from the structure-domain container hiding pipeline (write/read/restore).
//! Provides unified `embed_carrier` and `extract_carrier` entry points with automatic
//! format sniffing and extensible algorithm selection.

pub mod envelope;
pub mod jpeg;
pub mod params;
pub mod prng;
pub mod registry;
pub mod spatial;
pub mod traits;

pub use params::{JpegParams, SpatialParams, StegoOptions};
pub use registry::CostModelRegistry;

use crate::errors::StrHideError;

/// Automatically sniff carrier format and embed payload using content-adaptive steganography.
pub fn embed_carrier(
    carrier_bytes: &[u8],
    payload: &[u8],
    options: &StegoOptions,
) -> Result<Vec<u8>, StrHideError> {
    // Validate the whole option set up front: a bad window size must surface as
    // a configuration error, not as a panic deep inside the HILL convolution or
    // as an opaque "no capacity" later.
    options.spatial_params.validate()?;
    options.jpeg_params.validate()?;

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
            options.password.as_deref(),
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
            options.password.as_deref(),
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
pub fn extract_carrier(
    carrier_bytes: &[u8],
    options: &StegoOptions,
) -> Result<Vec<u8>, StrHideError> {
    options.spatial_params.validate()?;
    options.jpeg_params.validate()?;

    if carrier_bytes.len() >= 2 && &carrier_bytes[..2] == b"\xFF\xD8" {
        // JPEG format
        let model =
            CostModelRegistry::get_jpeg_model(options.algorithm.as_deref()).ok_or_else(|| {
                StrHideError::General(format!(
                    "Unknown or incompatible JPEG stego algorithm: {:?}",
                    options.algorithm
                ))
            })?;
        jpeg::extract_jpeg(
            carrier_bytes,
            options.password.as_deref(),
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
        spatial::extract_spatial(
            carrier_bytes,
            options.password.as_deref(),
            &*model,
            &options.spatial_params,
        )
    } else {
        Err(StrHideError::UnsupportedFormat(
            "Content-adaptive steganography requires a PNG or JPEG image carrier".into(),
        ))
    }
}

/// Capacity information for content-adaptive steganography.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StegoCapacityInfo {
    pub format: String,
    pub algorithm: String,
    pub total_elements: usize,
    pub available_slots: usize,
    pub max_raw_payload_bytes: usize,
    pub recommended_max_bytes: usize,
}

/// Automatically sniff carrier format and probe embedding capacity.
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
