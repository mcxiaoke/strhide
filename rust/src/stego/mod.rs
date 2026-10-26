//! Content-adaptive steganography module (HILL, UERD, LSB/DCT Matching).
//!
//! Fully decoupled from the structure-domain container hiding pipeline (write/read/restore).
//! Provides unified `embed_carrier` and `extract_carrier` entry points with automatic
//! format sniffing and extensible algorithm selection.

#[doc(hidden)]
pub mod coding;
#[doc(hidden)]
pub mod envelope;
pub mod format;
#[doc(hidden)]
pub mod header;
pub mod heif;
pub mod hevc;
pub mod io;
pub mod jpeg;
pub mod params;
pub mod png;
#[doc(hidden)]
pub mod prng;
pub mod registry;
pub mod sniff;
pub mod traits;
#[doc(hidden)]
pub mod wavelet;

pub use envelope::Freshness;
pub use format::{
    CipherSuite, DEFAULT_HEVC_FORMAT, DEFAULT_JPEG_FORMAT, GridRule, HevcFormatProfile,
    JpegFormatProfile, OFFICIAL_PNG_FORMAT, PngFormatProfile,
};
pub use params::{
    ExtractParams, JpegParams, PngParams, SafetyEnforcement, SafetyLevel, SafetyPolicy, StegoCodec,
    StegoOptions,
};
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
    embed_carrier_with_profile_info(carrier_bytes, payload, options, profile)
        .map(|(bytes, _)| bytes)
}

/// Automatically sniff carrier format, embed payload, and return both the modified carrier
/// and optional structured capacity metadata if produced during embedding.
pub fn embed_carrier_with_profile_info(
    carrier_bytes: &[u8],
    payload: &[u8],
    options: &StegoOptions,
    profile: &Profile,
) -> Result<(Vec<u8>, Option<StegoCapacityInfo>), StrHideError> {
    // Validate the whole option set up front: a bad window size must surface as
    // a configuration error, not as a panic deep inside the HILL convolution or
    // as an opaque "no capacity" later.
    options.png_params.validate()?;
    options.jpeg_params.validate()?;

    // Private dialect resolution happens exactly once, here: a configured
    // secret is indistinguishable from a user password downstream, which is
    // what keeps the two engine families byte-compatible.
    let secret = options.secret(profile);
    let domain = options.domain(profile);

    let png_params = options.png_params.clone();
    let mut jpeg_params = options.jpeg_params.clone();
    // A seeded run must not take the FMA path: it rounds differently from the
    // scalar one, and a last-bit disagreement in a cost value can move the
    // trellis to a different slot.
    jpeg_params.deterministic = options.freshness.is_seeded();

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
            domain,
            profile.jpeg_format(),
            &jpeg_params,
            options.safety,
            &*model,
            options.freshness,
        )
        .map(|b| (b, None))
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
        png::embed_png(
            carrier_bytes,
            payload,
            secret,
            domain,
            profile.png_format(),
            &*model,
            &png_params,
            options.safety,
            options.freshness,
        )
        .map(|b| (b, None))
    } else if crate::sniff::is_heif_bytes(carrier_bytes) {
        // HEIF content-domain steganography: Scheme C (HEVC CABAC in-place)
        // first, thumbnail bridge second. The order is the same on read, write
        // and capacity so all three agree on what a carrier holds: a file
        // embedded twice carries two payloads, and "the one the writer would
        // have produced" has to be the one the reader returns.
        //
        // The bridge is the older scheme and stays only as the fallback for
        // HEIFs whose HEVC items cannot be rewritten (no hvc1 item, unsupported
        // slice syntax) but which do carry a rewritable JPEG/auxiliary item.
        if options.algorithm.as_deref() == Some("hevc")
            || options.algorithm.as_deref() == Some("cabac")
        {
            hevc::embed_hevc_with_info(
                carrier_bytes,
                payload,
                secret,
                domain,
                profile.hevc_format(),
                options.freshness,
                options.safety.level,
            )
            .map(|(b, info)| (b, Some(info)))
        } else {
            match hevc::embed_hevc_with_info(
                carrier_bytes,
                payload,
                secret,
                domain,
                profile.hevc_format(),
                options.freshness,
                options.safety.level,
            ) {
                Ok((bytes, info)) => Ok((bytes, Some(info))),
                Err(_) => heif::embed_heif_bridge(carrier_bytes, payload, options, profile)
                    .map(|b| (b, None)),
            }
        }
    } else if hevc::sniff::is_mp4_bytes(carrier_bytes) {
        // MP4/MOV video container: Scheme C on the sample table. Byte length is
        // preserved (Delta = 0), so `stsz`/`stco`/`co64` stay valid untouched.
        hevc::embed_hevc_with_info(
            carrier_bytes,
            payload,
            secret,
            domain,
            profile.hevc_format(),
            options.freshness,
            options.safety.level,
        )
        .map(|(b, info)| (b, Some(info)))
    } else if hevc::sniff::is_hevc_annexb(carrier_bytes) {
        // Raw Annex-B HEVC bitstream
        hevc::embed_hevc_with_info(
            carrier_bytes,
            payload,
            secret,
            domain,
            profile.hevc_format(),
            options.freshness,
            options.safety.level,
        )
        .map(|(b, info)| (b, Some(info)))
    } else {
        Err(StrHideError::UnsupportedFormat(
            "Content-adaptive steganography requires a PNG, JPEG, HEIF/HEIC, or HEVC carrier (Annex-B or MP4/MOV)"
                .into(),
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
    options.png_params.validate()?;
    options.jpeg_params.validate()?;

    let secret = options.secret(profile);
    let domain = options.domain(profile);

    if carrier_bytes.len() >= 2 && &carrier_bytes[..2] == b"\xFF\xD8" {
        // JPEG format. No cost model is looked up on purpose: the V3 slot set
        // is geometric, so extraction must not depend on the embedder's cost
        // function (or on `--algorithm`).
        jpeg::extract_jpeg(
            carrier_bytes,
            secret,
            domain,
            profile.jpeg_format(),
            &options.extract_params,
        )
    } else if carrier_bytes.len() >= 8 && &carrier_bytes[..8] == b"\x89PNG\r\n\x1a\n" {
        // PNG format. The carrier names its cost model in the feature word
        // and the extractor rebuilds everything from that declaration, so
        // `--algorithm` must not gate extraction (mirroring the JPEG branch
        // above): a misspelled algorithm name is not a reason to refuse a
        // readable carrier. The instance below is only a logging hint.
        let model = CostModelRegistry::get_spatial_model(None)
            .expect("the default spatial model always resolves");
        png::extract_png(
            carrier_bytes,
            secret,
            domain,
            profile.png_format(),
            &*model,
            &options.png_params,
        )
    } else if crate::sniff::is_heif_bytes(carrier_bytes) {
        // HEIF content-domain steganography: Scheme C (HEVC CABAC in-place)
        // first, then the thumbnail bridge. Same order as embed and probe --
        // see the note on the HEIF branch in `embed_carrier`.
        match hevc::extract_hevc(carrier_bytes, secret, domain, profile.hevc_format()) {
            Ok(payload) => Ok(payload),
            Err(e) => {
                if options.algorithm.as_deref() == Some("hevc")
                    || options.algorithm.as_deref() == Some("cabac")
                {
                    return Err(e);
                }
                match heif::extract_heif_bridge(carrier_bytes, options, profile) {
                    Ok(payload) => Ok(payload),
                    // A Scheme C authentication failure means the carrier really
                    // does carry a CABAC payload, so its password verdict is the
                    // honest one. Every other HEVC failure only says "this is not
                    // a Scheme C carrier", and the bridge's verdict describes the
                    // carrier better than the HEVC probe does.
                    Err(bridge_err) => {
                        if matches!(e, StrHideError::Password(_)) {
                            Err(e)
                        } else {
                            Err(bridge_err)
                        }
                    }
                }
            }
        }
    } else if hevc::sniff::is_mp4_bytes(carrier_bytes) {
        // MP4/MOV video container
        hevc::extract_hevc(carrier_bytes, secret, domain, profile.hevc_format())
    } else if hevc::sniff::is_hevc_annexb(carrier_bytes) {
        // Raw Annex-B HEVC bitstream
        hevc::extract_hevc(carrier_bytes, secret, domain, profile.hevc_format())
    } else {
        Err(StrHideError::UnsupportedFormat(
            "Content-adaptive steganography requires a PNG, JPEG, HEIF/HEIC, or HEVC carrier (Annex-B or MP4/MOV)"
                .into(),
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
    /// Slots actually available to the payload: the slot grid minus the header
    /// slots (718 + extension area for JPEG V3, 512 for the spatial codec).
    pub available_slots: usize,
    pub max_raw_payload_bytes: usize,
    /// Whether `max_raw_payload_bytes` is the grouped-code (`u >= 2`) bound
    /// rather than the `u = 1` geometric one. True exactly when the carrier's
    /// Huffman table is over-optimised and `u = 1` would be refused; the CLI
    /// prints a caveat so the lower number is not mistaken for a regression.
    #[serde(default)]
    pub max_raw_is_grouped: bool,
    pub recommended_max_bytes: usize,
    /// Expected modified slots per embedded payload bit under the matrix
    /// coding in use (0.2917 for the default Hamming k=3, 0.5 for plain LSB
    /// replacement). Tail bits embedded 1:1 push the true rate slightly
    /// higher.
    pub estimated_change_rate: f64,
    /// Target safety capacity tier used to calculate `recommended_max_bytes`.
    #[serde(default = "default_safety_tier_str")]
    pub safety_level: String,
    /// Target bits-per-pixel (bpp) limit for the safety tier.
    #[serde(default = "default_safety_bpp_limit")]
    pub safety_bpp_limit: f64,
    /// Whether capacity was estimated by sampling rather than a full-carrier scan.
    #[serde(default)]
    pub is_estimated: bool,
}

impl StegoCapacityInfo {
    /// Whether `payload_len` bytes fit inside the safety-tier recommendation.
    pub fn fits_recommended(&self, payload_len: usize) -> bool {
        payload_len <= self.recommended_max_bytes
    }

    /// Whether `payload_len` bytes fit inside the raw (ungated) capacity.
    pub fn fits_max(&self, payload_len: usize) -> bool {
        payload_len <= self.max_raw_payload_bytes
    }

    /// One-line human-readable summary for logs and CLI output.
    pub fn summary_string(&self) -> String {
        format!(
            "{} / {}: {} payload slots of {} elements, max {} bytes ({}), recommended {} bytes at '{}' safety (bpp <= {:.2}), ~{:.4} changes/bit",
            self.format,
            self.algorithm,
            self.available_slots,
            self.total_elements,
            self.max_raw_payload_bytes,
            if self.max_raw_is_grouped {
                "grouped"
            } else {
                "u=1"
            },
            self.recommended_max_bytes,
            self.safety_level,
            self.safety_bpp_limit,
            self.estimated_change_rate,
        )
    }
}

fn default_safety_tier_str() -> String {
    "high".into()
}

fn default_safety_bpp_limit() -> f64 {
    0.10
}

/// Automatically sniff carrier format and probe embedding capacity.
///
/// Credentials matter, and they are taken from `options` exactly like
/// [`embed_carrier`] does:
///
/// - **JPEG V3** ignores them: the header budget is the fixed superblock +
///   extension area and the body budget is the geometric grid, both
///   independent of the key.
/// - **The spatial codec does not**: the 512 header/feature slots are chosen by
///   a permutation keyed on password + domain and are excluded from the body
///   pool, so a different credential assigns different pixels to the header
///   and yields a different capacity.
///
/// Use [`probe_carrier_capacity_with_profile`] when a private
/// [`Profile`](crate::params::Profile) supplies the no-password stego secret.
pub fn probe_carrier_capacity(
    carrier_bytes: &[u8],
    options: &StegoOptions,
) -> Result<StegoCapacityInfo, StrHideError> {
    probe_carrier_capacity_with_profile(carrier_bytes, options, &Profile::default())
}

/// [`probe_carrier_capacity`] with an explicit private-dialect [`Profile`].
pub fn probe_carrier_capacity_with_profile(
    carrier_bytes: &[u8],
    options: &StegoOptions,
    profile: &Profile,
) -> Result<StegoCapacityInfo, StrHideError> {
    options.png_params.validate()?;
    options.jpeg_params.validate()?;

    // Same resolution as embed: an explicit password wins, the profile's stego
    // secret is the fallback, `None` means the public constant downstream.
    let secret = options.secret(profile);
    let domain = options.domain(profile);

    if carrier_bytes.len() >= 2 && &carrier_bytes[..2] == b"\xFF\xD8" {
        let model =
            CostModelRegistry::get_jpeg_model(options.algorithm.as_deref()).ok_or_else(|| {
                StrHideError::General(format!(
                    "Unknown or incompatible JPEG stego algorithm: {:?}",
                    options.algorithm
                ))
            })?;
        jpeg::probe_jpeg_capacity(
            carrier_bytes,
            &*model,
            &options.jpeg_params,
            options.safety.level,
            profile.jpeg_format(),
        )
    } else if carrier_bytes.len() >= 8 && &carrier_bytes[..8] == b"\x89PNG\r\n\x1a\n" {
        let model = CostModelRegistry::get_spatial_model(options.algorithm.as_deref()).ok_or_else(
            || {
                StrHideError::General(format!(
                    "Unknown or incompatible spatial stego algorithm: {:?}",
                    options.algorithm
                ))
            },
        )?;
        png::probe_png_capacity(
            carrier_bytes,
            &*model,
            &options.png_params,
            options.safety.level,
            secret,
            domain,
            profile.png_format(),
        )
    } else if crate::sniff::is_heif_bytes(carrier_bytes) {
        // Same order as embed/extract: Scheme C first, bridge as the fallback.
        // A probe that advertises the bridge's capacity while the writer fills
        // the CABAC stream (or the other way round) is worse than useless.
        if options.algorithm.as_deref() == Some("hevc")
            || options.algorithm.as_deref() == Some("cabac")
        {
            hevc::probe_hevc_capacity_info(
                carrier_bytes,
                profile.hevc_format(),
                options.safety.level,
                options.exact,
            )
        } else {
            match hevc::probe_hevc_capacity_info(
                carrier_bytes,
                profile.hevc_format(),
                options.safety.level,
                options.exact,
            ) {
                Ok(info) => Ok(info),
                Err(_) => heif::probe_heif_bridge_capacity(carrier_bytes, options, profile),
            }
        }
    } else if hevc::sniff::is_mp4_bytes(carrier_bytes) || hevc::sniff::is_hevc_annexb(carrier_bytes)
    {
        // MP4/MOV video container, or a raw Annex-B bitstream: one entry point,
        // the container decides where the slice NALs live.
        hevc::probe_hevc_capacity_info(
            carrier_bytes,
            profile.hevc_format(),
            options.safety.level,
            options.exact,
        )
    } else {
        Err(StrHideError::UnsupportedFormat(
            "Content-adaptive steganography requires a PNG, JPEG, HEIF/HEIC, or HEVC carrier (Annex-B or MP4/MOV)"
                .into(),
        ))
    }
}
