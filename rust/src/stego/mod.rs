//! Content-adaptive steganography module (HILL, UERD, LSB/DCT Matching).
//!
//! Fully decoupled from the structure-domain container hiding pipeline
//! (write/read/restore). Provides unified `embed_carrier` and `extract_carrier`
//! entry points with automatic format sniffing and extensible algorithm
//! selection.
//!
//! Dispatch is one registry lookup ([`engine::engine_for`]) on the format the
//! sniffer reported; the engines own what happens next. Until stage 2 this file
//! held three parallel `if format == ...` waterfalls -- one per entry point --
//! which is how a probe could end up advertising a different capacity than the
//! writer filled.

#[doc(hidden)]
pub mod coding;
pub mod engine;
#[doc(hidden)]
pub mod envelope;
pub mod format;
#[doc(hidden)]
pub mod header;
#[cfg(feature = "content-hevc")]
pub mod heif;
#[cfg(feature = "content-hevc")]
pub mod hevc;
pub mod io;
#[cfg(feature = "content-jpeg")]
pub mod jpeg;
pub mod options;
pub mod params;
#[cfg(feature = "content-png")]
pub mod png;
#[doc(hidden)]
pub mod prng;
pub mod registry;
pub mod traits;
#[cfg(any(feature = "content-png", feature = "content-jpeg"))]
#[doc(hidden)]
pub mod wavelet;

#[cfg(feature = "content-jpeg")]
pub use crate::stego::jpeg::registry::get_jpeg_model;
#[cfg(feature = "content-png")]
pub use crate::stego::png::registry::{
    SPATIAL_ALGORITHM_HILL, SPATIAL_ALGORITHM_SUNIWARD, get_spatial_model,
    spatial_model_from_wire_id, spatial_name_from_wire_id, spatial_wire_id,
};
pub use engine::{StegoEngine, engine_for, supported_formats};
pub use envelope::Freshness;
pub use format::{CipherSuite, GridRule};
#[cfg(feature = "content-hevc")]
pub use format::{DEFAULT_HEVC_FORMAT, HevcFormatProfile};
#[cfg(feature = "content-jpeg")]
pub use format::{DEFAULT_JPEG_FORMAT, JpegFormatProfile};
#[cfg(feature = "content-png")]
pub use format::{OFFICIAL_PNG_FORMAT, PngFormatProfile};

#[cfg(feature = "content-heif-bridge")]
pub use options::BridgeOptions;
#[cfg(feature = "content-jpeg")]
pub use options::JpegAlgorithm;
#[cfg(feature = "content-png")]
pub use options::SpatialAlgorithm;
pub use options::{
    EmbedOptions, EmbedOutput, EmbedStats, ExtractOptions, InspectOptions, ProbeOptions,
    StegoEmbedResult, StegoHeaderInfo, StegoTuning, StegoVerifyResult, StegoWarning, VerifyLevel,
    VerifyOptions,
};
#[cfg(feature = "content-hevc")]
pub use options::{HevcMode, HevcParams};

#[cfg(feature = "content-jpeg")]
pub use params::JpegParams;
#[cfg(feature = "content-png")]
pub use params::PngParams;
pub use params::{ExtractParams, SafetyEnforcement, SafetyLevel, SafetyPolicy, StegoCodec};

pub use registry::list_algorithms;

static INIT_DEFAULT_POOL: std::sync::Once = std::sync::Once::new();

/// Computes the default worker thread count from the total available parallelism:
/// minimum 4, maximum half of the total cores, clamped to `total`.
#[inline]
pub fn compute_default_threads(total: usize) -> usize {
    if total == 0 {
        1
    } else {
        (total / 2).max(4).min(total)
    }
}

/// Returns the calculated default worker thread count for the current machine.
pub fn default_thread_count() -> usize {
    let total = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    compute_default_threads(total)
}

/// Initialize Rayon's global thread pool using the default thread count
/// (`(cores / 2).max(4).min(cores)`), unless overridden by the `RAYON_NUM_THREADS`
/// environment variable.
///
/// **Opt-in**: the library entry points no longer call this, because a library
/// must not lock the host process's global Rayon pool to a policy it chose.
/// The CLI calls it once at startup; an embedding application that wants the
/// same headroom can call it explicitly. Safe to call multiple times
/// (idempotent via `std::sync::Once`).
pub fn init_default_thread_pool() {
    INIT_DEFAULT_POOL.call_once(|| {
        if std::env::var_os("RAYON_NUM_THREADS").is_none() {
            let threads = default_thread_count();
            let _ = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build_global();
        }
    });
}

/// Compatibility facade over the per-domain registries.
pub struct CostModelRegistry;

impl CostModelRegistry {
    /// See [`crate::stego::png::registry::get_spatial_model`].
    #[cfg(feature = "content-png")]
    pub fn get_spatial_model(
        name: Option<&str>,
    ) -> Option<std::sync::Arc<dyn crate::stego::traits::PngCostModel>> {
        crate::stego::png::registry::get_spatial_model(name)
    }

    /// See [`crate::stego::jpeg::registry::get_jpeg_model`].
    #[cfg(feature = "content-jpeg")]
    pub fn get_jpeg_model(
        name: Option<&str>,
    ) -> Option<std::sync::Arc<dyn crate::stego::traits::JpegCostModel>> {
        crate::stego::jpeg::registry::get_jpeg_model(name)
    }

    /// See [`crate::stego::png::registry::spatial_wire_id`].
    #[cfg(feature = "content-png")]
    pub fn spatial_wire_id(name: &str) -> Option<u8> {
        crate::stego::png::registry::spatial_wire_id(name)
    }

    /// See [`crate::stego::png::registry::spatial_name_from_wire_id`].
    #[cfg(feature = "content-png")]
    pub fn spatial_name_from_wire_id(id: u8) -> Option<&'static str> {
        crate::stego::png::registry::spatial_name_from_wire_id(id)
    }

    /// See [`crate::stego::png::registry::spatial_model_from_wire_id`].
    #[cfg(feature = "content-png")]
    pub fn spatial_model_from_wire_id(
        id: u8,
    ) -> Option<std::sync::Arc<dyn crate::stego::traits::PngCostModel>> {
        crate::stego::png::registry::spatial_model_from_wire_id(id)
    }

    /// See [`registry::list_algorithms`].
    pub fn list_algorithms() -> Vec<(&'static str, &'static str, &'static str)> {
        crate::stego::registry::list_algorithms()
    }
}

use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::formats::sniff::{FileFormat, sniff_bytes};
use crate::stego::params::StegoProfile;

/// Resolve the engine for a carrier, or fail with the one unsupported-format
/// message every entry point shares.
fn engine_for_carrier(carrier_bytes: &[u8]) -> Result<&'static dyn StegoEngine, StrHideError> {
    let Some(format) = sniff_bytes(carrier_bytes) else {
        return Err(StrHideError::UnsupportedFormat(
            "Content-adaptive steganography requires a PNG, JPEG, HEIF/HEIC, or HEVC carrier (Annex-B or MP4/MOV)"
                .into(),
        ));
    };
    // A format the sniffer knows but the content domain cannot carry (ZIP, PE,
    // ...) says so by name instead of pretending the bytes are unreadable.
    engine::engine_for(format).ok_or_else(|| unsupported_carrier(format))
}

/// The unsupported-format error, worded once for every entry point.
pub(crate) fn unsupported_carrier(format: FileFormat) -> StrHideError {
    StrHideError::UnsupportedFormat(format!(
        "Content-adaptive steganography requires a PNG, JPEG, HEIF/HEIC, or HEVC carrier \
         (Annex-B or MP4/MOV); '{}' is not one",
        format.as_str()
    ))
}

/// Automatically sniff the carrier format and embed `payload` using
/// content-adaptive steganography.
///
/// Uses the official dialect (no private secret). Call
/// [`embed_carrier_with_dialect`] when a private [`StegoProfile`] must be honoured.
pub fn embed_carrier(
    carrier_bytes: &[u8],
    payload: &Payload<'_>,
    options: &EmbedOptions<'_>,
) -> Result<Vec<u8>, StrHideError> {
    embed_carrier_with_dialect(carrier_bytes, payload, options, &StegoProfile::default())
}

/// [`embed_carrier`] with an explicit private-dialect [`StegoProfile`].
///
/// The dialect only supplies the no-password secret; an explicit
/// [`EmbedOptions::password`] still wins. A carrier embedded under a private
/// secret is unreadable with the official dialect -- and fails as
/// `NoHiddenData`, not as a distinguishable error.
pub fn embed_carrier_with_dialect(
    carrier_bytes: &[u8],
    payload: &Payload<'_>,
    options: &EmbedOptions<'_>,
    dialect: &StegoProfile,
) -> Result<Vec<u8>, StrHideError> {
    embed_carrier_with_dialect_info(carrier_bytes, payload, options, dialect).map(|out| out.bytes)
}

/// Automatically sniff the carrier format, embed `payload`, and return the
/// modified carrier together with whatever capacity metadata the engine
/// produced while embedding.
pub fn embed_carrier_with_dialect_info(
    carrier_bytes: &[u8],
    payload: &Payload<'_>,
    options: &EmbedOptions<'_>,
    dialect: &StegoProfile,
) -> Result<EmbedOutput, StrHideError> {
    let engine = engine_for_carrier(carrier_bytes)?;
    // Private dialect resolution happens exactly once, inside the engine
    // adapter: a configured secret is indistinguishable from a user password
    // downstream, which is what keeps the two engine families byte-compatible.
    engine.embed(carrier_bytes, payload, options, dialect)
}

/// Automatically sniff the carrier format and extract the payload.
///
/// Uses the official dialect. Call [`extract_carrier_with_dialect`] when the
/// carrier was embedded under a private [`StegoProfile`].
pub fn extract_carrier(
    carrier_bytes: &[u8],
    options: &ExtractOptions<'_>,
) -> Result<Vec<u8>, StrHideError> {
    extract_carrier_with_dialect(carrier_bytes, options, &StegoProfile::default())
}

/// [`extract_carrier`] with an explicit private-dialect [`StegoProfile`].
///
/// A dialect mismatch is reported as `NoHiddenData`, identical to a wrong
/// password, so no oracle tells the caller which of the two was wrong.
pub fn extract_carrier_with_dialect(
    carrier_bytes: &[u8],
    options: &ExtractOptions<'_>,
    dialect: &StegoProfile,
) -> Result<Vec<u8>, StrHideError> {
    extract_carrier_payload(carrier_bytes, options, dialect).map(Payload::into_bytes)
}

/// [`extract_carrier_with_dialect`] returning the unified [`Payload`] instead of
/// raw bytes.
///
/// `kind` and `name` are not on the wire yet -- stage 3 adds the micro-header
/// that persists them -- so the result always carries
/// [`PayloadKind::Bytes`](crate::core::payload::PayloadKind::Bytes). The
/// signature is written once here so it does not have to change twice.
pub fn extract_carrier_payload(
    carrier_bytes: &[u8],
    options: &ExtractOptions<'_>,
    dialect: &StegoProfile,
) -> Result<Payload<'static>, StrHideError> {
    let engine = engine_for_carrier(carrier_bytes)?;
    engine.extract(carrier_bytes, options, dialect)
}

/// Automatically sniff the carrier format and inspect steganographic headers.
pub fn inspect_carrier(
    carrier_bytes: &[u8],
    options: &InspectOptions<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    inspect_carrier_with_dialect(carrier_bytes, options, &StegoProfile::default())
}

/// [`inspect_carrier`] with an explicit [`StegoProfile`].
pub fn inspect_carrier_with_dialect(
    carrier_bytes: &[u8],
    options: &InspectOptions<'_>,
    dialect: &StegoProfile,
) -> Result<StegoHeaderInfo, StrHideError> {
    let engine = engine_for_carrier(carrier_bytes)?;
    engine.inspect(carrier_bytes, options, dialect)
}

/// Automatically sniff the carrier format and run multi-tier verification.
pub fn verify_carrier(
    carrier_bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    verify_carrier_with_dialect(carrier_bytes, options, &StegoProfile::default())
}

/// [`verify_carrier`] with an explicit [`StegoProfile`].
pub fn verify_carrier_with_dialect(
    carrier_bytes: &[u8],
    options: &VerifyOptions<'_>,
    dialect: &StegoProfile,
) -> Result<StegoVerifyResult, StrHideError> {
    let engine = engine_for_carrier(carrier_bytes)?;
    engine.verify(carrier_bytes, options, dialect)
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
    /// What `recommended_max_bytes` would be at every tier, indexed by
    /// [`crate::params::SafetyLevel::tier_index`] (paranoid, high, balanced).
    ///
    /// The budget formulas live in each engine and are *not* interchangeable —
    /// video carriers spend a drift ladder per reference picture, the spatial
    /// codec bounds itself by the single-channel pool, and JPEG pays
    /// `BODY_OVERHEAD` on a grouped grid. A host that needs all three tiers at
    /// once (the Tauri capacity card) must read them from here instead of
    /// re-deriving them; the copy it used to keep drifted into comparing
    /// `info.format` against `"hevc"`, a string no engine ever produces.
    #[serde(default)]
    pub tier_limits: [usize; 3],
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
    /// Carrier resolution (plus frame rate/duration/bitrate for video), when
    /// the container could be parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_info: Option<crate::core::media::MediaInfo>,
}

impl StegoCapacityInfo {
    /// Recommended payload ceiling at `level`, from the engine-computed tier table.
    pub fn tier_limit(&self, level: crate::params::SafetyLevel) -> usize {
        self.tier_limits[level.tier_index()]
    }

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

/// Automatically sniff the carrier format and probe embedding capacity.
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
/// Use [`probe_carrier_capacity_with_dialect`] when a private
/// [`StegoProfile`] supplies the no-password secret.
pub fn probe_carrier_capacity(
    carrier_bytes: &[u8],
    options: &ProbeOptions<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    probe_carrier_capacity_with_dialect(carrier_bytes, options, &StegoProfile::default())
}

/// [`probe_carrier_capacity`] with an explicit private-dialect [`StegoProfile`].
pub fn probe_carrier_capacity_with_dialect(
    carrier_bytes: &[u8],
    options: &ProbeOptions<'_>,
    dialect: &StegoProfile,
) -> Result<StegoCapacityInfo, StrHideError> {
    let engine = engine_for_carrier(carrier_bytes)?;
    // Same resolution as embed: an explicit password wins, the profile's stego
    // secret is the fallback, `None` means the public constant downstream.
    engine.probe(carrier_bytes, options, dialect)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_default_threads() {
        assert_eq!(compute_default_threads(0), 1);
        assert_eq!(compute_default_threads(1), 1);
        assert_eq!(compute_default_threads(2), 2);
        assert_eq!(compute_default_threads(3), 3);
        assert_eq!(compute_default_threads(4), 4);
        assert_eq!(compute_default_threads(6), 4);
        assert_eq!(compute_default_threads(8), 4);
        assert_eq!(compute_default_threads(12), 6);
        assert_eq!(compute_default_threads(16), 8);
        assert_eq!(compute_default_threads(32), 16);
        assert_eq!(compute_default_threads(64), 32);
    }

    #[test]
    fn test_default_thread_pool_init_idempotent() {
        init_default_thread_pool();
        init_default_thread_pool();
        let threads = default_thread_count();
        assert!(threads >= 1);
    }
}
