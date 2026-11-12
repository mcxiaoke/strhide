//! The content-domain engine trait and its registry.
//!
//! Before this module, `stego::mod.rs` held three parallel `if format ==
//! Some(FileFormat::X)` waterfalls -- one for embed, one for extract, one for
//! probe. Every new format had to be added in three places, and the HEIF
//! fallback order (Scheme C first, thumbnail bridge second) was re-derived in
//! each of them. A probe that advertised the bridge's capacity while the writer
//! filled the CABAC stream was one forgotten `else` away.
//!
//! Now there is one engine per carrier format, one registry entry per engine,
//! and the fallback order lives inside [`HeifEngine`] only.
//!
//! # Why `formats()` and five engines rather than three
//!
//! The HEVC Scheme C engine serves three carriers (HEIF still image, MP4/MOV
//! video, raw Annex-B stream) whose *handling* differs: only HEIF may fall back
//! to the thumbnail bridge, and MP4/Annex-B have no bridge at all. Registering
//! three thin engines that share one implementation keeps `format()` honest and
//! removes any need to re-sniff the carrier inside the engine -- the registry
//! already knows which format it matched.

use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::formats::FileFormat;
use crate::stego::StegoCapacityInfo;
use crate::stego::options::{
    EmbedOptions, EmbedOutput, ExtractOptions, InspectOptions, ProbeOptions, StegoHeaderInfo,
    StegoVerifyResult, VerifyOptions,
};
use crate::stego::params::StegoProfile;

/// One content-domain embedding engine.
///
/// Implementations are stateless: every knob arrives in the options, every
/// secret in the dialect. That is what lets the registry hand out `&'static`
/// instances and lets two calls run concurrently on the same engine.
pub(crate) trait StegoEngine: Send + Sync {
    /// The carrier format this engine handles.
    fn format(&self) -> FileFormat;

    /// Report the carrier's embedding capacity under `opts`.
    fn probe(
        &self,
        carrier: &[u8],
        opts: &ProbeOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoCapacityInfo, StrHideError>;

    /// Embed `payload` into `carrier`.
    fn embed(
        &self,
        carrier: &[u8],
        payload: &Payload<'_>,
        opts: &EmbedOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<EmbedOutput, StrHideError>;

    /// Extract the payload from `carrier`.
    fn extract(
        &self,
        carrier: &[u8],
        opts: &ExtractOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<Payload<'static>, StrHideError>;

    /// Fast inspect carrier header for stego metadata without full decoding.
    fn inspect(
        &self,
        carrier: &[u8],
        opts: &InspectOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoHeaderInfo, StrHideError>;

    /// Multi-tier verification of carrier syntax and embedded stego payload.
    fn verify(
        &self,
        carrier: &[u8],
        opts: &VerifyOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoVerifyResult, StrHideError>;
}

/// Registry, in lookup order. `HeifEngine` before `Mp4Engine` is not a
/// preference: their format sets are disjoint, so order is irrelevant, but
/// keeping the image container first matches how the sniffer presents them.
static ENGINES: &[&dyn StegoEngine] = &[
    #[cfg(feature = "content-png")]
    &PngEngine,
    #[cfg(feature = "content-jpeg")]
    &JpegEngine,
    #[cfg(feature = "content-hevc")]
    &HeifEngine,
    #[cfg(feature = "content-hevc")]
    &Mp4Engine,
    #[cfg(feature = "content-hevc")]
    &AnnexBEngine,
    #[cfg(feature = "content-hevc")]
    &MkvEngine,
    #[cfg(feature = "content-audio")]
    &WavEngine,
    #[cfg(feature = "content-audio")]
    &FlacEngine,
];

/// The engine that handles `format`, or `None` when the content domain cannot
/// read it at all.
pub(crate) fn engine_for(format: FileFormat) -> Option<&'static dyn StegoEngine> {
    ENGINES.iter().copied().find(|e| e.format() == format)
}

/// The carrier formats this build accepts, spelled for a human.
///
/// Derived from [`ENGINES`] rather than hard-coded so an "unsupported carrier"
/// message never claims a format the current feature set does not compile in,
/// and never omits one it does.
pub(crate) fn supported_carrier_list() -> String {
    let labels: Vec<&str> = ENGINES
        .iter()
        .map(|engine| match engine.format() {
            FileFormat::Png => "PNG",
            FileFormat::Jpeg => "JPEG",
            FileFormat::Heif => "HEIF/HEIC",
            FileFormat::Mp4 => "MP4/MOV",
            FileFormat::HevcAnnexB => "raw Annex-B HEVC",
            FileFormat::Mkv => "MKV/WebM",
            FileFormat::Wav => "WAV",
            FileFormat::Flac => "FLAC",
            other => other.as_str(),
        })
        .collect();
    match labels.split_last() {
        None => "no carrier format (this build has no content engine)".to_string(),
        Some((last, [])) => (*last).to_string(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
    }
}

/// Every carrier format the content domain supports, in registry order.
///
/// `stego::mod` and the capability table both derive from this; a test asserts
/// the two agree, so a format cannot be claimed by one and forgotten by the
/// other.
#[allow(dead_code)]
pub(crate) fn supported_formats() -> impl Iterator<Item = FileFormat> {
    ENGINES.iter().map(|e| e.format())
}

/// Run `f` on the caller's rayon pool when one was supplied.
///
/// Every parallel section in the engines (`par_chunks` in the cost models, the
/// PNG deflate fan-out) inherits the pool of the thread that drives it, so
/// wrapping the whole call is enough. A GUI that wants to keep a core for its
/// UI therefore does not need a second API: it builds a `ThreadPool` and passes
/// it in `EmbedOptions::pool`.
pub(super) fn with_pool<T>(
    pool: Option<&std::sync::Arc<rayon::ThreadPool>>,
    f: impl FnOnce() -> T + Send,
) -> T
where
    T: Send,
{
    match pool {
        Some(pool) => pool.install(f),
        None => f(),
    }
}

#[cfg(feature = "content-audio")]
mod audio;
#[cfg(feature = "content-hevc")]
mod hevc;
#[cfg(any(feature = "content-png", feature = "content-jpeg"))]
mod image;

#[cfg(feature = "content-audio")]
pub(crate) use audio::{FlacEngine, WavEngine};
#[cfg(feature = "content-hevc")]
pub(crate) use hevc::{AnnexBEngine, HeifEngine, MkvEngine, Mp4Engine};
#[cfg(feature = "content-jpeg")]
pub(crate) use image::JpegEngine;
#[cfg(feature = "content-png")]
pub(crate) use image::PngEngine;

#[cfg(all(test, feature = "content-hevc"))]
pub(super) use hevc::should_try_bridge;

#[cfg(test)]
mod tests;
