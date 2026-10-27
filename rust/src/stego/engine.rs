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
use crate::params::StegoProfile;
use crate::stego::StegoCapacityInfo;
use crate::stego::heif::thumb_bridge;
use crate::stego::options::{EmbedOptions, EmbedOutput, ExtractOptions, HevcMode, ProbeOptions};

/// One content-domain embedding engine.
///
/// Implementations are stateless: every knob arrives in the options, every
/// secret in the dialect. That is what lets the registry hand out `&'static`
/// instances and lets two calls run concurrently on the same engine.
pub trait StegoEngine: Send + Sync {
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
}

/// Registry, in lookup order. `HeifEngine` before `Mp4Engine` is not a
/// preference: their format sets are disjoint, so order is irrelevant, but
/// keeping the image container first matches how the sniffer presents them.
static ENGINES: [&dyn StegoEngine; 5] = [
    &PngEngine,
    &JpegEngine,
    &HeifEngine,
    &Mp4Engine,
    &AnnexBEngine,
];

/// The engine that handles `format`, or `None` when the content domain cannot
/// read it at all.
pub fn engine_for(format: FileFormat) -> Option<&'static dyn StegoEngine> {
    ENGINES.iter().copied().find(|e| e.format() == format)
}

/// Every carrier format the content domain supports, in registry order.
///
/// `stego::mod` and the capability table both derive from this; a test asserts
/// the two agree, so a format cannot be claimed by one and forgotten by the
/// other.
pub fn supported_formats() -> impl Iterator<Item = FileFormat> {
    ENGINES.iter().map(|e| e.format())
}

/// Run `f` on the caller's rayon pool when one was supplied.
///
/// Every parallel section in the engines (`par_chunks` in the cost models, the
/// PNG deflate fan-out) inherits the pool of the thread that drives it, so
/// wrapping the whole call is enough. A GUI that wants to keep a core for its
/// UI therefore does not need a second API: it builds a `ThreadPool` and passes
/// it in `EmbedOptions::pool`.
fn with_pool<T>(pool: Option<&std::sync::Arc<rayon::ThreadPool>>, f: impl FnOnce() -> T + Send) -> T
where
    T: Send,
{
    match pool {
        Some(pool) => pool.install(f),
        None => f(),
    }
}

/// PNG spatial-domain engine (HILL / S-UNIWARD, STC or Hamming).
pub struct PngEngine;

impl StegoEngine for PngEngine {
    fn format(&self) -> FileFormat {
        FileFormat::Png
    }

    fn probe(
        &self,
        carrier: &[u8],
        opts: &ProbeOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoCapacityInfo, StrHideError> {
        opts.tuning.applicable_to(self.format())?;
        let resolved = opts.tuning.resolve();
        let secret = opts.secret(dialect);
        let domain = opts.domain(dialect);
        opts.control.check()?;
        with_pool(opts.pool.as_ref(), || {
            crate::stego::png::probe_png_capacity(
                carrier,
                &*resolved.png_model,
                &resolved.png_params,
                opts.safety.level,
                secret,
                domain,
                dialect.png_format(),
                &opts.control,
            )
        })
    }

    fn embed(
        &self,
        carrier: &[u8],
        payload: &Payload<'_>,
        opts: &EmbedOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<EmbedOutput, StrHideError> {
        opts.tuning.applicable_to(self.format())?;
        let resolved = opts.tuning.resolve();
        let secret = opts.secret(dialect);
        let domain = opts.domain(dialect);
        opts.control.check()?;
        let bytes = with_pool(opts.pool.as_ref(), || {
            crate::stego::png::embed_png(
                carrier,
                payload.as_bytes(),
                secret,
                domain,
                dialect.png_format(),
                &*resolved.png_model,
                &resolved.png_params,
                opts.safety,
                opts.freshness,
                &opts.control,
            )
        })?;
        Ok(EmbedOutput::bytes_only(bytes))
    }

    fn extract(
        &self,
        carrier: &[u8],
        opts: &ExtractOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<Payload<'static>, StrHideError> {
        let secret = opts.secret(dialect);
        let domain = opts.domain(dialect);
        opts.control.check()?;
        // The carrier names its cost model in the feature word and describes
        // every hyperparameter that shapes the cost map, so the extractor runs
        // the default model and default params; see `stego::options` module
        // docs and `extract_png`.
        let model = crate::stego::options::SpatialAlgorithm::default().model();
        let params = crate::stego::params::PngParams::default();
        let bytes = with_pool(opts.pool.as_ref(), || {
            crate::stego::png::extract_png(
                carrier,
                secret,
                domain,
                dialect.png_format(),
                &*model,
                &params,
                &opts.control,
            )
        })?;
        Ok(Payload::owned(bytes))
    }
}

/// JPEG DCT-domain engine (UERD / J-UNIWARD, ternary STC).
pub struct JpegEngine;

impl StegoEngine for JpegEngine {
    fn format(&self) -> FileFormat {
        FileFormat::Jpeg
    }

    fn probe(
        &self,
        carrier: &[u8],
        opts: &ProbeOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoCapacityInfo, StrHideError> {
        opts.tuning.applicable_to(self.format())?;
        let resolved = opts.tuning.resolve();
        opts.control.check()?;
        with_pool(opts.pool.as_ref(), || {
            crate::stego::jpeg::probe_jpeg_capacity(
                carrier,
                &*resolved.jpeg_model,
                &resolved.jpeg_params,
                opts.safety.level,
                dialect.jpeg_format(),
                &opts.control,
            )
        })
    }

    fn embed(
        &self,
        carrier: &[u8],
        payload: &Payload<'_>,
        opts: &EmbedOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<EmbedOutput, StrHideError> {
        opts.tuning.applicable_to(self.format())?;
        let resolved = opts.tuning.resolve();
        let secret = opts.secret(dialect);
        let domain = opts.domain(dialect);
        let mut jpeg_params = resolved.jpeg_params.clone();
        // A seeded run must not take the FMA path: it rounds differently from
        // the scalar one, and a last-bit disagreement in a cost value can move
        // the trellis to a different slot.
        jpeg_params.deterministic = opts.freshness.is_seeded();
        opts.control.check()?;
        let bytes = with_pool(opts.pool.as_ref(), || {
            crate::stego::jpeg::embed_jpeg(
                carrier,
                payload.as_bytes(),
                secret,
                domain,
                dialect.jpeg_format(),
                &jpeg_params,
                opts.safety,
                &*resolved.jpeg_model,
                opts.freshness,
                &opts.control,
            )
        })?;
        Ok(EmbedOutput::bytes_only(bytes))
    }

    fn extract(
        &self,
        carrier: &[u8],
        opts: &ExtractOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<Payload<'static>, StrHideError> {
        let secret = opts.secret(dialect);
        let domain = opts.domain(dialect);
        opts.control.check()?;
        // No cost model on purpose: the V3 slot set is geometric, so extraction
        // must not depend on the embedder's cost function.
        let bytes = with_pool(opts.pool.as_ref(), || {
            crate::stego::jpeg::extract_jpeg(
                carrier,
                secret,
                domain,
                dialect.jpeg_format(),
                &opts.limits,
                &opts.control,
            )
        })?;
        Ok(Payload::owned(bytes))
    }
}

/// Shared Scheme C implementation behind the three HEVC carriers.
fn hevc_embed(
    format: FileFormat,
    carrier: &[u8],
    payload: &Payload<'_>,
    opts: &EmbedOptions<'_>,
    dialect: &StegoProfile,
) -> Result<EmbedOutput, StrHideError> {
    let resolved = opts.tuning.resolve();
    let secret = opts.secret(dialect);
    let domain = opts.domain(dialect);
    opts.control.check()?;

    let direct = || {
        crate::stego::hevc::embed_hevc_with_info(
            carrier,
            payload.as_bytes(),
            secret,
            domain,
            dialect.hevc_format(),
            opts.freshness,
            opts.safety,
            &opts.control,
        )
    };

    if format != FileFormat::Heif {
        // MP4/MOV video and raw Annex-B: Scheme C is the only path.
        let (bytes, info) = with_pool(opts.pool.as_ref(), direct)?;
        return Ok(EmbedOutput {
            bytes,
            capacity: Some(info),
        });
    }

    let first = with_pool(opts.pool.as_ref(), direct);
    match first {
        Ok((bytes, info)) => Ok(EmbedOutput {
            bytes,
            capacity: Some(info),
        }),
        // A safety-policy refusal is final: retrying through the thumbnail
        // bridge would replace it with the bridge's own "no bridgeable item"
        // error and hide the real reason.
        Err(e @ StrHideError::SafetyThreshold(_)) => Err(e),
        Err(e) if resolved.hevc_mode == HevcMode::Cabac => Err(e),
        Err(_) => {
            let bridge = thumb_bridge::embed_heif_bridge(
                carrier,
                payload.as_bytes(),
                &crate::stego::options::BridgeOptions {
                    dialect,
                    password: opts.password,
                    domain: opts.domain,
                    tuning: opts.tuning.clone(),
                    safety: opts.safety,
                    freshness: opts.freshness,
                },
                &opts.control,
            )?;
            Ok(EmbedOutput::bytes_only(bridge))
        }
    }
}

fn hevc_extract(
    format: FileFormat,
    carrier: &[u8],
    opts: &ExtractOptions<'_>,
    dialect: &StegoProfile,
) -> Result<Payload<'static>, StrHideError> {
    let secret = opts.secret(dialect);
    let domain = opts.domain(dialect);
    opts.control.check()?;

    let direct = || {
        crate::stego::hevc::extract_hevc(
            carrier,
            secret,
            domain,
            dialect.hevc_format(),
            &opts.control,
        )
    };

    if format != FileFormat::Heif {
        return Ok(Payload::owned(with_pool(opts.pool.as_ref(), direct)?));
    }

    match with_pool(opts.pool.as_ref(), direct) {
        Ok(bytes) => Ok(Payload::owned(bytes)),
        Err(e) => {
            match thumb_bridge::extract_heif_bridge(
                carrier,
                &crate::stego::options::BridgeOptions::new(dialect)
                    .with_password(opts.password.unwrap_or_default())
                    .with_domain(opts.domain.unwrap_or_default()),
                &opts.limits,
                &opts.control,
            ) {
                Ok(payload) => Ok(Payload::owned(payload)),
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
}

fn hevc_probe(
    format: FileFormat,
    carrier: &[u8],
    opts: &ProbeOptions<'_>,
    dialect: &StegoProfile,
) -> Result<StegoCapacityInfo, StrHideError> {
    let resolved = opts.tuning.resolve();
    opts.control.check()?;

    let direct = || {
        crate::stego::hevc::probe_hevc_capacity_info(
            carrier,
            dialect.hevc_format(),
            opts.safety.level,
            opts.exact,
            &opts.control,
        )
    };

    if format != FileFormat::Heif {
        return with_pool(opts.pool.as_ref(), direct);
    }

    match with_pool(opts.pool.as_ref(), direct) {
        Ok(info) => Ok(info),
        Err(e) if resolved.hevc_mode == HevcMode::Cabac => Err(e),
        // Same order as embed and extract: a probe that advertises the
        // bridge's capacity while the writer fills the CABAC stream (or the
        // other way round) is worse than useless.
        Err(_) => thumb_bridge::probe_heif_bridge_capacity(
            carrier,
            &crate::stego::options::BridgeOptions {
                dialect,
                password: opts.password,
                domain: opts.domain,
                tuning: opts.tuning.clone(),
                safety: opts.safety,
                freshness: crate::stego::envelope::Freshness::Random,
            },
            &opts.control,
        ),
    }
}

/// HEIF/HEIC still image: Scheme C, with the thumbnail bridge as fallback.
pub struct HeifEngine;

impl StegoEngine for HeifEngine {
    fn format(&self) -> FileFormat {
        FileFormat::Heif
    }

    fn probe(
        &self,
        carrier: &[u8],
        opts: &ProbeOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoCapacityInfo, StrHideError> {
        // A PNG or JPEG tuning is legitimate here: the bridge may write through
        // a PNG auxiliary item or a JPEG thumbnail, and the tuning names which
        // cost model that half should use.
        hevc_probe(self.format(), carrier, opts, dialect)
    }

    fn embed(
        &self,
        carrier: &[u8],
        payload: &Payload<'_>,
        opts: &EmbedOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<EmbedOutput, StrHideError> {
        hevc_embed(self.format(), carrier, payload, opts, dialect)
    }

    fn extract(
        &self,
        carrier: &[u8],
        opts: &ExtractOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<Payload<'static>, StrHideError> {
        hevc_extract(self.format(), carrier, opts, dialect)
    }
}

/// MP4/MOV video: Scheme C on the sample table, no bridge.
pub struct Mp4Engine;

impl StegoEngine for Mp4Engine {
    fn format(&self) -> FileFormat {
        FileFormat::Mp4
    }

    fn probe(
        &self,
        carrier: &[u8],
        opts: &ProbeOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoCapacityInfo, StrHideError> {
        opts.tuning.applicable_to(self.format())?;
        hevc_probe(self.format(), carrier, opts, dialect)
    }

    fn embed(
        &self,
        carrier: &[u8],
        payload: &Payload<'_>,
        opts: &EmbedOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<EmbedOutput, StrHideError> {
        opts.tuning.applicable_to(self.format())?;
        hevc_embed(self.format(), carrier, payload, opts, dialect)
    }

    fn extract(
        &self,
        carrier: &[u8],
        opts: &ExtractOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<Payload<'static>, StrHideError> {
        hevc_extract(self.format(), carrier, opts, dialect)
    }
}

/// Raw Annex-B HEVC bitstream: Scheme C only.
pub struct AnnexBEngine;

impl StegoEngine for AnnexBEngine {
    fn format(&self) -> FileFormat {
        FileFormat::HevcAnnexB
    }

    fn probe(
        &self,
        carrier: &[u8],
        opts: &ProbeOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoCapacityInfo, StrHideError> {
        opts.tuning.applicable_to(self.format())?;
        hevc_probe(self.format(), carrier, opts, dialect)
    }

    fn embed(
        &self,
        carrier: &[u8],
        payload: &Payload<'_>,
        opts: &EmbedOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<EmbedOutput, StrHideError> {
        opts.tuning.applicable_to(self.format())?;
        hevc_embed(self.format(), carrier, payload, opts, dialect)
    }

    fn extract(
        &self,
        carrier: &[u8],
        opts: &ExtractOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<Payload<'static>, StrHideError> {
        hevc_extract(self.format(), carrier, opts, dialect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::capability::CAPABILITIES;

    #[test]
    fn every_content_capable_format_has_an_engine() {
        for cap in CAPABILITIES {
            if cap.stego.is_empty() {
                continue;
            }
            assert!(
                engine_for(cap.format).is_some(),
                "{} is advertised as a content carrier with no engine",
                cap.format.as_str()
            );
        }
    }

    #[test]
    fn no_engine_claims_a_format_the_capability_table_rejects() {
        for engine in ENGINES {
            let format = engine.format();
            let cap = CAPABILITIES
                .iter()
                .find(|c| c.format == format)
                .unwrap_or_else(|| panic!("{} has no capability row", format.as_str()));
            assert!(
                !cap.stego.is_empty(),
                "{} has an engine but the capability table says no",
                format.as_str()
            );
        }
    }

    #[test]
    fn the_registry_has_no_duplicate_formats() {
        let mut seen = std::collections::HashSet::new();
        for format in supported_formats() {
            assert!(seen.insert(format), "{:?} is registered twice", format);
        }
        assert_eq!(seen.len(), ENGINES.len());
    }

    #[test]
    fn container_formats_without_a_content_engine_have_none() {
        for format in [
            FileFormat::Zip,
            FileFormat::Pdf,
            FileFormat::Pe,
            FileFormat::Webp,
            FileFormat::Wav,
            FileFormat::Mkv,
        ] {
            assert!(
                engine_for(format).is_none(),
                "{} must not have a content engine",
                format.as_str()
            );
        }
    }
}
