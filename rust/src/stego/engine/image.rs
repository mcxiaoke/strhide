//! Image content engines (PNG and JPEG).

use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::formats::FileFormat;
use crate::stego::StegoCapacityInfo;
use crate::stego::options::{
    EmbedOptions, EmbedOutput, ExtractOptions, InspectOptions, ProbeOptions, StegoHeaderInfo,
    StegoVerifyResult, VerifyOptions,
};
use crate::stego::params::StegoProfile;

use super::{StegoEngine, with_pool};

pub(crate) struct PngEngine;

#[cfg(feature = "content-png")]
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
        let cred = crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?;
        let domain = opts.domain(dialect);
        opts.control.check()?;
        with_pool(opts.pool.as_ref(), || {
            crate::stego::png::probe_png_capacity(
                carrier,
                &*resolved.png_model,
                &resolved.png_params,
                opts.safety.level,
                cred,
                domain,
                &opts.extensions,
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
        let cred = crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?;
        let domain = opts.domain(dialect);
        let suite_id = opts
            .suite_id
            .unwrap_or_else(|| dialect.png_format().cipher.default_suite.as_u16());
        opts.control.check()?;
        let anon_payload;
        let eff_payload = if opts.no_filename && payload.name().is_some() {
            anon_payload = Payload::bytes(payload.as_bytes());
            &anon_payload
        } else {
            payload
        };
        let (bytes, stats, capacity) = with_pool(opts.pool.as_ref(), || {
            crate::stego::png::engine::embed_png_with_stats(
                carrier,
                eff_payload,
                cred,
                domain,
                suite_id,
                &opts.extensions,
                dialect.png_format(),
                &*resolved.png_model,
                &resolved.png_params,
                opts.safety,
                opts.freshness,
                &opts.control,
            )
        })?;
        Ok(EmbedOutput::with_capacity_and_stats(bytes, capacity, stats))
    }

    fn extract(
        &self,
        carrier: &[u8],
        opts: &ExtractOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<Payload<'static>, StrHideError> {
        let cred = crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?;
        let domain = opts.domain(dialect);
        opts.control.check()?;
        // The carrier names its cost model in the header and describes every
        // hyperparameter that shapes the cost map, so the extractor runs the
        // default model and default params; see `stego::options` module docs.
        let model = crate::stego::options::SpatialAlgorithm::default().model();
        let params = crate::stego::params::PngParams::default();
        with_pool(opts.pool.as_ref(), || {
            crate::stego::png::extract_png(
                carrier,
                cred,
                domain,
                dialect.png_format(),
                &*model,
                &params,
                &opts.limits,
                &opts.control,
            )
        })
    }

    fn inspect(
        &self,
        carrier: &[u8],
        opts: &InspectOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoHeaderInfo, StrHideError> {
        let cred = crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?;
        let domain = opts.domain(dialect);
        opts.control.check()?;
        crate::stego::png::engine::inspect_png(
            carrier,
            cred,
            domain,
            dialect.png_format(),
            &opts.limits,
            &opts.control,
        )
    }

    fn verify(
        &self,
        carrier: &[u8],
        opts: &VerifyOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoVerifyResult, StrHideError> {
        let cred = crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?;
        let domain = opts.domain(dialect);
        opts.control.check()?;
        crate::stego::png::engine::verify_png(
            carrier,
            cred,
            domain,
            dialect.png_format(),
            &opts.limits,
            &opts.control,
        )
    }
}

/// JPEG DCT-domain engine (UERD / J-UNIWARD, ternary STC).
#[cfg(feature = "content-jpeg")]
pub(crate) struct JpegEngine;

#[cfg(feature = "content-jpeg")]
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
                &opts.extensions,
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
        let cred = crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?;
        let domain = opts.domain(dialect);
        let suite_id = opts
            .suite_id
            .unwrap_or_else(|| dialect.jpeg_format().default_suite().as_u16());
        let mut jpeg_params = resolved.jpeg_params.clone();
        // A seeded run must not take the FMA path: it rounds differently from
        // the scalar one, and a last-bit disagreement in a cost value can move
        // the trellis to a different slot.
        jpeg_params.deterministic = opts.freshness.is_seeded();
        opts.control.check()?;
        let anon_payload;
        let eff_payload = if opts.no_filename && payload.name().is_some() {
            anon_payload = Payload::bytes(payload.as_bytes());
            &anon_payload
        } else {
            payload
        };
        let (bytes, stats, capacity) = with_pool(opts.pool.as_ref(), || {
            crate::stego::jpeg::engine::embed_jpeg_with_stats(
                carrier,
                eff_payload,
                cred,
                domain,
                suite_id,
                &opts.extensions,
                dialect.jpeg_format(),
                &jpeg_params,
                opts.safety,
                &*resolved.jpeg_model,
                opts.freshness,
                &opts.control,
            )
        })?;
        Ok(EmbedOutput::with_capacity_and_stats(bytes, capacity, stats))
    }

    fn extract(
        &self,
        carrier: &[u8],
        opts: &ExtractOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<Payload<'static>, StrHideError> {
        let cred = crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?;
        let domain = opts.domain(dialect);
        opts.control.check()?;
        // No cost model on purpose: the slot set is geometric, so extraction
        // must not depend on the embedder's cost function.
        with_pool(opts.pool.as_ref(), || {
            crate::stego::jpeg::extract_jpeg(
                carrier,
                cred,
                domain,
                dialect.jpeg_format(),
                &opts.limits,
                &opts.control,
            )
        })
    }

    fn inspect(
        &self,
        carrier: &[u8],
        opts: &InspectOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoHeaderInfo, StrHideError> {
        let cred = crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?;
        let domain = opts.domain(dialect);
        opts.control.check()?;
        crate::stego::jpeg::engine::inspect_jpeg(
            carrier,
            cred,
            domain,
            dialect.jpeg_format(),
            &opts.limits,
            &opts.control,
        )
    }

    fn verify(
        &self,
        carrier: &[u8],
        opts: &VerifyOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoVerifyResult, StrHideError> {
        let cred = crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?;
        let domain = opts.domain(dialect);
        opts.control.check()?;
        crate::stego::jpeg::engine::verify_jpeg(
            carrier,
            cred,
            domain,
            dialect.jpeg_format(),
            &opts.limits,
            &opts.control,
        )
    }
}
