//! Audio content engines (FLAC and WAV).

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

/// FLAC: residual-domain coding that keeps every Rice codeword the same width.
#[cfg(feature = "content-audio")]
pub(crate) struct FlacEngine;

#[cfg(feature = "content-audio")]
impl StegoEngine for FlacEngine {
    fn format(&self) -> FileFormat {
        FileFormat::Flac
    }

    fn probe(
        &self,
        carrier: &[u8],
        opts: &ProbeOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoCapacityInfo, StrHideError> {
        opts.tuning.applicable_to(self.format())?;
        let cred = crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?;
        let domain = opts.domain(dialect);
        opts.control.check()?;
        with_pool(opts.pool.as_ref(), || {
            crate::stego::audio::probe_flac(
                carrier,
                cred,
                domain,
                &opts.extensions,
                opts.safety.level,
                dialect.flac_format(),
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
        let cred = crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?;
        let domain = opts.domain(dialect);
        // FLAC reads its own profile: `audio_format()` is the WAV profile, and
        // a caller that customises only `with_flac_format` would otherwise get
        // WAV's default suite here while `dialect.flac_format()` still drives
        // every other FLAC parameter below.
        let suite_id = opts
            .suite_id
            .unwrap_or_else(|| dialect.flac_format().cipher.default_suite.as_u16());
        opts.control.check()?;
        let anon_payload;
        let eff_payload = if opts.no_filename && payload.name().is_some() {
            anon_payload = Payload::bytes(payload.as_bytes());
            &anon_payload
        } else {
            payload
        };
        let (bytes, capacity, stats) = with_pool(opts.pool.as_ref(), || {
            crate::stego::audio::embed_flac(
                carrier,
                eff_payload,
                cred,
                domain,
                suite_id,
                &opts.extensions,
                dialect.flac_format(),
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
        with_pool(opts.pool.as_ref(), || {
            crate::stego::audio::extract_flac(
                carrier,
                cred,
                domain,
                dialect.flac_format(),
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
        crate::stego::audio::inspect_flac(
            carrier,
            cred,
            domain,
            dialect.flac_format(),
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
        crate::stego::audio::verify_flac(
            carrier,
            cred,
            domain,
            dialect.flac_format(),
            &opts.limits,
            &opts.control,
        )
    }
}

/// WAV PCM: `±1` LSB moves on the sample stream, in place.
#[cfg(feature = "content-audio")]
pub(crate) struct WavEngine;

#[cfg(feature = "content-audio")]
impl StegoEngine for WavEngine {
    fn format(&self) -> FileFormat {
        FileFormat::Wav
    }

    fn probe(
        &self,
        carrier: &[u8],
        opts: &ProbeOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoCapacityInfo, StrHideError> {
        opts.tuning.applicable_to(self.format())?;
        let cred = crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?;
        let domain = opts.domain(dialect);
        opts.control.check()?;
        with_pool(opts.pool.as_ref(), || {
            crate::stego::audio::probe_wav(
                carrier,
                cred,
                domain,
                &opts.extensions,
                opts.safety.level,
                dialect.audio_format(),
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
        let cred = crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?;
        let domain = opts.domain(dialect);
        let suite_id = opts
            .suite_id
            .unwrap_or_else(|| dialect.audio_format().cipher.default_suite.as_u16());
        opts.control.check()?;
        let anon_payload;
        let eff_payload = if opts.no_filename && payload.name().is_some() {
            anon_payload = Payload::bytes(payload.as_bytes());
            &anon_payload
        } else {
            payload
        };
        let (bytes, capacity, stats) = with_pool(opts.pool.as_ref(), || {
            crate::stego::audio::embed_wav(
                carrier,
                eff_payload,
                cred,
                domain,
                suite_id,
                &opts.extensions,
                dialect.audio_format(),
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
        with_pool(opts.pool.as_ref(), || {
            crate::stego::audio::extract_wav(
                carrier,
                cred,
                domain,
                dialect.audio_format(),
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
        crate::stego::audio::inspect_wav(
            carrier,
            cred,
            domain,
            dialect.audio_format(),
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
        crate::stego::audio::verify_wav(
            carrier,
            cred,
            domain,
            dialect.audio_format(),
            &opts.limits,
            &opts.control,
        )
    }
}
