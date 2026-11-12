//! HEVC content engines (HEIF, MP4, raw Annex-B, MKV).

use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::formats::FileFormat;
use crate::stego::StegoCapacityInfo;
#[cfg(feature = "content-heif-bridge")]
use crate::stego::heif::thumb_bridge;
use crate::stego::options::HevcMode;
use crate::stego::options::{
    EmbedOptions, EmbedOutput, ExtractOptions, InspectOptions, ProbeOptions, StegoHeaderInfo,
    StegoVerifyResult, VerifyOptions,
};
use crate::stego::params::StegoProfile;

use super::{StegoEngine, with_pool};

/// Whether a failed Scheme C attempt may be retried through the HEIF thumbnail
/// bridge.
///
/// The bridge is only a better answer when Scheme C says "this carrier is not
/// a Scheme C carrier". `Cancelled`, credential conflicts, `Io`, policy
/// refusals, version mismatches and container-parse failures describe
/// something the bridge cannot fix, and replacing them with the bridge's own
/// "no bridgeable item" verdict hid the real cause -- a cancelled operation
/// used to surface as "no hidden data", which is exactly the kind of lie that
/// costs the user an hour of retrying.
#[cfg(feature = "content-hevc")]
pub(crate) fn should_try_bridge(err: &StrHideError) -> bool {
    match err {
        // "Not a Scheme C carrier": the common case for a HEIF whose primary
        // item is a JPEG thumbnail.
        StrHideError::NoHiddenData(_) | StrHideError::UnsupportedFormat(_) => true,
        // The carrier *is* Scheme C but has no encodable CABAC bypass run left.
        // The bridge is the documented fallback for exactly this shape.
        StrHideError::TrellisInfeasible { .. } => true,
        _ => false,
    }
}

/// Shared Scheme C implementation behind the three HEVC carriers.
#[cfg(feature = "content-hevc")]
fn hevc_embed(
    format: FileFormat,
    carrier: &[u8],
    payload: &Payload<'_>,
    opts: &EmbedOptions<'_>,
    dialect: &StegoProfile,
) -> Result<EmbedOutput, StrHideError> {
    let resolved = opts.tuning.resolve();
    let domain = opts.domain(dialect);
    let cred = crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?;
    opts.control.check()?;

    let anon_payload;
    let eff_payload = if opts.no_filename && payload.name().is_some() {
        anon_payload = Payload::bytes(payload.as_bytes());
        &anon_payload
    } else {
        payload
    };

    let direct = || {
        crate::stego::hevc::embed_hevc_with_info_v4(
            carrier,
            eff_payload,
            cred,
            domain,
            opts.suite_id
                .unwrap_or_else(|| dialect.hevc_format().cipher.default_suite.as_u16()),
            &opts.extensions,
            dialect.hevc_format(),
            opts.freshness,
            opts.safety,
            &opts.control,
        )
    };

    if format != FileFormat::Heif {
        // MP4/MOV video and raw Annex-B: Scheme C is the only path.
        let (bytes, info, stats) = with_pool(opts.pool.as_ref(), direct)?;
        return Ok(EmbedOutput {
            bytes,
            capacity: Some(info),
            stats: Some(stats),
        });
    }

    let first = with_pool(opts.pool.as_ref(), direct);
    match first {
        Ok((bytes, info, stats)) => Ok(EmbedOutput {
            bytes,
            capacity: Some(info),
            stats: Some(stats),
        }),
        // Errors the bridge cannot fix keep their own diagnosis; this covers
        // the safety-policy refusal that used to be special-cased here. Errors
        // that do reach the bridge are replaced by the bridge's own outcome.
        Err(e) if !should_try_bridge(&e) => Err(e),
        Err(e) if resolved.hevc_mode == HevcMode::Cabac => Err(e),
        #[cfg(feature = "content-heif-bridge")]
        Err(direct_err) => {
            // The bridge's verdict replaces this one, but the reason the direct
            // path gave up is the only record of why the fallback was needed.
            log::debug!(
                target: "stego::hevc",
                "embed falling back to the HEIF thumbnail bridge after: {direct_err}"
            );
            let (bridge, stats, capacity) = thumb_bridge::embed_heif_bridge(
                carrier,
                payload,
                &crate::stego::options::BridgeOptions {
                    dialect,
                    password: opts.password,
                    key: opts.key,
                    domain: opts.domain,
                    suite_id: opts.suite_id,
                    extensions: opts.extensions.clone(),
                    tuning: opts.tuning.clone(),
                    safety: opts.safety,
                    freshness: opts.freshness,
                    no_filename: opts.no_filename,
                },
                &opts.control,
            )?;
            Ok(EmbedOutput::with_capacity_and_stats(
                bridge, capacity, stats,
            ))
        }
        #[cfg(not(feature = "content-heif-bridge"))]
        Err(e) => Err(e),
    }
}

#[cfg(feature = "content-hevc")]
fn hevc_extract(
    format: FileFormat,
    carrier: &[u8],
    opts: &ExtractOptions<'_>,
    dialect: &StegoProfile,
) -> Result<Payload<'static>, StrHideError> {
    let domain = opts.domain(dialect);
    let cred = crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?;
    opts.control.check()?;

    let direct = || {
        crate::stego::hevc::extract_hevc_v4(
            carrier,
            cred,
            domain,
            dialect.hevc_format(),
            &opts.limits,
            &opts.control,
        )
    };

    if format != FileFormat::Heif {
        return with_pool(opts.pool.as_ref(), direct);
    }

    match with_pool(opts.pool.as_ref(), direct) {
        Ok(payload) => Ok(payload),
        Err(e) if !should_try_bridge(&e) => Err(e),
        #[cfg(feature = "content-heif-bridge")]
        Err(direct_err) => {
            log::debug!(
                target: "stego::hevc",
                "extract falling back to the HEIF thumbnail bridge after: {direct_err}"
            );
            // The bridge reads the same V4 envelope, so it needs the same
            // credential, domain and extension area the writer used. Dropping
            // the file key here made every `FileKey` bridge carrier unreadable
            // even with the correct key.
            let mut bridge = crate::stego::options::BridgeOptions::new(dialect)
                .with_password(opts.password.unwrap_or_default())
                .with_domain(opts.domain.unwrap_or_default());
            if let Some(key) = opts.key {
                bridge = bridge.with_key(key);
            }
            match thumb_bridge::extract_heif_bridge(carrier, &bridge, &opts.limits, &opts.control) {
                Ok(payload) => Ok(payload),
                // Scheme C only got here because it decided this is not a
                // Scheme C carrier, so the bridge's verdict is the better one.
                Err(bridge_err) => Err(bridge_err),
            }
        }
        #[cfg(not(feature = "content-heif-bridge"))]
        Err(e) => Err(e),
    }
}

#[cfg(feature = "content-hevc")]
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
            &opts.extensions,
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
        Err(e) if !should_try_bridge(&e) => Err(e),
        Err(e) if resolved.hevc_mode == HevcMode::Cabac => Err(e),
        // Same order as embed and extract: a probe that advertises the
        // bridge's capacity while the writer fills the CABAC stream (or the
        // other way round) is worse than useless.
        #[cfg(feature = "content-heif-bridge")]
        Err(direct_err) => {
            log::debug!(
                target: "stego::hevc",
                "probe falling back to the HEIF thumbnail bridge after: {direct_err}"
            );
            thumb_bridge::probe_heif_bridge_capacity(
                carrier,
                &crate::stego::options::BridgeOptions {
                    dialect,
                    password: opts.password,
                    key: opts.key,
                    domain: opts.domain,
                    suite_id: None,
                    extensions: opts.extensions.clone(),
                    tuning: opts.tuning.clone(),
                    safety: opts.safety,
                    freshness: crate::stego::envelope::Freshness::Random,
                    no_filename: false,
                },
                &opts.control,
            )
        }
        #[cfg(not(feature = "content-heif-bridge"))]
        Err(e) => Err(e),
    }
}

#[cfg(feature = "content-hevc")]
fn hevc_inspect(
    format: FileFormat,
    carrier: &[u8],
    opts: &InspectOptions<'_>,
    dialect: &StegoProfile,
) -> Result<StegoHeaderInfo, StrHideError> {
    let domain = opts.domain(dialect);
    opts.control.check()?;

    let direct = || {
        crate::stego::hevc::inspect_hevc_v4(
            carrier,
            crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?,
            domain,
            dialect.hevc_format(),
            &opts.limits,
            &opts.control,
        )
    };

    if format != FileFormat::Heif {
        return direct();
    }

    let primary_info = direct()?;
    if primary_info.has_hidden_data {
        return Ok(primary_info);
    }

    #[cfg(feature = "content-heif-bridge")]
    {
        let bridge_info = thumb_bridge::inspect_heif_bridge(
            carrier,
            opts.password,
            opts.key,
            opts.domain,
            dialect,
            &opts.limits,
            &opts.control,
        )?;
        if bridge_info.has_hidden_data {
            return Ok(bridge_info);
        }
    }

    Ok(primary_info)
}

#[cfg(feature = "content-hevc")]
fn hevc_verify(
    format: FileFormat,
    carrier: &[u8],
    opts: &VerifyOptions<'_>,
    dialect: &StegoProfile,
) -> Result<StegoVerifyResult, StrHideError> {
    let domain = opts.domain(dialect);
    opts.control.check()?;

    let direct = || {
        crate::stego::hevc::verify_hevc_v4(
            carrier,
            crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?,
            domain,
            dialect.hevc_format(),
            &opts.limits,
            &opts.control,
        )
    };

    if format != FileFormat::Heif {
        return direct();
    }

    let primary_ver = direct()?;
    if primary_ver.is_all_ok() {
        return Ok(primary_ver);
    }

    #[cfg(feature = "content-heif-bridge")]
    {
        let bridge_ver = thumb_bridge::verify_heif_bridge(
            carrier,
            opts.password,
            opts.key,
            opts.domain,
            dialect,
            &opts.limits,
            &opts.control,
        )?;
        if bridge_ver.is_all_ok() {
            return Ok(bridge_ver);
        }
    }

    Ok(primary_ver)
}

/// HEIF/HEIC still image: Scheme C, with the thumbnail bridge as fallback.
#[cfg(feature = "content-hevc")]
pub(crate) struct HeifEngine;

#[cfg(feature = "content-hevc")]
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

    fn inspect(
        &self,
        carrier: &[u8],
        opts: &InspectOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoHeaderInfo, StrHideError> {
        hevc_inspect(self.format(), carrier, opts, dialect)
    }

    fn verify(
        &self,
        carrier: &[u8],
        opts: &VerifyOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoVerifyResult, StrHideError> {
        hevc_verify(self.format(), carrier, opts, dialect)
    }
}

/// MP4/MOV video: Scheme C on the sample table, no bridge.
#[cfg(feature = "content-hevc")]
pub(crate) struct Mp4Engine;

#[cfg(feature = "content-hevc")]
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

    fn inspect(
        &self,
        carrier: &[u8],
        opts: &InspectOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoHeaderInfo, StrHideError> {
        hevc_inspect(self.format(), carrier, opts, dialect)
    }

    fn verify(
        &self,
        carrier: &[u8],
        opts: &VerifyOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoVerifyResult, StrHideError> {
        hevc_verify(self.format(), carrier, opts, dialect)
    }
}

/// Raw Annex-B HEVC bitstream: Scheme C only.
#[cfg(feature = "content-hevc")]
pub(crate) struct AnnexBEngine;

#[cfg(feature = "content-hevc")]
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

    fn inspect(
        &self,
        carrier: &[u8],
        opts: &InspectOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoHeaderInfo, StrHideError> {
        hevc_inspect(self.format(), carrier, opts, dialect)
    }

    fn verify(
        &self,
        carrier: &[u8],
        opts: &VerifyOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoVerifyResult, StrHideError> {
        hevc_verify(self.format(), carrier, opts, dialect)
    }
}

/// Matroska (MKV/WebM) video: Scheme C on the HEVC track, plus a checksum
/// refresh for the `CRC-32` elements the patch invalidates.
#[cfg(feature = "content-hevc")]
pub(crate) struct MkvEngine;

#[cfg(feature = "content-hevc")]
impl StegoEngine for MkvEngine {
    fn format(&self) -> FileFormat {
        FileFormat::Mkv
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
        let resolved = opts.tuning.resolve();
        let domain = opts.domain(dialect);
        opts.control.check()?;

        let anon_payload;
        let eff_payload = if opts.no_filename && payload.name().is_some() {
            anon_payload = Payload::bytes(payload.as_bytes());
            &anon_payload
        } else {
            payload
        };

        let (bytes, info, stats) = with_pool(opts.pool.as_ref(), || {
            crate::stego::hevc::embed_hevc_with_info_v4(
                carrier,
                eff_payload,
                crate::stego::options::resolve_credential(opts.password, opts.key, dialect)?,
                domain,
                opts.suite_id
                    .unwrap_or_else(|| dialect.hevc_format().cipher.default_suite.as_u16()),
                &opts.extensions,
                dialect.hevc_format(),
                opts.freshness,
                opts.safety,
                &opts.control,
            )
        })?;
        let _ = resolved;

        Ok(EmbedOutput {
            bytes,
            capacity: Some(info),
            stats: Some(stats),
        })
    }

    fn extract(
        &self,
        carrier: &[u8],
        opts: &ExtractOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<Payload<'static>, StrHideError> {
        hevc_extract(self.format(), carrier, opts, dialect)
    }

    fn inspect(
        &self,
        carrier: &[u8],
        opts: &InspectOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoHeaderInfo, StrHideError> {
        hevc_inspect(self.format(), carrier, opts, dialect)
    }

    fn verify(
        &self,
        carrier: &[u8],
        opts: &VerifyOptions<'_>,
        dialect: &StegoProfile,
    ) -> Result<StegoVerifyResult, StrHideError> {
        hevc_verify(self.format(), carrier, opts, dialect)
    }
}
