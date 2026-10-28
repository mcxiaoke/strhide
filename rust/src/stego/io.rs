//! File-level convenience API for content-adaptive steganography.
//!
//! The bytes-level entry points in [`crate::stego`] do the embedding; this
//! module adds the file plumbing a host application would otherwise repeat:
//! read the carrier, embed in memory, commit atomically (temp file + rename),
//! optionally keep a `.bak` backup and clone the original timestamps.
//!
//! It is available with the `stego` feature alone — no structure-domain
//! `engine` required — so a pure stego consumer (e.g. a dedicated image tool)
//! does not have to reimplement ~150 lines of crash-safe file handling.

use std::path::Path;

#[cfg(feature = "content-hevc")]
use crate::commit::commit_carrier_patches;
use crate::commit::{FileTarget, commit_carrier_bytes};
use crate::core::payload::Payload;
use crate::core::pipeline::check_overwrite;
use crate::errors::StrHideError;
use crate::stego::embed_carrier_with_dialect_info;
use crate::stego::options::{EmbedOptions, ExtractOptions, StegoEmbedResult, StegoWarning};
use crate::stego::params::{SafetyEnforcement, StegoProfile};

/// Embed `payload` into the carrier file at `carrier_path` and commit the result.
///
/// The carrier is read, the embedding happens in memory, and the result is
/// committed through [`crate::commit::commit_carrier_bytes`] (same-directory
/// temp file + atomic rename, permissions and timestamps preserved) — the same
/// path the structure domain and the CLI use.
///
/// When `target_path` is `None` the carrier is replaced in place; otherwise the
/// result is written to `target_path` and the original carrier is left alone.
/// An in-place write keeps a `<carrier>.bak` copy when `backup` is set.
///
/// Embed `payload` into the carrier file at `carrier_path` and commit the result atomically.
pub fn embed_carrier_file(
    carrier_path: &Path,
    payload: &Payload<'_>,
    options: &EmbedOptions<'_>,
    dialect: &StegoProfile,
    target: &FileTarget<'_>,
) -> Result<StegoEmbedResult, StrHideError> {
    let carrier_meta = std::fs::metadata(carrier_path)?;
    let carrier_before_bytes = carrier_meta.len();
    let dest = target.output_path.unwrap_or(carrier_path);
    if target.output_path.is_some() {
        check_overwrite(dest, target.overwrite)?;
    }

    let carrier_bytes = std::fs::read(carrier_path)?;
    let format = crate::formats::sniff::sniff_bytes(&carrier_bytes).ok_or_else(|| {
        StrHideError::UnsupportedFormat(format!(
            "Failed to identify carrier format for '{}'",
            carrier_path.display()
        ))
    })?;

    #[cfg(feature = "content-hevc")]
    if matches!(
        format,
        crate::formats::FileFormat::Mp4 | crate::formats::FileFormat::HevcAnnexB
    ) {
        let domain = options.domain(dialect);
        options.control.check()?;
        let anon_payload;
        let eff_payload = if options.no_filename && payload.name().is_some() {
            anon_payload = Payload::bytes(payload.as_bytes());
            &anon_payload
        } else {
            payload
        };
        let secret = options.secret(dialect);
        let direct = || {
            crate::stego::hevc::embed_hevc_patches(
                &carrier_bytes,
                eff_payload,
                secret,
                domain,
                dialect.hevc_format(),
                options.freshness,
                options.safety,
                &options.control,
            )
        };
        let patches_res = match &options.pool {
            Some(pool) => pool.install(direct),
            None => direct(),
        };
        match patches_res {
            Ok((patches, capacity, stats)) => {
                drop(carrier_bytes);
                let backup_file = commit_carrier_patches(
                    carrier_path,
                    dest,
                    &patches,
                    target.backup,
                    target.preserve_time,
                )?;
                let carrier_after_bytes = std::fs::metadata(dest)?.len();

                let mut warnings = Vec::new();
                if options.safety.enforcement == SafetyEnforcement::Advisory
                    && payload.as_bytes().len() > capacity.recommended_max_bytes
                {
                    let bpp = (payload.as_bytes().len() * 8) as f64
                        / capacity.total_elements.max(1) as f64;
                    warnings.push(StegoWarning::SafetyThresholdExceeded {
                        payload_bytes: payload.as_bytes().len(),
                        recommended_max_bytes: capacity.recommended_max_bytes,
                        safety_level: options.safety.level.as_str().to_string(),
                        actual_bpp: bpp,
                        limit_bpp: options.safety.level.bpp_limit(),
                    });
                }

                return Ok(StegoEmbedResult {
                    carrier: carrier_path.to_path_buf(),
                    written_to: dest.to_path_buf(),
                    format,
                    payload_bytes: payload.as_bytes().len(),
                    carrier_before_bytes,
                    carrier_after_bytes,
                    backup_file,
                    capacity: Some(capacity),
                    stats: Some(stats),
                    warnings,
                });
            }
            Err(e) => return Err(e),
        }
    }

    let output = embed_carrier_with_dialect_info(&carrier_bytes, payload, options, dialect)?;
    let cap = match output.capacity {
        Some(c) => Some(c),
        None => {
            let probe_opts = crate::stego::ProbeOptions {
                password: options.password,
                domain: options.domain,
                safety: options.safety,
                tuning: options.tuning.clone(),
                exact: false,
                control: options.control,
                pool: options.pool.clone(),
            };
            crate::stego::probe_carrier_capacity_with_dialect(&carrier_bytes, &probe_opts, dialect)
                .ok()
        }
    };
    drop(carrier_bytes);
    let backup_file = commit_carrier_bytes(
        carrier_path,
        dest,
        &output.bytes,
        target.backup,
        target.preserve_time,
    )?;
    let carrier_after_bytes = std::fs::metadata(dest)?.len();

    let mut warnings = Vec::new();
    if options.safety.enforcement == SafetyEnforcement::Advisory
        && let Some(ref cap_ref) = cap
        && payload.as_bytes().len() > cap_ref.recommended_max_bytes
    {
        let bpp = (payload.as_bytes().len() * 8) as f64 / cap_ref.total_elements.max(1) as f64;
        warnings.push(StegoWarning::SafetyThresholdExceeded {
            payload_bytes: payload.as_bytes().len(),
            recommended_max_bytes: cap_ref.recommended_max_bytes,
            safety_level: options.safety.level.as_str().to_string(),
            actual_bpp: bpp,
            limit_bpp: options.safety.level.bpp_limit(),
        });
    }

    Ok(StegoEmbedResult {
        carrier: carrier_path.to_path_buf(),
        written_to: dest.to_path_buf(),
        format,
        payload_bytes: payload.as_bytes().len(),
        carrier_before_bytes,
        carrier_after_bytes,
        backup_file,
        capacity: cap,
        stats: output.stats,
        warnings,
    })
}

/// Extract the payload from the carrier file at `carrier_path`.
///
/// The counterpart of [`embed_carrier_file`]: read the file, extract in memory,
/// return the payload bytes. Writing the payload somewhere is the caller's
/// decision, which keeps this function free of overwrite policy.
pub fn extract_carrier_file(
    carrier_path: &Path,
    options: &ExtractOptions<'_>,
    dialect: &StegoProfile,
) -> Result<Vec<u8>, StrHideError> {
    extract_carrier_file_payload(carrier_path, options, dialect).map(Payload::into_bytes)
}

/// [`extract_carrier_file`] returning the unified [`Payload`] with preserved metadata.
pub fn extract_carrier_file_payload(
    carrier_path: &Path,
    options: &ExtractOptions<'_>,
    dialect: &StegoProfile,
) -> Result<Payload<'static>, StrHideError> {
    let carrier_bytes = std::fs::read(carrier_path)?;
    crate::stego::extract_carrier_payload(&carrier_bytes, options, dialect)
}

/// Inspect the carrier file at `carrier_path`.
pub fn inspect_carrier_file(
    carrier_path: &Path,
    options: &crate::stego::InspectOptions<'_>,
    dialect: &StegoProfile,
) -> Result<crate::stego::StegoHeaderInfo, StrHideError> {
    #[cfg(feature = "content-hevc")]
    {
        let mut file = std::fs::File::open(carrier_path)?;
        let format = crate::formats::sniff::sniff_stream(&mut file)?;
        drop(file);

        if format == Some(crate::formats::FileFormat::Mp4) {
            return crate::stego::hevc::inspect_hevc_mp4_file(
                carrier_path,
                options.password,
                options.domain,
                dialect.hevc_format(),
                &options.control,
            );
        }
    }

    let carrier_bytes = std::fs::read(carrier_path)?;
    crate::stego::inspect_carrier_with_dialect(&carrier_bytes, options, dialect)
}

/// Probe the carrier file capacity at `carrier_path`.
pub fn probe_carrier_file(
    carrier_path: &Path,
    options: &crate::stego::ProbeOptions<'_>,
    dialect: &StegoProfile,
) -> Result<crate::stego::StegoCapacityInfo, StrHideError> {
    let carrier_bytes = std::fs::read(carrier_path)?;
    crate::stego::probe_carrier_capacity_with_dialect(&carrier_bytes, options, dialect)
}

/// Verify the carrier file at `carrier_path`.
pub fn verify_carrier_file(
    carrier_path: &Path,
    options: &crate::stego::VerifyOptions<'_>,
    dialect: &StegoProfile,
) -> Result<crate::stego::StegoVerifyResult, StrHideError> {
    let carrier_bytes = std::fs::read(carrier_path)?;
    crate::stego::verify_carrier_with_dialect(&carrier_bytes, options, dialect)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::{EmbedOptions, ExtractOptions};

    #[test]
    fn unsupported_carrier_is_refused_without_touching_the_file() {
        let dir = std::env::temp_dir().join(format!("strhide-io-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let carrier = dir.join("carrier.bin");
        let original = b"this is not an image carrier";
        std::fs::write(&carrier, original).expect("write carrier");

        let target = FileTarget::default();
        let result = embed_carrier_file(
            &carrier,
            &Payload::bytes(b"payload"),
            &EmbedOptions::default(),
            &StegoProfile::default(),
            &target,
        );
        assert!(
            matches!(result, Err(StrHideError::UnsupportedFormat(_))),
            "a non-image carrier must be refused as UnsupportedFormat, got {result:?}"
        );

        let after = std::fs::read(&carrier).expect("read back");
        assert_eq!(
            after, original,
            "a refused embed must not modify or replace the carrier"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_reports_unsupported_format() {
        let dir = std::env::temp_dir().join(format!("strhide-io-test-x-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let carrier = dir.join("carrier.bin");
        std::fs::write(&carrier, b"still not an image").expect("write carrier");

        let result = extract_carrier_file(
            &carrier,
            &ExtractOptions::default(),
            &StegoProfile::default(),
        );
        assert!(matches!(result, Err(StrHideError::UnsupportedFormat(_))));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(feature = "content-hevc")]
    fn hevc_annexb_embed_carrier_file_roundtrip_patches() {
        let candidate = Path::new("../temp/testhevc/annexb/test-25fps.hevc");
        if !candidate.is_file() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("strhide-io-hevc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let dest = dir.join("stego.hevc");

        let secret = "io-patch-test-pwd";
        let payload = Payload::bytes(b"hello patches from io");
        let opts = EmbedOptions {
            password: Some(secret),
            ..EmbedOptions::default()
        };
        let profile = StegoProfile::default();

        let target = FileTarget {
            output_path: Some(&dest),
            backup: false,
            preserve_time: true,
            overwrite: true,
        };
        let res = embed_carrier_file(candidate, &payload, &opts, &profile, &target)
            .expect("embed_carrier_file");
        assert!(res.backup_file.is_none());
        assert!(dest.is_file());

        let extract_opts = ExtractOptions {
            password: Some(secret),
            ..ExtractOptions::default()
        };
        let extracted =
            extract_carrier_file(&dest, &extract_opts, &profile).expect("extract_carrier_file");
        assert_eq!(extracted, b"hello patches from io");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
