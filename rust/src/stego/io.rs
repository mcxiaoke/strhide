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

use std::path::{Path, PathBuf};

use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::stego::params::StegoProfile;
use crate::stego::{EmbedOptions, ExtractOptions, embed_carrier_with_dialect};

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
/// Returns the backup path that was created, if any.
pub fn embed_carrier_file(
    carrier_path: &Path,
    target_path: Option<&Path>,
    payload: &Payload<'_>,
    options: &EmbedOptions<'_>,
    dialect: &StegoProfile,
    backup: bool,
) -> Result<Option<PathBuf>, StrHideError> {
    let carrier_bytes = std::fs::read(carrier_path)?;
    let dest = target_path.unwrap_or(carrier_path);
    let format = crate::formats::sniff::sniff_bytes(&carrier_bytes);

    if matches!(
        format,
        Some(crate::formats::FileFormat::Mp4 | crate::formats::FileFormat::HevcAnnexB)
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
            Ok((patches, _capacity)) => {
                drop(carrier_bytes);
                return crate::commit::commit_carrier_patches(
                    carrier_path,
                    dest,
                    &patches,
                    backup,
                    true,
                );
            }
            Err(e) => return Err(e),
        }
    }

    let stego_bytes = embed_carrier_with_dialect(&carrier_bytes, payload, options, dialect)?;
    drop(carrier_bytes);
    crate::commit::commit_carrier_bytes(carrier_path, dest, &stego_bytes, backup, true)
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

        let result = embed_carrier_file(
            &carrier,
            None,
            &Payload::bytes(b"payload"),
            &EmbedOptions::default(),
            &StegoProfile::default(),
            true,
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

        let bak = embed_carrier_file(candidate, Some(&dest), &payload, &opts, &profile, false)
            .expect("embed_carrier_file");
        assert!(bak.is_none());
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
