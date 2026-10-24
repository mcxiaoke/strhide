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

use crate::errors::StrHideError;
use crate::params::Profile;
use crate::stego::{StegoOptions, embed_carrier_with_profile, extract_carrier_with_profile};

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
    payload: &[u8],
    options: &StegoOptions,
    profile: &Profile,
    backup: bool,
) -> Result<Option<PathBuf>, StrHideError> {
    let carrier_bytes = std::fs::read(carrier_path)?;
    let stego_bytes = embed_carrier_with_profile(&carrier_bytes, payload, options, profile)?;
    let dest = target_path.unwrap_or(carrier_path);
    crate::commit::commit_carrier_bytes(carrier_path, dest, &stego_bytes, backup, true)
}

/// Extract the payload from the carrier file at `carrier_path`.
///
/// The counterpart of [`embed_carrier_file`]: read the file, extract in memory,
/// return the payload bytes. Writing the payload somewhere is the caller's
/// decision, which keeps this function free of overwrite policy.
pub fn extract_carrier_file(
    carrier_path: &Path,
    options: &StegoOptions,
    profile: &Profile,
) -> Result<Vec<u8>, StrHideError> {
    let carrier_bytes = std::fs::read(carrier_path)?;
    extract_carrier_with_profile(&carrier_bytes, options, profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::StegoOptions;

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
            b"payload",
            &StegoOptions::default(),
            &Profile::default(),
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

        let result = extract_carrier_file(&carrier, &StegoOptions::default(), &Profile::default());
        assert!(matches!(result, Err(StrHideError::UnsupportedFormat(_))));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
