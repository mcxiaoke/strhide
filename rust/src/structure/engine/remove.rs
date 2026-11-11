//! Remove/restore pipeline: strip the envelope and verify the restored host.

use std::fs::{File, OpenOptions};
use std::io::{Cursor, SeekFrom};
use std::path::{Path, PathBuf};

use super::locate::{locate_envelope_with_magic, no_hidden_data_error};
use super::read::open_authenticated_at;
use super::report::RemoveResult;
use crate::commit::{TmpGuard, temp_path_for};
use crate::crypto::derive_stealth_magics;
use crate::errors::StrHideError;
use crate::structure::adapters::{LocatedEnvelope, SeekRead, SeekWrite};
use crate::structure::envelope::EnvelopeHeader;
use crate::structure::options::RestoreOptions;
use crate::structure::params::StructureProfile;
use crate::structure::registry::{find_adapter, find_adapter_or_reject};

/// Strip the envelope from `carrier_path` and restore the original carrier
/// bit-for-bit, in the official dialect.
///
/// When [`RestoreOptions::output_path`] is `None` the carrier is rewritten in
/// place; otherwise the restored bytes are written there (the original carrier
/// is untouched).
///
/// The restored file is hashed and compared to the `orig_host_size` /
/// `orig_host_sha256` recorded in the envelope. On mismatch the new file is
/// discarded and [`StrHideError::RestoreMismatch`] is returned — usually
/// because a second envelope was layered on top and must be removed first.
///
/// A password is required when the envelope was written either encrypted or in
/// stealth mode: the metadata seal is authenticated before anything is stripped,
/// and that needs the derived key. A plaintext, non-stealth envelope still
/// restores without a password.
///
/// When [`RestoreOptions::backup`] is true and the write is in place, a
/// `<carrier>.bak` file is kept before overwriting.
pub fn remove_carrier(
    carrier_path: &Path,
    options: &RestoreOptions<'_>,
) -> Result<RemoveResult, StrHideError> {
    remove_carrier_with_dialect(carrier_path, options, &StructureProfile::default())
}

/// Strip the envelope from `host` into `out`, returning the envelope header.
///
/// I/O-free core shared by [`remove_carrier_with_dialect`] and
/// [`remove_carrier_bytes`]. Verification is a separate step
/// ([`verify_restored`]) because the caller owns the restored stream: the file
/// wrapper reopens the temp file, the in-memory wrapper rewinds its cursor.
fn remove_core(
    host: &mut dyn SeekRead,
    out: &mut dyn SeekWrite,
    label: &str,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<EnvelopeHeader, StrHideError> {
    let password = password.filter(|s| !s.is_empty());
    let host_len = host.seek(SeekFrom::End(0))?;
    let adapter = find_adapter_or_reject(host, label)?;
    let located = locate_envelope_with_magic(host, adapter, password, profile)?;
    let LocatedEnvelope {
        offset: ube_offset,
        size: ube_total_size,
        strategy: strategy_name,
    } = match located.location {
        Some(l) => l,
        None => {
            return Err(no_hidden_data_error(
                host,
                adapter,
                label,
                password.is_some(),
            ));
        }
    };

    // Decrypt the metadata AEAD before trusting any coordinate from the header.
    // `patch_offset` and the injection geometry are not covered by the seal, and
    // the old remove path stripped straight from an unauthenticated header, so a
    // forged `patch_offset` could drive `strip` outside the carrier. This also
    // makes `verified_identical` truthful: a header whose metadata seal does not
    // open is rejected before anything is written.
    let header = {
        let env = open_authenticated_at(
            host,
            adapter,
            LocatedEnvelope {
                offset: ube_offset,
                size: ube_total_size,
                strategy: strategy_name.clone(),
            },
            password,
            profile,
            located.stealth_header_magic,
            None,
        )?;
        env.header.clone()
    };

    let strip_header = strip_coordinates_for_location(&header, ube_offset, &strategy_name)?;
    // Bound the (possibly relocated) injected region against the physical
    // carrier. The post-injection coordinates are outside any AEAD, so this is
    // what stops a forged `inject_offset`/`inject_size` from driving `strip`
    // past EOF. `envelope_coordinates_agree` also accepts the legitimate shift
    // of a PNG `chunk` envelope moved by content re-compression.
    super::verify::envelope_coordinates_agree(
        &header,
        &strategy_name,
        ube_offset,
        ube_total_size,
        host_len,
    )
    .map_err(StrHideError::CorruptedData)?;
    adapter.strip(host, out, &strip_header)?;
    Ok(header)
}

/// Strategies whose envelope may physically move after it was written.
///
/// `chunk`: content-domain re-compression changes the length of the stream
/// before the PNG chunk. `eof`: the same for envelopes appended at the end.
/// `ebml_void`: an MKV remux (or a content-domain HEVC re-encode) can resize the
/// Segment in front of the appended Void block — `MkvAdapter::locate` resolves
/// the block from the tail precisely so that shift is tolerated, and validating
/// against the write-time coordinate would make that tolerance unreachable.
///
/// These coordinates are outside the AAD, so this is a corruption check, not a
/// security boundary: `verify_restored` still re-hashes the stripped carrier
/// against the sealed `orig_host_sha256` and refuses a carrier that no longer
/// reproduces the original.
pub(super) fn relocatable_strategy(strategy: &str) -> bool {
    matches!(strategy, "chunk" | "eof" | "ebml_void")
}

/// Return header coordinates translated to the *located* envelope position.
///
/// A PNG `chunk`, an appended EOF envelope or an MKV `ebml_void` envelope can
/// move after it was written: content-domain embedding re-compresses IDAT (or
/// re-encodes the media), and an external remux can shift a Matroska Segment
/// while leaving the Void block at EOF. The envelope trailer is authenticated,
/// but its `ube_offset` is the coordinate from write time, so `strip` must be
/// told where the envelope really is. All other strategies are anchored at
/// write time; a mismatch there means corruption.
pub(super) fn strip_coordinates_for_location(
    header: &EnvelopeHeader,
    ube_offset: u64,
    strategy: &str,
) -> Result<EnvelopeHeader, StrHideError> {
    let declared = header
        .inject_offset
        .checked_add(header.offset_delta as u64)
        .ok_or_else(|| StrHideError::CorruptedData("inject_offset overflow".into()))?;
    if declared == ube_offset {
        return Ok(header.clone());
    }
    if !relocatable_strategy(strategy) {
        return Err(StrHideError::CorruptedData(format!(
            "envelope coordinates disagree: header declares {declared}, located at {ube_offset}"
        )));
    }
    let shift = i128::from(ube_offset) - i128::from(declared);
    let adjusted = i128::from(header.inject_offset) + shift;
    let adjusted: u64 = adjusted.try_into().map_err(|_| {
        StrHideError::CorruptedData(format!(
            "relocated envelope underflows inject_offset {}",
            header.inject_offset
        ))
    })?;
    let mut relocated = header.clone();
    relocated.inject_offset = adjusted;
    Ok(relocated)
}

/// Check the restored carrier against the hashes recorded in the envelope.
fn verify_restored(
    restored: &mut dyn SeekRead,
    header: &EnvelopeHeader,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<(u64, [u8; 32]), StrHideError> {
    restored.seek(SeekFrom::Start(0))?;
    let restored_size = restored.seek(SeekFrom::End(0))?;
    restored.seek(SeekFrom::Start(0))?;
    let restored_sha256 = crate::crypto::compute_stream_sha256(restored)?;

    if restored_size == header.orig_host_size && restored_sha256 == header.orig_host_sha256 {
        return Ok((restored_size, restored_sha256));
    }

    // Diagnose the common cause: the carrier carried a second envelope (e.g. a
    // stealth envelope underneath), so stripping this one cannot reproduce the
    // recorded original. Envelopes must be removed in reverse order of
    // injection.
    let mut residual_envelope = false;
    restored.seek(SeekFrom::Start(0))?;
    if let Some(r_adapter) = find_adapter(restored) {
        let remaining = r_adapter
            .locate(restored, profile.locator_magic())
            .ok()
            .flatten()
            .or_else(|| r_adapter.locate(restored, None).ok().flatten())
            .or_else(|| {
                password.and_then(|pwd| {
                    derive_stealth_magics(pwd, profile.domain())
                        .ok()
                        .and_then(|m| r_adapter.locate(restored, Some(&m.1)).ok().flatten())
                })
            });
        // Removing an inner envelope shifts an outer one backwards, so its
        // trailer no longer describes its own coordinates and `locate`
        // correctly refuses it. The container is still there, though, and it
        // is the real reason the hashes cannot match: fall back to the
        // format's envelope-shaped-structure scan for the diagnosis.
        let envelope_shaped = !r_adapter.suspicious_structures(restored).is_empty();
        if remaining.is_some() || envelope_shaped {
            residual_envelope = true;
        }
    }

    let res_sha = restored_sha256
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let exp_sha = header
        .orig_host_sha256
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    Err(StrHideError::RestoreMismatch {
        restored_size,
        expected_size: header.orig_host_size,
        restored_sha256: res_sha,
        expected_sha256: exp_sha,
        residual_envelope,
    })
}

/// Strip the envelope of a carrier written under `dialect`.
///
/// The dialect must be the one used at write time: it drives envelope location
/// (custom magic), the stealth domain, and the `default_secret` used to decode
/// a non-password envelope.
///
/// [`RestoreOptions::overwrite`] decides what happens when the output path
/// names a different file that already exists. It defaults to refusing, which
/// is the safe answer for a library call: restoring replaces the file with the
/// pre-envelope host, and `rename`-ing over a user's file loses it with no way
/// back. The CLI resolves the user's choice first and passes `true` only after
/// they have confirmed. In-place restoration — the default when no output path
/// is given — is the one case where overwriting is the whole point.
pub fn remove_carrier_with_dialect(
    carrier_path: &Path,
    options: &RestoreOptions<'_>,
    dialect: &StructureProfile,
) -> Result<RemoveResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let target_path = options.output_path.unwrap_or(carrier_path);
    let meta = std::fs::metadata(carrier_path)?;
    let orig_permissions = meta.permissions();
    let orig_atime = filetime::FileTime::from_last_access_time(&meta);
    let orig_mtime = filetime::FileTime::from_last_modification_time(&meta);

    if !crate::commit::same_file(target_path, carrier_path) {
        crate::core::pipeline::check_overwrite(target_path, options.overwrite)?;
    }
    crate::commit::reject_read_only_target(target_path)?;
    // Same contract as the write path: one writer per target at a time.
    let _target_lock = crate::commit::TargetLock::acquire(target_path)?;

    let label = carrier_path.display().to_string();
    let tmp_target = temp_path_for(target_path);
    let mut tmp_guard = TmpGuard::new(tmp_target.clone());

    let header = {
        let mut cf = File::open(carrier_path)?;
        let mut out_f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_target)?;
        let mut pw = crate::core::control::ProgressWriter::new(
            &mut out_f,
            options.control,
            crate::core::control::Stage::Write,
            meta.len(),
        );
        let header = remove_core(&mut cf, &mut pw, &label, options.password, dialect)
            .map_err(|e| crate::core::control::map_io_cancel(&options.control, e))?;
        // Same durability contract as the write path: the restored file is
        // fsynced before its temp name is renamed over the carrier.
        out_f.sync_all()?;
        header
    };

    // Verify restored file
    options.control.stage(crate::core::control::Stage::Verify);
    options.control.check()?;
    let (restored_size, restored_sha256) = {
        let mut rf = File::open(&tmp_target)?;
        verify_restored(&mut rf, &header, options.password, dialect)?
    };

    // Strict cancellation check before .bak creation and atomic commit
    options.control.check()?;

    let is_inplace = crate::commit::same_file(target_path, carrier_path);
    let mut backup_file = None;
    if is_inplace && options.backup {
        backup_file = Some(crate::commit::create_carrier_backup(carrier_path)?);
    }

    crate::commit::rename_with_retry(&tmp_target, target_path)?;
    tmp_guard.commit();
    crate::commit::sync_parent_dir(target_path);
    // Same order as the write path: stamp, then restore permissions.
    if let Err(e) = filetime::set_file_times(target_path, orig_atime, orig_mtime) {
        log::warn!(
            "failed to preserve file timestamps for '{}': {e}",
            target_path.display()
        );
    }
    if let Err(e) = std::fs::set_permissions(target_path, orig_permissions) {
        log::warn!(
            "failed to restore file permissions for '{}': {e}",
            target_path.display()
        );
    }

    Ok(RemoveResult {
        carrier: target_path.to_path_buf(),
        restored_size,
        restored_sha256: restored_sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        verified_identical: true,
        backup_file,
    })
}

/// Strip the envelope from an in-memory carrier, returning the restored bytes.
///
/// The restored buffer is checked against the `orig_host_size` /
/// `orig_host_sha256` recorded in the envelope exactly like the file variant,
/// so a carrier that actually held two stacked envelopes fails with
/// [`StrHideError::RestoreMismatch`] instead of returning half-restored bytes.
/// No backup is produced (`backup` only exists for in-place file writes).
pub fn remove_carrier_bytes(
    carrier: &[u8],
    password: Option<&str>,
    dialect: &StructureProfile,
) -> Result<(Vec<u8>, RemoveResult), StrHideError> {
    let mut host = Cursor::new(carrier);
    let mut out = Cursor::new(Vec::new());
    let header = remove_core(&mut host, &mut out, "<memory>", password, dialect)?;
    let bytes = out.into_inner();

    let (restored_size, restored_sha256) = {
        let mut restored = Cursor::new(&bytes);
        verify_restored(&mut restored, &header, password, dialect)?
    };

    let result = RemoveResult {
        carrier: PathBuf::from("<memory>"),
        restored_size,
        restored_sha256: restored_sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        verified_identical: true,
        backup_file: None,
    };
    Ok((bytes, result))
}
