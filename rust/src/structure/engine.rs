//! High-level engine: write, read, inspect, verify, and remove operations.
//!
//! This is the module library callers should use. The flow for each operation
//! is:
//!
//! 1. Run rejection checks ([`crate::structure::rejection`]).
//! 2. Snapshot the carrier's metadata (size, SHA-256, permissions, mtime/atime).
//! 3. Detect the carrier format via [`crate::structure::registry`] and locate any existing
//!    envelope.
//! 4. Build the UBE (header + optional hint + encrypted metadata + chunked
//!    encrypted payload + trailer) in a staging buffer.
//! 5. Inject it into a `<target>.strhide.tmp` file, patch the header/trailer
//!    back with the real offsets, and self-verify the written envelope.
//! 6. On success: optional in-place `.bak` backup, atomic rename, restore
//!    permissions/timestamps.
//!
//! [`remove_carrier`] performs the inverse: it locates the envelope, strips
//! the injected bytes, restores any patched fields, and then **verifies the
//! result against the SHA-256 recorded in the header** before committing. Any
//! mismatch leaves the original carrier untouched.

use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::commit::{TmpGuard, temp_path_for};
use crate::structure::adapters::{
    HostAdapter, LocatedEnvelope, SeekRead, SeekWrite, StrategyCapacity,
};

pub use crate::commit::same_file;

pub use crate::commit::commit_carrier_bytes;
use crate::crypto::{
    decompress_stream, decrypt_metadata, decrypt_stream_from_chunks, derive_keys,
    derive_stealth_magics,
};
use crate::errors::StrHideError;
use crate::structure::envelope::{
    EnvelopeHeader, EnvelopeTrailer, HEADER_SIZE, TRAILER_SIZE, UnpackSecrets,
};
use crate::structure::options::{ReadOptions, RestoreOptions};
use crate::structure::params::StructureProfile;
use crate::structure::registry::{StrategyId, find_adapter, find_adapter_or_reject};

mod capacity;
mod locate;
mod metadata;
mod report;

pub use metadata::{CarrierMetadata, MetadataInspection};
pub use report::{
    InspectResult, LevelStatus, PayloadSource, ReadResult, ReadSummary, RemoveResult, VerifyResult,
    Warning, WriteResult, verify_passed,
};

use capacity::{apply_engine_payload_limit, structure_payload_limit};
use locate::{
    Located, adapter_format, locate_envelope, locate_envelope_with_magic, no_hidden_data_error,
};
use metadata::decode_metadata;
#[cfg(test)]
use metadata::encode_metadata;
#[cfg(test)]
use metadata::{COMPACT_META_MAX_NAME, put_varint, take_varint};

#[cfg(test)]
use crate::params::LocalParams;
#[cfg(test)]
use crate::structure::options::WriteOptions;

/// Stealth mode password derivation domain separation string.
///
/// Re-exported from [`crate::params`] for the public API: the constant lives
/// next to [`StructureProfile::stealth_domain`], which is what actually drives
/// derivation.
pub use crate::params::STEALTH_DOMAIN;

/// Sanitize an untrusted metadata filename down to a safe bare file name.
///
/// Re-exported from [`crate::core::fs`] so the structure-domain path keeps its
/// historical name and both domains share one implementation.
pub use crate::core::fs::sanitize_filename;

mod write;
pub use write::{write_carrier, write_carrier_bytes, write_carrier_with};

/// Extract the payload of a carrier, in the official dialect.
///
/// [`ReadOptions`] carries the destination, the password, and the overwrite
/// decision. Without [`ReadOptions::overwrite`], an existing destination is an
/// error: silently truncating it would lose a user file, which contradicts the
/// tool's "lossless, restorable" contract.
///
/// Call [`read_carrier_with_dialect`] when a private
/// [`StructureProfile`] was used at write time.
pub fn read_carrier(
    carrier_path: &Path,
    options: &ReadOptions<'_>,
) -> Result<ReadResult, StrHideError> {
    read_carrier_with_dialect(carrier_path, options, &StructureProfile::default())
}

/// Everything a successful read produces before any file is written.
///
/// Deliberately I/O-free: the same core serves [`read_carrier_with_profile`]
/// (path in, path out) and [`read_carrier_bytes`] (bytes in, bytes out), so the
/// two can never drift apart on envelope parsing.
struct ReadCore {
    data: Vec<u8>,
    is_file: bool,
    is_encrypted: bool,
    filename: String,
    raw_size: u64,
}

struct AuthenticatedEnvelope<'a> {
    ube_stream: Box<dyn SeekRead + 'a>,
    header: EnvelopeHeader,
    meta_obj: CarrierMetadata,
    payload_key: [u8; 32],
    /// Authenticated associated data this envelope's seals were bound to:
    /// header prefix + the two length fields + the hint body.
    aad: Vec<u8>,
    total_payload_bytes: u64,
}

/// Locate, unpack and authenticate envelope metadata and derive crypto keys.
fn open_and_authenticate_envelope<'a>(
    host: &'a mut dyn SeekRead,
    label: &str,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<AuthenticatedEnvelope<'a>, StrHideError> {
    let password = password.filter(|s| !s.is_empty());
    let adapter = find_adapter_or_reject(host, label)?;

    let Located {
        location,
        stealth_header_magic,
        ..
    } = locate_envelope_with_magic(host, adapter, password, profile)?;

    let location = match location {
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

    open_authenticated_at(
        host,
        adapter,
        location,
        password,
        profile,
        stealth_header_magic,
        None,
    )
}

/// [`open_and_authenticate_envelope`] for an envelope the caller already
/// located.
///
/// `precomputed` lets `verify` hand over the `UnpackSecrets` it derived for
/// Level 2, so Level 3 does not repeat PBKDF2 over the same (password, salt) pair.
fn open_authenticated_at<'a>(
    host: &'a mut dyn SeekRead,
    adapter: &dyn HostAdapter,
    location: LocatedEnvelope,
    password: Option<&str>,
    profile: &StructureProfile,
    stealth_header_magic: Option<[u8; 8]>,
    precomputed: Option<&UnpackSecrets>,
) -> Result<AuthenticatedEnvelope<'a>, StrHideError> {
    let LocatedEnvelope {
        offset: ube_offset,
        size: ube_total_size,
        strategy: strategy_name,
    } = location;

    // Captured before the envelope reader borrows `host`; the strip path needs
    // the physical carrier bound to reject out-of-range header coordinates.
    let host_len = host.seek(SeekFrom::End(0))?;

    let mut ube_stream =
        adapter.open_ube_reader(host, ube_offset, ube_total_size, &strategy_name)?;

    let mut header_bytes = [0u8; HEADER_SIZE];
    ube_stream.read_exact(&mut header_bytes)?;

    // `UnpackSecrets` is not `Copy` (it wipes the derived keys on drop), so
    // borrow the caller's material when there is any and keep this frame's own
    // derivation in a local that dies with the call.
    let derived;
    let secrets = match precomputed {
        Some(s) => s,
        None => {
            let salt = EnvelopeHeader::salt_of(&header_bytes).unwrap_or([0u8; 16]);
            derived =
                UnpackSecrets::derive_attempts(password, &salt, profile, stealth_header_magic)?;
            &derived
        }
    };
    let header = EnvelopeHeader::unpack_with_secrets(&header_bytes, password, profile, secrets)?;
    header.validate_against(ube_total_size, host_len)?;

    // `hint_len` is capped at `MAX_HINT_LEN` by `validate_against`, so this
    // allocation is bounded. The raw bytes are kept: they are part of the AAD,
    // while `hint_str` exists only for display.
    let mut hint_bytes: Vec<u8> = Vec::new();
    if header.hint_len > 0 {
        hint_bytes = vec![0u8; header.hint_len as usize];
        ube_stream.read_exact(&mut hint_bytes)?;
    }
    let hint_str = if hint_bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&hint_bytes).to_string())
    };

    let aad = header.auth_aad(&hint_bytes);

    let (payload_key, meta_key) = if header.is_encrypted() {
        secrets.password.as_ref().map_or_else(
            || {
                let message = match &hint_str {
                    Some(h) => format!("Password required to extract hidden data. Hint: '{h}'."),
                    None => "Password required to extract hidden data".into(),
                };
                Err(StrHideError::PasswordWithHint {
                    message,
                    hint: hint_str.clone(),
                })
            },
            |s| Ok((s.payload_key, s.meta_key)),
        )?
    } else {
        match &secrets.default {
            Some(s) => (s.payload_key, s.meta_key),
            None => derive_keys(profile.secret(), &header.salt)?,
        }
    };

    // `validate_against` capped `meta_len` at `MAX_META_LEN`, so the buffer a
    // forged field can request is 256 KiB, not 4 GiB.
    let mut meta_bytes = vec![0u8; header.meta_len as usize];
    ube_stream.read_exact(&mut meta_bytes)?;

    let meta_obj = decrypt_metadata(&meta_bytes, &meta_key, &header.base_nonce, &aad)
        .map_err(|_| StrHideError::Password("Invalid password or corrupted metadata".into()))
        .and_then(|plain| decode_metadata(&plain, header.is_compact_meta()))?;

    let total_payload_bytes = ube_total_size
        - (HEADER_SIZE as u64
            + TRAILER_SIZE as u64
            + header.hint_len as u64
            + header.meta_len as u64);

    Ok(AuthenticatedEnvelope {
        ube_stream,
        header,
        meta_obj,
        payload_key,
        aad,
        total_payload_bytes,
    })
}

/// Locate, authenticate and decrypt the envelope in `host`.
///
/// `label` only appears in error messages ("'photo.png'" vs "'<memory>'").
fn read_core(
    host: &mut dyn SeekRead,
    label: &str,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<ReadCore, StrHideError> {
    // Captured before the envelope reader borrows `host`; `open_and_authenticate`
    // seeks around while locating the envelope.
    let carrier_len = host.seek(SeekFrom::End(0))?;
    let mut env = open_and_authenticate_envelope(host, label, password, profile)?;

    // Bound the declared output size *before* decrypting: the chunk ciphertext
    // itself is already bounded by the carrier, but `raw_size` drives the
    // decompression buffer and is only protected by the (public-key) metadata
    // seal on non-password envelopes. One MiB of slack covers chunk framing for
    // a genuinely large uncompressed payload.
    let max_safe_size = structure_payload_limit(carrier_len);
    if env.meta_obj.raw_size > max_safe_size {
        return Err(StrHideError::General(format!(
            "Declared payload size ({} bytes) exceeds the safe decompression limit ({} bytes)",
            env.meta_obj.raw_size, max_safe_size
        )));
    }
    if env.total_payload_bytes > max_safe_size.saturating_add(1 << 20) {
        return Err(StrHideError::General(format!(
            "Envelope payload stream ({} bytes) exceeds the safe decompression limit ({} bytes)",
            env.total_payload_bytes, max_safe_size
        )));
    }

    let mut decrypted_payload = Vec::new();
    decrypt_stream_from_chunks(
        &mut env.ube_stream,
        &mut decrypted_payload,
        &env.payload_key,
        &env.header.base_nonce,
        &env.aad,
        env.total_payload_bytes,
    )?;

    let data = if env.header.is_compressed() {
        let mut decomp = Vec::with_capacity(env.meta_obj.raw_size.min(1024 * 1024) as usize);
        decompress_stream(
            &mut Cursor::new(&decrypted_payload),
            &mut decomp,
            env.meta_obj.raw_size,
        )?;
        decomp
    } else {
        decrypted_payload
    };

    let actual_sha256 = {
        let h = crate::crypto::compute_sha256(&data);
        h.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    if actual_sha256 != env.meta_obj.raw_sha256 {
        return Err(StrHideError::CorruptedData(format!(
            "Payload SHA-256 mismatch: {actual_sha256} != {}",
            env.meta_obj.raw_sha256
        )));
    }

    // The metadata filename is attacker-controlled input (unencrypted
    // envelopes especially), and every caller that writes the payload out
    // trusts it: sanitise once here so no consumer can turn it into a path.
    let filename = if env.meta_obj.filename.is_empty() {
        String::new()
    } else {
        sanitize_filename(&env.meta_obj.filename)
    };

    Ok(ReadCore {
        data,
        is_file: env.header.is_file(),
        is_encrypted: env.header.is_encrypted(),
        filename,
        raw_size: env.meta_obj.raw_size,
    })
}

/// Streamingly verify Level 3 payload decryption and SHA-256, enforcing a
/// 1 GiB limit and using minimal memory (~4 MiB chunk buffer).
fn verify_authenticated_payload(env: &mut AuthenticatedEnvelope<'_>) -> Result<u64, StrHideError> {
    crate::crypto::verify_payload_stream(
        &mut env.ube_stream,
        &env.payload_key,
        &env.header.base_nonce,
        &env.aad,
        env.total_payload_bytes,
        env.header.is_compressed(),
        env.meta_obj.raw_size,
        &env.meta_obj.raw_sha256,
        crate::crypto::MAX_VERIFY_PAYLOAD_SIZE,
    )
}

/// Write the recovered payload to `out_p`, returning the path actually used.
///
/// `out_p` may name a file or an existing directory; in the latter case the
/// untrusted metadata filename is sanitised down to a bare name so a crafted
/// carrier cannot write outside that directory.
fn write_payload_to(
    out_p: &Path,
    carrier_path: &Path,
    core: &ReadCore,
    overwrite: bool,
) -> Result<PathBuf, StrHideError> {
    let final_dest = if out_p.is_dir() {
        let fn_to_use = if core.filename.is_empty() {
            "extracted.bin".to_string()
        } else {
            sanitize_filename(&core.filename)
        };
        out_p.join(fn_to_use)
    } else {
        out_p.to_path_buf()
    };

    // Writing the payload over its own carrier truncates the file that still
    // holds the hidden data, so the extraction would destroy its own source.
    if same_file(&final_dest, carrier_path) {
        return Err(StrHideError::Rejection(format!(
            "Refusing to write the extracted payload over carrier '{}': choose a different output path",
            carrier_path.display()
        )));
    }

    // Never truncate an existing file by accident: extracting several
    // carriers that contain the same payload name (or reading into a busy
    // directory) used to replace user files silently.
    crate::core::pipeline::check_overwrite(&final_dest, overwrite)?;

    // Write through a sibling temp file and rename atomically, preventing partially
    // written files on failure and avoiding symlink traversal at the destination.
    crate::core::commit::write_bytes_atomic(&final_dest, &core.data).map_err(|err| {
        let reason = match &err {
            StrHideError::Io(e) => match e.kind() {
                std::io::ErrorKind::NotFound => "the output directory does not exist",
                std::io::ErrorKind::PermissionDenied => "the output directory is not writable",
                _ => "the output file could not be created",
            },
            _ => "the output file could not be created",
        };
        StrHideError::General(format!(
            "Cannot create '{}': {reason} [{err}]",
            final_dest.display()
        ))
    })?;
    Ok(final_dest)
}

/// Extract the payload of a carrier written under `dialect`.
///
/// The dialect must be the same one used at write time. For the official
/// dialect this is identical to [`read_carrier`]; for a private dialect a
/// mismatched profile cannot return payload bytes — the envelope is either not
/// found at all (stealth, or a custom trailer magic) or fails header/`AEAD`
/// validation (custom `default_secret` with the standard magics).
pub fn read_carrier_with_dialect(
    carrier_path: &Path,
    options: &ReadOptions<'_>,
    dialect: &StructureProfile,
) -> Result<ReadResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let label = carrier_path.display().to_string();
    options.control.stage(crate::core::control::Stage::Read);
    options.control.check()?;
    let mut f = File::open(carrier_path)?;
    let core = read_core(&mut f, &label, options.password, dialect)?;
    options.control.check()?;
    let written_file = match options.output_path {
        Some(out_p) => {
            options.control.stage(crate::core::control::Stage::Write);
            Some(write_payload_to(
                out_p,
                carrier_path,
                &core,
                options.overwrite,
            )?)
        }
        None => None,
    };

    Ok(ReadResult {
        carrier: carrier_path.to_path_buf(),
        data: core.data,
        is_file: core.is_file,
        is_encrypted: core.is_encrypted,
        filename: core.filename,
        raw_size: core.raw_size,
        written_file,
    })
}

/// Extract the payload of an in-memory carrier.
///
/// Identical validation to [`read_carrier_with_dialect`] (format detection,
/// AEAD authentication, SHA-256 check); `written_file` is always `None` because
/// nothing is written — the caller already has the bytes.
pub fn read_carrier_bytes(
    carrier: &[u8],
    password: Option<&str>,
    dialect: &StructureProfile,
) -> Result<ReadResult, StrHideError> {
    let mut host = Cursor::new(carrier);
    let core = read_core(&mut host, "<memory>", password, dialect)?;
    Ok(ReadResult {
        carrier: PathBuf::from("<memory>"),
        data: core.data,
        is_file: core.is_file,
        is_encrypted: core.is_encrypted,
        filename: core.filename,
        raw_size: core.raw_size,
        written_file: None,
    })
}

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
/// I/O-free core shared by [`remove_carrier_with`] and
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
    envelope_coordinates_agree(
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
fn relocatable_strategy(strategy: &str) -> bool {
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
fn strip_coordinates_for_location(
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

    if !same_file(target_path, carrier_path) {
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

    let is_inplace = same_file(target_path, carrier_path);
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

/// Inspect a carrier: report its format, any envelope found, decrypted
/// metadata, and the capacity of every available strategy.
///
/// This function never modifies the carrier. A carrier with no envelope
/// returns `Ok` with `has_hidden_data == false` rather than an error.
pub fn inspect_carrier(
    carrier_path: &Path,
    password: Option<&str>,
) -> Result<InspectResult, StrHideError> {
    inspect_carrier_with(carrier_path, password, &StructureProfile::default())
}

/// Inspect a carrier written under `profile`.
///
/// A carrier whose envelope belongs to a different dialect reports
/// `has_hidden_data == false`: a private dialect is meant to be invisible to
/// readers that do not know it.
pub fn inspect_carrier_with(
    carrier_path: &Path,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<InspectResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let mut cf = File::open(carrier_path)?;
    inspect_core(
        &mut cf,
        &carrier_path.display().to_string(),
        password,
        profile,
    )
}

/// Inspect an in-memory carrier, using the same dialect resolution as
/// [`inspect_carrier_with`].
pub fn inspect_carrier_bytes(
    carrier: &[u8],
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<InspectResult, StrHideError> {
    let mut host = Cursor::new(carrier);
    inspect_core(&mut host, "<memory>", password, profile)
}

/// Build the "no readable envelope" inspect result.
///
/// Shared by the genuinely-empty carrier and the carrier whose envelope cannot
/// be opened with the caller's profile: both are indistinguishable from the
/// outside, which is the point of a private dialect.
fn empty_inspect_result(
    host: &mut dyn SeekRead,
    adapter: &dyn HostAdapter,
    label: &str,
    strategies: Vec<StrategyCapacity>,
) -> Result<InspectResult, StrHideError> {
    let _ = host.seek(SeekFrom::Start(0));
    let suspicious_hints = adapter.suspicious_structures(host);
    Ok(InspectResult {
        carrier: PathBuf::from(label),
        format: adapter_format(adapter)?,
        has_hidden_data: false,
        strategy: None,
        ube_offset: None,
        ube_total_size: None,
        is_encrypted: None,
        is_compressed: None,
        is_stealth: None,
        password_hint: None,
        orig_host_size: None,
        orig_host_sha256: None,
        metadata: None,
        suspicious_hints,
        strategies,
    })
}

/// Shared inspect logic over any seekable reader (a `File` on the path path, a
/// `Cursor` on the bytes path).
fn inspect_core(
    host: &mut dyn SeekRead,
    label: &str,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<InspectResult, StrHideError> {
    host.seek(SeekFrom::Start(0))?;
    let adapter = find_adapter_or_reject(host, label)?;
    let host_len = host.seek(SeekFrom::End(0))?;

    // Measured strategy capacities (design: folds the former `check` command
    // into `inspect`). Adapters that can answer statically ignore the reader;
    // PE measures `.text` density and zero slack, ZIP measures the EOCD offset.
    let mut strategies = adapter.strategy_capacities(Some(host));
    // Adapter ceilings describe the *container* mechanism only; the engine
    // itself refuses payloads above `structure_payload_limit(host_len)` on both
    // the write and the read path. Clamp every advertised capacity to that
    // effective limit so `inspect` never promises a payload the writer would
    // reject (an "unlimited (file grows)" EOF strategy is still bounded by the
    // 256x-host / 64 MiB-floor / 1 GiB-ceiling rule).
    apply_engine_payload_limit(&mut strategies, host_len);

    let loc = locate_envelope(host, adapter, password, profile)?;

    let located = match loc {
        Some(l) => l,
        None => return empty_inspect_result(host, adapter, label, strategies),
    };
    let (ube_offset, ube_total_size, strategy_name) =
        (located.offset, located.size, located.strategy);

    let mut ube_stream =
        adapter.open_ube_reader(host, ube_offset, ube_total_size, &strategy_name)?;

    let mut header_bytes = [0u8; HEADER_SIZE];
    ube_stream.read_exact(&mut header_bytes)?;
    // Envelopes unopenable under this profile represent unknown dialects or mismatched keys;
    // treat as not hidden to maintain dialect invisibility.
    let header = match EnvelopeHeader::unpack_with_profile(&header_bytes, password, profile) {
        Ok(h) => h,
        Err(e) => {
            // Maintain dialect invisibility by reporting empty result, while logging diagnostic detail.
            log::debug!(
                target: "structure::inspect",
                "envelope header does not open under this profile: {e}"
            );
            drop(ube_stream);
            return empty_inspect_result(host, adapter, label, strategies);
        }
    };
    // Treat shape check failures as unparseable/empty rather than fatal CorruptedData,
    // preventing false aborts in inspect_any/smart_extract.
    if let Err(e) = header.validate_against(ube_total_size, host_len) {
        log::debug!(
            target: "structure::inspect",
            "envelope header failed the level-2 shape check: {e}"
        );
        drop(ube_stream);
        return empty_inspect_result(host, adapter, label, strategies);
    }

    let mut hint_bytes: Vec<u8> = Vec::new();
    if header.hint_len > 0 {
        hint_bytes = vec![0u8; header.hint_len as usize];
        ube_stream.read_exact(&mut hint_bytes)?;
    }
    let hint_str = if hint_bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&hint_bytes).to_string())
    };
    // The same AAD the writer sealed: header prefix + lengths + hint.
    let aad = header.auth_aad(&hint_bytes);

    let mut meta_val = None;
    if !header.is_encrypted() {
        let mut meta_bytes = vec![0u8; header.meta_len as usize];
        if ube_stream.read_exact(&mut meta_bytes).is_ok() {
            let decoded = if let Ok((_, meta_key)) = derive_keys(profile.secret(), &header.salt)
                && let Ok(dec) = decrypt_metadata(&meta_bytes, &meta_key, &header.base_nonce, &aad)
            {
                decode_metadata(&dec, header.is_compact_meta()).ok()
            } else {
                None
            };
            if let Some(meta_obj) = decoded {
                meta_val = Some(MetadataInspection::Decrypted(meta_obj));
            } else {
                log::debug!(
                    target: "structure::inspect",
                    "metadata block ({} B) present but did not decrypt/decode",
                    header.meta_len
                );
            }
        } else {
            log::debug!(
                target: "structure::inspect",
                "metadata block ({} B) could not be read",
                header.meta_len
            );
        }
    } else if let Some(pwd) = password {
        let mut meta_bytes = vec![0u8; header.meta_len as usize];
        if ube_stream.read_exact(&mut meta_bytes).is_ok()
            && let Ok((_, meta_key)) = derive_keys(pwd, &header.salt)
        {
            if let Ok(dec) = decrypt_metadata(&meta_bytes, &meta_key, &header.base_nonce, &aad) {
                if let Ok(meta_obj) = decode_metadata(&dec, header.is_compact_meta()) {
                    meta_val = Some(MetadataInspection::Decrypted(meta_obj));
                } else {
                    log::debug!(
                        target: "structure::inspect",
                        "metadata block decrypted but did not decode"
                    );
                }
            } else {
                meta_val = Some(MetadataInspection::DecryptFailed {
                    error: "Invalid password".to_string(),
                });
            }
        } else {
            log::debug!(
                target: "structure::inspect",
                "metadata block ({} B) unreadable or key derivation failed",
                header.meta_len
            );
        }
    }

    let reported_strategy = if header.strategy_id > 0 {
        StrategyId::from_u8(header.strategy_id)
    } else {
        StrategyId::from_name(&strategy_name).unwrap_or(StrategyId::from_u8(0))
    };

    Ok(InspectResult {
        carrier: PathBuf::from(label),
        format: adapter_format(adapter)?,
        has_hidden_data: true,
        strategy: Some(reported_strategy),
        ube_offset: Some(ube_offset),
        ube_total_size: Some(ube_total_size),
        is_encrypted: Some(header.is_encrypted()),
        is_compressed: Some(header.is_compressed()),
        is_stealth: Some(header.is_stealth()),
        password_hint: hint_str,
        orig_host_size: Some(header.orig_host_size),
        orig_host_sha256: Some(
            header
                .orig_host_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        ),
        metadata: meta_val,
        suspicious_hints: Vec::new(),
        strategies,
    })
}

/// Run three independent checks against a carrier: host structure integrity,
/// envelope boundary/CRC validity, and payload decrypt + SHA-256 match.
///
/// Does not modify the carrier. The returned [`VerifyResult`] reports each
/// level separately so a caller can distinguish "the file is structurally
/// fine" from "the payload does not decrypt".
pub fn verify_carrier(
    carrier_path: &Path,
    password: Option<&str>,
) -> Result<VerifyResult, StrHideError> {
    verify_carrier_with(carrier_path, password, &StructureProfile::default())
}

/// Verify a carrier written under `profile`.
///
/// Level 1 (host structure) is dialect-independent; levels 2 and 3 need the
/// same profile used at write time.
pub fn verify_carrier_with(
    carrier_path: &Path,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<VerifyResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let mut cf = File::open(carrier_path)?;
    verify_core(
        &mut cf,
        &carrier_path.display().to_string(),
        password,
        profile,
    )
}

/// Verify an in-memory carrier, using the same dialect resolution as
/// [`verify_carrier_with`].
pub fn verify_carrier_bytes(
    carrier: &[u8],
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<VerifyResult, StrHideError> {
    let mut host = Cursor::new(carrier);
    verify_core(&mut host, "<memory>", password, profile)
}

/// Cross-check the header's injection coordinates against the located envelope.
///
/// Validates that the header's injection coordinates match the located envelope
/// to detect header/body mismatches early during verification rather than during removal.
///
/// These four fields are the only header bytes the AEAD cannot cover: they are
/// filled in after the injector has run, i.e. after the metadata block and every
/// payload chunk were sealed (see `EnvelopeHeader`). Nothing here is trusted on
/// its own, though: `offset_delta` *is* inside the AAD, the envelope end is
/// pinned to the physical file by `confine_location`, and a wrong answer here
/// makes `remove` reproduce a carrier whose SHA-256 mismatches the
/// authenticated `orig_host_sha256`.
///
/// Relationships used, all of which hold for every registered strategy:
/// the envelope starts `offset_delta` bytes after the injection point, the
/// injected region is at least as large as the envelope it wraps (strategies
/// add container headers), and the whole region lies inside the file.
fn envelope_coordinates_agree(
    header: &EnvelopeHeader,
    strategy: &str,
    ube_offset: u64,
    ube_total_size: u64,
    file_len: u64,
) -> Result<(), String> {
    // Scattered strategies (`pe_codebits`) record 0/0 by definition as payloads are
    // distributed rather than contiguous. Both caller strategy and header id must
    // agree on `pe_codebits` to prevent contiguous strategies from bypassing coordinate checks.
    if cfg!(feature = "structure-pe")
        && strategy == "pe_codebits"
        && crate::structure::registry::id_to_strategy(header.strategy_id) == strategy
    {
        return Ok(());
    }
    let expected_offset = header
        .inject_offset
        .checked_add(header.offset_delta as u64)
        .ok_or_else(|| {
            format!(
                "Header injection offset {} overflows once its {}-byte displacement is applied",
                header.inject_offset, header.offset_delta
            )
        })?;
    // PNG `chunk`, appended EOF envelopes and MKV `ebml_void` can be physically
    // relocated by content-domain embedding or an external remux: re-compressing
    // IDAT (or re-encoding the media) changes the length of the stream before the
    // envelope, so the trailer still carries the write-time coordinate. The
    // trailer and header are authenticated, and MKV's `locate` resolves the void
    // block from the tail precisely so this shift is tolerated, so accept it and
    // bound the relocated region against EOF. Every other strategy is anchored at
    // write time and a mismatch is corruption.
    let relocated = expected_offset != ube_offset;
    if relocated && !relocatable_strategy(strategy) {
        return Err(format!(
            "Header coordinates disagree with the envelope: inject_offset {} + delta {} = {}, \
             but the envelope sits at {}",
            header.inject_offset, header.offset_delta, expected_offset, ube_offset
        ));
    }
    if ube_total_size > header.inject_size {
        return Err(format!(
            "Envelope size {ube_total_size}B exceeds the injected region of {}B",
            header.inject_size
        ));
    }
    let injected_end = if relocated {
        let wrapped = header
            .inject_size
            .checked_sub(header.offset_delta as u64)
            .ok_or_else(|| "Header displacement exceeds injected region".to_string())?;
        ube_offset
            .checked_add(wrapped)
            .ok_or_else(|| "Relocated injection region overflows".to_string())?
    } else {
        header
            .inject_offset
            .checked_add(header.inject_size)
            .ok_or_else(|| "Header injection region overflows".to_string())?
    };
    if injected_end > file_len {
        return Err(format!(
            "Header places the injected region at [{}..{}], past the end of the {file_len}B file",
            header.inject_offset, injected_end
        ));
    }
    Ok(())
}

fn attempt_l1(
    host: &mut dyn SeekRead,
    adapter: &dyn HostAdapter,
    magic: Option<&[u8; 4]>,
) -> Result<(bool, String), StrHideError> {
    host.seek(SeekFrom::Start(0))?;
    adapter.verify_structure_with_magic(host, magic)
}

/// Level 1 with every dialect the caller could be verifying: the profile's
/// own magic, the standard magic, and — only when a password is available —
/// the password-derived stealth magic. EOF-overlay formats need the right
/// trailer magic to step over the envelope; trying them in order avoids a
/// false "corrupted host" for stealth/private carriers.
fn verify_structure_for_dialects(
    host: &mut dyn SeekRead,
    adapter: &dyn HostAdapter,
    password: Option<&str>,
    profile: &StructureProfile,
    known_stealth_trailer_magic: Option<[u8; 4]>,
) -> Result<(bool, String), StrHideError> {
    if let Some(magic) = profile.locator_magic() {
        let result = attempt_l1(host, adapter, Some(magic))?;
        if result.0 {
            return Ok(result);
        }
    }
    let mut last = attempt_l1(host, adapter, None)?;
    if last.0 {
        return Ok(last);
    }
    let stealth_trailer_magic = match known_stealth_trailer_magic {
        Some(magic) => Some(magic),
        None => match password {
            Some(pwd) => Some(derive_stealth_magics(pwd, profile.domain())?.1),
            None => None,
        },
    };
    if let Some(magic) = stealth_trailer_magic {
        let result = attempt_l1(host, adapter, Some(&magic))?;
        if result.0 {
            return Ok(result);
        }
        last = result;
    }
    Ok(last)
}

fn verify_core(
    host: &mut dyn SeekRead,
    label: &str,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<VerifyResult, StrHideError> {
    let password = password.filter(|s| !s.is_empty());
    host.seek(SeekFrom::Start(0))?;
    let adapter = find_adapter_or_reject(host, label)?;

    // Needed by Level 2 to bound the injection coordinates the header claims.
    // Captured before the envelope reader borrows `host`.
    let file_len = host.seek(SeekFrom::End(0))?;

    // A single locate scan feeds Level 1's stealth trailer magic, Level 2's
    // header unpack and its trailer check, and Level 3's authentication.
    // Secrets are derived once to avoid redundant PBKDF2 runs during verification.
    let Located {
        location,
        stealth_header_magic,
        stealth_trailer_magic,
    } = locate_envelope_with_magic(host, adapter, password, profile)?;

    // Level 1: Host format integrity
    let (l1_ok, l1_msg) =
        verify_structure_for_dialects(host, adapter, password, profile, stealth_trailer_magic)?;

    let LocatedEnvelope {
        offset: ube_offset,
        size: ube_total_size,
        strategy: strategy_name,
    } = match location {
        Some(l) => l,
        None => {
            return Ok(VerifyResult {
                carrier: PathBuf::from(label),
                format: adapter_format(adapter)?,
                level1_host: LevelStatus {
                    ok: l1_ok,
                    detail: l1_msg,
                    skipped: false,
                },
                level2_envelope: LevelStatus::fail("No envelope found"),
                level3_crypto: LevelStatus::skipped("Skipped (no envelope)"),
            });
        }
    };

    let mut secrets: Option<UnpackSecrets> = None;
    let (l2_ok, l2_msg, is_encrypted) = {
        match adapter.open_ube_reader(host, ube_offset, ube_total_size, &strategy_name) {
            Err(e) => (false, format!("Cannot open envelope reader: {e}"), false),
            Ok(mut ube_stream) => {
                let mut header_bytes = [0u8; HEADER_SIZE];
                if ube_stream.read_exact(&mut header_bytes).is_err() {
                    (false, "Cannot read header".into(), false)
                } else {
                    // Derive once for Level 2 and hand the same material to
                    // Level 3; `open_authenticated_at` would otherwise repeat
                    // PBKDF2 over the identical (password, salt) pair.
                    let salt = EnvelopeHeader::salt_of(&header_bytes).unwrap_or([0u8; 16]);
                    let built = UnpackSecrets::derive_attempts(
                        password,
                        &salt,
                        profile,
                        stealth_header_magic,
                    )?;
                    // Cloned once: `UnpackSecrets` is not `Copy` any more, and
                    // the verify path keeps its own copy for Level 3.
                    secrets = Some(built.clone());

                    match EnvelopeHeader::unpack_with_secrets(
                        &header_bytes,
                        password,
                        profile,
                        &built,
                    ) {
                        Err(e) => {
                            log::debug!(
                                target: "structure::verify",
                                "envelope header unpacking failed: {e}"
                            );
                            (
                                false,
                                format!("Envelope header unpacking failed: {e}"),
                                false,
                            )
                        }
                        Ok(header) => {
                            // Validate header field ranges against the located
                            // envelope size (version / hint_len / meta_len
                            // consistency) before trusting any downstream reads —
                            // a crafted or corrupted header must fail Level 2 with
                            // a domain error instead of being silently accepted.
                            if let Err(e) = header.validate_against(ube_total_size, file_len) {
                                (
                                    false,
                                    format!("Envelope header validation failed: {e}"),
                                    false,
                                )
                            } else if let Err(msg) = envelope_coordinates_agree(
                                &header,
                                &strategy_name,
                                ube_offset,
                                ube_total_size,
                                file_len,
                            ) {
                                (false, msg, header.is_encrypted())
                            } else if ube_stream
                                .seek(SeekFrom::Start(ube_total_size - 24))
                                .is_err()
                            {
                                (
                                    false,
                                    "Cannot seek to trailer".into(),
                                    header.is_encrypted(),
                                )
                            } else {
                                let mut trailer_bytes = [0u8; 24];
                                // Stealth: the locator already derived this magic.
                                // Official dialect: `None` keeps the legacy magics
                                // acceptable. Private dialect: only its own magic.
                                let expected_trailer_magic = if header.is_stealth() {
                                    stealth_trailer_magic
                                } else {
                                    profile.locator_magic().copied()
                                };

                                if ube_stream.read_exact(&mut trailer_bytes).is_err() {
                                    (false, "Cannot read trailer".into(), header.is_encrypted())
                                } else if let Ok(trailer) = EnvelopeTrailer::unpack(
                                    &trailer_bytes,
                                    expected_trailer_magic.as_ref(),
                                ) {
                                    // The trailer provides magic + CRC32 verification; physical coordinate checks
                                    // are enforced via authenticated offset_delta and confine_location above.
                                    // A relocated PNG chunk envelope preserves its write-time ube_offset in the trailer,
                                    // so coordinate validation is handled in envelope_coordinates_agree.
                                    debug_assert_eq!(trailer.ube_total_size, ube_total_size);
                                    let _ = &trailer;
                                    (
                                        true,
                                        format!(
                                            "Envelope valid at offset {ube_offset}, size {ube_total_size}B (CRC32 OK)"
                                        ),
                                        header.is_encrypted(),
                                    )
                                } else {
                                    (
                                        false,
                                        "Envelope trailer unpacking failed".into(),
                                        header.is_encrypted(),
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    // Level 3: Crypto & payload SHA-256.
    //
    // "No password was supplied" is a *skipped* level, not a failure: the
    // caller could not have checked, and exit code 0 used to hide the case that
    // *did* run and failed (wrong password, corrupted payload) behind the same
    // boolean as this one.
    let l3 = if !is_encrypted || password.is_some() {
        match open_authenticated_at(
            host,
            adapter,
            LocatedEnvelope {
                offset: ube_offset,
                size: ube_total_size,
                strategy: strategy_name,
            },
            password,
            profile,
            stealth_header_magic,
            secrets.as_ref(),
        ) {
            Ok(mut env) => match verify_authenticated_payload(&mut env) {
                Ok(raw_size) => LevelStatus::pass(format!(
                    "Decryption and SHA-256 verified successfully (payload {raw_size} bytes)"
                )),
                Err(e) => LevelStatus::fail(e.to_string()),
            },
            Err(e) => LevelStatus::fail(e.to_string()),
        }
    } else {
        LevelStatus::skipped("Password required for cryptographic verification")
    };

    Ok(VerifyResult {
        carrier: PathBuf::from(label),
        format: adapter_format(adapter)?,
        level1_host: LevelStatus {
            ok: l1_ok,
            detail: l1_msg,
            skipped: false,
        },
        level2_envelope: LevelStatus {
            ok: l2_ok,
            detail: l2_msg,
            skipped: false,
        },
        level3_crypto: l3,
    })
}

#[cfg(test)]
#[path = "engine_tests/compact_meta_tests.rs"]
mod compact_meta_tests;

#[cfg(test)]
#[path = "engine_tests/envelope_coordinate_tests.rs"]
mod envelope_coordinate_tests;

#[cfg(test)]
#[path = "engine_tests/pbkdf2_budget_tests.rs"]
mod pbkdf2_budget_tests;
