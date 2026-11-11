//! Read/extract pipeline: locate, unpack, authenticate and decrypt.

use std::fs::File;
use std::io::{Cursor, Read, SeekFrom};
use std::path::{Path, PathBuf};

use super::capacity::structure_payload_limit;
use super::locate::{Located, locate_envelope_with_magic, no_hidden_data_error};
use super::metadata::{CarrierMetadata, decode_metadata};
use super::report::ReadResult;
use crate::crypto::{decompress_stream, decrypt_metadata, decrypt_stream_from_chunks, derive_keys};
use crate::errors::StrHideError;
use crate::structure::adapters::{HostAdapter, LocatedEnvelope, SeekRead};
use crate::structure::envelope::{EnvelopeHeader, HEADER_SIZE, TRAILER_SIZE, UnpackSecrets};
use crate::structure::options::ReadOptions;
use crate::structure::params::StructureProfile;
use crate::structure::registry::find_adapter_or_reject;

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
/// Deliberately I/O-free: the same core serves [`read_carrier_with_dialect`]
/// (path in, path out) and [`read_carrier_bytes`] (bytes in, bytes out), so the
/// two can never drift apart on envelope parsing.
struct ReadCore {
    data: Vec<u8>,
    is_file: bool,
    is_encrypted: bool,
    filename: String,
    raw_size: u64,
}

pub(super) struct AuthenticatedEnvelope<'a> {
    ube_stream: Box<dyn SeekRead + 'a>,
    pub(super) header: EnvelopeHeader,
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
pub(super) fn open_authenticated_at<'a>(
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
        super::sanitize_filename(&env.meta_obj.filename)
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
pub(super) fn verify_authenticated_payload(
    env: &mut AuthenticatedEnvelope<'_>,
) -> Result<u64, StrHideError> {
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
            super::sanitize_filename(&core.filename)
        };
        out_p.join(fn_to_use)
    } else {
        out_p.to_path_buf()
    };

    // Writing the payload over its own carrier truncates the file that still
    // holds the hidden data, so the extraction would destroy its own source.
    if crate::commit::same_file(&final_dest, carrier_path) {
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
