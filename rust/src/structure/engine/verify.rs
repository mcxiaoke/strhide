//! Verify pipeline: host structure, envelope validity and payload crypto.

use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::locate::{Located, adapter_format, locate_envelope_with_magic};
use super::read::{open_authenticated_at, verify_authenticated_payload};
use super::remove::relocatable_strategy;
use super::report::{LevelStatus, VerifyResult};
use crate::crypto::derive_stealth_magics;
use crate::errors::StrHideError;
use crate::structure::adapters::{HostAdapter, LocatedEnvelope, SeekRead};
use crate::structure::envelope::{EnvelopeHeader, EnvelopeTrailer, HEADER_SIZE, UnpackSecrets};
use crate::structure::params::StructureProfile;
use crate::structure::registry::find_adapter_or_reject;

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
pub(super) fn envelope_coordinates_agree(
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
