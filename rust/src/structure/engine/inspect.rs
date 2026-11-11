//! Inspect pipeline: report format, envelope, metadata and strategy capacity.

use std::fs::File;
use std::io::{Cursor, Read, SeekFrom};
use std::path::{Path, PathBuf};

use super::capacity::apply_engine_payload_limit;
use super::locate::{adapter_format, locate_envelope};
use super::metadata::{MetadataInspection, decode_metadata};
use super::report::InspectResult;
use crate::crypto::{decrypt_metadata, derive_keys};
use crate::errors::StrHideError;
use crate::structure::adapters::{HostAdapter, SeekRead, StrategyCapacity};
use crate::structure::envelope::{EnvelopeHeader, HEADER_SIZE};
use crate::structure::params::StructureProfile;
use crate::structure::registry::{StrategyId, find_adapter_or_reject};

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
