//! Write pipeline: payload preparation, host checks, injection and commit.
//!
//! Path-shaped concerns (rejection checks, temp file, atomic rename, backup,
//! timestamp/permission cloning) live in the public entry points here; the
//! protocol itself is [`write_core`], which knows nothing about paths.

use std::borrow::Cow;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngExt;

use super::capacity::structure_payload_limit;
use super::metadata::{CarrierMetadata, encode_metadata};
use super::report::{PayloadSource, Warning, WriteResult};
use crate::commit::{TmpGuard, create_temp_file_for};
use crate::crypto::{
    compress_stream, derive_all, derive_stealth_magics, encrypt_metadata, encrypt_stream_to_chunks,
    normalize_nfc,
};
use crate::errors::StrHideError;
use crate::formats::FileFormat;
use crate::params::LocalParams;
use crate::structure::adapters::{FinalizeCtx, HostAdapter, TrailerCtx};
use crate::structure::envelope::{
    EnvelopeHeader, EnvelopeTrailer, FLAG_COMPACT_META, FLAG_COMPRESSED, FLAG_ENCRYPTED,
    FLAG_HAS_HINT, FLAG_IS_FILE, FLAG_STEALTH, HEADER_SIZE, TRAILER_SIZE,
};
use crate::structure::options::WriteOptions;
use crate::structure::params::StructureProfile;
use crate::structure::registry::{StrategyId, find_adapter_or_reject, strategy_to_id};
use crate::structure::rejection::run_rejection_checks;

/// Inject `source` into `carrier_path`, returning a [`WriteResult`].
///
/// # Parameters
///
/// - `carrier_path`: an existing supported carrier (PNG/JPEG/MP4/ZIP/PDF/PE).
/// - `source`: where the payload comes from (bytes, file, text, or stdin) —
///   see [`PayloadSource`].
/// - `options`: see [`WriteOptions`]. The defaults match the CLI defaults.
///
/// # Errors
///
/// Returns [`StrHideError::Rejection`] for pre-write safety failures
/// (signed carrier, read-only target), [`StrHideError::General`] for bad
/// arguments or an already-populated carrier, and [`StrHideError::Io`] for
/// filesystem problems. On any error the carrier is left untouched.
///
/// # Examples
///
/// ```no_run
/// use strhide::structure::{write_carrier, PayloadSource, WriteOptions};
/// # fn main() -> Result<(), strhide::errors::StrHideError> {
/// write_carrier(
///     std::path::Path::new("photo.png"),
///     PayloadSource::Text("secret"),
///     &WriteOptions::default().with_password("pw"),
/// )?;
/// # Ok(()) }
/// ```
pub fn write_carrier(
    carrier_path: &Path,
    source: PayloadSource,
    options: &WriteOptions<'_>,
) -> Result<WriteResult, StrHideError> {
    write_carrier_with(
        carrier_path,
        source,
        options,
        &LocalParams::default(),
        &StructureProfile::default(),
    )
}

/// Inject `source` into `carrier_path` with library-level tuning.
///
/// Same as [`write_carrier`], plus:
///
/// - `local`: writer-only knobs ([`LocalParams`]) that the reader never needs.
///   Passing different values than the reader uses is safe.
/// - `dialect`: the private dialect ([`StructureProfile`]). The reader must be
///   given the same dialect; `StructureProfile::default()` is the official one.
///
/// ```no_run
/// use strhide::structure::params::StructureProfile;
/// use strhide::structure::{PayloadSource, WriteOptions, write_carrier_with};
/// use strhide::params::{CompressionStrategy, LocalParams};
/// # fn main() -> Result<(), strhide::errors::StrHideError> {
/// // Both types are `#[non_exhaustive]`: build from `default()` with setters.
/// let dialect = StructureProfile::default().with_default_secret("my-private-dialect");
/// let local = LocalParams::default()
///     .with_chunk_size(64 * 1024)
///     .with_compression(CompressionStrategy::Never);
/// write_carrier_with(
///     std::path::Path::new("photo.png"),
///     PayloadSource::Text("secret"),
///     &WriteOptions::default(),
///     &local,
///     &dialect,
/// )?;
/// # Ok(()) }
/// ```
/// Everything a write produces that does not depend on a path.
struct WriteCoreResult {
    format: FileFormat,
    strategy: StrategyId,
    strategy_note: Option<String>,
    raw_size: u64,
    ube_size: u64,
    is_encrypted: bool,
    is_stealth: bool,
    warnings: Vec<Warning>,
}

/// Build and inject an envelope from `host` into `out`.
///
/// This is the whole protocol, with no filesystem opinions: no existence check,
/// no permission probe, no `.bak`, no atomic rename, no timestamp cloning, and
/// no rejection checks (the caller owns those, because two of them are
/// path-based). [`write_carrier_with`] and [`write_carrier_bytes`] differ only
/// in the I/O objects they hand in and the side effects they add around it.
///
/// `H`/`W` are sized generics rather than `&mut dyn ...`: the adapters take
/// `&mut dyn Write` / `&mut dyn SeekRead`, and passing a concrete type through
/// avoids relying on trait-object upcasting.
fn write_core<H, W>(
    host: &mut H,
    out: &mut W,
    source: PayloadSource,
    options: &WriteOptions<'_>,
    local: &LocalParams,
    profile: &StructureProfile,
    carrier_label: &str,
) -> Result<WriteCoreResult, StrHideError>
where
    H: Read + Seek,
    W: Read + Write + Seek,
{
    local.validate()?;
    // An empty string means "no password", matching the content domain: a
    // caller who passes `Some("")` must not get a stealth envelope derived from
    // an empty secret.
    let password = options.password.filter(|s| !s.is_empty());
    let password_hint = options.password_hint;
    let strategy = options.strategy;
    let stealth = options.stealth;

    if password_hint.is_some() && stealth {
        return Err(StrHideError::General(
            "Password hint is not supported in --stealth mode (stealth mode requires password to locate envelope).".into(),
        ));
    }

    // Stealth mode derives its magics from the password; without a password the
    // envelope would silently degrade to the standard (plaintext-magic) mode,
    // which contradicts the user's stealth expectation. Fail fast instead.
    if stealth && password.is_none() {
        return Err(StrHideError::General(
            "Stealth mode requires a password (provide -p/--password, --password-file, or STRHIDE_PASSWORD).".into(),
        ));
    }

    let hint_bytes = if let Some(hint) = password_hint {
        let norm_hint = normalize_nfc(hint.trim());
        let bytes = norm_hint.into_bytes();
        if bytes.len() > 1024 {
            return Err(StrHideError::General(
                "Password hint cannot exceed 1024 bytes".into(),
            ));
        }
        bytes
    } else {
        Vec::new()
    };

    // 2. Capture carrier facts that live in the envelope: size and full SHA-256.
    // The file variant cannot get these from fs::metadata alone (the hash needs
    // a read pass anyway), so both variants derive them from the stream.
    host.seek(SeekFrom::End(0))?;
    let orig_host_size = host.stream_position()?;
    host.seek(SeekFrom::Start(0))?;
    let orig_host_sha256 = crate::crypto::compute_stream_sha256(host)?;

    // 3. Detect adapter & check existing envelope
    host.seek(SeekFrom::Start(0))?;
    let adapter = find_adapter_or_reject(host, carrier_label)?;

    // 3a. Refuse malformed hosts before touching them. Detection is deliberately
    // cheap (a JPEG is "anything starting with FF D8"), so without this a
    // truncated or forged header followed by arbitrary bytes used to be turned
    // into a stego carrier by the `auto` -> `eof` fallback: strhide would report
    // success while the output was no longer a valid container. Only recognized
    // formats reach this point (unknown files are already rejected), and each
    // adapter's verifier accepts plain, un-stegoed carriers.
    // Derive once: the pre-write verifier needs the same magic the new
    // envelope will use, and the occupied scans below reuse the pair.
    let stealth_magics = match password {
        Some(pwd) => Some(derive_stealth_magics(pwd, profile.domain())?),
        None => None,
    };
    let write_trailer_magic = if stealth {
        stealth_magics.as_ref().map(|m| &m.1)
    } else {
        profile.locator_magic()
    };
    let structural_warnings = ensure_writable_host(
        host,
        adapter,
        profile,
        stealth_magics.as_ref(),
        write_trailer_magic,
    )?;

    // 4. Prepare data payload stream
    let PreparedPayload {
        bytes: to_encrypt_bytes,
        filename,
        is_file,
        raw_size,
        raw_sha256,
        is_compressed,
    } = prepare_write_payload(source, local, orig_host_size)?;

    // 6. Keys and Magics
    // `FLAG_ENCRYPTED` means "a user password is required", not "the payload is
    // encrypted": with a private `default_secret` the payload is still sealed
    // (under that secret) but the flag stays clear, so the reader knows not to
    // demand a password and instead uses the profile's secret.
    let has_custom_password = password.is_some();
    let effective_password = password.unwrap_or(profile.secret());
    let mut flags: u8 = 0;
    if has_custom_password {
        flags |= FLAG_ENCRYPTED;
    }
    if is_compressed {
        flags |= FLAG_COMPRESSED;
    }
    if is_file {
        flags |= FLAG_IS_FILE;
    }
    if !hint_bytes.is_empty() {
        flags |= FLAG_HAS_HINT;
    }

    let mut salt = [0u8; 16];
    let mut base_nonce = [0u8; 12];
    rand::rng().fill(&mut salt);
    rand::rng().fill(&mut base_nonce);
    // Payload key, metadata key and header mask are three HKDF expansions of
    // one PBKDF2 output, so they are derived together: a write used to run
    // PBKDF2 twice for the same (password, salt) pair.
    let secrets = derive_all(effective_password, &salt)?;
    let (payload_key, meta_key) = (secrets.payload_key, secrets.meta_key);
    // The mask only applies when the keying secret is the profile default
    // (no user password) or when stealth mode uses the user password. A
    // non-stealth encrypted header stays readable on purpose: without that, a
    // reader given no password could not tell an encrypted envelope from a
    // corrupted file, and the password hint would be unreachable. Its integrity
    // does not depend on the mask -- `EnvelopeHeader::auth_aad` binds the
    // header prefix, the two lengths and the hint into every AEAD seal.
    let header_mask = if !has_custom_password || stealth {
        Some(secrets.header_mask)
    } else {
        None
    };

    let header_magic: [u8; 8];
    let trailer_magic: [u8; 4];

    if stealth && has_custom_password {
        flags |= FLAG_STEALTH;
        let magics = stealth_magics.expect("stealth requires password");
        header_magic = magics.0;
        trailer_magic = magics.1;
    } else {
        // The profile decides the dialect; `StructureProfile::default()` yields the
        // standard magics, byte-identical to every earlier release.
        header_magic = profile.header_magic();
        trailer_magic = profile.trailer_magic();
    }

    // 7. Metadata Block
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let meta_obj = CarrierMetadata {
        filename,
        raw_size,
        raw_sha256,
        created_at,
    };
    // The compact binary block is the only metadata layout; `FLAG_COMPACT_META`
    // is therefore always set and must be in place before the AAD is captured.
    let meta_raw = encode_metadata(&meta_obj)?;
    flags |= FLAG_COMPACT_META;

    // Exact UBE size, computed before any strategy decision. All components are
    // deterministic at this point:
    //   meta_len      = len(meta_raw) + (16 if encrypted else 0)
    //   payload_len   = to_encrypt_len + chunks * 20 if encrypted else to_encrypt_len
    //                    (each encrypted chunk is 4B length + ciphertext + 16B tag;
    //                     an empty payload still emits one empty final chunk)
    // This eliminates the previous under-estimate (4B per chunk) that made the
    // JPEG/PNG/ZIP `auto` capacity checks select a strategy the injector then
    // rejected instead of gracefully falling back to `eof`.
    let to_encrypt_len = to_encrypt_bytes.len() as u64;
    let exact_meta_len = meta_raw.len() as u64 + crate::crypto::AEAD_TAG_LEN as u64;
    // Must use the *configured* chunk size: `exact_ube_size` is cross-checked
    // against the real ciphertext length, so a mismatch here would fail-fast.
    let exact_payload_len = crate::crypto::framed_len(to_encrypt_len, local.chunk_size);
    let exact_ube_size = HEADER_SIZE as u64
        + hint_bytes.len() as u64
        + exact_meta_len
        + exact_payload_len
        + TRAILER_SIZE as u64;

    let selected_strategy: String = if strategy == "auto" {
        host.seek(SeekFrom::Start(0))?;
        adapter
            .choose_auto_strategy(host, exact_ube_size)
            .to_string()
    } else {
        if !adapter.supported_strategies().contains(&strategy) {
            return Err(StrHideError::General(format!(
                "Strategy '{strategy}' not supported by adapter '{}'",
                adapter.format_name()
            )));
        }
        strategy.to_string()
    };

    // 8. Populate Header structure
    let strat_id = strategy_to_id(&selected_strategy)?;
    // Where the envelope lands relative to the injection point. Strategies
    // that prepend a container header (PNG chunk, JPEG APP15 segment, ISO-BMFF
    // box, EBML Void, PDF object) shift it by 4..32 bytes. The shift only
    // depends on the strategy and the envelope size, so it is computed *before*
    // the header is sealed and therefore protected inside the AAD.
    let offset_delta = {
        host.seek(SeekFrom::Start(0))?;
        adapter.envelope_offset_delta(host, &selected_strategy, exact_ube_size)?
    };
    if offset_delta > crate::structure::envelope::MAX_OFFSET_DELTA as u64 {
        return Err(StrHideError::General(format!(
            "Strategy '{selected_strategy}' displaces the envelope by {offset_delta} bytes, which \
             exceeds the {} bytes the header can record",
            crate::structure::envelope::MAX_OFFSET_DELTA
        )));
    }
    let offset_delta_u8 = offset_delta as u8;
    let exact_meta_len_u32 = u32::try_from(exact_meta_len).map_err(|_| {
        StrHideError::General("Metadata block exceeds the 4 GiB envelope field".into())
    })?;
    let mut header = EnvelopeHeader {
        magic_header: header_magic,
        flags,
        strategy_id: strat_id,
        offset_delta: offset_delta_u8,
        salt,
        base_nonce,
        orig_host_size,
        orig_host_sha256,
        hint_len: hint_bytes.len() as u32,
        // The metadata ciphertext length is `plaintext + tag`, both known here,
        // so the field can be filled *before* the seal and take part in the AAD.
        meta_len: exact_meta_len_u32,
        ..Default::default()
    };

    // The authenticated set: header prefix, the two length fields and the hint
    // body. Everything in it is known before the first byte is sealed, and
    // everything a reader must trust before it can check a tag is in it.
    let aad = header.auth_aad(&hint_bytes);

    // Encrypt metadata
    let meta_block = encrypt_metadata(&meta_raw, &meta_key, &base_nonce, &aad)?;
    // `meta_len` was sealed into the AAD above, so a length that disagreed with
    // reality would emit an envelope whose header, metadata block and AAD no
    // longer line up. Fail loudly instead of trusting the pre-computation.
    if meta_block.len() as u64 != exact_meta_len {
        return Err(StrHideError::General(format!(
            "Internal metadata size mismatch: sealed {} bytes, header declares {exact_meta_len}",
            meta_block.len()
        )));
    }

    // Assemble the UBE prefix first, then append the ciphertext directly into
    // the same buffer. The old path encrypted into a second full-size Vec and
    // then copied it into the envelope, so plaintext, ciphertext and envelope
    // were all resident at once (~3x the payload).
    let mut tmp_ube = Vec::with_capacity(exact_ube_size as usize);
    tmp_ube.extend_from_slice(&header.pack_masked(header_mask.as_ref()));
    if !hint_bytes.is_empty() {
        tmp_ube.extend_from_slice(&hint_bytes);
    }
    tmp_ube.extend_from_slice(&meta_block);

    // Encrypt payload stream directly into the envelope buffer.
    let payload_written = encrypt_stream_to_chunks(
        &mut Cursor::new(&to_encrypt_bytes),
        &mut tmp_ube,
        &payload_key,
        &base_nonce,
        &aad,
        local.chunk_size,
    )?;
    // Release the plaintext before the injector reads the envelope: only the
    // ciphertext copy is needed from here on.
    drop(to_encrypt_bytes);

    let ube_total_size = HEADER_SIZE as u64
        + hint_bytes.len() as u64
        + header.meta_len as u64
        + payload_written
        + TRAILER_SIZE as u64;

    // Defensive cross-check: the exact pre-computation above must match reality.
    // A mismatch would indicate a protocol drift between crypto and engine.
    if ube_total_size != exact_ube_size {
        return Err(StrHideError::General(format!(
            "Internal envelope size mismatch: computed {ube_total_size}, expected {exact_ube_size}"
        )));
    }

    // Non-fatal warnings. Both can fire for one write, so they are collected
    // instead of being merged into one sentence.
    let mut warnings = Vec::new();
    if orig_host_size > 0 && ube_total_size > (orig_host_size / 2) {
        let ratio_pct = (ube_total_size as f64 / orig_host_size as f64) * 100.0;
        // State the measured ratio and refer to the threshold separately. The
        // old text hard-coded "exceeds 50.0%" next to the real percentage,
        // which read like a contradiction for tiny carriers (e.g. "50.0% ...
        // 319.4%").
        warnings.push(Warning::SizeInflation {
            ube_size: ube_total_size,
            host_size: orig_host_size,
            ratio_pct,
        });
    }
    // Probable pre-existing stealth envelope.
    if !structural_warnings.is_empty() {
        warnings.push(Warning::SuspiciousStructures {
            hints: structural_warnings.clone(),
        });
    }

    // Finish the envelope: the dummy trailer carries placeholder coordinates
    // that are patched into the written file after injection.
    let dummy_trailer = if stealth && has_custom_password {
        EnvelopeTrailer::create_stealth(0, ube_total_size, trailer_magic)
    } else {
        EnvelopeTrailer::create(0, ube_total_size, trailer_magic)
    };
    tmp_ube.extend_from_slice(&dummy_trailer.pack());

    // 9. Inject into `out`. Where that is (temp file vs memory buffer, and the
    // atomic-rename dance around it) is the caller's business.
    let coordinates = {
        host.seek(SeekFrom::Start(0))?;
        let mut ube_cursor = Cursor::new(&tmp_ube);
        adapter.inject(host, &mut ube_cursor, out, &selected_strategy)?
    };
    let (inject_offset, inject_size) = (coordinates.offset, coordinates.size);
    let (patch_offset, orig_patch_val) =
        (coordinates.patch_offset, coordinates.original_patch_value);

    // 10. Update real ube_offset in Header and Trailer.
    //
    // The shift was computed before the header was sealed (it is part of the
    // AAD), so this only applies it. Recomputing it here would let the two
    // disagree silently; the debug assertion keeps the pre-computation honest.
    debug_assert_eq!(
        {
            host.seek(SeekFrom::Start(0))?;
            offset_delta
        },
        adapter
            .envelope_offset_delta(host, &selected_strategy, ube_total_size)
            .unwrap_or(u64::MAX),
        "envelope offset delta changed between pre-seal and post-inject"
    );
    let actual_ube_offset = inject_offset + offset_delta;

    header.inject_offset = inject_offset;
    header.inject_size = inject_size;
    header.patch_offset = patch_offset;
    header.orig_patch_val = orig_patch_val;

    let final_trailer = if stealth && has_custom_password {
        EnvelopeTrailer::create_stealth(actual_ube_offset, ube_total_size, trailer_magic)
    } else {
        EnvelopeTrailer::create(actual_ube_offset, ube_total_size, trailer_magic)
    };

    // Scattered strategies (pe_codebits) embed the final envelope bytes during
    // inject(): inject_offset/inject_size are 0 by definition and the trailer
    // was assembled with ube_offset = 0, so there is nothing to patch at file
    // offsets. Patching anyway would overwrite host bytes (offset 0 is the MZ
    // header of a PE).
    finish_injection(
        out,
        adapter,
        &header,
        header_mask.as_ref(),
        &final_trailer,
        &selected_strategy,
        actual_ube_offset,
        ube_total_size,
        InjectionPlacement {
            offset: inject_offset,
            size: inject_size,
        },
        &trailer_magic,
    )?;

    let strategy_note = adapter.strategy_note(&selected_strategy, strategy == "auto");

    Ok(WriteCoreResult {
        format: FileFormat::from_adapter_name(adapter.format_name())
            .expect("every registered adapter maps to a FileFormat"),
        strategy: StrategyId::from_name(&selected_strategy)
            .expect("the selected strategy comes from STRATEGY_REGISTRY"),
        strategy_note,
        raw_size,
        ube_size: ube_total_size,
        is_encrypted: has_custom_password,
        is_stealth: (flags & FLAG_STEALTH) != 0,
        warnings,
    })
}

/// Verify that `host` is a well-formed carrier with no existing envelope.
///
/// Runs the adapter's structural verification, both magic scans (the
/// profile's own magic, then the official one for a private dialect, then the
/// password-derived stealth magic when available) and finally the structural
/// hints. Returns those hints; they are warnings, not refusals, because a
/// stealth envelope written with an unknown password is invisible to a magic
/// scan.
fn ensure_writable_host<H>(
    host: &mut H,
    adapter: &dyn HostAdapter,
    profile: &StructureProfile,
    stealth_magics: Option<&([u8; 8], [u8; 4])>,
    write_trailer_magic: Option<&[u8; 4]>,
) -> Result<Vec<String>, StrHideError>
where
    H: Read + Seek,
{
    host.seek(SeekFrom::Start(0))?;
    let (structure_ok, detail) = adapter.verify_structure_with_magic(host, write_trailer_magic)?;
    if !structure_ok {
        return Err(StrHideError::CorruptedData(format!(
            "Refusing to write into a malformed {} carrier: {}",
            adapter.format_name(),
            detail
        )));
    }

    let mut occupied = {
        host.seek(SeekFrom::Start(0))?;
        adapter.locate(host, profile.locator_magic())?.is_some()
    };
    if !occupied && profile.locator_magic().is_some() {
        host.seek(SeekFrom::Start(0))?;
        occupied = adapter.locate(host, None)?.is_some();
    }
    if occupied {
        return Err(StrHideError::General(
            "Carrier already contains hidden data. Use remove first or specify another file."
                .into(),
        ));
    }
    if let Some((_, tr_magic)) = stealth_magics {
        host.seek(SeekFrom::Start(0))?;
        if adapter.locate(host, Some(tr_magic))?.is_some() {
            return Err(StrHideError::General(
                "Carrier already contains hidden data (stealth envelope). Use remove first or specify another file.".into(),
            ));
        }
    }

    host.seek(SeekFrom::Start(0))?;
    Ok(adapter.suspicious_structures(host))
}

/// Payload bytes after size validation and the compression decision.
struct PreparedPayload<'a> {
    bytes: Cow<'a, [u8]>,
    filename: String,
    is_file: bool,
    raw_size: u64,
    raw_sha256: String,
    is_compressed: bool,
}

/// Normalise the payload, enforce the carrier's size limit and decide whether
/// the configured compression strategy actually keeps the compressed stream.
///
/// The reader rejects any declared `raw_size` above `structure_payload_limit`
/// before decrypting. Applying the same bound here (with the same function)
/// means a payload that would be unreadable forever is refused up front
/// instead of producing a carrier that `read` can never extract. The input
/// host is at most as large as the post-injection carrier, so its limit is
/// the stricter of the two and the read path is guaranteed to pass.
fn prepare_write_payload<'a>(
    source: PayloadSource<'a>,
    local: &LocalParams,
    orig_host_size: u64,
) -> Result<PreparedPayload<'a>, StrHideError> {
    let (payload_raw_bytes, filename, is_file) = source.into_buffered()?;
    let raw_size = payload_raw_bytes.len() as u64;
    let max_payload = structure_payload_limit(orig_host_size);
    if raw_size > max_payload {
        return Err(StrHideError::PayloadTooLarge(format!(
            "Payload ({} bytes) exceeds the maximum supported by this carrier ({} bytes for a {} byte host); use a larger carrier or a smaller payload",
            raw_size, max_payload, orig_host_size
        )));
    }
    let raw_sha256 = {
        let h = crate::crypto::compute_sha256(&payload_raw_bytes);
        h.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    // `CompressionStrategy::Auto` keeps the historical integer criterion
    // (cross-language identical: keep compression only when it saves at least
    // 2%: comp_len * 100 < raw_size * 98). The level and the decision are
    // writer-only; the reader just inflates raw deflate when FLAG_COMPRESSED
    // is set.
    //
    // Large payloads are probed first: a full deflate pass over incompressible
    // data costs ~17 ms/MiB and is discarded, so a fixed 256 KiB stratified
    // sample decides whether the full pass is worth starting. The same
    // `should_compress` rule is applied to the sample, so the flag written
    // below always reflects the bytes actually kept.
    let (bytes, is_compressed) = match local.compression {
        crate::params::CompressionStrategy::Never => (payload_raw_bytes, false),
        strategy => {
            let level = strategy.level();
            let worth_full_pass =
                if payload_raw_bytes.len() > crate::crypto::COMPRESSION_PROBE_MIN_BYTES {
                    let (sample_raw, sample_comp) =
                        crate::crypto::probe_compressibility(&payload_raw_bytes, level)?;
                    strategy.should_compress(sample_raw, sample_comp)
                } else {
                    true
                };

            if !worth_full_pass {
                (payload_raw_bytes, false)
            } else {
                let mut compressed_buf = Vec::new();
                let (_, comp_len) = compress_stream(
                    &mut Cursor::new(&payload_raw_bytes),
                    &mut compressed_buf,
                    level,
                )?;

                if strategy.should_compress(raw_size, comp_len) {
                    // Keep the compressed stream and release the raw payload buffer early.
                    drop(payload_raw_bytes);
                    (Cow::Owned(compressed_buf), true)
                } else {
                    // Keep the raw payload and release the compressed buffer early.
                    drop(compressed_buf);
                    (payload_raw_bytes, false)
                }
            }
        }
    };

    Ok(PreparedPayload {
        bytes,
        filename,
        is_file,
        raw_size,
        raw_sha256,
        is_compressed,
    })
}

/// Where the adapter put the envelope and what it patched in the host.
struct InjectionPlacement {
    offset: u64,
    size: u64,
}

/// Patch the real coordinates into the header and trailer, run the adapter's
/// finalization, and require that `locate` finds exactly this write.
///
/// Scattered strategies (pe_codebits) embed the final envelope bytes during
/// `inject()`: `inject_offset`/`inject_size` are 0 by definition and the
/// trailer was assembled with `ube_offset = 0`, so there is nothing to patch at
/// file offsets. Patching anyway would overwrite host bytes (offset 0 is the MZ
/// header of a PE).
#[allow(clippy::too_many_arguments)]
fn finish_injection<W>(
    out: &mut W,
    adapter: &dyn HostAdapter,
    header: &EnvelopeHeader,
    header_mask: Option<&[u8; 76]>,
    final_trailer: &EnvelopeTrailer,
    strategy: &str,
    actual_ube_offset: u64,
    ube_total_size: u64,
    placement: InjectionPlacement,
    trailer_magic: &[u8; 4],
) -> Result<(), StrHideError>
where
    W: Read + Write + Seek,
{
    let InjectionPlacement {
        offset: inject_offset,
        size: inject_size,
        ..
    } = placement;

    if !adapter.is_scattered_strategy(strategy) {
        // Patch header
        out.seek(SeekFrom::Start(actual_ube_offset))?;
        out.write_all(&header.pack_masked(header_mask))?;

        // Patch trailer at end of UBE
        let trailer_ctx = TrailerCtx {
            actual_ube_offset,
            ube_total_size,
            inject_offset,
            inject_size,
            strategy,
        };
        let trailer_pos = adapter.trailer_offset(&trailer_ctx);
        out.seek(SeekFrom::Start(trailer_pos))?;
        out.write_all(&final_trailer.pack())?;

        // Post-write finalization (e.g. recalculating chunk CRCs)
        let fin_ctx = FinalizeCtx {
            ube_offset: actual_ube_offset,
            ube_total_size,
            inject_offset,
            inject_size,
            strategy,
        };
        adapter.finalize(out, &fin_ctx)?;
    }

    // Post-write self-check: inject and locate must agree on where the
    // envelope landed, or the write reports success for data that
    // read/inspect/remove can never reach. Matching against the trailer magic
    // this write produced is exactly what the read path demands, so a fresh
    // output its own locate cannot find aborts here instead of orphaning the
    // envelope. Cost: one streaming locate pass over the output.
    out.flush()?;
    out.seek(SeekFrom::Start(0))?;
    let self_located = adapter.locate(out, Some(trailer_magic))?;
    // `Some` alone is not enough: a second envelope with the same trailer magic
    // could satisfy `locate` while `read` / `remove` would then reach the *old*
    // one. Require the coordinates this very write sealed into the trailer.
    let located_at = self_located.as_ref().map(|loc| (loc.offset, loc.size));
    if located_at != Some((actual_ube_offset, ube_total_size)) {
        return Err(StrHideError::General(format!(
            "Post-write self-check failed: strategy '{}' wrote the envelope at {} ({} bytes), but locate returned {:?}; aborting so no unreadable stego is committed",
            strategy, actual_ube_offset, ube_total_size, located_at
        )));
    }
    Ok(())
}

/// Inject `source` into `carrier_path`, staging through a temp file and an
/// atomic rename.
///
/// Everything path-shaped lives here: rejection checks, permission probing, the
/// `.bak` backup, the rename, and timestamp cloning. The protocol itself is in
/// `write_core`, which is why [`write_carrier_bytes`] can offer the same
/// guarantees minus the filesystem ones.
pub fn write_carrier_with(
    carrier_path: &Path,
    source: PayloadSource,
    options: &WriteOptions<'_>,
    local: &LocalParams,
    profile: &StructureProfile,
) -> Result<WriteResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let target_path = options.output_path.unwrap_or(carrier_path);

    if !crate::commit::same_file(target_path, carrier_path) {
        crate::core::pipeline::check_overwrite(target_path, options.overwrite)?;
    }
    // Fail before the envelope work: a read-only target would otherwise fail
    // the final rename with a misleading `TargetBusy`.
    crate::commit::reject_read_only_target(target_path)?;
    // Held until the commit finishes: a concurrent writer to the same target
    // must fail instead of silently replacing this envelope.
    let _target_lock = crate::commit::TargetLock::acquire(target_path)?;

    // 1. Run security rejection checks (carrier policy + target permissions)
    run_rejection_checks(carrier_path, target_path, local.rejection)?;

    let meta = std::fs::metadata(carrier_path)?;
    let orig_permissions = meta.permissions();
    let orig_atime = filetime::FileTime::from_last_access_time(&meta);
    let orig_mtime = filetime::FileTime::from_last_modification_time(&meta);

    // Collision-free temp file guard prevents races under concurrent execution.
    // TmpGuard removes the half-written file on any early return unless `commit()`
    // runs after the rename succeeded.
    // Read+write, not write-only: the patch/finalize step seeks back into the
    // staged output and adapter `finalize` implementations may read what they
    // just wrote (a write-only handle fails with "access denied" on Windows).
    let (tmp_target, mut out_file) = match create_temp_file_for(target_path, true) {
        Ok(pair) => pair,
        Err(StrHideError::Io(e)) => {
            let dir = match target_path.parent() {
                Some(p) if !p.as_os_str().is_empty() => p,
                _ => Path::new("."),
            };
            let reason = match e.kind() {
                std::io::ErrorKind::NotFound => "the output directory does not exist",
                std::io::ErrorKind::PermissionDenied => "the output directory is not writable",
                _ => "the output file could not be created",
            };
            return Err(StrHideError::General(format!(
                "Cannot create '{}' in '{}': {reason} [{e}]",
                target_path.display(),
                dir.display()
            )));
        }
        Err(e) => return Err(e),
    };
    let mut tmp_guard = TmpGuard::new(tmp_target.clone());

    let core = {
        let mut host = File::open(carrier_path)?;
        let mut pw = crate::core::control::ProgressWriter::new(
            &mut out_file,
            options.control,
            crate::core::control::Stage::Write,
            meta.len(),
        );
        let carrier_label = carrier_path.display().to_string();
        let core = write_core(
            &mut host,
            &mut pw,
            source,
            options,
            local,
            profile,
            &carrier_label,
        )
        .map_err(|e| crate::core::control::map_io_cancel(&options.control, e))?;
        // Durability before the rename, the same contract `commit.rs` applies to
        // every payload write: renaming first and syncing later leaves a window
        // where the new name exists with an unwritten tail. `pw` borrows
        // `out_file`, and its last use is the `write_core` call above, so the
        // borrow is already over here.
        out_file.sync_all()?;
        core
    };

    // Strict cancellation check before .bak creation and atomic commit
    options.control.check()?;

    // 2. In-place backup (if applicable) & Atomic commit
    let is_inplace = crate::commit::same_file(target_path, carrier_path);
    let mut backup_file = None;
    if is_inplace && options.backup {
        backup_file = Some(crate::commit::create_carrier_backup(carrier_path)?);
    }

    crate::commit::rename_with_retry(&tmp_target, target_path)?;
    tmp_guard.commit();
    crate::commit::sync_parent_dir(target_path);

    // Timestamps first, permissions second: restoring the carrier's read-only
    // attribute first would make the timestamp update fail on Windows and be
    // dropped silently. Warn instead of swallowing the failure (the write
    // itself succeeded).
    if options.preserve_time
        && let Err(e) = filetime::set_file_times(target_path, orig_atime, orig_mtime)
    {
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

    Ok(WriteResult {
        carrier: target_path.to_path_buf(),
        format: core.format,
        strategy: core.strategy,
        strategy_note: core.strategy_note,
        raw_size: core.raw_size,
        ube_size: core.ube_size,
        is_encrypted: core.is_encrypted,
        is_stealth: core.is_stealth,
        password_hint: options.password_hint.map(|s| s.to_string()),
        backup_file,
        warnings: core.warnings,
    })
}

/// Inject `source` into an in-memory carrier, returning the stego bytes.
///
/// Same protocol and same self-verification as [`write_carrier_with`], minus
/// everything that only makes sense for a file. Three capabilities are
/// deliberately *not* provided, and the absence is the reason this entry point
/// exists for services that have no writable filesystem:
///
/// - **no atomic commit** — the caller owns the buffer it gets back; there is no
///   half-written state to roll back because nothing is written until it
///   decides to;
/// - **no `<carrier>.bak`** — the original bytes are still in the caller's
///   hands (`options.backup` is ignored);
/// - **no timestamp cloning** — there is no inode to stamp
///   (`options.preserve_time` is ignored).
///
/// Rejection checks are content-only: the path-based ones (read-only carrier,
/// target-directory write probe, `.apk`/signature-file name checks) describe
/// the filesystem, not the carrier. [`crate::structure::rejection::check_content`] still
/// refuses Authenticode/PDF/JAR-signed carriers, which is the part that matters
/// for "do not break someone's signature".
///
/// `options.output_path` must be `None`: honouring it here would silently write
/// a file from a function whose contract is "give me bytes".
pub fn write_carrier_bytes(
    carrier: &[u8],
    source: PayloadSource,
    options: &WriteOptions<'_>,
    local: &LocalParams,
    profile: &StructureProfile,
) -> Result<(Vec<u8>, WriteResult), StrHideError> {
    if let Some(p) = options.output_path {
        return Err(StrHideError::General(format!(
            "write_carrier_bytes returns the stego bytes instead of writing a file; \
             output_path '{}' is not honoured (use write_carrier_with for file output)",
            p.display()
        )));
    }

    let mut host = Cursor::new(carrier);
    if local.rejection != crate::params::RejectionPolicy::Skip {
        host.seek(SeekFrom::Start(0))?;
        crate::structure::rejection::check_content(&mut host, None)?;
    }

    let mut out = Cursor::new(Vec::new());
    let core = write_core(
        &mut host, &mut out, source, options, local, profile, "<memory>",
    )?;
    let bytes = out.into_inner();

    let result = WriteResult {
        carrier: PathBuf::from("<memory>"),
        format: core.format,
        strategy: core.strategy,
        strategy_note: core.strategy_note,
        raw_size: core.raw_size,
        ube_size: core.ube_size,
        is_encrypted: core.is_encrypted,
        is_stealth: core.is_stealth,
        password_hint: options.password_hint.map(|s| s.to_string()),
        backup_file: None,
        warnings: core.warnings,
    };
    Ok((bytes, result))
}
