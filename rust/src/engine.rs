//! Core engine orchestrating write, read, verify, inspect, and remove operations.

use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngExt;
use serde::{Deserialize, Serialize};

use crate::adapters::{
    mp4::Mp4Adapter,
    pdf::PdfAdapter,
    HostAdapter,
};
use crate::crypto::{
    compress_stream, compute_file_sha256, decompress_stream,
    decrypt_metadata, decrypt_stream_from_chunks, derive_keys, derive_stealth_magics,
    encrypt_metadata, encrypt_stream_to_chunks, normalize_nfc,
};
use crate::envelope::{
    EnvelopeHeader, EnvelopeTrailer, FLAG_COMPRESSED, FLAG_ENCRYPTED, FLAG_HAS_HINT,
    FLAG_IS_FILE, FLAG_STEALTH, HEADER_SIZE, STANDARD_HEADER_MAGIC, STANDARD_TRAILER_MAGIC,
};
use crate::errors::StrHideError;
use crate::rejection::run_all_rejection_checks;
use crate::router::{find_adapter, strategy_to_id};

#[derive(Debug, Serialize, Deserialize)]
pub struct CarrierMetadata {
    pub filename: String,
    pub raw_size: u64,
    pub raw_sha256: String,
    pub created_at: u64,
}

pub enum PayloadSource<'a> {
    Bytes(&'a [u8]),
    File(&'a Path),
    Text(&'a str),
    Stdin,
}

#[derive(Debug, Serialize)]
pub struct WriteResult {
    pub status: String,
    pub carrier: String,
    pub format: String,
    pub strategy: String,
    pub strategy_note: Option<String>,
    pub raw_size: u64,
    pub ube_size: u64,
    pub is_encrypted: bool,
    pub is_stealth: bool,
    pub password_hint: Option<String>,
    pub backup_file: Option<String>,
    pub warning: Option<String>,
}

#[derive(Debug)]
pub struct ReadResult {
    pub carrier: String,
    pub data: Vec<u8>,
    pub is_file: bool,
    pub filename: String,
    pub raw_size: u64,
    pub written_file: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InspectResult {
    pub carrier: String,
    pub format: String,
    pub has_hidden_data: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ube_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ube_total_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_encrypted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_compressed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_stealth: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orig_host_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orig_host_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_strategies: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct LevelStatus {
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyResult {
    pub carrier: String,
    pub format: String,
    pub level1_host: LevelStatus,
    pub level2_envelope: LevelStatus,
    pub level3_crypto: LevelStatus,
}

#[derive(Debug, Serialize)]
pub struct RemoveResult {
    pub status: String,
    pub carrier: String,
    pub restored_size: u64,
    pub restored_sha256: String,
    pub verified_identical: bool,
    pub backup_file: Option<String>,
}

pub fn write_carrier(
    carrier_path: &Path,
    source: PayloadSource,
    output_path: Option<&Path>,
    password: Option<&str>,
    password_hint: Option<&str>,
    strategy: &str,
    stealth: bool,
    preserve_time: bool,
    backup: bool,
) -> Result<WriteResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    if password_hint.is_some() && stealth {
        return Err(StrHideError::General(
            "Password hint is not supported in --stealth mode (stealth mode requires password to locate envelope).".into(),
        ));
    }

    let hint_bytes = if let Some(hint) = password_hint {
        let norm_hint = normalize_nfc(hint.trim());
        let bytes = norm_hint.into_bytes();
        if bytes.len() > 1024 {
            return Err(StrHideError::General("Password hint cannot exceed 1024 bytes".into()));
        }
        bytes
    } else {
        Vec::new()
    };

    let target_path = output_path.unwrap_or(carrier_path);

    // 1. Run security rejection checks
    run_all_rejection_checks(carrier_path)?;

    // 2. Capture carrier metadata (stats, permissions, timestamps, full SHA-256)
    let meta = std::fs::metadata(carrier_path)?;
    let orig_host_size = meta.len();
    let orig_atime = filetime::FileTime::from_last_access_time(&meta);
    let orig_mtime = filetime::FileTime::from_last_modification_time(&meta);
    let orig_host_sha256 = compute_file_sha256(carrier_path)?;

    // 3. Detect adapter & check existing envelope
    let adapter: &'static dyn HostAdapter;
    let mut selected_strategy: String;

    {
        let mut cf = File::open(carrier_path)?;
        adapter = find_adapter(&mut cf);

        if strategy == "auto" {
            selected_strategy = adapter.choose_auto_strategy(&mut cf, 0).to_string();
        } else {
            if !adapter.supported_strategies().contains(&strategy) {
                return Err(StrHideError::General(format!(
                    "Strategy '{strategy}' not supported by adapter '{}'",
                    adapter.format_name()
                )));
            }
            selected_strategy = strategy.to_string();
        }

        if adapter.locate(&mut cf, None)?.is_some() {
            return Err(StrHideError::General(
                "Carrier already contains hidden data. Use remove first or specify another file.".into(),
            ));
        }
    }

    // 4. Prepare data payload stream
    let (payload_raw_bytes, filename, is_file) = match source {
        PayloadSource::Bytes(b) => (b.to_vec(), "payload.bin".to_string(), true),
        PayloadSource::File(p) => {
            let mut f = File::open(p)?;
            let mut b = Vec::new();
            f.read_to_end(&mut b)?;
            let name = p
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("payload.bin")
                .to_string();
            (b, name, true)
        }
        PayloadSource::Text(t) => {
            let norm = normalize_nfc(t);
            (norm.into_bytes(), String::new(), false)
        }
        PayloadSource::Stdin => {
            let mut b = Vec::new();
            std::io::stdin().read_to_end(&mut b)?;
            (b, String::new(), false)
        }
    };

    let raw_size = payload_raw_bytes.len() as u64;
    let raw_sha256 = {
        let h = crate::crypto::compute_sha256(&payload_raw_bytes);
        h.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    // 5. Compress data with Deflate
    let mut compressed_buf = Vec::new();
    let (_, comp_len) = compress_stream(&mut Cursor::new(&payload_raw_bytes), &mut compressed_buf)?;

    let (to_encrypt_bytes, is_compressed) = if comp_len < (raw_size as f64 * 0.98) as u64 {
        (compressed_buf, true)
    } else {
        (payload_raw_bytes, false)
    };

    // 6. Keys and Magics
    let is_encrypted = password.is_some();
    let mut flags: u8 = 0;
    if is_encrypted {
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
    let mut payload_key = [0u8; 32];
    let mut meta_key = [0u8; 32];
    let header_magic: [u8; 8];
    let trailer_magic: [u8; 4];

    if stealth && is_encrypted {
        flags |= FLAG_STEALTH;
        rand::rng().fill(&mut salt);
        rand::rng().fill(&mut base_nonce);
        let keys = derive_keys(password.unwrap(), &salt)?;
        payload_key = keys.0;
        meta_key = keys.1;
        let magics = derive_stealth_magics(password.unwrap(), b"strhide-stealth-v1")?;
        header_magic = magics.0;
        trailer_magic = magics.1;
    } else if is_encrypted {
        rand::rng().fill(&mut salt);
        rand::rng().fill(&mut base_nonce);
        let keys = derive_keys(password.unwrap(), &salt)?;
        payload_key = keys.0;
        meta_key = keys.1;
        header_magic = STANDARD_HEADER_MAGIC;
        trailer_magic = STANDARD_TRAILER_MAGIC;
    } else {
        header_magic = STANDARD_HEADER_MAGIC;
        trailer_magic = STANDARD_TRAILER_MAGIC;
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
    let meta_raw = serde_json::to_vec(&meta_obj)?;

    // Estimate UBE size for auto strategy selection
    let to_encrypt_len = to_encrypt_bytes.len() as u64;
    let est_meta_len = meta_raw.len() as u64 + if is_encrypted { 16 } else { 0 };
    let est_payload_len = to_encrypt_len
        + if is_encrypted {
            ((to_encrypt_len + 2097152 - 1) / 2097152) * 16
        } else {
            0
        };
    let est_ube_size = HEADER_SIZE as u64 + hint_bytes.len() as u64 + est_meta_len + est_payload_len + 24;

    if strategy == "auto" {
        let mut cf = File::open(carrier_path)?;
        selected_strategy = adapter.choose_auto_strategy(&mut cf, est_ube_size).to_string();
    }

    // 8. Populate Header structure
    let strat_id = strategy_to_id(&selected_strategy);
    let mut header = EnvelopeHeader {
        magic_header: header_magic,
        flags,
        strategy_id: strat_id,
        salt,
        base_nonce,
        orig_host_size,
        orig_host_sha256,
        hint_len: hint_bytes.len() as u32,
        ..Default::default()
    };

    let fixed_header_aad = header.get_aad();

    // Encrypt metadata
    let meta_block = if is_encrypted {
        let enc = encrypt_metadata(&meta_raw, &meta_key, &base_nonce, &fixed_header_aad)?;
        header.meta_len = enc.len() as u32;
        enc
    } else {
        header.meta_len = meta_raw.len() as u32;
        meta_raw
    };

    // Encrypt payload stream
    let mut payload_cipher_buf = Vec::new();
    let payload_written = if is_encrypted {
        encrypt_stream_to_chunks(
            &mut Cursor::new(&to_encrypt_bytes),
            &mut payload_cipher_buf,
            &payload_key,
            &base_nonce,
            &fixed_header_aad,
        )?
    } else {
        payload_cipher_buf = to_encrypt_bytes;
        payload_cipher_buf.len() as u64
    };

    let ube_total_size = HEADER_SIZE as u64
        + hint_bytes.len() as u64
        + header.meta_len as u64
        + payload_written
        + 24;

    // Check size inflation warning (> 50%)
    let mut warning_msg = None;
    if orig_host_size > 0 && ube_total_size > (orig_host_size / 2) {
        let ratio_pct = (ube_total_size as f64 / orig_host_size as f64) * 100.0;
        warning_msg = Some(format!(
            "Hidden data envelope size ({ube_total_size} bytes) exceeds 50.0% of carrier file size ({orig_host_size} bytes, {ratio_pct:.1}%). Noticeable file size inflation may compromise stealthiness!"
        ));
    }

    // Assemble full UBE
    let mut tmp_ube = Vec::with_capacity(ube_total_size as usize);
    tmp_ube.extend_from_slice(&header.pack());
    if !hint_bytes.is_empty() {
        tmp_ube.extend_from_slice(&hint_bytes);
    }
    tmp_ube.extend_from_slice(&meta_block);
    tmp_ube.extend_from_slice(&payload_cipher_buf);
    let dummy_trailer = EnvelopeTrailer::create(0, ube_total_size, trailer_magic);
    tmp_ube.extend_from_slice(&dummy_trailer.pack());

    // 9. Inject into temporary target file
    let tmp_target = PathBuf::from(format!("{}.strhide.tmp", target_path.display()));
    let (inject_offset, inject_size, patch_offset, orig_patch_val) = {
        let mut host_in = File::open(carrier_path)?;
        let mut out_file = File::create(&tmp_target)?;
        let mut ube_cursor = Cursor::new(&tmp_ube);
        adapter.inject(&mut host_in, &mut ube_cursor, &mut out_file, &selected_strategy)?
    };

    // 10. Update real ube_offset in Header and Trailer
    let mut actual_ube_offset = inject_offset;
    if adapter.format_name() == "PNG" && selected_strategy == "chunk" {
        actual_ube_offset = inject_offset + 8;
    } else if adapter.format_name() == "MP4" && selected_strategy == "box_uuid" {
        actual_ube_offset = inject_offset + Mp4Adapter::calc_prefix_len(ube_total_size);
    } else if adapter.format_name() == "JPEG" && selected_strategy == "app_segment" {
        actual_ube_offset = inject_offset + 4;
    } else if adapter.format_name() == "PDF" && selected_strategy == "incremental" {
        let mut cf = File::open(carrier_path)?;
        actual_ube_offset = inject_offset + PdfAdapter::calc_prefix_len(&mut cf, ube_total_size)?;
    }

    header.inject_offset = inject_offset;
    header.inject_size = inject_size;
    header.patch_offset = patch_offset;
    header.orig_patch_val = orig_patch_val;

    let final_trailer = EnvelopeTrailer::create(actual_ube_offset, ube_total_size, trailer_magic);

    {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&tmp_target)?;

        // Patch header
        f.seek(SeekFrom::Start(actual_ube_offset))?;
        f.write_all(&header.pack())?;

        // Patch trailer at end of UBE
        f.seek(SeekFrom::Start(actual_ube_offset + ube_total_size - 24))?;
        f.write_all(&final_trailer.pack())?;

        // For PNG chunk: recalculate chunk CRC
        if adapter.format_name() == "PNG" && selected_strategy == "chunk" {
            f.seek(SeekFrom::Start(actual_ube_offset - 4))?;
            let mut chunk_type_and_data = vec![0u8; 4 + ube_total_size as usize];
            f.read_exact(&mut chunk_type_and_data)?;
            let new_crc = crc32fast::hash(&chunk_type_and_data);
            f.seek(SeekFrom::Start(actual_ube_offset + ube_total_size))?;
            f.write_all(&new_crc.to_be_bytes())?;
        }
    }

    // 11. Self-verification check
    let loc_ok = {
        let mut f = File::open(&tmp_target)?;
        adapter
            .locate(
                &mut f,
                if stealth { Some(&trailer_magic) } else { None },
            )?
            .is_some()
    };

    if !loc_ok {
        let _ = std::fs::remove_file(&tmp_target);
        return Err(StrHideError::General(
            "Self-verification failed: could not locate injected envelope".into(),
        ));
    }

    // 12. In-place backup (if applicable) & Atomic commit
    let is_inplace = std::path::absolute(target_path)? == std::path::absolute(carrier_path)?;
    let mut backup_file = None;
    if is_inplace && backup {
        let bak = PathBuf::from(format!("{}.bak", carrier_path.display()));
        std::fs::copy(carrier_path, &bak)?;
        backup_file = Some(bak.display().to_string());
    }

    std::fs::rename(&tmp_target, target_path)?;

    if preserve_time {
        let _ = filetime::set_file_times(target_path, orig_atime, orig_mtime);
    }

    let mut strategy_note = None;
    if adapter.format_name() == "JPEG" {
        if selected_strategy == "app_segment" {
            strategy_note = Some("Embedded into compliant JPEG COM segment before SOS (clean EOI at EOF, 0 trailing bytes).".into());
        } else if selected_strategy == "eof" && strategy == "auto" {
            strategy_note = Some(format!("Payload ({ube_total_size} bytes) exceeded JPEG single segment limit (64KB); automatically fell back to EOF overlay."));
        } else if selected_strategy == "eof" {
            strategy_note = Some("Appended after JPEG EOI marker (EOF overlay).".into());
        }
    } else if adapter.format_name() == "PNG" {
        if selected_strategy == "chunk" {
            strategy_note = Some("Embedded into compliant PNG private ancillary chunk 'prIv' before IEND (0 trailing bytes).".into());
        } else if selected_strategy == "eof" && strategy == "auto" {
            strategy_note = Some(format!("Payload ({ube_total_size} bytes) exceeded PNG chunk limit (2GB); automatically fell back to EOF overlay."));
        } else if selected_strategy == "eof" {
            strategy_note = Some("Appended after PNG IEND (EOF overlay).".into());
        }
    } else if adapter.format_name() == "PDF" {
        if selected_strategy == "incremental" {
            strategy_note = Some("Embedded into compliant PDF Incremental Update stream ending with %%EOF (0 trailing garbage bytes).".into());
        } else if selected_strategy == "eof" && strategy == "auto" {
            strategy_note = Some("PDF trailer could not be incrementally parsed; automatically fell back to EOF overlay.".into());
        } else if selected_strategy == "eof" {
            strategy_note = Some("Appended after PDF %%EOF (EOF overlay).".into());
        }
    } else if adapter.format_name() == "MP4" {
        if selected_strategy == "box_uuid" {
            strategy_note = Some("Embedded into compliant ISO BMFF 64-bit uuid Box (preserves media frame offsets).".into());
        } else if selected_strategy == "eof" {
            strategy_note = Some("Appended after MP4 EOF (EOF overlay).".into());
        }
    } else if adapter.format_name() == "ZIP" {
        if selected_strategy == "pre_cd_inject" {
            strategy_note = Some("Embedded before Central Directory with adjusted EOCD offset (all archive entries intact).".into());
        } else if selected_strategy == "eof" && strategy == "auto" {
            strategy_note = Some("ZIP Central Directory could not be safely adjusted; automatically fell back to EOF overlay.".into());
        } else if selected_strategy == "eof" {
            strategy_note = Some("Appended after ZIP EOCD (EOF overlay).".into());
        }
    } else if adapter.format_name() == "PE" {
        if selected_strategy == "pe_overlay" {
            strategy_note = Some("Embedded into Windows PE image overlay (executable code and PE sections remain 100% intact).".into());
        } else if selected_strategy == "eof" {
            strategy_note = Some("Appended after PE executable EOF (EOF overlay).".into());
        }
    }

    Ok(WriteResult {
        status: "success".into(),
        carrier: target_path.display().to_string(),
        format: adapter.format_name().into(),
        strategy: selected_strategy,
        strategy_note,
        raw_size,
        ube_size: ube_total_size,
        is_encrypted,
        is_stealth: stealth,
        password_hint: password_hint.map(|s| s.to_string()),
        backup_file,
        warning: warning_msg,
    })
}

pub fn read_carrier(
    carrier_path: &Path,
    output_path: Option<&Path>,
    password: Option<&str>,
) -> Result<ReadResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let mut f = File::open(carrier_path)?;
    let adapter = find_adapter(&mut f);

    let mut loc = adapter.locate(&mut f, None)?;
    if loc.is_none() && password.is_some() {
        let magics = derive_stealth_magics(password.unwrap(), b"strhide-stealth-v1")?;
        loc = adapter.locate(&mut f, Some(&magics.1))?;
    }

    let (ube_offset, _ube_total_size, _strategy_name) = loc.ok_or_else(|| {
        StrHideError::General(format!(
            "No hidden strhide data found in '{}'",
            carrier_path.display()
        ))
    })?;

    // Read fixed header
    f.seek(SeekFrom::Start(ube_offset))?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes)?;
    let header = EnvelopeHeader::unpack(&header_bytes)?;

    // Read hint if present
    let mut hint_str = None;
    if header.hint_len > 0 {
        let mut hint_buf = vec![0u8; header.hint_len as usize];
        f.read_exact(&mut hint_buf)?;
        hint_str = Some(String::from_utf8_lossy(&hint_buf).to_string());
    }

    let fixed_header_aad = header.get_aad();

    // Derive keys
    let (payload_key, meta_key) = if header.is_encrypted() {
        if password.is_none() {
            let hint_msg = match &hint_str {
                Some(h) => format!(" Hint: '{h}'."),
                None => String::new(),
            };
            return Err(StrHideError::Password(format!(
                "Password required to extract hidden data.{hint_msg}"
            )));
        }
        derive_keys(password.unwrap(), &header.salt)?
    } else {
        ([0u8; 32], [0u8; 32])
    };

    // Read metadata
    let mut meta_bytes = vec![0u8; header.meta_len as usize];
    f.read_exact(&mut meta_bytes)?;

    let meta_plain = if header.is_encrypted() {
        decrypt_metadata(&meta_bytes, &meta_key, &header.base_nonce, &fixed_header_aad)?
    } else {
        meta_bytes
    };

    let meta_obj: CarrierMetadata = serde_json::from_slice(&meta_plain).map_err(|e| {
        StrHideError::CorruptedData(format!("Corrupted metadata block: {e}"))
    })?;

    // Read payload
    let total_payload_bytes = _ube_total_size
        - HEADER_SIZE as u64
        - header.hint_len as u64
        - header.meta_len as u64
        - 24;

    let mut decrypted_payload = Vec::new();
    if header.is_encrypted() {
        decrypt_stream_from_chunks(
            &mut f,
            &mut decrypted_payload,
            &payload_key,
            &header.base_nonce,
            &fixed_header_aad,
            total_payload_bytes,
        )?;
    } else {
        let mut taken = (&mut f).take(total_payload_bytes);
        taken.read_to_end(&mut decrypted_payload)?;
    }

    // Decompress if needed
    let final_data = if header.is_compressed() {
        let mut decomp = Vec::new();
        decompress_stream(&mut Cursor::new(&decrypted_payload), &mut decomp)?;
        decomp
    } else {
        decrypted_payload
    };

    // Verify SHA-256
    let actual_sha256 = {
        let h = crate::crypto::compute_sha256(&final_data);
        h.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    if actual_sha256 != meta_obj.raw_sha256 {
        return Err(StrHideError::CorruptedData(format!(
            "Payload SHA-256 mismatch: {actual_sha256} != {}",
            meta_obj.raw_sha256
        )));
    }

    let mut written_file = None;
    if let Some(out_p) = output_path {
        let final_dest = if out_p.is_dir() {
            let fn_to_use = if !meta_obj.filename.is_empty() {
                meta_obj.filename.as_str()
            } else {
                "extracted.bin"
            };
            out_p.join(fn_to_use)
        } else {
            out_p.to_path_buf()
        };

        let mut out_f = File::create(&final_dest)?;
        out_f.write_all(&final_data)?;
        written_file = Some(final_dest.display().to_string());
    }

    Ok(ReadResult {
        carrier: carrier_path.display().to_string(),
        data: final_data,
        is_file: header.is_file(),
        filename: meta_obj.filename,
        raw_size: meta_obj.raw_size,
        written_file,
    })
}

pub fn remove_carrier(
    carrier_path: &Path,
    output_path: Option<&Path>,
    password: Option<&str>,
    backup: bool,
) -> Result<RemoveResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let target_path = output_path.unwrap_or(carrier_path);
    let meta = std::fs::metadata(carrier_path)?;
    let orig_atime = filetime::FileTime::from_last_access_time(&meta);
    let orig_mtime = filetime::FileTime::from_last_modification_time(&meta);

    let header: EnvelopeHeader;
    let tmp_target = PathBuf::from(format!("{}.strhide.restoring.tmp", target_path.display()));

    {
        let mut cf = File::open(carrier_path)?;
        let adapter = find_adapter(&mut cf);

        let mut loc = adapter.locate(&mut cf, None)?;
        if loc.is_none() && password.is_some() {
            let magics = derive_stealth_magics(password.unwrap(), b"strhide-stealth-v1")?;
            loc = adapter.locate(&mut cf, Some(&magics.1))?;
        }

        let (ube_offset, _, _) = loc.ok_or_else(|| {
            StrHideError::General(format!(
                "No hidden strhide data found in '{}'",
                carrier_path.display()
            ))
        })?;

        cf.seek(SeekFrom::Start(ube_offset))?;
        let mut header_bytes = [0u8; HEADER_SIZE];
        cf.read_exact(&mut header_bytes)?;
        header = EnvelopeHeader::unpack(&header_bytes)?;

        let mut out_f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_target)?;

        adapter.strip(&mut cf, &mut out_f, &header)?;
    }

    // Verify restored file
    let restored_size = std::fs::metadata(&tmp_target)?.len();
    let restored_sha256 = compute_file_sha256(&tmp_target)?;

    if restored_size != header.orig_host_size || restored_sha256 != header.orig_host_sha256 {
        let _ = std::fs::remove_file(&tmp_target);
        return Err(StrHideError::RestoreMismatch(format!(
            "Restored size: {restored_size} (expected {})\nRestored SHA256: {}\nExpected SHA256: {}",
            header.orig_host_size,
            restored_sha256.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            header.orig_host_sha256.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )));
    }

    let is_inplace = std::path::absolute(target_path)? == std::path::absolute(carrier_path)?;
    let mut backup_file = None;
    if is_inplace && backup {
        let bak = PathBuf::from(format!("{}.bak", carrier_path.display()));
        std::fs::copy(carrier_path, &bak)?;
        backup_file = Some(bak.display().to_string());
    }

    std::fs::rename(&tmp_target, target_path)?;
    let _ = filetime::set_file_times(target_path, orig_atime, orig_mtime);

    Ok(RemoveResult {
        status: "success".into(),
        carrier: target_path.display().to_string(),
        restored_size,
        restored_sha256: restored_sha256.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        verified_identical: true,
        backup_file,
    })
}

pub fn inspect_carrier(
    carrier_path: &Path,
    password: Option<&str>,
) -> Result<InspectResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let mut cf = File::open(carrier_path)?;
    let adapter = find_adapter(&mut cf);

    let mut loc = adapter.locate(&mut cf, None)?;
    if loc.is_none() && password.is_some() {
        let magics = derive_stealth_magics(password.unwrap(), b"strhide-stealth-v1")?;
        loc = adapter.locate(&mut cf, Some(&magics.1))?;
    }

    let (ube_offset, ube_total_size, strategy_name) = match loc {
        Some(l) => l,
        None => {
            return Ok(InspectResult {
                carrier: carrier_path.display().to_string(),
                format: adapter.format_name().into(),
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
                supported_strategies: Some(
                    adapter
                        .supported_strategies()
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                ),
            })
        }
    };

    cf.seek(SeekFrom::Start(ube_offset))?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    cf.read_exact(&mut header_bytes)?;
    let header = EnvelopeHeader::unpack(&header_bytes)?;

    let mut hint_str = None;
    if header.hint_len > 0 {
        let mut hint_buf = vec![0u8; header.hint_len as usize];
        cf.read_exact(&mut hint_buf)?;
        hint_str = Some(String::from_utf8_lossy(&hint_buf).to_string());
    }

    let mut meta_val = None;
    if !header.is_encrypted() {
        let mut meta_bytes = vec![0u8; header.meta_len as usize];
        if cf.read_exact(&mut meta_bytes).is_ok() {
            if let Ok(val) = serde_json::from_slice(&meta_bytes) {
                meta_val = Some(val);
            }
        }
    } else if let Some(pwd) = password {
        let mut meta_bytes = vec![0u8; header.meta_len as usize];
        if cf.read_exact(&mut meta_bytes).is_ok() {
            if let Ok((_, meta_key)) = derive_keys(pwd, &header.salt) {
                if let Ok(dec) = decrypt_metadata(&meta_bytes, &meta_key, &header.base_nonce, &header.get_aad()) {
                    if let Ok(val) = serde_json::from_slice(&dec) {
                        meta_val = Some(val);
                    }
                } else {
                    meta_val = Some(serde_json::json!({"error": "Invalid password"}));
                }
            }
        }
    }

    Ok(InspectResult {
        carrier: carrier_path.display().to_string(),
        format: adapter.format_name().into(),
        has_hidden_data: true,
        strategy: Some(strategy_name),
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
        supported_strategies: None,
    })
}

pub fn verify_carrier(
    carrier_path: &Path,
    password: Option<&str>,
) -> Result<VerifyResult, StrHideError> {
    if !carrier_path.exists() {
        return Err(StrHideError::General(format!(
            "Carrier file '{}' not found",
            carrier_path.display()
        )));
    }

    let mut cf = File::open(carrier_path)?;
    let adapter = find_adapter(&mut cf);

    // Level 1: Host format integrity
    let (l1_ok, l1_msg) = adapter.verify_structure(&mut cf)?;

    // Level 2: Envelope boundary & CRC
    let mut loc = adapter.locate(&mut cf, None)?;
    if loc.is_none() && password.is_some() {
        let magics = derive_stealth_magics(password.unwrap(), b"strhide-stealth-v1")?;
        loc = adapter.locate(&mut cf, Some(&magics.1))?;
    }

    let (ube_offset, ube_total_size, _) = match loc {
        Some(l) => l,
        None => {
            return Ok(VerifyResult {
                carrier: carrier_path.display().to_string(),
                format: adapter.format_name().into(),
                level1_host: LevelStatus {
                    ok: l1_ok,
                    detail: l1_msg,
                },
                level2_envelope: LevelStatus {
                    ok: false,
                    detail: "No envelope found".into(),
                },
                level3_crypto: LevelStatus {
                    ok: false,
                    detail: "Skipped (no envelope)".into(),
                },
            })
        }
    };

    let (l2_ok, l2_msg, is_encrypted, _is_stealth) = {
        cf.seek(SeekFrom::Start(ube_offset))?;
        let mut header_bytes = [0u8; HEADER_SIZE];
        if cf.read_exact(&mut header_bytes).is_err() {
            (false, "Cannot read header".into(), false, false)
        } else if let Ok(header) = EnvelopeHeader::unpack(&header_bytes) {
            cf.seek(SeekFrom::Start(ube_offset + ube_total_size - 24))?;
            let mut trailer_bytes = [0u8; 24];
            let expected_trailer_magic = if header.is_stealth() && password.is_some() {
                let magics = derive_stealth_magics(password.unwrap(), b"strhide-stealth-v1")?;
                Some(magics.1)
            } else {
                None
            };

            if cf.read_exact(&mut trailer_bytes).is_err() {
                (false, "Cannot read trailer".into(), header.is_encrypted(), header.is_stealth())
            } else if let Ok(trailer) = EnvelopeTrailer::unpack(&trailer_bytes, expected_trailer_magic.as_ref()) {
                if trailer.ube_offset != ube_offset || trailer.ube_total_size != ube_total_size {
                    (false, "Envelope trailer boundary parameters mismatch".into(), header.is_encrypted(), header.is_stealth())
                } else {
                    (
                        true,
                        format!("Envelope valid at offset {ube_offset}, size {ube_total_size}B (CRC32 OK)"),
                        header.is_encrypted(),
                        header.is_stealth(),
                    )
                }
            } else {
                (false, "Envelope trailer unpacking failed".into(), header.is_encrypted(), header.is_stealth())
            }
        } else {
            (false, "Envelope header unpacking failed".into(), false, false)
        }
    };

    // Level 3: Crypto & payload SHA-256
    let (l3_ok, l3_msg) = if !is_encrypted || password.is_some() {
        match read_carrier(carrier_path, None, password) {
            Ok(res) => (
                true,
                format!(
                    "Decryption and SHA-256 verified successfully (payload {} bytes)",
                    res.raw_size
                ),
            ),
            Err(e) => (false, e.to_string()),
        }
    } else {
        (false, "Password required for cryptographic verification".into())
    };

    Ok(VerifyResult {
        carrier: carrier_path.display().to_string(),
        format: adapter.format_name().into(),
        level1_host: LevelStatus {
            ok: l1_ok,
            detail: l1_msg,
        },
        level2_envelope: LevelStatus {
            ok: l2_ok,
            detail: l2_msg,
        },
        level3_crypto: LevelStatus {
            ok: l3_ok,
            detail: l3_msg,
        },
    })
}
