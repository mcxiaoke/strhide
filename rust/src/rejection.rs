//! Pre-write safety checks and rejection rules.
//!
//! Before [`crate::engine::write_carrier`] opens the target for writing, it
//! runs every check here. The goal is to refuse operations that would
//! silently break something the user did not ask to break:
//!
//! - signed Windows PE files (Authenticode)
//! - signed PDF documents (ByteRange / `/Sig`)
//! - signed JAR / APK archives (`META-INF/*.SF|RSA|DSA`)
//! - standalone signature files (`.sig` / `.asc` / `.p7s` / `.p7b`)
//! - APK carriers (unsupported container)
//! - read-only carriers being written in place
//! - target directories that are not writable
//!
//! Each check returns `Ok(None)` when the carrier is safe, or
//! `Ok(Some(reason))` / `Err(..)` describing why the write must be refused.
//! [`run_all_rejection_checks`] composes them in the order the engine uses.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::errors::StrHideError;
use crate::params::RejectionPolicy;

/// Inspect a PE reader for an Authenticode certificate table.
///
/// Returns `Ok(Some(reason))` when the PE has a non-empty security directory;
/// `Ok(None)` when the file is not a PE or is unsigned. The reader's
/// position is always restored.
pub fn check_pe_authenticode<R: Read + Seek + ?Sized>(
    reader: &mut R,
) -> Result<Option<String>, StrHideError> {
    let start_pos = reader.stream_position()?;
    let mut mz = [0u8; 2];
    if reader.read_exact(&mut mz).is_err() || &mz != b"MZ" {
        reader.seek(SeekFrom::Start(start_pos))?;
        return Ok(None);
    }

    if reader.seek(SeekFrom::Start(0x3C)).is_err() {
        reader.seek(SeekFrom::Start(start_pos))?;
        return Ok(None);
    }

    let mut lfanew_bytes = [0u8; 4];
    if reader.read_exact(&mut lfanew_bytes).is_err() {
        reader.seek(SeekFrom::Start(start_pos))?;
        return Ok(None);
    }
    let e_lfanew = u32::from_le_bytes(lfanew_bytes) as u64;

    if reader.seek(SeekFrom::Start(e_lfanew)).is_err() {
        reader.seek(SeekFrom::Start(start_pos))?;
        return Ok(None);
    }

    let mut pe_sig = [0u8; 4];
    if reader.read_exact(&mut pe_sig).is_err() || &pe_sig != b"PE\x00\x00" {
        reader.seek(SeekFrom::Start(start_pos))?;
        return Ok(None);
    }

    let mut coff_header = [0u8; 20];
    if reader.read_exact(&mut coff_header).is_err() {
        reader.seek(SeekFrom::Start(start_pos))?;
        return Ok(None);
    }

    let size_of_opt_header = u16::from_le_bytes(coff_header[16..18].try_into().unwrap());
    if size_of_opt_header == 0 {
        reader.seek(SeekFrom::Start(start_pos))?;
        return Ok(None);
    }

    let mut opt_magic_bytes = [0u8; 2];
    if reader.read_exact(&mut opt_magic_bytes).is_err() {
        reader.seek(SeekFrom::Start(start_pos))?;
        return Ok(None);
    }
    let opt_magic = u16::from_le_bytes(opt_magic_bytes);

    let sec_dir_offset = match opt_magic {
        0x10B => e_lfanew + 24 + 128,
        0x20B => e_lfanew + 24 + 144,
        _ => {
            reader.seek(SeekFrom::Start(start_pos))?;
            return Ok(None);
        }
    };

    if reader.seek(SeekFrom::Start(sec_dir_offset)).is_err() {
        reader.seek(SeekFrom::Start(start_pos))?;
        return Ok(None);
    }

    let mut sec_dir_bytes = [0u8; 8];
    if reader.read_exact(&mut sec_dir_bytes).is_err() {
        reader.seek(SeekFrom::Start(start_pos))?;
        return Ok(None);
    }

    let virt_addr = u32::from_le_bytes(sec_dir_bytes[0..4].try_into().unwrap());
    let size = u32::from_le_bytes(sec_dir_bytes[4..8].try_into().unwrap());

    reader.seek(SeekFrom::Start(start_pos))?;

    if virt_addr != 0 && size != 0 {
        return Ok(Some(
            "Windows PE contains an Authenticode digital signature. Modification will invalidate the signature.".into(),
        ));
    }

    Ok(None)
}

/// Reject `.apk` carriers outright: the APK container carries its own
/// signature and alignment that strhide does not preserve.
pub fn check_unsupported_apk(filename: Option<&str>) -> Option<String> {
    if let Some(name) = filename
        && name.to_lowercase().ends_with(".apk")
    {
        return Some(
            "APK carriers are not supported (modifying the container would break it).".into(),
        );
    }
    None
}

/// Reject standalone signature files as carriers — hiding data inside a
/// detached signature would corrupt the signature itself.
pub fn check_signature_file(filename: Option<&str>) -> Option<String> {
    if let Some(name) = filename {
        let lower = name.to_lowercase();
        if lower.ends_with(".sig")
            || lower.ends_with(".asc")
            || lower.ends_with(".p7s")
            || lower.ends_with(".p7b")
        {
            return Some(format!(
                "File '{name}' is a standalone digital signature file and cannot be used as a carrier."
            ));
        }
    }
    None
}

/// Scan a PDF reader for a `/ByteRange` + `/Sig` pair (the CMS/PKCS#7
/// signature pattern). Returns `Ok(Some(reason))` when found.
pub fn check_pdf_signature<R: Read + Seek + ?Sized>(
    reader: &mut R,
) -> Result<Option<String>, StrHideError> {
    let start_pos = reader.stream_position()?;
    let mut header = [0u8; 1024];
    let n = reader.read(&mut header)?;
    if !header[..n].starts_with(b"%PDF-") {
        reader.seek(SeekFrom::Start(start_pos))?;
        return Ok(None);
    }

    reader.seek(SeekFrom::Start(0))?;
    let chunk_size = 64 * 1024;
    let overlap = 1024;
    let mut prev_tail = Vec::new();
    let mut buf = vec![0u8; chunk_size];
    let mut has_byterange = false;
    let mut has_sig = false;

    loop {
        let bytes_read = reader.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }

        let mut window = Vec::with_capacity(prev_tail.len() + bytes_read);
        window.extend_from_slice(&prev_tail);
        window.extend_from_slice(&buf[..bytes_read]);

        if find_subsequence(&window, b"/ByteRange").is_some() {
            has_byterange = true;
        }
        if find_subsequence(&window, b"/Sig").is_some()
            || find_subsequence(&window, b"/Type /Sig").is_some()
            || find_subsequence(&window, b"/Type/Sig").is_some()
        {
            has_sig = true;
        }

        if has_byterange && has_sig {
            reader.seek(SeekFrom::Start(start_pos))?;
            return Ok(Some(
                "PDF document contains a cryptographic digital signature. Modifying it will invalidate the signature.".into(),
            ));
        }

        if bytes_read >= overlap {
            prev_tail.clear();
            prev_tail.extend_from_slice(&buf[bytes_read - overlap..bytes_read]);
        } else {
            prev_tail.clear();
            prev_tail.extend_from_slice(&buf[..bytes_read]);
        }
    }

    reader.seek(SeekFrom::Start(start_pos))?;
    Ok(None)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Content-based JAR signature detection: scans the central directory of any
/// ZIP container for `META-INF/*.SF|.RSA|.DSA`.
///
/// Detection is magic-based, not extension-based, so a signed JAR renamed to
/// `.zip` is still caught. The reader's position is restored on return.
pub fn check_jar_signature<R: Read + Seek + ?Sized>(
    reader: &mut R,
    _filename: Option<&str>,
) -> Result<Option<String>, StrHideError> {
    // Content-based detection: any ZIP container may be a signed JAR/APK-style
    // archive regardless of its extension. Extension-gated checks let a signed
    // archive renamed to .zip bypass the signature guard, so detection is done
    // on the ZIP magic instead.
    let start_pos = reader.stream_position()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 4];
    if reader.read_exact(&mut magic).is_err()
        || (magic != *b"PK\x03\x04" && magic != *b"PK\x05\x06" && magic != *b"PK\x07\x08")
    {
        reader.seek(SeekFrom::Start(start_pos))?;
        return Ok(None);
    }

    let file_size = reader.seek(SeekFrom::End(0))?;
    let scan_len = std::cmp::min(file_size, 65536 + 22);
    reader.seek(SeekFrom::End(-(scan_len as i64)))?;
    let mut tail = vec![0u8; scan_len as usize];
    reader.read_exact(&mut tail)?;

    // Find EOCD PK\x05\x06
    if let Some(pos) = tail.windows(4).rposition(|w| w == b"PK\x05\x06") {
        let eocd_pos = (file_size - scan_len) + pos as u64;
        reader.seek(SeekFrom::Start(eocd_pos + 12))?;
        let mut cd_info = [0u8; 8];
        if reader.read_exact(&mut cd_info).is_ok() {
            let cd_size = u32::from_le_bytes(cd_info[0..4].try_into().unwrap()) as u64;
            let cd_offset = u32::from_le_bytes(cd_info[4..8].try_into().unwrap()) as u64;

            if cd_offset + cd_size <= file_size && reader.seek(SeekFrom::Start(cd_offset)).is_ok() {
                let mut cd_buf = vec![0u8; cd_size as usize];
                if reader.read_exact(&mut cd_buf).is_ok() {
                    let mut offset = 0;
                    while offset + 46 <= cd_buf.len() {
                        if &cd_buf[offset..offset + 4] != b"PK\x01\x02" {
                            break;
                        }
                        let name_len = u16::from_le_bytes(
                            cd_buf[offset + 28..offset + 30].try_into().unwrap(),
                        ) as usize;
                        let extra_len = u16::from_le_bytes(
                            cd_buf[offset + 30..offset + 32].try_into().unwrap(),
                        ) as usize;
                        let comment_len = u16::from_le_bytes(
                            cd_buf[offset + 32..offset + 34].try_into().unwrap(),
                        ) as usize;

                        let name_start = offset + 46;
                        if name_start + name_len <= cd_buf.len() {
                            let name =
                                String::from_utf8_lossy(&cd_buf[name_start..name_start + name_len]);
                            let upper = name.to_uppercase();
                            if upper.starts_with("META-INF/")
                                && (upper.ends_with(".SF")
                                    || upper.ends_with(".RSA")
                                    || upper.ends_with(".DSA"))
                            {
                                reader.seek(SeekFrom::Start(start_pos))?;
                                return Ok(Some(format!(
                                    "ZIP/JAR archive contains digital signature file ({name}). Modifying it will break JVM/signature verification."
                                )));
                            }
                        }
                        offset += 46 + name_len + extra_len + comment_len;
                    }
                }
            }
        }
    }

    reader.seek(SeekFrom::Start(start_pos))?;
    Ok(None)
}

/// Structure checks only: signed PE Authenticode block, PDF incremental-update
/// signature, JAR signature entries.
///
/// These are the checks that need nothing but the carrier bytes, so an
/// in-memory carrier can run them from a cursor. `filename` is passed through
/// because JAR signature detection reports the offending entry by file name.
pub fn check_content<R: Read + Seek + ?Sized>(
    reader: &mut R,
    filename: Option<&str>,
) -> Result<(), StrHideError> {
    if let Some(err) = check_pe_authenticode(reader)? {
        return Err(StrHideError::Rejection(err));
    }

    if let Some(err) = check_pdf_signature(reader)? {
        return Err(StrHideError::Rejection(err));
    }

    if let Some(err) = check_jar_signature(reader, filename)? {
        return Err(StrHideError::Rejection(err));
    }

    Ok(())
}

/// Run every pre-write check in order (the historical, strict behaviour).
///
/// Kept as a stable entry point; [`run_rejection_checks`] adds the
/// [`RejectionPolicy`] knob.
pub fn run_all_rejection_checks(carrier: &Path, target: &Path) -> Result<(), StrHideError> {
    run_rejection_checks(carrier, target, RejectionPolicy::Strict)
}

/// Run pre-write checks at the granularity selected by `policy`.
///
/// [`RejectionPolicy::Strict`] runs everything; [`RejectionPolicy::ContentOnly`]
/// skips the filesystem-dependent checks (read-only carrier, target-directory
/// write probe) but still refuses signed containers;
/// [`RejectionPolicy::Skip`] runs nothing.
///
/// The carrier itself is only opened for read; a write probe is created (and
/// immediately deleted) next to `target`, because the engine stages its
/// output as `<target>.strhide.tmp` before an atomic rename.
pub fn run_rejection_checks(
    carrier: &Path,
    target: &Path,
    policy: RejectionPolicy,
) -> Result<(), StrHideError> {
    if policy == RejectionPolicy::Skip {
        return Ok(());
    }

    let filename = carrier.file_name().and_then(|s| s.to_str());

    if policy == RejectionPolicy::Strict {
        if let Some(err) = check_signature_file(filename) {
            return Err(StrHideError::Rejection(err));
        }

        if let Some(err) = check_unsupported_apk(filename) {
            return Err(StrHideError::Rejection(err));
        }

        // The carrier is only written to in place. When `-o` names a different
        // file the carrier stays read-only on purpose (read-only media, mounted
        // images, C:\Program Files\...), so only reject a read-only carrier for
        // in-place writes.
        let in_place = match (std::path::absolute(carrier), std::path::absolute(target)) {
            (Ok(c), Ok(t)) => c == t,
            _ => carrier == target,
        };
        let metadata = std::fs::metadata(carrier)?;
        if in_place && metadata.permissions().readonly() {
            return Err(StrHideError::Rejection(format!(
                "No write permission on target file '{}'.",
                carrier.display()
            )));
        }

        // Write probe: the engine creates "<target>.strhide.tmp" next to the
        // *target* before the atomic rename, so the probe must live in the
        // target's directory — probing the carrier's directory rejects legal
        // "read from read-only media, write elsewhere" workflows and says
        // nothing about the directory actually being written.
        //
        // The probe carries a PID and a monotonic suffix: a fixed PID-only name
        // is shared by threads of one process and can collide or be left
        // behind.
        let parent = match target.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let probe = parent.join(format!(
            ".strhide_write_probe_{}_{nonce}",
            std::process::id()
        ));
        match File::create(&probe) {
            Ok(_) => {
                let _ = std::fs::remove_file(&probe);
            }
            Err(e) => {
                let reason = match e.kind() {
                    std::io::ErrorKind::NotFound => "the directory does not exist",
                    std::io::ErrorKind::PermissionDenied => "the directory is not writable",
                    _ => "the directory cannot be written to",
                };
                return Err(StrHideError::Rejection(format!(
                    "Cannot write to target directory '{}': {reason} [{e}]",
                    parent.display()
                )));
            }
        }
    }

    let mut file = File::open(carrier)?;
    check_content(&mut file, filename)
}
