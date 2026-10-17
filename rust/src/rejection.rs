//! Security pre-check and rejection rules for strhide.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::errors::StrHideError;

pub fn check_pe_authenticode<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<Option<String>, StrHideError> {
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

pub fn check_unsupported_apk(filename: Option<&str>) -> Option<String> {
    if let Some(name) = filename
        && name.to_lowercase().ends_with(".apk") {
            return Some("APK 格式不在支持列表中（不支持作为载体文件进行修改）。".into());
        }
    None
}

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

pub fn check_pdf_signature<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<Option<String>, StrHideError> {
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
    haystack.windows(needle.len()).position(|window| window == needle)
}

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
        || (magic != *b"PK\x03\x04"
            && magic != *b"PK\x05\x06"
            && magic != *b"PK\x07\x08")
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
                        let name_len =
                            u16::from_le_bytes(cd_buf[offset + 28..offset + 30].try_into().unwrap())
                                as usize;
                        let extra_len =
                            u16::from_le_bytes(cd_buf[offset + 30..offset + 32].try_into().unwrap())
                                as usize;
                        let comment_len =
                            u16::from_le_bytes(cd_buf[offset + 32..offset + 34].try_into().unwrap())
                                as usize;

                        let name_start = offset + 46;
                        if name_start + name_len <= cd_buf.len() {
                            let name = String::from_utf8_lossy(&cd_buf[name_start..name_start + name_len]);
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

pub fn run_all_rejection_checks(path: &Path) -> Result<(), StrHideError> {
    let filename = path.file_name().and_then(|s| s.to_str());

    if let Some(err) = check_signature_file(filename) {
        return Err(StrHideError::Rejection(err));
    }

    if let Some(err) = check_unsupported_apk(filename) {
        return Err(StrHideError::Rejection(err));
    }

    // Check write permissions
    let metadata = std::fs::metadata(path)?;
    if metadata.permissions().readonly() {
        return Err(StrHideError::Rejection(format!(
            "No write permission on target file '{}'.",
            path.display()
        )));
    }

    // Parent directory write probe: the engine creates "<target>.strhide.tmp"
    // next to the target before the atomic rename, so a read-only directory
    // must be rejected here with a clear message instead of failing later with
    // a raw OS error. This mirrors Python's os.access(parent_dir, W_OK) check
    // in a portable way (the permission bit is unreliable on Windows).
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let probe = parent.join(format!(".strhide_write_probe_{}", std::process::id()));
    match File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
        }
        Err(e) => {
            return Err(StrHideError::Rejection(format!(
                "No write permission on target directory '{}': {e}",
                parent.display()
            )));
        }
    }

    let mut file = File::open(path)?;

    if let Some(err) = check_pe_authenticode(&mut file)? {
        return Err(StrHideError::Rejection(err));
    }

    if let Some(err) = check_pdf_signature(&mut file)? {
        return Err(StrHideError::Rejection(err));
    }

    if let Some(err) = check_jar_signature(&mut file, filename)? {
        return Err(StrHideError::Rejection(err));
    }

    Ok(())
}
