//! Windows Portable Executable (PE) adapter for strhide.

use std::io::{Read, Seek, SeekFrom, Write};
use crate::adapters::{HostAdapter, SeekRead};
use crate::envelope::EnvelopeTrailer;
use crate::errors::StrHideError;

pub const PE_DOS_MAGIC: [u8; 2] = *b"MZ";
pub const PE_NT_MAGIC: [u8; 4] = *b"PE\x00\x00";

pub struct PeInfo {
    pub arch: &'static str,
    pub num_sections: usize,
    pub pe_image_end: u64,
    pub host_size: u64,
    pub has_authenticode: bool,
}

pub fn parse_pe_headers<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<PeInfo, StrHideError> {
    let host_size = reader.seek(SeekFrom::End(0))?;
    if host_size < 0x40 {
        return Err(StrHideError::UnsupportedFormat("File too small to be a PE executable".into()));
    }

    reader.seek(SeekFrom::Start(0))?;
    let mut mz = [0u8; 2];
    reader.read_exact(&mut mz)?;
    if mz != PE_DOS_MAGIC {
        return Err(StrHideError::UnsupportedFormat("Not a valid DOS/PE executable (missing 'MZ')".into()));
    }

    reader.seek(SeekFrom::Start(0x3C))?;
    let mut lfanew_bytes = [0u8; 4];
    reader.read_exact(&mut lfanew_bytes)?;
    let e_lfanew = u32::from_le_bytes(lfanew_bytes) as u64;

    if e_lfanew < 0x40 || e_lfanew + 24 > host_size {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Invalid e_lfanew offset (0x{e_lfanew:X})"
        )));
    }

    reader.seek(SeekFrom::Start(e_lfanew))?;
    let mut pe_sig = [0u8; 4];
    reader.read_exact(&mut pe_sig)?;
    if pe_sig != PE_NT_MAGIC {
        return Err(StrHideError::UnsupportedFormat(
            "Not a valid PE executable (missing 'PE\\0\\0')".into(),
        ));
    }

    let mut coff_header = [0u8; 20];
    reader.read_exact(&mut coff_header)?;

    let num_sections = u16::from_le_bytes(coff_header[2..4].try_into().unwrap()) as usize;
    let size_of_opt_header = u16::from_le_bytes(coff_header[16..18].try_into().unwrap()) as u64;

    let mut arch = "Unknown";
    let mut has_authenticode = false;

    if size_of_opt_header >= 2 {
        let opt_pos = reader.stream_position()?;
        let mut opt_magic_bytes = [0u8; 2];
        reader.read_exact(&mut opt_magic_bytes)?;
        let opt_magic = u16::from_le_bytes(opt_magic_bytes);

        let sec_dir_offset = if opt_magic == 0x10B {
            arch = "PE32";
            Some(128u64)
        } else if opt_magic == 0x20B {
            arch = "PE32+";
            Some(144u64)
        } else {
            None
        };

        if let Some(offset) = sec_dir_offset
            && size_of_opt_header >= offset + 8 {
                reader.seek(SeekFrom::Start(opt_pos + offset))?;
                let mut sec_bytes = [0u8; 8];
                if reader.read_exact(&mut sec_bytes).is_ok() {
                    let sec_va = u32::from_le_bytes(sec_bytes[0..4].try_into().unwrap());
                    let sec_sz = u32::from_le_bytes(sec_bytes[4..8].try_into().unwrap());
                    if sec_va != 0 && sec_sz != 0 {
                        has_authenticode = true;
                    }
                }
            }
    }

    // Read sections to determine pe_image_end
    let sec_table_offset = e_lfanew + 24 + size_of_opt_header;
    reader.seek(SeekFrom::Start(sec_table_offset))?;
    let mut pe_image_end = sec_table_offset;

    for _ in 0..num_sections {
        let mut sec_header = [0u8; 40];
        if reader.read_exact(&mut sec_header).is_err() {
            break;
        }
        let raw_size = u32::from_le_bytes(sec_header[16..20].try_into().unwrap()) as u64;
        let raw_ptr = u32::from_le_bytes(sec_header[20..24].try_into().unwrap()) as u64;
        let sec_end = raw_ptr + raw_size;
        if sec_end > pe_image_end {
            pe_image_end = sec_end;
        }
    }

    Ok(PeInfo {
        arch,
        num_sections,
        pe_image_end,
        host_size,
        has_authenticode,
    })
}

pub struct PeAdapter;

impl HostAdapter for PeAdapter {
    fn format_name(&self) -> &'static str {
        "PE"
    }

    fn detect(&self, reader: &mut dyn SeekRead) -> bool {
        let start_pos = match reader.stream_position() {
            Ok(pos) => pos,
            Err(_) => return false,
        };
        let ok = parse_pe_headers(reader).is_ok();
        let _ = reader.seek(SeekFrom::Start(start_pos));
        ok
    }

    fn supported_strategies(&self) -> Vec<&'static str> {
        vec!["pe_overlay", "eof"]
    }

    fn choose_auto_strategy(&self, _reader: &mut dyn SeekRead, _ube_size: u64) -> &'static str {
        "pe_overlay"
    }

    fn inject(
        &self,
        host_in: &mut dyn SeekRead,
        ube_in: &mut dyn SeekRead,
        out: &mut dyn Write,
        strategy: &str,
    ) -> Result<(u64, u64, u32, u32), StrHideError> {
        if strategy != "pe_overlay" && strategy != "eof" {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Strategy '{strategy}' not supported by PE adapter"
            )));
        }

        let pe_info = parse_pe_headers(host_in)?;

        if pe_info.has_authenticode {
            return Err(StrHideError::UnsupportedFormat(
                "Cannot inject into Windows PE: Executable contains an Authenticode digital signature. Modifying it will invalidate the digital signature.".into(),
            ));
        }

        if pe_info.host_size < pe_info.pe_image_end {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Corrupted PE executable: file size ({} bytes) is smaller than PE section headers dictate ({} bytes).",
                pe_info.host_size, pe_info.pe_image_end
            )));
        }

        host_in.seek(SeekFrom::Start(0))?;
        let mut buf = [0u8; 64 * 1024];
        let mut host_len = 0u64;

        loop {
            let n = host_in.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            host_len += n as u64;
        }

        let inject_offset = host_len;
        let ube_size = ube_in.seek(SeekFrom::End(0))?;
        ube_in.seek(SeekFrom::Start(0))?;

        loop {
            let n = ube_in.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
        }

        Ok((inject_offset, ube_size, 0, 0))
    }

    fn locate(
        &self,
        stego_in: &mut dyn SeekRead,
        expected_trailer_magic: Option<&[u8; 4]>,
    ) -> Result<Option<(u64, u64, String)>, StrHideError> {
        let trailer = match EnvelopeTrailer::read_from_tail(stego_in, expected_trailer_magic)? {
            Some(t) => t,
            None => return Ok(None),
        };

        if let Ok(pe_info) = parse_pe_headers(stego_in)
            && trailer.ube_offset >= pe_info.pe_image_end {
                return Ok(Some((
                    trailer.ube_offset,
                    trailer.ube_total_size,
                    "pe_overlay".into(),
                )));
            }

        let file_size = stego_in.seek(SeekFrom::End(0))?;
        if trailer.ube_offset + trailer.ube_total_size == file_size {
            return Ok(Some((trailer.ube_offset, trailer.ube_total_size, "eof".into())));
        }

        Ok(None)
    }

    fn verify_structure(
        &self,
        stego_in: &mut dyn SeekRead,
    ) -> Result<(bool, String), StrHideError> {
        match parse_pe_headers(stego_in) {
            Ok(info) => Ok((
                true,
                format!(
                    "Valid Windows PE executable ({}, {} sections, code boundary at {} bytes)",
                    info.arch, info.num_sections, info.pe_image_end
                ),
            )),
            Err(e) => Ok((false, format!("Corrupted PE executable: {e}"))),
        }
    }

    fn suspicious_structures(&self, stego_in: &mut dyn SeekRead) -> Vec<String> {
        // Data appended beyond the PE image boundary is an overlay; anything
        // past the minimum envelope size is a probable hidden envelope.
        const MIN_ENVELOPE: u64 = 112 + 24;
        let mut found = Vec::new();
        if let Ok(info) = parse_pe_headers(stego_in)
            && info.host_size > info.pe_image_end + MIN_ENVELOPE {
                found.push(format!(
                    "overlay of {} bytes beyond PE image boundary (minimum envelope size is {MIN_ENVELOPE})",
                    info.host_size - info.pe_image_end
                ));
            }
        found
    }
}
