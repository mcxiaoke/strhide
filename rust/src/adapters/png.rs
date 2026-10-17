//! PNG format adapter for strhide with neutral ancillary chunk and dirty-tail tolerance.

use std::io::{Read, Seek, SeekFrom, Write};
use crate::adapters::{HostAdapter, SeekRead, eof::EofAdapter};
use crate::envelope::{EnvelopeTrailer, STANDARD_TRAILER_MAGIC};
use crate::errors::StrHideError;

pub const PNG_MAGIC: [u8; 8] = *b"\x89PNG\r\n\x1a\n";
pub const IEND_FULL: [u8; 12] = *b"\x00\x00\x00\x00IEND\xaeB`\x82";
pub const CHUNK_PRIV: [u8; 4] = *b"prIv";
pub const CHUNK_STEG: [u8; 4] = *b"stEg";
pub const PNG_MAX_CHUNK_LEN: u64 = 0x7FFFFFFF; // 2GB

pub fn find_iend_offset<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<(u64, u64), StrHideError> {
    let total_size = reader.seek(SeekFrom::End(0))?;
    let scan_len = std::cmp::min(total_size, 64 * 1024);
    reader.seek(SeekFrom::End(-(scan_len as i64)))?;
    let mut tail = vec![0u8; scan_len as usize];
    reader.read_exact(&mut tail)?;

    let idx = tail
        .windows(12)
        .rposition(|w| w == IEND_FULL)
        .ok_or_else(|| {
            StrHideError::CorruptedData("Valid PNG IEND chunk not found within tail scan window".into())
        })?;

    let iend_offset = (total_size - scan_len) + idx as u64;
    Ok((iend_offset, total_size))
}

pub struct PngAdapter;

impl HostAdapter for PngAdapter {
    fn format_name(&self) -> &'static str {
        "PNG"
    }

    fn detect(&self, reader: &mut dyn SeekRead) -> bool {
        let start_pos = match reader.stream_position() {
            Ok(pos) => pos,
            Err(_) => return false,
        };
        if reader.seek(SeekFrom::Start(0)).is_err() {
            return false;
        }
        let mut magic = [0u8; 8];
        let ok = reader.read_exact(&mut magic).is_ok() && magic == PNG_MAGIC;
        let _ = reader.seek(SeekFrom::Start(start_pos));
        ok
    }

    fn supported_strategies(&self) -> Vec<&'static str> {
        vec!["chunk", "eof"]
    }

    fn choose_auto_strategy(&self, _reader: &mut dyn SeekRead, ube_size: u64) -> &'static str {
        if ube_size > PNG_MAX_CHUNK_LEN {
            "eof"
        } else {
            "chunk"
        }
    }

    fn inject(
        &self,
        host_in: &mut dyn SeekRead,
        ube_in: &mut dyn SeekRead,
        out: &mut dyn Write,
        strategy: &str,
    ) -> Result<(u64, u64, u32, u32), StrHideError> {
        if strategy == "eof" {
            return EofAdapter.inject(host_in, ube_in, out, strategy);
        }

        if strategy != "chunk" {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Strategy '{strategy}' not supported by PNG adapter"
            )));
        }

        let ube_size = ube_in.seek(SeekFrom::End(0))?;
        ube_in.seek(SeekFrom::Start(0))?;

        if ube_size > PNG_MAX_CHUNK_LEN {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Payload size ({ube_size} bytes) exceeds PNG chunk maximum capacity (2GB). Please specify --strategy eof."
            )));
        }

        let (iend_offset, _) = find_iend_offset(host_in)?;

        // 1. Write everything before IEND
        host_in.seek(SeekFrom::Start(0))?;
        let mut remaining = iend_offset;
        let mut buf = [0u8; 64 * 1024];

        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
            let n = host_in.read(&mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            remaining -= n as u64;
        }

        let inject_offset = iend_offset;

        // 2. Prepare and write prIv chunk
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&CHUNK_PRIV);

        // CRC pass: an I/O error here must propagate, not be mistaken for EOF,
        // otherwise a truncated read would yield a wrong CRC silently.
        loop {
            let n = ube_in.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let crc_val = hasher.finalize();

        // Write length and chunk type
        out.write_all(&(ube_size as u32).to_be_bytes())?;
        out.write_all(&CHUNK_PRIV)?;

        // Write UBE data
        ube_in.seek(SeekFrom::Start(0))?;
        loop {
            let n = ube_in.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
        }

        // Write CRC
        out.write_all(&crc_val.to_be_bytes())?;

        let inject_size = 4 + 4 + ube_size + 4;

        // 3. Write IEND chunk and any trailing dirty data
        host_in.seek(SeekFrom::Start(iend_offset))?;
        loop {
            let n = host_in.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
        }

        Ok((inject_offset, inject_size, 0, 0))
    }

    fn locate(
        &self,
        stego_in: &mut dyn SeekRead,
        expected_trailer_magic: Option<&[u8; 4]>,
    ) -> Result<Option<(u64, u64, String)>, StrHideError> {
        stego_in.seek(SeekFrom::Start(0))?;
        let mut magic = [0u8; 8];
        if stego_in.read_exact(&mut magic).is_err() || magic != PNG_MAGIC {
            return Ok(None);
        }

        // Check chunk strategy first
        loop {
            let mut hdr = [0u8; 8];
            if stego_in.read_exact(&mut hdr).is_err() {
                break;
            }
            let length = u32::from_be_bytes(hdr[0..4].try_into().unwrap()) as u64;
            let mut chunk_type = [0u8; 4];
            chunk_type.copy_from_slice(&hdr[4..8]);
            let chunk_data_offset = stego_in.stream_position()?;

            if (chunk_type == CHUNK_PRIV || chunk_type == CHUNK_STEG)
                && length >= 112 + 24 {
                    let trailer_offset = chunk_data_offset + length - 24;
                    stego_in.seek(SeekFrom::Start(trailer_offset))?;
                    let mut trailer_bytes = [0u8; 24];
                    if stego_in.read_exact(&mut trailer_bytes).is_ok()
                        && let Ok(trailer) = EnvelopeTrailer::unpack(&trailer_bytes, expected_trailer_magic) {
                            if expected_trailer_magic.is_none() && trailer.trailer_magic != STANDARD_TRAILER_MAGIC {
                                return Ok(None);
                            }
                            return Ok(Some((chunk_data_offset, length, "chunk".into())));
                        }
                }

            if chunk_type == *b"IEND" {
                break;
            }

            stego_in.seek(SeekFrom::Start(chunk_data_offset + length + 4))?;
        }

        // Fallback to EOF
        if let Some(t) = EnvelopeTrailer::read_from_tail(stego_in, expected_trailer_magic)? {
            let file_size = stego_in.seek(SeekFrom::End(0))?;
            if t.ube_offset + t.ube_total_size == file_size {
                return Ok(Some((t.ube_offset, t.ube_total_size, "eof".into())));
            }
        }

        Ok(None)
    }

    fn verify_structure(
        &self,
        stego_in: &mut dyn SeekRead,
    ) -> Result<(bool, String), StrHideError> {
        // Walk every chunk (not just the tail): each 8-byte header and 4-byte
        // CRC must be present, the CRC32 over type+data must match, and the
        // chunk stream must terminate with IEND. Data is streamed through the
        // hasher so multi-GB chunks never materialize in memory.
        stego_in.seek(SeekFrom::Start(0))?;
        let mut magic = [0u8; 8];
        if stego_in.read_exact(&mut magic).is_err() || magic != PNG_MAGIC {
            return Ok((false, "Invalid PNG magic header".into()));
        }

        let mut found_private: Option<String> = None;
        loop {
            let mut hdr = [0u8; 8];
            if stego_in.read_exact(&mut hdr).is_err() {
                return Ok((false, "Truncated PNG chunk header".into()));
            }
            let length = u32::from_be_bytes(hdr[0..4].try_into().unwrap());
            let mut chunk_type = [0u8; 4];
            chunk_type.copy_from_slice(&hdr[4..8]);
            if chunk_type == CHUNK_PRIV || chunk_type == CHUNK_STEG {
                found_private = Some(String::from_utf8_lossy(&chunk_type).to_string());
            }

            let mut hasher = crc32fast::Hasher::new();
            hasher.update(&chunk_type);
            let mut remaining = length as u64;
            let mut buf = [0u8; 64 * 1024];
            while remaining > 0 {
                let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
                let n = stego_in.read(&mut buf[..to_read])?;
                if n == 0 {
                    return Ok((false, format!(
                        "Truncated data for chunk {}",
                        String::from_utf8_lossy(&chunk_type)
                    )));
                }
                hasher.update(&buf[..n]);
                remaining -= n as u64;
            }

            let mut crc_bytes = [0u8; 4];
            if stego_in.read_exact(&mut crc_bytes).is_err() {
                return Ok((false, format!(
                    "Truncated CRC for chunk {}",
                    String::from_utf8_lossy(&chunk_type)
                )));
            }
            if u32::from_be_bytes(crc_bytes) != hasher.finalize() {
                return Ok((false, format!(
                    "CRC32 mismatch for chunk {}",
                    String::from_utf8_lossy(&chunk_type)
                )));
            }

            if chunk_type == *b"IEND" {
                break;
            }
        }

        let detail = match found_private {
            Some(c) => format!("private chunk '{c}' present"),
            None => "clean standard chunks".to_string(),
        };
        Ok((true, format!("PNG structure valid ({detail})")))
    }

    fn suspicious_structures(&self, stego_in: &mut dyn SeekRead) -> Vec<String> {
        // A prIv/stEg chunk carrying >= 136 bytes (minimum envelope size) can
        // only realistically be a hidden envelope.
        const MIN_ENVELOPE: u64 = 112 + 24;
        let mut found = Vec::new();
        stego_in.seek(SeekFrom::Start(0)).ok();
        let mut magic = [0u8; 8];
        if stego_in.read_exact(&mut magic).is_err() || magic != PNG_MAGIC {
            return found;
        }
        loop {
            let mut hdr = [0u8; 8];
            if stego_in.read_exact(&mut hdr).is_err() {
                break;
            }
            let length = u32::from_be_bytes(hdr[0..4].try_into().unwrap()) as u64;
            let mut chunk_type = [0u8; 4];
            chunk_type.copy_from_slice(&hdr[4..8]);
            let data_offset = match stego_in.stream_position() {
                Ok(p) => p,
                Err(_) => break,
            };
            if (chunk_type == CHUNK_PRIV || chunk_type == CHUNK_STEG) && length >= MIN_ENVELOPE {
                found.push(format!(
                    "private chunk '{}' at offset {} carries {length} bytes (minimum envelope size is {MIN_ENVELOPE})",
                    String::from_utf8_lossy(&chunk_type),
                    data_offset - 8
                ));
            }
            if chunk_type == *b"IEND" {
                break;
            }
            if stego_in
                .seek(SeekFrom::Start(data_offset + length + 4))
                .is_err()
            {
                break;
            }
        }
        found
    }
}
