//! JPEG format adapter for strhide with COM segment hiding and precise marker scanning.

use std::io::{Read, Seek, SeekFrom, Write};
use crate::adapters::{HostAdapter, SeekRead, eof::EofAdapter};
use crate::envelope::EnvelopeTrailer;
use crate::errors::StrHideError;

pub const JPEG_SOI: [u8; 2] = [0xFF, 0xD8];
pub const JPEG_SOS: [u8; 2] = [0xFF, 0xDA];
pub const JPEG_COM: [u8; 2] = [0xFF, 0xFE];
pub const JPEG_MAX_SEG_PAYLOAD: u64 = 65533; // 65535 - 2 bytes length

pub fn find_jpeg_sos_offset<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<u64, StrHideError> {
    reader.seek(SeekFrom::Start(0))?;
    let mut soi = [0u8; 2];
    reader.read_exact(&mut soi)?;
    if soi != JPEG_SOI {
        return Err(StrHideError::CorruptedData("Invalid JPEG SOI marker".into()));
    }

    loop {
        let marker_start = reader.stream_position()?;
        let mut lead = [0u8; 1];
        if reader.read_exact(&mut lead).is_err() {
            break;
        }
        if lead[0] != 0xFF {
            continue;
        }

        let mut code = [0u8; 1];
        if reader.read_exact(&mut code).is_err() {
            break;
        }
        while code[0] == 0xFF {
            if reader.read_exact(&mut code).is_err() {
                break;
            }
        }

        let b = code[0];
        // Standalone markers without length: SOI, EOI, TEM, RSTm
        if b == 0xD8 || b == 0xD9 || b == 0x01 || (0xD0..=0xD7).contains(&b) {
            continue;
        }

        if b == 0xDA {
            // SOS (Start of Scan)
            return Ok(marker_start);
        }

        let mut len_bytes = [0u8; 2];
        if reader.read_exact(&mut len_bytes).is_err() {
            break;
        }
        let seg_len = u16::from_be_bytes(len_bytes) as u64;
        if seg_len < 2 {
            return Err(StrHideError::CorruptedData(format!(
                "Invalid JPEG segment length: {seg_len}"
            )));
        }
        reader.seek(SeekFrom::Current((seg_len - 2) as i64))?;
    }

    Err(StrHideError::CorruptedData(
        "JPEG SOS (Start of Scan) marker not found".into(),
    ))
}

pub struct JpegAdapter;

impl HostAdapter for JpegAdapter {
    fn format_name(&self) -> &'static str {
        "JPEG"
    }

    fn detect(&self, reader: &mut dyn SeekRead) -> bool {
        let start_pos = match reader.stream_position() {
            Ok(pos) => pos,
            Err(_) => return false,
        };
        if reader.seek(SeekFrom::Start(0)).is_err() {
            return false;
        }
        let mut soi = [0u8; 2];
        let ok = reader.read_exact(&mut soi).is_ok() && soi == JPEG_SOI;
        let _ = reader.seek(SeekFrom::Start(start_pos));
        ok
    }

    fn supported_strategies(&self) -> Vec<&'static str> {
        vec!["app_segment", "eof"]
    }

    fn choose_auto_strategy(&self, _reader: &mut dyn SeekRead, ube_size: u64) -> &'static str {
        if ube_size > JPEG_MAX_SEG_PAYLOAD {
            "eof"
        } else {
            "app_segment"
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

        if strategy != "app_segment" {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Strategy '{strategy}' not supported by JPEG adapter"
            )));
        }

        let ube_size = ube_in.seek(SeekFrom::End(0))?;
        ube_in.seek(SeekFrom::Start(0))?;

        if ube_size > JPEG_MAX_SEG_PAYLOAD {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Payload size ({ube_size} bytes) exceeds JPEG single segment maximum capacity ({JPEG_MAX_SEG_PAYLOAD} bytes). Please specify --strategy eof."
            )));
        }

        let sos_offset = find_jpeg_sos_offset(host_in)?;

        // 1. Write everything before SOS
        host_in.seek(SeekFrom::Start(0))?;
        let mut remaining = sos_offset;
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

        let inject_offset = sos_offset;

        // 2. Write COM marker segment: [0xFF, 0xFE] + [2B length (BE)] + [UBE]
        let seg_len = (2 + ube_size) as u16;
        out.write_all(&JPEG_COM)?;
        out.write_all(&seg_len.to_be_bytes())?;

        loop {
            let n = ube_in.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
        }

        let inject_size = 2 + 2 + ube_size;

        // 3. Write host from SOS onwards
        host_in.seek(SeekFrom::Start(sos_offset))?;
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
        let mut soi = [0u8; 2];
        if stego_in.read_exact(&mut soi).is_err() || soi != JPEG_SOI {
            return Ok(None);
        }

        // 1. Scan markers before SOS for COM segment containing UBE
        loop {
            let mut lead = [0u8; 1];
            if stego_in.read_exact(&mut lead).is_err() {
                break;
            }
            if lead[0] != 0xFF {
                continue;
            }

            let mut code = [0u8; 1];
            if stego_in.read_exact(&mut code).is_err() {
                break;
            }
            while code[0] == 0xFF {
                if stego_in.read_exact(&mut code).is_err() {
                    break;
                }
            }

            let b = code[0];
            if b == 0xD8 || b == 0xD9 || b == 0x01 || (0xD0..=0xD7).contains(&b) {
                continue;
            }

            if b == 0xDA {
                // SOS reached, stop scan
                break;
            }

            let mut len_bytes = [0u8; 2];
            if stego_in.read_exact(&mut len_bytes).is_err() {
                break;
            }
            let seg_len = u16::from_be_bytes(len_bytes) as u64;
            if seg_len < 2 {
                break;
            }

            let payload_len = seg_len - 2;
            let payload_offset = stego_in.stream_position()?;

            if b == 0xFE && payload_len >= 112 + 24 {
                let trailer_offset = payload_offset + payload_len - 24;
                stego_in.seek(SeekFrom::Start(trailer_offset))?;
                let mut trailer_bytes = [0u8; 24];
                if stego_in.read_exact(&mut trailer_bytes).is_ok() {
                    if let Ok(trailer) = EnvelopeTrailer::unpack(&trailer_bytes, expected_trailer_magic) {
                        if expected_trailer_magic.is_none() && trailer.trailer_magic != crate::envelope::STANDARD_TRAILER_MAGIC {
                            return Ok(None);
                        }
                        return Ok(Some((payload_offset, payload_len, "app_segment".into())));
                    }
                }
            }

            stego_in.seek(SeekFrom::Start(payload_offset + payload_len))?;
        }

        // 2. Fallback to EOF
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
        match find_jpeg_sos_offset(stego_in) {
            Ok(offset) => Ok((
                true,
                format!("Valid JPEG image (SOS marker at offset {offset})"),
            )),
            Err(e) => Ok((false, format!("Corrupted JPEG structure: {e}"))),
        }
    }

    fn suspicious_structures(&self, stego_in: &mut dyn SeekRead) -> Vec<String> {
        // A COM segment before SOS carrying >= 136 bytes (minimum envelope
        // size) can only realistically be a hidden envelope.
        const MIN_ENVELOPE: u64 = 112 + 24;
        let mut found = Vec::new();
        stego_in.seek(SeekFrom::Start(0)).ok();
        let mut soi = [0u8; 2];
        if stego_in.read_exact(&mut soi).is_err() || soi != JPEG_SOI {
            return found;
        }
        loop {
            let mut lead = [0u8; 1];
            if stego_in.read_exact(&mut lead).is_err() {
                break;
            }
            if lead[0] != 0xFF {
                continue;
            }
            let mut code = [0u8; 1];
            if stego_in.read_exact(&mut code).is_err() {
                break;
            }
            while code[0] == 0xFF {
                if stego_in.read_exact(&mut code).is_err() {
                    return found;
                }
            }
            let b = code[0];
            if b == 0xD8 || b == 0xD9 || b == 0x01 || (0xD0..=0xD7).contains(&b) {
                continue;
            }
            if b == 0xDA {
                break;
            }
            let mut len_bytes = [0u8; 2];
            if stego_in.read_exact(&mut len_bytes).is_err() {
                break;
            }
            let seg_len = u16::from_be_bytes(len_bytes) as u64;
            if seg_len < 2 {
                break;
            }
            let payload_offset = match stego_in.stream_position() {
                Ok(p) => p,
                Err(_) => break,
            };
            let payload_len = seg_len - 2;
            if b == 0xFE && payload_len >= MIN_ENVELOPE {
                found.push(format!(
                    "COM segment at offset {payload_offset} carries {payload_len} bytes (minimum envelope size is {MIN_ENVELOPE})"
                ));
            }
            if stego_in
                .seek(SeekFrom::Start(payload_offset + payload_len))
                .is_err()
            {
                break;
            }
        }
        found
    }
}
