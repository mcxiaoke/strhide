//! Shared RIFF (Resource Interchange File Format) container logic.
//!
//! Shared by [`super::webp::WebpAdapter`] and [`super::wav::WavAdapter`].

use std::io::{SeekFrom, Write};

use crate::adapters::{SeekRead, StrategyCapacity};
use crate::envelope::EnvelopeTrailer;
use crate::errors::StrHideError;

pub const RIFF_CHUNK_FOURCC: [u8; 4] = *b"SHRD";

pub fn riff_detect(reader: &mut dyn SeekRead, expected_form_type: &[u8; 4]) -> bool {
    let start_pos = match reader.stream_position() {
        Ok(pos) => pos,
        Err(_) => return false,
    };
    if reader.seek(SeekFrom::Start(0)).is_err() {
        return false;
    }

    let mut buf = [0u8; 12];
    let detected = if reader.read_exact(&mut buf).is_ok() {
        &buf[0..4] == b"RIFF" && &buf[8..12] == expected_form_type
    } else {
        false
    };

    let _ = reader.seek(SeekFrom::Start(start_pos));
    detected
}

pub fn riff_inject(
    format_name: &str,
    host_in: &mut dyn SeekRead,
    ube_in: &mut dyn SeekRead,
    out: &mut dyn Write,
    strategy: &str,
) -> Result<(u64, u64, u32, u32), StrHideError> {
    if strategy != "riff_chunk" && strategy != "eof" {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Strategy '{strategy}' not supported by {format_name} adapter"
        )));
    }

    let host_len = host_in.seek(SeekFrom::End(0))?;
    if host_len < 12 {
        return Err(StrHideError::CorruptedData(format!(
            "{format_name} file too small for a valid RIFF header"
        )));
    }
    host_in.seek(SeekFrom::Start(0))?;

    let ube_size = ube_in.seek(SeekFrom::End(0))?;
    ube_in.seek(SeekFrom::Start(0))?;

    if strategy == "eof" {
        // Simple EOF overlay
        let host_len = crate::adapters::io::copy_stream(host_in, out)?;
        let inject_offset = host_len;
        crate::adapters::io::copy_exact(ube_in, out, ube_size)?;
        return Ok((inject_offset, ube_size, 0, 0));
    }

    // strategy == "riff_chunk"
    let mut header = [0u8; 12];
    host_in.read_exact(&mut header)?;
    let old_riff_size = u32::from_le_bytes(header[4..8].try_into().unwrap());

    // The SHRD chunk is appended at the physical end of the file while the
    // RIFF size patch assumes the declared boundary coincides with it. A
    // carrier that violates this (streaming WAV with size = 0, trailing ID3
    // or garbage) would leave locate walking junk past the declared boundary
    // — for odd ube sizes the envelope becomes unreachable and the occupied
    // check double-injects — so refuse such carriers up front (review
    // 2026-10-25); `--strategy eof` stays available and symmetric.
    let declared_end = 8u64 + old_riff_size as u64;
    if host_len != declared_end {
        return Err(StrHideError::CorruptedData(format!(
            "{format_name} file length ({host_len}) does not match the declared RIFF size \
             (chunk area ends at {declared_end}); please specify --strategy eof"
        )));
    }

    let pad_len = ube_size % 2;
    let inject_size = 8 + ube_size + pad_len;

    let new_riff_size = (old_riff_size as u64)
        .checked_add(inject_size)
        .ok_or_else(|| StrHideError::General("RIFF 4GB container size overflow".into()))?;
    if new_riff_size > u32::MAX as u64 {
        return Err(StrHideError::General(
            "RIFF 4GB container size overflow".into(),
        ));
    }

    // 1. Write updated RIFF header: "RIFF" + new_riff_size + form_type
    out.write_all(&header[0..4])?;
    out.write_all(&(new_riff_size as u32).to_le_bytes())?;
    out.write_all(&header[8..12])?;

    // 2. Copy remainder of original host carrier
    crate::adapters::io::copy_stream(host_in, out)?;

    let inject_offset = host_len;

    // 3. Write 'SHRD' chunk header (4-byte tag + 4-byte size LE)
    out.write_all(&RIFF_CHUNK_FOURCC)?;
    out.write_all(&(ube_size as u32).to_le_bytes())?;

    // 4. Write UBE data
    crate::adapters::io::copy_exact(ube_in, out, ube_size)?;

    // 5. Write 1-byte 0 padding if chunk data size was odd
    if pad_len == 1 {
        out.write_all(&[0u8])?;
    }

    // Patch record: offset 4 was modified from old_riff_size
    Ok((inject_offset, inject_size, 4, old_riff_size))
}

pub fn riff_locate(
    stego_in: &mut dyn SeekRead,
    expected_trailer_magic: Option<&[u8; 4]>,
) -> Result<Option<(u64, u64, String)>, StrHideError> {
    let file_size = stego_in.seek(SeekFrom::End(0))?;
    if file_size < 12 {
        return Ok(None);
    }
    stego_in.seek(SeekFrom::Start(0))?;

    let mut header = [0u8; 12];
    if stego_in.read_exact(&mut header).is_err() || &header[0..4] != b"RIFF" {
        return Ok(None);
    }

    // Walk chunks looking for 'SHRD'
    let mut offset = 12u64;
    while offset + 8 <= file_size {
        if stego_in.seek(SeekFrom::Start(offset)).is_err() {
            break;
        }
        let mut chunk_hdr = [0u8; 8];
        if stego_in.read_exact(&mut chunk_hdr).is_err() {
            break;
        }
        let fourcc = &chunk_hdr[0..4];
        let chunk_size = u32::from_le_bytes(chunk_hdr[4..8].try_into().unwrap()) as u64;
        let pad = chunk_size % 2;

        if fourcc == RIFF_CHUNK_FOURCC {
            // Found 'SHRD' chunk: verify trailer inside it
            if chunk_size >= 24 && offset + 8 + chunk_size <= file_size {
                let trailer_pos = offset + 8 + chunk_size - 24;
                if stego_in.seek(SeekFrom::Start(trailer_pos)).is_ok() {
                    let mut tail = [0u8; 24];
                    let matched = stego_in
                        .read_exact(&mut tail)
                        .ok()
                        .and_then(|()| EnvelopeTrailer::unpack(&tail, expected_trailer_magic).ok())
                        .filter(|t| t.ube_offset == offset + 8 && t.ube_total_size == chunk_size);
                    if let Some(trailer) = matched {
                        return Ok(Some((
                            trailer.ube_offset,
                            trailer.ube_total_size,
                            "riff_chunk".into(),
                        )));
                    }
                }
            }
        }

        offset = match offset.checked_add(8 + chunk_size + pad) {
            Some(o) => o,
            None => break,
        };
    }

    // Check EOF fallback
    if let Some(trailer) = EnvelopeTrailer::read_from_tail(stego_in, expected_trailer_magic)?
        .filter(|t| t.ube_offset.checked_add(t.ube_total_size) == Some(file_size))
    {
        return Ok(Some((
            trailer.ube_offset,
            trailer.ube_total_size,
            "eof".into(),
        )));
    }

    Ok(None)
}

pub fn riff_verify_structure<F>(
    format_name: &str,
    stego_in: &mut dyn SeekRead,
    expected_form_type: &[u8; 4],
    validate_specific: F,
) -> Result<(bool, String), StrHideError>
where
    F: Fn(&[([u8; 4], u64)]) -> Result<(), String>,
{
    let file_size = stego_in.seek(SeekFrom::End(0))?;
    if file_size < 12 {
        return Ok((false, format!("{format_name} too small for RIFF header")));
    }
    stego_in.seek(SeekFrom::Start(0))?;

    let mut header = [0u8; 12];
    if stego_in.read_exact(&mut header).is_err() {
        return Ok((false, format!("Truncated {format_name} header")));
    }
    if &header[0..4] != b"RIFF" {
        return Ok((false, format!("{format_name} missing 'RIFF' signature")));
    }
    if &header[8..12] != expected_form_type {
        return Ok((
            false,
            format!(
                "{format_name} form type mismatch (expected {}, got {})",
                String::from_utf8_lossy(expected_form_type),
                String::from_utf8_lossy(&header[8..12])
            ),
        ));
    }
    let riff_size = u32::from_le_bytes(header[4..8].try_into().unwrap()) as u64;

    let mut offset = 12u64;
    let mut chunk_count = 0u64;
    let mut chunks = Vec::new();

    let boundary = 8 + riff_size;

    while offset < file_size {
        // Check if remaining bytes at/after declared RIFF boundary are an EOF envelope
        if offset >= boundary {
            let tail_envelope = EnvelopeTrailer::read_from_tail(stego_in, None)
                .ok()
                .flatten()
                .filter(|t| {
                    t.ube_offset == offset
                        && offset.checked_add(t.ube_total_size) == Some(file_size)
                });
            if let Some(trailer) = tail_envelope {
                validate_specific(&chunks).map_err(StrHideError::CorruptedData)?;
                return Ok((
                    true,
                    format!(
                        "Valid {format_name} RIFF container ({chunk_count} chunks, {} bytes appended after RIFF boundary)",
                        trailer.ube_total_size
                    ),
                ));
            }
        }

        if offset + 8 > file_size {
            return Ok((
                false,
                format!("Truncated chunk header at offset {offset} in {format_name}"),
            ));
        }
        stego_in.seek(SeekFrom::Start(offset))?;
        let mut ch_hdr = [0u8; 8];
        if stego_in.read_exact(&mut ch_hdr).is_err() {
            return Ok((false, format!("Failed to read chunk header at {offset}")));
        }
        let tag = [ch_hdr[0], ch_hdr[1], ch_hdr[2], ch_hdr[3]];
        let size = u32::from_le_bytes(ch_hdr[4..8].try_into().unwrap()) as u64;
        let pad = size % 2;

        chunks.push((tag, size));
        chunk_count += 1;

        offset = match offset.checked_add(8 + size + pad) {
            Some(o) => o,
            None => return Ok((false, "Chunk offset arithmetic overflow".into())),
        };

        if offset > file_size && offset != file_size + pad {
            return Ok((
                false,
                format!(
                    "Chunk '{}' at offset {} extends past end of file",
                    String::from_utf8_lossy(&tag),
                    offset - (8 + size + pad)
                ),
            ));
        }
    }

    if let Err(msg) = validate_specific(&chunks) {
        return Ok((false, msg));
    }

    Ok((
        true,
        format!("Valid {format_name} RIFF container ({chunk_count} chunks)"),
    ))
}

pub fn riff_suspicious_structures(stego_in: &mut dyn SeekRead) -> Vec<String> {
    let mut found = Vec::new();
    let file_size = match stego_in.seek(SeekFrom::End(0)) {
        Ok(s) => s,
        Err(_) => return found,
    };
    if file_size < 12 {
        return found;
    }
    if stego_in.seek(SeekFrom::Start(12)).is_err() {
        return found;
    }

    let mut offset = 12u64;
    while offset + 8 <= file_size {
        if stego_in.seek(SeekFrom::Start(offset)).is_err() {
            break;
        }
        let mut hdr = [0u8; 8];
        if stego_in.read_exact(&mut hdr).is_err() {
            break;
        }
        let tag = &hdr[0..4];
        let size = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as u64;
        let pad = size % 2;

        if tag == RIFF_CHUNK_FOURCC {
            found.push(format!(
                "RIFF private chunk 'SHRD' at offset {offset} carries {size} bytes"
            ));
        }

        offset = match offset.checked_add(8 + size + pad) {
            Some(o) => o,
            None => break,
        };
    }
    found
}

/// Whether `riff_chunk` can accept this carrier and envelope: the declared
/// RIFF boundary must coincide with the physical end of the file, and the
/// patched size field must stay inside u32. Mirrors the hard checks in
/// [`riff_inject`] so the auto decision and the capacity table share one
/// predicate instead of drifting (review P3-17).
pub fn riff_can_chunk(reader: &mut dyn SeekRead, ube_size: u64) -> bool {
    let start = reader.stream_position().unwrap_or(0);
    let host_len = match reader.seek(SeekFrom::End(0)) {
        Ok(l) => l,
        Err(_) => return false,
    };
    if reader.seek(SeekFrom::Start(0)).is_err() {
        return false;
    }
    let mut header = [0u8; 12];
    let ok = if reader.read_exact(&mut header).is_ok() {
        let old_riff_size = u32::from_le_bytes(header[4..8].try_into().unwrap()) as u64;
        let pad = ube_size % 2;
        let inject_size = 8 + ube_size + pad;
        host_len == 8 + old_riff_size && old_riff_size + inject_size <= u32::MAX as u64
    } else {
        false
    };
    let _ = reader.seek(SeekFrom::Start(start));
    ok
}

pub fn riff_strategy_capacities(
    format_name: &str,
    reader: Option<&mut dyn SeekRead>,
) -> Vec<StrategyCapacity> {
    let mut chunk = StrategyCapacity {
        strategy: "riff_chunk".into(),
        capacity_bytes: None,
        available: true,
        limit: "up to 4GB RIFF limit (file grows)".into(),
        note: Some(format!(
            "Embedded into compliant {format_name} private RIFF chunk 'SHRD' (0 trailing bytes)"
        )),
    };
    if let Some(r) = reader {
        let start = r.stream_position().ok();
        // The boundary predicate is payload-independent, so a zero-sized
        // envelope decides availability; the 4 GiB limit is payload-dependent
        // and stays as the generic limit text.
        if !riff_can_chunk(r, 0) {
            chunk.available = false;
            chunk.note = Some(
                "declared RIFF boundary does not match the file length; auto falls back to eof"
                    .into(),
            );
        }
        if let Some(p) = start {
            let _ = r.seek(SeekFrom::Start(p));
        }
    }
    vec![
        chunk,
        StrategyCapacity {
            strategy: "eof".into(),
            capacity_bytes: None,
            available: true,
            limit: "unlimited (file grows)".into(),
            note: Some(format!("Appended after {format_name} EOF (EOF overlay)")),
        },
    ]
}
