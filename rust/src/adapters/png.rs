//! PNG format adapter for strhide with neutral ancillary chunk and dirty-tail tolerance.

use crate::adapters::{
    FinalizeCtx, HostAdapter, SeekRead, SeekReadWrite, StrategyCapacity, eof::EofAdapter,
    format_bytes,
};
use crate::envelope::EnvelopeTrailer;
use crate::errors::StrHideError;
use std::io::{Read, Seek, SeekFrom, Write};

pub const PNG_MAGIC: [u8; 8] = *b"\x89PNG\r\n\x1a\n";
pub const IEND_FULL: [u8; 12] = *b"\x00\x00\x00\x00IEND\xaeB`\x82";
pub const CHUNK_PRIV: [u8; 4] = *b"prIv";
pub const CHUNK_STEG: [u8; 4] = *b"stEg";
pub const PNG_MAX_CHUNK_LEN: u64 = 0x7FFFFFFF; // 2GB

/// Offset of the last IEND chunk and the total file size.
///
/// IEND is not required to sit inside a fixed tail window: PNGs are commonly
/// followed by arbitrary bytes (watermarks, vendor metadata, anti-scraping
/// padding, and for strhide specifically an EOF-overlay envelope). A 64 KiB
/// tail window made `write -s chunk` — and `auto` for small payloads — fail on
/// otherwise valid PNGs.
///
/// The scan walks backwards in 64 KiB chunks with an `IEND_FULL.len() - 1`
/// byte overlap (so a marker straddling a chunk boundary is still seen) and
/// stops at the first hit, i.e. the last marker in file order — the one that
/// terminates the chunk stream. Matching the full 12-byte chunk
/// (`length = 0`, `IEND`, CRC `AE 42 60 82`) instead of a short magic keeps
/// accidental hits inside compressed image data negligible (~2^-96).
pub fn find_iend_offset<R: Read + Seek + ?Sized>(
    reader: &mut R,
) -> Result<(u64, u64), StrHideError> {
    const CHUNK: u64 = 64 * 1024;
    let total_size = reader.seek(SeekFrom::End(0))?;
    let mut end = total_size;
    while end > 0 {
        let start = end.saturating_sub(CHUNK);
        let read_start = start.saturating_sub(IEND_FULL.len() as u64 - 1);
        let mut buf = vec![0u8; (end - read_start) as usize];
        reader.seek(SeekFrom::Start(read_start))?;
        reader.read_exact(&mut buf)?;
        if let Some(idx) = buf.windows(IEND_FULL.len()).rposition(|w| w == IEND_FULL) {
            return Ok((read_start + idx as u64, total_size));
        }
        end = start;
    }

    Err(StrHideError::CorruptedData(
        "Valid PNG IEND chunk not found".into(),
    ))
}

pub struct PngAdapter;

impl HostAdapter for PngAdapter {
    fn format_name(&self) -> &'static str {
        "PNG"
    }

    fn supports_content_stego(&self) -> bool {
        true
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

    fn strategy_capacities(&self, _reader: Option<&mut dyn SeekRead>) -> Vec<StrategyCapacity> {
        vec![
            StrategyCapacity {
                strategy: "chunk".into(),
                capacity_bytes: Some(PNG_MAX_CHUNK_LEN),
                available: true,
                limit: format!("<= {} B (2 GiB - 1)", format_bytes(PNG_MAX_CHUNK_LEN)),
                note: Some(
                    "private ancillary chunk 'prIv' before IEND; file grows slightly".into(),
                ),
            },
            StrategyCapacity {
                strategy: "eof".into(),
                capacity_bytes: None,
                available: true,
                limit: "unlimited (file grows)".into(),
                note: Some("appended after IEND".into()),
            },
        ]
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
        crate::adapters::io::copy_exact(host_in, out, iend_offset)?;

        let inject_offset = iend_offset;

        // 2. Write the prIv chunk: `[u32 length][type][data][u32 crc]`.
        // The CRC sits *after* the data, so it can be accumulated while the
        // same bytes are being written — the previous two-pass version read the
        // whole envelope twice (once for the CRC, once to copy).
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&CHUNK_PRIV);

        out.write_all(&(ube_size as u32).to_be_bytes())?;
        out.write_all(&CHUNK_PRIV)?;

        let mut buf = [0u8; 64 * 1024];
        let mut remaining = ube_size;
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
            let n = ube_in.read(&mut buf[..to_read])?;
            if n == 0 {
                return Err(StrHideError::CorruptedData(
                    "Envelope stream ended before its declared size".into(),
                ));
            }
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        out.write_all(&hasher.finalize().to_be_bytes())?;

        let inject_size = 4 + 4 + ube_size + 4;

        // 3. Write IEND chunk and any trailing dirty data
        host_in.seek(SeekFrom::Start(iend_offset))?;
        crate::adapters::io::copy_stream(host_in, out)?;

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

            if (chunk_type == CHUNK_PRIV || chunk_type == CHUNK_STEG) && length >= 112 + 24 {
                let trailer_offset = chunk_data_offset + length - 24;
                stego_in.seek(SeekFrom::Start(trailer_offset))?;
                let mut trailer_bytes = [0u8; 24];
                if stego_in.read_exact(&mut trailer_bytes).is_ok()
                    && EnvelopeTrailer::unpack(&trailer_bytes, expected_trailer_magic).is_ok()
                {
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
                    return Ok((
                        false,
                        format!(
                            "Truncated data for chunk {}",
                            String::from_utf8_lossy(&chunk_type)
                        ),
                    ));
                }
                hasher.update(&buf[..n]);
                remaining -= n as u64;
            }

            let mut crc_bytes = [0u8; 4];
            if stego_in.read_exact(&mut crc_bytes).is_err() {
                return Ok((
                    false,
                    format!(
                        "Truncated CRC for chunk {}",
                        String::from_utf8_lossy(&chunk_type)
                    ),
                ));
            }
            if u32::from_be_bytes(crc_bytes) != hasher.finalize() {
                return Ok((
                    false,
                    format!(
                        "CRC32 mismatch for chunk {}",
                        String::from_utf8_lossy(&chunk_type)
                    ),
                ));
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

    fn envelope_offset_delta(
        &self,
        _carrier: &mut dyn SeekRead,
        strategy: &str,
        _ube_size: u64,
    ) -> Result<u64, StrHideError> {
        if strategy == "chunk" { Ok(8) } else { Ok(0) }
    }

    fn finalize(
        &self,
        carrier: &mut dyn SeekReadWrite,
        ctx: &FinalizeCtx,
    ) -> Result<(), StrHideError> {
        if ctx.strategy == "chunk" {
            // PNG chunk: recalculate chunk CRC over chunk_type + data (streaming to avoid large allocations)
            carrier.seek(SeekFrom::Start(ctx.ube_offset - 4))?;
            let mut hasher = crc32fast::Hasher::new();
            let mut buf = [0u8; 64 * 1024];
            let mut remaining = 4 + ctx.ube_total_size;

            while remaining > 0 {
                let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
                carrier.read_exact(&mut buf[..to_read])?;
                hasher.update(&buf[..to_read]);
                remaining -= to_read as u64;
            }

            let new_crc = hasher.finalize();
            carrier.seek(SeekFrom::Start(ctx.ube_offset + ctx.ube_total_size))?;
            carrier.write_all(&new_crc.to_be_bytes())?;
        }
        Ok(())
    }

    fn strategy_note(&self, strategy: &str, fallback: bool) -> Option<String> {
        if strategy == "chunk" {
            Some("Embedded into compliant PNG private ancillary chunk 'prIv' before IEND (0 trailing bytes).".into())
        } else if strategy == "eof" && fallback {
            Some(
                "Payload exceeded PNG chunk limit (2GB); automatically fell back to EOF overlay."
                    .into(),
            )
        } else if strategy == "eof" {
            Some("Appended after PNG IEND (EOF overlay).".into())
        } else {
            None
        }
    }
}
