//! PNG format adapter for strhide with neutral ancillary chunk and dirty-tail tolerance.

use crate::errors::StrHideError;
use crate::structure::adapters::{
    FinalizeCtx, HostAdapter, SeekRead, SeekReadWrite, StrategyCapacity, eof::EofAdapter,
    format_bytes,
};
use crate::structure::envelope::EnvelopeTrailer;
use std::io::{Read, Seek, SeekFrom, Write};

pub const PNG_MAGIC: [u8; 8] = *b"\x89PNG\r\n\x1a\n";
pub const IEND_FULL: [u8; 12] = *b"\x00\x00\x00\x00IEND\xaeB`\x82";
pub const CHUNK_PRIV: [u8; 4] = *b"prIv";
pub const CHUNK_STEG: [u8; 4] = *b"stEg";
pub const PNG_MAX_CHUNK_LEN: u64 = 0x7FFFFFFF; // 2GB

/// Offset of the standard IEND chunk and the total file size.
///
/// Follows the standard PNG chunk stream from offset 8 forward: each chunk's
/// 4-byte big-endian length dictates the jump to the next chunk. The scan stops
/// at the first `IEND` chunk encountered. Any arbitrary bytes following `IEND`
/// (such as an EOF-overlay envelope or dirty tail metadata) are preserved as part
/// of `total_size`.
///
/// If any chunk header is truncated or malformed, or if the file does not begin
/// with the PNG signature, the function immediately rejects the carrier.
pub fn find_iend_offset<R: Read + Seek + ?Sized>(
    reader: &mut R,
) -> Result<(u64, u64), StrHideError> {
    let total_size = reader.seek(SeekFrom::End(0))?;
    if total_size < 8 + 12 {
        return Err(StrHideError::CorruptedData(
            "File too small to be a valid PNG".into(),
        ));
    }
    reader.seek(SeekFrom::Start(0))?;
    let mut sig = [0u8; 8];
    reader.read_exact(&mut sig)?;
    if sig != PNG_MAGIC {
        return Err(StrHideError::UnsupportedFormat(
            "Invalid PNG magic signature".into(),
        ));
    }

    let mut last_iend = None;
    let mut pos = 8u64;

    while pos + 8 <= total_size {
        reader.seek(SeekFrom::Start(pos))?;
        let mut hdr = [0u8; 8];
        if reader.read_exact(&mut hdr).is_err() {
            break;
        }

        // If a concatenated PNG stream is encountered, skip its 8-byte magic
        if hdr == PNG_MAGIC {
            pos += 8;
            continue;
        }

        let length = u32::from_be_bytes(hdr[0..4].try_into().unwrap()) as u64;
        let chunk_type = &hdr[4..8];

        if length > PNG_MAX_CHUNK_LEN {
            break;
        }

        let Some(chunk_total_len) = length.checked_add(12) else {
            break;
        };
        let Some(next_pos) = pos.checked_add(chunk_total_len) else {
            break;
        };
        if next_pos > total_size {
            break;
        }

        if chunk_type == b"IEND" && length == 0 {
            last_iend = Some(pos);
        }

        pos = next_pos;
    }

    if let Some(iend_pos) = last_iend {
        Ok((iend_pos, total_size))
    } else {
        Err(StrHideError::CorruptedData(
            "Valid PNG IEND chunk not found".into(),
        ))
    }
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
        crate::structure::adapters::io::copy_exact(host_in, out, iend_offset)?;

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
        crate::structure::adapters::io::copy_stream(host_in, out)?;

        Ok((inject_offset, inject_size, 0, 0))
    }

    fn locate(
        &self,
        stego_in: &mut dyn SeekRead,
        expected_trailer_magic: Option<&[u8; 4]>,
    ) -> Result<Option<(u64, u64, String)>, StrHideError> {
        self.locate_with_hint(stego_in, expected_trailer_magic, None)
    }

    fn locate_with_hint(
        &self,
        stego_in: &mut dyn SeekRead,
        expected_trailer_magic: Option<&[u8; 4]>,
        expected_header_magic: Option<&[u8; 8]>,
    ) -> Result<Option<(u64, u64, String)>, StrHideError> {
        // Stealth and custom-magic dialects use a password/seed-derived 8-byte
        // header magic, not the standard one. Without the caller's hint the
        // shifted-chunk check below would reject every shifted non-official
        // envelope (the original P0-2 failure).
        let expected_header_magic = expected_header_magic
            .copied()
            .unwrap_or(crate::params::STANDARD_HEADER_MAGIC);
        let file_size = stego_in.seek(SeekFrom::End(0))?;
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

            // A truncated or crafted chunk must not send the scan past EOF or
            // wrap the next-offset arithmetic.
            let Some(next_pos) = chunk_data_offset
                .checked_add(length)
                .and_then(|v| v.checked_add(4))
            else {
                break;
            };
            if next_pos > file_size {
                break;
            }

            if (chunk_type == CHUNK_PRIV || chunk_type == CHUNK_STEG) && length >= 112 + 24 {
                let trailer_offset = chunk_data_offset + length - 24;
                stego_in.seek(SeekFrom::Start(trailer_offset))?;
                let mut trailer_bytes = [0u8; 24];
                if stego_in.read_exact(&mut trailer_bytes).is_ok()
                    && let Ok(trailer) =
                        EnvelopeTrailer::unpack(&trailer_bytes, expected_trailer_magic)
                {
                    // A valid trailer alone is not enough: private chunks from
                    // other tools (or an old envelope's leftover bytes) can
                    // carry one that points somewhere else entirely.
                    // When content-domain steganography embeds payload into the
                    // preceding IDAT chunks, re-compression may shift the physical
                    // file offset of this chunk. We accept the shifted chunk if
                    // its declared size matches and its data begins with a valid header magic.
                    if trailer.ube_total_size == length {
                        let is_exact = trailer.ube_offset == chunk_data_offset;
                        let is_valid_shifted = if !is_exact {
                            stego_in.seek(SeekFrom::Start(chunk_data_offset))?;
                            let mut hdr = [0u8; 8];
                            if stego_in.read_exact(&mut hdr).is_ok() {
                                hdr == expected_header_magic
                            } else {
                                false
                            }
                        } else {
                            false
                        };

                        if is_exact || is_valid_shifted {
                            return Ok(Some((chunk_data_offset, length, "chunk".into())));
                        }
                    }
                }
            }

            stego_in.seek(SeekFrom::Start(next_pos))?;
            if chunk_type == *b"IEND" {
                // Concatenated PNG streams are legal input. The next stream's
                // 8-byte magic sits exactly where a chunk header would; skip it
                // and keep scanning instead of stopping at the first IEND, which
                // hid envelopes written before the *last* one (review B-01).
                let mut next_magic = [0u8; 8];
                if stego_in.read_exact(&mut next_magic).is_ok() && next_magic == PNG_MAGIC {
                    continue;
                }
                break;
            }
        }

        // Fallback to EOF
        if let Some(t) = EnvelopeTrailer::read_from_tail(stego_in, expected_trailer_magic)? {
            let file_size = stego_in.seek(SeekFrom::End(0))?;
            if t.ube_offset.checked_add(t.ube_total_size) == Some(file_size) {
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
                // Keep verifying a concatenated stream too: hiding before the
                // last IEND is legal, so the first IEND is not the end of the
                // chunk stream (review B-01).
                let mut next_magic = [0u8; 8];
                if stego_in.read_exact(&mut next_magic).is_ok() && next_magic == PNG_MAGIC {
                    continue;
                }
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
            if stego_in
                .seek(SeekFrom::Start(data_offset + length + 4))
                .is_err()
            {
                break;
            }
            if chunk_type == *b"IEND" {
                // Continue through a concatenated PNG stream (review B-01).
                let mut next_magic = [0u8; 8];
                if stego_in.read_exact(&mut next_magic).is_ok() && next_magic == PNG_MAGIC {
                    continue;
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structure::envelope::{STANDARD_TRAILER_MAGIC, TRAILER_SIZE};
    use std::io::Cursor;

    fn push_chunk(out: &mut Vec<u8>, tag: &[u8; 4], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(tag);
        out.extend_from_slice(data);
        // `locate` does not verify chunk CRCs, so zeros are fine in fixtures.
        out.extend_from_slice(&[0u8; 4]);
    }

    /// Build a PNG carrying one `prIv` chunk with a valid trailer whose
    /// `ube_offset` is `trailer_offset`.
    fn png_with_private_chunk(trailer_offset: u64) -> (Vec<u8>, usize) {
        let mut png = Vec::new();
        png.extend_from_slice(&PNG_MAGIC);
        push_chunk(&mut png, b"IHDR", &[0u8; 13]);

        let body_len = 112usize;
        let mut data = vec![0u8; body_len + TRAILER_SIZE];
        let trailer =
            EnvelopeTrailer::create(trailer_offset, data.len() as u64, STANDARD_TRAILER_MAGIC);
        data[body_len..].copy_from_slice(&trailer.pack());
        push_chunk(&mut png, &CHUNK_PRIV, &data);
        push_chunk(&mut png, b"IEND", &[]);
        (png, data.len())
    }

    /// A private chunk whose trailing 24 bytes look like a trailer but point at
    /// another region must not be mistaken for an envelope.
    #[test]
    fn locate_rejects_a_trailer_that_describes_another_region() {
        let (png, _) = png_with_private_chunk(0);
        let mut cursor = Cursor::new(&png);
        let located = PngAdapter
            .locate(&mut cursor, Some(&STANDARD_TRAILER_MAGIC))
            .expect("locate must not error");
        assert!(located.is_none(), "foreign trailer must not match");
    }

    /// Positive control: the same bytes are found once the trailer describes
    /// the chunk it sits in.
    #[test]
    fn locate_accepts_a_trailer_that_describes_its_chunk() {
        // magic(8) + IHDR chunk(25) + the private chunk's own header(8).
        let chunk_data_offset = 8 + 25 + 8;
        let (png, data_len) = png_with_private_chunk(chunk_data_offset as u64);
        let mut cursor = Cursor::new(&png);
        let located = PngAdapter
            .locate(&mut cursor, Some(&STANDARD_TRAILER_MAGIC))
            .expect("locate must not error")
            .expect("a self-describing trailer must be found");
        assert_eq!(located.0, chunk_data_offset as u64);
        assert_eq!(located.1, data_len as u64);
    }
}
