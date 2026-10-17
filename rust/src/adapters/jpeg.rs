//! JPEG format adapter for strhide with APP15/COM segment multi-chain hiding.

use std::io::{Read, Seek, SeekFrom, Write};
use crate::adapters::{HostAdapter, SeekRead, SubStream, eof::EofAdapter};
use crate::envelope::EnvelopeTrailer;
use crate::errors::StrHideError;

pub const JPEG_SOI: [u8; 2] = [0xFF, 0xD8];
pub const JPEG_SOS: [u8; 2] = [0xFF, 0xDA];
pub const JPEG_EOI: [u8; 2] = [0xFF, 0xD9];
pub const JPEG_APP15: [u8; 2] = [0xFF, 0xEF];
pub const JPEG_COM: [u8; 2] = [0xFF, 0xFE];
pub const JPEG_MAX_SEG_PAYLOAD: u64 = 65533; // 65535 - 2 bytes length
pub const JPEG_MAX_TOTAL_CAPACITY: u64 = 64 * 1024 * 1024; // 64MB

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

/// Compute segment payload lengths such that each segment <= 65533 bytes
/// and the final segment is always >= 24 bytes (to safely contain EnvelopeTrailer).
pub fn partition_jpeg_payload_lengths(mut total_size: u64) -> Vec<u64> {
    if total_size <= JPEG_MAX_SEG_PAYLOAD {
        return vec![total_size];
    }
    let mut lengths = Vec::new();
    while total_size > 0 {
        if total_size <= JPEG_MAX_SEG_PAYLOAD {
            lengths.push(total_size);
            break;
        }
        let rem = total_size - JPEG_MAX_SEG_PAYLOAD;
        if rem < 24 {
            // Borrow from current segment so the final segment has at least 1024 bytes
            let borrow = 1024.min(JPEG_MAX_SEG_PAYLOAD - 24);
            lengths.push(JPEG_MAX_SEG_PAYLOAD - borrow);
            lengths.push(rem + borrow);
            break;
        } else {
            lengths.push(JPEG_MAX_SEG_PAYLOAD);
            total_size -= JPEG_MAX_SEG_PAYLOAD;
        }
    }
    lengths
}

/// A SeekRead stream bridging across a chained sequence of JPEG segment bodies.
pub struct JpegChainedSegmentReader<'a> {
    inner: &'a mut dyn SeekRead,
    segments: Vec<(u64, u64)>, // (payload_offset, payload_len)
    total_size: u64,
    logical_pos: u64,
}

impl<'a> JpegChainedSegmentReader<'a> {
    pub fn new(
        inner: &'a mut dyn SeekRead,
        segments: Vec<(u64, u64)>,
        total_size: u64,
    ) -> Result<Self, StrHideError> {
        let mut r = Self {
            inner,
            segments,
            total_size,
            logical_pos: 0,
        };
        r.sync_inner_seek()?;
        Ok(r)
    }

    fn sync_inner_seek(&mut self) -> Result<(), StrHideError> {
        if self.logical_pos >= self.total_size {
            return Ok(());
        }
        let mut rem = self.logical_pos;
        for &(start, len) in &self.segments {
            if rem < len {
                self.inner.seek(SeekFrom::Start(start + rem))?;
                return Ok(());
            }
            rem -= len;
        }
        Ok(())
    }
}

impl Read for JpegChainedSegmentReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.logical_pos >= self.total_size || buf.is_empty() {
            return Ok(0);
        }

        let mut rem = self.logical_pos;
        let mut target_seg = None;
        for &(start, len) in &self.segments {
            if rem < len {
                target_seg = Some((start, len, rem));
                break;
            }
            rem -= len;
        }

        let (seg_start, seg_len, offset_in_seg) = match target_seg {
            Some(s) => s,
            None => return Ok(0),
        };

        let seg_remaining = seg_len - offset_in_seg;
        let total_remaining = self.total_size - self.logical_pos;
        let to_read = std::cmp::min(
            buf.len() as u64,
            std::cmp::min(seg_remaining, total_remaining),
        ) as usize;

        self.inner
            .seek(SeekFrom::Start(seg_start + offset_in_seg))?;
        let n = self.inner.read(&mut buf[..to_read])?;
        self.logical_pos += n as u64;
        Ok(n)
    }
}

impl Seek for JpegChainedSegmentReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::Current(p) => self.logical_pos as i64 + p,
            SeekFrom::End(p) => self.total_size as i64 + p,
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid seek to negative position",
            ));
        }
        self.logical_pos = new_pos as u64;
        self.sync_inner_seek()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(self.logical_pos)
    }
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
        if ube_size > JPEG_MAX_TOTAL_CAPACITY {
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

        if ube_size > JPEG_MAX_TOTAL_CAPACITY {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Payload size ({ube_size} bytes) exceeds JPEG maximum chain capacity ({JPEG_MAX_TOTAL_CAPACITY} bytes). Please specify --strategy eof."
            )));
        }

        let sos_offset = find_jpeg_sos_offset(host_in)?;

        // 1. Write host before SOS
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

        // 2. Write multi-segment APP15 chain using safe length partitioning
        let seg_lengths = partition_jpeg_payload_lengths(ube_size);
        let mut inject_size = 0u64;

        for seg_payload_len in seg_lengths {
            let seg_len = (2 + seg_payload_len) as u16;
            out.write_all(&JPEG_APP15)?;
            out.write_all(&seg_len.to_be_bytes())?;
            inject_size += 4 + seg_payload_len;

            let mut seg_to_write = seg_payload_len;
            while seg_to_write > 0 {
                let to_read = std::cmp::min(seg_to_write, buf.len() as u64) as usize;
                let n = ube_in.read(&mut buf[..to_read])?;
                if n == 0 {
                    return Err(StrHideError::CorruptedData(
                        "Unexpected end of UBE input stream".into(),
                    ));
                }
                out.write_all(&buf[..n])?;
                seg_to_write -= n as u64;
            }
        }

        // 3. Write host from SOS onwards through EOI
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

        // 1. Scan markers before SOS, collecting candidate segments for APP15 and COM
        let mut app15_segments: Vec<(u64, u64)> = Vec::new();
        let mut com_segments: Vec<(u64, u64)> = Vec::new();

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
                // SOS reached
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

            if b == 0xEF {
                // APP15
                app15_segments.push((payload_offset, payload_len));
            } else if b == 0xFE {
                // COM
                com_segments.push((payload_offset, payload_len));
            }

            stego_in.seek(SeekFrom::Start(payload_offset + payload_len))?;
        }

        // Helper to check a chain of candidate segments
        let try_locate_chain = |segments: &[(u64, u64)],
                                stego_in: &mut dyn SeekRead|
         -> Result<Option<(u64, u64, String)>, StrHideError> {
            for (k, &(seg_payload_offset, seg_payload_len)) in segments.iter().enumerate().rev() {
                if seg_payload_len < 24 {
                    continue;
                }
                let trailer_offset = seg_payload_offset + seg_payload_len - 24;
                stego_in.seek(SeekFrom::Start(trailer_offset))?;
                let mut trailer_bytes = [0u8; 24];
                if stego_in.read_exact(&mut trailer_bytes).is_err() {
                    continue;
                }
                let trailer = match EnvelopeTrailer::unpack(&trailer_bytes, expected_trailer_magic) {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                if expected_trailer_magic.is_none()
                    && trailer.trailer_magic != crate::envelope::STANDARD_TRAILER_MAGIC
                {
                    continue;
                }

                // Single segment match
                if trailer.ube_offset == seg_payload_offset
                    && trailer.ube_total_size == seg_payload_len
                {
                    return Ok(Some((
                        trailer.ube_offset,
                        trailer.ube_total_size,
                        "app_segment".into(),
                    )));
                }

                // Multi-segment chain match: trace backwards from segment k
                if trailer.ube_total_size > seg_payload_len {
                    let mut accum_len = 0u64;
                    let mut start_idx = None;

                    for m in (0..=k).rev() {
                        let (curr_off, curr_len) = segments[m];
                        if m < k {
                            let (next_off, _) = segments[m + 1];
                            if curr_off + curr_len != next_off - 4 {
                                break;
                            }
                        }
                        accum_len += curr_len;
                        if accum_len == trailer.ube_total_size {
                            if curr_off == trailer.ube_offset {
                                start_idx = Some(m);
                            }
                            break;
                        } else if accum_len > trailer.ube_total_size {
                            break;
                        }
                    }

                    if start_idx.is_some() {
                        return Ok(Some((
                            trailer.ube_offset,
                            trailer.ube_total_size,
                            "app_segment".into(),
                        )));
                    }
                }
            }
            Ok(None)
        };

        // 2. Priority check: APP15 multi-segment chain
        if let Some(res) = try_locate_chain(&app15_segments, stego_in)? {
            return Ok(Some(res));
        }

        // 3. Fallback check: Legacy COM segment chain
        if let Some(res) = try_locate_chain(&com_segments, stego_in)? {
            return Ok(Some(res));
        }

        // 4. Fallback check: EOF trailer
        if let Some(t) = EnvelopeTrailer::read_from_tail(stego_in, expected_trailer_magic)? {
            let file_size = stego_in.seek(SeekFrom::End(0))?;
            if t.ube_offset + t.ube_total_size == file_size {
                return Ok(Some((t.ube_offset, t.ube_total_size, "eof".into())));
            }
        }

        Ok(None)
    }

    fn open_ube_reader<'a>(
        &self,
        carrier: &'a mut dyn SeekRead,
        ube_offset: u64,
        ube_total_size: u64,
        strategy: &str,
    ) -> Result<Box<dyn SeekRead + 'a>, StrHideError> {
        if strategy == "eof" || ube_total_size <= JPEG_MAX_SEG_PAYLOAD {
            return Ok(Box::new(SubStream::new(carrier, ube_offset, ube_total_size)?));
        }

        // Construct multi-segment intervals using the deterministic partition function
        let seg_lengths = partition_jpeg_payload_lengths(ube_total_size);
        let mut segments = Vec::with_capacity(seg_lengths.len());
        let mut curr_offset = ube_offset;

        for seg_len in seg_lengths {
            segments.push((curr_offset, seg_len));
            curr_offset += seg_len + 4;
        }

        Ok(Box::new(JpegChainedSegmentReader::new(
            carrier,
            segments,
            ube_total_size,
        )?))
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
            if (b == 0xEF || b == 0xFE) && payload_len >= MIN_ENVELOPE {
                let seg_name = if b == 0xEF { "APP15" } else { "COM" };
                found.push(format!(
                    "{seg_name} segment at offset {payload_offset} carries {payload_len} bytes (minimum envelope size is {MIN_ENVELOPE})"
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
