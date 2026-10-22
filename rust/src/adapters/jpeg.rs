//! JPEG format adapter for strhide with APP15/COM segment multi-chain hiding.

use crate::adapters::{
    HostAdapter, SeekRead, SegmentedSubStream, StrategyCapacity, SubStream, TrailerCtx,
    eof::EofAdapter, format_bytes,
};
use crate::envelope::EnvelopeTrailer;
use crate::errors::StrHideError;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};

pub const JPEG_SOI: [u8; 2] = [0xFF, 0xD8];
pub const JPEG_SOS: [u8; 2] = [0xFF, 0xDA];
pub const JPEG_EOI: [u8; 2] = [0xFF, 0xD9];
pub const JPEG_APP15: [u8; 2] = [0xFF, 0xEF];
pub const JPEG_COM: [u8; 2] = [0xFF, 0xFE];
pub const JPEG_MAX_SEG_PAYLOAD: u64 = 65533; // 65535 - 2 bytes length
pub const JPEG_MAX_TOTAL_CAPACITY: u64 = 64 * 1024 * 1024; // 64MB
pub const MAX_JPEG_HEADER_SCAN: u64 = 16 * 1024 * 1024; // 16MB max scan for JPEG header
pub const MAX_JPEG_NON_MARKER_SKIP: usize = 4096; // Max stray non-marker bytes before SOS

/// One marker segment encountered while walking a JPEG marker stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JpegSegment {
    /// File offset of the segment's `0xFF` lead byte.
    pub marker_offset: u64,
    /// Marker code byte: `0xEF` for APP15, `0xFE` for COM, `0xDA` for SOS, ...
    pub code: u8,
    /// `None` for standalone markers (SOI / EOI / TEM / RSTn); otherwise the
    /// payload's `(offset, length)` — the length excludes the 2 bytes that
    /// encode it, per the JPEG spec.
    pub payload: Option<(u64, u64)>,
}

/// Why a marker walk finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JpegScanEnd {
    /// The callback returned `false`, or the walk reached SOS.
    Stopped,
    /// End of the available bytes.
    Eof,
    /// A segment declared a length below 2 (the minimum legal value).
    MalformedLength(u64),
    /// More than [`MAX_JPEG_NON_MARKER_SKIP`] consecutive non-marker bytes.
    NonMarkerRun,
    /// The walk passed [`MAX_JPEG_HEADER_SCAN`] without reaching SOS.
    HeaderScanLimit,
}

/// Walk JPEG marker segments starting at the current stream position.
///
/// Three callers used to carry their own copy of this state machine — finding
/// the SOS offset, enumerating APP15 segments, and flagging oversized
/// APP15/COM — all of them reading one byte at a time from an unbuffered file.
/// This is the single copy, buffered, with the caller supplying only what it
/// collects.
///
/// The walk stops at SOS: everything after it is entropy-coded data, where a
/// `0xFF` is either byte-stuffed or the start of a real marker, and none of the
/// callers wants to guess. The callback returns `false` to stop early.
///
/// Read failures end the walk (that is how EOF shows up here); only seek
/// failures are propagated as errors.
pub fn scan_jpeg_markers<R: Read + Seek + ?Sized>(
    reader: &mut R,
    mut on_segment: impl FnMut(&JpegSegment) -> bool,
) -> Result<JpegScanEnd, StrHideError> {
    // The walk reads one or two bytes and then seeks forward, which is exactly
    // the pattern an unbuffered `File` turns into one syscall per byte.
    let mut in_reader = BufReader::with_capacity(64 * 1024, reader);
    let mut non_marker_skip = 0usize;
    loop {
        let marker_offset = in_reader.stream_position()?;
        if marker_offset > MAX_JPEG_HEADER_SCAN {
            return Ok(JpegScanEnd::HeaderScanLimit);
        }
        let mut lead = [0u8; 1];
        if in_reader.read_exact(&mut lead).is_err() {
            return Ok(JpegScanEnd::Eof);
        }
        if lead[0] != 0xFF {
            non_marker_skip += 1;
            if non_marker_skip > MAX_JPEG_NON_MARKER_SKIP {
                return Ok(JpegScanEnd::NonMarkerRun);
            }
            continue;
        }
        non_marker_skip = 0;

        let mut code = [0u8; 1];
        if in_reader.read_exact(&mut code).is_err() {
            return Ok(JpegScanEnd::Eof);
        }
        // 0xFF fill bytes may precede the code byte.
        while code[0] == 0xFF && in_reader.read_exact(&mut code).is_ok() {}

        let b = code[0];
        // Standalone markers without a length field.
        if matches!(b, 0xD8 | 0xD9 | 0x01 | 0xD0..=0xD7) {
            if !on_segment(&JpegSegment {
                marker_offset,
                code: b,
                payload: None,
            }) {
                return Ok(JpegScanEnd::Stopped);
            }
            continue;
        }
        if b == 0xDA {
            // SOS: the entropy-coded scan follows, so the marker stream is over.
            let _ = on_segment(&JpegSegment {
                marker_offset,
                code: b,
                payload: None,
            });
            return Ok(JpegScanEnd::Stopped);
        }

        let mut len_bytes = [0u8; 2];
        if in_reader.read_exact(&mut len_bytes).is_err() {
            return Ok(JpegScanEnd::Eof);
        }
        let seg_len = u16::from_be_bytes(len_bytes) as u64;
        if seg_len < 2 {
            return Ok(JpegScanEnd::MalformedLength(seg_len));
        }
        let payload_offset = in_reader.stream_position()?;
        let payload_len = seg_len - 2;
        if !on_segment(&JpegSegment {
            marker_offset,
            code: b,
            payload: Some((payload_offset, payload_len)),
        }) {
            return Ok(JpegScanEnd::Stopped);
        }
        if in_reader
            .seek(SeekFrom::Start(payload_offset + payload_len))
            .is_err()
        {
            return Ok(JpegScanEnd::Eof);
        }
    }
}

pub fn find_jpeg_sos_offset<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<u64, StrHideError> {
    reader.seek(SeekFrom::Start(0))?;
    let mut soi = [0u8; 2];
    reader.read_exact(&mut soi)?;
    if soi != JPEG_SOI {
        return Err(StrHideError::CorruptedData(
            "Invalid JPEG SOI marker".into(),
        ));
    }

    let mut sos_offset = None;
    let end = scan_jpeg_markers(reader, |seg| {
        if seg.code == 0xDA {
            sos_offset = Some(seg.marker_offset);
            return false;
        }
        true
    })?;
    sos_offset.ok_or_else(|| match end {
        JpegScanEnd::MalformedLength(len) => {
            StrHideError::CorruptedData(format!("Invalid JPEG segment length: {len}"))
        }
        _ => StrHideError::CorruptedData("JPEG SOS (Start of Scan) marker not found".into()),
    })
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

pub struct JpegAdapter;

impl HostAdapter for JpegAdapter {
    fn format_name(&self) -> &'static str {
        "JPEG"
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

    fn strategy_capacities(&self, _reader: Option<&mut dyn SeekRead>) -> Vec<StrategyCapacity> {
        vec![
            StrategyCapacity {
                strategy: "app_segment".into(),
                capacity_bytes: Some(JPEG_MAX_TOTAL_CAPACITY),
                available: true,
                limit: format!("<= {} B (64 MiB)", format_bytes(JPEG_MAX_TOTAL_CAPACITY)),
                note: Some(
                    "APP15 segment chain before SOS; per-segment payload capped at 65,533 B; file grows"
                        .into(),
                ),
            },
            StrategyCapacity {
                strategy: "eof".into(),
                capacity_bytes: None,
                available: true,
                limit: "unlimited (file grows)".into(),
                note: Some("appended after EOI".into()),
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
        crate::adapters::io::copy_exact(host_in, out, sos_offset)?;

        let inject_offset = sos_offset;

        // 2. Write multi-segment APP15 chain using safe length partitioning
        let seg_lengths = partition_jpeg_payload_lengths(ube_size);
        let mut inject_size = 0u64;

        for seg_payload_len in seg_lengths {
            let seg_len = (2 + seg_payload_len) as u16;
            out.write_all(&JPEG_APP15)?;
            out.write_all(&seg_len.to_be_bytes())?;
            inject_size += 4 + seg_payload_len;

            // The segment length was computed from `ube_size` on this same
            // stream, so a short read means the envelope was truncated.
            crate::adapters::io::copy_exact(ube_in, out, seg_payload_len)?;
        }

        // 3. Write host from SOS onwards through EOI
        host_in.seek(SeekFrom::Start(sos_offset))?;
        crate::adapters::io::copy_stream(host_in, out)?;

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

        // 1. Scan markers before SOS, collecting candidate APP15 segments.
        let mut app15_segments: Vec<(u64, u64)> = Vec::new();
        let _ = scan_jpeg_markers(stego_in, |seg| {
            if let Some((payload_offset, payload_len)) = seg.payload
                && seg.code == 0xEF
            {
                app15_segments.push((payload_offset, payload_len));
            }
            true
        });

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
                let trailer = match EnvelopeTrailer::unpack(&trailer_bytes, expected_trailer_magic)
                {
                    Ok(t) => t,
                    Err(_) => continue,
                };

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

        // 3. Fallback check: EOF trailer
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
            return Ok(Box::new(SubStream::new(
                carrier,
                ube_offset,
                ube_total_size,
            )?));
        }

        // Construct multi-segment intervals using the deterministic partition function
        let seg_lengths = partition_jpeg_payload_lengths(ube_total_size);
        let mut segments = Vec::with_capacity(seg_lengths.len());
        let mut curr_offset = ube_offset;

        for seg_len in seg_lengths {
            segments.push((curr_offset, seg_len));
            curr_offset += seg_len + 4;
        }

        Ok(Box::new(SegmentedSubStream::from_segments(
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
        let _ = scan_jpeg_markers(stego_in, |seg| {
            let Some((payload_offset, payload_len)) = seg.payload else {
                return true;
            };
            if (seg.code == 0xEF || seg.code == 0xFE) && payload_len >= MIN_ENVELOPE {
                let seg_name = if seg.code == 0xEF { "APP15" } else { "COM" };
                found.push(format!(
                    "{seg_name} segment at offset {payload_offset} carries {payload_len} bytes (minimum envelope size is {MIN_ENVELOPE})"
                ));
            }
            true
        });
        found
    }

    fn envelope_offset_delta(
        &self,
        _carrier: &mut dyn SeekRead,
        strategy: &str,
        _ube_size: u64,
    ) -> Result<u64, StrHideError> {
        if strategy == "app_segment" {
            Ok(4)
        } else {
            Ok(0)
        }
    }

    fn trailer_offset(&self, ctx: &TrailerCtx) -> u64 {
        if ctx.strategy == "app_segment" {
            ctx.inject_offset + ctx.inject_size - 24
        } else {
            ctx.actual_ube_offset + ctx.ube_total_size - 24
        }
    }

    fn strategy_note(&self, strategy: &str, fallback: bool) -> Option<String> {
        if strategy == "app_segment" {
            Some("Embedded into compliant JPEG APP15 segment(s) before SOS (clean EOI at EOF, 0 trailing bytes).".into())
        } else if strategy == "eof" && fallback {
            Some(
                "Payload exceeded JPEG maximum capacity; automatically fell back to EOF overlay."
                    .into(),
            )
        } else if strategy == "eof" {
            Some("Appended after JPEG EOI marker (EOF overlay).".into())
        } else {
            None
        }
    }
}
