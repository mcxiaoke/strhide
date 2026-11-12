//! PDF format adapter for strhide with compliant Incremental Update object stream hiding.

use std::io::{Read, Seek, SeekFrom, Write};

use crate::errors::StrHideError;
use crate::structure::adapters::{
    HostAdapter, InjectCoordinates, LocatedEnvelope, SeekRead, StrategyCapacity, eof::EofAdapter,
};
use crate::structure::envelope::{EnvelopeTrailer, TRAILER_SIZE};

pub mod syntax;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use syntax::balanced_dict_end;
pub(crate) use syntax::find_last_eof;
pub use syntax::{
    PDF_MAGIC, PdfTailInfo, PdfTrailerInfo, parse_pdf_tail_info, parse_pdf_tail_info_with_magic,
    parse_pdf_trailer_info, pdf_obj_header,
};

pub struct PdfAdapter;

impl PdfAdapter {
    pub fn calc_prefix_len<R: Read + Seek + ?Sized>(
        reader: &mut R,
        ube_size: u64,
    ) -> Result<u64, StrHideError> {
        let info = parse_pdf_trailer_info(reader)?;
        Ok(pdf_obj_header(info.new_obj_num, ube_size).len() as u64)
    }
}

/// Validate the envelope trailer that must sit immediately before an
/// `endstream` keyword at `endstream_pos`.
///
/// The writer emits `UBE + "\nendstream"`, so the trailer normally ends exactly
/// one EOL before `endstream`; up to three trailing EOLs are tried so a stealth
/// magic that itself ends in `\r`/`\n` cannot misalign the 24-byte window.
/// Trailer magic/CRC, the end-of-stream equality and the `stream` prefix all
/// have to agree, so unrelated `endstream` keywords cannot match.
fn try_locate_endstream(
    stego_in: &mut dyn SeekRead,
    endstream_pos: u64,
    expected_trailer_magic: Option<&[u8; 4]>,
) -> Result<Option<LocatedEnvelope>, StrHideError> {
    const EOL_SLACK: usize = 3;
    let Some(window_start) = endstream_pos.checked_sub((TRAILER_SIZE + EOL_SLACK) as u64) else {
        return Ok(None);
    };
    let len = (endstream_pos - window_start) as usize;
    let mut buf = [0u8; TRAILER_SIZE + EOL_SLACK];
    stego_in.seek(SeekFrom::Start(window_start))?;
    if stego_in.read_exact(&mut buf[..len]).is_err() {
        return Ok(None);
    }

    for skip in 0..=EOL_SLACK {
        let stream_end = len - skip;
        if buf[stream_end..].iter().any(|b| *b != b'\r' && *b != b'\n') {
            continue;
        }
        if stream_end < TRAILER_SIZE {
            continue;
        }
        let Ok(trailer) = EnvelopeTrailer::unpack(
            &buf[stream_end - TRAILER_SIZE..stream_end],
            expected_trailer_magic,
        ) else {
            continue;
        };
        let abs_stream_end = window_start + stream_end as u64;
        if trailer.ube_offset.checked_add(trailer.ube_total_size) != Some(abs_stream_end)
            || trailer.ube_offset < 8
        {
            continue;
        }
        stego_in.seek(SeekFrom::Start(trailer.ube_offset - 8))?;
        let mut prefix = [0u8; 8];
        if stego_in.read_exact(&mut prefix).is_ok()
            && (prefix.ends_with(b"stream\r\n")
                || prefix.ends_with(b"stream\n")
                || prefix.ends_with(b"stream"))
        {
            return Ok(Some(LocatedEnvelope {
                offset: trailer.ube_offset,
                size: trailer.ube_total_size,
                strategy: "incremental".into(),
            }));
        }
    }

    Ok(None)
}

impl HostAdapter for PdfAdapter {
    fn format_name(&self) -> &'static str {
        "PDF"
    }

    fn detect(&self, reader: &mut dyn SeekRead) -> bool {
        let start_pos = match reader.stream_position() {
            Ok(pos) => pos,
            Err(_) => return false,
        };
        if reader.seek(SeekFrom::Start(0)).is_err() {
            return false;
        }
        let mut prefix = [0u8; 5];
        let ok = reader.read_exact(&mut prefix).is_ok() && prefix == PDF_MAGIC;
        let _ = reader.seek(SeekFrom::Start(start_pos));
        ok
    }

    fn supported_strategies(&self) -> Vec<&'static str> {
        vec!["incremental", "eof"]
    }

    fn choose_auto_strategy(&self, reader: &mut dyn SeekRead, ube_size: u64) -> &'static str {
        // The incremental object header (`\n<N> 0 obj\n<< /Type /Metadata
        // /Length <L> >>\nstream\n`) shifts the envelope by its own length, and
        // the sealed header can only record `MAX_OFFSET_DELTA` bytes. With a
        // 10-digit object number and a 9-digit payload the template exceeds
        // that, which the writer then rejects as a hard error instead of
        // falling back. Pick `eof` up front when the shift cannot be recorded.
        match parse_pdf_trailer_info(reader) {
            Ok(info)
                if pdf_obj_header(info.new_obj_num, ube_size).len()
                    <= crate::structure::envelope::MAX_OFFSET_DELTA as usize =>
            {
                "incremental"
            }
            _ => "eof",
        }
    }

    fn strategy_capacities(&self, reader: Option<&mut dyn SeekRead>) -> Vec<StrategyCapacity> {
        let mut incremental = StrategyCapacity {
            strategy: "incremental".into(),
            capacity_bytes: None,
            available: true,
            limit: "unlimited (file grows)".into(),
            note: Some("incremental update ending in %%EOF; requires a parseable trailer".into()),
        };
        if let Some(r) = reader {
            let start = r.stream_position().ok();
            if parse_pdf_trailer_info(r).is_err() {
                incremental.available = false;
                incremental.note = Some(
                    "incremental update not possible for this carrier (unparseable trailer or \
                     encrypted document); auto falls back to eof"
                        .into(),
                );
            }
            if let Some(p) = start {
                let _ = r.seek(SeekFrom::Start(p));
            }
        }
        vec![
            incremental,
            StrategyCapacity {
                strategy: "eof".into(),
                capacity_bytes: None,
                available: true,
                limit: "unlimited (file grows)".into(),
                note: Some("appended after %%EOF".into()),
            },
        ]
    }

    fn inject(
        &self,
        host_in: &mut dyn SeekRead,
        ube_in: &mut dyn SeekRead,
        out: &mut dyn Write,
        strategy: &str,
    ) -> Result<InjectCoordinates, StrHideError> {
        if strategy == "eof" {
            return EofAdapter.inject(host_in, ube_in, out, strategy);
        }

        if strategy != "incremental" {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Strategy '{strategy}' not supported by PDF adapter"
            )));
        }

        let info = parse_pdf_trailer_info(host_in).map_err(|e| {
            StrHideError::UnsupportedFormat(format!(
                "PDF cannot be incrementally updated ({e}). Please specify --strategy eof."
            ))
        })?;

        let ube_size = ube_in.seek(SeekFrom::End(0))?;
        ube_in.seek(SeekFrom::Start(0))?;

        // 1. Write host up to eof_offset
        host_in.seek(SeekFrom::Start(0))?;
        crate::structure::adapters::io::copy_exact(host_in, out, info.eof_offset)?;

        let inject_offset = info.eof_offset;

        // 2. Construct object header
        let obj_header = pdf_obj_header(info.new_obj_num, ube_size);
        let actual_obj_offset = inject_offset + 1; // skips leading \n
        out.write_all(obj_header.as_bytes())?;

        // 3. Write UBE data stream. `ube_size` was measured on this stream, so
        // a short read means the envelope was truncated.
        crate::structure::adapters::io::copy_exact(ube_in, out, ube_size)?;

        // 4. End object stream
        const END_OBJ: &[u8] = b"\nendstream\nendobj\n";
        out.write_all(END_OBJ)?;

        // 5. Write the incremental cross-reference section in the document's
        // own dialect. A classic `xref`/`trailer` appended to an XRef-stream
        // document leaves `/Prev` pointing at an indirect object, which strict
        // parsers reject (ISO 32000-1 §7.5.8.4).
        let xref_offset = inject_offset + obj_header.len() as u64 + ube_size + END_OBJ.len() as u64;

        let section_len: u64 = if info.uses_xref_stream {
            const W_OFFSET: usize = 4;
            if xref_offset >= 1u64 << (8 * W_OFFSET) {
                return Err(StrHideError::UnsupportedFormat(
                    "Carrier is larger than 4 GB, which overflows the 4-byte offsets an XRef \
                     stream entry can hold. Use --strategy eof for this carrier."
                        .into(),
                ));
            }
            let xref_obj_num = info.new_obj_num + 1;
            let entry_len = 1 + W_OFFSET + 2;
            let stream_data_len = entry_len * 2;
            let mut header = format!(
                "{xref_obj_num} 0 obj\n<<\n/Type /XRef\n/Size {}\n/W [1 {W_OFFSET} 2]\n\
                 /Index [{} 2]\n",
                xref_obj_num + 1,
                info.new_obj_num
            );
            if let Some(root) = &info.root_ref {
                header.push_str(&format!("/Root {root}\n"));
            }
            if let Some(info_r) = &info.info_ref {
                header.push_str(&format!("/Info {info_r}\n"));
            }
            header.push_str(&format!(
                "/Prev {}\n/Length {stream_data_len}\n>>\nstream\n",
                info.prev_startxref
            ));
            let mut data = Vec::with_capacity(stream_data_len);
            for offset in [actual_obj_offset, xref_offset] {
                data.push(1u8); // entry type 1: used, uncompressed
                data.extend_from_slice(&(offset as u32).to_be_bytes());
                data.extend_from_slice(&[0u8, 0u8]); // generation 0
            }
            let footer = format!("\nendstream\nendobj\nstartxref\n{xref_offset}\n%%EOF\n");
            out.write_all(header.as_bytes())?;
            out.write_all(&data)?;
            out.write_all(footer.as_bytes())?;
            (header.len() + data.len() + footer.len()) as u64
        } else {
            // A classic xref entry is exactly 20 bytes: a fixed 10-digit offset,
            // then ` ggggg n \n`. An offset past 10^10 grows the field and shifts
            // every following entry, producing a file whose `startxref`/`%%EOF`
            // still look right — so neither the write self-check nor
            // `verify_structure` (which only parses the tail) notices.
            // Refuse instead of writing a broken table.
            if actual_obj_offset >= 10_000_000_000 {
                return Err(StrHideError::UnsupportedFormat(
                    "Carrier is larger than 10 GB, which overflows the 10-digit offsets a classic \
                     PDF xref table can hold. Use --strategy eof for this carrier."
                        .into(),
                ));
            }
            let xref_str = format!(
                "xref\n{} 1\n{:010} 00000 n \n",
                info.new_obj_num, actual_obj_offset
            );
            out.write_all(xref_str.as_bytes())?;

            let mut trailer_str = format!("trailer\n<<\n/Size {}\n", info.new_obj_num + 1);
            if let Some(root) = &info.root_ref {
                trailer_str.push_str(&format!("/Root {root}\n"));
            }
            if let Some(info_r) = &info.info_ref {
                trailer_str.push_str(&format!("/Info {info_r}\n"));
            }
            trailer_str.push_str(&format!(
                "/Prev {}\n>>\nstartxref\n{}\n%%EOF\n",
                info.prev_startxref, xref_offset
            ));
            out.write_all(trailer_str.as_bytes())?;
            (xref_str.len() + trailer_str.len()) as u64
        };

        let inject_size = obj_header.len() as u64 + ube_size + END_OBJ.len() as u64 + section_len;

        // 7. Preserve any bytes the original host carried after its final
        // %%EOF (non-standard "dirty tail"). Dropping them would silently
        // damage the carrier and break the 100% bit-exact restore guarantee,
        // so they are copied verbatim after the new %%EOF.
        host_in.seek(SeekFrom::Start(info.eof_offset))?;
        crate::structure::adapters::io::copy_stream(host_in, out)?;

        Ok(InjectCoordinates {
            offset: inject_offset,
            size: inject_size,
            patch_offset: 0,
            original_patch_value: 0,
        })
    }

    fn locate(
        &self,
        stego_in: &mut dyn SeekRead,
        expected_trailer_magic: Option<&[u8; 4]>,
    ) -> Result<Option<LocatedEnvelope>, StrHideError> {
        stego_in.seek(SeekFrom::Start(0))?;
        let mut magic = [0u8; 5];
        if stego_in.read_exact(&mut magic).is_err() || magic != PDF_MAGIC {
            return Ok(None);
        }

        // 1. Check incremental update object stream first.
        //
        // An incremental update written by strhide places the stream object
        // directly inside the newest revision (before the final %%EOF).
        // The metadata between `endstream` and `%%EOF` (endobj, xref, trailer,
        // startxref, %%EOF) is compact (a few hundred bytes). We search only
        // within a single 64 KiB window immediately before the final %%EOF.
        // We do NOT scan backward past this window into earlier revisions or host streams.
        let total_size = stego_in.seek(SeekFrom::End(0))?;
        if let Ok(eof_offset) = find_last_eof(stego_in, total_size) {
            const CHUNK: u64 = 64 * 1024;
            const ENDSTREAM: &[u8] = b"endstream";
            let start = eof_offset.saturating_sub(CHUNK);
            let read_start = start.saturating_sub(ENDSTREAM.len() as u64 - 1);
            let mut buf = vec![0u8; (eof_offset - read_start) as usize];
            stego_in.seek(SeekFrom::Start(read_start))?;
            if stego_in.read_exact(&mut buf).is_ok() {
                let mut search_end = buf.len();
                while search_end > 0 {
                    let Some(idx) = buf[..search_end]
                        .windows(ENDSTREAM.len())
                        .rposition(|w| w == ENDSTREAM)
                    else {
                        break;
                    };
                    let abs = read_start + idx as u64;
                    if let Some(found) =
                        try_locate_endstream(stego_in, abs, expected_trailer_magic)?
                    {
                        return Ok(Some(found));
                    }
                    search_end = idx;
                }
            }
        }

        // 2. Fallback to EOF
        if let Some(t) = EnvelopeTrailer::read_from_tail(stego_in, expected_trailer_magic)? {
            let file_size = stego_in.seek(SeekFrom::End(0))?;
            if t.ube_offset.checked_add(t.ube_total_size) == Some(file_size) {
                return Ok(Some(LocatedEnvelope {
                    offset: t.ube_offset,
                    size: t.ube_total_size,
                    strategy: "eof".into(),
                }));
            }
        }

        Ok(None)
    }

    fn verify_structure(
        &self,
        stego_in: &mut dyn SeekRead,
    ) -> Result<(bool, String), StrHideError> {
        self.verify_structure_with_magic(stego_in, None)
    }

    fn verify_structure_with_magic(
        &self,
        stego_in: &mut dyn SeekRead,
        locator_magic: Option<&[u8; 4]>,
    ) -> Result<(bool, String), StrHideError> {
        // Structural validity only: `%%EOF`/`startxref` must be intact. A
        // newest trailer without `/Root` is legal (it inherits the reference
        // from an earlier revision via `/Prev`), it merely rules out an
        // incremental update — so it must not be reported as corruption.
        match parse_pdf_tail_info_with_magic(stego_in, locator_magic) {
            Ok(info) => {
                let root = match info.root_ref {
                    Some(_) => "trailer /Root resolved",
                    None => {
                        "/Root inherited from an earlier revision (incremental update disabled for this carrier)"
                    }
                };
                Ok((
                    true,
                    format!(
                        "Valid PDF document (%%EOF at {}, prev_startxref at {}; {root})",
                        info.eof_offset, info.prev_startxref
                    ),
                ))
            }
            Err(e) => Ok((false, format!("Corrupted PDF structure: {e}"))),
        }
    }

    fn suspicious_structures(&self, stego_in: &mut dyn SeekRead) -> Vec<String> {
        const MIN_UBE_SIZE: u64 = 112 + 24;
        let mut found = Vec::new();

        stego_in.seek(SeekFrom::Start(0)).ok();
        let mut magic = [0u8; 5];
        if stego_in.read_exact(&mut magic).is_err() || magic != PDF_MAGIC {
            return found;
        }

        let total_size = match stego_in.seek(SeekFrom::End(0)) {
            Ok(s) => s,
            Err(_) => return found,
        };

        // 1. Inspect incremental update object stream candidate
        let scan_len = std::cmp::min(total_size, 128 * 1024);
        if scan_len >= 24 && stego_in.seek(SeekFrom::End(-(scan_len as i64))).is_ok() {
            let mut tail = vec![0u8; scan_len as usize];
            if stego_in.read_exact(&mut tail).is_ok()
                && let Some(eof_idx) = tail.windows(5).rposition(|w| w == b"%%EOF")
                && let Some(endstream_idx) =
                    tail[..eof_idx].windows(9).rposition(|w| w == b"endstream")
            {
                let stream_content_tail = &tail[..endstream_idx];
                let mut stream_end_in_tail = stream_content_tail.len();
                while stream_end_in_tail > 0
                    && (stream_content_tail[stream_end_in_tail - 1] == b'\r'
                        || stream_content_tail[stream_end_in_tail - 1] == b'\n')
                {
                    stream_end_in_tail -= 1;
                }

                if stream_end_in_tail >= 24 {
                    let trailer_bytes =
                        &stream_content_tail[stream_end_in_tail - 24..stream_end_in_tail];
                    let ube_offset = u64::from_le_bytes(trailer_bytes[0..8].try_into().unwrap());
                    let ube_total_size =
                        u64::from_le_bytes(trailer_bytes[8..16].try_into().unwrap());
                    let abs_stream_end = (total_size - scan_len) + stream_end_in_tail as u64;

                    if ube_offset.checked_add(ube_total_size) == Some(abs_stream_end)
                        && ube_total_size >= MIN_UBE_SIZE
                        && ube_offset >= 8
                        && stego_in.seek(SeekFrom::Start(ube_offset - 8)).is_ok()
                    {
                        let mut prefix = [0u8; 8];
                        if stego_in.read_exact(&mut prefix).is_ok()
                            && (prefix.ends_with(b"stream\r\n")
                                || prefix.ends_with(b"stream\n")
                                || prefix.ends_with(b"stream"))
                        {
                            found.push(format!(
                                "incremental update object stream carries an envelope-shaped structure at offset {ube_offset} (size {ube_total_size} B)"
                            ));
                        }
                    }
                }
            }
        }

        // 2. Inspect eof candidate after final %%EOF
        if let Ok(eof_offset) = find_last_eof(stego_in, total_size) {
            let eof_marker_end = eof_offset + 5;
            if total_size >= eof_marker_end + 24 && stego_in.seek(SeekFrom::End(-24)).is_ok() {
                let mut tail = [0u8; 24];
                if stego_in.read_exact(&mut tail).is_ok() {
                    let ube_offset = u64::from_le_bytes(tail[0..8].try_into().unwrap());
                    let ube_total_size = u64::from_le_bytes(tail[8..16].try_into().unwrap());
                    if ube_offset.checked_add(ube_total_size) == Some(total_size)
                        && ube_total_size >= MIN_UBE_SIZE
                        && ube_offset >= eof_marker_end
                    {
                        found.push(format!(
                            "trailing data past %%EOF carries an envelope-shaped structure at offset {ube_offset} (size {ube_total_size} B)"
                        ));
                    }
                }
            }
        }

        found
    }

    fn envelope_offset_delta(
        &self,
        carrier: &mut dyn SeekRead,
        strategy: &str,
        ube_size: u64,
    ) -> Result<u64, StrHideError> {
        if strategy == "incremental" {
            PdfAdapter::calc_prefix_len(carrier, ube_size)
        } else {
            Ok(0)
        }
    }

    fn strategy_note(&self, strategy: &str, fallback: bool) -> Option<String> {
        if strategy == "incremental" {
            Some("Embedded into compliant PDF Incremental Update stream ending with %%EOF (original trailing bytes, if any, preserved after the final %%EOF).".into())
        } else if strategy == "eof" && fallback {
            Some("PDF trailer could not be incrementally parsed; automatically fell back to EOF overlay.".into())
        } else if strategy == "eof" {
            Some("Appended after PDF %%EOF (EOF overlay).".into())
        } else {
            None
        }
    }
}
