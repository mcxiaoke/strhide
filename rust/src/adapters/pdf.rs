//! PDF format adapter for strhide with compliant Incremental Update object stream hiding.

use crate::adapters::{HostAdapter, SeekRead, StrategyCapacity, eof::EofAdapter};
use crate::envelope::EnvelopeTrailer;
use crate::errors::StrHideError;
use std::io::{Read, Seek, SeekFrom, Write};

pub const PDF_MAGIC: [u8; 5] = *b"%PDF-";

pub struct PdfTrailerInfo {
    pub eof_offset: u64,
    pub prev_startxref: u64,
    pub new_obj_num: u64,
    pub root_ref: Option<String>,
    pub info_ref: Option<String>,
}

/// Raw tail facts of a PDF, before the two "can we write an incremental
/// update?" requirements (`/Root` and a next object number) are enforced.
///
/// `%PDF` incremental updates are allowed to omit `/Root` and inherit it from
/// an earlier revision through the `/Prev` chain, so a document whose newest
/// trailer is just `<</Size N>>` is perfectly valid — it simply cannot be
/// extended without walking that chain. Structural verification needs the raw
/// facts; the *writer* needs them plus the two requirements.
pub struct PdfTailInfo {
    pub eof_offset: u64,
    pub prev_startxref: u64,
    pub new_obj_num: Option<u64>,
    pub root_ref: Option<String>,
    pub info_ref: Option<String>,
}

pub fn parse_pdf_trailer_info<R: Read + Seek + ?Sized>(
    reader: &mut R,
) -> Result<PdfTrailerInfo, StrHideError> {
    let tail = parse_pdf_tail_info(reader)?;
    let new_obj_num = tail.new_obj_num.ok_or_else(|| {
        StrHideError::CorruptedData(
            "cannot determine next PDF object number (no /Size and no 'N G obj' definitions in tail window)".into(),
        )
    })?;

    // An incremental trailer without /Root breaks the document tree for every
    // conforming reader; refuse instead of writing a damaged carrier (auto
    // strategy falls back to the lossless EOF overlay).
    let root_ref = tail.root_ref.ok_or_else(|| {
        StrHideError::CorruptedData(
            "cannot locate /Root reference in PDF tail; incremental update would break the document tree".into(),
        )
    })?;

    Ok(PdfTrailerInfo {
        eof_offset: tail.eof_offset,
        prev_startxref: tail.prev_startxref,
        new_obj_num,
        root_ref: Some(root_ref),
        info_ref: tail.info_ref,
    })
}

/// Offset of the last `%%EOF` marker in the file.
///
/// The marker is not required to sit inside a fixed tail window: PDFs may
/// legally be followed by arbitrary bytes (appended data, and for strhide
/// specifically an EOF-overlay envelope). A 64 KiB tail window made `verify`
/// report a carrier strhide itself had just written as "corrupted" as soon as
/// the envelope exceeded the window. The scan walks backwards in 64 KiB chunks
/// with a 4-byte overlap (so a marker straddling a chunk boundary is still
/// seen) and stops at the first hit, i.e. the last marker in file order — the
/// one a reader following `startxref` from the end would use.
fn find_last_eof<R: Read + Seek + ?Sized>(
    reader: &mut R,
    file_size: u64,
) -> Result<u64, StrHideError> {
    const CHUNK: u64 = 64 * 1024;
    const MARKER: &[u8] = b"%%EOF";

    let mut end = file_size;
    while end > 0 {
        let start = end.saturating_sub(CHUNK);
        let read_start = start.saturating_sub(MARKER.len() as u64 - 1);
        let mut buf = vec![0u8; (end - read_start) as usize];
        reader.seek(SeekFrom::Start(read_start))?;
        reader.read_exact(&mut buf)?;
        if let Some(idx) = buf.windows(MARKER.len()).rposition(|w| w == MARKER) {
            return Ok(read_start + idx as u64);
        }
        end = start;
    }

    Err(StrHideError::CorruptedData(
        "Valid PDF %%EOF marker not found".into(),
    ))
}

pub fn parse_pdf_tail_info<R: Read + Seek + ?Sized>(
    reader: &mut R,
) -> Result<PdfTailInfo, StrHideError> {
    let file_size = reader.seek(SeekFrom::End(0))?;
    let eof_idx = find_last_eof(reader, file_size)?;
    let abs_eof_pos = eof_idx + 5;

    // Trailer facts live *before* the marker, so the window ends at it instead
    // of at EOF: trailing data after `%%EOF` (a stego EOF overlay, appended
    // garbage) must not shrink the amount of trailer text available.
    let window_start = eof_idx.saturating_sub(64 * 1024);
    let mut before = vec![0u8; (eof_idx - window_start) as usize];
    reader.seek(SeekFrom::Start(window_start))?;
    reader.read_exact(&mut before)?;

    reader.seek(SeekFrom::Start(abs_eof_pos))?;
    let mut trailing = [0u8; 16];
    let n = reader.read(&mut trailing)?;
    let mut idx_nl = 0;
    while idx_nl < n && (trailing[idx_nl] == b'\r' || trailing[idx_nl] == b'\n') {
        idx_nl += 1;
    }
    let eof_offset = abs_eof_pos + idx_nl as u64;

    let text_before_eof = String::from_utf8_lossy(&before);
    let sx_idx = text_before_eof.rfind("startxref").ok_or_else(|| {
        StrHideError::CorruptedData("PDF startxref marker not found before %%EOF".into())
    })?;

    let sx_part = text_before_eof[sx_idx + "startxref".len()..].trim();
    let prev_startxref: u64 = sx_part
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            StrHideError::CorruptedData("Could not parse startxref offset integer".into())
        })?;

    // Next free object number. Classic PDFs expose /Size in a `trailer`
    // dictionary, where Size is defined as one past the highest object number
    // in use, so /Size itself is the next free number. xref-stream PDFs
    // (PDF 1.5+) carry their trailer dictionary inside the XRef stream object
    // and have no `trailer` keyword; for those, scan the tail window for
    // `N G obj` definitions and use max(N) + 1. The previous hardcoded 9999
    // fallback could collide with a real object number and silently corrupt
    // the incremental update.
    let mut new_obj_num: Option<u64> = None;
    let mut root_ref = None;
    let mut info_ref = None;

    if let Some(trailer_idx) = text_before_eof.rfind("trailer") {
        let trailer_str = &text_before_eof[trailer_idx..sx_idx];
        new_obj_num = find_int_after(trailer_str, "/Size");
        root_ref = find_indirect_ref(trailer_str, "/Root", false);
        info_ref = find_indirect_ref(trailer_str, "/Info", false);
    }

    // No classic trailer dictionary (xref-stream PDF): derive the next object
    // number from the highest `N G obj` definition in the tail window.
    if new_obj_num.is_none() {
        new_obj_num = scan_max_object_number(&text_before_eof).map(|n| n + 1);
    }

    // /Root and /Info may live inside an xref-stream trailer dict (or an older
    // incremental trailer) even when the newest trailer omits them; the last
    // valid reference in the tail is the currently effective one.
    if root_ref.is_none() {
        root_ref = find_indirect_ref(&text_before_eof, "/Root", true);
    }
    if info_ref.is_none() {
        info_ref = find_indirect_ref(&text_before_eof, "/Info", true);
    }

    Ok(PdfTailInfo {
        eof_offset,
        prev_startxref,
        new_obj_num,
        root_ref,
        info_ref,
    })
}

/// ASCII whitespace set shared with the Python implementation (`\s` in a
/// bytes regex / `bytes.split()`): space, TAB, LF, VT, FF, CR.
#[inline]
fn is_pdf_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

/// Read an optional whitespace run followed by a decimal digit run starting at
/// `i`; returns the parsed u64 and the new position. The digit run stops at
/// the first non-digit, so compact dictionaries such as `/Size 90/Root`
/// yield 90. Returns `None` when no digits are present or the value exceeds
/// u64 (mirroring the Python implementation's bound check).
fn read_digits_after_ws(text: &str, i: &mut usize) -> Option<u64> {
    let bytes = text.as_bytes();
    while *i < bytes.len() && is_pdf_ws(bytes[*i]) {
        *i += 1;
    }
    let start = *i;
    while *i < bytes.len() && bytes[*i].is_ascii_digit() {
        *i += 1;
    }
    if *i == start {
        return None;
    }
    text[start..*i].parse::<u64>().ok()
}

/// Return the decimal number that directly follows `key` (after optional
/// whitespace), if any.
fn find_int_after(text: &str, key: &str) -> Option<u64> {
    let mut pos = text.find(key)? + key.len();
    read_digits_after_ws(text, &mut pos)
}

/// Parse `<digits> <ws+> <digits> <ws+> R` starting at `pos` (the end of a
/// dictionary key such as `/Root`). The trailing `R` only needs to start the
/// next token, so compact forms like `/Root 1 0 R/Info` parse correctly.
fn parse_indirect_ref_after(text: &str, pos: usize) -> Option<(u64, u64)> {
    let bytes = text.as_bytes();
    let mut i = pos;
    let num1 = read_digits_after_ws(text, &mut i)?;
    let num2 = read_digits_after_ws(text, &mut i)?;
    while i < bytes.len() && is_pdf_ws(bytes[i]) {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b'R' {
        Some((num1, num2))
    } else {
        None
    }
}

/// Find an indirect reference such as `/Root 12 0 R` in PDF text and return
/// its normalized `"12 0 R"` body. `take_last` selects the final valid match
/// (the most recent incremental update carries the effective reference);
/// otherwise the first match wins (single trailer dictionary).
fn find_indirect_ref(text: &str, key: &str, take_last: bool) -> Option<String> {
    let key_len = key.len();
    let mut found = None;
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].find(key) {
        let after_key = search_from + rel + key_len;
        if let Some((num1, num2)) = parse_indirect_ref_after(text, after_key) {
            found = Some(format!("{num1} {num2} R"));
            if !take_last {
                return found;
            }
        }
        search_from = after_key;
    }
    found
}

/// Scan PDF text for `N G obj` definitions and return the highest object
/// number found. Used for xref-stream PDFs that have no `trailer` keyword.
/// The accepted shape is exactly `<digits> <ws+> <digits> <ws+> obj`, matching
/// the Python implementation.
fn scan_max_object_number(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    let mut max_obj: Option<u64> = None;
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].find("obj") {
        let obj_end = search_from + rel + 3;
        let mut j = search_from + rel;
        let mut obj_num: Option<u64> = None;

        // whitespace before "obj" (at least one byte)
        let ws1 = j;
        while j > 0 && is_pdf_ws(bytes[j - 1]) {
            j -= 1;
        }
        if j < ws1 {
            // generation digits (at least one)
            let gen_end = j;
            while j > 0 && bytes[j - 1].is_ascii_digit() {
                j -= 1;
            }
            if j < gen_end {
                // whitespace before generation (at least one byte)
                let ws2 = j;
                while j > 0 && is_pdf_ws(bytes[j - 1]) {
                    j -= 1;
                }
                if j < ws2 {
                    // object number digits (at least one)
                    let num_end = j;
                    while j > 0 && bytes[j - 1].is_ascii_digit() {
                        j -= 1;
                    }
                    if j < num_end {
                        obj_num = text[j..num_end].parse::<u64>().ok();
                    }
                }
            }
        }
        if let Some(n) = obj_num {
            max_obj = Some(max_obj.map_or(n, |m: u64| m.max(n)));
        }
        search_from = obj_end;
    }
    max_obj
}

pub struct PdfAdapter;

impl PdfAdapter {
    pub fn calc_prefix_len<R: Read + Seek + ?Sized>(
        reader: &mut R,
        ube_size: u64,
    ) -> Result<u64, StrHideError> {
        let info = parse_pdf_trailer_info(reader)?;
        let obj_header = format!(
            "\n{} 0 obj\n<< /Type /Metadata /Length {} >>\nstream\n",
            info.new_obj_num, ube_size
        );
        Ok(obj_header.len() as u64)
    }
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

    fn choose_auto_strategy(&self, reader: &mut dyn SeekRead, _ube_size: u64) -> &'static str {
        if parse_pdf_trailer_info(reader).is_ok() {
            "incremental"
        } else {
            "eof"
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
                incremental.note =
                    Some("PDF trailer / %%EOF could not be parsed; auto falls back to eof".into());
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
    ) -> Result<(u64, u64, u32, u32), StrHideError> {
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
        let mut remaining = info.eof_offset;
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

        let inject_offset = info.eof_offset;

        // 2. Construct object header
        let obj_header = format!(
            "\n{} 0 obj\n<< /Type /Metadata /Length {} >>\nstream\n",
            info.new_obj_num, ube_size
        );
        let actual_obj_offset = inject_offset + 1; // skips leading \n
        out.write_all(obj_header.as_bytes())?;

        // 3. Write UBE data stream (propagate read errors instead of treating them as EOF)
        loop {
            let n = ube_in.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
        }

        // 4. End object stream
        out.write_all(b"\nendstream\nendobj\n")?;

        // 5. Write incremental xref
        let xref_offset = inject_offset
            + obj_header.len() as u64
            + ube_size
            + b"\nendstream\nendobj\n".len() as u64;

        let xref_str = format!(
            "xref\n{} 1\n{:010} 00000 n \n",
            info.new_obj_num, actual_obj_offset
        );
        out.write_all(xref_str.as_bytes())?;

        // 6. Write incremental trailer
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

        let inject_size = obj_header.len() as u64
            + ube_size
            + b"\nendstream\nendobj\n".len() as u64
            + xref_str.len() as u64
            + trailer_str.len() as u64;

        // 7. Preserve any bytes the original host carried after its final
        // %%EOF (non-standard "dirty tail"). Dropping them would silently
        // damage the carrier and break the 100% bit-exact restore guarantee,
        // so they are copied verbatim after the new %%EOF.
        host_in.seek(SeekFrom::Start(info.eof_offset))?;
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
        let mut magic = [0u8; 5];
        if stego_in.read_exact(&mut magic).is_err() || magic != PDF_MAGIC {
            return Ok(None);
        }

        // 1. Check incremental update object stream first
        let total_size = stego_in.seek(SeekFrom::End(0))?;
        let scan_len = std::cmp::min(total_size, 128 * 1024);
        stego_in.seek(SeekFrom::End(-(scan_len as i64)))?;
        let mut tail = vec![0u8; scan_len as usize];
        stego_in.read_exact(&mut tail)?;

        if let Some(eof_idx) = tail.windows(5).rposition(|w| w == b"%%EOF")
            && let Some(endstream_idx) = tail[..eof_idx].windows(9).rposition(|w| w == b"endstream")
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
                if let Ok(trailer) = EnvelopeTrailer::unpack(trailer_bytes, expected_trailer_magic)
                {
                    let abs_stream_end = (total_size - scan_len) + stream_end_in_tail as u64;
                    if trailer.ube_offset + trailer.ube_total_size == abs_stream_end
                        && trailer.ube_offset >= 8
                    {
                        stego_in.seek(SeekFrom::Start(trailer.ube_offset - 8))?;
                        let mut prefix = [0u8; 8];
                        if stego_in.read_exact(&mut prefix).is_ok()
                            && (prefix.ends_with(b"stream\r\n")
                                || prefix.ends_with(b"stream\n")
                                || prefix.ends_with(b"stream"))
                        {
                            return Ok(Some((
                                trailer.ube_offset,
                                trailer.ube_total_size,
                                "incremental".into(),
                            )));
                        }
                    }
                }
            }
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
        // Structural validity only: `%%EOF`/`startxref` must be intact. A
        // newest trailer without `/Root` is legal (it inherits the reference
        // from an earlier revision via `/Prev`), it merely rules out an
        // incremental update — so it must not be reported as corruption.
        match parse_pdf_tail_info(stego_in) {
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
}
