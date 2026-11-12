//! PDF syntax parsing: trailer, cross-reference tables, and indirect object headers.

use crate::errors::StrHideError;
use crate::structure::envelope::EnvelopeTrailer;
use std::io::{Read, Seek, SeekFrom};

pub const PDF_MAGIC: [u8; 5] = *b"%PDF-";

pub struct PdfTrailerInfo {
    pub eof_offset: u64,
    pub prev_startxref: u64,
    pub new_obj_num: u64,
    pub root_ref: Option<String>,
    pub info_ref: Option<String>,
    /// Whether the newest cross-reference section is an XRef *stream* rather
    /// than a classic `xref` table. A conforming incremental update must repeat
    /// the document's dialect: appending `xref`/`trailer` after an XRef stream
    /// leaves `/Prev` pointing at an indirect object (`N 0 obj << /Type /XRef
    /// ... >>`) where strict parsers expect the `xref` keyword (ISO 32000-1
    /// §7.5.8.4).
    pub uses_xref_stream: bool,
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
    /// `/Encrypt` reference from the newest trailer (classic or XRef stream),
    /// if any. Mainstream readers take `/Encrypt` only from the trailer that
    /// `startxref` points at, without walking `/Prev`, so an incremental
    /// update that does not carry the key forward leaves every encrypted
    /// string/stream unreadable.
    pub encrypt_ref: Option<String>,
    /// Newest cross-reference section is an XRef stream (see
    /// [`PdfTrailerInfo::uses_xref_stream`]).
    pub uses_xref_stream: bool,
}

pub fn parse_pdf_trailer_info<R: Read + Seek + ?Sized>(
    reader: &mut R,
) -> Result<PdfTrailerInfo, StrHideError> {
    let tail = parse_pdf_tail_info(reader)?;

    // An encrypted document cannot be extended incrementally: the new trailer
    // would not carry /Encrypt, and readers do not inherit it through /Prev.
    // The lossless EOF overlay never touches the trailer, so auto falls back
    // to it through the same parse failure.
    if tail.encrypt_ref.is_some() {
        return Err(StrHideError::CorruptedData(
            "PDF is encrypted (/Encrypt in the newest trailer); an incremental update would \
             break decryption for standard readers"
                .into(),
        ));
    }

    let new_obj_num = tail.new_obj_num.ok_or_else(|| {
        StrHideError::CorruptedData(
            "cannot determine next PDF object number (no /Size and no 'N G obj' definitions in tail window)".into(),
        )
    })?;
    if new_obj_num >= 0x7FFF_FFFF || new_obj_num >= u64::MAX - 1 {
        return Err(StrHideError::CorruptedData(
            "PDF /Size or object number is excessively large or overflows".into(),
        ));
    }

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
        uses_xref_stream: tail.uses_xref_stream,
    })
}

/// Offset of the last `%%EOF` marker in the PDF document.
///
/// Under ISO 32000-1 §7.5.5, a conforming reader searches the end of the file
/// for the `%%EOF` marker. When an EOF-overlay envelope is present at the physical
/// end of the carrier, the PDF boundary sits at `trailer.ube_offset` rather than
/// `file_size`.
///
/// To prevent scanning arbitrary file bodies or random high-entropy payloads,
/// the backward search is bounded to a maximum window of 1 MiB from the effective
/// PDF tail. Files lacking a valid `%%EOF` within this window are rejected.
pub(crate) fn find_last_eof<R: Read + Seek + ?Sized>(
    reader: &mut R,
    file_size: u64,
) -> Result<u64, StrHideError> {
    find_last_eof_with_magic(reader, file_size, None)
}

fn find_last_eof_with_magic<R: Read + Seek + ?Sized>(
    reader: &mut R,
    file_size: u64,
    expected_trailer_magic: Option<&[u8; 4]>,
) -> Result<u64, StrHideError> {
    const CHUNK: u64 = 64 * 1024;
    const MAX_SEARCH_DEPTH: u64 = 1024 * 1024; // 1 MiB cap on trailing data
    const MARKER: &[u8] = b"%%EOF";

    // 1. If an EOF overlay envelope sits at the tail, the PDF ends before it.
    let search_end = if file_size >= 24 {
        let restore = reader.stream_position().unwrap_or(0);
        let maybe_trailer = EnvelopeTrailer::read_from_tail(reader, expected_trailer_magic)
            .ok()
            .flatten();
        let _ = reader.seek(SeekFrom::Start(restore));
        if let Some(t) = maybe_trailer
            && t.ube_offset.checked_add(t.ube_total_size) == Some(file_size)
            && t.ube_offset < file_size
        {
            t.ube_offset
        } else {
            file_size
        }
    } else {
        file_size
    };

    let floor = search_end.saturating_sub(MAX_SEARCH_DEPTH);
    let mut end = search_end;
    while end > floor {
        let start = end.saturating_sub(CHUNK).max(floor);
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
        "Valid PDF %%EOF marker not found within tail window".into(),
    ))
}

/// Trailer facts carried by an XRef *stream* dictionary (PDF 1.5+).
struct XRefStreamDict {
    /// `/Size`: one past the highest object number, i.e. the next free number.
    size: Option<u64>,
    root_ref: Option<String>,
    info_ref: Option<String>,
    encrypt_ref: Option<String>,
}

/// End offset of the first balanced `<< ... >>` dictionary in `text`.
///
/// A plain `find(">>")` stops at the first *nested* dictionary, e.g.
/// `/DecodeParms << /Columns 5 /Predictor 12 >>`, truncating every key after
/// it (`/Size`, `/Root`, `/Encrypt`). Encrypted documents then look
/// unencrypted to the incremental writer.
///
/// Also handles PDF comments (`%...`) and literal strings (`(...)`) containing
/// angle brackets, preventing false early termination or underflow.
pub(crate) fn balanced_dict_end(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = text.find("<<")?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut str_paren_depth = 0usize;
    let mut in_comment = false;

    while i < bytes.len() {
        let b = bytes[i];

        if in_comment {
            if b == b'\r' || b == b'\n' {
                in_comment = false;
            }
            i += 1;
            continue;
        }

        if in_string {
            if b == b'\\' {
                // Skip escaped character inside PDF literal string: \(, \), \\, etc.
                i += 2;
                continue;
            }
            if b == b'(' {
                str_paren_depth += 1;
            } else if b == b')' {
                str_paren_depth = str_paren_depth.saturating_sub(1);
                if str_paren_depth == 0 {
                    in_string = false;
                }
            }
            i += 1;
            continue;
        }

        if b == b'%' {
            in_comment = true;
            i += 1;
            continue;
        }

        if b == b'(' {
            in_string = true;
            str_paren_depth = 1;
            i += 1;
            continue;
        }

        if b == b'<' && bytes.get(i + 1) == Some(&b'<') {
            depth += 1;
            i += 2;
            continue;
        }

        if b == b'>' && bytes.get(i + 1) == Some(&b'>') {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(i + 2);
            }
            i += 2;
            continue;
        }

        i += 1;
    }
    None
}

/// Read the dictionary of the XRef stream that `startxref` points at.
///
/// This is the only reliable source of the next object number in a
/// cross-reference-stream document: `/Size` lives in the stream's dictionary,
/// which is **plaintext even when the stream data itself is Flate-compressed**.
/// Deriving the number by scanning the 64 KiB tail for `N G obj` instead cannot
/// work there, because objects inside an object stream never appear in that
/// form, so `max + 1` can be lower than a number already in use — and the
/// incremental update would then collide with an existing object and corrupt
/// the document.
fn read_xref_stream_dict<R: Read + Seek + ?Sized>(
    reader: &mut R,
    startxref: u64,
) -> Option<XRefStreamDict> {
    const WINDOW: usize = 8 * 1024;

    let file_size = reader.seek(SeekFrom::End(0)).ok()?;
    if startxref == 0 || startxref >= file_size {
        return None;
    }
    let restore = reader.stream_position().unwrap_or(0);
    reader.seek(SeekFrom::Start(startxref)).ok()?;
    let mut buf = vec![0u8; WINDOW];
    let n = reader.read(&mut buf[..]).unwrap_or(0);
    let _ = reader.seek(SeekFrom::Start(restore));
    buf.truncate(n);
    if buf.len() < 16 {
        return None;
    }

    // The dictionary ends at the `>>` that closes the outermost `<<`, not at
    // the first `>>` (which may belong to a nested `/DecodeParms`).
    let text = String::from_utf8_lossy(&buf);
    let end = balanced_dict_end(&text)?;
    let dict_text = &text[..end];
    // Only accept an actual XRef stream: a `startxref` that points at something
    // else (a content stream, a classic xref table) must not be parsed as one.
    if !dict_text.contains("/XRef") {
        return None;
    }

    Some(XRefStreamDict {
        size: find_int_after(dict_text, "/Size"),
        root_ref: find_indirect_ref(dict_text, "/Root", false),
        info_ref: find_indirect_ref(dict_text, "/Info", false),
        encrypt_ref: find_indirect_ref(dict_text, "/Encrypt", false),
    })
}

/// Which cross-reference dialect the newest revision uses, judged only by the
/// bytes at `startxref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XrefAnchor {
    /// The offset points at the `xref` keyword of a classic table.
    Classic,
    /// The offset points at an indirect object (`N G obj`), i.e. an XRef stream.
    Stream,
    /// The offset is out of range or points at something unrecognised.
    Unknown,
}

/// Classify the cross-reference section that begins at `startxref`.
fn xref_anchor<R: Read + Seek + ?Sized>(
    reader: &mut R,
    startxref: u64,
    file_size: u64,
) -> XrefAnchor {
    if startxref == 0 || startxref >= file_size {
        return XrefAnchor::Unknown;
    }
    let Ok(restore) = reader.stream_position() else {
        return XrefAnchor::Unknown;
    };
    if reader.seek(SeekFrom::Start(startxref)).is_err() {
        return XrefAnchor::Unknown;
    }
    let mut buf = [0u8; 32];
    let n = reader.read(&mut buf).unwrap_or(0);
    let _ = reader.seek(SeekFrom::Start(restore));
    let text = String::from_utf8_lossy(&buf[..n]);
    let t = text
        .trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '\u{0B}' || c == '\u{0C}');
    if t.starts_with("xref") {
        XrefAnchor::Classic
    } else if t.starts_with(|c: char| c.is_ascii_digit()) {
        XrefAnchor::Stream
    } else {
        XrefAnchor::Unknown
    }
}

pub fn parse_pdf_tail_info<R: Read + Seek + ?Sized>(
    reader: &mut R,
) -> Result<PdfTailInfo, StrHideError> {
    parse_pdf_tail_info_with_magic(reader, None)
}

pub fn parse_pdf_tail_info_with_magic<R: Read + Seek + ?Sized>(
    reader: &mut R,
    expected_trailer_magic: Option<&[u8; 4]>,
) -> Result<PdfTailInfo, StrHideError> {
    let file_size = reader.seek(SeekFrom::End(0))?;
    let eof_idx = find_last_eof_with_magic(reader, file_size, expected_trailer_magic)?;
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
    let mut encrypt_ref = None;
    let mut uses_xref_stream = false;

    // The dialect of the *newest* cross-reference section is decided by the
    // object `startxref` points at, not by what the last 64 KiB happen to
    // contain: a document that began with a classic `xref`/`trailer` and was
    // later updated with an XRef stream still carries rev1's trailer in that
    // window, and its `/Size` is stale. Adopting it mints an object number that
    // rev2 already uses, so the incremental update would collide.
    // For a classic table the trailer must be searched only from
    // `startxref` onwards (the trailer follows the table it describes).
    let mut anchor = xref_anchor(reader, prev_startxref, file_size);
    // A `N G obj` anchor only proves the offset lands on *an* object. Treat it
    // as an XRef stream only when its dictionary really says `/Type /XRef`;
    // anything else keeps the lenient path so slightly-off `startxref` offsets
    // in third-party writers still parse.
    let stream_dict = if anchor == XrefAnchor::Stream {
        read_xref_stream_dict(reader, prev_startxref)
    } else {
        None
    };
    if anchor == XrefAnchor::Stream && stream_dict.is_none() {
        anchor = XrefAnchor::Unknown;
    }
    if anchor != XrefAnchor::Stream {
        let from = match anchor {
            XrefAnchor::Classic => prev_startxref.saturating_sub(window_start) as usize,
            // Unknown anchors keep the lenient whole-window search so a carrier
            // whose `startxref` is not exactly on the section start still parses.
            _ => 0,
        };
        // `before` is lossy UTF-8: a file offset can land inside a replacement
        // character, so snap it forward to a char boundary before slicing.
        let mut start_idx = from.min(sx_idx);
        while start_idx < sx_idx && !text_before_eof.is_char_boundary(start_idx) {
            start_idx += 1;
        }
        if let Some(rel) = text_before_eof[start_idx..sx_idx].rfind("trailer") {
            let trailer_idx = start_idx + rel;
            let trailer_str = &text_before_eof[trailer_idx..sx_idx];
            new_obj_num = find_int_after(trailer_str, "/Size");
            root_ref = find_indirect_ref(trailer_str, "/Root", false);
            info_ref = find_indirect_ref(trailer_str, "/Info", false);
            encrypt_ref = find_indirect_ref(trailer_str, "/Encrypt", false);
        }
    }

    // No classic trailer dictionary (xref-stream PDF): read /Size (and /Root,
    // /Info, /Encrypt) from the XRef stream that `startxref` points at. Only
    // when that is unavailable does the tail-window `N G obj` scan remain as a
    // last resort.
    let stream_dict = stream_dict.or_else(|| {
        if new_obj_num.is_none() {
            read_xref_stream_dict(reader, prev_startxref)
        } else {
            None
        }
    });
    if new_obj_num.is_none()
        && let Some(dict) = stream_dict
    {
        uses_xref_stream = true;
        new_obj_num = dict.size;
        if root_ref.is_none() {
            root_ref = dict.root_ref;
        }
        if info_ref.is_none() {
            info_ref = dict.info_ref;
        }
        if encrypt_ref.is_none() {
            encrypt_ref = dict.encrypt_ref;
        }
    }
    if new_obj_num.is_none() {
        new_obj_num = scan_max_object_number(&text_before_eof).and_then(|n| n.checked_add(1));
    } else if anchor != XrefAnchor::Classic
        && let Some(scanned) =
            scan_max_object_number(&text_before_eof).and_then(|n| n.checked_add(1))
        && let Some(current) = new_obj_num
    {
        // An XRef stream's `/Size` is the authoritative next object number, but
        // a stale one must never under-report: taking the larger of `/Size` and
        // `max(objnum) + 1` cannot collide either way.
        new_obj_num = Some(current.max(scanned));
    }

    // /Root and /Info may live inside an xref-stream trailer dict (or an older
    // incremental trailer) even when the newest trailer omits them; the last
    // valid reference in the tail is the currently effective one. /Encrypt is
    // deliberately NOT resolved with the same tail-wide fallback: readers take
    // it from the newest trailer only, so an older /Encrypt without the newest
    // one means the document is already inconsistent, not that an update must
    // avoid it.
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
        encrypt_ref,
        uses_xref_stream,
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

/// Header of the incremental-update object that carries the envelope stream.
///
/// The leading `\n` separates the new object from the previous `%%EOF`, and
/// its length is exactly what [`super::PdfAdapter::calc_prefix_len`] reports so the
/// engine can point the trailer at the stream instead of at the object
/// keyword. Writer and accounting must use this one function: two hand-written
/// format strings drifting apart would put `ube_offset` a few bytes off, which
/// reads back as "no hidden data" rather than as a visible error.
pub fn pdf_obj_header(new_obj_num: u64, ube_size: u64) -> String {
    format!("\n{new_obj_num} 0 obj\n<< /Type /Metadata /Length {ube_size} >>\nstream\n")
}
