//! PDF format adapter for strhide with compliant Incremental Update object stream hiding.

use crate::errors::StrHideError;
use crate::structure::adapters::{
    HostAdapter, InjectCoordinates, LocatedEnvelope, SeekRead, StrategyCapacity, eof::EofAdapter,
};
use crate::structure::envelope::{EnvelopeTrailer, TRAILER_SIZE};
use std::io::{Read, Seek, SeekFrom, Write};

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
fn find_last_eof<R: Read + Seek + ?Sized>(
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
fn balanced_dict_end(text: &str) -> Option<usize> {
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
/// its length is exactly what [`PdfAdapter::calc_prefix_len`] reports so the
/// engine can point the trailer at the stream instead of at the object
/// keyword. Writer and accounting must use this one function: two hand-written
/// format strings drifting apart would put `ube_offset` a few bytes off, which
/// reads back as "no hidden data" rather than as a visible error.
pub fn pdf_obj_header(new_obj_num: u64, ube_size: u64) -> String {
    format!("\n{new_obj_num} 0 obj\n<< /Type /Metadata /Length {ube_size} >>\nstream\n")
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structure::adapters::HostAdapter;
    use crate::structure::envelope::{STANDARD_TRAILER_MAGIC, TRAILER_SIZE};
    use std::io::Cursor;

    /// Classic PDF with `/Size 2` and `/Root`: the smallest carrier the
    /// incremental strategy accepts.
    fn minimal_pdf() -> Vec<u8> {
        minimal_pdf_with_size(2)
    }

    /// Minimal classic PDF whose `/Size` (i.e. next object number) is `size`.
    fn minimal_pdf_with_size(size: u64) -> Vec<u8> {
        format!(
            "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n\
             xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n\
             trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n9\n%%EOF\n"
        )
        .into_bytes()
    }

    /// Full UBE (payload + trailer) for `payload_len` bytes of body.
    fn ube_of(payload_len: usize, ube_offset: u64) -> Vec<u8> {
        let mut ube = vec![0x7Bu8; payload_len];
        let total = payload_len as u64 + TRAILER_SIZE as u64;
        ube.extend_from_slice(
            &EnvelopeTrailer::create(ube_offset, total, STANDARD_TRAILER_MAGIC).pack(),
        );
        ube
    }

    /// `calc_prefix_len` is the writer's own offset accounting: it must equal
    /// the number of bytes `inject` writes between `%%EOF` and the envelope,
    /// for every payload length (the `/Length` digits change the width).
    #[test]
    fn calc_prefix_len_matches_the_injected_offset() {
        for payload_len in [0usize, 1, 9, 10, 99, 100, 9_999, 10_000, 123_456] {
            let host = minimal_pdf();
            let ube = ube_of(payload_len, 0); // offset ignored by the carrier
            let ube_size = ube.len() as u64;

            let prefix = PdfAdapter::calc_prefix_len(&mut Cursor::new(&host), ube_size).unwrap();
            assert_eq!(
                prefix,
                pdf_obj_header(2, ube_size).len() as u64,
                "prefix must be the object header for /Size 2 and {ube_size} bytes"
            );

            let mut out = Vec::new();
            let InjectCoordinates {
                offset: inject_offset,
                size: inject_size,
                ..
            } = PdfAdapter
                .inject(
                    &mut Cursor::new(host.clone()),
                    &mut Cursor::new(ube.clone()),
                    &mut out,
                    "incremental",
                )
                .unwrap();

            assert_eq!(inject_offset, host.len() as u64);
            assert_eq!(
                &out[inject_offset as usize..(inject_offset + prefix) as usize],
                pdf_obj_header(2, ube_size).as_bytes(),
                "bytes before the envelope must be exactly the object header"
            );
            assert_eq!(
                &out[(inject_offset + prefix) as usize
                    ..(inject_offset + prefix) as usize + ube.len()],
                &ube[..],
                "envelope must start at inject_offset + calc_prefix_len"
            );
            assert!(
                out[(inject_offset + prefix + ube_size) as usize..]
                    .starts_with(b"\nendstream\nendobj\n"),
                "the envelope stream must be closed right after the envelope bytes"
            );
            assert_eq!(
                inject_size,
                (out.len() as u64) - inject_offset,
                "inject_size must cover the object, the xref section and the new trailer"
            );
        }
    }

    /// A 10-digit object number plus a 9-digit `/Length` makes the incremental
    /// object header 65 bytes, which the old 64-byte limit could not record.
    /// `MAX_OFFSET_DELTA` is 128 now, so the reachable worst case fits and auto
    /// must pick the lossless-in-place strategy instead of the EOF overlay.
    ///
    /// The template is `46 + digits(N) + digits(L)`; both inputs are `u64`, so
    /// no parseable PDF can produce a header longer than 86 bytes. Asserting
    /// that keeps the limit and the template from drifting apart again.
    #[test]
    fn ten_digit_object_numbers_fit_the_recordable_shift() {
        let host = minimal_pdf_with_size(1_000_000_001);
        let mut cursor = Cursor::new(&host);
        assert_eq!(
            PdfAdapter.choose_auto_strategy(&mut cursor, 100_000_000),
            "incremental",
            "65 bytes of shift must be recordable under MAX_OFFSET_DELTA = 128"
        );

        let worst = pdf_obj_header(u64::MAX, u64::MAX);
        assert!(
            worst.len() <= crate::structure::envelope::MAX_OFFSET_DELTA as usize,
            "the longest representable object header is {} bytes, over the {}-byte limit",
            worst.len(),
            crate::structure::envelope::MAX_OFFSET_DELTA
        );
    }

    /// Two consecutive incremental updates: the second carrier's `/Size` has
    /// grown, so its object number (and therefore the prefix length) changes.
    /// Reading back the first envelope must still work afterwards.
    #[test]
    fn prefix_len_follows_successive_incremental_updates() {
        let host = minimal_pdf();
        let mut prev = host.clone();

        for round in 0..2 {
            let expected_obj = 2 + round as u64;
            let ube = ube_of(64, 0);
            let ube_size = ube.len() as u64;

            let prefix = PdfAdapter::calc_prefix_len(&mut Cursor::new(&prev), ube_size).unwrap();
            assert_eq!(
                prefix,
                pdf_obj_header(expected_obj, ube_size).len() as u64,
                "round {round}: next object number must follow /Size"
            );

            let mut out = Vec::new();
            let InjectCoordinates {
                offset: inject_offset,
                ..
            } = PdfAdapter
                .inject(
                    &mut Cursor::new(prev.clone()),
                    &mut Cursor::new(ube.clone()),
                    &mut out,
                    "incremental",
                )
                .unwrap();
            assert_eq!(
                &out[(inject_offset + prefix) as usize
                    ..(inject_offset + prefix) as usize + ube.len()],
                &ube[..],
                "round {round}: envelope offset drifted"
            );
            assert!(
                out.windows(9)
                    .any(|w| w == format!("\n{expected_obj} 0 obj\n").as_bytes()),
                "round {round}: injected object number missing"
            );

            // The newest trailer must still declare a /Root and a larger /Size.
            let info = parse_pdf_trailer_info(&mut Cursor::new(out.clone())).unwrap();
            assert_eq!(info.new_obj_num, expected_obj + 1);
            prev = out;
        }
    }

    /// PDF 1.5+ XRef-stream document whose compressed stream data is larger than
    /// the 64 KiB tail window.
    ///
    /// The window then holds nothing but stream bytes, so neither
    /// `trailer << /Size >>` nor the `N G obj` scan can find the next object
    /// number: the only place it exists is the XRef stream dictionary at
    /// `startxref`. Deriving it from the tail instead under-reports (objects
    /// inside an object stream never appear as `N G obj`), which makes the
    /// incremental update collide with an existing object.
    #[test]
    fn xref_stream_size_comes_from_the_stream_dictionary() {
        let mut pdf = Vec::new();
        pdf.extend_from_slice(
            b"%PDF-1.5
",
        );
        for obj in [
            "1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
",
            "2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
",
            "3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
",
        ] {
            pdf.extend_from_slice(obj.as_bytes());
        }
        let xref_obj_offset = pdf.len() as u64;
        // A dictionary whose compressed payload is far larger than the tail
        // window: the window ends up holding stream bytes only.
        let dict = "<< /Length 70000 /Type /XRef /Root 1 0 R /Size 10 /W [1 2 1] >>";
        pdf.extend_from_slice(
            format!(
                "4 0 obj
{dict}
stream
"
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&[0u8; 70_000]);
        pdf.extend_from_slice(
            b"
endstream
endobj
",
        );
        pdf.extend_from_slice(
            format!(
                "startxref
{xref_obj_offset}
%%EOF
"
            )
            .as_bytes(),
        );

        let info = parse_pdf_tail_info(&mut Cursor::new(pdf.clone())).expect("must parse");
        assert_eq!(info.prev_startxref, xref_obj_offset);
        assert_eq!(
            info.new_obj_num,
            Some(10),
            "/Size from the XRef stream dictionary is the next object number"
        );
        assert_eq!(info.root_ref.as_deref(), Some("1 0 R"));

        // ...and the writer can therefore name a free object.
        assert_eq!(
            PdfAdapter::calc_prefix_len(&mut Cursor::new(pdf), 88).unwrap(),
            pdf_obj_header(10, 88).len() as u64
        );
    }

    #[test]
    fn classic_trailer_still_wins_over_the_xref_stream_scan() {
        // A hybrid document whose newest section is a classic table: an older
        // XRef stream sits in the tail window, but /Size must come from the
        // trailer that follows the table `startxref` points at.
        let mut pdf = Vec::new();
        pdf.extend_from_slice(
            b"%PDF-1.4
1 0 obj
<< /Type /Catalog >>
endobj
",
        );
        pdf.extend_from_slice(
            b"2 0 obj
<< /Length 4 /Type /XRef /Size 3 >>
stream
0000
endstream
endobj
",
        );
        let classic_xref_offset = pdf.len() as u64;
        pdf.extend_from_slice(
            b"xref
0 2
0000000000 65535 f 
0000000009 00000 n 
trailer
<< /Size 7 /Root 1 0 R >>
",
        );
        pdf.extend_from_slice(
            format!(
                "startxref
{classic_xref_offset}
%%EOF
"
            )
            .as_bytes(),
        );

        let info = parse_pdf_tail_info(&mut Cursor::new(pdf)).expect("must parse");
        assert_eq!(info.new_obj_num, Some(7));
        assert_eq!(info.root_ref.as_deref(), Some("1 0 R"));
        assert!(!info.uses_xref_stream);
    }

    /// Revision 1 is a classic `xref`/`trailer` document, revision 2 replaces
    /// Verifies that incremental updates on XRef-stream documents ignore earlier classic trailers.
    #[test]
    fn xref_stream_revision_ignores_the_earlier_classic_trailer() {
        let mut pdf = Vec::new();
        pdf.extend_from_slice(
            b"%PDF-1.4
1 0 obj
<< /Type /Catalog >>
endobj
",
        );
        let rev1_xref = pdf.len() as u64;
        pdf.extend_from_slice(
            format!(
                "xref
0 2
0000000000 65535 f 
0000000009 00000 n 
trailer
<< /Size 2 /Root 1 0 R >>
startxref
{rev1_xref}
%%EOF
"
            )
            .as_bytes(),
        );
        let rev2_xref = pdf.len() as u64;
        pdf.extend_from_slice(
            b"2 0 obj
<< /Type /XRef /Root 1 0 R /Size 3 /Length 7 >>
stream
",
        );
        pdf.extend_from_slice(&[1u8, 0, 0, 0, 0, 0, 0]);
        pdf.extend_from_slice(
            format!(
                "
endstream
endobj
startxref
{rev2_xref}
%%EOF
"
            )
            .as_bytes(),
        );

        let info = parse_pdf_tail_info(&mut Cursor::new(pdf.clone())).expect("must parse");
        assert_eq!(
            info.new_obj_num,
            Some(3),
            "the XRef stream's /Size must win over the stale rev-1 trailer"
        );
        assert!(info.uses_xref_stream);

        let original_len = pdf.len();
        let ube = ube_of(32, 0);
        let mut out = Vec::new();
        PdfAdapter
            .inject(
                &mut Cursor::new(pdf),
                &mut Cursor::new(ube),
                &mut out,
                "incremental",
            )
            .unwrap();
        let tail = &out[original_len..];
        assert!(
            tail.windows(9).any(|w| w == b"\n3 0 obj\n"),
            "the envelope object must take /Size 3, not the colliding rev-1 value"
        );
        assert!(
            tail.windows(11).any(|w| w == b"/Type /XRef"),
            "an XRef-stream revision must receive an XRef-stream update"
        );
        assert!(
            !tail.windows(6).any(|w| w == b"\nxref\n"),
            "a classic xref table must not be appended to an XRef-stream revision"
        );
    }

    #[test]
    fn parse_pdf_tail_info_with_trailer_comment_after_startxref() {
        let pdf_data = b"%PDF-1.7\n\
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n\
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n\
trailer\n\
<< /Size 4 /Root 1 0 R >>\n\
startxref\n\
9\n\
% appended comment mentioning trailer written here\n\
%%EOF\n";
        let mut cur = Cursor::new(pdf_data.to_vec());
        let info = parse_pdf_tail_info(&mut cur).expect("must not panic and succeed");
        assert_eq!(info.new_obj_num, Some(4));
        assert_eq!(info.root_ref.as_deref(), Some("1 0 R"));
    }

    #[test]
    fn test_balanced_dict_end_edge_cases() {
        // 1. Basic nested dict
        let text1 = "1 0 obj << /Type /XRef /DecodeParms << /Columns 5 >> /Size 10 >> stream";
        let end1 = balanced_dict_end(text1).unwrap();
        assert_eq!(
            &text1[..end1],
            "1 0 obj << /Type /XRef /DecodeParms << /Columns 5 >> /Size 10 >>"
        );

        // 2. Dict containing string with unbalanced >>
        let text2 = "<< /Title (Chapter 1 >> Intro) /Size 20 >> tail";
        let end2 = balanced_dict_end(text2).unwrap();
        assert_eq!(&text2[..end2], "<< /Title (Chapter 1 >> Intro) /Size 20 >>");

        // 3. Dict containing escaped parentheses in string
        let text3 = r"<< /Title (Nested \( >> \) paren) /Root 1 0 R >>";
        let end3 = balanced_dict_end(text3).unwrap();
        assert_eq!(&text3[..end3], text3);

        // 4. Dict containing comment with >>
        let text4 = "<< /Size 5\n% Comment with >> marker\n/Root 2 0 R\n>>";
        let end4 = balanced_dict_end(text4).unwrap();
        assert_eq!(&text4[..end4], text4);

        // 5. Malformed text without <<
        assert_eq!(balanced_dict_end("no dictionary here"), None);

        // 6. Malformed text with premature unclosed <<
        assert_eq!(balanced_dict_end("<< /Size 5 /Root 1 0 R"), None);

        // 7. Extra >> before << should not cause underflow or panic
        let text7 = ">> >> << /Size 1 >>";
        let end7 = balanced_dict_end(text7).unwrap();
        assert_eq!(&text7[..end7], ">> >> << /Size 1 >>");
    }
}
