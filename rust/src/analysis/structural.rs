//! Structural fingerprinting: known signatures and container heuristics.
//!
//! Every detector here reasons about bytes and container layout, not image
//! statistics. It is the only track that can recognise this project's own
//! structure-domain envelopes and third-party overlays.

use std::io::Cursor;

use crate::formats::FileFormat;
use crate::structure::adapters::{pe_layout, pe_slack};
use crate::structure::envelope::{
    EnvelopeTrailer, STANDARD_HEADER_MAGIC, STANDARD_TRAILER_MAGIC, TRAILER_SIZE,
};

use super::{
    DetectorMetric, Finding, JPEG_EOI, PNG_IEND_FULL, STRUCT_TAIL_WINDOW, ScanMagics, ScanView,
    Severity, TAIL_WINDOW, report_trailing, shannon_entropy,
};

// ---------------------------------------------------------------------------
// Track 1a: known steganography tool signatures (auxiliary fingerprinting).
// ---------------------------------------------------------------------------

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut start = 0;
    while let Some(pos) = haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
    {
        let match_idx = start + pos;
        out.push(match_idx);
        start = match_idx.saturating_add(needle.len());
        if start >= haystack.len() {
            break;
        }
    }
    out
}

struct KnownSignature {
    tool: &'static str,
    pattern: &'static [u8],
    /// Four-byte patterns require self-consistent trailer context to avoid false positives in compressed data.
    needs_trailer_context: bool,
}

const KNOWN_TOOL_SIGNATURES: &[KnownSignature] = &[
    KnownSignature {
        tool: "strhide (standard v2)",
        pattern: &[0xb7, 0x54, 0x2c, 0x82, 0x7e, 0x31, 0x1d, 0x6e],
        needs_trailer_context: false,
    },
    KnownSignature {
        tool: "strhide (legacy v0)",
        pattern: b"\x89STRHIDE",
        needs_trailer_context: false,
    },
    KnownSignature {
        tool: "strhide (trailer mark)",
        pattern: &[0x78, 0xe6, 0x66, 0xd2],
        needs_trailer_context: true,
    },
    KnownSignature {
        tool: "OpenStego",
        pattern: b"OPENSTEGO",
        needs_trailer_context: false,
    },
    KnownSignature {
        tool: "Camouflage",
        pattern: b"\x1a\x00\x00\x00CAMOUFLAGE",
        needs_trailer_context: false,
    },
];

pub(super) fn track_tool_signatures(view: &ScanView, out: &mut Vec<Finding>, magics: ScanMagics) {
    for sig in KNOWN_TOOL_SIGNATURES {
        // An appended envelope lives in the tail of an oversized carrier, so
        // both windows have to be searched.
        let prefix_hit = find_all(view.prefix, sig.pattern)
            .into_iter()
            .any(|pos| !sig.needs_trailer_context || trailer_context_ok(view, pos as u64, magics));
        let tail_hit = view.tail.is_some_and(|(offset, bytes)| {
            find_all(bytes, sig.pattern).into_iter().any(|pos| {
                !sig.needs_trailer_context || trailer_context_ok(view, offset + pos as u64, magics)
            })
        });
        if prefix_hit || tail_hit {
            out.push(Finding {
                detector: "signature:known-tool".into(),
                severity: Severity::Likely,
                detail: format!("Matches known steganography tool signature: {}", sig.tool),
            });
        }
    }

    // A private dialect's header magic is exactly as much a strhide signature
    // as the official constant above, so a scan asked about that dialect must
    // report it instead of calling the carrier clean.
    if let Some(header) = magics.header {
        let prefix_hit = !find_all(view.prefix, &header).is_empty();
        let tail_hit = view
            .tail
            .is_some_and(|(_, bytes)| !find_all(bytes, &header).is_empty());
        if prefix_hit || tail_hit {
            out.push(Finding {
                detector: "signature:known-tool".into(),
                severity: Severity::Likely,
                detail: "Matches known steganography tool signature: strhide (private dialect)"
                    .into(),
            });
        }
    }
}

/// Checks whether the 4-byte trailer magic at `magic_pos` is backed by a
/// self-consistent 24-byte trailer and valid CRC to eliminate accidental false positives.
fn trailer_context_ok(view: &ScanView<'_>, magic_pos: u64, magics: ScanMagics) -> bool {
    let Some(start) = magic_pos.checked_sub((TRAILER_SIZE - 4) as u64) else {
        return false;
    };
    let Some(bytes) = view.slice(start, TRAILER_SIZE) else {
        return false;
    };
    let trailer = EnvelopeTrailer::unpack(bytes, Some(&STANDARD_TRAILER_MAGIC)).or_else(|e| {
        match magics.trailer {
            Some(magic) => EnvelopeTrailer::unpack(bytes, Some(&magic)).map_err(|_| e),
            None => Err(e),
        }
    });
    let Ok(trailer) = trailer else {
        return false;
    };
    trailer
        .ube_offset
        .checked_add(trailer.ube_total_size)
        .is_some_and(|end| end <= view.file_size)
}

// ---------------------------------------------------------------------------
// Track 1b: container structure heuristics
// ---------------------------------------------------------------------------

/// PNG chunk names that are part of the official spec or standard extensions.
/// Anything else is either strhide's own `prIv`/`stEg` or a third-party private chunk.
const PNG_STANDARD_CHUNKS: &[&[u8]] = &[
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"iCCP", b"sBIT", b"sRGB",
    b"iTXt", b"tEXt", b"zTXt", b"bKGD", b"hIST", b"pHYs", b"sPLT", b"tIME", b"eXIf", b"acTL",
    b"fcTL", b"fdAT",
];

/// Cap on how many private / non-standard chunk names one scan reports.
const MAX_CHUNK_FINDINGS: usize = 64;

/// Result of walking as much of a PNG chunk stream as the available bytes
/// allow.
struct PngWalk {
    /// File offset just past `IEND`, when the walk reached it.
    iend_end: Option<u64>,
    /// Private ancillary chunks, with their declared body length.
    private: Vec<(String, u32)>,
    /// Non-standard public chunks, with their declared body length.
    unknown: Vec<(String, u32)>,
}

impl PngWalk {
    fn emit(self, out: &mut Vec<Finding>) {
        for (name, len) in self.private {
            out.push(Finding {
                detector: "png:private-chunk".into(),
                severity: Severity::Likely,
                detail: format!(
                    "Private ancillary chunk '{name}' ({len} bytes) - non-standard metadata injection"
                ),
            });
        }
        for (name, len) in self.unknown {
            out.push(Finding {
                detector: "png:unknown-chunk".into(),
                severity: Severity::Info,
                detail: format!("Non-standard public chunk '{name}' ({len} bytes)"),
            });
        }
    }
}

/// Walk PNG chunks in `data` (which starts at file offset 0).
fn walk_png_chunks(data: &[u8]) -> PngWalk {
    // Walk chunks: 8-byte PNG signature, then [u32 length][4-byte type][data][u32 crc].
    let mut pos = 8usize;
    let mut walk = PngWalk {
        iend_end: None,
        private: Vec::new(),
        unknown: Vec::new(),
    };
    while pos + 8 <= data.len() {
        let len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let ty = &data[pos + 4..pos + 8];
        // Chunk types are four ASCII letters (RFC 2083 §3.3). Anything else
        // means the chunk stream has ended and the rest is padding or garbage
        // — continuing would decode zero fill as an endless run of empty chunks.
        if !ty.iter().all(|b| b.is_ascii_alphabetic()) {
            break;
        }
        let ty_str = String::from_utf8_lossy(ty).to_string();
        let total = 12u64.saturating_add(len as u64);
        let next = match (pos as u64).checked_add(total) {
            Some(n) if n <= data.len() as u64 => n as usize,
            // A length that runs past the available bytes means the walk
            // cannot continue: either a truncated file or the end of the
            // prefix window.
            _ => break,
        };

        // PNG Specification (RFC 2083 Section 5.4):
        // Bit 5 of the second byte (0x20) indicates private (1) vs public (0) chunk.
        //
        // The whitelist is consulted *first*. The case that forces this order is
        // APNG: `acTL`, `fcTL` and `fdAT` are registered PNG/APNG chunk types
        // (they are in `PNG_STANDARD_CHUNKS`) whose second letter is lowercase,
        // i.e. by the RFC's naming rule they are "private" too. Checking
        // private-ness first flagged every ordinary animated PNG as metadata
        // injection with a `Likely` severity -- three such chunks saturate the
        // risk score at 100 on a perfectly clean carrier.
        //
        // Cap the collected list: a crafted file can repeat one chunk type
        // (or use thousands of distinct types) at no cost, and every entry
        // becomes a finding. 64 is well past what a real image carries.
        let is_standard = PNG_STANDARD_CHUNKS.contains(&ty);
        if is_standard {
            // Known chunk type: nothing to report, whatever its naming bits say.
        } else if (ty[1] & 0x20) != 0 {
            if walk.private.len() < MAX_CHUNK_FINDINGS {
                walk.private.push((ty_str, len));
            }
        } else if ty != b"IEND" && walk.unknown.len() < MAX_CHUNK_FINDINGS {
            walk.unknown.push((ty_str, len));
        }

        if ty == b"IEND" {
            walk.iend_end = Some(next as u64);
            return walk;
        }
        pos = next;
    }
    walk
}

/// Structural checks for a PNG, returning whether the chunk stream reached
/// `IEND`.
///
/// The return value drives the `png:trailing-data` metric: with no terminator
/// the metric cannot claim "0 bytes / clean termination at IEND".
pub(super) fn track_png_structure(view: &ScanView, out: &mut Vec<Finding>) -> bool {
    let walk = walk_png_chunks(view.prefix);
    let terminated = match walk.iend_end {
        // The whole chunk stream was inside the bytes we have.
        Some(end) => {
            report_trailing(view, end, "png:trailing-data", "IEND", out);
            true
        }
        None => match view.tail {
            None => {
                // Whole file, and the walk never reached IEND. A conforming
                // PNG always ends with it, so this is either a truncated file
                // or an IEND that was removed and replaced with other bytes.
                // An absent IEND must be reported to prevent appending payloads
                // without detection.
                out.push(Finding {
                    detector: "png:trailing-data".into(),
                    severity: Severity::Suspicious,
                    detail: format!(
                        "no IEND chunk anywhere in the {}-byte file: the chunk stream is \
                         truncated or the terminator was replaced by other data",
                        view.file_size
                    ),
                });
                false
            }
            Some((tail_offset, tail)) => {
                match tail
                    .windows(PNG_IEND_FULL.len())
                    .rposition(|w| w == PNG_IEND_FULL)
                {
                    Some(idx) => {
                        let end = tail_offset + idx as u64 + PNG_IEND_FULL.len() as u64;
                        report_trailing(view, end, "png:trailing-data", "IEND", out);
                        true
                    }
                    None => {
                        // IEND is a fixed 12-byte pattern with a fixed CRC, so
                        // "not in the last 64 KiB" means at least that much data
                        // follows the chunk stream: the container does not end
                        // where a PNG ends it.
                        out.push(Finding {
                            detector: "png:trailing-data".into(),
                            severity: Severity::Suspicious,
                            detail: format!(
                                "no IEND chunk in the last {} bytes; at least {} bytes follow the chunk stream (tail entropy {:.2} bits/byte)",
                                STRUCT_TAIL_WINDOW,
                                view.bytes_after(tail_offset),
                                view.trailing_entropy(tail_offset)
                            ),
                        });
                        false
                    }
                }
            }
        },
    };
    walk.emit(out);
    terminated
}

/// Result of walking as much of a JPEG marker stream as the available bytes
/// allow.
struct JpegWalk {
    /// File offset just past `EOI`, when the walk reached it.
    eoi_end: Option<u64>,
    app_segments: Vec<(u8, u32)>,
    com_segments: Vec<(u32, f64)>,
    dqt_count: u32,
    dht_count: u32,
    sos_count: u32,
}

fn walk_jpeg_markers(data: &[u8]) -> JpegWalk {
    // Walk markers: 0xFF 0xM[arker]; markers with payload carry a u16 length.
    let mut pos = 2usize; // skip SOI
    let mut walk = JpegWalk {
        eoi_end: None,
        app_segments: Vec::new(),
        com_segments: Vec::new(),
        dqt_count: 0,
        dht_count: 0,
        sos_count: 0,
    };
    while pos + 1 < data.len() {
        if data[pos] != 0xFF {
            break;
        }
        // Skip consecutive 0xFF fill bytes
        while pos < data.len() && data[pos] == 0xFF {
            pos += 1;
        }
        if pos >= data.len() {
            break;
        }
        let marker = data[pos];
        pos += 1;

        // Standalone markers (no length): TEM 0x01, RSTn 0xD0..=0xD7, SOI/EOI.
        let standalone = matches!(marker, 0x01 | 0xD0..=0xD7 | 0xD8 | 0xD9);
        if standalone {
            if marker == 0xD9 {
                // EOI: legitimate JPEG ends here.
                walk.eoi_end = Some(pos as u64);
                return walk;
            }
            continue;
        }
        if pos + 2 > data.len() {
            break;
        }
        let seg_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        if seg_len < 2 {
            break;
        }
        if (0xE0..=0xEF).contains(&marker) {
            walk.app_segments.push((marker & 0x0F, seg_len as u32));
        } else if marker == 0xFE {
            let payload_start = pos + 2;
            let payload_end = (pos + seg_len).min(data.len());
            let ent = if payload_end > payload_start {
                shannon_entropy(&data[payload_start..payload_end])
            } else {
                0.0
            };
            walk.com_segments.push((seg_len as u32, ent));
        }

        // SOS: entropy-coded image data follows until the next non-stuffed
        // marker; skip past it so we can still see trailing markers.
        match marker {
            0xDB => walk.dqt_count += 1,
            0xC4 => walk.dht_count += 1,
            0xDA => {
                walk.sos_count += 1;
                let scan_start = pos.saturating_add(seg_len);
                pos = find_next_jpeg_marker(data, scan_start);
                continue;
            }
            _ => {}
        }
        let next = pos.saturating_add(seg_len);
        if next <= pos {
            break;
        }
        pos = next;
    }
    walk
}

/// Structural checks for a JPEG, returning whether the marker stream reached
/// `EOI`.
///
/// The return value drives the `jpeg:trailing-data` metric: with no terminator
/// the metric cannot claim "0 bytes / clean termination at EOI". Same contract
/// as [`track_png_structure`], and for the same reason — a whole-file view with
/// no EOI must produce a finding, preventing payloads from being appended after
/// removing the terminator.
pub(super) fn track_jpeg_structure(view: &ScanView, out: &mut Vec<Finding>) -> bool {
    let walk = walk_jpeg_markers(view.prefix);
    let terminated = match walk.eoi_end {
        Some(end) => {
            report_trailing(view, end, "jpeg:trailing-data", "EOI", out);
            true
        }
        None if view.is_whole() => {
            // A conforming JPEG ends with FF D9; nothing else can terminate the
            // entropy-coded scan. Either the file is truncated or the marker was
            // removed and replaced with other bytes.
            out.push(Finding {
                detector: "jpeg:trailing-data".into(),
                severity: Severity::Suspicious,
                detail: format!(
                    "no EOI marker (FF D9) anywhere in the {}-byte file: the marker stream is \
                     truncated or the terminator was replaced by other data",
                    view.file_size
                ),
            });
            false
        }
        None => {
            report_jpeg_tail(view, out);
            // The tail window is where the real EOI would be, if the walk simply
            // ran out of scanned bytes before reaching it.
            view.tail
                .is_some_and(|(_, tail)| tail.windows(2).any(|w| w == JPEG_EOI))
        }
    };
    emit_jpeg_findings(walk, out);
    terminated
}

/// Trailing-data check for a JPEG too large to walk to its end.
///
/// The marker walk stops inside the entropy-coded scan data, which has no
/// marker structure to follow. The file's own end is the evidence: `EOI` is
/// literally the last two bytes of a JPEG with nothing appended, so anything
/// else means bytes follow the image.
fn report_jpeg_tail(view: &ScanView, out: &mut Vec<Finding>) {
    let Some((tail_offset, tail)) = view.tail else {
        return;
    };
    if tail.ends_with(&JPEG_EOI) {
        return;
    }
    let ent = view.trailing_entropy(tail_offset);
    // A found EOI with bytes after it is confirmed trailing data; "no EOI in
    // the window" may equally be a truncated carrier, so it stays Suspicious.
    let (detail, severity) = match tail.windows(2).rposition(|w| w == JPEG_EOI) {
        Some(idx) => {
            let trailing = view.bytes_after(tail_offset + idx as u64 + 2);
            let detail = format!(
                "file does not end with EOI; {trailing} trailing bytes present after the last EOI marker (entropy {ent:.2} bits/byte)"
            );
            (detail, Severity::Likely)
        }
        None => {
            let trailing = view.bytes_after(tail_offset);
            let detail = format!(
                "file does not end with EOI; no EOI marker in the last {} bytes, so at least {trailing} bytes follow the image data (entropy {ent:.2} bits/byte)",
                STRUCT_TAIL_WINDOW
            );
            (detail, Severity::Suspicious)
        }
    };
    out.push(Finding {
        detector: "jpeg:trailing-data".into(),
        severity,
        detail,
    });
}

fn emit_jpeg_findings(walk: JpegWalk, out: &mut Vec<Finding>) {
    // Flag oversized or anomalous APP segments
    for (id, len) in &walk.app_segments {
        if *len > 32 * 1024 {
            out.push(Finding {
                detector: "jpeg:oversized-app".into(),
                severity: Severity::Suspicious,
                detail: format!("APP{id} segment is {len} bytes (unusually large)"),
            });
        }
        if *id == 15 {
            out.push(Finding {
                detector: "jpeg:rare-app-marker".into(),
                severity: Severity::Suspicious,
                detail: format!("Rare application segment APP15 present ({len} bytes)"),
            });
        }
    }
    for (len, ent) in &walk.com_segments {
        if *ent >= 7.0 && *len > 64 {
            out.push(Finding {
                detector: "jpeg:high-entropy-com".into(),
                severity: Severity::Likely,
                detail: format!(
                    "COM (comment) segment contains high-entropy payload ({len} bytes, entropy {ent:.2} bits/byte)"
                ),
            });
        } else if *len > 16 * 1024 {
            out.push(Finding {
                detector: "jpeg:oversized-com".into(),
                severity: Severity::Suspicious,
                detail: format!("COM segment is {len} bytes (unusually large)"),
            });
        }
    }
    if walk.app_segments.len() > 6 {
        out.push(Finding {
            detector: "jpeg:many-appn".into(),
            severity: Severity::Info,
            detail: format!("{} APPn segments present", walk.app_segments.len()),
        });
    }
    // More than 4 DQT tables is highly unusual (baseline uses 1-2).
    if walk.dqt_count > 4 {
        out.push(Finding {
            detector: "jpeg:many-dqt".into(),
            severity: Severity::Info,
            detail: format!("{} DQT tables (baseline JPEG uses 1-2)", walk.dqt_count),
        });
    }
    if walk.dht_count > 8 {
        out.push(Finding {
            detector: "jpeg:many-dht".into(),
            severity: Severity::Info,
            detail: format!("{} DHT tables present", walk.dht_count),
        });
    }
    if walk.sos_count > 1 {
        out.push(Finding {
            detector: "jpeg:multi-scan".into(),
            severity: Severity::Info,
            detail: format!(
                "{} SOS scans (progressive JPEG; suspicious if unexpected)",
                walk.sos_count
            ),
        });
    }
}

/// Skip entropy-coded data after an SOS header: walk until we hit a 0xFF
/// marker that is not stuffed (0xFF 0x00) nor a restart (0xFF D0..D7).
fn find_next_jpeg_marker(data: &[u8], start: usize) -> usize {
    let mut i = start;
    while i + 1 < data.len() {
        if data[i] == 0xFF {
            let b = data[i + 1];
            if b == 0x00 || (0xD0..=0xD7).contains(&b) || b == 0xFF {
                i += 1;
                continue;
            }
            return i;
        }
        i += 1;
    }
    data.len()
}

/// PE-specific structural check: non-zero section padding.
///
/// A linker zero-fills the alignment padding after every section, so padding
/// that is not zero is the password-independent trace of `pe_slack` — and of
/// any other code-cave embedder. (Appended overlay data is covered separately
/// by the trailing-entropy and `overlay:high-entropy` checks.)
pub(super) fn track_pe_structure(data: &[u8], out: &mut Vec<Finding>, magics: ScanMagics) {
    let Ok(layout) = pe_layout::pe_slack_layout(data) else {
        return;
    };
    let mut nonzero = 0u64;
    let mut longest = 0usize;
    let mut ranges = 0usize;
    for &(start, end) in &layout.slack_ranges {
        let (a, b) = (start as usize, (end as usize).min(data.len()));
        if a >= b {
            continue;
        }
        ranges += 1;
        let mut run = 0usize;
        for &byte in &data[a..b] {
            if byte == 0 {
                run = 0;
            } else {
                nonzero += 1;
                run += 1;
                longest = longest.max(run);
            }
        }
    }
    // A strhide header magic inside padding is hard evidence. A non-zero count
    // alone is not: some linkers leave real bytes after a section's mapped span
    // and packed binaries contain code caves, so ordinary executables trip it.
    // Ciphertext, however, also fills most of the byte alphabet, which
    // repetitive compiler padding does not — require both signals.
    let mut header_offset = None;
    let mut distinct = [false; 256];
    let standard_magic = &STANDARD_HEADER_MAGIC[..];
    let dialect_magic = magics.header.as_ref().map(|m| &m[..]);
    'ranges: for &(start, end) in &layout.slack_ranges {
        let a = start as usize;
        let b = (end as usize).min(data.len());
        if a >= b {
            continue;
        }
        let range = &data[a..b];
        for &byte in range {
            distinct[byte as usize] = true;
        }
        let found = range
            .windows(standard_magic.len())
            .position(|w| w == standard_magic || dialect_magic.is_some_and(|magic| w == magic));
        if let Some(idx) = found {
            header_offset = Some(a + idx);
            break 'ranges;
        }
    }
    let distinct = distinct.iter().filter(|s| **s).count();

    if let Some(offset) = header_offset {
        out.push(Finding {
            detector: "pe:envelope-header".into(),
            severity: Severity::Likely,
            detail: format!(
                "strhide envelope header (magic) at offset {offset} inside PE section padding; \
                 this is a pe_slack payload"
            ),
        });
    } else if nonzero >= pe_slack::MIN_CIPHERTEXT_NONZERO
        && distinct >= pe_slack::MIN_CIPHERTEXT_DISTINCT
    {
        out.push(Finding {
            detector: "pe:nonzero-padding".into(),
            severity: Severity::Suspicious,
            detail: format!(
                "{nonzero} non-zero bytes ({distinct} distinct byte values) in PE section padding \
                 ({ranges} range(s), longest non-zero run {longest} B); consistent with a stealth \
                 envelope written with an unknown password"
            ),
        });
    }
}

/// Structural scan through the shared format adapters.
///
/// Only formats the structure domain actually supports reach here; PNG/JPEG/PE
/// keep their dedicated scanners above. A stealth envelope carries no magic by
/// design, so the adapter's `suspicious_structures` hints are the only
/// structural signal the analyser can offer for it.
pub(super) fn track_container_structures(
    view: &ScanView<'_>,
    format: FileFormat,
    findings: &mut Vec<Finding>,
    detectors: &mut Vec<DetectorMetric>,
) {
    if !view.is_whole() || !format.supports_structure() {
        return;
    }
    let mut cursor = Cursor::new(view.prefix);
    let Some(adapter) = crate::structure::registry::find_adapter(&mut cursor) else {
        return;
    };
    let hints = adapter.suspicious_structures(&mut cursor);
    let detector = format!("{}:structure", format.as_str().to_ascii_lowercase());
    for hint in &hints {
        findings.push(Finding {
            detector: detector.clone(),
            severity: Severity::Suspicious,
            detail: hint.clone(),
        });
    }
    detectors.push(DetectorMetric {
        name: detector,
        domain: "structural".into(),
        status: if hints.is_empty() { "PASS" } else { "ALERT" }.into(),
        metric: format!("{} hint(s)", hints.len()),
        threshold: None,
        detail: if hints.is_empty() {
            "container structure matches its declared boxes".into()
        } else {
            hints.join("; ")
        },
    });
}

/// A trailing overlay is *structure*, not statistics: the container's own end
/// marker says the file should end there. Severity no longer depends on the
/// tail's entropy (an appended text file is still appended data); entropy only
/// sharpens the detail line.
pub(super) fn track_trailing_entropy(
    view: &ScanView,
    format: Option<FileFormat>,
    out: &mut Vec<Finding>,
) {
    if view.file_size < TAIL_WINDOW as u64 {
        return;
    }
    let tail = view.entropy_tail();
    let entropy = shannon_entropy(tail);
    // A legitimate container (PNG/JPEG/MP4) has already ended where its parser
    // stops. High-entropy bytes after that are either compressed payload or
    // ciphertext — i.e. an appended envelope.
    let suspicious_tail = match format {
        // Dedicated scanners report the exact marker and already classify
        // trailing bytes as structure.
        Some(FileFormat::Png | FileFormat::Jpeg) => false,
        // COMPRESSED / CONTAINER FORMATS routinely end with entropy-coded
        // payload, so a high-entropy tail is not evidence of an overlay. The
        // previous sniffer could not even name WEBP/WAV/MKV and flagged every
        // clean one of them here.
        Some(
            FileFormat::Mp4
            | FileFormat::Heif
            | FileFormat::Mkv
            | FileFormat::Webp
            | FileFormat::Wav
            | FileFormat::Zip
            | FileFormat::Pdf,
        ) => false,
        _ => entropy >= 7.5,
    };
    if suspicious_tail {
        out.push(Finding {
            detector: "overlay:high-entropy".into(),
            severity: Severity::Suspicious,
            detail: format!(
                "Trailing {TAIL_WINDOW} bytes have Shannon entropy {entropy:.2} bits/byte \
                 (>=7.5 indicates encrypted or compressed payload overlay)"
            ),
        });
    }
}
