//! Steganalysis: black-box scanning of arbitrary files for hidden content.
//!
//! This is the runtime counterpart to strhide's own write/read pipeline:
//! where [`crate::engine::inspect_carrier`] answers "is there a strhide
//! envelope *I* know about in this file?", `scan_file` answers "is this file
//! suspiciously modified, by *any* tool, and by how much?".
//!
//! Two detection tracks:
//!
//! - **Structural fingerprint** — strhide envelope magic bytes, non-standard
//!   container chunks/segments/boxes, and high-entropy trailing data after the
//!   legitimate container has already ended. This is the track that can actually
//!   catch *strhide itself* (a structure-domain embedder is invisible to pixel
//!   statistics).
//! - **Content-domain statistics** — Chi-square LSB attack, Sample Pair
//!   Analysis (SPA), and Regular/Singular (RS) analysis run on decoded pixel
//!   samples. These catch classic LSB embedders (and, later, strhide's own
//!   optional pixel strategy). Algorithms follow the published papers
//!   (Westfeld & Pfitzmann 1999; Dumitrescu et al. 2003; Fridrich 2001) and
//!   are implemented from scratch; thresholds are heuristic defaults, not
//!   calibrated on a clean corpus yet.
//!
//! All findings carry a `severity` and the report aggregates a 0–100
//! `risk_score` plus a coarse `verdict`. This is a heuristic triage tool, not
//! a forensic instrument: a clean verdict means "nothing suspicious stood
//! out", not "no hidden data exists".

use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;

use serde::Serialize;

use crate::adapters::{pe_codebits, pe_slack};
use crate::envelope::{LEGACY_HEADER_MAGIC, MIN_UBE_PLAIN, STANDARD_HEADER_MAGIC};
use crate::errors::StrHideError;

/// Hard cap on file size we fully load for scanning. Larger files still get
/// magic-byte and structural scanning on a prefix+tail window, but pixel
/// decoding is skipped (it needs the whole compressed image).
const MAX_FULL_SCAN: u64 = 64 * 1024 * 1024; // 64 MiB
/// Tail window for entropy / trailing-data heuristics.
const TAIL_WINDOW: usize = 4096;

/// How strongly a single finding points at embedded data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Observation only (e.g. a standard-but-unusual ancillary chunk).
    Info,
    /// Statistically or structurally suspicious; worth a manual look.
    Suspicious,
    /// Strong indicator (e.g. an exact strhide envelope magic).
    Likely,
}

/// One detector's verdict on the file.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Detector id, e.g. "magic:strhide-header", "png:unknown-chunk", "chi2-lsb".
    pub detector: String,
    pub severity: Severity,
    pub detail: String,
}

/// Aggregated scan result for one file.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub carrier: String,
    /// Detected container format, or `None` for unrecognized files.
    pub format: Option<String>,
    pub file_size: u64,
    pub findings: Vec<Finding>,
    /// 0 (clean) .. 10 (very likely hidden).
    pub risk_score: u32,
    /// One of `clean` / `low` / `suspicious` / `likely-hidden`.
    pub verdict: String,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Scan one file end to end. Never errors out on "nothing found"; only real
/// I/O / unreadable-file problems return `Err`.
pub fn scan_file(path: &Path) -> Result<ScanReport, StrHideError> {
    let metadata = std::fs::metadata(path)?;
    let file_size = metadata.len();
    let carrier = path.display().to_string();

    let mut findings: Vec<Finding> = Vec::new();

    // Read whole file (bounded). For very large files we still pull a prefix and
    // the tail, enough for magic bytes and structural heuristics.
    let data: Vec<u8> = if file_size <= MAX_FULL_SCAN {
        let mut f = File::open(path)?;
        let mut buf = Vec::with_capacity(file_size as usize);
        f.read_to_end(&mut buf)?;
        buf
    } else {
        let mut f = File::open(path)?;
        let mut prefix = vec![0u8; 1 << 20]; // 1 MiB
        let n = f.read(&mut prefix)?;
        prefix.truncate(n);
        let mut tail = Vec::new();
        if f.seek(SeekFrom::End(-(TAIL_WINDOW as i64))).is_ok() {
            f.read_to_end(&mut tail)?;
        }
        let mut combined = prefix;
        combined.extend_from_slice(b"\n..<truncated>..\n");
        combined.extend_from_slice(&tail);
        combined
    };

    let format = sniff_format(&data);

    track_tool_signatures(&data, &mut findings);
    match format.as_deref() {
        Some("PNG") => track_png_structure(&data, &mut findings),
        Some("JPEG") => track_jpeg_structure(&data, &mut findings),
        // PE padding can only be measured on a complete image; for oversized
        // files `data` is a prefix+tail window and the section table alone
        // would not be enough to read the padding.
        Some("PE") if file_size <= MAX_FULL_SCAN => track_pe_structure(&data, &mut findings),
        _ => {}
    }
    track_trailing_entropy(&data, format.as_deref(), &mut findings);

    // Content-domain track (PNG + JPEG, and only when we have the full image).
    if file_size <= MAX_FULL_SCAN {
        let decoded: Option<(Vec<u8>, u32, usize)> = match format.as_deref() {
            Some("PNG") => decode_png_pixels(&data),
            Some("JPEG") => decode_jpeg_pixels(&data),
            _ => None,
        };
        if let Some((px, width, channels)) = decoded
            && !px.is_empty()
        {
            track_content_domain(&px, width, channels, &mut findings);
        }
        // DCT-domain JSteg detection (JPEG only): operates on quantized AC
        // coefficients directly, where JPEG steganography actually lives.
        if format.as_deref() == Some("JPEG")
            && let Some(f) = jsteg_dct_test(&data)
        {
            findings.push(f);
        }
    }

    let risk_score = aggregate_risk(&findings);
    let verdict = match risk_score {
        0..=9 => "clean",
        10..=29 => "low",
        30..=59 => "suspicious",
        _ => "likely-hidden",
    };

    Ok(ScanReport {
        carrier,
        format,
        file_size,
        findings,
        risk_score,
        verdict: verdict.into(),
    })
}

// ---------------------------------------------------------------------------
// Format sniffing (lightweight, independent of the adapter machinery so the
// scanner can also classify files strhide itself would refuse to embed in).
// ---------------------------------------------------------------------------

fn sniff_format(data: &[u8]) -> Option<String> {
    if data.len() >= 8 && &data[..8] == b"\x89PNG\r\n\x1a\n" {
        return Some("PNG".into());
    }
    if data.len() >= 3 && data[..3] == [0xFF, 0xD8, 0xFF] {
        return Some("JPEG".into());
    }
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        return Some("MP4".into());
    }
    if data.len() >= 4 && &data[..4] == b"PK\x03\x04" {
        return Some("ZIP".into());
    }
    if data.len() >= 5 && &data[..5] == b"%PDF-" {
        return Some("PDF".into());
    }
    if data.len() >= 2 && &data[..2] == b"MZ" {
        return Some("PE".into());
    }
    None
}

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
}

const KNOWN_TOOL_SIGNATURES: &[KnownSignature] = &[
    KnownSignature {
        tool: "strhide (standard v2)",
        pattern: &[0xb7, 0x54, 0x2c, 0x82, 0x7e, 0x31, 0x1d, 0x6e],
    },
    KnownSignature {
        tool: "strhide (legacy v0)",
        pattern: b"\x89STRHIDE",
    },
    KnownSignature {
        tool: "strhide (trailer mark)",
        pattern: &[0x78, 0xe6, 0x66, 0xd2],
    },
    KnownSignature {
        tool: "OpenStego",
        pattern: b"OPENSTEGO",
    },
    KnownSignature {
        tool: "Camouflage",
        pattern: b"\x1a\x00\x00\x00CAMOUFLAGE",
    },
];

fn track_tool_signatures(data: &[u8], out: &mut Vec<Finding>) {
    for sig in KNOWN_TOOL_SIGNATURES {
        if !find_all(data, sig.pattern).is_empty() {
            out.push(Finding {
                detector: "signature:known-tool".into(),
                severity: Severity::Likely,
                detail: format!("Matches known steganography tool signature: {}", sig.tool),
            });
        }
    }
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

fn track_png_structure(data: &[u8], out: &mut Vec<Finding>) {
    // Walk chunks: 8-byte PNG signature, then [u32 length][4-byte type][data][u32 crc].
    let mut pos = 8usize;
    let mut unknown: Vec<(String, u32)> = Vec::new();
    let mut private: Vec<(String, u32)> = Vec::new();
    while pos + 8 <= data.len() {
        let len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let ty = &data[pos + 4..pos + 8];
        let ty_str = String::from_utf8_lossy(ty).to_string();
        let total = 12u64.saturating_add(len as u64);
        let next = match (pos as u64).checked_add(total) {
            Some(n) if n <= data.len() as u64 => n as usize,
            _ => break,
        };

        // PNG Specification (RFC 2083 Section 5.4):
        // Bit 5 of the second byte (0x20) indicates private (1) vs public (0) chunk.
        let is_private = (ty[1] & 0x20) != 0;
        let is_standard = PNG_STANDARD_CHUNKS.contains(&ty);

        if is_private {
            private.push((ty_str, len));
        } else if !is_standard && ty != b"IEND" {
            unknown.push((ty_str, len));
        }

        if ty == b"IEND" {
            let trailing = data.len() - next;
            if trailing > 0 {
                let ent = shannon_entropy(&data[next..]);
                let severity = if ent >= 7.0 && trailing >= 32 {
                    Severity::Likely
                } else {
                    Severity::Suspicious
                };
                out.push(Finding {
                    detector: "png:trailing-data".into(),
                    severity,
                    detail: format!(
                        "{trailing} trailing bytes present after IEND (entropy {ent:.2} bits/byte)"
                    ),
                });
            }
            break;
        }
        pos = next;
    }
    for (name, len) in private {
        out.push(Finding {
            detector: "png:private-chunk".into(),
            severity: Severity::Likely,
            detail: format!(
                "Private ancillary chunk '{name}' ({len} bytes) - non-standard metadata injection"
            ),
        });
    }
    for (name, len) in unknown {
        out.push(Finding {
            detector: "png:unknown-chunk".into(),
            severity: Severity::Info,
            detail: format!("Non-standard public chunk '{name}' ({len} bytes)"),
        });
    }
}

fn track_jpeg_structure(data: &[u8], out: &mut Vec<Finding>) {
    // Walk markers: 0xFF 0xM[arker]; markers with payload carry a u16 length.
    let mut pos = 2usize; // skip SOI
    let mut app_segments: Vec<(u8, u32)> = Vec::new();
    let mut com_segments: Vec<(u32, f64)> = Vec::new();
    let mut dqt_count = 0u32;
    let mut dht_count = 0u32;
    let mut sos_count = 0u32;
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
                let trailing = data.len() - pos;
                if trailing > 0 {
                    let ent = shannon_entropy(&data[pos..]);
                    let severity = if ent >= 7.0 && trailing >= 32 {
                        Severity::Likely
                    } else {
                        Severity::Suspicious
                    };
                    out.push(Finding {
                        detector: "jpeg:trailing-data".into(),
                        severity,
                        detail: format!(
                            "{trailing} trailing bytes present after EOI (entropy {ent:.2} bits/byte)"
                        ),
                    });
                }
                break;
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
            app_segments.push((marker & 0x0F, seg_len as u32));
        } else if marker == 0xFE {
            let payload_start = pos + 2;
            let payload_end = (pos + seg_len).min(data.len());
            let ent = if payload_end > payload_start {
                shannon_entropy(&data[payload_start..payload_end])
            } else {
                0.0
            };
            com_segments.push((seg_len as u32, ent));
        }

        // SOS: entropy-coded image data follows until the next non-stuffed
        // marker; skip past it so we can still see trailing markers.
        match marker {
            0xDB => dqt_count += 1,
            0xC4 => dht_count += 1,
            0xDA => {
                sos_count += 1;
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
    // Flag oversized or anomalous APP segments
    for (id, len) in &app_segments {
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
    for (len, ent) in &com_segments {
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
    if app_segments.len() > 6 {
        out.push(Finding {
            detector: "jpeg:many-appn".into(),
            severity: Severity::Info,
            detail: format!("{} APPn segments present", app_segments.len()),
        });
    }
    // More than 4 DQT tables is highly unusual (baseline uses 1-2).
    if dqt_count > 4 {
        out.push(Finding {
            detector: "jpeg:many-dqt".into(),
            severity: Severity::Info,
            detail: format!("{dqt_count} DQT tables (baseline JPEG uses 1-2)"),
        });
    }
    if dht_count > 8 {
        out.push(Finding {
            detector: "jpeg:many-dht".into(),
            severity: Severity::Info,
            detail: format!("{dht_count} DHT tables present"),
        });
    }
    if sos_count > 1 {
        out.push(Finding {
            detector: "jpeg:multi-scan".into(),
            severity: Severity::Info,
            detail: format!("{sos_count} SOS scans (progressive JPEG; suspicious if unexpected)"),
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
fn track_pe_structure(data: &[u8], out: &mut Vec<Finding>) {
    let Ok(layout) = pe_codebits::pe_slack_layout(data) else {
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
        for magic in [&STANDARD_HEADER_MAGIC[..], &LEGACY_HEADER_MAGIC[..]] {
            if let Some(idx) = range.windows(magic.len()).position(|w| w == magic) {
                header_offset = Some(a + idx);
                break 'ranges;
            }
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
    } else if nonzero >= MIN_UBE_PLAIN as u64 && distinct >= pe_slack::MIN_CIPHERTEXT_DISTINCT {
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

/// Shannon entropy of the last `TAIL_WINDOW` bytes, and whether it sits in
/// the "looks like compressed/encrypted payload" band.
fn track_trailing_entropy(data: &[u8], format: Option<&str>, out: &mut Vec<Finding>) {
    if data.len() < TAIL_WINDOW {
        return;
    }
    let tail = &data[data.len() - TAIL_WINDOW..];
    let entropy = shannon_entropy(tail);
    // A legitimate container (PNG/JPEG/MP4) has already ended where its parser
    // stops. High-entropy bytes after that are either compressed payload or
    // ciphertext — i.e. an appended envelope.
    let suspicious_tail = match format {
        Some("PNG") => false,  // covered precisely by png:trailing-data
        Some("JPEG") => false, // covered precisely by jpeg:trailing-data
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

fn shannon_entropy(buf: &[u8]) -> f64 {
    let mut hist = [0u64; 256];
    for &b in buf {
        hist[b as usize] += 1;
    }
    let n = buf.len() as f64;
    let mut ent = 0.0;
    for &c in hist.iter() {
        if c > 0 {
            let p = c as f64 / n;
            ent -= p * p.log2();
        }
    }
    ent
}

// ---------------------------------------------------------------------------
// Track 2: content-domain statistics on decoded pixels (PNG only, 8-bit)
// ---------------------------------------------------------------------------

/// Minimal PNG decoder: de-zlib all IDAT chunks and undo scanline filtering,
/// returning a flat pixel byte buffer. Returns `None` for interlaced images,
/// non-8-bit depths, or anything that fails to parse — content stats are
/// strictly a bonus track, never a reason to fail the scan.
fn decode_png_pixels(data: &[u8]) -> Option<(Vec<u8>, u32, usize)> {
    if data.len() < 8 || &data[..8] != b"\x89PNG\r\n\x1a\n" {
        return None;
    }
    let mut pos = 8usize;
    let mut width: u32 = 0;
    let mut height: u32 = 0;
    let mut bit_depth: u8 = 0;
    let mut color_type: u8 = 0;
    let mut idat: Vec<u8> = Vec::new();
    while pos + 8 <= data.len() {
        let len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let ty = &data[pos + 4..pos + 8];
        let body_start = pos + 8;
        let body_end = body_start.checked_add(len as usize)?;
        if body_end + 4 > data.len() {
            return None;
        }
        let body = &data[body_start..body_end];
        match ty {
            b"IHDR" => {
                if len < 13 {
                    return None;
                }
                width = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                height = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                bit_depth = body[8];
                color_type = body[9];
                if body[12] != 0 {
                    return None; // interlaced — skip
                }
            }
            b"IDAT" => idat.extend_from_slice(body),
            b"IEND" => break,
            _ => {}
        }
        pos = body_end + 4; // skip CRC
    }
    if bit_depth != 8 || width == 0 || height == 0 || idat.is_empty() {
        return None;
    }
    let channels: usize = match color_type {
        0 => 1,
        2 => 3,
        3 => 1,
        4 => 2,
        6 => 4,
        _ => return None,
    };
    let bpp = channels; // 8-bit
    let stride = width as usize * bpp;

    // Inflate.
    let mut z = flate2::read::ZlibDecoder::new(Cursor::new(&idat));
    let mut raw = Vec::new();
    if z.read_to_end(&mut raw).is_err() {
        return None;
    }
    let expected = stride * height as usize + height as usize; // +1 filter byte per row
    if raw.len() < expected {
        return None;
    }

    // Undo filtering row by row.
    let mut out: Vec<u8> = Vec::with_capacity(stride * height as usize);
    let mut prev = vec![0u8; stride];
    let mut rp = 0usize;
    for _ in 0..height {
        let filter = raw[rp];
        rp += 1;
        let line = &raw[rp..rp + stride];
        rp += stride;
        let mut recon = vec![0u8; stride];
        for i in 0..stride {
            let a = if i >= bpp { recon[i - bpp] } else { 0 };
            let b = prev[i];
            let c = if i >= bpp { prev[i - bpp] } else { 0 };
            recon[i] = match filter {
                0 => line[i],
                1 => line[i].wrapping_add(a),
                2 => line[i].wrapping_add(b),
                3 => line[i].wrapping_add(((a as u16 + b as u16) / 2) as u8),
                4 => line[i].wrapping_add(paeth(a, b, c)),
                _ => return None,
            };
        }
        out.extend_from_slice(&recon);
        prev = recon;
    }
    Some((out, width, channels))
}

#[inline]
fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let (a, b, c) = (a as i32, b as i32, c as i32);
    let p = a + b - c;
    let pa = (p - a).abs();
    let pb = (p - b).abs();
    let pc = (p - c).abs();
    if pa <= pb && pa <= pc {
        a as u8
    } else if pb <= pc {
        b as u8
    } else {
        c as u8
    }
}

/// Decode a JPEG to a flat RGB pixel buffer via `jpeg-decoder`.
fn decode_jpeg_pixels(data: &[u8]) -> Option<(Vec<u8>, u32, usize)> {
    use jpeg_decoder::Decoder;
    let mut decoder = Decoder::new(std::io::Cursor::new(data));
    let pixels = decoder.decode().ok()?;
    let width = decoder.info()?.width as u32;
    if pixels.is_empty() {
        None
    } else {
        Some((pixels, width, 3))
    }
}

/// JSteg-style steganalysis on quantized DCT coefficients.
///
/// JSteg flips the LSB of AC coefficients whose |v| >= 2.
/// We apply the chi-square pair-uniformity test across non-overlapping
/// PoVs (2v, 2v+1) on the coefficient histogram.
fn jsteg_dct_test(data: &[u8]) -> Option<Finding> {
    use dct_io::read_coefficients;
    let coeffs = read_coefficients(data).ok()?;

    // Histogram over signed AC coefficient values (range -1024..1024 for 8-bit).
    const RANGE: usize = 2049;
    const OFFSET: i32 = 1024;
    let mut hist = vec![0u64; RANGE];
    let mut eligible = 0u64;
    for comp in &coeffs.components {
        for block in &comp.blocks {
            for (k, &v) in block.iter().enumerate() {
                if k == 0 {
                    continue; // skip DC
                }
                let av = v.abs();
                if av >= 2 {
                    let idx = v as i32 + OFFSET;
                    if idx >= 0 && (idx as usize) < RANGE {
                        hist[idx as usize] += 1;
                        eligible += 1;
                    }
                }
            }
        }
    }
    if eligible < 100 {
        return None; // too few coefficients to make a call
    }

    // Chi-square on non-overlapping paired bins (2k, 2k+1) across the central range.
    let mut chi2 = 0.0;
    let mut df = 0.0;
    for v in (2i32..=64).step_by(2) {
        let i0 = (v + OFFSET) as usize;
        let i1 = (v + 1 + OFFSET) as usize;
        let expected = (hist[i0] + hist[i1]) as f64 / 2.0;
        if expected > 0.0 {
            chi2 += (hist[i0] as f64 - expected).powi(2) / expected;
            df += 1.0;
        }
        // negative side: (-v-1, -v) e.g. (-3, -2), (-5, -4)
        let n0 = (-v - 1 + OFFSET) as usize;
        let n1 = (-v + OFFSET) as usize;
        let expected = (hist[n0] + hist[n1]) as f64 / 2.0;
        if expected > 0.0 {
            chi2 += (hist[n0] as f64 - expected).powi(2) / expected;
            df += 1.0;
        }
    }
    if df == 0.0 {
        return None;
    }
    let suspicion = ((df - chi2) / df).clamp(0.0, 1.0);
    if suspicion < 0.5 {
        return None;
    }
    Some(Finding {
        detector: "dct:jsteg-chi2".into(),
        severity: Severity::Suspicious,
        detail: format!(
            "DCT coefficient chi-square: {eligible} eligible AC coefficients, \
             pair-histogram uniformity suspicion {suspicion:.2} \
             (consistent with JSteg/F5-style LSB embedding on DCT coefficients)"
        ),
    })
}

// ---------------------------------------------------------------------------
// Content detectors
// ---------------------------------------------------------------------------

fn track_content_domain(pixels: &[u8], width: u32, channels: usize, out: &mut Vec<Finding>) {
    // Cap sample size: stats are O(n), and huge images just add tail.
    let sample: &[u8] = if pixels.len() > 4_000_000 {
        &pixels[..4_000_000]
    } else {
        pixels
    };

    let chi2_score = chi2_lsb_suspicion(sample);
    if chi2_score > 0.5 {
        out.push(Finding {
            detector: "chi2-lsb".into(),
            severity: Severity::Suspicious,
            detail: format!(
                "Chi-square LSB attack: pair histogram looks uniform (suspicion {chi2_score:.2}) \
                 - consistent with LSB embedding"
            ),
        });
    }

    if let Some(p) = rs_analysis(sample, width, channels)
        && p > 0.05
    {
        out.push(Finding {
            detector: "rs-analysis".into(),
            severity: Severity::Suspicious,
            detail: format!("RS analysis estimates LSB embedding rate ~{p:.2}"),
        });
    }

    let spa_p = spa_estimate_dww(sample, width, channels);
    if spa_p > 0.05 {
        out.push(Finding {
            detector: "spa".into(),
            severity: Severity::Suspicious,
            detail: format!("Sample Pair Analysis (DWW) estimates embedding rate ~{spa_p:.2}"),
        });
    }
}

/// Westfeld & Pfitzmann 1999, Chi-square attack on LSB embedding.
///
/// Under LSB embedding, value pairs (2i, 2i+1) migrate toward equal counts.
/// We return how far the observed chi-square statistic is below the
/// expectation df (≈127 for 8-bit pixels), normalised to 0..1.
fn chi2_lsb_suspicion(data: &[u8]) -> f64 {
    let mut hist = [0u64; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    let mut chi2 = 0.0;
    let mut df = 0.0;
    for i in (0..256).step_by(2) {
        let expected = (hist[i] + hist[i + 1]) as f64 / 2.0;
        if expected > 0.0 {
            chi2 += (hist[i] as f64 - expected).powi(2) / expected;
            df += 1.0;
        }
    }
    if df == 0.0 {
        return 0.0;
    }
    // Clean images: chi2 ≈ df. Fully embedded: chi2 → 0.
    ((df - chi2) / df).clamp(0.0, 1.0)
}

#[derive(Clone, Copy)]
enum RsMask {
    Plus,
    Minus,
}

fn rs_window_smoothness(w: &[i32; 9]) -> i64 {
    let mut s = 0i64;
    for r in 0..2 {
        for c in 0..3 {
            s += (w[r * 3 + c] - w[(r + 1) * 3 + c]).unsigned_abs() as i64;
        }
    }
    for r in 0..3 {
        for c in 0..2 {
            s += (w[r * 3 + c] - w[r * 3 + c + 1]).unsigned_abs() as i64;
        }
    }
    s
}

fn rs_difference(plane: &[i32], rows: usize, cols: usize, mask: RsMask) -> f64 {
    if rows < 4 || cols < 4 {
        return 0.0;
    }
    let (mut r_count, mut s_count, mut n) = (0i64, 0i64, 0i64);
    for i in 0..rows - 3 {
        for j in 0..cols - 3 {
            let mut w = [0i32; 9];
            for dr in 0..3 {
                for dc in 0..3 {
                    w[dr * 3 + dc] = plane[(i + dr) * cols + (j + dc)];
                }
            }
            let orig = rs_window_smoothness(&w);
            let mut f = w;
            f[4] = match mask {
                RsMask::Plus => w[4] ^ 1,
                RsMask::Minus => w[4] + 1,
            };
            n += 1;
            match rs_window_smoothness(&f).cmp(&orig) {
                std::cmp::Ordering::Greater => r_count += 1,
                std::cmp::Ordering::Less => s_count += 1,
                std::cmp::Ordering::Equal => {}
            }
        }
    }
    if n == 0 {
        return 0.0;
    }
    (r_count - s_count) as f64 / n as f64
}

fn aletheia_rs(plane: &[i32], rows: usize, cols: usize) -> f64 {
    let inverted: Vec<i32> = plane.iter().map(|&v| v ^ 1).collect();
    let d0 = rs_difference(plane, rows, cols, RsMask::Plus);
    let d1 = rs_difference(&inverted, rows, cols, RsMask::Plus);
    let n_d0 = rs_difference(plane, rows, cols, RsMask::Minus);
    let n_d1 = rs_difference(&inverted, rows, cols, RsMask::Minus);

    let a = 2.0 * (d1 + d0);
    let b = n_d0 - n_d1 - d1 - 3.0 * d0;
    let c = d0 - n_d0;
    if a.abs() < 1e-12 {
        return 0.0;
    }
    let disc = b * b - 4.0 * a * c;
    if disc < 0.0 {
        return 0.0;
    }
    let sq = disc.sqrt();
    let p0 = (-b + sq) / (2.0 * a);
    let p1 = (-b - sq) / (2.0 * a);
    let z = if p0.abs() < p1.abs() { p0 } else { p1 };
    if (z - 0.5).abs() < 1e-12 {
        return 0.0;
    }
    (z / (z - 0.5)).clamp(0.0, 1.0)
}

fn rs_analysis(pixels: &[u8], width: u32, channels: usize) -> Option<f64> {
    let width = width as usize;
    let stride = width.checked_mul(channels)?;
    if stride == 0 || pixels.len() < stride * 4 || width < 4 {
        return None;
    }
    let rows = (pixels.len() / stride).min(512);
    let eval_channels = channels.min(3);
    let mut best = 0.0f64;
    for ch in 0..eval_channels {
        let mut plane = Vec::with_capacity(rows * width);
        for row in 0..rows {
            let base = row * stride + ch;
            for col in 0..width {
                plane.push(pixels[base + col * channels] as i32);
            }
        }
        let score = aletheia_rs(&plane, rows, width);
        if score > best {
            best = score;
        }
    }
    if best > 0.0 { Some(best) } else { None }
}

/// Sample Pair Analysis (Dumitrescu, Wu & Wang 2003), faithful to the
/// Aletheia `spa_image` reference. Walks vertically adjacent pixel pairs,
/// accumulates the DWW trace-set counters (x, y, k), and solves the
/// quadratic for the LSB-replacement embedding rate alpha.
fn spa_estimate_dww(pixels: &[u8], width: u32, channels: usize) -> f64 {
    let width = width as usize;
    let stride = width.checked_mul(channels).unwrap_or(0);
    if width == 0 || stride == 0 || pixels.len() < stride * 2 {
        return 0.0;
    }
    let rows = (pixels.len() / stride).min(512);
    if rows < 2 {
        return 0.0;
    }

    let eval_channels = channels.min(3);
    let mut best = 0.0_f64;
    for ch in 0..eval_channels {
        let (x, y, k, pair_count) = {
            let mut x: i64 = 0;
            let mut y: i64 = 0;
            let mut k: i64 = 0;
            let mut pair_count: i64 = 0;
            for row in 0..rows - 1 {
                let top = row * stride;
                let bot = top + stride;
                for col in 0..width {
                    let off = col * channels + ch;
                    let r = pixels[top + off] as i32;
                    let s = pixels[bot + off] as i32;
                    pair_count += 1;
                    let s_even = (s & 1) == 0;
                    let r_lt = r < s;
                    let r_gt = r > s;
                    if (s_even && r_lt) || (!s_even && r_gt) {
                        x += 1;
                    }
                    if (s_even && r_gt) || (!s_even && r_lt) {
                        y += 1;
                    }
                    if (r & 0xFE) == (s & 0xFE) {
                        k += 1;
                    }
                }
            }
            (x, y, k, pair_count)
        };
        if k == 0 {
            continue;
        }
        // DWW quadratic: a*beta^2 + b*beta + c = 0, alpha = 2*beta.
        let a = (2 * k) as f64;
        let b = (2 * (2 * x - pair_count)) as f64;
        let c = (y - x) as f64;
        let disc = b * b - 4.0 * a * c;
        let beta = if disc < 0.0 {
            -b / (2.0 * a)
        } else {
            (-b - disc.sqrt()) / (2.0 * a)
        };
        let alpha = 2.0 * beta;
        if alpha > best {
            best = alpha;
        }
    }
    best.clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

fn aggregate_risk(findings: &[Finding]) -> u32 {
    let mut score: u32 = 0;
    for f in findings {
        let w = match f.severity {
            Severity::Info => 2,
            Severity::Suspicious => 25,
            Severity::Likely => 60,
        };
        score = score.saturating_add(w);
    }
    score.min(100)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_png(
        width: u32,
        height: u32,
        color_type: u8,
        pixel_fn: impl Fn(usize, usize) -> Vec<u8>,
    ) -> Vec<u8> {
        // Build a minimal valid PNG: IHDR + one filtered IDAT + IEND.
        let _channels = match color_type {
            0 => 1,
            2 => 3,
            4 => 2,
            6 => 4,
            _ => 3,
        };
        let mut raw: Vec<u8> = Vec::new();
        for y in 0..height as usize {
            raw.push(0); // filter: None
            for x in 0..width as usize {
                raw.extend_from_slice(&pixel_fn(x, y));
            }
        }
        let compressed = {
            use std::io::Write;
            let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            z.write_all(&raw).unwrap();
            z.finish().unwrap()
        };
        let mut out = Vec::new();
        out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        let mut chunk = |ty: &[u8], body: &[u8]| {
            out.extend_from_slice(&(body.len() as u32).to_be_bytes());
            out.extend_from_slice(ty);
            out.extend_from_slice(body);
            let mut crc = crc32fast::Hasher::new();
            crc.update(ty);
            crc.update(body);
            out.extend_from_slice(&crc.finalize().to_be_bytes());
        };
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.push(8); // bit depth
        ihdr.push(color_type);
        ihdr.extend_from_slice(&[0, 0, 0]);
        chunk(b"IHDR", &ihdr);
        chunk(b"IDAT", &compressed);
        chunk(b"IEND", &[]);
        out
    }

    #[test]
    fn entropy_of_random_is_high() {
        let buf: Vec<u8> = (0..4096u64)
            .map(|i| i.wrapping_mul(1103515245).wrapping_add(12345) as u8)
            .collect();
        assert!(shannon_entropy(&buf) > 7.0);
    }

    #[test]
    fn chi2_clean_image_low_suspicion() {
        // Values concentrated on even bins (like a clean low-noise image's
        // histogram where adjacent values cluster): pair histograms are NOT
        // uniform, so chi2 is large and suspicion stays low.
        let px: Vec<u8> = (0..40000).map(|i| (i as u8) & 0xFE).collect();
        let s = chi2_lsb_suspicion(&px);
        assert!(s < 0.5, "suspicion={s}");
    }

    #[test]
    fn chi2_uniform_histogram_looks_embedded() {
        // A flat/random byte stream has perfectly uniform pair histograms —
        // exactly the signature the chi-square attack flags as embedded.
        let px: Vec<u8> = (0..40000u64)
            .map(|i| i.wrapping_mul(2654435761) as u8)
            .collect();
        let s = chi2_lsb_suspicion(&px);
        assert!(s > 0.8, "suspicion={s}");
    }

    #[test]
    fn tool_signature_detected() {
        let mut blob = vec![0u8; 100];
        blob[40..48].copy_from_slice(&[0xb7, 0x54, 0x2c, 0x82, 0x7e, 0x31, 0x1d, 0x6e]);
        let mut f = Vec::new();
        track_tool_signatures(&blob, &mut f);
        assert!(f.iter().any(|x| x.detector == "signature:known-tool"));
    }

    #[test]
    fn png_private_chunk_detected() {
        // Hand-build a PNG with a prIv chunk injected.
        let mut png = fake_png(4, 4, 2, |x, _| vec![(x * 60) as u8, 128, 200]);
        // Insert a prIv chunk before IEND.
        let iend_pos = png.windows(4).rposition(|w| w == b"IEND").unwrap() - 4;
        let mut injection = Vec::new();
        injection.extend_from_slice(&8u32.to_be_bytes());
        injection.extend_from_slice(b"prIv");
        injection.extend_from_slice(b"hiddend!");
        let mut crc = crc32fast::Hasher::new();
        crc.update(b"prIv");
        crc.update(b"hiddend!");
        injection.extend_from_slice(&crc.finalize().to_be_bytes());
        png.splice(iend_pos..iend_pos, injection);

        let mut findings = Vec::new();
        track_png_structure(&png, &mut findings);
        assert!(
            findings.iter().any(|f| f.detector == "png:private-chunk"),
            "findings: {findings:?}"
        );
    }

    #[test]
    fn png_pixel_decode_roundtrip() {
        let png = fake_png(4, 4, 2, |x, y| vec![(x * 50 + y * 10) as u8, 128, 200]);
        let (px, width, channels) = decode_png_pixels(&png).expect("decode");
        assert_eq!(width, 4);
        assert_eq!(channels, 3);
        assert_eq!(px.len(), 4 * 4 * 3);
    }

    #[test]
    fn clean_gradient_scores_low() {
        // Full scan on a clean gradient PNG should stay in the low band.
        let tmp = std::env::temp_dir().join("strhide_scan_test_clean.png");
        let png = fake_png(8, 8, 2, |x, y| vec![(x * 20 + y * 5) as u8, 100, 150]);
        std::fs::write(&tmp, &png).unwrap();
        let rep = scan_file(&tmp).unwrap();
        assert!(rep.risk_score < 30, "report: {rep:?}");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn tool_signature_lifts_score() {
        let tmp = std::env::temp_dir().join("strhide_scan_test_magic.bin");
        let mut blob = vec![0u8; 200];
        blob[100..108].copy_from_slice(&[0xb7, 0x54, 0x2c, 0x82, 0x7e, 0x31, 0x1d, 0x6e]);
        std::fs::write(&tmp, &blob).unwrap();
        let rep = scan_file(&tmp).unwrap();
        assert!(rep.risk_score >= 45, "report: {rep:?}");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn jpeg_decode_rejects_non_jpeg() {
        // Garbage bytes must not panic; decode returns None.
        let garbage: Vec<u8> = (0..512u64)
            .map(|i| i.wrapping_mul(2654435761) as u8)
            .collect();
        assert!(decode_jpeg_pixels(&garbage).is_none());
    }

    #[test]
    fn jpeg_eoi_tail_detected() {
        // Synthesize a minimal JPEG structure: SOI, DQT, EOI, then extra bytes.
        let mut data = Vec::new();
        data.extend_from_slice(&[0xFF, 0xD8]); // SOI
        // DQT: FF DB, length=4 (payload=2: table spec + 1 quant value).
        data.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x04, 0x00, 0x10]);
        data.extend_from_slice(&[0xFF, 0xD9]); // EOI
        data.extend_from_slice(b"extra-tail-data"); // appended after EOI
        let mut findings = Vec::new();
        track_jpeg_structure(&data, &mut findings);
        assert!(
            findings.iter().any(|f| f.detector == "jpeg:trailing-data"),
            "findings: {findings:?}"
        );
    }

    #[test]
    fn jpeg_many_dqt_flagged() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xFF, 0xD8]);
        for _ in 0..6 {
            data.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x04, 0x00, 0x10]);
        }
        data.extend_from_slice(&[0xFF, 0xD9]);
        let mut findings = Vec::new();
        track_jpeg_structure(&data, &mut findings);
        assert!(
            findings.iter().any(|f| f.detector == "jpeg:many-dqt"),
            "findings: {findings:?}"
        );
    }

    #[test]
    fn rs_smooth_plane_estimates_near_zero() {
        // Flat smooth gradient: RS estimate must stay 0.0 or low
        let mut plane = vec![128u8; 16 * 16 * 3];
        for y in 0..16 {
            for x in 0..16 {
                let idx = (y * 16 + x) * 3;
                plane[idx] = (x * 4) as u8;
                plane[idx + 1] = (y * 4) as u8;
                plane[idx + 2] = 100;
            }
        }
        let est = rs_analysis(&plane, 16, 3);
        assert!(est.is_none() || est.unwrap() < 0.1);
    }
}
