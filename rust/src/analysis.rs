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

pub mod calibration;

use crate::adapters::{pe_codebits, pe_slack};
use crate::envelope::{MIN_UBE_PLAIN, STANDARD_HEADER_MAGIC};
use crate::errors::StrHideError;

/// Hard cap on file size we fully load for scanning. Larger files still get
/// magic-byte and structural scanning on a prefix+tail window, but pixel
/// decoding is skipped (it needs the whole compressed image).
const MAX_FULL_SCAN: u64 = 64 * 1024 * 1024; // 64 MiB
/// Prefix read from a carrier too large to load whole: its container header
/// (and, for small containers, the whole chunk/segment table) lives here.
const PREFIX_WINDOW: usize = 1 << 20; // 1 MiB
/// Tail window for entropy / trailing-data heuristics.
const TAIL_WINDOW: usize = 4096;
/// Tail window used to find a container end marker (PNG `IEND`, JPEG `EOI`)
/// in a file too large to read whole.
///
/// Deliberately much larger than [`TAIL_WINDOW`]: an appended payload of a few
/// KiB would otherwise push the marker that proves the container ended out of
/// view, and the trailing-data detectors would go blind for exactly the files
/// they matter most for.
const STRUCT_TAIL_WINDOW: usize = 64 * 1024;

/// PNG `IEND` in full: `length = 0`, type, CRC `AE 42 60 82`.
const PNG_IEND_FULL: [u8; 12] = *b"\x00\x00\x00\x00IEND\xaeB`\x82";
/// JPEG end-of-image marker.
const JPEG_EOI: [u8; 2] = [0xFF, 0xD9];

/// Calibrated DCT estimate at which a JPEG is reported as suspicious.
///
/// Recalibrated for the ternary (V3) embedding model on the 80-carrier corpus
/// (2026-10-21): the statistic now also looks at the `(0, 1)` pair, which is
/// where `0 <-> ±1` moves land. Measured on that corpus:
///
/// | population | median | max |
/// | :--- | ---: | ---: |
/// | clean | 0.000 | 0.011 |
/// | recommended load (bpp <= 0.10) | 0.000 | 0.007 |
/// | full capacity | 0.141 | 0.741 |
///
/// `0.05` is 4.5x above the highest clean value and detects 85% of
/// full-capacity carriers; the recommended load stays undetected by design.
/// This is a heuristic with a measured false-negative rate, not a proof
/// procedure -- see `docs/stego_keyed_parameters_plan_20261020.md` §13.
const CALIBRATION_FLAG_RATE: f64 = 0.05;
/// Estimate above which the finding is raised to `Likely`.
const CALIBRATION_STRONG_RATE: f64 = 0.15;

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

/// Quantitative measurement and status for one individual detector.
#[derive(Debug, Clone, Serialize)]
pub struct DetectorMetric {
    /// Detector id (e.g. "dct:calibration", "dct:chi2", "spatial:ws", "spatial:rs", "jpeg:structure")
    pub name: String,
    /// Target domain category: "spatial", "dct", "structural", "signature"
    pub domain: String,
    /// Outcome status: "PASS", "ALERT"
    pub status: String,
    /// Primary quantitative metric (e.g. "rate: 0.000", "0 bytes", "suspicion: 0.000")
    pub metric: String,
    /// Detection threshold
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<String>,
    /// Technical summary message
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
    /// Scanner-level caveats about what the verdict does NOT prove. Emitted for
    /// formats where the available detectors have a known blind spot, so a
    /// `clean` result is not read as evidence of absence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Quantitative detector metrics evaluated for this carrier.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detectors: Vec<DetectorMetric>,
}

// ---------------------------------------------------------------------------
// Scan view: what a detector is allowed to look at
// ---------------------------------------------------------------------------

/// The bytes available to the structural detectors, and where they sit.
///
/// Small carriers are scanned whole. Larger ones only yield a prefix and a
/// tail, and the two must stay **separate**: the previous implementation
/// spliced them into one buffer with a fake `"\n..<truncated>..\n"` marker.
/// Every walker then decoded the marker as chunk/segment bytes, tripped its own
/// bounds check and stopped — before ever reaching the real tail. The only
/// detectors that can see an appended payload (`png:trailing-data`,
/// `jpeg:trailing-data`) could therefore never fire on a carrier above
/// [`MAX_FULL_SCAN`], leaving just the known-signature scan.
struct ScanView<'a> {
    /// Bytes starting at file offset 0.
    prefix: &'a [u8],
    /// `Some((file offset, bytes))` when the file was too large to read whole.
    tail: Option<(u64, &'a [u8])>,
    file_size: u64,
}

impl<'a> ScanView<'a> {
    fn whole(data: &'a [u8]) -> Self {
        Self {
            prefix: data,
            tail: None,
            file_size: data.len() as u64,
        }
    }

    fn windowed(prefix: &'a [u8], tail_offset: u64, tail: &'a [u8], file_size: u64) -> Self {
        Self {
            prefix,
            tail: Some((tail_offset, tail)),
            file_size,
        }
    }

    fn is_whole(&self) -> bool {
        self.tail.is_none()
    }

    /// Number of bytes between `offset` and EOF.
    fn bytes_after(&self, offset: u64) -> u64 {
        self.file_size.saturating_sub(offset)
    }

    /// Entropy of the data that follows `offset`.
    ///
    /// Measured on at most [`TAIL_WINDOW`] bytes: an overlay is homogeneous
    /// enough that a longer sample only costs time.
    fn trailing_entropy(&self, offset: u64) -> f64 {
        match self.tail {
            // Windowed: the last `TAIL_WINDOW` bytes of the file. Whenever the
            // overlay is at least that long this is exactly overlay bytes.
            Some(_) => shannon_entropy(self.entropy_tail()),
            None => {
                let region = self.prefix.get(offset as usize..).unwrap_or(&[]);
                let region = if region.len() > TAIL_WINDOW {
                    &region[region.len() - TAIL_WINDOW..]
                } else {
                    region
                };
                shannon_entropy(region)
            }
        }
    }

    /// The last [`TAIL_WINDOW`] bytes of the file.
    fn entropy_tail(&self) -> &'a [u8] {
        let buf = match self.tail {
            Some((_, t)) => t,
            None => self.prefix,
        };
        &buf[buf.len().saturating_sub(TAIL_WINDOW)..]
    }
}

/// Emit the "bytes after the container end marker" finding, if any.
fn report_trailing(
    view: &ScanView,
    end_offset: u64,
    detector: &str,
    marker: &str,
    out: &mut Vec<Finding>,
) {
    let trailing = view.bytes_after(end_offset);
    if trailing == 0 {
        return;
    }
    let ent = view.trailing_entropy(end_offset);
    let severity = if ent >= 7.0 && trailing >= 32 {
        Severity::Likely
    } else {
        Severity::Suspicious
    };
    out.push(Finding {
        detector: detector.into(),
        severity,
        detail: format!(
            "{trailing} trailing bytes present after {marker} (entropy {ent:.2} bits/byte)"
        ),
    });
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
    let mut detectors: Vec<DetectorMetric> = Vec::new();

    // Read whole file (bounded). Above the cap we keep the first
    // `PREFIX_WINDOW` and the last `STRUCT_TAIL_WINDOW` bytes *separately*.
    let (prefix, tail): (Vec<u8>, Option<(u64, Vec<u8>)>) = if file_size <= MAX_FULL_SCAN {
        let mut f = File::open(path)?;
        let mut buf = Vec::with_capacity(file_size as usize);
        f.read_to_end(&mut buf)?;
        (buf, None)
    } else {
        let mut f = File::open(path)?;
        let mut head = vec![0u8; PREFIX_WINDOW];
        let n = f.read(&mut head)?;
        head.truncate(n);
        // `file_size > MAX_FULL_SCAN` guarantees the seek target is >= 0.
        let tail_offset = file_size.saturating_sub(STRUCT_TAIL_WINDOW as u64);
        f.seek(SeekFrom::Start(tail_offset))?;
        let mut tail = Vec::with_capacity(STRUCT_TAIL_WINDOW);
        f.read_to_end(&mut tail)?;
        (head, Some((tail_offset, tail)))
    };

    let view = match &tail {
        Some((off, t)) => ScanView::windowed(&prefix, *off, t, file_size),
        None => ScanView::whole(&prefix),
    };

    let format = sniff_format(view.prefix);

    // 1. Signature domain: known tools / envelopes
    let sig_before = findings.len();
    track_tool_signatures(&view, &mut findings);
    let sig_alert = findings[sig_before..]
        .iter()
        .any(|f| f.detector == "signature:known-tool");
    detectors.push(DetectorMetric {
        name: "signature:known-tool".into(),
        domain: "signature".into(),
        status: if sig_alert {
            "ALERT".into()
        } else {
            "PASS".into()
        },
        metric: if sig_alert {
            "matched".into()
        } else {
            "clean".into()
        },
        threshold: None,
        detail: if sig_alert {
            "matches known tool signature".into()
        } else {
            "no known steganography tool signatures".into()
        },
    });

    // 2. Container structure domain
    match format.as_deref() {
        Some("PNG") => {
            let before_cnt = findings.len();
            track_png_structure(&view, &mut findings);
            let has_trailing = findings[before_cnt..]
                .iter()
                .any(|f| f.detector == "png:trailing-data");
            let has_struct_err = findings[before_cnt..]
                .iter()
                .any(|f| f.detector.starts_with("png:") && f.detector != "png:trailing-data");

            detectors.push(DetectorMetric {
                name: "png:structure".into(),
                domain: "structural".into(),
                status: if has_struct_err {
                    "ALERT".into()
                } else {
                    "PASS".into()
                },
                metric: if has_struct_err {
                    "abnormal chunks".into()
                } else {
                    "normal".into()
                },
                threshold: None,
                detail: if has_struct_err {
                    "anomalous or private chunks detected".into()
                } else {
                    "standard PNG chunk layout".into()
                },
            });
            detectors.push(DetectorMetric {
                name: "png:trailing-data".into(),
                domain: "structural".into(),
                status: if has_trailing {
                    "ALERT".into()
                } else {
                    "PASS".into()
                },
                metric: if has_trailing {
                    "trailing bytes present".into()
                } else {
                    "0 bytes".into()
                },
                threshold: Some("0 bytes".into()),
                detail: if has_trailing {
                    "overlay data after IEND chunk".into()
                } else {
                    "clean termination at IEND".into()
                },
            });
        }
        Some("JPEG") => {
            let before_cnt = findings.len();
            track_jpeg_structure(&view, &mut findings);
            let has_trailing = findings[before_cnt..]
                .iter()
                .any(|f| f.detector == "jpeg:trailing-data");
            let has_struct_err = findings[before_cnt..]
                .iter()
                .any(|f| f.detector.starts_with("jpeg:") && f.detector != "jpeg:trailing-data");

            detectors.push(DetectorMetric {
                name: "jpeg:structure".into(),
                domain: "structural".into(),
                status: if has_struct_err {
                    "ALERT".into()
                } else {
                    "PASS".into()
                },
                metric: if has_struct_err {
                    "abnormal markers".into()
                } else {
                    "normal".into()
                },
                threshold: None,
                detail: if has_struct_err {
                    "anomalous marker segment counts or high-entropy comment".into()
                } else {
                    "markers within standard bounds".into()
                },
            });
            detectors.push(DetectorMetric {
                name: "jpeg:trailing-data".into(),
                domain: "structural".into(),
                status: if has_trailing {
                    "ALERT".into()
                } else {
                    "PASS".into()
                },
                metric: if has_trailing {
                    "trailing bytes present".into()
                } else {
                    "0 bytes".into()
                },
                threshold: Some("0 bytes".into()),
                detail: if has_trailing {
                    "overlay data after EOI marker".into()
                } else {
                    "clean termination at EOI".into()
                },
            });
        }
        Some("PE") if view.is_whole() => track_pe_structure(view.prefix, &mut findings),
        _ => {}
    }
    track_trailing_entropy(&view, format.as_deref(), &mut findings);

    // Set when the calibrated DCT test fired; used to decide whether the
    // "clean is not proof" caveat still applies to this report.
    let mut calibrated_signal = false;

    // 3. Statistical domain: strictly separate spatial domain (PNG) and frequency domain (JPEG)
    if view.is_whole() {
        let data = view.prefix;
        match format.as_deref() {
            Some("PNG") => {
                if let Some((px, width, channels)) = decode_png_pixels(data)
                    && !px.is_empty()
                {
                    track_spatial_domain(&px, width, channels, &mut findings, &mut detectors);
                }
            }
            Some("JPEG") => {
                track_jpeg_dct_domain(data, &mut findings, &mut detectors, &mut calibrated_signal);
            }
            _ => {}
        }
    }

    let risk_score = aggregate_risk(&findings);
    let verdict = match risk_score {
        0..=9 => "clean",
        10..=29 => "low",
        30..=59 => "suspicious",
        _ => "likely-hidden",
    };

    let mut notes = Vec::new();
    if format.as_deref() == Some("JPEG") && matches!(verdict, "clean" | "low") && !calibrated_signal
    {
        notes.push(
            "JPEG statistical detectors are weak against low-rate DCT embedding: a clean/low verdict is NOT evidence that nothing is hidden".to_string(),
        );
    }
    if !view.is_whole() {
        notes.push(format!(
            "Carrier is larger than {} MiB: only the first {} KiB and the last {} KiB were inspected, and pixel/DCT statistics were skipped",
            MAX_FULL_SCAN / (1024 * 1024),
            PREFIX_WINDOW / 1024,
            STRUCT_TAIL_WINDOW / 1024
        ));
    }

    Ok(ScanReport {
        carrier,
        format,
        file_size,
        findings,
        risk_score,
        verdict: verdict.into(),
        notes,
        detectors,
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

fn track_tool_signatures(view: &ScanView, out: &mut Vec<Finding>) {
    for sig in KNOWN_TOOL_SIGNATURES {
        // An appended envelope lives in the tail of an oversized carrier, so
        // both windows have to be searched.
        let in_prefix = !find_all(view.prefix, sig.pattern).is_empty();
        let in_tail = view
            .tail
            .is_some_and(|(_, t)| !find_all(t, sig.pattern).is_empty());
        if in_prefix || in_tail {
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
        let is_private = (ty[1] & 0x20) != 0;
        let is_standard = PNG_STANDARD_CHUNKS.contains(&ty);

        // Cap the collected list: a crafted file can repeat one chunk type
        // (or use thousands of distinct types) at no cost, and every entry
        // becomes a finding. 64 is well past what a real image carries.
        if is_private {
            if walk.private.len() < MAX_CHUNK_FINDINGS {
                walk.private.push((ty_str, len));
            }
        } else if !is_standard && ty != b"IEND" && walk.unknown.len() < MAX_CHUNK_FINDINGS {
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

fn track_png_structure(view: &ScanView, out: &mut Vec<Finding>) {
    let walk = walk_png_chunks(view.prefix);
    match walk.iend_end {
        // The whole chunk stream was inside the bytes we have.
        Some(end) => report_trailing(view, end, "png:trailing-data", "IEND", out),
        None => {
            let Some((tail_offset, tail)) = view.tail else {
                // Whole file without a terminating IEND: a truncated PNG. Not
                // evidence of hidden data, so say nothing (as before).
                walk.emit(out);
                return;
            };
            match tail
                .windows(PNG_IEND_FULL.len())
                .rposition(|w| w == PNG_IEND_FULL)
            {
                Some(idx) => {
                    let end = tail_offset + idx as u64 + PNG_IEND_FULL.len() as u64;
                    report_trailing(view, end, "png:trailing-data", "IEND", out);
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
                }
            }
        }
    }
    walk.emit(out);
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

fn track_jpeg_structure(view: &ScanView, out: &mut Vec<Finding>) {
    let walk = walk_jpeg_markers(view.prefix);
    match walk.eoi_end {
        Some(end) => report_trailing(view, end, "jpeg:trailing-data", "EOI", out),
        None => {
            if !view.is_whole() {
                report_jpeg_tail(view, out);
            }
            // A whole file without EOI is a truncated JPEG, not evidence of
            // hidden data.
        }
    }
    emit_jpeg_findings(walk, out);
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
    let (trailing, detail) = match tail.windows(2).rposition(|w| w == JPEG_EOI) {
        Some(idx) => {
            let trailing = view.bytes_after(tail_offset + idx as u64 + 2);
            let detail = format!(
                "file does not end with EOI; {trailing} trailing bytes present after the last EOI marker (entropy {ent:.2} bits/byte)"
            );
            (trailing, detail)
        }
        None => {
            let trailing = view.bytes_after(tail_offset);
            let detail = format!(
                "file does not end with EOI; no EOI marker in the last {} bytes, so at least {trailing} bytes follow the image data (entropy {ent:.2} bits/byte)",
                STRUCT_TAIL_WINDOW
            );
            (trailing, detail)
        }
    };
    let severity = if ent >= 7.0 && trailing >= 32 {
        Severity::Likely
    } else {
        Severity::Suspicious
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
        let magic = &STANDARD_HEADER_MAGIC[..];
        if let Some(idx) = range.windows(magic.len()).position(|w| w == magic) {
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

/// Shannon entropy of the last [`TAIL_WINDOW`] bytes, and whether it sits in
/// the "looks like compressed/encrypted payload" band.
fn track_trailing_entropy(view: &ScanView, format: Option<&str>, out: &mut Vec<Finding>) {
    if view.file_size < TAIL_WINDOW as u64 {
        return;
    }
    let tail = view.entropy_tail();
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

    // The scan input is by definition untrusted, and a few hundred KiB of IDAT
    // can inflate to tens of gigabytes. IHDR states exactly how many bytes a
    // valid image produces, so bound the inflate by that and treat an overrun
    // as corruption instead of letting flate2 grow a Vec without limit.
    let expected = stride
        .checked_mul(height as usize)
        .and_then(|v| v.checked_add(height as usize))?; // +1 filter byte per row

    // Inflate.
    let mut z = flate2::read::ZlibDecoder::new(Cursor::new(&idat)).take(expected as u64 + 1);
    let mut raw = Vec::new();
    if z.read_to_end(&mut raw).is_err() {
        return None;
    }
    if raw.len() < expected {
        return None; // truncated
    }
    if raw.len() != expected {
        return None; // declared geometry does not match the stream: bomb or corrupt
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

/// Decode a JPEG to a flat pixel buffer via `jpeg-decoder`.
///
/// The channel count comes from the decoder's own `PixelFormat`: hard-coding 3
/// assumed RGB and mis-scaled every downstream detector on a grayscale image
/// (the row width `width * 3` pointed past each real row, so the statistics were
/// computed on scrambled pixels and silently reported "clean").
fn decode_jpeg_pixels(data: &[u8]) -> Option<(Vec<u8>, u32, usize)> {
    use jpeg_decoder::{Decoder, PixelFormat};
    let mut decoder = Decoder::new(std::io::Cursor::new(data));
    let pixels = decoder.decode().ok()?;
    let info = decoder.info()?;
    let channels = match info.pixel_format {
        PixelFormat::L8 => 1,
        PixelFormat::L16 => 2,
        PixelFormat::RGB24 => 3,
        PixelFormat::CMYK32 => 4,
    };
    if pixels.is_empty() {
        None
    } else {
        Some((pixels, info.width as u32, channels))
    }
}

// ---------------------------------------------------------------------------
// Content detectors
// ---------------------------------------------------------------------------

/// Weighted Stego-analysis (WS) for spatial LSB embedding with 8-neighbourhood context (Ker 2007).
///
/// Uses local filtering with both orthogonal and diagonal neighbours to predict cover pixel values,
/// balancing bipartite parity lattices, then estimates the LSB replacement rate alpha via weighted
/// covariance between prediction residuals and LSB flips.
fn ws_analysis(pixels: &[u8], width: u32, channels: usize) -> f64 {
    let width = width as usize;
    let stride = match width.checked_mul(channels) {
        Some(s) if s > 0 => s,
        _ => return 0.0,
    };
    if pixels.len() < stride * 3 || width < 3 {
        return 0.0;
    }
    let rows = (pixels.len() / stride).min(512);
    if rows < 3 {
        return 0.0;
    }

    let eval_channels = channels.min(3);
    let mut best_rate = 0.0f64;

    for ch in 0..eval_channels {
        let mut numerator = 0.0f64;
        let mut denominator = 0.0f64;

        for r in 1..rows - 1 {
            let row_curr = r * stride;
            let row_prev = (r - 1) * stride;
            let row_next = (r + 1) * stride;

            for c in 1..width - 1 {
                let off = c * channels + ch;
                let p = pixels[row_curr + off] as f64;

                // Orthogonal neighbours (weight 2 each)
                let p_l = pixels[row_curr + off - channels] as f64;
                let p_r = pixels[row_curr + off + channels] as f64;
                let p_u = pixels[row_prev + off] as f64;
                let p_d = pixels[row_next + off] as f64;

                // Diagonal neighbours (weight 1 each, breaks bipartite checkerboard parity bias)
                let p_lu = pixels[row_prev + off - channels] as f64;
                let p_ru = pixels[row_prev + off + channels] as f64;
                let p_ld = pixels[row_next + off - channels] as f64;
                let p_rd = pixels[row_next + off + channels] as f64;

                let pred = (2.0 * (p_l + p_r + p_u + p_d) + (p_lu + p_ru + p_ld + p_rd)) / 12.0;
                let residual = p - pred;

                let var = 0.25
                    * ((p_l - pred).powi(2)
                        + (p_r - pred).powi(2)
                        + (p_u - pred).powi(2)
                        + (p_d - pred).powi(2));
                let w = 1.0 / (1.0 + var).powi(2);

                let p_int = pixels[row_curr + off] as i32;
                let d = (p_int - (p_int ^ 1)) as f64;

                numerator += w * residual * d;
                denominator += w;
            }
        }

        if denominator > 0.0 {
            let alpha = (2.0 * numerator / denominator).clamp(0.0, 1.0);
            if alpha > best_rate {
                best_rate = alpha;
            }
        }
    }

    best_rate
}

fn track_spatial_domain(
    pixels: &[u8],
    width: u32,
    channels: usize,
    findings: &mut Vec<Finding>,
    detectors: &mut Vec<DetectorMetric>,
) {
    let sample: &[u8] = if pixels.len() > 4_000_000 {
        &pixels[..4_000_000]
    } else {
        pixels
    };

    // 1. WS (Weighted Stego-analysis)
    let ws_rate = ws_analysis(sample, width, channels);
    if ws_rate > 0.05 {
        findings.push(Finding {
            detector: "spatial:ws".into(),
            severity: Severity::Info,
            detail: format!("Weighted Stego-analysis (WS) estimates LSB rate ~{ws_rate:.2}"),
        });
        detectors.push(DetectorMetric {
            name: "spatial:ws".into(),
            domain: "spatial".into(),
            status: "ALERT".into(),
            metric: format!("rate: {ws_rate:.3}"),
            threshold: Some("0.050".into()),
            detail: "prediction residual covariance elevated".into(),
        });
    } else {
        detectors.push(DetectorMetric {
            name: "spatial:ws".into(),
            domain: "spatial".into(),
            status: "PASS".into(),
            metric: format!("rate: {ws_rate:.3}"),
            threshold: Some("0.050".into()),
            detail: "prediction residuals within normal bounds".into(),
        });
    }

    // 2. RS Analysis
    let rs_p = rs_analysis(sample, width, channels);
    if let Some(p) = rs_p
        && p > 0.05
    {
        findings.push(Finding {
            detector: "rs-analysis".into(),
            severity: Severity::Suspicious,
            detail: format!("RS analysis estimates LSB embedding rate ~{p:.2}"),
        });
        detectors.push(DetectorMetric {
            name: "spatial:rs".into(),
            domain: "spatial".into(),
            status: "ALERT".into(),
            metric: format!("rate: {p:.3}"),
            threshold: Some("0.050".into()),
            detail: "dual-mask flipping asymmetry".into(),
        });
    } else {
        detectors.push(DetectorMetric {
            name: "spatial:rs".into(),
            domain: "spatial".into(),
            status: "PASS".into(),
            metric: format!("rate: {:.3}", rs_p.unwrap_or(0.0)),
            threshold: Some("0.050".into()),
            detail: "dual-mask symmetry preserved".into(),
        });
    }

    // 3. SPA (Sample Pair Analysis)
    let spa_p = spa_estimate_dww(sample, width, channels);
    if spa_p > 0.05 {
        findings.push(Finding {
            detector: "spa".into(),
            severity: Severity::Suspicious,
            detail: format!("Sample Pair Analysis (DWW) estimates embedding rate ~{spa_p:.2}"),
        });
        detectors.push(DetectorMetric {
            name: "spatial:spa".into(),
            domain: "spatial".into(),
            status: "ALERT".into(),
            metric: format!("rate: {spa_p:.3}"),
            threshold: Some("0.050".into()),
            detail: "DWW sample pair trace deviation".into(),
        });
    } else {
        detectors.push(DetectorMetric {
            name: "spatial:spa".into(),
            domain: "spatial".into(),
            status: "PASS".into(),
            metric: format!("rate: {spa_p:.3}"),
            threshold: Some("0.050".into()),
            detail: "sample pair trace counts normal".into(),
        });
    }

    // 4. Chi-square LSB attack
    let chi2_score = chi2_lsb_suspicion(sample);
    if chi2_score > 0.5 {
        findings.push(Finding {
            detector: "chi2-lsb".into(),
            severity: Severity::Suspicious,
            detail: format!(
                "Chi-square LSB attack: pair histogram looks uniform (suspicion {chi2_score:.2}) \
                 - consistent with LSB embedding"
            ),
        });
        detectors.push(DetectorMetric {
            name: "spatial:chi2".into(),
            domain: "spatial".into(),
            status: "ALERT".into(),
            metric: format!("suspicion: {chi2_score:.3}"),
            threshold: Some("0.500".into()),
            detail: "LSB pair histogram artificially uniform".into(),
        });
    } else {
        detectors.push(DetectorMetric {
            name: "spatial:chi2".into(),
            domain: "spatial".into(),
            status: "PASS".into(),
            metric: format!("suspicion: {chi2_score:.3}"),
            threshold: Some("0.500".into()),
            detail: "LSB pair counts match natural distribution".into(),
        });
    }
}

fn track_jpeg_dct_domain(
    data: &[u8],
    findings: &mut Vec<Finding>,
    detectors: &mut Vec<DetectorMetric>,
    calibrated_signal: &mut bool,
) {
    // 1. Calibrated DCT Analysis (Fridrich 2002)
    if let Some(est) = calibration::estimate(data) {
        if est.rate >= CALIBRATION_FLAG_RATE {
            *calibrated_signal = true;
            findings.push(Finding {
                detector: "dct:calibration".into(),
                severity: if est.rate >= CALIBRATION_STRONG_RATE {
                    Severity::Likely
                } else {
                    Severity::Suspicious
                },
                detail: format!(
                    "Calibrated DCT estimate: ~{:.0}% of coefficients look LSB-replaced (rate {:.3}, imbalance ratio {:.2} vs calibrated reference, {} blocks)",
                    est.rate * 100.0,
                    est.rate,
                    est.imbalance_ratio,
                    est.blocks
                ),
            });
            detectors.push(DetectorMetric {
                name: "dct:calibration".into(),
                domain: "dct".into(),
                status: "ALERT".into(),
                metric: format!("rate: {:.3}", est.rate),
                threshold: Some(format!("{CALIBRATION_FLAG_RATE:.3}")),
                detail: format!(
                    "imbalance: {:.3}, {} blocks",
                    est.imbalance_ratio, est.blocks
                ),
            });
        } else {
            detectors.push(DetectorMetric {
                name: "dct:calibration".into(),
                domain: "dct".into(),
                status: "PASS".into(),
                metric: format!("rate: {:.3}", est.rate),
                threshold: Some(format!("{CALIBRATION_FLAG_RATE:.3}")),
                detail: format!(
                    "imbalance: {:.3}, {} blocks",
                    est.imbalance_ratio, est.blocks
                ),
            });
        }
    } else {
        detectors.push(DetectorMetric {
            name: "dct:calibration".into(),
            domain: "dct".into(),
            status: "PASS".into(),
            metric: "n/a".into(),
            threshold: Some(format!("{CALIBRATION_FLAG_RATE:.3}")),
            detail: "carrier quantization not suitable for calibration (e.g. q100)".into(),
        });
    }

    // 2. DCT AC Pairs Chi-Square Analysis (Westfeld 2001)
    if let Some(suspicion) = calibration::dct_chi2_suspicion(data) {
        if suspicion > 0.50 {
            findings.push(Finding {
                detector: "dct:chi2".into(),
                severity: Severity::Suspicious,
                detail: format!("DCT AC pairs heavily equalized (suspicion {suspicion:.2})"),
            });
            detectors.push(DetectorMetric {
                name: "dct:chi2".into(),
                domain: "dct".into(),
                status: "ALERT".into(),
                metric: format!("suspicion: {suspicion:.3}"),
                threshold: Some("0.500".into()),
                detail: "AC coefficient pair equalization detected".into(),
            });
        } else {
            detectors.push(DetectorMetric {
                name: "dct:chi2".into(),
                domain: "dct".into(),
                status: "PASS".into(),
                metric: format!("suspicion: {suspicion:.3}"),
                threshold: Some("0.500".into()),
                detail: "natural Laplacian AC coefficient decay".into(),
            });
        }
    }
}

#[allow(dead_code)]
fn track_content_domain(pixels: &[u8], width: u32, channels: usize, out: &mut Vec<Finding>) {
    let mut unused_detectors = Vec::new();
    track_spatial_domain(pixels, width, channels, out, &mut unused_detectors);
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
        track_tool_signatures(&ScanView::whole(&blob), &mut f);
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
        track_png_structure(&ScanView::whole(&png), &mut findings);
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

    /// A grayscale JPEG must be reported as 1 channel. Reporting 3 for it (as
    /// this used to) made `chi2_lsb_suspicion` read rows three times too wide.
    ///
    /// The fixture is hand-built so the assertion is meaningful: a broken
    /// fixture would decode to `None` and the test would pass for the wrong
    /// reason, so the decode itself is asserted first.
    #[test]
    fn grayscale_jpeg_reports_one_channel() {
        // Smallest legal baseline grayscale JPEG: one 16x16 MCU, flat
        // quantisation table, and DC + AC Huffman tables with two 1-bit codes
        // (`0` -> symbol 0x00, `1` -> symbol 0x01). Symbol 0x00 is both
        // "DC diff category 0" and "AC end-of-block", so each MCU costs two
        // zero bits: DC diff, then EOB.
        let mut counts = [0u8; 16];
        counts[0] = 2;
        // DHT segment: [class<<4 | table] [16 code counts] [symbols].
        let dht_payload: Vec<u8> = [&[0x00u8], &counts[..], &[0x00u8, 0x01u8][..]].concat();
        let mut d = Vec::new();
        d.extend_from_slice(&[0xFF, 0xD8]); // SOI
        d.extend_from_slice(&[0xFF, 0xDB]); // DQT
        let dqt_len = 2u16 + 1 + 64;
        d.extend_from_slice(&dqt_len.to_be_bytes());
        d.push(0x00); // 8-bit table 0
        d.extend_from_slice(&[0x10u8; 64]); // flat quantisation values
        d.extend_from_slice(&[0xFF, 0xC0]); // SOF0
        d.extend_from_slice(&(2u16 + 6 + 3).to_be_bytes());
        d.push(8); // 8-bit precision
        d.extend_from_slice(&16u16.to_be_bytes()); // width
        d.extend_from_slice(&16u16.to_be_bytes()); // height
        d.push(1); // one component
        d.push(1); // component id 1
        d.push(0x11); // sampling factors 1x1
        d.push(0x00); // quantisation table 0
        d.extend_from_slice(&[0xFF, 0xC4]); // DHT: DC table 0
        d.extend_from_slice(&(dht_payload.len() as u16 + 2).to_be_bytes());
        d.extend_from_slice(&dht_payload);
        // The scan references an AC table as well, and a scan component may not
        // leave one unset -- so define AC table 0 with the same two codes.
        let ac_payload: Vec<u8> = [&[0x10u8], &counts[..], &[0x00u8, 0x01u8][..]].concat();
        d.extend_from_slice(&[0xFF, 0xC4]); // DHT: AC table 0
        d.extend_from_slice(&(ac_payload.len() as u16 + 2).to_be_bytes());
        d.extend_from_slice(&ac_payload);
        d.extend_from_slice(&[0xFF, 0xDA]); // SOS
        // `read_length` in jpeg-decoder subtracts itself, so the on-wire value is
        // `4 + 2 * component_count + 2` for a 1-component scan.
        d.extend_from_slice(&8u16.to_be_bytes());
        d.push(1); // one component in scan
        d.push(1); // component selector 1
        d.push(0x00); // DC table 0, AC table 0
        d.extend_from_slice(&[0x00, 0x3F, 0x00]); // spectral 0..63, successive approx 0
        d.push(0b0000_0000); // DC diff 0
        d.push(0b0000_0000); // AC EOB
        d.extend_from_slice(&[0xFF, 0xD9]); // EOI

        let (pixels, width, channels) = decode_jpeg_pixels(&d).expect("fixture must decode");
        assert_eq!(channels, 1, "grayscale JPEG must decode to 1 channel");
        assert_eq!(pixels.len(), 16 * 16);
        assert_eq!(width, 16);
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
        track_jpeg_structure(&ScanView::whole(&data), &mut findings);
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
        track_jpeg_structure(&ScanView::whole(&data), &mut findings);
        assert!(
            findings.iter().any(|f| f.detector == "jpeg:many-dqt"),
            "findings: {findings:?}"
        );
    }

    /// Chunk sequence with a caller-supplied IHDR body and IDAT payload.
    fn raw_png(ihdr_body: &[u8], idat: &[u8]) -> Vec<u8> {
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
        chunk(b"IHDR", ihdr_body);
        chunk(b"IDAT", idat);
        chunk(b"IEND", &[]);
        out
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(data).unwrap();
        z.finish().unwrap()
    }

    /// Write a file above [`MAX_FULL_SCAN`] with `prefix` at offset 0 and
    /// `suffix` at the very end. The gap is created by seeking, so the file
    /// costs almost no disk space.
    fn write_windowed_file(path: &Path, prefix: &[u8], suffix: &[u8]) {
        use std::io::Write;
        let mut f = File::create(path).unwrap();
        f.write_all(prefix).unwrap();
        f.seek(SeekFrom::Start(MAX_FULL_SCAN + 1)).unwrap();
        f.write_all(suffix).unwrap();
        f.sync_all().unwrap();
    }

    /// Payload bytes for the windowed tests: every value 0..=250 cycling, so
    /// no `FF D9` can occur by accident. Entropy is ~7.9 bits/byte.
    fn filler(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    /// B1 acceptance: a PNG above the full-scan cap with data appended after
    /// IEND must be flagged. Before the prefix/tail split this reported clean.
    #[test]
    fn oversized_png_with_appended_payload_is_detected() {
        let tmp = std::env::temp_dir().join("strhide_scan_big_appended.png");
        // A chunk stream that ends before the padding: signature + IHDR + IDAT.
        let mut head = fake_png(4, 4, 2, |x, y| vec![(x * 50 + y * 10) as u8, 128, 200]);
        let iend_pos = head.windows(4).rposition(|w| w == b"IEND").unwrap() - 4;
        head.truncate(iend_pos);

        let mut suffix = PNG_IEND_FULL.to_vec();
        suffix.extend_from_slice(&filler(4096));
        write_windowed_file(&tmp, &head, &suffix);

        let rep = scan_file(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert!(
            rep.findings
                .iter()
                .any(|f| f.detector == "png:trailing-data"),
            "report: {rep:?}"
        );
        assert!(rep.risk_score >= 30, "report: {rep:?}");
        assert!(
            rep.notes.iter().any(|n| n.contains("larger than")),
            "a windowed scan must say so: {rep:?}"
        );
    }

    /// The same oversized PNG with *nothing* appended must stay clean: the
    /// trailing-data detector must key on real bytes after IEND, not on the
    /// window boundary.
    #[test]
    fn oversized_png_without_trailing_data_stays_clean() {
        let tmp = std::env::temp_dir().join("strhide_scan_big_clean.png");
        let mut head = fake_png(4, 4, 2, |x, _| vec![(x * 60) as u8, 128, 200]);
        let iend_pos = head.windows(4).rposition(|w| w == b"IEND").unwrap() - 4;
        head.truncate(iend_pos);
        write_windowed_file(&tmp, &head, &PNG_IEND_FULL);

        let rep = scan_file(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert!(
            !rep.findings
                .iter()
                .any(|f| f.detector == "png:trailing-data"),
            "report: {rep:?}"
        );
    }

    /// B7 acceptance: same for JPEG. The marker walk cannot reach EOI in a
    /// windowed view, so the file's own tail is the evidence.
    #[test]
    fn oversized_jpeg_with_appended_payload_is_detected() {
        let tmp = std::env::temp_dir().join("strhide_scan_big_appended.jpg");
        let mut head = vec![0xFF, 0xD8]; // SOI
        head.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x04, 0x00, 0x10]); // DQT
        head.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]); // SOS header

        let mut suffix = JPEG_EOI.to_vec();
        suffix.extend_from_slice(&filler(4096));
        write_windowed_file(&tmp, &head, &suffix);

        let rep = scan_file(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert!(
            rep.findings
                .iter()
                .any(|f| f.detector == "jpeg:trailing-data"),
            "report: {rep:?}"
        );
        assert!(rep.risk_score >= 30, "report: {rep:?}");
    }

    /// B4: IHDR states how many scanline bytes the image must produce, so a
    /// small IDAT that inflates far past that is a bomb, not an image.
    #[test]
    fn png_inflate_is_bounded_by_declared_geometry() {
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&4u32.to_be_bytes()); // width
        ihdr.extend_from_slice(&4u32.to_be_bytes()); // height
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB, non-interlaced
        // 1 MiB of zeros compresses to ~1 KiB but decodes to 20k times the
        // 52 bytes the header promises.
        let png = raw_png(&ihdr, &zlib(&vec![0u8; 1024 * 1024]));
        assert!(
            decode_png_pixels(&png).is_none(),
            "an inflate that overshoots the declared geometry must be rejected"
        );
    }

    #[test]
    fn rs_smooth_plane_estimates_near_zero() {
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
