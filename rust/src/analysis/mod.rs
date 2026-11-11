//! Steganalysis: black-box scanning of arbitrary files for hidden content.
//!
//! This is the runtime counterpart to strhide's own write/read pipeline:
//! where [`crate::structure::inspect_carrier`] answers "is there a strhide
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
//!   samples. These catch classic LSB *replacement* embedders. Algorithms follow
//!   the published papers (Westfeld & Pfitzmann 1999; Dumitrescu et al. 2003;
//!   Fridrich 2001) and are implemented from scratch.
//!
//!   The rate thresholds are calibrated on a 107-cover corpus, not taken from
//!   the papers: at the textbook 0.05, 21-33% of *clean* PNGs alert, because
//!   these estimators respond to image content (texture, saturation,
//!   JPEG-derived blockiness) at least as strongly as to a payload. They are
//!   also blind to ternary `±1` matching by construction -- embedding this
//!   project's own PNG carriers leaves the estimates unchanged at low load and
//!   *lowers* them at full load.
//!
//! All findings carry a `severity` and the report aggregates a 0–100
//! `risk_score` plus a coarse `verdict`. This is a heuristic triage tool, not
//! a forensic instrument: a clean verdict means "nothing suspicious stood
//! out", not "no hidden data exists".
//!
//! Layout: this module owns the report types, the scanned-bytes view and the
//! entry points; [`structural`] walks container/signature structure, [`spatial`]
//! holds the pixel-domain estimators and [`dct`] the JPEG calibration track.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::errors::StrHideError;
use crate::formats::FileFormat;
use crate::structure::envelope::{STANDARD_HEADER_MAGIC, STANDARD_TRAILER_MAGIC};

#[doc(hidden)]
pub mod calibration;

mod dct;
mod spatial;
mod structural;
#[cfg(test)]
mod tests;

use dct::track_jpeg_dct_domain;
use spatial::{decode_png_pixels, track_spatial_domain};
use structural::{
    track_container_structures, track_jpeg_structure, track_pe_structure, track_png_structure,
    track_tool_signatures, track_trailing_entropy,
};

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

/// How strongly a single finding points at embedded data.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Finding {
    /// Detector id, e.g. "magic:strhide-header", "png:unknown-chunk", "chi2-lsb".
    pub detector: String,
    pub severity: Severity,
    pub detail: String,
}

/// Quantitative measurement and status for one individual detector.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ScanReport {
    pub carrier: String,
    /// Detected container format, or `None` for unrecognized files.
    pub format: Option<String>,
    pub file_size: u64,
    pub findings: Vec<Finding>,
    /// 0 (clean) ..= 100 (very likely hidden); `aggregate_risk` saturates at 100.
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

/// Convenient alias for [`ScanReport`].
pub type AnalysisReport = ScanReport;

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

    /// Read `len` bytes starting at file offset `start`, if they are fully
    /// contained in either scanned window.
    fn slice(&self, start: u64, len: usize) -> Option<&'a [u8]> {
        let end = start.checked_add(len as u64)?;
        if end <= self.prefix.len() as u64 {
            return Some(&self.prefix[start as usize..end as usize]);
        }
        let (tail_offset, tail) = self.tail?;
        if start >= tail_offset && end <= tail_offset + tail.len() as u64 {
            return Some(&tail[(start - tail_offset) as usize..(end - tail_offset) as usize]);
        }
        None
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
    // Trailing bytes after container end markers indicate overlay data; entropy refines details.
    out.push(Finding {
        detector: detector.into(),
        severity: Severity::Likely,
        detail: format!(
            "{trailing} trailing bytes present after {marker} (entropy {ent:.2} bits/byte)"
        ),
    });
}

// ---------------------------------------------------------------------------
// Public entry points and internal scan dispatcher
// ---------------------------------------------------------------------------

/// Envelope magics a scan should recognise.
///
/// The official constants stay the default, so `scan_bytes`/`scan_file` behave
/// exactly as before. A private dialect adds its own pair: both are searched,
/// because a carrier may hold an official envelope or a private one, and a
/// scan that only knew the official magic would call a private carrier clean.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ScanMagics {
    /// Private 8-byte envelope header magic.
    pub header: Option<[u8; 8]>,
    /// Private 4-byte envelope trailer magic.
    pub trailer: Option<[u8; 4]>,
}

/// Envelope magics to add for `profile`, or none when it is the official one.
///
/// Only magics that actually differ are returned: handing the official
/// constants back would make every official carrier look like a
/// private-dialect hit.
pub(crate) fn scan_magics_for(profile: &crate::structure::StructureProfile) -> ScanMagics {
    let header = profile.header_magic();
    ScanMagics {
        header: (header != STANDARD_HEADER_MAGIC).then_some(header),
        trailer: profile
            .locator_magic()
            .copied()
            .filter(|magic| *magic != STANDARD_TRAILER_MAGIC),
    }
}

/// Scan raw bytes in memory. Never errors out on "nothing found".
pub fn scan_bytes(data: &[u8], label: &str) -> ScanReport {
    scan_bytes_with_magics(data, label, ScanMagics::default())
}

/// [`scan_bytes`] with a private dialect's envelope magics recognised too.
pub(crate) fn scan_bytes_with_magics(data: &[u8], label: &str, magics: ScanMagics) -> ScanReport {
    let file_size = data.len() as u64;
    let carrier = label.to_string();
    let view = if file_size <= MAX_FULL_SCAN {
        ScanView::whole(data)
    } else {
        let prefix = &data[..PREFIX_WINDOW.min(data.len())];
        let tail_offset = file_size.saturating_sub(STRUCT_TAIL_WINDOW as u64);
        let tail = &data[tail_offset as usize..];
        ScanView::windowed(prefix, tail_offset, tail, file_size)
    };
    scan_view_internal(&view, carrier, file_size, magics)
}

/// Scan one file end to end. Never errors out on "nothing found"; only real
/// I/O / unreadable-file problems return `Err`.
pub fn scan_file(path: &Path) -> Result<ScanReport, StrHideError> {
    scan_file_with_magics(path, ScanMagics::default())
}

/// [`scan_file`] with a private dialect's envelope magics recognised too.
pub(crate) fn scan_file_with_magics(
    path: &Path,
    magics: ScanMagics,
) -> Result<ScanReport, StrHideError> {
    let metadata = std::fs::metadata(path)?;
    let file_size = metadata.len();
    let carrier = path.display().to_string();

    // Read whole file (bounded). Above the cap we keep the first
    // `PREFIX_WINDOW` and the last `STRUCT_TAIL_WINDOW` bytes *separately*.
    let (prefix, tail): (Vec<u8>, Option<(u64, Vec<u8>)>) = if file_size <= MAX_FULL_SCAN {
        let f = File::open(path)?;
        let mut buf = Vec::with_capacity(file_size as usize);
        // The size was checked above, but the file may grow while it is read;
        // cap the read so a concurrent writer cannot blow past the scan budget.
        f.take(MAX_FULL_SCAN).read_to_end(&mut buf)?;
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
        f.take(STRUCT_TAIL_WINDOW as u64).read_to_end(&mut tail)?;
        (head, Some((tail_offset, tail)))
    };

    let view = match &tail {
        Some((off, t)) => ScanView::windowed(&prefix, *off, t, file_size),
        None => ScanView::whole(&prefix),
    };

    Ok(scan_view_internal(&view, carrier, file_size, magics))
}

fn scan_view_internal(
    view: &ScanView<'_>,
    carrier: String,
    file_size: u64,
    magics: ScanMagics,
) -> ScanReport {
    let mut findings: Vec<Finding> = Vec::new();
    let mut detectors: Vec<DetectorMetric> = Vec::new();

    let format = crate::formats::sniff::sniff_bytes(view.prefix);

    // 1. Signature domain: known tools / envelopes
    let sig_before = findings.len();
    track_tool_signatures(view, &mut findings, magics);
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
    match format {
        Some(FileFormat::Png) => {
            let before_cnt = findings.len();
            let terminated = track_png_structure(view, &mut findings);
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
                metric: if !terminated {
                    "no terminator".into()
                } else if has_trailing {
                    "trailing bytes present".into()
                } else {
                    "0 bytes".into()
                },
                threshold: Some("0 bytes".into()),
                detail: if !terminated {
                    "no IEND chunk: the terminator is missing or was replaced".into()
                } else if has_trailing {
                    "overlay data after IEND chunk".into()
                } else {
                    "clean termination at IEND".into()
                },
            });
        }
        Some(FileFormat::Jpeg) => {
            let before_cnt = findings.len();
            let terminated = track_jpeg_structure(view, &mut findings);
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
                metric: if !terminated {
                    "no terminator".into()
                } else if has_trailing {
                    "trailing bytes present".into()
                } else {
                    "0 bytes".into()
                },
                threshold: Some("0 bytes".into()),
                detail: if !terminated {
                    "no EOI marker: the terminator is missing or was replaced".into()
                } else if has_trailing {
                    "overlay data after EOI marker".into()
                } else {
                    "clean termination at EOI".into()
                },
            });
        }
        Some(FileFormat::Pe) if view.is_whole() => {
            track_pe_structure(view.prefix, &mut findings, magics)
        }
        Some(other) if view.is_whole() => {
            track_container_structures(view, other, &mut findings, &mut detectors);
        }
        _ => {}
    }
    track_trailing_entropy(view, format, &mut findings);

    // Set when the calibrated DCT test fired; used to decide whether the
    // "clean is not proof" caveat still applies to this report.
    let mut calibrated_signal = false;
    // Set when a PNG could not be turned into pixels at all (16-bit, Adam7,
    // oversized, corrupt), preventing false clean reports when spatial analysis cannot run.
    let mut png_stats_skipped = false;

    // 3. Statistical domain: strictly separate spatial domain (PNG) and frequency domain (JPEG)
    if view.is_whole() {
        let data = view.prefix;
        match format {
            Some(FileFormat::Png) => match decode_png_pixels(data) {
                Some((px, width, channels)) if !px.is_empty() => {
                    track_spatial_domain(&px, width, channels, &mut findings, &mut detectors);
                }
                _ => png_stats_skipped = true,
            },
            Some(FileFormat::Jpeg) => {
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
    if format == Some(FileFormat::Jpeg) && matches!(verdict, "clean" | "low") && !calibrated_signal
    {
        notes.push(
            "JPEG statistical detectors are weak against low-rate DCT embedding: a clean/low verdict is NOT evidence that nothing is hidden".to_string(),
        );
    }
    if matches!(format, Some(FileFormat::Wav | FileFormat::Flac)) {
        notes.push(
            "Content-domain audio steganography detectors are not implemented for WAV/FLAC: a clean/low verdict only reflects structural integrity and says nothing about sample-domain embedding"
                .to_string(),
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
    if png_stats_skipped {
        notes.push(
            "PNG pixel statistics were skipped (16-bit depth, interlaced/Adam7, oversized, or undecodable): no spatial detector ran, so this verdict says nothing about pixel-domain embedding"
                .to_string(),
        );
    }

    ScanReport {
        carrier,
        format: format.map(|f| f.as_str().to_string()),
        file_size,
        findings,
        risk_score,
        verdict: verdict.into(),
        notes,
        detectors,
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
