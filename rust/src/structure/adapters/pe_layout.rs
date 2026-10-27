//! Windows PE executable layout parser and alignment padding (slack) scanner.
//!
//! Provides zero-third-party-dependency PE header parsing, section geometry,
//! and candidate zero-slack run discovery for:
//! - [`crate::structure::adapters::pe_slack`] (pure section-padding steganography)
//! - `pe_codebits` (code-bit channel steganography)
//! - Steganalysis PE scanning
//!
//! This module requires only `std::io` (no `iced-x86`).

use std::io::{Read, Seek, SeekFrom, Write};

use crate::errors::StrHideError;

/// Errors raised during PE parsing or code-bit channel operations.
#[derive(Debug)]
pub enum CodebitsError {
    /// Not a PE file (missing MZ / PE signature).
    NotPe,
    /// PE without a usable `.text` section.
    NoText,
    /// PE `Machine` value is neither x86 nor x86-64.
    UnsupportedMachine(u16),
    /// `.text` does not have enough instrumentable positions.
    Capacity { need_bits: usize, have_bits: usize },
    /// No contiguous zero-value slack run large enough for the diff.
    NoSlack { need_bytes: usize },
    /// Channel header magic/version mismatch (locate: no channel present).
    ChannelNotFound,
    /// Channel header parsed but the payload region is inconsistent.
    Corrupted(String),
    /// iced-x86 or general I/O error.
    Iced(String),
    /// General I/O error.
    Io(String),
}

impl std::fmt::Display for CodebitsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPe => write!(f, "not a PE executable (missing MZ/PE signature)"),
            Self::NoText => write!(f, "PE has no usable .text section"),
            Self::UnsupportedMachine(m) => {
                write!(f, "unsupported PE machine type 0x{m:04X} (x86/x64 only)")
            }
            Self::Capacity {
                need_bits,
                have_bits,
            } => write!(
                f,
                "insufficient .text steganographic capacity: need {need_bits} bits, have {have_bits}"
            ),
            Self::NoSlack { need_bytes } => write!(
                f,
                "no contiguous zero-value PE slack run of {need_bytes} bytes for the restore diff"
            ),
            Self::ChannelNotFound => write!(f, "no code-bit channel found"),
            Self::Corrupted(msg) => write!(f, "corrupted code-bit channel: {msg}"),
            Self::Iced(msg) | Self::Io(msg) => write!(f, "PE operation failed: {msg}"),
        }
    }
}

impl std::error::Error for CodebitsError {}

impl From<CodebitsError> for StrHideError {
    fn from(e: CodebitsError) -> Self {
        match e {
            CodebitsError::ChannelNotFound => {
                StrHideError::NoHiddenData("no code-bit channel found".into())
            }
            CodebitsError::Capacity { .. } | CodebitsError::NoSlack { .. } => {
                StrHideError::UnsupportedFormat(e.to_string())
            }
            other => StrHideError::CorruptedData(other.to_string()),
        }
    }
}

/// `.text` location, bitness and candidate slack ranges of a PE file.
#[derive(Debug, Clone)]
pub struct PeCodeLayout {
    /// 16/32/64.
    pub bitness: u32,
    /// File offset of the `.text` section raw data.
    pub text_offset: u64,
    /// Bytes to scan: `min(virtual_size, size_of_raw_data)`, clamped to EOF.
    pub text_scan_len: u64,
    /// Total file size.
    pub host_size: u64,
    /// Candidate zero-value padding ranges `(start, end)`, file order.
    pub slack_ranges: Vec<(u64, u64)>,
}

/// Reads a PE's code layout from an in-memory image.
pub fn pe_code_layout(data: &[u8]) -> Result<PeCodeLayout, CodebitsError> {
    pe_code_layout_with_host(data, data.len() as u64)
}

/// PE section-table geometry, independent of architecture and of `.text`.
///
/// Shared by the code-bit layout (which additionally requires an x86/x64
/// `.text`) and by the `pe_slack` strategy (which only needs the alignment
/// padding, so it must also work for ARM64 / .NET / any other machine type).
pub(crate) struct PeGeometry {
    pub(crate) machine: u16,
    /// `(name, virtual_size, size_of_raw_data, pointer_to_raw_data)`.
    pub(crate) sections: Vec<(String, u32, u32, u32)>,
    pub(crate) sec_table_end: u64,
}

pub(crate) fn pe_geometry(data: &[u8]) -> Result<PeGeometry, CodebitsError> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return Err(CodebitsError::NotPe);
    }
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    if e_lfanew < 0x40 || e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(CodebitsError::NotPe);
    }
    let coff = e_lfanew + 4;
    let machine = u16::from_le_bytes(data[coff..coff + 2].try_into().unwrap());
    let num_sections = u16::from_le_bytes(data[coff + 2..coff + 4].try_into().unwrap()) as usize;
    let size_of_opt = u16::from_le_bytes(data[coff + 16..coff + 18].try_into().unwrap()) as usize;

    let opt = coff + 20;
    if opt + 2 > data.len() {
        return Err(CodebitsError::NotPe);
    }
    let opt_magic = u16::from_le_bytes(data[opt..opt + 2].try_into().unwrap());
    if !matches!(opt_magic, 0x10B | 0x20B) {
        return Err(CodebitsError::NotPe);
    }

    let sec_table = opt + size_of_opt;
    let mut sections: Vec<(String, u32, u32, u32)> = Vec::new(); // (name, vsize, rawsize, rawptr)
    for i in 0..num_sections {
        let off = sec_table + i * 40;
        if off + 40 > data.len() {
            return Err(CodebitsError::NotPe);
        }
        let name = String::from_utf8_lossy(&data[off..off + 8])
            .trim_end_matches('\0')
            .to_string();
        let vsize = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap());
        let rawsize = u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap());
        let rawptr = u32::from_le_bytes(data[off + 20..off + 24].try_into().unwrap());
        sections.push((name, vsize, rawsize, rawptr));
    }

    Ok(PeGeometry {
        machine,
        sec_table_end: (sec_table + sections.len() * 40) as u64,
        sections,
    })
}

/// Alignment padding candidates `(start, end)` of a PE, in file order:
/// the gap between the section table and the first section's raw data, plus
/// each section's tail padding beyond `min(vsize, rawsize)`. The file-tail
/// overlay region is deliberately excluded.
pub(crate) fn slack_ranges(geo: &PeGeometry, host_size: u64) -> Vec<(u64, u64)> {
    let used: Vec<(u64, u64)> = geo
        .sections
        .iter()
        .map(|(_, vsize, rawsize, rawptr)| {
            let start = *rawptr as u64;
            (start, start + (*vsize).min(*rawsize) as u64)
        })
        .filter(|(a, b)| b > a && *a < host_size)
        .collect();

    let mut candidates = Vec::new();
    let first_raw = geo
        .sections
        .iter()
        .map(|(.., rawptr)| *rawptr as u64)
        .filter(|p| *p > 0)
        .min();
    if let Some(first_raw) = first_raw
        && first_raw > geo.sec_table_end
    {
        candidates.push((geo.sec_table_end, first_raw.min(host_size)));
    }
    for (_, vsize, rawsize, rawptr) in &geo.sections {
        if *vsize == 0 {
            continue;
        }
        let a = *rawptr as u64 + (*vsize).min(*rawsize) as u64;
        let b = (*rawptr as u64 + *rawsize as u64).min(host_size);
        if b > a {
            candidates.push((a, b));
        }
    }

    let mut ranges = Vec::new();
    for (start, end) in candidates {
        subtract_intervals(start, end, &used, &mut ranges);
    }
    ranges
}

/// Appends `[start, end)` minus every interval in `mask` to `out`, in order.
fn subtract_intervals(start: u64, end: u64, mask: &[(u64, u64)], out: &mut Vec<(u64, u64)>) {
    let mut overlapping: Vec<(u64, u64)> = mask
        .iter()
        .copied()
        .filter(|(s, e)| *e > start && *s < end)
        .collect();
    overlapping.sort_by_key(|(s, _)| *s);
    let mut cur = start;
    for (s, e) in overlapping {
        if s > cur {
            out.push((cur, s.min(end)));
        }
        cur = cur.max(e);
        if cur >= end {
            return;
        }
    }
    if cur < end {
        out.push((cur, end));
    }
}

/// Reads a PE's code layout from an in-memory *header window*, clamped against
/// an explicit `host_size`.
fn pe_code_layout_with_host(data: &[u8], host_size: u64) -> Result<PeCodeLayout, CodebitsError> {
    let geo = pe_geometry(data)?;
    let bitness = match geo.machine {
        0x14C => 32,
        0x8664 => 64,
        other => return Err(CodebitsError::UnsupportedMachine(other)),
    };

    let text = geo
        .sections
        .iter()
        .find(|(name, ..)| name == ".text")
        .ok_or(CodebitsError::NoText)?;
    let text_offset = text.3 as u64;
    let scan_len = (text.1.min(text.2) as u64).min(host_size.saturating_sub(text_offset));

    Ok(PeCodeLayout {
        bitness,
        text_offset,
        text_scan_len: scan_len,
        host_size,
        slack_ranges: slack_ranges(&geo, host_size),
    })
}

/// Scans the slack candidate ranges of an in-memory image for the best
/// contiguous all-zero run of at least `needed` bytes.
pub fn find_slack_run(data: &[u8], ranges: &[(u64, u64)], needed: usize) -> Option<u64> {
    let mut best: Option<(usize, u64)> = None; // (len, offset)
    for &(start, end) in ranges {
        let start = start as usize;
        let end = (end as usize).min(data.len());
        if start >= end {
            continue;
        }
        let mut i = start;
        while i < end {
            if data[i] != 0 {
                i += 1;
                continue;
            }
            let run_start = i;
            while i < end && data[i] == 0 {
                i += 1;
            }
            let len = i - run_start;
            if len >= needed && best.is_none_or(|(bl, _)| len < bl) {
                best = Some((len, run_start as u64));
            }
        }
    }
    best.map(|(_, off)| off)
}

/// Reads a `Read + Seek` stream's PE code layout without loading the whole file.
pub fn parse_pe_code_layout_streaming<R: Read + Seek + ?Sized>(
    reader: &mut R,
) -> Result<PeCodeLayout, CodebitsError> {
    let start_pos = reader
        .stream_position()
        .map_err(|e| CodebitsError::Io(e.to_string()))?;
    let host_size = reader
        .seek(SeekFrom::End(0))
        .map_err(|e| CodebitsError::Io(e.to_string()))?;
    if host_size < 0x40 {
        reader.seek(SeekFrom::Start(start_pos)).ok();
        return Err(CodebitsError::NotPe);
    }
    let header_window = (host_size.min(0x10000)) as usize;
    reader.seek(SeekFrom::Start(0)).ok();
    let mut head = vec![0u8; header_window];
    reader
        .read_exact(&mut head)
        .map_err(|e| CodebitsError::Io(e.to_string()))?;

    let layout = pe_code_layout_with_host(&head, host_size).inspect_err(|_| {
        reader.seek(SeekFrom::Start(start_pos)).ok();
    })?;
    let text_scan_len = layout
        .text_scan_len
        .min(host_size.saturating_sub(layout.text_offset));
    let slack_ranges = layout
        .slack_ranges
        .into_iter()
        .map(|(a, b)| (a, b.min(host_size)))
        .filter(|(a, b)| b > a)
        .collect();
    reader.seek(SeekFrom::Start(start_pos)).ok();
    Ok(PeCodeLayout {
        bitness: layout.bitness,
        text_offset: layout.text_offset,
        text_scan_len,
        host_size,
        slack_ranges,
    })
}

/// Padding geometry of a PE, for the `pe_slack` strategy.
#[derive(Debug, Clone)]
pub struct PeSlackLayout {
    /// Total file size.
    pub host_size: u64,
    /// Candidate zero-value padding ranges `(start, end)`, file order.
    pub slack_ranges: Vec<(u64, u64)>,
}

/// Reads a PE's padding ranges from a complete in-memory image.
pub fn pe_slack_layout(data: &[u8]) -> Result<PeSlackLayout, CodebitsError> {
    let geo = pe_geometry(data)?;
    let host_size = data.len() as u64;
    Ok(PeSlackLayout {
        host_size,
        slack_ranges: slack_ranges(&geo, host_size)
            .into_iter()
            .filter(|(a, b)| b > a)
            .collect(),
    })
}

/// Reads a PE's padding ranges without loading the whole file.
pub fn parse_slack_layout_streaming<R: Read + Seek + ?Sized>(
    reader: &mut R,
) -> Result<PeSlackLayout, CodebitsError> {
    let start_pos = reader
        .stream_position()
        .map_err(|e| CodebitsError::Io(e.to_string()))?;
    let host_size = reader
        .seek(SeekFrom::End(0))
        .map_err(|e| CodebitsError::Io(e.to_string()))?;
    if host_size < 0x40 {
        reader.seek(SeekFrom::Start(start_pos)).ok();
        return Err(CodebitsError::NotPe);
    }
    let header_window = (host_size.min(0x10000)) as usize;
    reader.seek(SeekFrom::Start(0)).ok();
    let mut head = vec![0u8; header_window];
    reader
        .read_exact(&mut head)
        .map_err(|e| CodebitsError::Io(e.to_string()))?;

    let geo = match pe_geometry(&head) {
        Ok(geo) => geo,
        Err(e) => {
            reader.seek(SeekFrom::Start(start_pos)).ok();
            return Err(e);
        }
    };
    let ranges = slack_ranges(&geo, host_size)
        .into_iter()
        .filter(|(a, b)| b > a)
        .collect();
    reader.seek(SeekFrom::Start(start_pos)).ok();
    Ok(PeSlackLayout {
        host_size,
        slack_ranges: ranges,
    })
}

/// Reads the `.text` scan window of `layout` from `reader`.
pub fn read_text_range<R: Read + Seek + ?Sized>(
    reader: &mut R,
    layout: &PeCodeLayout,
) -> Result<Vec<u8>, CodebitsError> {
    let start_pos = reader
        .stream_position()
        .map_err(|e| CodebitsError::Io(e.to_string()))?;
    reader
        .seek(SeekFrom::Start(layout.text_offset))
        .map_err(|e| CodebitsError::Io(e.to_string()))?;
    let mut buf = vec![0u8; layout.text_scan_len as usize];
    reader
        .read_exact(&mut buf)
        .map_err(|e| CodebitsError::Io(e.to_string()))?;
    reader.seek(SeekFrom::Start(start_pos)).ok();
    Ok(buf)
}

/// Streams the slack candidate ranges, tracking the best all-zero run of at
/// least `needed` bytes.
pub fn find_slack_run_streaming<R: Read + Seek + ?Sized>(
    reader: &mut R,
    ranges: &[(u64, u64)],
    needed: usize,
) -> Result<Option<u64>, CodebitsError> {
    let start_pos = reader
        .stream_position()
        .map_err(|e| CodebitsError::Io(e.to_string()))?;
    let mut best: Option<(usize, u64)> = None;
    let mut buf = vec![0u8; 64 * 1024];

    for &(start, end) in ranges {
        if end <= start {
            continue;
        }
        reader
            .seek(SeekFrom::Start(start))
            .map_err(|e| CodebitsError::Io(e.to_string()))?;
        let mut remaining = end - start;
        let mut run_start: Option<u64> = None;
        let mut run_len = 0usize;
        let mut pos = start;
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let n = reader
                .read(&mut buf[..want])
                .map_err(|e| CodebitsError::Io(e.to_string()))?;
            if n == 0 {
                break;
            }
            for &b in &buf[..n] {
                if b == 0 {
                    if run_start.is_none() {
                        run_start = Some(pos);
                    }
                    run_len += 1;
                } else {
                    if let Some(rs) = run_start.take()
                        && run_len >= needed
                        && best.is_none_or(|(bl, _)| run_len < bl)
                    {
                        best = Some((run_len, rs));
                    }
                    run_len = 0;
                }
                pos += 1;
            }
            remaining -= n as u64;
        }
        if let Some(rs) = run_start.take()
            && run_len >= needed
            && best.is_none_or(|(bl, _)| run_len < bl)
        {
            best = Some((run_len, rs));
        }
    }

    reader.seek(SeekFrom::Start(start_pos)).ok();
    Ok(best.map(|(_, off)| off))
}

/// Longest all-zero run across the slack candidate ranges (streaming).
pub fn max_zero_run_streaming<R: Read + Seek + ?Sized>(
    reader: &mut R,
    ranges: &[(u64, u64)],
) -> Result<usize, CodebitsError> {
    let start_pos = reader
        .stream_position()
        .map_err(|e| CodebitsError::Io(e.to_string()))?;
    let mut best = 0usize;
    let mut buf = vec![0u8; 64 * 1024];

    for &(start, end) in ranges {
        if end <= start {
            continue;
        }
        reader
            .seek(SeekFrom::Start(start))
            .map_err(|e| CodebitsError::Io(e.to_string()))?;
        let mut remaining = end - start;
        let mut run = 0usize;
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let n = reader
                .read(&mut buf[..want])
                .map_err(|e| CodebitsError::Io(e.to_string()))?;
            if n == 0 {
                break;
            }
            for &b in &buf[..n] {
                if b == 0 {
                    run += 1;
                    if run > best {
                        best = run;
                    }
                } else {
                    run = 0;
                }
            }
            remaining -= n as u64;
        }
    }

    reader.seek(SeekFrom::Start(start_pos)).ok();
    Ok(best)
}

/// Reads `len` bytes at `offset` from a `Read + Seek` stream.
pub fn read_at<R: Read + Seek + ?Sized>(
    reader: &mut R,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, CodebitsError> {
    let start_pos = reader
        .stream_position()
        .map_err(|e| CodebitsError::Io(e.to_string()))?;
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|e| CodebitsError::Io(e.to_string()))?;
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .map_err(|e| CodebitsError::Io(e.to_string()))?;
    reader.seek(SeekFrom::Start(start_pos)).ok();
    Ok(buf)
}

/// Verifies that `[offset, offset + len)` is entirely zero, then returns a
/// zero-filled buffer of `len` bytes.
pub fn verify_zero_slack<R: Read + Seek + ?Sized>(
    reader: &mut R,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, CodebitsError> {
    let existing = read_at(reader, offset, len)?;
    if existing.iter().any(|&b| b != 0) {
        return Err(CodebitsError::NoSlack { need_bytes: len });
    }
    Ok(vec![0u8; len])
}

/// Writes `bytes` at `offset` into a `Write + Seek` stream.
pub fn write_at<W: Write + Seek + ?Sized>(
    writer: &mut W,
    offset: u64,
    bytes: &[u8],
) -> Result<(), CodebitsError> {
    writer
        .seek(SeekFrom::Start(offset))
        .map_err(|e| CodebitsError::Io(e.to_string()))?;
    writer
        .write_all(bytes)
        .map_err(|e| CodebitsError::Io(e.to_string()))?;
    Ok(())
}
