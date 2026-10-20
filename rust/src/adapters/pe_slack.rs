//! `pe_slack` — the envelope lives in a PE's section alignment padding.
//!
//! Every PE section's raw data is padded up to `FileAlignment`, and the section
//! table is followed by padding up to the first section's raw data. Those bytes
//! are *outside* `VirtualSize`, so the loader never maps them and the CPU can
//! never execute them, yet they are part of the file and are zero-filled by the
//! linker.
//!
//! Writing the envelope there gives the two properties `pe_overlay` cannot:
//! the carrier's size stays byte-identical, and there is no "data past the last
//! section" to spot. In exchange the capacity is small (a few KB) and
//! fragmented, so the strategy is a complement to, not a replacement for,
//! `pe_overlay`.
//!
//! Restore contract (100% bit-exact): the chosen run is *verified all-zero*
//! before anything is written, so `strip` reproduces the original bytes by
//! zero-filling exactly the region the envelope occupies. Nothing else in the
//! file is touched.

use crate::adapters::{SeekRead, SeekWrite, format_bytes, pe_codebits};
use crate::envelope::{
    EnvelopeHeader, EnvelopeTrailer, MIN_UBE_PLAIN, STANDARD_HEADER_MAGIC, STANDARD_TRAILER_MAGIC,
    TRAILER_SIZE,
};
use crate::errors::StrHideError;
use std::io::{Read, Seek, SeekFrom, Write};

/// Byte offset of `trailer_magic` inside a packed [`EnvelopeTrailer`].
const TRAILER_MAGIC_OFFSET: usize = 20;
/// Chunk size for scanning padding ranges.
const SCAN_CHUNK: usize = 64 * 1024;
/// Copy buffer size for restores.
const COPY_CHUNK: usize = 64 * 1024;

/// Finds a contiguous all-zero run of at least `needed` bytes inside the
/// carrier's padding. Returns its file offset.
///
/// The same function feeds `auto` strategy selection and the writer, so the
/// "does it fit?" answer and the actual placement can never disagree.
pub fn find_slack_run<R: Read + Seek + ?Sized>(
    reader: &mut R,
    ranges: &[(u64, u64)],
    needed: usize,
) -> Result<Option<u64>, StrHideError> {
    Ok(pe_codebits::find_slack_run_streaming(
        reader, ranges, needed,
    )?)
}

/// Injects `ube_in` into the carrier's padding and writes the container to
/// `out`. The output is byte-for-byte the host except for the envelope region,
/// so `inject_size` is the envelope length at `inject_offset` (an overwrite,
/// not an insertion).
pub fn inject(
    host_in: &mut dyn SeekRead,
    ube_in: &mut dyn SeekRead,
    out: &mut dyn Write,
) -> Result<(u64, u64, u32, u32), StrHideError> {
    let ube_size = ube_in.seek(SeekFrom::End(0))?;
    ube_in.seek(SeekFrom::Start(0))?;
    if ube_size == 0 {
        return Err(StrHideError::CorruptedData(
            "empty UBE payload for pe_slack".into(),
        ));
    }
    let ube_len = usize::try_from(ube_size)
        .map_err(|_| StrHideError::UnsupportedFormat("envelope is too large".into()))?;

    let layout = pe_codebits::parse_slack_layout_streaming(host_in)?;
    let off = match find_slack_run(host_in, &layout.slack_ranges, ube_len)? {
        Some(off) => off,
        None => {
            let largest =
                pe_codebits::max_zero_run_streaming(host_in, &layout.slack_ranges).unwrap_or(0);
            return Err(StrHideError::UnsupportedFormat(format!(
                "PE section padding cannot host a pe_slack envelope: no contiguous zero-value run \
                 of {} bytes (largest padding run is {} bytes; use pe_overlay for this payload)",
                format_bytes(ube_size),
                format_bytes(largest as u64)
            )));
        }
    };

    // Defensive re-check: the bytes we are about to overwrite must be all-zero,
    // otherwise zero-filling them on strip would not restore the original file.
    pe_codebits::verify_zero_slack(host_in, off, ube_len)?;

    // Stream the host, splicing the envelope over `[off, off + ube_size)`.
    copy_range(host_in, out, 0, off)?;
    copy_stream(ube_in, out)?;
    copy_range(host_in, out, off + ube_size, layout.host_size)?;

    Ok((off, ube_size, 0, 0))
}

/// Locates a `pe_slack` envelope inside the carrier's padding.
///
/// A candidate is accepted only when the trailer magic *and* its CRC32 match
/// (masked CRC for stealth envelopes), the advertised boundary is exactly
/// `[ube_offset, trailer_start)`, the whole envelope sits inside one padding
/// range, and — for standard envelopes — the header magic matches too. Random
/// padding cannot satisfy that by accident.
pub fn locate(
    stego_in: &mut dyn SeekRead,
    expected_trailer_magic: Option<&[u8; 4]>,
) -> Result<Option<(u64, u64)>, StrHideError> {
    let layout = match pe_codebits::parse_slack_layout_streaming(stego_in) {
        Ok(layout) => layout,
        Err(
            pe_codebits::CodebitsError::NotPe
            | pe_codebits::CodebitsError::NoText
            | pe_codebits::CodebitsError::UnsupportedMachine(_),
        ) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if layout.slack_ranges.is_empty() {
        return Ok(None);
    }

    let magics: Vec<[u8; 4]> = match expected_trailer_magic {
        Some(m) => vec![*m],
        None => vec![STANDARD_TRAILER_MAGIC],
    };

    for &(start, end) in &layout.slack_ranges {
        if let Some(found) = scan_range(stego_in, (start, end), &magics, expected_trailer_magic)? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

/// Scans one padding range for a trailer magic and validates a full envelope
/// around every hit.
fn scan_range(
    reader: &mut dyn SeekRead,
    range: (u64, u64),
    magics: &[[u8; 4]],
    expected_magic: Option<&[u8; 4]>,
) -> Result<Option<(u64, u64)>, StrHideError> {
    let (start, end) = range;
    if end <= start + TRAILER_SIZE as u64 {
        return Ok(None);
    }
    let mut buf = vec![0u8; SCAN_CHUNK];
    let mut pos = start;
    while pos < end {
        let want = ((end - pos) as usize).min(SCAN_CHUNK);
        reader.seek(SeekFrom::Start(pos))?;
        reader.read_exact(&mut buf[..want])?;
        if want < 4 {
            break;
        }
        for i in 0..=want - 4 {
            if !magics.iter().any(|m| buf[i..i + 4] == m[..]) {
                continue;
            }
            let magic_pos = pos + i as u64;
            let Some(trailer_start) = magic_pos.checked_sub(TRAILER_MAGIC_OFFSET as u64) else {
                continue;
            };
            if trailer_start < start || trailer_start + TRAILER_SIZE as u64 > end {
                continue;
            }
            if let Some(found) = validate_trailer_at(reader, trailer_start, range, expected_magic)?
            {
                return Ok(Some(found));
            }
        }
        // Keep the last 3 bytes so a magic split across chunks is still seen.
        pos += (want - 3) as u64;
    }
    Ok(None)
}

/// Validates the trailer at `trailer_start` and, on success, returns
/// `(ube_offset, ube_total_size)`.
fn validate_trailer_at(
    reader: &mut dyn SeekRead,
    trailer_start: u64,
    range: (u64, u64),
    expected_magic: Option<&[u8; 4]>,
) -> Result<Option<(u64, u64)>, StrHideError> {
    let bytes = read_exact_at(reader, trailer_start, TRAILER_SIZE)?;
    let trailer = match EnvelopeTrailer::unpack(&bytes, expected_magic) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    // The trailer must immediately follow the envelope it describes.
    if trailer.ube_offset.checked_add(trailer.ube_total_size)
        != Some(trailer_start + TRAILER_SIZE as u64)
    {
        return Ok(None);
    }
    if trailer.ube_total_size < MIN_UBE_PLAIN as u64 {
        return Ok(None);
    }
    // The envelope must be contained in this single padding range: `pe_slack`
    // never straddles two ranges or spills into section data.
    if trailer.ube_offset < range.0 || trailer_start + TRAILER_SIZE as u64 > range.1 {
        return Ok(None);
    }
    // Standard envelopes carry a fixed header magic. Stealth envelopes derive
    // theirs from the password (which `locate` does not receive), so the magic
    // + masked-CRC trailer check above is the only password-independent
    // evidence available for them.
    if expected_magic.is_none() {
        let header = read_exact_at(reader, trailer.ube_offset, 8)?;
        if header != STANDARD_HEADER_MAGIC.as_slice() {
            return Ok(None);
        }
    }
    Ok(Some((trailer.ube_offset, trailer.ube_total_size)))
}

/// Restores the carrier: copies it verbatim while zero-filling exactly the
/// envelope region.
pub fn strip(
    stego_in: &mut dyn SeekRead,
    out: &mut dyn SeekWrite,
    header: &EnvelopeHeader,
) -> Result<(), StrHideError> {
    let offset = header.inject_offset;
    let size = header.inject_size;
    if size == 0 {
        return Err(StrHideError::CorruptedData(
            "pe_slack envelope has zero size".into(),
        ));
    }
    let host_size = stego_in.seek(SeekFrom::End(0))?;
    if offset.checked_add(size).is_none_or(|end| end > host_size) {
        return Err(StrHideError::CorruptedData(format!(
            "pe_slack envelope [{offset}, +{size}) lies outside the carrier ({host_size} bytes)"
        )));
    }

    // Only ever zero bytes that are inside a padding range. A corrupted header
    // pointing at section data must fail instead of silently destroying code.
    let layout = pe_codebits::parse_slack_layout_streaming(stego_in)?;
    let inside_padding = layout
        .slack_ranges
        .iter()
        .any(|&(start, end)| offset >= start && offset + size <= end);
    if !inside_padding {
        return Err(StrHideError::CorruptedData(format!(
            "pe_slack envelope [{offset}, +{size}) is not inside PE padding; refusing to overwrite section data"
        )));
    }

    copy_range(stego_in, out, 0, offset)?;
    write_zeros(out, size)?;
    copy_range(stego_in, out, offset + size, host_size)?;
    Ok(())
}

/// Result of scanning the carrier's section-alignment padding.
#[derive(Debug, Default)]
pub struct SlackScan {
    /// Non-zero bytes anywhere in the padding ranges.
    pub nonzero: u64,
    /// Number of distinct byte values across the padding ranges.
    ///
    /// Ciphertext fills almost the whole 0..=255 alphabet (~139 values in 200
    /// bytes), while compiler-generated padding that is not zero-filled is
    /// highly repetitive: one ordinary executable in the corpus has a 224-byte
    /// non-zero block using only **7** distinct values. This separates a
    /// stealth envelope from ordinary padding far better than a byte count.
    pub distinct: usize,
    /// Number of padding ranges that were scanned.
    pub ranges: usize,
    /// Offset of a strhide envelope header (standard magic) found in the
    /// padding. This is hard evidence; `nonzero` alone is not.
    pub header_offset: Option<u64>,
}

/// Minimum number of distinct byte values for padding to look like ciphertext.
///
/// 178 uniformly random bytes fill ~129 distinct values on average; the
/// smallest envelope is 178 bytes. Repetitive compiler padding stays far below
/// (7 in the corpus sample), so this separates "encrypted payload" from
/// "leftover data" without needing the password.
pub const MIN_CIPHERTEXT_DISTINCT: usize = 100;

/// Scans the carrier's padding ranges once, reporting both the non-zero count
/// and whether a strhide header magic is present.
pub fn scan_slack(stego_in: &mut dyn SeekRead) -> Result<SlackScan, StrHideError> {
    let layout = match pe_codebits::parse_slack_layout_streaming(stego_in) {
        Ok(layout) => layout,
        Err(_) => return Ok(SlackScan::default()),
    };
    const MAGICS: [&[u8; 8]; 1] = [&STANDARD_HEADER_MAGIC];
    let mut buf = vec![0u8; SCAN_CHUNK];
    let mut seen = [false; 256];
    let mut scan = SlackScan {
        ranges: layout.slack_ranges.len(),
        ..Default::default()
    };
    for &(start, end) in &layout.slack_ranges {
        let mut pos = start;
        // Bytes carried over from the previous chunk so a magic straddling a
        // chunk boundary is still found.
        let mut carry: Vec<u8> = Vec::new();
        while pos < end {
            let want = ((end - pos) as usize).min(SCAN_CHUNK);
            stego_in.seek(SeekFrom::Start(pos))?;
            let n = stego_in.read(&mut buf[..want])?;
            if n == 0 {
                break;
            }
            for &b in &buf[..n] {
                if b != 0 {
                    scan.nonzero += 1;
                }
                seen[b as usize] = true;
            }
            if scan.header_offset.is_none() {
                let mut window = Vec::with_capacity(carry.len() + n);
                window.extend_from_slice(&carry);
                window.extend_from_slice(&buf[..n]);
                'magic: for magic in MAGICS {
                    if let Some(idx) = window.windows(magic.len()).position(|w| w == magic) {
                        scan.header_offset = Some(pos - carry.len() as u64 + idx as u64);
                        break 'magic;
                    }
                }
                let keep = window.len().min(7);
                carry.clear();
                carry.extend_from_slice(&window[window.len() - keep..]);
            }
            pos += n as u64;
        }
    }
    scan.distinct = seen.iter().filter(|s| **s).count();
    Ok(scan)
}

fn read_exact_at<R: Read + Seek + ?Sized>(
    reader: &mut R,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, StrHideError> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Copies `[from, to)` of `reader` to `writer`.
fn copy_range<W: Write + ?Sized, R: Read + Seek + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    from: u64,
    to: u64,
) -> Result<(), StrHideError> {
    if to <= from {
        return Ok(());
    }
    reader.seek(SeekFrom::Start(from))?;
    let mut remaining = to - from;
    let mut buf = vec![0u8; COPY_CHUNK];
    while remaining > 0 {
        let want = remaining.min(COPY_CHUNK as u64) as usize;
        let n = reader.read(&mut buf[..want])?;
        if n == 0 {
            return Err(StrHideError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "carrier ended before the expected offset",
            )));
        }
        writer.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}

/// Copies `reader` from its current position to EOF.
fn copy_stream<W: Write + ?Sized, R: Read + ?Sized>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(), StrHideError> {
    let mut buf = vec![0u8; COPY_CHUNK];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        writer.write_all(&buf[..n])?;
    }
}

fn write_zeros<W: Write + ?Sized>(writer: &mut W, len: u64) -> Result<(), StrHideError> {
    let zeros = vec![0u8; COPY_CHUNK];
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(COPY_CHUNK as u64) as usize;
        writer.write_all(&zeros[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}
