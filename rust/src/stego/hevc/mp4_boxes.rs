//! Lightweight, zero-copy ISOBMFF MP4/MOV parser for Scheme C.
//!
//! Locates the HEVC video track, reads its `hvcC` configuration and resolves
//! every VCL NAL unit of the sample table to an exact file byte span, so the
//! CABAC rewriter can flip signs in place (Δ = 0) without touching the
//! container: sample sizes, chunk offsets and `moov` stay byte-identical.
//!
//! # Robustness contract
//!
//! This parser reads **untrusted input**: every length, offset and count field
//! in an MP4 is attacker-controlled. Therefore this module contains **no
//! `unwrap()` / `expect()` / `panic!`** — every read is bounds-checked and
//! every malformed structure is reported as [`HevcError`].
//!
//! # Real-world shape (5/5 phone-recorded corpus files)
//!
//! * `moov` sits **after** `mdat`, i.e. at the end of the file. The walk
//!   therefore scans the whole file instead of assuming a media-data-first or
//!   metadata-first layout.
//! * Both `stco` (32-bit) and `co64` (64-bit) chunk offsets occur.
//! * `stsz` is the variable-sample-size form (`sample_size == 0`); the fixed
//!   size form is handled too, `stz2` is rejected explicitly.
//! * Parameter sets live only in `hvcC` (no in-band VPS/SPS/PPS), even for
//!   `hvc1` files, where the spec nominally forbids it.
//!
//! # Explicitly rejected
//!
//! Fragmented files (`moof`/`traf`/`trun`), encrypted tracks (`encv`,
//! `sinf`) and non-HEVC video tracks: their sample layout is not derivable
//! from the tables parsed here, and a guessed span would corrupt the carrier.

use crate::stego::hevc::error::{HevcError, Result};
use crate::stego::hevc::heif_boxes::{PhysicalNalSpan, be_u16, be_u32, be_u64, parse_hvcc_record};

/// Sample entry box types that carry an HEVC decoder configuration record.
const HEVC_SAMPLE_ENTRIES: [&[u8; 4]; 2] = [b"hvc1", b"hev1"];

/// Bytes of a `VisualSampleEntry` before its child boxes start: 8-byte box
/// header + the fixed 78-byte visual sample entry fields
/// (ISO/IEC 14496-12 §12.1.3).
const VISUAL_SAMPLE_ENTRY_HEADER: usize = 86;

/// Extracted MP4/MOV carrier information ready for Scheme C steganography.
pub struct Mp4HevcTarget<'a> {
    /// VPS, SPS, PPS (and any other array entries) from `hvcC`, without
    /// length prefixes.
    pub parameter_sets: Vec<&'a [u8]>,
    /// NAL length prefix size in bytes as declared by `hvcC` (typically 4).
    pub length_size: usize,
    /// Physical spans of every VCL NAL unit in the video track, in sample
    /// order, which is decode order.
    pub slice_spans: Vec<PhysicalNalSpan>,
    /// Number of samples (pictures) in the video track, from `stsz`.
    ///
    /// One sample is one coded picture: multi-slice pictures are a single
    /// sample, so this is the picture count the capacity report needs -- the
    /// slice span list cannot give it.
    pub picture_count: usize,
    /// Video duration in seconds from `mdhd`.
    pub duration_secs: Option<f64>,
    /// Video frame rate (fps) from sample count and duration.
    pub fps: Option<f64>,
}

/// Target representation parsed from `moov` only, without reading `mdat`.
pub struct Mp4StreamTarget<'a> {
    pub parameter_sets: Vec<&'a [u8]>,
    pub length_size: usize,
    pub samples: Vec<(usize, usize)>,
    pub picture_count: usize,
    pub duration_secs: Option<f64>,
    pub fps: Option<f64>,
}

/// A parsed box header: tag, slice ranges of the box and of its payload.
struct BoxRef {
    tag: [u8; 4],
    payload_start: usize,
    end: usize,
}

/// Parse an MP4/MOV container and locate the HEVC parameter sets and the byte
/// spans of all slice NAL units of its first HEVC video track.
pub fn parse_mp4_targets(bytes: &[u8]) -> Result<Mp4HevcTarget<'_>> {
    // A fragmented file keeps its samples in `moof`/`traf`/`trun`, not in the
    // `stbl` tables below; the offsets there are relative to each fragment's
    // data offset. Probed with a tolerant walk first: a fragmented file often
    // has a box layout the strict walk rejects before ever reaching the table
    // it would misread.
    if top_level_has_moof(bytes) {
        return Err(HevcError::Unsupported(
            "fragmented MP4/MOV (moof/traf/trun) is not supported; remux to a \
             regular MP4 or an Annex-B stream",
        ));
    }

    let top = boxes_in(bytes, 0, bytes.len())?;

    let moov = top
        .iter()
        .find(|b| &b.tag == b"moov")
        .ok_or(HevcError::ContainerMalformed("missing moov box"))?;
    let moov_children = boxes_in(bytes, moov.payload_start, moov.end)?;
    // `mvex` announces movie fragments; the samples live in `moof` boxes that
    // may follow, so the `stbl` tables describe initial state only.
    if moov_children.iter().any(|b| &b.tag == b"mvex") {
        return Err(HevcError::Unsupported(
            "fragmented MP4/MOV (mvex in moov) is not supported",
        ));
    }

    // Deterministic track choice: the first `vide` track, in file order.
    // Multi-track files (iPhone MOV carries metadata tracks on top of video
    // and audio) must not depend on which trailer box came first.
    let mut video_tracks = 0usize;
    let mut last_error: Option<HevcError> = None;
    for trak in moov_children.iter().filter(|b| &b.tag == b"trak") {
        let trak_children = boxes_in(bytes, trak.payload_start, trak.end)?;
        if trak_children.iter().any(|b| &b.tag == b"traf") {
            return Err(HevcError::Unsupported(
                "fragmented MP4/MOV (traf inside trak) is not supported",
            ));
        }
        let Some(mdia) = trak_children.iter().find(|b| &b.tag == b"mdia") else {
            continue;
        };
        let mdia_children = boxes_in(bytes, mdia.payload_start, mdia.end)?;
        let Some(hdlr) = mdia_children.iter().find(|b| &b.tag == b"hdlr") else {
            continue;
        };
        // FullBox: version/flags (4) + pre_defined (4) + handler_type (4).
        let handler = be_u32(bytes, hdlr.payload_start.saturating_add(8));
        if handler != Some(u32::from_be_bytes(*b"vide")) {
            continue;
        }
        video_tracks += 1;
        match parse_video_trak(bytes, &mdia_children) {
            Ok(target) => return Ok(target),
            // Keep the first honest reason: a video track that is not HEVC
            // (avc1, av01) says more than a later track that is simply
            // missing boxes.
            Err(e) => {
                if last_error.is_none() {
                    last_error = Some(e);
                }
            }
        }
    }

    if video_tracks == 0 {
        return Err(HevcError::ContainerMalformed("no video track in moov"));
    }
    Err(last_error.unwrap_or(HevcError::ContainerMalformed("no HEVC video track in moov")))
}

/// Parse an MP4/MOV `moov` box buffer directly, without requiring `mdat` to be in memory.
pub fn parse_moov_target<'a>(moov_bytes: &'a [u8], file_len: usize) -> Result<Mp4StreamTarget<'a>> {
    let top = boxes_in(moov_bytes, 0, moov_bytes.len())?;
    let moov = top
        .iter()
        .find(|b| &b.tag == b"moov")
        .ok_or(HevcError::ContainerMalformed("missing moov box"))?;
    let moov_children = boxes_in(moov_bytes, moov.payload_start, moov.end)?;
    if moov_children.iter().any(|b| &b.tag == b"mvex") {
        return Err(HevcError::Unsupported(
            "fragmented MP4/MOV (mvex in moov) is not supported",
        ));
    }

    let mut video_tracks = 0usize;
    let mut last_error: Option<HevcError> = None;
    for trak in moov_children.iter().filter(|b| &b.tag == b"trak") {
        let trak_children = boxes_in(moov_bytes, trak.payload_start, trak.end)?;
        if trak_children.iter().any(|b| &b.tag == b"traf") {
            return Err(HevcError::Unsupported(
                "fragmented MP4/MOV (traf inside trak) is not supported",
            ));
        }
        let Some(mdia) = trak_children.iter().find(|b| &b.tag == b"mdia") else {
            continue;
        };
        let mdia_children = boxes_in(moov_bytes, mdia.payload_start, mdia.end)?;
        let Some(hdlr) = mdia_children.iter().find(|b| &b.tag == b"hdlr") else {
            continue;
        };
        let handler = be_u32(moov_bytes, hdlr.payload_start.saturating_add(8));
        if handler != Some(u32::from_be_bytes(*b"vide")) {
            continue;
        }
        video_tracks += 1;
        match parse_video_trak_stream(moov_bytes, &mdia_children, file_len) {
            Ok(target) => return Ok(target),
            Err(e) => {
                if last_error.is_none() {
                    last_error = Some(e);
                }
            }
        }
    }

    if video_tracks == 0 {
        return Err(HevcError::ContainerMalformed("no video track in moov"));
    }
    Err(last_error.unwrap_or(HevcError::ContainerMalformed("no HEVC video track in moov")))
}

fn parse_video_trak_stream<'a>(
    bytes: &'a [u8],
    mdia_children: &[BoxRef],
    file_len: usize,
) -> Result<Mp4StreamTarget<'a>> {
    let mdhd_timing = mdia_children
        .iter()
        .find(|b| &b.tag == b"mdhd")
        .and_then(|b| parse_mdhd(bytes, b));

    let minf = mdia_children
        .iter()
        .find(|b| &b.tag == b"minf")
        .ok_or(HevcError::ContainerMalformed("video track has no minf box"))?;
    let minf_children = boxes_in(bytes, minf.payload_start, minf.end)?;
    let stbl = minf_children
        .iter()
        .find(|b| &b.tag == b"stbl")
        .ok_or(HevcError::ContainerMalformed("video track has no stbl box"))?;
    let (parameter_sets, length_size, description_index) = {
        let kids = boxes_in(bytes, stbl.payload_start, stbl.end)?;
        let stsd = kids
            .iter()
            .find(|b| &b.tag == b"stsd")
            .ok_or(HevcError::ContainerMalformed("missing stsd box"))?;
        parse_sample_description(bytes, stsd)?
    };

    let kids = boxes_in(bytes, stbl.payload_start, stbl.end)?;
    let stsz = kids
        .iter()
        .find(|b| &b.tag == b"stsz")
        .ok_or(HevcError::ContainerMalformed("missing stsz box"))?;
    let sizes = parse_sample_sizes(bytes, stsz)?;
    let sample_count = sizes.len();

    let chunk_offsets = if let Some(co64) = kids.iter().find(|b| &b.tag == b"co64") {
        parse_chunk_offsets(bytes, co64, true)?
    } else if let Some(stco) = kids.iter().find(|b| &b.tag == b"stco") {
        parse_chunk_offsets(bytes, stco, false)?
    } else {
        return Err(HevcError::ContainerMalformed(
            "missing stco/co64 chunk offset box",
        ));
    };

    let stsc = kids
        .iter()
        .find(|b| &b.tag == b"stsc")
        .ok_or(HevcError::ContainerMalformed("missing stsc box"))?;
    let runs = parse_sample_to_chunk(bytes, stsc)?;

    let samples =
        resolve_sample_offsets(file_len, &sizes, &chunk_offsets, &runs, description_index)?;

    let mut target = Mp4StreamTarget {
        parameter_sets,
        length_size,
        samples,
        picture_count: sample_count,
        duration_secs: None,
        fps: None,
    };

    if let Some((timescale, duration)) = mdhd_timing.filter(|(ts, _)| *ts > 0) {
        let sec = duration as f64 / timescale as f64;
        target.duration_secs = Some(sec);
        if sec > 0.0 && sample_count > 0 {
            target.fps = Some(sample_count as f64 / sec);
        }
    }

    Ok(target)
}

/// Parse one `vide` track: `mdia/minf/stbl`.
fn parse_video_trak<'a>(bytes: &'a [u8], mdia_children: &[BoxRef]) -> Result<Mp4HevcTarget<'a>> {
    let mdhd_timing = mdia_children
        .iter()
        .find(|b| &b.tag == b"mdhd")
        .and_then(|b| parse_mdhd(bytes, b));

    let minf = mdia_children
        .iter()
        .find(|b| &b.tag == b"minf")
        .ok_or(HevcError::ContainerMalformed("video track has no minf box"))?;
    let minf_children = boxes_in(bytes, minf.payload_start, minf.end)?;
    let stbl = minf_children
        .iter()
        .find(|b| &b.tag == b"stbl")
        .ok_or(HevcError::ContainerMalformed("video track has no stbl box"))?;
    let (mut target, sample_count) = parse_stbl(bytes, stbl)?;
    target.picture_count = sample_count;

    if let Some((timescale, duration)) = mdhd_timing.filter(|(ts, _)| *ts > 0) {
        let sec = duration as f64 / timescale as f64;
        target.duration_secs = Some(sec);
        if sec > 0.0 && sample_count > 0 {
            target.fps = Some(sample_count as f64 / sec);
        }
    }

    Ok(target)
}

fn parse_mdhd(bytes: &[u8], mdhd: &BoxRef) -> Option<(u32, u64)> {
    let p = mdhd.payload_start;
    if p + 4 > mdhd.end || p + 4 > bytes.len() {
        return None;
    }
    let version = bytes[p];
    if version == 0 {
        if p + 20 > mdhd.end || p + 20 > bytes.len() {
            return None;
        }
        let timescale = be_u32(bytes, p + 12)?;
        let duration = be_u32(bytes, p + 16)? as u64;
        Some((timescale, duration))
    } else if version == 1 {
        if p + 32 > mdhd.end || p + 32 > bytes.len() {
            return None;
        }
        let timescale = be_u32(bytes, p + 20)?;
        let duration = be_u64(bytes, p + 24)?;
        Some((timescale, duration))
    } else {
        None
    }
}

/// Parse `stbl`: sample description (`hvcC`), sizes, chunk offsets and the
/// sample-to-chunk map, then resolve every VCL NAL to a file span.
fn parse_stbl<'a>(bytes: &'a [u8], stbl: &BoxRef) -> Result<(Mp4HevcTarget<'a>, usize)> {
    let kids = boxes_in(bytes, stbl.payload_start, stbl.end)?;

    if kids.iter().any(|b| &b.tag == b"stz2") && !kids.iter().any(|b| &b.tag == b"stsz") {
        return Err(HevcError::Unsupported(
            "compact sample size box (stz2) is not supported; only stsz",
        ));
    }

    let stsd = kids
        .iter()
        .find(|b| &b.tag == b"stsd")
        .ok_or(HevcError::ContainerMalformed("missing stsd box"))?;
    let (parameter_sets, length_size, description_index) = parse_sample_description(bytes, stsd)?;

    let stsz = kids
        .iter()
        .find(|b| &b.tag == b"stsz")
        .ok_or(HevcError::ContainerMalformed("missing stsz box"))?;
    let sizes = parse_sample_sizes(bytes, stsz)?;
    let sample_count = sizes.len();

    // 64-bit offsets win when both are present: a file that had to grow past
    // 4 GiB carries `co64`, and a stale `stco` beside it would be wrong.
    let chunk_offsets = if let Some(co64) = kids.iter().find(|b| &b.tag == b"co64") {
        parse_chunk_offsets(bytes, co64, true)?
    } else if let Some(stco) = kids.iter().find(|b| &b.tag == b"stco") {
        parse_chunk_offsets(bytes, stco, false)?
    } else {
        return Err(HevcError::ContainerMalformed(
            "missing stco/co64 chunk offset box",
        ));
    };

    let stsc = kids
        .iter()
        .find(|b| &b.tag == b"stsc")
        .ok_or(HevcError::ContainerMalformed("missing stsc box"))?;
    let runs = parse_sample_to_chunk(bytes, stsc)?;

    let samples = resolve_sample_offsets(
        bytes.len(),
        &sizes,
        &chunk_offsets,
        &runs,
        description_index,
    )?;

    let mut slice_spans = Vec::new();
    for (offset, size) in samples {
        collect_sample_slice_spans(bytes, offset, size, length_size, &mut slice_spans)?;
    }

    if slice_spans.is_empty() {
        return Err(HevcError::NoSlices);
    }

    Ok((
        Mp4HevcTarget {
            parameter_sets,
            length_size,
            slice_spans,
            picture_count: sample_count,
            duration_secs: None,
            fps: None,
        },
        sample_count,
    ))
}

/// Locate the HEVC sample entry in `stsd` and parse its `hvcC`.
///
/// Returns the parameter sets, the NAL length prefix size and the 1-based
/// `sample_description_index` of the chosen entry, which every `stsc` run must
/// reference (a run pointing at a different entry would describe samples with
/// another codec's NAL length framing).
fn parse_sample_description<'a>(
    bytes: &'a [u8],
    stsd: &BoxRef,
) -> Result<(Vec<&'a [u8]>, usize, u32)> {
    // FullBox: version/flags (4) + entry_count (4) + entries.
    let payload = bytes
        .get(stsd.payload_start..stsd.end)
        .ok_or(HevcError::Truncated)?;
    if payload.len() < 8 {
        return Err(HevcError::Truncated);
    }
    let entry_count = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    let mut pos = 8usize;
    let mut chosen: Option<(usize, usize, u32)> = None;

    for index in 0..entry_count {
        if pos + 8 > payload.len() {
            return Err(HevcError::Truncated);
        }
        let size = u32::from_be_bytes([
            payload[pos],
            payload[pos + 1],
            payload[pos + 2],
            payload[pos + 3],
        ]) as usize;
        let tag = &payload[pos + 4..pos + 8];
        if size < 8 || pos.checked_add(size).is_none_or(|end| end > payload.len()) {
            return Err(HevcError::ContainerMalformed("invalid sample entry size"));
        }
        if tag == b"encv" {
            return Err(HevcError::Unsupported(
                "encrypted video track (encv sample entry) is not supported",
            ));
        }
        if chosen.is_none() && HEVC_SAMPLE_ENTRIES.iter().any(|t| *t == tag) {
            // Indexes into `bytes`, not into `payload`: the slice starts at
            // `stsd.payload_start`.
            let start = stsd.payload_start + pos;
            chosen = Some((start, start + size, index as u32 + 1));
        }
        pos += size;
    }

    let (entry_start, entry_end, description_index) = chosen.ok_or(HevcError::Unsupported(
        "video track sample entry is not HEVC (hvc1/hev1)",
    ))?;

    // `sinf` inside the sample entry means the bitstream is protected; the
    // `hvcC` beside it may still describe the pre-encryption stream, so
    // rewriting CABAC data here would produce a file no decoder can use.
    let child_start = entry_start.saturating_add(VISUAL_SAMPLE_ENTRY_HEADER);
    if child_start > entry_end {
        return Err(HevcError::Truncated);
    }
    let children = boxes_in(bytes, child_start, entry_end)?;
    if children.iter().any(|b| &b.tag == b"sinf") {
        return Err(HevcError::Unsupported(
            "encrypted video track (sinf protection) is not supported",
        ));
    }
    let hvcc = children
        .iter()
        .find(|b| &b.tag == b"hvcC")
        .ok_or(HevcError::ContainerMalformed("missing hvcC box"))?;
    let hvcc_bytes = bytes
        .get(hvcc.payload_start..hvcc.end)
        .ok_or(HevcError::Truncated)?;
    let (parameter_sets, length_size) = parse_hvcc_record(hvcc_bytes)?;
    // Some writers put a prefix SEI array in `hvcC` too (both sample files in
    // the corpus do). Only VPS/SPS/PPS are parameter sets in the sense the
    // decoder and the cover digest need; feeding the SEI array would duplicate
    // metadata that is not part of the carrier's identity.
    let parameter_sets: Vec<&[u8]> = parameter_sets
        .into_iter()
        .filter(|ps| ps.len() > 2 && matches!((ps[0] >> 1) & 0x3F, 32..=34))
        .collect();
    if parameter_sets.is_empty() {
        return Err(HevcError::ContainerMalformed("hvcC carries no VPS/SPS/PPS"));
    }
    if !(1..=4).contains(&length_size) {
        return Err(HevcError::InvalidData("hvcC length_size out of range"));
    }

    Ok((parameter_sets, length_size, description_index))
}

/// Parse `stsz` (Sample Size Box): either one fixed size or a per-sample table.
fn parse_sample_sizes(bytes: &[u8], stsz: &BoxRef) -> Result<Vec<u32>> {
    // FullBox: version/flags (4) + sample_size (4) + sample_count (4) + table.
    let payload = bytes
        .get(stsz.payload_start..stsz.end)
        .ok_or(HevcError::Truncated)?;
    if payload.len() < 12 {
        return Err(HevcError::Truncated);
    }
    let fixed = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let count = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]) as usize;
    if fixed != 0 {
        return Ok(vec![fixed; count]);
    }
    // A declared count larger than the box can hold is malformed: `sizes`
    // would silently end short and every later sample would shift.
    let available = (payload.len() - 12) / 4;
    if count > available {
        return Err(HevcError::Truncated);
    }
    let mut sizes = Vec::with_capacity(count);
    for i in 0..count {
        let off = 12 + i * 4;
        sizes.push(u32::from_be_bytes([
            payload[off],
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
        ]));
    }
    Ok(sizes)
}

/// Parse `stco` (32-bit) or `co64` (64-bit) chunk offsets.
fn parse_chunk_offsets(bytes: &[u8], stco: &BoxRef, wide: bool) -> Result<Vec<u64>> {
    let payload = bytes
        .get(stco.payload_start..stco.end)
        .ok_or(HevcError::Truncated)?;
    if payload.len() < 8 {
        return Err(HevcError::Truncated);
    }
    let count = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    let width = if wide { 8 } else { 4 };
    if (payload.len() - 8) / width < count {
        return Err(HevcError::Truncated);
    }
    let mut offsets = Vec::with_capacity(count);
    for i in 0..count {
        let off = 8 + i * width;
        let value = if wide {
            be_u64(payload, off).ok_or(HevcError::Truncated)?
        } else {
            be_u32(payload, off).ok_or(HevcError::Truncated)? as u64
        };
        offsets.push(value);
    }
    Ok(offsets)
}

/// Parse `stsc` (Sample To Chunk Box) into `(first_chunk, samples_per_chunk,
/// sample_description_index)` runs, 1-based chunk numbers as stored.
fn parse_sample_to_chunk(bytes: &[u8], stsc: &BoxRef) -> Result<Vec<(u32, u32, u32)>> {
    let payload = bytes
        .get(stsc.payload_start..stsc.end)
        .ok_or(HevcError::Truncated)?;
    if payload.len() < 8 {
        return Err(HevcError::Truncated);
    }
    let count = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    if (payload.len() - 8) / 12 < count {
        return Err(HevcError::Truncated);
    }
    let mut runs = Vec::with_capacity(count);
    for i in 0..count {
        let off = 8 + i * 12;
        let first = u32::from_be_bytes([
            payload[off],
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
        ]);
        let per = u32::from_be_bytes([
            payload[off + 4],
            payload[off + 5],
            payload[off + 6],
            payload[off + 7],
        ]);
        let desc = u32::from_be_bytes([
            payload[off + 8],
            payload[off + 9],
            payload[off + 10],
            payload[off + 11],
        ]);
        if first == 0 || per == 0 {
            return Err(HevcError::ContainerMalformed(
                "stsc run has a zero first_chunk or samples_per_chunk",
            ));
        }
        if let Some(&(prev, _, _)) = runs.last()
            && first <= prev
        {
            return Err(HevcError::ContainerMalformed(
                "stsc first_chunk values are not strictly increasing",
            ));
        }
        runs.push((first, per, desc));
    }
    Ok(runs)
}

/// Resolve every sample to its absolute `(offset, size)` in the file.
///
/// Chunk `c` (1-based) starts at `chunk_offsets[c - 1]` and holds
/// `samples_per_chunk` consecutive samples; each sample's offset follows the
/// previous sample's size. The total number of samples implied by `stsc` must
/// equal the `stsz` count — a mismatch means the tables disagree and any span
/// derived from them would be a guess.
fn resolve_sample_offsets(
    file_len: usize,
    sizes: &[u32],
    chunk_offsets: &[u64],
    runs: &[(u32, u32, u32)],
    description_index: u32,
) -> Result<Vec<(usize, usize)>> {
    if sizes.is_empty() {
        return Err(HevcError::NoSlices);
    }
    if runs.is_empty() {
        return Err(HevcError::ContainerMalformed("stsc has no runs"));
    }

    let mut samples = Vec::with_capacity(sizes.len());
    let mut sample_idx = 0usize;

    for (run_idx, &(first_chunk, per_chunk, desc)) in runs.iter().enumerate() {
        if desc != description_index {
            return Err(HevcError::Unsupported(
                "samples reference more than one sample description; only a single \
                 HEVC entry is supported",
            ));
        }
        // Chunks after this run's first until the next run's first.
        let last_chunk = match runs.get(run_idx + 1) {
            Some(&(next_first, _, _)) => next_first.saturating_sub(1),
            None => chunk_offsets.len() as u32,
        };
        if last_chunk < first_chunk {
            return Err(HevcError::ContainerMalformed("stsc run covers no chunk"));
        }
        for chunk in first_chunk..=last_chunk {
            let chunk_index = (chunk - 1) as usize;
            let Some(&chunk_offset) = chunk_offsets.get(chunk_index) else {
                // `stsc` names a chunk `stco`/`co64` does not list.
                return Err(HevcError::ContainerMalformed(
                    "stsc references a chunk missing from stco/co64",
                ));
            };
            let mut offset = usize::try_from(chunk_offset).map_err(|_| HevcError::TooLarge)?;
            for _ in 0..per_chunk {
                let Some(&size) = sizes.get(sample_idx) else {
                    // More samples implied than `stsz` declares.
                    return Err(HevcError::ContainerMalformed(
                        "stsc implies more samples than stsz declares",
                    ));
                };
                let size = size as usize;
                if offset.checked_add(size).is_none_or(|end| end > file_len) {
                    return Err(HevcError::Truncated);
                }
                samples.push((offset, size));
                offset += size;
                sample_idx += 1;
            }
        }
    }

    if sample_idx != sizes.len() {
        return Err(HevcError::ContainerMalformed(
            "stsc implies fewer samples than stsz declares",
        ));
    }
    Ok(samples)
}

/// Split one sample into length-prefixed NAL units and keep the VCL spans.
///
/// The leading length prefix is deliberately excluded from the span: it is
/// container framing, not part of the NAL, and the engine guarantees the
/// re-encoded NAL keeps its length (Δ = 0), so the prefix stays valid.
pub(crate) fn collect_sample_slice_spans(
    bytes: &[u8],
    offset: usize,
    size: usize,
    length_size: usize,
    out: &mut Vec<PhysicalNalSpan>,
) -> Result<()> {
    if !(1..=4).contains(&length_size) {
        return Err(HevcError::InvalidData("unsupported length_size"));
    }
    let end = offset.checked_add(size).ok_or(HevcError::Truncated)?;
    if end > bytes.len() {
        return Err(HevcError::Truncated);
    }
    let mut pos = offset;
    while pos + length_size <= end {
        let nal_len = match length_size {
            1 => bytes[pos] as usize,
            2 => be_u16(bytes, pos).ok_or(HevcError::Truncated)? as usize,
            3 => {
                let b = bytes.get(pos..pos + 3).ok_or(HevcError::Truncated)?;
                ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize
            }
            _ => be_u32(bytes, pos).ok_or(HevcError::Truncated)? as usize,
        };
        let nal_start = pos + length_size;
        let nal_end = nal_start.checked_add(nal_len).ok_or(HevcError::Truncated)?;
        if nal_end > end {
            return Err(HevcError::Truncated);
        }
        if nal_len >= 2 {
            let b0 = bytes[nal_start];
            let b1 = bytes[nal_start + 1];
            let nal_type = (b0 >> 1) & 0x3F;
            let tid_plus1 = b1 & 0x07;
            // Same acceptance rule as the Annex-B and HEIF parsers: VCL only,
            // `forbidden_zero_bit` clear, non-zero temporal id.
            if nal_type <= 31 && (b0 & 0x80) == 0 && tid_plus1 > 0 {
                out.push(PhysicalNalSpan {
                    start: nal_start,
                    len: nal_len,
                });
            }
        }
        pos = nal_end;
    }

    // A sample either ends exactly on a NAL boundary or carries zero padding
    // (some writers emit trailing zero bytes). Anything else means the length
    // prefixes disagree with the sample size and the spans are unreliable.
    if pos < end && bytes[pos..end].iter().any(|b| *b != 0) {
        return Err(HevcError::InvalidData(
            "sample has trailing bytes after its last NAL unit",
        ));
    }
    Ok(())
}

/// Does the top level contain a `moof` box?
///
/// This is a *tolerant* walk: it stops at the first malformed box instead of
/// reporting it. Its only job is to distinguish "fragmented, unsupported" from
/// "malformed", and a fragmented file may well contain boxes that the strict
/// walk cannot size.
fn top_level_has_moof(bytes: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos + 8 <= bytes.len() {
        let Some(size32) = be_u32(bytes, pos) else {
            return false;
        };
        if &bytes[pos + 4..pos + 8] == b"moof" {
            return true;
        }
        let (header_len, total_size) = if size32 == 1 {
            match be_u64(bytes, pos + 8) {
                Some(size64) => (16usize, usize::try_from(size64).unwrap_or(0)),
                None => return false,
            }
        } else if size32 == 0 {
            return false;
        } else {
            (8usize, size32 as usize)
        };
        if total_size < header_len
            || pos
                .checked_add(total_size)
                .is_none_or(|end| end > bytes.len())
        {
            return false;
        }
        pos += total_size;
    }
    false
}

/// Read the direct children of `[start, end)` strictly.
///
/// Unlike the HEIF walker this does not silently stop at a malformed box: an
/// MP4 sample table lives at the end of the file and a truncated box there
/// means the offsets cannot be trusted, so a partial walk is reported.
fn boxes_in(bytes: &[u8], start: usize, end: usize) -> Result<Vec<BoxRef>> {
    let mut out = Vec::new();
    let mut pos = start;
    let limit = end.min(bytes.len());
    while pos + 8 <= limit {
        let size32 = be_u32(bytes, pos).ok_or(HevcError::Truncated)?;
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&bytes[pos + 4..pos + 8]);
        let (header_len, total_size) = if size32 == 1 {
            let Some(size64) = be_u64(bytes, pos + 8) else {
                return Err(HevcError::Truncated);
            };
            (
                16usize,
                usize::try_from(size64).map_err(|_| {
                    HevcError::ContainerMalformed("64-bit box size does not fit in usize")
                })?,
            )
        } else if size32 == 0 {
            // `size == 0` means "extends to the end of the enclosing box".
            (8usize, limit - pos)
        } else {
            (8usize, size32 as usize)
        };
        if total_size < header_len
            || pos
                .checked_add(total_size)
                .is_none_or(|box_end| box_end > limit)
        {
            return Err(HevcError::ContainerMalformed("invalid box size"));
        }
        out.push(BoxRef {
            tag,
            payload_start: pos + header_len,
            end: pos + total_size,
        });
        pos += total_size;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be_box(tag: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + payload.len());
        v.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
        v.extend_from_slice(tag);
        v.extend_from_slice(payload);
        v
    }

    /// A `hvcC` record with one array each for VPS, SPS and PPS.
    fn hvcc(nals: &[&[u8]]) -> Vec<u8> {
        let mut p = vec![0u8; 23];
        p[0] = 1; // configurationVersion
        p[21] = 3; // lengthSizeMinusOne -> 4-byte NAL lengths
        p[22] = nals.len() as u8;
        for (i, nal) in nals.iter().enumerate() {
            p.push(32 + i as u8); // array_completeness = 0, NAL type 32..34
            p.extend_from_slice(&1u16.to_be_bytes()); // numNalus
            p.extend_from_slice(&(nal.len() as u16).to_be_bytes());
            p.extend_from_slice(nal);
        }
        p
    }

    /// `stbl` for a single-sample, single-chunk HEVC track. `chunk_offset` is
    /// the absolute file offset of the sample, which the test layout knows.
    fn stbl_boxes(sample_len: usize, chunk_offset: u32) -> Vec<u8> {
        let mut entry = vec![0u8; VISUAL_SAMPLE_ENTRY_HEADER];
        entry.extend_from_slice(&be_box(
            b"hvcC",
            &hvcc(&[
                &[0x40, 0x01, 0x0C],
                &[0x42, 0x01, 0x01],
                &[0x44, 0x01, 0xC0],
            ]),
        ));
        let entry_len = entry.len() as u32;
        entry[0..4].copy_from_slice(&entry_len.to_be_bytes());
        entry[4..8].copy_from_slice(b"hvc1");

        let mut stsd = vec![0u8, 0, 0, 0];
        stsd.extend_from_slice(&1u32.to_be_bytes());
        stsd.extend_from_slice(&entry);

        let mut stsz = vec![0u8, 0, 0, 0];
        stsz.extend_from_slice(&0u32.to_be_bytes()); // variable sizes
        stsz.extend_from_slice(&1u32.to_be_bytes()); // sample_count
        stsz.extend_from_slice(&(sample_len as u32).to_be_bytes());

        let mut stsc = vec![0u8, 0, 0, 0];
        stsc.extend_from_slice(&1u32.to_be_bytes()); // entry_count
        stsc.extend_from_slice(&1u32.to_be_bytes()); // first_chunk
        stsc.extend_from_slice(&1u32.to_be_bytes()); // samples_per_chunk
        stsc.extend_from_slice(&1u32.to_be_bytes()); // sample_description_index

        let mut stco = vec![0u8, 0, 0, 0];
        stco.extend_from_slice(&1u32.to_be_bytes()); // entry_count
        stco.extend_from_slice(&chunk_offset.to_be_bytes());

        [
            be_box(b"stsd", &stsd),
            be_box(b"stsz", &stsz),
            be_box(b"stsc", &stsc),
            be_box(b"stco", &stco),
        ]
        .concat()
    }

    /// `ftyp` (16 bytes) + `mdat` (8 + sample) + `moov`: the sample starts at
    /// 24 and the metadata lives after the media data -- the shape every
    /// phone recording in the corpus uses.
    fn tiny_mp4(slice: &[u8]) -> Vec<u8> {
        let mut sample = Vec::new();
        sample.extend_from_slice(&((2 + slice.len()) as u32).to_be_bytes());
        sample.extend_from_slice(&[0x26, 0x01]); // IDR_W_RADL, temporal id 0
        sample.extend_from_slice(slice);

        let ftyp = be_box(b"ftyp", b"isomisom");
        let mdat = be_box(b"mdat", &sample);
        let sample_offset = (ftyp.len() + 8) as u32;

        let stbl = stbl_boxes(sample.len(), sample_offset);
        let minf = be_box(b"minf", &be_box(b"stbl", &stbl));
        let mut hdlr_payload = vec![0u8; 8];
        hdlr_payload.extend_from_slice(b"vide");
        hdlr_payload.extend_from_slice(&[0u8; 13]);
        let mdia = be_box(b"mdia", &[be_box(b"hdlr", &hdlr_payload), minf].concat());
        let moov = be_box(b"moov", &be_box(b"trak", &mdia));

        [ftyp, mdat, moov].concat()
    }

    /// Offset of the payload of the first box whose tag is `tag`.
    fn payload_of(data: &[u8], tag: &[u8; 4]) -> usize {
        data.windows(4)
            .position(|w| w == tag)
            .map(|i| i + 4)
            .expect("tag present")
    }

    #[test]
    fn parses_a_minimal_hev1_container() {
        let file = tiny_mp4(&[0xAA; 16]);
        let target = parse_mp4_targets(&file).expect("parse");
        assert_eq!(target.length_size, 4);
        assert_eq!(target.parameter_sets.len(), 3);
        assert_eq!(target.parameter_sets[0], &[0x40, 0x01, 0x0C]);
        assert_eq!(target.slice_spans.len(), 1);
        let span = target.slice_spans[0];
        assert_eq!(&file[span.start..span.start + 2], &[0x26, 0x01]);
        // 4-byte length prefix, then the 2-byte NAL header + 16 payload bytes.
        assert_eq!(span.len, 18);
        assert_eq!(span.start, 24 + 4);
    }

    #[test]
    fn truncated_inputs_never_panic() {
        let file = tiny_mp4(&[0x55; 8]);
        for cut in 0..file.len() {
            let _ = parse_mp4_targets(&file[..cut]);
        }
    }

    #[test]
    fn fragmented_mp4_is_rejected() {
        let file = tiny_mp4(&[0x55; 8]);
        let mut fragmented = file.clone();
        fragmented.extend_from_slice(&be_box(b"moof", &[0u8; 8]));
        assert!(matches!(
            parse_mp4_targets(&fragmented),
            Err(HevcError::Unsupported(_))
        ));
    }

    #[test]
    fn sample_table_disagreement_is_an_error() {
        // samples_per_chunk = 2 while stsz declares a single sample: the
        // tables disagree, so no span derived from them can be trusted.
        let mut file = tiny_mp4(&[0x55; 8]);
        let stsc = payload_of(&file, b"stsc");
        file[stsc + 8..stsc + 12].copy_from_slice(&2u32.to_be_bytes());
        assert!(matches!(
            parse_mp4_targets(&file),
            Err(HevcError::ContainerMalformed(_))
        ));
    }

    #[test]
    fn sample_entry_without_hvcc_is_an_error() {
        let mut file = tiny_mp4(&[0x55; 8]);
        let hvcc_pos = payload_of(&file, b"hvcC") - 4;
        file[hvcc_pos..hvcc_pos + 4].copy_from_slice(b"free");
        assert!(matches!(
            parse_mp4_targets(&file),
            Err(HevcError::ContainerMalformed(_))
        ));
    }

    #[test]
    fn non_video_handler_is_not_accepted() {
        // The only track is marked as audio: there is no video track at all.
        let mut file = tiny_mp4(&[0x55; 8]);
        let hdlr = payload_of(&file, b"hdlr");
        file[hdlr + 8..hdlr + 12].copy_from_slice(b"soun");
        assert!(matches!(
            parse_mp4_targets(&file),
            Err(HevcError::ContainerMalformed(_))
        ));
    }
}
