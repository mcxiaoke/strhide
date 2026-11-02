//! Zero-copy Matroska (MKV/WebM) scanner for Scheme C.
//!
//! # Why a purpose-built scanner instead of a demuxer crate
//!
//! The engine needs exactly one thing from the container: the **absolute byte
//! span of every VCL NAL unit**, so the CABAC rewriter can flip signs in place
//! while the file stays byte-identical. Playback-oriented demuxers
//! (`matroska-demuxer`, `symphonia`, libavformat) hand out decoded packets and
//! discard the offsets; re-muxing to get a file back would rewrite Cluster
//! layout, `Cues` and `SeekHead`, which is precisely what this project must not
//! do. `ebml-iterable` does expose tag positions, but its data model copies
//! every tag payload into a `Vec` and does not carry the payload offset, so the
//! span arithmetic would have to be re-derived anyway.
//!
//! What is left is the walk below: ~300 lines over `&[u8]`, no allocation per
//! block, reusing the VINT semantics already implemented for the structure
//! domain in [`crate::structure::adapters::ebml`] (`encode_vint` there is the
//! inverse of [`read_vint_size`] here).
//!
//! # Robustness contract
//!
//! This parses **untrusted input**: every size and offset is attacker
//! controlled. There is no `unwrap`/`expect`/panic; a malformed element ends
//! the walk and is reported as [`HevcError`]. Sizes are clamped to the parent's
//! end so a forged length cannot make the scanner read outside its slice.
//!
//! # Explicitly rejected
//!
//! * Tracks with `ContentEncodings` (header stripping / compression / encryption)
//!   -- the per-block payload is not what the `hvcC` length prefixes describe.
//! * Blocks with lacing -- the frame boundaries inside the block would need a
//!   second layer of parsing for no practical gain on a video track.
//! * Codec IDs other than `V_MPEGH/ISO/HEVC`.

use std::ops::Range;

use crate::stego::hevc::error::{HevcError, Result};
use crate::stego::hevc::heif_boxes::{PhysicalNalSpan, parse_hvcc_record};

/// `EBML` header element.
const ID_EBML: u32 = 0x1A45_DFA3;
/// `Segment` master element.
const ID_SEGMENT: u32 = 0x1853_8067;
/// `Tracks` master element.
const ID_TRACKS: u32 = 0x1654_AE6B;
/// `TrackEntry` master element.
const ID_TRACK_ENTRY: u32 = 0xAE;
/// `TrackNumber`.
const ID_TRACK_NUMBER: u32 = 0xD7;
/// `TrackType` (1 = video).
const ID_TRACK_TYPE: u32 = 0x83;
/// `CodecID` (ASCII).
const ID_CODEC_ID: u32 = 0x86;
/// `CodecPrivate` (binary).
const ID_CODEC_PRIVATE: u32 = 0x63A2;
/// `ContentEncodings` master element.
const ID_CONTENT_ENCODINGS: u32 = 0x6D80;
/// `Cluster` master element.
const ID_CLUSTER: u32 = 0x1F43_B675;
/// `SimpleBlock`.
const ID_SIMPLE_BLOCK: u32 = 0xA3;
/// `BlockGroup` master element.
const ID_BLOCK_GROUP: u32 = 0xA0;
/// `Block` inside a `BlockGroup`.
const ID_BLOCK: u32 = 0xA1;
/// `CRC-32` element.
const ID_CRC32: u32 = 0xBF;
/// `DocType` inside the EBML header.
const ID_DOC_TYPE: u32 = 0x4282;
/// `Info` master element (Level 1).
const ID_INFO: u32 = 0x1549_A966;
/// `SeekHead` master element (Level 1).
const ID_SEEK_HEAD: u32 = 0x114D_9B74;
/// `Cues` master element (Level 1).
const ID_CUES: u32 = 0x1C53_BB6B;
/// `Attachments` master element (Level 1).
const ID_ATTACHMENTS: u32 = 0x1941_A469;
/// `Chapters` master element (Level 1).
const ID_CHAPTERS: u32 = 0x1043_A770;
/// `Tags` master element (Level 1).
const ID_TAGS: u32 = 0x1254_C367;

#[inline]
fn is_level1_element(id: u32) -> bool {
    matches!(
        id,
        ID_CLUSTER
            | ID_INFO
            | ID_TRACKS
            | ID_SEEK_HEAD
            | ID_CUES
            | ID_ATTACHMENTS
            | ID_CHAPTERS
            | ID_TAGS
    )
}

/// The only `CodecID` this module accepts.
const CODEC_ID_HEVC: &[u8] = b"V_MPEGH/ISO/HEVC";

/// Byte order a muxer used to store a `CRC-32` value.
///
/// EBML describes the element as a 32-bit binary value and real muxers
/// disagree: libavformat writes it little-endian, `mkvmerge` writes
/// big-endian, and the common demuxers accept both. Rather than pick a side,
/// the byte order is detected from the file itself (see [`collect_crc`]) so a
/// rewrite never changes a carrier's convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrcEndian {
    Big,
    Little,
}

/// A `CRC-32` element and the byte range it covers.
///
/// RFC 9559: the checksum is the first child of its parent and covers
/// everything the parent holds except the `CRC-32` element itself, i.e. from
/// the end of the checksum element to the parent's end.
#[derive(Debug, Clone)]
pub(crate) struct MkvCrc {
    /// Offset of the 4-byte checksum value.
    pub value_offset: usize,
    /// Bytes the value is computed over.
    pub covers: Range<usize>,
    /// Detected byte order, or `None` when the stored value matches neither
    /// interpretation (the muxer left a stale checksum). A stale element is
    /// never rewritten: turning an already-invalid checksum into a valid one
    /// would be a bigger change than leaving the file as it was.
    pub endian: Option<CrcEndian>,
}

/// Extracted Matroska carrier information ready for Scheme C steganography.
#[derive(Debug)]
pub(crate) struct MkvHevcTarget<'a> {
    /// VPS/SPS/PPS from the track's `CodecPrivate` (`HEVCDecoderConfigurationRecord`).
    pub parameter_sets: Vec<&'a [u8]>,
    /// Physical span of every VCL NAL unit of the video track, in decode order.
    pub slice_spans: Vec<PhysicalNalSpan>,
    /// Every `CRC-32` element in the file, with its coverage.
    pub crcs: Vec<MkvCrc>,
}

/// One EBML element located inside the file.
#[derive(Debug, Clone, Copy)]
struct Element {
    id: u32,
    /// Absolute offset of the element's ID header.
    header_at: usize,
    /// Offset of the first payload byte.
    payload: usize,
    /// Declared payload length, clamped to the parent's end.
    len: usize,
    /// Whether the element had an "unknown" size VINT (streaming).
    unknown_size: bool,
}

impl Element {
    fn end(&self) -> usize {
        self.payload.saturating_add(self.len)
    }
}

/// Read an EBML element ID (1..=4 bytes, leading length marker preserved).
fn read_id(bytes: &[u8], pos: usize) -> Option<(u32, usize)> {
    let first = *bytes.get(pos)?;
    if first == 0 {
        return None;
    }
    let len = first.leading_zeros() as usize + 1;
    if len > 4 || pos + len > bytes.len() {
        return None;
    }
    let mut id = first as u32;
    for i in 1..len {
        id = (id << 8) | bytes[pos + i] as u32;
    }
    Some((id, len))
}

/// Read an EBML data-size VINT. `None` payload = "unknown size" (streaming).
fn read_vint_size(bytes: &[u8], pos: usize) -> Option<(Option<u64>, usize)> {
    let first = *bytes.get(pos)?;
    if first == 0 {
        return None;
    }
    let len = first.leading_zeros() as usize + 1;
    if len > 8 || pos + len > bytes.len() {
        return None;
    }
    let mask = (1u8 << (8 - len)) - 1;
    let mut value = (first & mask) as u64;
    let mut all_ones = (first & mask) == mask;
    for i in 1..len {
        let byte = bytes[pos + i];
        value = (value << 8) | byte as u64;
        if byte != 0xFF {
            all_ones = false;
        }
    }
    Some(((!all_ones).then_some(value), len))
}

/// Read an unsigned integer payload of 1..=8 bytes (big endian).
fn read_uint(bytes: &[u8], element: &Element) -> Option<u64> {
    let payload = bytes.get(element.payload..element.end())?;
    if payload.is_empty() || payload.len() > 8 {
        return None;
    }
    let mut value = 0u64;
    for &byte in payload {
        value = (value << 8) | byte as u64;
    }
    Some(value)
}

/// Parse the element at `pos`, clamping its payload to `parent_end`.
fn read_element(bytes: &[u8], pos: usize, parent_end: usize) -> Option<Element> {
    let (id, id_len) = read_id(bytes, pos)?;
    let (size, size_len) = read_vint_size(bytes, pos + id_len)?;
    let payload = pos + id_len + size_len;
    if payload > parent_end || payload > bytes.len() {
        return None;
    }
    let unknown_size = size.is_none();
    let declared = match size {
        // Unknown size: the element runs to its parent's end. Only `Segment`
        // and `Cluster` legitimately do this (live/streaming muxers).
        None => parent_end.saturating_sub(payload),
        Some(size) => {
            let size = usize::try_from(size).ok()?;
            size.min(parent_end.saturating_sub(payload))
        }
    };
    Some(Element {
        id,
        header_at: pos,
        payload,
        len: declared,
        unknown_size,
    })
}

/// Iterate the children of a master element.
struct Children<'a> {
    bytes: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Children<'a> {
    fn new(bytes: &'a [u8], start: usize, end: usize) -> Self {
        Self {
            bytes,
            pos: start,
            end: end.min(bytes.len()),
        }
    }
}

impl Iterator for Children<'_> {
    type Item = Element;

    fn next(&mut self) -> Option<Element> {
        if self.pos >= self.end {
            return None;
        }
        let element = read_element(self.bytes, self.pos, self.end)?;
        // A zero-length element at the same offset would spin forever; the
        // header is at least two bytes, so `end()` always advances.
        let next = element.end().max(self.pos + 2);
        self.pos = next;
        Some(element)
    }
}

/// Find the first child with `id`.
fn child(bytes: &[u8], parent: &Element, id: u32) -> Option<Element> {
    Children::new(bytes, parent.payload, parent.end()).find(|e| e.id == id)
}

/// Values read from the target `TrackEntry`.
struct TrackInfo<'a> {
    number: u64,
    codec_private: &'a [u8],
}

/// Locate the first HEVC video track, rejecting anything we cannot rewrite.
fn find_hevc_track<'a>(bytes: &'a [u8], segment: &Element) -> Result<TrackInfo<'a>> {
    let tracks = child(bytes, segment, ID_TRACKS).ok_or(HevcError::ContainerMalformed(
        "Matroska file has no Tracks element",
    ))?;

    for entry in Children::new(bytes, tracks.payload, tracks.end()) {
        if entry.id != ID_TRACK_ENTRY {
            continue;
        }
        let track_type = child(bytes, &entry, ID_TRACK_TYPE).and_then(|e| read_uint(bytes, &e));
        let codec_id = child(bytes, &entry, ID_CODEC_ID)
            .and_then(|e| bytes.get(e.payload..e.end()))
            .unwrap_or(b"");
        if track_type != Some(1) || codec_id != CODEC_ID_HEVC {
            continue;
        }
        if child(bytes, &entry, ID_CONTENT_ENCODINGS).is_some() {
            return Err(HevcError::Unsupported(
                "Matroska track uses ContentEncodings (header stripping/compression); \
                 per-block payloads are not directly addressable",
            ));
        }
        let number = child(bytes, &entry, ID_TRACK_NUMBER)
            .and_then(|e| read_uint(bytes, &e))
            .ok_or(HevcError::ContainerMalformed(
                "HEVC track has no TrackNumber",
            ))?;
        let codec_private = child(bytes, &entry, ID_CODEC_PRIVATE)
            .and_then(|e| bytes.get(e.payload..e.end()))
            .ok_or(HevcError::ContainerMalformed(
                "HEVC track has no CodecPrivate (hvcC record)",
            ))?;
        return Ok(TrackInfo {
            number,
            codec_private,
        });
    }

    Err(HevcError::Unsupported(
        "Matroska file has no HEVC video track (V_MPEGH/ISO/HEVC)",
    ))
}

/// Parse a `Block`/`SimpleBlock` header and push its VCL NAL spans.
///
/// Returns `true` when the block belonged to the target track.
fn scan_block(
    bytes: &[u8],
    block: &Element,
    track_number: u64,
    length_size: usize,
    spans: &mut Vec<PhysicalNalSpan>,
) -> Result<bool> {
    let payload = bytes
        .get(block.payload..block.end())
        .ok_or(HevcError::Truncated)?;
    let (track, track_len) = read_vint_size(payload, 0).ok_or(HevcError::Truncated)?;
    let track = track.ok_or(HevcError::ContainerMalformed(
        "block track number has unknown-size encoding",
    ))?;
    // Track number is a plain VINT *value*, not an element ID.
    let mut track_value = track;
    if track_len == 0 {
        return Err(HevcError::Truncated);
    }
    // `read_vint_size` already strips the length marker, so the value is final.
    track_value &= u64::MAX;
    if track_value != track_number {
        return Ok(false);
    }

    let header_len = track_len + 2 /* timecode */ + 1 /* flags */;
    if payload.len() < header_len {
        return Err(HevcError::Truncated);
    }
    let flags = payload[header_len - 1];
    if flags & 0x06 != 0 {
        return Err(HevcError::Unsupported(
            "Matroska block uses lacing; frame boundaries inside a laced block are not supported",
        ));
    }

    let mut cursor = block.payload + header_len;
    let end = block.end();
    while cursor + length_size <= end {
        let mut nal_len = 0usize;
        for i in 0..length_size {
            nal_len = (nal_len << 8) | bytes[cursor + i] as usize;
        }
        let start = cursor + length_size;
        let stop = start.saturating_add(nal_len);
        if stop > end {
            return Err(HevcError::ContainerMalformed(
                "block NAL length runs past the block payload",
            ));
        }
        if let Some(&header) = bytes.get(start) {
            let nal_type = (header >> 1) & 0x3F;
            // VCL types only: everything else is a parameter set / SEI /
            // filler and must not be treated as a slice.
            if (0..=31).contains(&nal_type) && stop > start + 2 {
                spans.push(PhysicalNalSpan {
                    start,
                    len: stop - start,
                });
            }
        }
        cursor = stop;
    }

    Ok(true)
}

/// Parse a Matroska file and locate the HEVC parameter sets and every slice span.
pub(crate) fn parse_mkv_targets(bytes: &[u8]) -> Result<MkvHevcTarget<'_>> {
    let ebml = read_element(bytes, 0, bytes.len())
        .ok_or(HevcError::ContainerMalformed("not an EBML file"))?;
    if ebml.id != ID_EBML {
        return Err(HevcError::ContainerMalformed("missing EBML header"));
    }
    if let Some(doc_type) =
        child(bytes, &ebml, ID_DOC_TYPE).and_then(|e| bytes.get(e.payload..e.end()))
        && !matches!(doc_type, b"matroska" | b"webm")
    {
        return Err(HevcError::Unsupported(
            "EBML DocType is neither matroska nor webm",
        ));
    }

    let segment = Children::new(bytes, ebml.end(), bytes.len())
        .find(|e| e.id == ID_SEGMENT)
        .ok_or(HevcError::ContainerMalformed("missing Segment element"))?;

    let track = find_hevc_track(bytes, &segment)?;
    let (parameter_sets, length_size) = parse_hvcc_record(track.codec_private)?;

    let mut slice_spans = Vec::new();
    let mut crcs = Vec::new();

    let mut seg_children = Children::new(bytes, segment.payload, segment.end());
    while let Some(element) = seg_children.next() {
        match element.id {
            ID_CLUSTER => {
                let cluster_children = Children::new(bytes, element.payload, element.end());
                for item in cluster_children {
                    if element.unknown_size && is_level1_element(item.id) {
                        // In an unknown-size Cluster (streaming), encountering another Level-1
                        // element marks the implicit end of this Cluster. Rewind the outer
                        // iterator so it consumes this Level-1 element next.
                        seg_children.pos = item.header_at;
                        break;
                    }
                    match item.id {
                        ID_SIMPLE_BLOCK => {
                            scan_block(bytes, &item, track.number, length_size, &mut slice_spans)?;
                        }
                        ID_BLOCK_GROUP => {
                            for bg_item in Children::new(bytes, item.payload, item.end()) {
                                match bg_item.id {
                                    ID_BLOCK => {
                                        scan_block(
                                            bytes,
                                            &bg_item,
                                            track.number,
                                            length_size,
                                            &mut slice_spans,
                                        )?;
                                    }
                                    ID_CRC32 => collect_crc(bytes, &bg_item, item.end(), &mut crcs),
                                    _ => {}
                                }
                            }
                        }
                        ID_CRC32 => collect_crc(bytes, &item, element.end(), &mut crcs),
                        _ => {}
                    }
                }
            }
            ID_CRC32 => collect_crc(bytes, &element, segment.end(), &mut crcs),
            _ => {}
        }
    }

    if slice_spans.is_empty() {
        return Err(HevcError::Unsupported(
            "Matroska file contains no decodable HEVC slices",
        ));
    }

    Ok(MkvHevcTarget {
        parameter_sets,
        slice_spans,
        crcs,
    })
}

/// Record one `CRC-32` element, the range it protects, and its byte order.
fn collect_crc(bytes: &[u8], element: &Element, parent_end: usize, out: &mut Vec<MkvCrc>) {
    if element.len != 4 || element.payload + 4 > bytes.len() {
        return;
    }
    let covers = element.end()..parent_end.min(bytes.len());
    let stored = &bytes[element.payload..element.payload + 4];
    let actual = crc32fast::hash(&bytes[covers.clone()]);
    let big = u32::from_be_bytes([stored[0], stored[1], stored[2], stored[3]]);
    let little = u32::from_le_bytes([stored[0], stored[1], stored[2], stored[3]]);
    let endian = if big == actual {
        Some(CrcEndian::Big)
    } else if little == actual {
        Some(CrcEndian::Little)
    } else {
        None
    };
    out.push(MkvCrc {
        value_offset: element.payload,
        covers,
        endian,
    });
}

/// Recompute every checksum whose coverage intersects a modified range.
///
/// Called after the CABAC patches are written. Idempotent: a cluster whose
/// bytes did not change recomputes the same value, so a conservative
/// intersection test is safe.
pub(crate) fn refresh_crcs(original: &[u8], out: &mut [u8], crcs: &[MkvCrc]) {
    let Some(changed) = changed_ranges(original, out) else {
        return;
    };
    // Update innermost spans first (BlockGroup -> Cluster -> Segment) so that
    // patches to inner CRC bytes are included in the hash of outer elements.
    let mut ordered: Vec<&MkvCrc> = crcs.iter().collect();
    ordered.sort_by_key(|c| c.covers.end.saturating_sub(c.covers.start));

    for crc in ordered {
        // A checksum that was already stale stays stale: see `MkvCrc::endian`.
        let Some(endian) = crc.endian else { continue };
        let touched = changed
            .iter()
            .any(|range| range.start < crc.covers.end && crc.covers.start < range.end);
        if !touched {
            continue;
        }
        let value = crc32fast::hash(&out[crc.covers.clone()]);
        let bytes = match endian {
            CrcEndian::Big => value.to_be_bytes(),
            CrcEndian::Little => value.to_le_bytes(),
        };
        if crc.value_offset + 4 <= out.len() {
            out[crc.value_offset..crc.value_offset + 4].copy_from_slice(&bytes);
        }
    }
}

/// Byte ranges that differ between two same-length buffers, merged greedily.
fn changed_ranges(original: &[u8], out: &[u8]) -> Option<Vec<Range<usize>>> {
    if original.len() != out.len() {
        return None;
    }
    let mut ranges: Vec<Range<usize>> = Vec::new();
    let mut i = 0usize;
    while i < original.len() {
        if original[i] == out[i] {
            i += 1;
            continue;
        }
        let start = i;
        // Coalesce runs separated by small unchanged gaps: a slice patch
        // changes a handful of scattered bytes inside one NAL.
        let mut last_change = i;
        while i < original.len() && i - last_change < 4096 {
            if original[i] != out[i] {
                last_change = i;
            }
            i += 1;
        }
        ranges.push(start..last_change + 1);
    }
    Some(ranges)
}

/// Recompute the Matroska checksums of a patched file and verify the result.
///
/// The CABAC patches change bytes inside `Cluster` payloads, and every
/// `Cluster`/`Info`/`Tracks`/`Cues` element in a real muxer's output carries a
/// `CRC-32` over exactly those bytes. Leaving it stale produces a file that
/// `mkvmerge` and `ffmpeg` both reject with "CRC-32 mismatch", so this runs on
/// every MKV embed and **fails closed**: if a checksum still disagrees after
/// the refresh, the embed reports an error instead of returning a broken file.
pub(crate) fn refresh_mkv_crcs(original: &[u8], out: &mut [u8]) -> Result<()> {
    if original.len() != out.len() {
        return Err(HevcError::ContainerMalformed(
            "patched Matroska carrier changed length",
        ));
    }
    // The checksum list comes from the *original* file: the patch only changes
    // payload bytes, so every element offset is still valid.
    let crcs = {
        let target = parse_mkv_targets(original)?;
        target.crcs
    };
    refresh_crcs(original, out, &crcs);

    for crc in &crcs {
        // Stale checksums are exempt: they were invalid before the embed and
        // are left exactly as the muxer wrote them.
        let Some(endian) = crc.endian else { continue };
        if crc.value_offset + 4 > out.len() || crc.covers.end > out.len() {
            return Err(HevcError::ContainerMalformed("CRC-32 element out of range"));
        }
        let expected = crc32fast::hash(&out[crc.covers.clone()]);
        let raw = &out[crc.value_offset..crc.value_offset + 4];
        let stored = match endian {
            CrcEndian::Big => u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
            CrcEndian::Little => u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
        };
        if stored != expected {
            return Err(HevcError::ContainerMalformed(
                "Matroska CRC-32 could not be refreshed",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_vint(val: u64) -> Vec<u8> {
        for len in 1usize..=8 {
            let marker = 1u64 << (7 * len);
            if val < marker - 1 {
                let v = marker | val;
                return v.to_be_bytes()[8 - len..].to_vec();
            }
        }
        panic!("value too large for EBML VINT");
    }

    /// Build a minimal EBML element: id bytes + size VINT + payload.
    fn element(id: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut out = id.to_vec();
        out.extend_from_slice(&encode_vint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    fn master(id: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = Vec::new();
        for child in children {
            payload.extend_from_slice(child);
        }
        element(id, &payload)
    }

    /// A block whose payload is `track | timecode(2) | flags(1) | length-prefixed NALs`.
    fn simple_block(track: u8, nals: &[&[u8]]) -> Vec<u8> {
        let mut payload = vec![0x80 | track, 0x00, 0x00, 0x00];
        for nal in nals {
            payload.extend_from_slice(&(nal.len() as u32).to_be_bytes());
            payload.extend_from_slice(nal);
        }
        element(&[0xA3], &payload)
    }

    /// Minimal `hvcC`: 23-byte header + one array holding one NAL.
    fn hvcc(ps: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 23];
        out[21] = 0x03; // length_size = 4
        out[22] = 1; // one array
        out.push(0x80 | 32); // VPS array
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(ps.len() as u16).to_be_bytes());
        out.extend_from_slice(ps);
        out
    }

    fn build_file(blocks: &[Vec<u8>], with_content_encodings: bool) -> Vec<u8> {
        let mut track = vec![
            element(&[0x83], &[1]),                             // TrackType = video
            element(&[0xD7], &[1]),                             // TrackNumber = 1
            element(&[0x86], CODEC_ID_HEVC),                    // CodecID
            element(&[0x63, 0xA2], &hvcc(&[0x40, 0x01, 0x00])), // CodecPrivate
        ];
        if with_content_encodings {
            track.push(master(&[0x6D, 0x80], &[element(&[0x50, 0x35], &[0])]));
        }
        let tracks = master(&[0x16, 0x54, 0xAE, 0x6B], &[master(&[0xAE], &track)]);
        let cluster = master(&[0x1F, 0x43, 0xB6, 0x75], blocks);
        let segment = master(&[0x18, 0x53, 0x80, 0x67], &[tracks, cluster]);
        let mut file = element(
            &[0x1A, 0x45, 0xDF, 0xA3],
            &element(&[0x42, 0x82], b"matroska"),
        );
        file.extend_from_slice(&segment);
        file
    }

    #[test]
    fn locates_vcl_spans_in_a_simple_file() {
        let idr = [0x26u8, 0x01, 0xAA, 0xBB];
        let trai = [0x02u8, 0x01, 0xCC, 0xDD];
        let file = build_file(
            &[simple_block(1, &[&idr]), simple_block(1, &[&trai])],
            false,
        );

        let target = parse_mkv_targets(&file).expect("parse");
        assert_eq!(target.parameter_sets.len(), 1);
        assert_eq!(target.slice_spans.len(), 2);
        for (span, nal) in target.slice_spans.iter().zip([idr, trai]) {
            assert_eq!(
                &file[span.start..span.end()],
                &nal,
                "span must cover the NAL"
            );
        }
    }

    #[test]
    fn skips_other_tracks_and_non_vcl_nalus() {
        let idr = [0x26u8, 0x01, 0xAA];
        let sei = [0x4Eu8, 0x01, 0x00]; // nal type 39: not VCL
        let file = build_file(
            &[simple_block(2, &[&idr]), simple_block(1, &[&sei, &idr])],
            false,
        );
        let target = parse_mkv_targets(&file).expect("parse");
        assert_eq!(
            target.slice_spans.len(),
            1,
            "track 2 is skipped and the SEI NAL is not addressable"
        );
        assert_eq!(
            &file[target.slice_spans[0].start..target.slice_spans[0].end()],
            &idr
        );
    }

    #[test]
    fn rejects_header_stripped_tracks() {
        let idr = [0x26u8, 0x01, 0xAA];
        let file = build_file(&[simple_block(1, &[&idr])], true);
        let err = parse_mkv_targets(&file).unwrap_err().to_string();
        assert!(err.contains("ContentEncodings"), "{err}");
    }

    #[test]
    fn rejects_laced_blocks() {
        let mut payload = vec![0x81u8, 0x00, 0x00, 0x02]; // lacing bits = 1 (Xiph)
        payload.extend_from_slice(&4u32.to_be_bytes());
        payload.extend_from_slice(&[0x26, 0x01, 0xAA, 0xBB]);
        let file = build_file(&[element(&[0xA3], &payload)], false);
        let err = parse_mkv_targets(&file).unwrap_err().to_string();
        assert!(err.contains("lacing"), "{err}");
    }

    #[test]
    fn rejects_a_missing_hevc_track() {
        let tracks = master(
            &[0x16, 0x54, 0xAE, 0x6B],
            &[master(
                &[0xAE],
                &[
                    element(&[0x83], &[2]), // audio
                    element(&[0xD7], &[1]),
                    element(&[0x86], b"A_OPUS"),
                ],
            )],
        );
        let segment = master(&[0x18, 0x53, 0x80, 0x67], &[tracks]);
        let mut file = element(
            &[0x1A, 0x45, 0xDF, 0xA3],
            &element(&[0x42, 0x82], b"matroska"),
        );
        file.extend_from_slice(&segment);
        let err = parse_mkv_targets(&file).unwrap_err().to_string();
        assert!(err.contains("no HEVC video track"), "{err}");
    }

    /// Build a Matroska file whose single `Cluster` carries a **valid**
    /// CRC-32 in the requested byte order.
    fn build_crc_file(endian: CrcEndian) -> (Vec<u8>, MkvCrc) {
        let idr = [0x26u8, 0x01, 0xAA];
        let block = simple_block(1, &[&idr]);

        // Lay the cluster out with a zero checksum, then patch in the real one.
        let mut cluster_payload = element(&[0xBF], &[0, 0, 0, 0]);
        cluster_payload.extend_from_slice(&block);
        let cluster = element(&[0x1F, 0x43, 0xB6, 0x75], &cluster_payload);

        let tracks = master(
            &[0x16, 0x54, 0xAE, 0x6B],
            &[master(
                &[0xAE],
                &[
                    element(&[0x83], &[1]),
                    element(&[0xD7], &[1]),
                    element(&[0x86], CODEC_ID_HEVC),
                    element(&[0x63, 0xA2], &hvcc(&[0x40, 0x01, 0x00])),
                ],
            )],
        );
        let segment = master(&[0x18, 0x53, 0x80, 0x67], &[tracks, cluster]);
        let mut file = element(
            &[0x1A, 0x45, 0xDF, 0xA3],
            &element(&[0x42, 0x82], b"matroska"),
        );
        file.extend_from_slice(&segment);

        // Locate the checksum element inside the cluster and write a valid value.
        let crc_start = file
            .windows(2)
            .position(|w| w == [0xBF, 0x84])
            .expect("checksum element");
        let value_offset = crc_start + 2;
        let cluster_end = file.len();
        let hash = crc32fast::hash(&file[value_offset + 4..cluster_end]);
        let bytes = match endian {
            CrcEndian::Big => hash.to_be_bytes(),
            CrcEndian::Little => hash.to_le_bytes(),
        };
        file[value_offset..value_offset + 4].copy_from_slice(&bytes);

        let crc = MkvCrc {
            value_offset,
            covers: value_offset + 4..cluster_end,
            endian: Some(endian),
        };
        (file, crc)
    }

    #[test]
    fn crc32_byte_order_is_detected_and_preserved() {
        for endian in [CrcEndian::Big, CrcEndian::Little] {
            let (file, expected) = build_crc_file(endian);
            let target = parse_mkv_targets(&file).expect("parse");
            assert_eq!(target.crcs.len(), 1);
            let crc = &target.crcs[0];
            assert_eq!(
                crc.endian,
                Some(endian),
                "{endian:?}: byte order must be detected from the file"
            );
            assert_eq!(crc.value_offset, expected.value_offset);

            // An unchanged file keeps its checksum untouched.
            let mut untouched = file.clone();
            refresh_crcs(&file, &mut untouched, std::slice::from_ref(crc));
            assert_eq!(untouched, file);

            // A covered byte change is followed by a rewrite in the same order.
            let mut patched = file.clone();
            patched[crc.covers.start + 4] ^= 0x01;
            refresh_crcs(&file, &mut patched, std::slice::from_ref(crc));
            let hash = crc32fast::hash(&patched[crc.covers.clone()]);
            let bytes = match endian {
                CrcEndian::Big => hash.to_be_bytes(),
                CrcEndian::Little => hash.to_le_bytes(),
            };
            assert_eq!(&patched[crc.value_offset..crc.value_offset + 4], &bytes);
        }
    }

    #[test]
    fn a_stale_checksum_is_left_exactly_as_found() {
        // A muxer that hashed the wrong range leaves an unusable checksum;
        // rewriting it to a *valid* one would be a bigger observable change
        // than leaving it alone.
        let (mut file, _) = build_crc_file(CrcEndian::Big);
        let target = parse_mkv_targets(&file).expect("parse");
        let crc = target.crcs[0].clone();
        file[crc.value_offset] ^= 0xFF; // break it
        let target = parse_mkv_targets(&file).expect("parse");
        assert_eq!(target.crcs[0].endian, None, "broken checksum is stale");

        let mut out = file.clone();
        out[crc.covers.start + 4] ^= 0x01;
        let before = out[crc.value_offset..crc.value_offset + 4].to_vec();
        refresh_crcs(&file, &mut out, &target.crcs);
        assert_eq!(
            &out[crc.value_offset..crc.value_offset + 4],
            &before[..],
            "a stale checksum must not be rewritten"
        );
    }

    #[test]
    fn unknown_size_cluster_does_not_swallow_subsequent_clusters() {
        let idr = [0x26u8, 0x01, 0xAA, 0xBB];
        let trai = [0x02u8, 0x01, 0xCC, 0xDD];
        let block1 = simple_block(1, &[&idr]);
        let block2 = simple_block(1, &[&trai]);

        // Cluster 1 with unknown size (0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
        let mut cluster1 = vec![
            0x1F, 0x43, 0xB6, 0x75, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        cluster1.extend_from_slice(&block1);

        // Cluster 2 with known size
        let cluster2 = master(&[0x1F, 0x43, 0xB6, 0x75], &[block2]);

        let tracks = master(
            &[0x16, 0x54, 0xAE, 0x6B],
            &[master(
                &[0xAE],
                &[
                    element(&[0xD7], &[1]),
                    element(&[0x83], &[1]),
                    element(&[0x86], CODEC_ID_HEVC),
                    element(&[0x63, 0xA2], &hvcc(&[0x40, 0x01, 0x00])),
                ],
            )],
        );

        let mut seg_payload = tracks;
        seg_payload.extend_from_slice(&cluster1);
        seg_payload.extend_from_slice(&cluster2);

        let segment = element(&[0x18, 0x53, 0x80, 0x67], &seg_payload);
        let mut file = element(
            &[0x1A, 0x45, 0xDF, 0xA3],
            &element(&[0x42, 0x82], b"matroska"),
        );
        file.extend_from_slice(&segment);

        let target = parse_mkv_targets(&file).expect("parse");
        assert_eq!(
            target.slice_spans.len(),
            2,
            "both slices from both clusters must be located despite cluster 1 having unknown size"
        );
    }
}
