//! Lightweight, zero-copy ISOBMFF HEIF parser for Scheme C.
//!
//! Extracts parameter sets (VPS/SPS/PPS) from `hvcC` and locates the exact file byte spans
//! of all HEVC slice NAL units belonging to the primary image (including iPhone grid tiles).
//!
//! # Robustness contract
//!
//! This parser reads **untrusted input**: a HEIF file may come from any source and
//! every length field in it is attacker-controlled. Therefore this module contains
//! **no `unwrap()` / `expect()` / `panic!`** — every read is bounds-checked and
//! every malformed structure is reported as [`HevcError`] instead of aborting
//! the process. The helpers at the bottom of the file (`be_u16`, `be_u32`,
//! `be_u64`, `read_uint`) are the only sanctioned way to read big-endian
//! integers out of a byte slice, and they return `Option` / saturate.

use crate::stego::hevc::error::{HevcError, Result};

/// A physical byte span in the file containing a single NAL unit (excluding length prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalNalSpan {
    /// Start byte offset of the NAL unit in the file (starts with NAL unit header).
    pub start: usize,
    /// Length of the NAL unit in bytes.
    pub len: usize,
}

impl PhysicalNalSpan {
    pub fn end(&self) -> usize {
        self.start.saturating_add(self.len)
    }
}

/// Extracted HEIF carrier information ready for Scheme C steganography.
pub struct HeifHevcTarget<'a> {
    /// VPS, SPS, PPS parameter sets (without length prefixes or start codes).
    pub parameter_sets: Vec<&'a [u8]>,
    /// NAL length prefix size in bytes (typically 4).
    pub length_size: usize,
    /// Physical spans of all slice NAL units in the carrier file.
    pub slice_spans: Vec<PhysicalNalSpan>,
}

/// Parse HEIF container and locate HEVC parameter sets and slice NAL byte spans.
pub fn parse_heif_targets<'a>(bytes: &'a [u8]) -> Result<HeifHevcTarget<'a>> {
    let mut pos = 0usize;
    let mut meta_span = None;

    // 1. Walk top-level boxes to locate `meta`
    while pos + 8 <= bytes.len() {
        let Some(size32) = be_u32(bytes, pos) else {
            return Err(HevcError::Truncated);
        };
        let tag = &bytes[pos + 4..pos + 8];
        let (hdr_len, total_size) = if size32 == 1 {
            if pos + 16 > bytes.len() {
                return Err(HevcError::Truncated);
            }
            let Some(s64) = be_u64(bytes, pos + 8) else {
                return Err(HevcError::Truncated);
            };
            (
                16usize,
                usize::try_from(s64).map_err(|_| {
                    HevcError::ContainerMalformed("64-bit box size does not fit in usize")
                })?,
            )
        } else if size32 == 0 {
            (8usize, bytes.len() - pos)
        } else {
            (8usize, size32 as usize)
        };

        if total_size < hdr_len
            || pos
                .checked_add(total_size)
                .is_none_or(|end| end > bytes.len())
        {
            return Err(HevcError::ContainerMalformed("invalid top-level box size"));
        }

        if tag == b"meta" {
            meta_span = Some((pos + hdr_len, pos + total_size));
            break;
        }

        pos += total_size;
    }

    let (meta_start, meta_end) =
        meta_span.ok_or(HevcError::ContainerMalformed("missing meta box"))?;
    if meta_start + 4 > meta_end {
        return Err(HevcError::Truncated);
    }

    // `meta` is a FullBox (4 bytes: version + flags)
    let meta_children_start = meta_start + 4;
    let meta_payload = &bytes[meta_children_start..meta_end];

    // 2. Parse children of `meta`
    let mut primary_id: Option<u32> = None;
    let mut iloc_span = None;
    let mut iprp_span = None;
    let mut iref_span = None;
    let mut iinf_span = None;

    let mut cpos = 0usize;
    while cpos + 8 <= meta_payload.len() {
        let Some(size32) = be_u32(meta_payload, cpos) else {
            break;
        };
        let tag = &meta_payload[cpos + 4..cpos + 8];
        let (hdr_len, total_size) = if size32 == 1 {
            if cpos + 16 > meta_payload.len() {
                break;
            }
            let Some(s64) = be_u64(meta_payload, cpos + 8) else {
                break;
            };
            match usize::try_from(s64) {
                Ok(v) => (16usize, v),
                Err(_) => break,
            }
        } else if size32 == 0 {
            (8usize, meta_payload.len() - cpos)
        } else {
            (8usize, size32 as usize)
        };

        if total_size < hdr_len
            || cpos
                .checked_add(total_size)
                .is_none_or(|end| end > meta_payload.len())
        {
            break;
        }

        let child_data = &meta_payload[cpos + hdr_len..cpos + total_size];
        match tag {
            b"pitm" => {
                let version = child_data.first().copied().unwrap_or(0);
                if version == 0 {
                    if let Some(v) = be_u16(child_data, 4) {
                        primary_id = Some(v as u32);
                    }
                } else if version == 1 {
                    primary_id = be_u32(child_data, 4);
                }
            }
            b"iloc" => iloc_span = Some(child_data),
            b"iprp" => iprp_span = Some(child_data),
            b"iref" => iref_span = Some(child_data),
            b"iinf" => iinf_span = Some(child_data),
            _ => {}
        }

        cpos += total_size;
    }

    let pid = primary_id.unwrap_or(1);

    // 3. Parse `iinf` to determine if primary item is `grid`
    let mut is_grid = false;
    if let Some(iinf) = iinf_span {
        is_grid = check_is_grid(iinf, pid);
    }

    // 4. Resolve target items (single item vs. tiles from `iref`)
    let mut target_item_ids = Vec::new();
    if is_grid {
        if let Some(iref) = iref_span {
            let tiles = parse_dimg_tiles(iref, pid);
            if !tiles.is_empty() {
                target_item_ids = tiles;
            } else {
                target_item_ids.push(pid);
            }
        } else {
            target_item_ids.push(pid);
        }
    } else {
        target_item_ids.push(pid);
    }

    // 5. Parse `iprp` to extract `hvcC` (VPS/SPS/PPS and length_size)
    let iprp = iprp_span.ok_or(HevcError::ContainerMalformed("missing iprp box"))?;
    let (parameter_sets, length_size) = parse_hvcc_from_iprp(iprp)?;

    // 6. Parse `iloc` to get file byte spans for target items
    let iloc = iloc_span.ok_or(HevcError::ContainerMalformed("missing iloc box"))?;
    let item_extents = parse_iloc_extents(iloc, &target_item_ids)?;

    // 7. For each target item extent, split into NAL unit physical spans
    let mut slice_spans = Vec::new();
    for (item_offset, item_len) in item_extents {
        let Some(item_end) = item_offset.checked_add(item_len) else {
            return Err(HevcError::Truncated);
        };
        if item_end > bytes.len() {
            return Err(HevcError::Truncated);
        }
        let mut curr = item_offset;
        while curr + length_size <= item_end {
            let nal_len = match length_size {
                4 => be_u32(bytes, curr).ok_or(HevcError::Truncated)? as usize,
                2 => be_u16(bytes, curr).ok_or(HevcError::Truncated)? as usize,
                1 => bytes[curr] as usize,
                _ => return Err(HevcError::InvalidData("unsupported length_size")),
            };
            let nal_start = curr + length_size;
            let Some(nal_end) = nal_start.checked_add(nal_len) else {
                return Err(HevcError::Truncated);
            };
            if nal_end > item_end {
                return Err(HevcError::Truncated);
            }
            if nal_len >= 2 {
                let b0 = bytes[nal_start];
                let nal_type = (b0 >> 1) & 0x3F;
                // VCL slices are types 0..=31
                if nal_type <= 31 {
                    slice_spans.push(PhysicalNalSpan {
                        start: nal_start,
                        len: nal_len,
                    });
                }
            }
            curr = nal_end;
        }
    }

    if slice_spans.is_empty() {
        return Err(HevcError::NoSlices);
    }

    Ok(HeifHevcTarget {
        parameter_sets,
        length_size,
        slice_spans,
    })
}

fn check_is_grid(iinf: &[u8], target_id: u32) -> bool {
    if iinf.len() < 4 {
        return false;
    }
    let version = iinf[0];
    let mut pos = 4usize;
    let entry_count = if version == 0 {
        match be_u16(iinf, pos) {
            Some(c) => {
                pos += 2;
                c as usize
            }
            None => return false,
        }
    } else {
        match be_u32(iinf, pos) {
            Some(c) => {
                pos += 4;
                c as usize
            }
            None => return false,
        }
    };

    let mut found_count = 0;
    while pos + 8 <= iinf.len() && found_count < entry_count {
        let Some(size) = be_u32(iinf, pos).map(|v| v as usize) else {
            break;
        };
        let tag = &iinf[pos + 4..pos + 8];
        if size < 8 || pos.checked_add(size).is_none_or(|end| end > iinf.len()) {
            break;
        }
        if tag == b"infe" && size >= 12 {
            let infe_ver = iinf[pos + 8];
            let ipos = pos + 12;
            let (item_id, item_type) = if infe_ver == 2 {
                // v2: item_ID(16) + item_protection_index(16) + item_type(4)
                if ipos + 8 <= pos + size {
                    match (be_u16(iinf, ipos), iinf.get(ipos + 4..ipos + 8)) {
                        (Some(id), Some(itype)) => (Some(id as u32), Some(itype)),
                        _ => (None, None),
                    }
                } else {
                    (None, None)
                }
            } else if infe_ver == 3 {
                // v3: item_ID(32) + item_protection_index(16) + item_type(4)
                if ipos + 10 <= pos + size {
                    match (be_u32(iinf, ipos), iinf.get(ipos + 6..ipos + 10)) {
                        (Some(id), Some(itype)) => (Some(id), Some(itype)),
                        _ => (None, None),
                    }
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            if let (Some(id), Some(itype)) = (item_id, item_type)
                && id == target_id
            {
                return itype == b"grid";
            }
        }
        pos += size;
        found_count += 1;
    }
    false
}

fn parse_dimg_tiles(iref: &[u8], grid_id: u32) -> Vec<u32> {
    let mut tiles = Vec::new();
    if iref.len() < 4 {
        return tiles;
    }
    let version = iref[0];
    let mut pos = 4usize;
    while pos + 8 <= iref.len() {
        let Some(size) = be_u32(iref, pos).map(|v| v as usize) else {
            break;
        };
        let tag = &iref[pos + 4..pos + 8];
        if size < 8 || pos.checked_add(size).is_none_or(|end| end > iref.len()) {
            break;
        }
        if tag == b"dimg" {
            let body = &iref[pos + 8..pos + size];
            if version == 0 {
                // from_item_ID(16) + reference_count(16) + to_item_ID(16)*
                if let (Some(from), Some(count)) = (be_u16(body, 0), be_u16(body, 2)) {
                    let count = count as usize;
                    if from as u32 == grid_id && body.len() >= 4 + count * 2 {
                        for i in 0..count {
                            if let Some(to) = be_u16(body, 4 + i * 2) {
                                tiles.push(to as u32);
                            }
                        }
                    }
                }
            } else {
                // from_item_ID(32) + reference_count(16) + to_item_ID(32)*
                if let (Some(from), Some(count)) = (be_u32(body, 0), be_u16(body, 4)) {
                    let count = count as usize;
                    if from == grid_id && body.len() >= 6 + count * 4 {
                        for i in 0..count {
                            if let Some(to) = be_u32(body, 6 + i * 4) {
                                tiles.push(to);
                            }
                        }
                    }
                }
            }
        }
        pos += size;
    }
    tiles
}

fn parse_hvcc_from_iprp(iprp: &[u8]) -> Result<(Vec<&[u8]>, usize)> {
    let mut pos = 0usize;
    let mut ipco_data = None;

    while pos + 8 <= iprp.len() {
        let Some(size) = be_u32(iprp, pos).map(|v| v as usize) else {
            break;
        };
        let tag = &iprp[pos + 4..pos + 8];
        if size < 8 || pos.checked_add(size).is_none_or(|end| end > iprp.len()) {
            break;
        }
        if tag == b"ipco" {
            ipco_data = Some(&iprp[pos + 8..pos + size]);
            break;
        }
        pos += size;
    }

    let ipco = ipco_data.ok_or(HevcError::ContainerMalformed("missing ipco in iprp"))?;

    // Walk properties in `ipco` to find `hvcC`
    let mut ppos = 0usize;
    let mut hvcc_payload = None;
    while ppos + 8 <= ipco.len() {
        let Some(size) = be_u32(ipco, ppos).map(|v| v as usize) else {
            break;
        };
        let tag = &ipco[ppos + 4..ppos + 8];
        if size < 8 || ppos.checked_add(size).is_none_or(|end| end > ipco.len()) {
            break;
        }
        if tag == b"hvcC" {
            hvcc_payload = Some(&ipco[ppos + 8..ppos + size]);
            break;
        }
        ppos += size;
    }

    let hvcc = hvcc_payload.ok_or(HevcError::ContainerMalformed("missing hvcC property"))?;
    if hvcc.len() < 23 {
        return Err(HevcError::Truncated);
    }

    let length_size = (hvcc[21] & 0x03) as usize + 1;
    let num_of_arrays = hvcc[22] as usize;
    let mut rpos = 23usize;
    let mut parameter_sets = Vec::new();

    for _ in 0..num_of_arrays {
        if rpos + 3 > hvcc.len() {
            break;
        }
        let _nal_type = hvcc[rpos] & 0x3F;
        let Some(num_nals) = be_u16(hvcc, rpos + 1) else {
            break;
        };
        rpos += 3;
        for _ in 0..num_nals as usize {
            if rpos + 2 > hvcc.len() {
                break;
            }
            let Some(nal_len) = be_u16(hvcc, rpos).map(|v| v as usize) else {
                break;
            };
            rpos += 2;
            let Some(end) = rpos.checked_add(nal_len) else {
                break;
            };
            if end > hvcc.len() {
                break;
            }
            parameter_sets.push(&hvcc[rpos..end]);
            rpos = end;
        }
    }

    Ok((parameter_sets, length_size))
}

fn parse_iloc_extents(iloc: &[u8], target_ids: &[u32]) -> Result<Vec<(usize, usize)>> {
    let mut extents = Vec::new();
    if iloc.len() < 8 {
        return Err(HevcError::Truncated);
    }
    let version = iloc[0];
    let size_b0 = iloc[4];
    let size_b1 = iloc[5];
    let offset_size = (size_b0 >> 4) as usize;
    let length_size = (size_b0 & 0x0F) as usize;
    let base_offset_size = (size_b1 >> 4) as usize;
    let index_size = if version >= 1 {
        (size_b1 & 0x0F) as usize
    } else {
        0
    };

    let mut pos = 6usize;
    let item_count = if version < 2 {
        match be_u16(iloc, pos) {
            Some(c) => {
                pos += 2;
                c as usize
            }
            None => return Err(HevcError::Truncated),
        }
    } else {
        match be_u32(iloc, pos) {
            Some(c) => {
                pos += 4;
                c as usize
            }
            None => return Err(HevcError::Truncated),
        }
    };

    for _ in 0..item_count {
        if pos >= iloc.len() {
            break;
        }
        let item_id = if version < 2 {
            match be_u16(iloc, pos) {
                Some(id) => {
                    pos += 2;
                    id as u32
                }
                None => break,
            }
        } else {
            match be_u32(iloc, pos) {
                Some(id) => {
                    pos += 4;
                    id
                }
                None => break,
            }
        };

        if version >= 1 {
            pos += 2; // construction_method
        }
        pos += 2; // data_reference_index

        // `read_uint` saturates to 0 when the field would run past the end of
        // the box, but we still must not slice `iloc[pos..]` with an
        // out-of-range `pos` — that is the panic this guards against.
        let base_offset = read_uint(&iloc[pos.min(iloc.len())..], base_offset_size);
        pos += base_offset_size;

        let Some(extent_count) = be_u16(iloc, pos) else {
            break;
        };
        pos += 2;

        let is_target = target_ids.contains(&item_id);

        for _ in 0..extent_count as usize {
            pos += index_size;
            let ext_offset = read_uint(&iloc[pos.min(iloc.len())..], offset_size);
            pos += offset_size;
            let ext_len = read_uint(&iloc[pos.min(iloc.len())..], length_size);
            pos += length_size;

            if is_target {
                extents.push((
                    (base_offset.saturating_add(ext_offset)) as usize,
                    ext_len as usize,
                ));
            }
        }
    }

    Ok(extents)
}

// ---- Bounds-checked big-endian readers ------------------------------------
//
// Every integer read from a HEIF box goes through these helpers. They return
// `None` instead of panicking when the requested field does not fit, so a
// truncated or hostile container can never abort the process.

/// Read a big-endian `u16` at `off`. Returns `None` if out of bounds.
#[inline]
fn be_u16(bytes: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    if end > bytes.len() {
        return None;
    }
    Some(u16::from_be_bytes([bytes[off], bytes[off + 1]]))
}

/// Read a big-endian `u32` at `off`. Returns `None` if out of bounds.
#[inline]
fn be_u32(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    if end > bytes.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
    ]))
}

/// Read a big-endian `u64` at `off`. Returns `None` if out of bounds.
#[inline]
fn be_u64(bytes: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    if end > bytes.len() {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[off..end]);
    Some(u64::from_be_bytes(buf))
}

/// Read a big-endian unsigned integer of `size` bytes.
///
/// `size == 0` means "this field is absent" per ISO/IEC 14496-12 and yields 0.
/// A `size` that would run past the end of `bytes` also yields 0 — the caller
/// detects the inconsistency through the surrounding length checks.
fn read_uint(bytes: &[u8], size: usize) -> u64 {
    if size == 0 || bytes.len() < size {
        return 0;
    }
    let mut v = 0u64;
    for &b in &bytes[..size] {
        v = (v << 8) | (b as u64);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A malformed `infe` v3 entry whose declared size is long enough to pass
    /// the old `ipos + 8` check but too short for the old `ipos + 6..ipos + 10`
    /// slice. The old code panicked here (verified: "range end index 28 out of
    /// range for slice of length 24"); the new code must not.
    #[test]
    fn malformed_infe_v3_does_not_panic() {
        // iinf: version(1) + flags(3) + entry_count(2) = 6 bytes
        let mut iinf = vec![1u8, 0, 0, 0];
        iinf.extend_from_slice(&1u16.to_be_bytes());
        let pos = 6usize;
        // A single `infe` box whose *declared* size is 20 but whose payload
        // only carries item_ID + protection_index — item_type is missing.
        // The old code sliced `iinf[ipos + 6..ipos + 10]` (needs 28 bytes)
        // from a 24-byte buffer and panicked.
        iinf.extend_from_slice(&20u32.to_be_bytes());
        iinf.extend_from_slice(b"infe");
        iinf.push(3); // infe_version = 3
        iinf.extend_from_slice(&[0u8; 3]); // flags
        iinf.extend_from_slice(&7u32.to_be_bytes()); // item_ID
        iinf.extend_from_slice(&0u16.to_be_bytes()); // protection_index
        // The declared size (20) is smaller than the bytes actually present
        // for the box header + payload, and the buffer ends right there —
        // exactly the shape that made the old code slice past the end.
        assert_eq!(iinf.len(), pos + 18);
        // Must return a value, not panic.
        let _ = check_is_grid(&iinf, 7);
    }

    #[test]
    fn truncated_boxes_are_errors_not_panics() {
        for len in 0..64usize {
            let buf = vec![0xABu8; len];
            // Must return Err or Ok, never panic.
            let _ = parse_heif_targets(&buf);
        }
    }

    #[test]
    fn fuzz_like_random_prefixes_do_not_panic() {
        // Deterministic pseudo-random corpus: every prefix of a plausible HEIF.
        let mut state = 0x1234_5678u32;
        let mut corpus = Vec::new();
        for _ in 0..512 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            corpus.push((state >> 16) as u8);
        }
        for cut in 0..corpus.len() {
            let _ = parse_heif_targets(&corpus[..cut]);
        }
    }

    #[test]
    fn extent_parsing_tolerates_truncation() {
        for len in 0..32usize {
            let buf = vec![0u8; len];
            let _ = parse_iloc_extents(&buf, &[1]);
        }
    }
}
