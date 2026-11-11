//! HEIF `item_hidden` strategy: hidden-item injection and strip.

use std::io::{SeekFrom, Write};

use crate::errors::StrHideError;
use crate::structure::adapters::{InjectCoordinates, SeekRead, SeekWrite};
use crate::structure::envelope::EnvelopeHeader;

use super::boxes::{
    patch_sized_uint, read_box_size, read_sized_uint, read_stream_box_header, write_sized_uint,
};
use super::{MAX_ISOBMFF_META_SCAN, check_item_hidden_layout};

pub(super) fn heif_item_hidden_inject(
    host_in: &mut dyn SeekRead,
    ube_in: &mut dyn SeekRead,
    out: &mut dyn Write,
) -> Result<InjectCoordinates, StrHideError> {
    host_in.seek(SeekFrom::End(0))?;
    let host_size = host_in.stream_position()?;
    let ube_size = ube_in.seek(SeekFrom::End(0))?;

    // 1. Locate the meta box by streaming its top-level header. Only the bytes
    // up to the end of `meta` are needed in memory; the rest of the host is
    // streamed straight into the output afterwards.
    let mut pos = 0u64;
    let mut meta_span = None;
    while pos + 8 <= host_size {
        let (bsize, hlen, tag) = read_stream_box_header(host_in, pos, host_size)?;
        if tag == *b"meta" {
            meta_span = Some((pos, bsize, hlen));
            break;
        }
        pos += bsize;
    }
    let (m_off, m_size, m_hlen) = meta_span.ok_or_else(|| {
        StrHideError::UnsupportedFormat("No meta box found in HEIF carrier for item_hidden".into())
    })?;
    // The rewrite below rebuilds the meta header as `size32 + "meta" +
    // version/flags` (12 bytes); a 64-bit (`largesize`) header would have its
    // largesize high word overwritten. `check_item_hidden_layout` (called once
    // the prefix is buffered) rejects that and every other layout the writer
    // cannot rewrite, and the probe uses the same function.
    let m_off = usize::try_from(m_off)
        .map_err(|_| StrHideError::UnsupportedFormat("meta box offset exceeds usize".into()))?;
    let m_size = usize::try_from(m_size)
        .map_err(|_| StrHideError::UnsupportedFormat("meta box size exceeds usize".into()))?;
    let m_end = m_off
        .checked_add(m_size)
        .ok_or_else(|| StrHideError::CorruptedData("meta box offset overflows".into()))?;
    if m_end as u64 > MAX_ISOBMFF_META_SCAN {
        return Err(StrHideError::UnsupportedFormat(
            "HEIF meta box is too large for item_hidden".into(),
        ));
    }
    host_in.seek(SeekFrom::Start(0))?;
    let mut host_prefix = vec![0u8; m_end];
    host_in.read_exact(&mut host_prefix)?;
    check_item_hidden_layout(&host_prefix[m_off..m_end])?;

    let m_body_start = m_off + m_hlen + 4; // FullBox version+flags
    if m_body_start > m_end {
        return Err(StrHideError::CorruptedData("Truncated meta box".into()));
    }

    // 2. Extract sub-boxes in meta
    let mut subboxes: Vec<([u8; 4], Vec<u8>)> = Vec::new();
    let mut bpos = m_body_start;
    while bpos + 8 <= m_end {
        let (s_size, s_hlen) = read_box_size(&host_prefix, bpos)?;
        if s_size < s_hlen || s_size > m_end - bpos {
            return Err(StrHideError::CorruptedData(
                "Invalid sub-box in meta".into(),
            ));
        }
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&host_prefix[bpos + 4..bpos + 8]);
        subboxes.push((tag, host_prefix[bpos..bpos + s_size].to_vec()));
        bpos += s_size;
    }
    // Meta bodies ending in <8 bytes (padding/residue) cannot start a box header;
    // preserve them verbatim on inject and strip to ensure exact bit-level restore.
    let meta_tail: Vec<u8> = if bpos < m_end {
        host_prefix[bpos..m_end].to_vec()
    } else {
        Vec::new()
    };

    let iinf_idx = subboxes
        .iter()
        .position(|(tag, _)| tag == b"iinf")
        .ok_or_else(|| StrHideError::UnsupportedFormat("Missing iinf box in meta".into()))?;
    let iloc_idx = subboxes
        .iter()
        .position(|(tag, _)| tag == b"iloc")
        .ok_or_else(|| StrHideError::UnsupportedFormat("Missing iloc box in meta".into()))?;

    // Both sub-boxes are rewritten in place at their parsed offsets; that is
    // only valid for the 8-byte header form. `check_item_hidden_layout` has
    // already rejected a 64-bit `iloc`/`iinf` header above.

    // 3. Parse iinf to find max_item_id
    let iinf_box = &subboxes[iinf_idx].1;
    if iinf_box.len() < 12 {
        return Err(StrHideError::CorruptedData("Truncated iinf box".into()));
    }
    let iinf_ver = iinf_box[8];
    if iinf_box.len() < if iinf_ver == 0 { 14 } else { 16 } {
        return Err(StrHideError::CorruptedData("Truncated iinf box".into()));
    }
    let entry_cnt = if iinf_ver == 0 {
        u16::from_be_bytes(iinf_box[12..14].try_into().unwrap()) as u32
    } else {
        u32::from_be_bytes(iinf_box[12..16].try_into().unwrap())
    };
    let mut ipos = if iinf_ver == 0 { 14 } else { 16 };
    let mut max_id = 0u32;
    for _ in 0..entry_cnt {
        // Entry header bounds check: size/type (8) + version (1), with item id at +12.
        // Truncated entries must be rejected early to prevent id collisions on partial max_id.
        if ipos + 9 > iinf_box.len() {
            return Err(StrHideError::CorruptedData("Truncated iinf entry".into()));
        }
        let iver = iinf_box[ipos + 8];
        let need = if iver < 3 { 14 } else { 16 };
        if ipos + need > iinf_box.len() {
            return Err(StrHideError::CorruptedData("Truncated iinf entry".into()));
        }
        let isz = u32::from_be_bytes(iinf_box[ipos..ipos + 4].try_into().unwrap()) as usize;
        let iid = if iver < 3 {
            u16::from_be_bytes(iinf_box[ipos + 12..ipos + 14].try_into().unwrap()) as u32
        } else {
            u32::from_be_bytes(iinf_box[ipos + 12..ipos + 16].try_into().unwrap())
        };
        max_id = max_id.max(iid);
        if isz < need {
            return Err(StrHideError::CorruptedData(
                "Malformed iinf entry size".into(),
            ));
        }
        ipos += isz;
    }
    // A crafted infe entry may declare item_id = u32::MAX. Wrapping to 0 here
    // would collide with the primary image's item id (conventionally 1), so
    // refuse the carrier instead of emitting an invalid stego.
    let new_id = max_id
        .checked_add(1)
        .ok_or_else(|| StrHideError::CorruptedData("iinf item_id space exhausted".into()))?;

    // Build new infe
    let new_infe = if new_id <= 0xFFFF {
        let mut b = Vec::with_capacity(21);
        b.extend_from_slice(&21u32.to_be_bytes());
        b.extend_from_slice(b"infe");
        b.push(2); // ver 2
        b.extend_from_slice(&[0, 0, 0]);
        b.extend_from_slice(&(new_id as u16).to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes());
        b.extend_from_slice(b"resv");
        b.push(0);
        b
    } else {
        let mut b = Vec::with_capacity(23);
        b.extend_from_slice(&23u32.to_be_bytes());
        b.extend_from_slice(b"infe");
        b.push(3); // ver 3
        b.extend_from_slice(&[0, 0, 0]);
        b.extend_from_slice(&new_id.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes());
        b.extend_from_slice(b"resv");
        b.push(0);
        b
    };
    let infe_len = new_infe.len();

    // 4. Parse iloc geometry
    let iloc_box = &subboxes[iloc_idx].1;
    // Versioned length gates (same style as `check_iloc_has_target`): the meta
    // sub-box extraction only guarantees `size >= header_len`, so a crafted
    // ultra-short iloc must fail as CorruptedData instead of panicking on the
    // bare index reads below.
    if iloc_box.len() < 14 {
        return Err(StrHideError::CorruptedData("Truncated iloc box".into()));
    }
    let iloc_ver = iloc_box[8];
    if iloc_box.len() < if iloc_ver < 2 { 16 } else { 18 } {
        return Err(StrHideError::CorruptedData("Truncated iloc box".into()));
    }
    let off_sz = ((iloc_box[12] >> 4) & 0x0F) as usize;
    let len_sz = (iloc_box[12] & 0x0F) as usize;
    let base_sz = ((iloc_box[13] >> 4) & 0x0F) as usize;
    let idx_sz = if iloc_ver >= 1 {
        (iloc_box[13] & 0x0F) as usize
    } else {
        0
    };
    let iloc_cnt = if iloc_ver < 2 {
        u16::from_be_bytes(iloc_box[14..16].try_into().unwrap()) as u32
    } else {
        u32::from_be_bytes(iloc_box[14..18].try_into().unwrap())
    };

    let id_sz = if iloc_ver < 2 { 2 } else { 4 };
    let cm_sz = if iloc_ver >= 1 { 2 } else { 0 };
    let iloc_item_len = id_sz + cm_sz + 2 + base_sz + 2 + idx_sz + off_sz + len_sz;
    // `iloc` v0/v1 address items with 16-bit ids and 16-bit entry counts; a
    // larger new id or a full count would silently wrap to 0 and pair the
    // iinf entry with the wrong iloc record. v2+ has 32-bit fields, so only
    // the v0/v1 forms need the guard.
    if iloc_ver < 2 && (new_id > 0xFFFF || iloc_cnt >= 0xFFFF) {
        return Err(StrHideError::UnsupportedFormat(
            "HEIF iloc v0/v1 item-id or entry-count space is exhausted".into(),
        ));
    }
    let delta_meta = infe_len + iloc_item_len;
    let target_ext_off = host_size + delta_meta as u64 + 8;

    // Build new iloc item
    let mut new_iloc_entry = Vec::with_capacity(iloc_item_len);
    if iloc_ver < 2 {
        new_iloc_entry.extend_from_slice(&(new_id as u16).to_be_bytes());
    } else {
        new_iloc_entry.extend_from_slice(&new_id.to_be_bytes());
    }
    if iloc_ver >= 1 {
        new_iloc_entry.extend_from_slice(&0u16.to_be_bytes()); // cm = 0
    }
    new_iloc_entry.extend_from_slice(&0u16.to_be_bytes()); // dref = 0
    new_iloc_entry.resize(new_iloc_entry.len() + base_sz, 0); // base_offset = 0
    new_iloc_entry.extend_from_slice(&1u16.to_be_bytes()); // extent_count = 1
    if idx_sz > 0 {
        new_iloc_entry.resize(new_iloc_entry.len() + idx_sz, 0);
    }
    write_sized_uint(&mut new_iloc_entry, target_ext_off, off_sz)?;
    write_sized_uint(&mut new_iloc_entry, ube_size, len_sz)?;

    // 5. Patch subboxes:
    // Update iloc
    {
        let iloc_buf = &mut subboxes[iloc_idx].1;
        let mut cpos = if iloc_ver < 2 { 16 } else { 18 };
        // Same budget as the read-side scan: declared counts are
        // attacker-controlled and zero-width fields make extent iterations
        // consume no bytes.
        let mut budget = iloc_buf.len();
        for _ in 0..iloc_cnt {
            if budget == 0 {
                return Err(StrHideError::CorruptedData(
                    "iloc item count exceeds the box size".into(),
                ));
            }
            budget -= 1;
            cpos += id_sz;
            let cm = if iloc_ver >= 1 {
                if cpos + 2 > iloc_buf.len() {
                    return Err(StrHideError::CorruptedData("Truncated iloc entry".into()));
                }
                let val = u16::from_be_bytes(iloc_buf[cpos..cpos + 2].try_into().unwrap()) & 0x0F;
                cpos += 2;
                val
            } else {
                0
            };
            cpos += 2; // dref
            let base_pos = cpos;
            let b_off = read_sized_uint(iloc_buf, cpos, base_sz)?;
            cpos += base_sz;
            if cpos + 2 > iloc_buf.len() {
                return Err(StrHideError::CorruptedData("Truncated iloc entry".into()));
            }
            let e_cnt = u16::from_be_bytes(iloc_buf[cpos..cpos + 2].try_into().unwrap()) as usize;
            cpos += 2;
            for _ in 0..e_cnt {
                if budget == 0 {
                    return Err(StrHideError::CorruptedData(
                        "iloc extent count exceeds the box size".into(),
                    ));
                }
                budget -= 1;
                cpos += idx_sz;
                let ext_pos = cpos;
                let ext_off = read_sized_uint(iloc_buf, cpos, off_sz)?;
                cpos += off_sz + len_sz;
                if cm == 0 {
                    // Rewrite base offset only when pointing outside pre-growth `meta`.
                    // When base is inside `meta`, absolute extent offset determines if data moved.
                    let base_patched = base_sz > 0 && b_off > 0 && b_off >= m_end as u64;
                    let abs_off = b_off.saturating_add(ext_off);
                    if !base_patched && abs_off >= m_end as u64 {
                        // Only extents physically located after old meta are shifted by `delta_meta`.
                        // Extents must have sufficient headroom for expansion to prevent overflow.
                        let shifted = ext_off.checked_add(delta_meta as u64).ok_or_else(|| {
                            StrHideError::CorruptedData("iloc extent offset overflows".into())
                        })?;
                        patch_sized_uint(iloc_buf, ext_pos, off_sz, shifted)?;
                    }
                }
            }
            if cm == 0 && base_sz > 0 && b_off > 0 && b_off >= m_end as u64 {
                let shifted = b_off.checked_add(delta_meta as u64).ok_or_else(|| {
                    StrHideError::CorruptedData("iloc base offset overflows".into())
                })?;
                patch_sized_uint(iloc_buf, base_pos, base_sz, shifted)?;
            }
        }

        let new_iloc_sz = u32::try_from(iloc_buf.len() + iloc_item_len)
            .map_err(|_| StrHideError::General("iloc box exceeds its 32-bit size field".into()))?;
        iloc_buf[0..4].copy_from_slice(&new_iloc_sz.to_be_bytes());
        if iloc_ver < 2 {
            let new_cnt = (iloc_cnt + 1) as u16;
            iloc_buf[14..16].copy_from_slice(&new_cnt.to_be_bytes());
        } else {
            let new_cnt = iloc_cnt + 1;
            iloc_buf[14..18].copy_from_slice(&new_cnt.to_be_bytes());
        }
        iloc_buf.extend_from_slice(&new_iloc_entry);
    }

    // Update iinf
    {
        let iinf_buf = &mut subboxes[iinf_idx].1;
        if iinf_ver == 0 && entry_cnt >= 0xFFFF {
            return Err(StrHideError::UnsupportedFormat(
                "HEIF iinf v0 entry-count space is exhausted".into(),
            ));
        }
        let new_iinf_sz = u32::try_from(iinf_buf.len() + infe_len)
            .map_err(|_| StrHideError::General("iinf box exceeds its 32-bit size field".into()))?;
        iinf_buf[0..4].copy_from_slice(&new_iinf_sz.to_be_bytes());
        if iinf_ver == 0 {
            let new_cnt = (entry_cnt + 1) as u16;
            iinf_buf[12..14].copy_from_slice(&new_cnt.to_be_bytes());
        } else {
            let new_cnt = entry_cnt + 1;
            iinf_buf[12..16].copy_from_slice(&new_cnt.to_be_bytes());
        }
        iinf_buf.extend_from_slice(&new_infe);
    }

    // 6. Reassemble meta
    let mut new_meta_body = Vec::new();
    for (_, b) in &subboxes {
        new_meta_body.extend_from_slice(b);
    }
    new_meta_body.extend_from_slice(&meta_tail);
    let new_meta_size = u32::try_from(new_meta_body.len() + 12)
        .map_err(|_| StrHideError::General("meta box exceeds its 32-bit size field".into()))?;
    let mut patched_meta = Vec::with_capacity(new_meta_size as usize);
    patched_meta.extend_from_slice(&new_meta_size.to_be_bytes());
    patched_meta.extend_from_slice(b"meta");
    patched_meta.extend_from_slice(&host_prefix[m_off + 8..m_off + 12]);
    patched_meta.extend_from_slice(&new_meta_body);

    // 7. Write output stream: the bytes before meta and everything after it
    // are streamed, so a large HEIF is never fully buffered.
    out.write_all(&host_prefix[..m_off])?;
    out.write_all(&patched_meta)?;
    host_in.seek(SeekFrom::Start((m_off + m_size) as u64))?;
    crate::structure::adapters::io::copy_stream(host_in, out)?;

    // Second mdat box
    ube_in.seek(SeekFrom::Start(0))?;
    let mdat2_size = u32::try_from(8 + ube_size)
        .map_err(|_| StrHideError::General("Envelope too large for 32-bit mdat box".into()))?;
    out.write_all(&mdat2_size.to_be_bytes())?;
    out.write_all(b"mdat")?;
    crate::structure::adapters::io::copy_exact(ube_in, out, ube_size)?;

    let inject_offset = host_size + delta_meta as u64;
    let inject_size = 8 + ube_size;

    Ok(InjectCoordinates {
        offset: inject_offset,
        size: inject_size,
        patch_offset: 0,
        original_patch_value: 0,
    })
}

pub(super) fn heif_item_hidden_strip(
    stego_in: &mut dyn SeekRead,
    out: &mut dyn SeekWrite,
    header: &EnvelopeHeader,
) -> Result<(), StrHideError> {
    stego_in.seek(SeekFrom::End(0))?;
    let total_size = stego_in.stream_position()?;
    if header.inject_offset > total_size {
        return Err(StrHideError::CorruptedData("Inject offset past EOF".into()));
    }

    // 1. Locate the meta box by streaming its header; only the bytes up to the
    // end of meta stay in memory, the rest of the carrier is streamed back out.
    let mut pos = 0u64;
    let mut meta_span = None;
    while pos + 8 <= total_size {
        let (bsize, hlen, tag) = read_stream_box_header(stego_in, pos, total_size)?;
        if tag == *b"meta" {
            meta_span = Some((pos, bsize, hlen));
            break;
        }
        pos += bsize;
    }
    let (m_off, m_size, m_hlen) = meta_span.ok_or_else(|| {
        StrHideError::CorruptedData("No meta box found in HEIF carrier for strip".into())
    })?;
    if m_hlen != 8 {
        return Err(StrHideError::CorruptedData(
            "64-bit meta box header is not supported for item_hidden strip".into(),
        ));
    }
    let m_off = usize::try_from(m_off)
        .map_err(|_| StrHideError::CorruptedData("meta box offset exceeds usize".into()))?;
    let m_size = usize::try_from(m_size)
        .map_err(|_| StrHideError::CorruptedData("meta box size exceeds usize".into()))?;
    let m_end = m_off
        .checked_add(m_size)
        .ok_or_else(|| StrHideError::CorruptedData("meta box offset overflows".into()))?;
    if m_end as u64 > MAX_ISOBMFF_META_SCAN {
        return Err(StrHideError::CorruptedData(
            "HEIF meta box is too large for item_hidden strip".into(),
        ));
    }
    stego_in.seek(SeekFrom::Start(0))?;
    let mut stego_prefix = vec![0u8; m_end];
    stego_in.read_exact(&mut stego_prefix)?;

    let m_body_start = m_off + m_hlen + 4;
    if m_body_start > m_end {
        return Err(StrHideError::CorruptedData("Truncated meta box".into()));
    }

    // The header is only masked with the public built-in key, so a forged
    // stego can name arbitrary coordinates. Beyond the EOF check above, the
    // meta box must end before the injected region and the injected region
    // (meta growth + the trailing mdat2 box) must run to the end of the file;
    // anything else would slice with start > end in step 7 below.
    if header.inject_offset < m_end as u64 {
        return Err(StrHideError::CorruptedData(
            "inject_offset precedes the end of the meta box".into(),
        ));
    }
    let inject_end = header
        .inject_offset
        .checked_add(header.inject_size)
        .ok_or_else(|| {
            StrHideError::CorruptedData("Injected region overflows u64 offsets".into())
        })?;
    if inject_end != total_size {
        return Err(StrHideError::CorruptedData(
            "inject_offset + inject_size does not match the stego file length".into(),
        ));
    }

    // 2. Extract sub-boxes in meta
    let mut subboxes: Vec<([u8; 4], Vec<u8>)> = Vec::new();
    let mut bpos = m_body_start;
    while bpos + 8 <= m_end {
        let (s_size, s_hlen) = read_box_size(&stego_prefix, bpos)?;
        if s_size < s_hlen || s_size > m_end - bpos {
            return Err(StrHideError::CorruptedData(
                "Invalid sub-box in meta".into(),
            ));
        }
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&stego_prefix[bpos + 4..bpos + 8]);
        subboxes.push((tag, stego_prefix[bpos..bpos + s_size].to_vec()));
        bpos += s_size;
    }
    // Preserve trailing meta residue (<8 bytes) verbatim during restoration.
    let meta_tail: Vec<u8> = if bpos < m_end {
        stego_prefix[bpos..m_end].to_vec()
    } else {
        Vec::new()
    };

    let iinf_idx = subboxes
        .iter()
        .position(|(tag, _)| tag == b"iinf")
        .ok_or_else(|| StrHideError::CorruptedData("Missing iinf box in meta".into()))?;
    let iloc_idx = subboxes
        .iter()
        .position(|(tag, _)| tag == b"iloc")
        .ok_or_else(|| StrHideError::CorruptedData("Missing iloc box in meta".into()))?;

    // 3. Inspect iloc and iinf to determine added lengths
    let (iloc_item_len, infe_len, delta_meta) = {
        let iloc_box = &subboxes[iloc_idx].1;
        if iloc_box.len() < 14 {
            return Err(StrHideError::CorruptedData("Truncated iloc box".into()));
        }
        let iloc_ver = iloc_box[8];
        let off_sz = ((iloc_box[12] >> 4) & 0x0F) as usize;
        let len_sz = (iloc_box[12] & 0x0F) as usize;
        let base_sz = ((iloc_box[13] >> 4) & 0x0F) as usize;
        let idx_sz = if iloc_ver >= 1 {
            (iloc_box[13] & 0x0F) as usize
        } else {
            0
        };
        let id_sz = if iloc_ver < 2 { 2 } else { 4 };
        let cm_sz = if iloc_ver >= 1 { 2 } else { 0 };
        let item_len = id_sz + cm_sz + 2 + base_sz + 2 + idx_sz + off_sz + len_sz;

        let iinf_box = &subboxes[iinf_idx].1;
        if iinf_box.len() < 12 {
            return Err(StrHideError::CorruptedData("Truncated iinf box".into()));
        }
        let iinf_ver = iinf_box[8];
        if iinf_box.len() < if iinf_ver == 0 { 14 } else { 16 } {
            return Err(StrHideError::CorruptedData("Truncated iinf box".into()));
        }
        let entry_cnt = if iinf_ver == 0 {
            u16::from_be_bytes(iinf_box[12..14].try_into().unwrap()) as usize
        } else {
            u32::from_be_bytes(iinf_box[12..16].try_into().unwrap()) as usize
        };
        if entry_cnt == 0 {
            return Err(StrHideError::CorruptedData("Empty iinf box".into()));
        }
        // Walk the entries by their own size fields instead of guessing the
        // trailing entry's length from 21/23-byte templates: a third-party
        // re-mux or a crafted `infe` used to mis-compute `delta_meta` and shift
        // every post-meta `iloc` offset by the wrong amount.
        let mut pos = if iinf_ver == 0 { 14 } else { 16 };
        let mut trailing_infe_len = None;
        for _ in 0..entry_cnt {
            if pos + 8 > iinf_box.len() {
                return Err(StrHideError::CorruptedData("Truncated iinf entry".into()));
            }
            let size = u32::from_be_bytes(iinf_box[pos..pos + 4].try_into().unwrap()) as usize;
            let end = pos
                .checked_add(size)
                .filter(|&end| size >= 8 && end <= iinf_box.len())
                .ok_or_else(|| StrHideError::CorruptedData("Invalid iinf entry size".into()))?;
            if &iinf_box[pos + 4..pos + 8] == b"infe" && end == iinf_box.len() {
                trailing_infe_len = Some(size);
            }
            pos = end;
        }
        if pos != iinf_box.len() {
            return Err(StrHideError::CorruptedData(
                "iinf entry count does not cover the box".into(),
            ));
        }
        let actual_infe_len = trailing_infe_len.ok_or_else(|| {
            StrHideError::CorruptedData("Could not locate the trailing infe entry".into())
        })?;
        (item_len, actual_infe_len, actual_infe_len + item_len)
    };

    // 4. Strip iloc
    {
        let iloc_buf = &mut subboxes[iloc_idx].1;
        if iloc_buf.len() < 14 {
            return Err(StrHideError::CorruptedData("Truncated iloc box".into()));
        }
        let iloc_ver = iloc_buf[8];
        let off_sz = ((iloc_buf[12] >> 4) & 0x0F) as usize;
        let len_sz = (iloc_buf[12] & 0x0F) as usize;
        let base_sz = ((iloc_buf[13] >> 4) & 0x0F) as usize;
        let idx_sz = if iloc_ver >= 1 {
            (iloc_buf[13] & 0x0F) as usize
        } else {
            0
        };
        let id_sz = if iloc_ver < 2 { 2 } else { 4 };
        // The count read requires 16 bytes (v0/v1) or 18 bytes (v2+); check before reading.
        if iloc_buf.len() < if iloc_ver < 2 { 16 } else { 18 } {
            return Err(StrHideError::CorruptedData("Truncated iloc box".into()));
        }
        let iloc_cnt = if iloc_ver < 2 {
            u16::from_be_bytes(iloc_buf[14..16].try_into().unwrap()) as u32
        } else {
            u32::from_be_bytes(iloc_buf[14..18].try_into().unwrap())
        };
        if iloc_cnt == 0 || iloc_buf.len() < iloc_item_len {
            return Err(StrHideError::CorruptedData("Invalid iloc for strip".into()));
        }

        iloc_buf.truncate(iloc_buf.len() - iloc_item_len);
        let new_iloc_sz = u32::try_from(iloc_buf.len())
            .map_err(|_| StrHideError::CorruptedData("iloc box exceeds 32-bit size".into()))?;
        iloc_buf[0..4].copy_from_slice(&new_iloc_sz.to_be_bytes());
        if iloc_ver < 2 {
            let new_cnt = (iloc_cnt - 1) as u16;
            iloc_buf[14..16].copy_from_slice(&new_cnt.to_be_bytes());
        } else {
            let new_cnt = iloc_cnt - 1;
            iloc_buf[14..18].copy_from_slice(&new_cnt.to_be_bytes());
        }

        // Shift remaining items back
        let mut cpos = if iloc_ver < 2 { 16 } else { 18 };
        // Same per-byte iteration budget as the other iloc scans.
        let mut budget = iloc_buf.len();
        for _ in 0..iloc_cnt - 1 {
            if budget == 0 {
                return Err(StrHideError::CorruptedData(
                    "iloc item count exceeds the box size".into(),
                ));
            }
            budget -= 1;
            cpos += id_sz;
            let cm = if iloc_ver >= 1 {
                if cpos + 2 > iloc_buf.len() {
                    return Err(StrHideError::CorruptedData("Truncated iloc entry".into()));
                }
                let val = u16::from_be_bytes(iloc_buf[cpos..cpos + 2].try_into().unwrap()) & 0x0F;
                cpos += 2;
                val
            } else {
                0
            };
            cpos += 2; // dref
            let base_pos = cpos;
            let b_off = read_sized_uint(iloc_buf, cpos, base_sz)?;
            cpos += base_sz;
            if cpos + 2 > iloc_buf.len() {
                return Err(StrHideError::CorruptedData("Truncated iloc entry".into()));
            }
            let e_cnt = u16::from_be_bytes(iloc_buf[cpos..cpos + 2].try_into().unwrap()) as usize;
            cpos += 2;
            for _ in 0..e_cnt {
                if budget == 0 {
                    return Err(StrHideError::CorruptedData(
                        "iloc extent count exceeds the box size".into(),
                    ));
                }
                budget -= 1;
                cpos += idx_sz;
                let ext_pos = cpos;
                let ext_off = read_sized_uint(iloc_buf, cpos, off_sz)?;
                cpos += off_sz + len_sz;
                if cm == 0 {
                    // Mirror the inject-side condition exactly: an extent is
                    // reverted when its absolute position moved, which is not
                    // the same as "a base offset exists".
                    let base_patched = base_sz > 0 && b_off > 0 && b_off >= m_end as u64;
                    let abs_off = b_off.saturating_add(ext_off);
                    if !base_patched && abs_off >= m_end as u64 {
                        patch_sized_uint(
                            iloc_buf,
                            ext_pos,
                            off_sz,
                            ext_off.saturating_sub(delta_meta as u64),
                        )?;
                    }
                }
            }
            if cm == 0 && base_sz > 0 && b_off > 0 && b_off >= m_end as u64 {
                patch_sized_uint(
                    iloc_buf,
                    base_pos,
                    base_sz,
                    b_off.saturating_sub(delta_meta as u64),
                )?;
            }
        }
    }

    // 5. Strip iinf
    {
        let iinf_buf = &mut subboxes[iinf_idx].1;
        if iinf_buf.len() < 14 {
            return Err(StrHideError::CorruptedData("Truncated iinf box".into()));
        }
        let iinf_ver = iinf_buf[8];
        if iinf_buf.len() < if iinf_ver == 0 { 14 } else { 16 } {
            return Err(StrHideError::CorruptedData("Truncated iinf box".into()));
        }
        let entry_cnt = if iinf_ver == 0 {
            u16::from_be_bytes(iinf_buf[12..14].try_into().unwrap()) as u32
        } else {
            u32::from_be_bytes(iinf_buf[12..16].try_into().unwrap())
        };
        if entry_cnt == 0 || iinf_buf.len() < infe_len {
            return Err(StrHideError::CorruptedData("Invalid iinf for strip".into()));
        }
        iinf_buf.truncate(iinf_buf.len() - infe_len);
        let new_iinf_sz = u32::try_from(iinf_buf.len())
            .map_err(|_| StrHideError::CorruptedData("iinf box exceeds 32-bit size".into()))?;
        iinf_buf[0..4].copy_from_slice(&new_iinf_sz.to_be_bytes());
        if iinf_ver == 0 {
            let new_cnt = (entry_cnt - 1) as u16;
            iinf_buf[12..14].copy_from_slice(&new_cnt.to_be_bytes());
        } else {
            let new_cnt = entry_cnt - 1;
            iinf_buf[12..16].copy_from_slice(&new_cnt.to_be_bytes());
        }
    }

    // 6. Reassemble restored meta
    let mut restored_meta_body = Vec::new();
    for (_, b) in &subboxes {
        restored_meta_body.extend_from_slice(b);
    }
    restored_meta_body.extend_from_slice(&meta_tail);
    let restored_meta_size = u32::try_from(restored_meta_body.len() + 12)
        .map_err(|_| StrHideError::CorruptedData("meta box exceeds 32-bit size".into()))?;
    let mut restored_meta = Vec::with_capacity(restored_meta_size as usize);
    restored_meta.extend_from_slice(&restored_meta_size.to_be_bytes());
    restored_meta.extend_from_slice(b"meta");
    restored_meta.extend_from_slice(&stego_prefix[m_off + 8..m_off + 12]);
    restored_meta.extend_from_slice(&restored_meta_body);

    // 7. Write output: prefix, restored meta, then the untouched host bytes up
    // to the injected mdat2, streamed instead of sliced from a whole-file Vec.
    out.write_all(&stego_prefix[..m_off])?;
    out.write_all(&restored_meta)?;
    let tail_start = (m_off + m_size) as u64;
    let tail_len = header
        .inject_offset
        .checked_sub(tail_start)
        .ok_or_else(|| {
            StrHideError::CorruptedData("Restored tail starts past inject_offset".into())
        })?;
    stego_in.seek(SeekFrom::Start(tail_start))?;
    crate::structure::adapters::io::copy_exact(stego_in, out, tail_len)?;

    Ok(())
}
