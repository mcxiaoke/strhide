//! Shared ISO Base Media File Format (ISO BMFF / ISOBMFF) utilities.
//!
//! Used by [`super::mp4::Mp4Adapter`] and [`super::heif::HeifAdapter`].

use std::io::{SeekFrom, Write};

use crate::adapters::{SeekRead, SeekWrite, StrategyCapacity};
use crate::envelope::{EnvelopeHeader, EnvelopeTrailer};
use crate::errors::StrHideError;

pub const MP4_UUID_NEUTRAL: [u8; 16] = [
    0xd4, 0x1a, 0x8e, 0x9c, 0x4f, 0x21, 0x4e, 0x87, 0x9a, 0x33, 0x5b, 0x6d, 0x12, 0x84, 0xef, 0x70,
];

/// Largest envelope the `item_hidden` strategy can carry: the second `mdat`
/// box writes its size into a 32-bit field (`8 + ube_size <= u32::MAX`) and
/// registers the extent through 32-bit iloc offset/length fields. Capacity
/// text and the auto strategy both derive from this constant (review P2-4).
pub const ITEM_HIDDEN_MAX_ENVELOPE: u64 = u32::MAX as u64 - 8;

/// Bytes of Box header written before the envelope for the `box_uuid`
/// strategy: 24 for the standard 32-bit header (`size` + `uuid` + usertype),
/// 32 for the 64-bit large header (`size == 1` + `uuid` + `largesize` +
/// usertype).
///
/// The 32-bit form can only express a box size below `0xFFFFFFFF`, and that
/// value is where the 64-bit form takes over. Both the writer and the
/// `envelope_offset_delta` accounting must agree on the switchover point, so
/// the decision lives here and nowhere else.
pub fn calc_prefix_len(ube_size: u64) -> u64 {
    if 24 + ube_size < 0xFFFFFFFF { 24 } else { 32 }
}

pub fn trailing_envelope_len(
    stego_in: &mut dyn SeekRead,
    offset: u64,
    total_size: u64,
) -> Option<u64> {
    let remaining = total_size.checked_sub(offset)?;
    if remaining < 24 {
        return None;
    }
    if stego_in.seek(SeekFrom::End(-24)).is_err() {
        return None;
    }
    let mut tail = [0u8; 24];
    if stego_in.read_exact(&mut tail).is_err() {
        return None;
    }
    if stego_in.seek(SeekFrom::Start(offset)).is_err() {
        return None;
    }
    let ube_offset = u64::from_le_bytes(tail[0..8].try_into().ok()?);
    let ube_total_size = u64::from_le_bytes(tail[8..16].try_into().ok()?);
    if ube_offset != offset || ube_offset.checked_add(ube_total_size) != Some(total_size) {
        return None;
    }
    Some(ube_total_size)
}

pub fn isobmff_inject(
    format_name: &str,
    host_in: &mut dyn SeekRead,
    ube_in: &mut dyn SeekRead,
    out: &mut dyn Write,
    strategy: &str,
) -> Result<(u64, u64, u32, u32), StrHideError> {
    if strategy == "item_hidden" {
        return heif_item_hidden_inject(host_in, ube_in, out);
    }
    if strategy != "box_uuid" && strategy != "free_box" && strategy != "eof" {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Strategy '{strategy}' not supported by {format_name} adapter"
        )));
    }

    host_in.seek(SeekFrom::Start(0))?;
    let host_len = crate::adapters::io::copy_stream(host_in, out)?;

    let inject_offset = host_len;
    let ube_size = ube_in.seek(SeekFrom::End(0))?;
    ube_in.seek(SeekFrom::Start(0))?;

    let inject_size = if strategy == "box_uuid" {
        // The switchover lives in `calc_prefix_len`, which the envelope-offset
        // accounting also uses; duplicating the threshold here is how the two
        // silently drift apart.
        let header_len = calc_prefix_len(ube_size);
        let total_box_size = header_len + ube_size;
        if header_len == 24 {
            // Standard 32-bit Box header.
            out.write_all(&(total_box_size as u32).to_be_bytes())?;
            out.write_all(b"uuid")?;
            out.write_all(&MP4_UUID_NEUTRAL)?;
        } else {
            // 64-bit Large Box header: `size == 1` plus an explicit 64-bit
            // `largesize` that counts the whole box, header included.
            out.write_all(&(1u32).to_be_bytes())?;
            out.write_all(b"uuid")?;
            out.write_all(&total_box_size.to_be_bytes())?;
            out.write_all(&MP4_UUID_NEUTRAL)?;
        }
        total_box_size
    } else if strategy == "free_box" {
        let total_box_size = 8 + ube_size;
        let bsize = u32::try_from(total_box_size)
            .map_err(|_| StrHideError::General("Envelope too large for 32-bit free box".into()))?;
        out.write_all(&bsize.to_be_bytes())?;
        out.write_all(b"free")?;
        total_box_size
    } else {
        ube_size
    };

    crate::adapters::io::copy_stream(ube_in, out)?;

    Ok((inject_offset, inject_size, 0, 0))
}

pub fn isobmff_locate(
    stego_in: &mut dyn SeekRead,
    expected_trailer_magic: Option<&[u8; 4]>,
) -> Result<Option<(u64, u64, String)>, StrHideError> {
    let trailer = match EnvelopeTrailer::read_from_tail(stego_in, expected_trailer_magic)? {
        Some(t) => t,
        None => return Ok(None),
    };

    // 1. Check standard 32-bit uuid box (24-byte header before trailer.ube_offset)
    if trailer.ube_offset >= 24 {
        stego_in.seek(SeekFrom::Start(trailer.ube_offset - 24))?;
        let mut hdr24 = [0u8; 24];
        if stego_in.read_exact(&mut hdr24).is_ok() {
            let box_type = &hdr24[4..8];
            let box_uuid = &hdr24[8..24];
            let box_size = u32::from_be_bytes(hdr24[0..4].try_into().unwrap()) as u64;

            if box_type == b"uuid"
                && box_uuid == MP4_UUID_NEUTRAL
                && box_size == 24 + trailer.ube_total_size
            {
                return Ok(Some((
                    trailer.ube_offset,
                    trailer.ube_total_size,
                    "box_uuid".into(),
                )));
            }
        }
    }

    // 2. Check 64-bit uuid box (32-byte header before trailer.ube_offset)
    if trailer.ube_offset >= 32 {
        stego_in.seek(SeekFrom::Start(trailer.ube_offset - 32))?;
        let mut hdr32 = [0u8; 32];
        if stego_in.read_exact(&mut hdr32).is_ok() {
            let box_size = u32::from_be_bytes(hdr32[0..4].try_into().unwrap());
            let box_type = &hdr32[4..8];
            let large_size = u64::from_be_bytes(hdr32[8..16].try_into().unwrap());
            let box_uuid = &hdr32[16..32];

            if box_size == 1
                && box_type == b"uuid"
                && box_uuid == MP4_UUID_NEUTRAL
                && large_size == 32 + trailer.ube_total_size
            {
                return Ok(Some((
                    trailer.ube_offset,
                    trailer.ube_total_size,
                    "box_uuid".into(),
                )));
            }
        }
    }

    // 3. Check 8-byte box header before trailer.ube_offset (free_box or item_hidden)
    if trailer.ube_offset >= 8 {
        stego_in.seek(SeekFrom::Start(trailer.ube_offset - 8))?;
        let mut hdr8 = [0u8; 8];
        if stego_in.read_exact(&mut hdr8).is_ok() {
            let box_size = u32::from_be_bytes(hdr8[0..4].try_into().unwrap()) as u64;
            let box_type = &hdr8[4..8];
            if box_size == 8 + trailer.ube_total_size {
                if box_type == b"free" || box_type == b"skip" {
                    return Ok(Some((
                        trailer.ube_offset,
                        trailer.ube_total_size,
                        "free_box".into(),
                    )));
                }
                if box_type == b"mdat"
                    && isobmff_has_iloc_item(stego_in, trailer.ube_offset, trailer.ube_total_size)?
                {
                    return Ok(Some((
                        trailer.ube_offset,
                        trailer.ube_total_size,
                        "item_hidden".into(),
                    )));
                }
            }
        }
    }

    // 4. Fallback to EOF
    let file_size = stego_in.seek(SeekFrom::End(0))?;
    if trailer.ube_offset.checked_add(trailer.ube_total_size) == Some(file_size) {
        return Ok(Some((
            trailer.ube_offset,
            trailer.ube_total_size,
            "eof".into(),
        )));
    }

    Ok(None)
}

pub fn isobmff_verify_structure(
    format_name: &str,
    stego_in: &mut dyn SeekRead,
) -> Result<(bool, String), StrHideError> {
    let total_size = stego_in.seek(SeekFrom::End(0))?;
    stego_in.seek(SeekFrom::Start(0))?;

    let mut offset = 0u64;
    let mut box_count = 0u64;
    let mut has_ftyp = false;

    while offset < total_size {
        if let Some(envelope_len) = trailing_envelope_len(stego_in, offset, total_size) {
            return Ok((
                true,
                format!(
                    "Valid ISO BMFF container ({box_count} top-level boxes, {envelope_len} bytes appended after the last box)"
                ),
            ));
        }

        let mut hdr = [0u8; 8];
        if stego_in.read_exact(&mut hdr).is_err() {
            return Ok((false, format!("Truncated box header at offset {offset}")));
        }
        let size = u32::from_be_bytes(hdr[0..4].try_into().unwrap());
        let box_type = &hdr[4..8];
        if box_type == *b"ftyp" {
            has_ftyp = true;
        }

        let (box_size, header_len) = if size == 1 {
            let mut large = [0u8; 8];
            if stego_in.read_exact(&mut large).is_err() {
                return Ok((
                    false,
                    format!(
                        "Truncated 64-bit size for box {}",
                        String::from_utf8_lossy(box_type)
                    ),
                ));
            }
            (u64::from_be_bytes(large), 16u64)
        } else if size == 0 {
            (total_size - offset, 8u64)
        } else {
            (size as u64, 8u64)
        };

        if box_size < header_len {
            return Ok((
                false,
                format!(
                    "Invalid box size {box_size} for box {}",
                    String::from_utf8_lossy(box_type)
                ),
            ));
        }

        let box_offset = offset;
        let next_offset = match offset.checked_add(box_size) {
            Some(o) => o,
            None => {
                return Ok((
                    false,
                    format!(
                        "Box {} at offset {box_offset} size calculation overflows u64",
                        String::from_utf8_lossy(box_type)
                    ),
                ));
            }
        };
        offset = next_offset;
        box_count += 1;
        if box_count > 1_000_000 {
            return Ok((
                false,
                "Exceeded maximum top-level box count (1000000)".into(),
            ));
        }
        if offset > total_size {
            return Ok((
                false,
                format!(
                    "Box {} at offset {box_offset} extends past end of file",
                    String::from_utf8_lossy(box_type)
                ),
            ));
        }
        stego_in.seek(SeekFrom::Start(offset))?;
    }

    if !has_ftyp {
        return Ok((false, format!("{format_name} missing ftyp box")));
    }

    Ok((
        true,
        format!("Valid ISO BMFF container ({box_count} top-level boxes)"),
    ))
}

pub fn isobmff_suspicious_structures(stego_in: &mut dyn SeekRead) -> Vec<String> {
    let mut found = Vec::new();
    let file_size = match stego_in.seek(SeekFrom::End(0)) {
        Ok(s) => s,
        Err(_) => return found,
    };
    if file_size < 24 {
        return found;
    }
    if stego_in.seek(SeekFrom::End(-24)).is_err() {
        return found;
    }
    let mut tail = [0u8; 24];
    if stego_in.read_exact(&mut tail).is_err() {
        return found;
    }
    let ube_offset = u64::from_le_bytes(tail[0..8].try_into().unwrap());
    let ube_total_size = u64::from_le_bytes(tail[8..16].try_into().unwrap());
    if ube_offset.checked_add(ube_total_size) != Some(file_size) {
        return found;
    }
    if ube_offset >= 24 && stego_in.seek(SeekFrom::Start(ube_offset - 24)).is_ok() {
        let mut hdr = [0u8; 24];
        if stego_in.read_exact(&mut hdr).is_ok() && &hdr[4..8] == b"uuid" {
            let uuid = &hdr[8..24];
            if uuid == MP4_UUID_NEUTRAL {
                found.push(format!(
                    "trailing uuid box at offset {} carries {ube_total_size} bytes",
                    ube_offset - 24
                ));
            }
        }
    }

    // The 64-bit large-size form (`size == 1` + largesize + usertype) is only
    // produced for envelopes at or above 4 GiB, so it will not show up in a
    // scan of typical carriers -- but a carrier that has one is exactly the
    // case a structural scan must not miss.
    if ube_offset >= 32 && stego_in.seek(SeekFrom::Start(ube_offset - 32)).is_ok() {
        let mut hdr = [0u8; 32];
        if stego_in.read_exact(&mut hdr).is_ok()
            && u32::from_be_bytes(hdr[0..4].try_into().unwrap()) == 1
            && &hdr[4..8] == b"uuid"
            && hdr[16..32] == MP4_UUID_NEUTRAL
        {
            found.push(format!(
                "trailing 64-bit uuid box at offset {} carries {ube_total_size} bytes",
                ube_offset - 32
            ));
        }
    }
    found
}

pub fn isobmff_strategy_capacities() -> Vec<StrategyCapacity> {
    vec![
        StrategyCapacity {
            strategy: "box_uuid".into(),
            capacity_bytes: None,
            available: true,
            limit: "unlimited (file grows)".into(),
            note: Some(
                "uuid box with a 32-bit header below 4 GiB and a 64-bit large header at or above it; media frame offsets preserved"
                    .into(),
            ),
        },
        StrategyCapacity {
            strategy: "eof".into(),
            capacity_bytes: None,
            available: true,
            limit: "unlimited (file grows)".into(),
            note: Some("appended at EOF".into()),
        },
    ]
}

pub fn heif_strategy_capacities() -> Vec<StrategyCapacity> {
    vec![
        StrategyCapacity {
            strategy: "item_hidden".into(),
            capacity_bytes: None,
            available: true,
            limit: "up to ~4 GiB envelope (32-bit mdat box and iloc fields); file grows".into(),
            note: Some(
                "hidden ISO BMFF Item registered in iinf/iloc; unreferenced by pitm/iref, primary photo bit-exact, zero suspicious boxes".into(),
            ),
        },
        StrategyCapacity {
            strategy: "free_box".into(),
            capacity_bytes: None,
            available: true,
            limit: "up to ~4 GiB envelope (32-bit box size); file grows".into(),
            note: Some("standard ISO BMFF free padding box at EOF; skipped by all standard media decoders".into()),
        },
        StrategyCapacity {
            strategy: "box_uuid".into(),
            capacity_bytes: None,
            available: true,
            limit: "unlimited (file grows)".into(),
            note: Some(
                "uuid box with a 32-bit header below 4 GiB and a 64-bit large header at or above it; media frame offsets preserved".into(),
            ),
        },
        StrategyCapacity {
            strategy: "eof".into(),
            capacity_bytes: None,
            available: true,
            limit: "unlimited (file grows)".into(),
            note: Some("appended at EOF".into()),
        },
    ]
}

pub fn isobmff_can_item_hidden(reader: &mut dyn SeekRead) -> bool {
    let start_pos = match reader.stream_position() {
        Ok(p) => p,
        Err(_) => return false,
    };
    if reader.seek(SeekFrom::Start(0)).is_err() {
        return false;
    }
    let mut data = Vec::new();
    if reader.read_to_end(&mut data).is_err() {
        let _ = reader.seek(SeekFrom::Start(start_pos));
        return false;
    }
    let _ = reader.seek(SeekFrom::Start(start_pos));

    let mut pos = 0usize;
    while pos + 8 <= data.len() {
        let (bsize, _) = match read_box_size(&data, pos) {
            Ok(s) => s,
            Err(_) => return false,
        };
        if bsize == 0 || pos + bsize > data.len() {
            break;
        }
        if &data[pos + 4..pos + 8] == b"meta" {
            let m_end = pos + bsize;
            let mut mpos = pos + 12;
            let mut has_iinf = false;
            let mut has_iloc = false;
            while mpos + 8 <= m_end {
                let (sb_size, _) = match read_box_size(&data, mpos) {
                    Ok(s) => s,
                    Err(_) => break,
                };
                if sb_size == 0 || mpos + sb_size > m_end {
                    break;
                }
                if &data[mpos + 4..mpos + 8] == b"iinf" {
                    has_iinf = true;
                } else if &data[mpos + 4..mpos + 8] == b"iloc" {
                    has_iloc = true;
                }
                mpos += sb_size;
            }
            return has_iinf && has_iloc;
        }
        pos += bsize;
    }
    false
}

pub fn isobmff_strip(
    stego_in: &mut dyn SeekRead,
    out: &mut dyn SeekWrite,
    header: &EnvelopeHeader,
) -> Result<(), StrHideError> {
    if header.strategy_id == 12 {
        return heif_item_hidden_strip(stego_in, out, header);
    }
    stego_in.seek(SeekFrom::Start(0))?;
    crate::adapters::io::copy_exact(stego_in, out, header.inject_offset)?;
    let inject_end = header
        .inject_offset
        .checked_add(header.inject_size)
        .ok_or_else(|| {
            StrHideError::CorruptedData(format!(
                "Injected region [{}, {}] overflows u64 offsets",
                header.inject_offset, header.inject_size
            ))
        })?;
    stego_in.seek(SeekFrom::Start(inject_end))?;
    crate::adapters::io::copy_stream(stego_in, out)?;
    Ok(())
}

fn read_box_size(bytes: &[u8], pos: usize) -> Result<(usize, usize), StrHideError> {
    if pos + 8 > bytes.len() {
        return Err(StrHideError::CorruptedData("Truncated box header".into()));
    }
    let size32 = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap());
    if size32 == 1 {
        if pos + 16 > bytes.len() {
            return Err(StrHideError::CorruptedData(
                "Truncated 64-bit box header".into(),
            ));
        }
        let size64 = u64::from_be_bytes(bytes[pos + 8..pos + 16].try_into().unwrap()) as usize;
        Ok((size64, 16))
    } else if size32 == 0 {
        Ok((bytes.len() - pos, 8))
    } else {
        Ok((size32 as usize, 8))
    }
}

fn write_sized_uint(buf: &mut Vec<u8>, val: u64, width: usize) -> Result<(), StrHideError> {
    match width {
        4 => {
            let v32 = u32::try_from(val).map_err(|_| {
                StrHideError::General(format!("Offset {val} overflows 32-bit iloc field"))
            })?;
            buf.extend_from_slice(&v32.to_be_bytes());
            Ok(())
        }
        8 => {
            buf.extend_from_slice(&val.to_be_bytes());
            Ok(())
        }
        _ => Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported iloc field width {width}"
        ))),
    }
}

fn patch_sized_uint(
    buf: &mut [u8],
    pos: usize,
    width: usize,
    val: u64,
) -> Result<(), StrHideError> {
    match width {
        4 => {
            let v32 = u32::try_from(val).map_err(|_| {
                StrHideError::General(format!("Offset {val} overflows 32-bit iloc field"))
            })?;
            buf[pos..pos + 4].copy_from_slice(&v32.to_be_bytes());
            Ok(())
        }
        8 => {
            buf[pos..pos + 8].copy_from_slice(&val.to_be_bytes());
            Ok(())
        }
        _ => Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported iloc field width {width}"
        ))),
    }
}

fn read_sized_uint(buf: &[u8], pos: usize, width: usize) -> Result<u64, StrHideError> {
    match width {
        0 => Ok(0),
        4 => {
            if pos + 4 > buf.len() {
                return Err(StrHideError::CorruptedData("Truncated 32-bit uint".into()));
            }
            Ok(u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap()) as u64)
        }
        8 => {
            if pos + 8 > buf.len() {
                return Err(StrHideError::CorruptedData("Truncated 64-bit uint".into()));
            }
            Ok(u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap()))
        }
        _ => Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported field width {width}"
        ))),
    }
}

fn heif_item_hidden_inject(
    host_in: &mut dyn SeekRead,
    ube_in: &mut dyn SeekRead,
    out: &mut dyn Write,
) -> Result<(u64, u64, u32, u32), StrHideError> {
    host_in.seek(SeekFrom::Start(0))?;
    let mut host_bytes = Vec::new();
    host_in.read_to_end(&mut host_bytes)?;

    let ube_size = ube_in.seek(SeekFrom::End(0))?;
    ube_in.seek(SeekFrom::Start(0))?;
    let mut ube_bytes = Vec::with_capacity(ube_size as usize);
    ube_in.read_to_end(&mut ube_bytes)?;

    // 1. Locate meta box
    let mut pos = 0usize;
    let mut meta_span = None;
    while pos + 8 <= host_bytes.len() {
        let (bsize, hlen) = read_box_size(&host_bytes, pos)?;
        if bsize < hlen || pos + bsize > host_bytes.len() {
            return Err(StrHideError::CorruptedData("Invalid box size".into()));
        }
        if &host_bytes[pos + 4..pos + 8] == b"meta" {
            meta_span = Some((pos, bsize, hlen));
            break;
        }
        pos += bsize;
    }
    let (m_off, m_size, m_hlen) = meta_span.ok_or_else(|| {
        StrHideError::UnsupportedFormat("No meta box found in HEIF carrier for item_hidden".into())
    })?;

    let m_body_start = m_off + m_hlen + 4; // FullBox version+flags
    let m_end = m_off + m_size;
    if m_body_start > m_end {
        return Err(StrHideError::CorruptedData("Truncated meta box".into()));
    }

    // 2. Extract sub-boxes in meta
    let mut subboxes: Vec<([u8; 4], Vec<u8>)> = Vec::new();
    let mut bpos = m_body_start;
    while bpos + 8 <= m_end {
        let (s_size, s_hlen) = read_box_size(&host_bytes, bpos)?;
        if s_size < s_hlen || bpos + s_size > m_end {
            return Err(StrHideError::CorruptedData(
                "Invalid sub-box in meta".into(),
            ));
        }
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&host_bytes[bpos + 4..bpos + 8]);
        subboxes.push((tag, host_bytes[bpos..bpos + s_size].to_vec()));
        bpos += s_size;
    }

    let iinf_idx = subboxes
        .iter()
        .position(|(tag, _)| tag == b"iinf")
        .ok_or_else(|| StrHideError::UnsupportedFormat("Missing iinf box in meta".into()))?;
    let iloc_idx = subboxes
        .iter()
        .position(|(tag, _)| tag == b"iloc")
        .ok_or_else(|| StrHideError::UnsupportedFormat("Missing iloc box in meta".into()))?;

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
        // Entry header: size/type (8) + version (1); the item id sits at +12
        // (u16 for infe v2, u32 for v3). The old `ipos + 8` gate allowed an
        // off-by-one on `[ipos + 8]` and did not cover the +12..+16 reads at
        // all, so a truncated iinf panicked instead of breaking out.
        if ipos + 9 > iinf_box.len() {
            break;
        }
        let iver = iinf_box[ipos + 8];
        let need = if iver < 3 { 14 } else { 16 };
        if ipos + need > iinf_box.len() {
            break;
        }
        let isz = u32::from_be_bytes(iinf_box[ipos..ipos + 4].try_into().unwrap()) as usize;
        let iid = if iver < 3 {
            u16::from_be_bytes(iinf_box[ipos + 12..ipos + 14].try_into().unwrap()) as u32
        } else {
            u32::from_be_bytes(iinf_box[ipos + 12..ipos + 16].try_into().unwrap())
        };
        max_id = max_id.max(iid);
        if isz < need {
            break; // cannot advance past this entry; stop scanning
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
    let delta_meta = infe_len + iloc_item_len;
    let target_ext_off = host_bytes.len() as u64 + delta_meta as u64 + 8;

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
        for _ in 0..iloc_cnt {
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
                cpos += idx_sz;
                let ext_pos = cpos;
                let ext_off = read_sized_uint(iloc_buf, cpos, off_sz)?;
                cpos += off_sz + len_sz;
                if cm == 0 {
                    if base_sz > 0 && b_off > 0 {
                        // patched via base_pos
                    } else {
                        patch_sized_uint(iloc_buf, ext_pos, off_sz, ext_off + delta_meta as u64)?;
                    }
                }
            }
            if cm == 0 && base_sz > 0 && b_off > 0 {
                patch_sized_uint(iloc_buf, base_pos, base_sz, b_off + delta_meta as u64)?;
            }
        }

        let new_iloc_sz = (iloc_buf.len() + iloc_item_len) as u32;
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
        let new_iinf_sz = (iinf_buf.len() + infe_len) as u32;
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
    let new_meta_size = (new_meta_body.len() + 12) as u32;
    let mut patched_meta = Vec::with_capacity(new_meta_size as usize);
    patched_meta.extend_from_slice(&new_meta_size.to_be_bytes());
    patched_meta.extend_from_slice(b"meta");
    patched_meta.extend_from_slice(&host_bytes[m_off + 8..m_off + 12]);
    patched_meta.extend_from_slice(&new_meta_body);

    // 7. Write output stream
    out.write_all(&host_bytes[..m_off])?;
    out.write_all(&patched_meta)?;
    out.write_all(&host_bytes[m_off + m_size..])?;

    // Second mdat box
    let mdat2_size = u32::try_from(8 + ube_size)
        .map_err(|_| StrHideError::General("Envelope too large for 32-bit mdat box".into()))?;
    out.write_all(&mdat2_size.to_be_bytes())?;
    out.write_all(b"mdat")?;
    out.write_all(&ube_bytes)?;

    let inject_offset = host_bytes.len() as u64 + delta_meta as u64;
    let inject_size = 8 + ube_size;

    Ok((inject_offset, inject_size, 0, 0))
}

fn heif_item_hidden_strip(
    stego_in: &mut dyn SeekRead,
    out: &mut dyn SeekWrite,
    header: &EnvelopeHeader,
) -> Result<(), StrHideError> {
    stego_in.seek(SeekFrom::Start(0))?;
    let mut stego_bytes = Vec::new();
    stego_in.read_to_end(&mut stego_bytes)?;

    if (header.inject_offset as usize) > stego_bytes.len() {
        return Err(StrHideError::CorruptedData("Inject offset past EOF".into()));
    }

    // 1. Locate meta box
    let mut pos = 0usize;
    let mut meta_span = None;
    while pos + 8 <= stego_bytes.len() {
        let (bsize, hlen) = read_box_size(&stego_bytes, pos)?;
        if bsize < hlen || pos + bsize > stego_bytes.len() {
            return Err(StrHideError::CorruptedData("Invalid box size".into()));
        }
        if &stego_bytes[pos + 4..pos + 8] == b"meta" {
            meta_span = Some((pos, bsize, hlen));
            break;
        }
        pos += bsize;
    }
    let (m_off, m_size, m_hlen) = meta_span.ok_or_else(|| {
        StrHideError::CorruptedData("No meta box found in HEIF carrier for strip".into())
    })?;

    let m_body_start = m_off + m_hlen + 4;
    let m_end = m_off + m_size;
    if m_body_start > m_end {
        return Err(StrHideError::CorruptedData("Truncated meta box".into()));
    }

    // The header is only masked with the public built-in key, so a forged
    // stego can name arbitrary coordinates. Beyond the EOF check above, the
    // meta box must end before the injected region and the injected region
    // (meta growth + the trailing mdat2 box) must run to the end of the file;
    // anything else would slice with start > end in step 7 below.
    if (header.inject_offset as usize) < m_end {
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
    if inject_end != stego_bytes.len() as u64 {
        return Err(StrHideError::CorruptedData(
            "inject_offset + inject_size does not match the stego file length".into(),
        ));
    }

    // 2. Extract sub-boxes in meta
    let mut subboxes: Vec<([u8; 4], Vec<u8>)> = Vec::new();
    let mut bpos = m_body_start;
    while bpos + 8 <= m_end {
        let (s_size, s_hlen) = read_box_size(&stego_bytes, bpos)?;
        if s_size < s_hlen || bpos + s_size > m_end {
            return Err(StrHideError::CorruptedData(
                "Invalid sub-box in meta".into(),
            ));
        }
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&stego_bytes[bpos + 4..bpos + 8]);
        subboxes.push((tag, stego_bytes[bpos..bpos + s_size].to_vec()));
        bpos += s_size;
    }

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
        if iinf_box.len() < 21 {
            return Err(StrHideError::CorruptedData("Truncated iinf box".into()));
        }
        let last_infe_pos = iinf_box.len().saturating_sub(21);
        let infe_sz = u32::from_be_bytes(
            iinf_box[last_infe_pos..last_infe_pos + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let actual_infe_len = if infe_sz == 21 {
            21
        } else if iinf_box.len() >= 23 {
            let p23 = iinf_box.len() - 23;
            let sz23 = u32::from_be_bytes(iinf_box[p23..p23 + 4].try_into().unwrap()) as usize;
            if sz23 == 23 { 23 } else { infe_sz }
        } else {
            infe_sz
        };
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
        // The count read needs 16 bytes (v0/v1) or 18 (v2+); checking it only
        // after the read let a short box panic first (review 2026-10-25).
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
        let new_iloc_sz = iloc_buf.len() as u32;
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
        for _ in 0..iloc_cnt - 1 {
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
                cpos += idx_sz;
                let ext_pos = cpos;
                let ext_off = read_sized_uint(iloc_buf, cpos, off_sz)?;
                cpos += off_sz + len_sz;
                if cm == 0 {
                    if base_sz > 0 && b_off > 0 {
                        // handled at base_pos
                    } else {
                        patch_sized_uint(
                            iloc_buf,
                            ext_pos,
                            off_sz,
                            ext_off.saturating_sub(delta_meta as u64),
                        )?;
                    }
                }
            }
            if cm == 0 && base_sz > 0 && b_off > 0 {
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
        let new_iinf_sz = iinf_buf.len() as u32;
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
    let restored_meta_size = (restored_meta_body.len() + 12) as u32;
    let mut restored_meta = Vec::with_capacity(restored_meta_size as usize);
    restored_meta.extend_from_slice(&restored_meta_size.to_be_bytes());
    restored_meta.extend_from_slice(b"meta");
    restored_meta.extend_from_slice(&stego_bytes[m_off + 8..m_off + 12]);
    restored_meta.extend_from_slice(&restored_meta_body);

    // 7. Write output
    out.write_all(&stego_bytes[..m_off])?;
    out.write_all(&restored_meta)?;
    out.write_all(&stego_bytes[m_off + m_size..header.inject_offset as usize])?;

    Ok(())
}

fn isobmff_has_iloc_item(
    stego_in: &mut dyn SeekRead,
    target_off: u64,
    target_len: u64,
) -> Result<bool, StrHideError> {
    let cur_pos = stego_in.stream_position().unwrap_or(0);
    stego_in.seek(SeekFrom::Start(0))?;
    let mut data = Vec::new();
    stego_in.read_to_end(&mut data)?;
    let _ = stego_in.seek(SeekFrom::Start(cur_pos));

    let mut pos = 0usize;
    while pos + 8 <= data.len() {
        let (bsize, _) = match read_box_size(&data, pos) {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };
        if bsize == 0 || pos + bsize > data.len() {
            break;
        }
        if &data[pos + 4..pos + 8] == b"meta" {
            let m_end = pos + bsize;
            let mut mpos = pos + 12;
            while mpos + 8 <= m_end {
                let (sb_size, _) = match read_box_size(&data, mpos) {
                    Ok(s) => s,
                    Err(_) => break,
                };
                if sb_size == 0 || mpos + sb_size > m_end {
                    break;
                }
                if &data[mpos + 4..mpos + 8] == b"iloc" {
                    return check_iloc_has_target(
                        &data[mpos..mpos + sb_size],
                        target_off,
                        target_len,
                    );
                }
                mpos += sb_size;
            }
            break;
        }
        pos += bsize;
    }
    Ok(false)
}

fn check_iloc_has_target(
    iloc_box: &[u8],
    target_off: u64,
    target_len: u64,
) -> Result<bool, StrHideError> {
    if iloc_box.len() < 14 {
        return Ok(false);
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
    // v2+ carries a 32-bit count at +14..18; the old `>= 16` gate let a 16-
    // or 17-byte box panic on the wider read (review 2026-10-25).
    if iloc_box.len() < if iloc_ver < 2 { 16 } else { 18 } {
        return Ok(false);
    }
    let iloc_cnt = if iloc_ver < 2 {
        u16::from_be_bytes(iloc_box[14..16].try_into().unwrap()) as u32
    } else {
        u32::from_be_bytes(iloc_box[14..18].try_into().unwrap())
    };

    let id_sz = if iloc_ver < 2 { 2 } else { 4 };
    let mut cpos = if iloc_ver < 2 { 16 } else { 18 };
    for _ in 0..iloc_cnt {
        if cpos + id_sz > iloc_box.len() {
            break;
        }
        cpos += id_sz;
        let cm = if iloc_ver >= 1 {
            if cpos + 2 > iloc_box.len() {
                break;
            }
            let v = u16::from_be_bytes(iloc_box[cpos..cpos + 2].try_into().unwrap()) & 0x0F;
            cpos += 2;
            v
        } else {
            0
        };
        cpos += 2; // dref
        let b_off = read_sized_uint(iloc_box, cpos, base_sz)?;
        cpos += base_sz;
        if cpos + 2 > iloc_box.len() {
            break;
        }
        let e_cnt = u16::from_be_bytes(iloc_box[cpos..cpos + 2].try_into().unwrap()) as usize;
        cpos += 2;
        for _ in 0..e_cnt {
            cpos += idx_sz;
            let ext_off = read_sized_uint(iloc_box, cpos, off_sz)?;
            cpos += off_sz;
            let ext_len = read_sized_uint(iloc_box, cpos, len_sz)?;
            cpos += len_sz;
            let abs_off = if cm == 0 { b_off + ext_off } else { ext_off };
            if abs_off == target_off && ext_len == target_len {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{EnvelopeHeader, STANDARD_TRAILER_MAGIC, TRAILER_SIZE};
    use std::io::Cursor;

    /// The 32-bit form tops out at `0xFFFFFFFF`; the value that exactly reaches
    /// that bound must already use the 64-bit header, so no truncated size is
    /// ever written.
    #[test]
    fn prefix_len_switches_to_the_large_header_at_the_u32_bound() {
        assert_eq!(calc_prefix_len(0), 24);
        assert_eq!(calc_prefix_len(1), 24);
        assert_eq!(calc_prefix_len(0xFFFF_FFE6), 24, "24 + it == 0xFFFFFFFE");
        assert_eq!(calc_prefix_len(0xFFFF_FFE7), 32, "24 + it == 0xFFFFFFFF");
        assert_eq!(calc_prefix_len(0xFFFF_FFE8), 32);
        assert_eq!(calc_prefix_len(u32::MAX as u64), 32);
        assert_eq!(calc_prefix_len(5 * 1024 * 1024 * 1024), 32);
    }

    /// `inject` and `envelope_offset_delta` must agree on the header length:
    /// the writer places the envelope after `calc_prefix_len` bytes, and this
    /// test pins the two together for both header forms.
    #[test]
    fn inject_writes_exactly_calc_prefix_len_header_bytes() {
        for ube_size in [0usize, 100, 4096] {
            let host = b"....ftypisom....mdat".to_vec();
            let ube = vec![0x5Au8; ube_size];
            let mut out = Vec::new();
            let (offset, size, _, _) = isobmff_inject(
                "MP4",
                &mut Cursor::new(host.clone()),
                &mut Cursor::new(ube.clone()),
                &mut out,
                "box_uuid",
            )
            .unwrap();

            let prefix = calc_prefix_len(ube_size as u64) as usize;
            assert_eq!(offset, host.len() as u64);
            assert_eq!(size, prefix as u64 + ube_size as u64);
            assert_eq!(out.len(), host.len() + prefix + ube_size);
            assert_eq!(
                &out[host.len() + prefix..],
                &ube[..],
                "envelope must start exactly after the header"
            );
            // 32-bit form: size field, 'uuid', usertype.
            assert_eq!(
                u32::from_be_bytes(out[host.len()..host.len() + 4].try_into().unwrap()) as usize,
                prefix + ube_size
            );
            assert_eq!(&out[host.len() + 4..host.len() + 8], b"uuid");
            assert_eq!(&out[host.len() + 8..host.len() + 24], &MP4_UUID_NEUTRAL);
        }
    }

    /// Build `host + 64-bit uuid box + envelope` by hand. The 64-bit form is
    /// unreachable through `inject` without a 4 GiB payload, so the reader path
    /// is exercised with a synthesised container whose declared `largesize`
    /// matches the (small) envelope it actually carries.
    ///
    /// `ube_data` is the envelope body without its 24-byte trailer; the trailer
    /// emitted here records the same total size the large header declares.
    fn synthesise_large_box_stego(host: &[u8], ube_data: &[u8]) -> Vec<u8> {
        let ube_offset = host.len() as u64 + 32;
        let ube_total = ube_data.len() as u64 + TRAILER_SIZE as u64;
        let mut out = host.to_vec();
        out.extend_from_slice(&1u32.to_be_bytes()); // size == 1
        out.extend_from_slice(b"uuid");
        out.extend_from_slice(&(32 + ube_total).to_be_bytes());
        out.extend_from_slice(&MP4_UUID_NEUTRAL);
        out.extend_from_slice(ube_data);
        out.extend_from_slice(
            &EnvelopeTrailer::create(ube_offset, ube_total, STANDARD_TRAILER_MAGIC).pack(),
        );
        out
    }

    #[test]
    fn locate_and_verify_accept_a_64_bit_box() {
        let host = b"\x00\x00\x00\x18ftypisom\x00\x00\x00\x00isomiso2".to_vec();
        let ube = vec![0xA5u8; 128];
        let stego = synthesise_large_box_stego(&host, &ube);

        let mut cursor = Cursor::new(stego.clone());
        let found = isobmff_locate(&mut cursor, None).unwrap();
        let (offset, size, strategy) = found.expect("64-bit box must be located");
        assert_eq!(strategy, "box_uuid");
        assert_eq!(offset, host.len() as u64 + 32);
        assert_eq!(size, ube.len() as u64 + 24);

        let mut cursor = Cursor::new(stego.clone());
        let (ok, detail) = isobmff_verify_structure("MP4", &mut cursor).unwrap();
        assert!(ok, "64-bit box container must verify: {detail}");

        let mut cursor = Cursor::new(stego);
        let warnings = isobmff_suspicious_structures(&mut cursor);
        assert!(
            warnings.iter().any(|w| w.contains("64-bit uuid box")),
            "structural scan must report the 64-bit box, got {warnings:?}"
        );
    }

    /// A 32-bit box in the same position must NOT be reported as 64-bit, and
    /// vice versa: the two header shapes overlap in their first 24 bytes.
    #[test]
    fn suspicious_structures_distinguishes_the_two_header_forms() {
        let host = b"\x00\x00\x00\x18ftypisom\x00\x00\x00\x00isomiso2".to_vec();
        let ube = vec![0x11u8; 96];

        // 32-bit form
        let ube_offset = host.len() as u64 + 24;
        let ube_total = ube.len() as u64 + TRAILER_SIZE as u64;
        let mut stego = host.clone();
        stego.extend_from_slice(&((24 + ube_total) as u32).to_be_bytes());
        stego.extend_from_slice(b"uuid");
        stego.extend_from_slice(&MP4_UUID_NEUTRAL);
        stego.extend_from_slice(&ube);
        stego.extend_from_slice(
            &EnvelopeTrailer::create(ube_offset, ube_total, STANDARD_TRAILER_MAGIC).pack(),
        );

        let mut cursor = Cursor::new(stego.clone());
        let warnings = isobmff_suspicious_structures(&mut cursor);
        assert_eq!(warnings.len(), 1, "got {warnings:?}");
        assert!(warnings[0].contains("trailing uuid box"));
        assert!(!warnings[0].contains("64-bit"));

        let mut cursor = Cursor::new(stego);
        let (offset, _, strategy) = isobmff_locate(&mut cursor, None).unwrap().unwrap();
        assert_eq!(strategy, "box_uuid");
        assert_eq!(offset, ube_offset);
    }

    /// A v2+ iloc box of 16 or 17 bytes cannot hold the 32-bit item count at
    /// +14..18; the old `>= 16` gate let the wider read panic. Every short
    /// form must return `Ok(false)`, never abort (review 2026-10-25).
    #[test]
    fn short_iloc_boxes_of_every_version_do_not_panic() {
        for len in 0..24usize {
            let mut box_bytes = vec![0u8; len];
            if len >= 9 {
                box_bytes[8] = 2; // version 2 wherever the byte exists
            }
            let _ = check_iloc_has_target(&box_bytes, 0, 0);
            if len >= 9 {
                box_bytes[8] = 0; // and version 0
            }
            let _ = check_iloc_has_target(&box_bytes, 0, 0);
        }
    }

    // ------------------------------------------------------------------
    // Synthetic meta-HEIF hosts for the item_hidden iinf/iloc core.
    //
    // These are the only in-CI carriers that reach the iinf/iloc patch and
    // restore code of the item_hidden strategy; the real-corpus lifecycle
    // tests for that path are all `--ignored`.

    /// `iinf` box (v0 with an infe v2 entry, or v1 with an infe v3 entry).
    fn make_iinf(item_id: u32, infe_version: u8) -> Vec<u8> {
        let mut infe = Vec::new();
        if infe_version == 2 {
            infe.extend_from_slice(&21u32.to_be_bytes());
            infe.extend_from_slice(b"infe");
            infe.extend_from_slice(&[2, 0, 0, 0]);
            infe.extend_from_slice(&(item_id as u16).to_be_bytes());
            infe.extend_from_slice(&0u16.to_be_bytes()); // protection_index
            infe.extend_from_slice(b"hvc1");
            infe.push(0); // null-terminated item name
        } else {
            infe.extend_from_slice(&23u32.to_be_bytes());
            infe.extend_from_slice(b"infe");
            infe.extend_from_slice(&[3, 0, 0, 0]);
            infe.extend_from_slice(&item_id.to_be_bytes());
            infe.extend_from_slice(&0u16.to_be_bytes());
            infe.extend_from_slice(b"hvc1");
            infe.push(0);
        }
        let iinf_ver = if infe_version == 2 { 0u8 } else { 1u8 };
        let mut iinf = Vec::new();
        let count_sz = if iinf_ver == 0 { 2usize } else { 4 };
        iinf.extend_from_slice(&((12 + count_sz + infe.len()) as u32).to_be_bytes());
        iinf.extend_from_slice(b"iinf");
        iinf.extend_from_slice(&[iinf_ver, 0, 0, 0]);
        if iinf_ver == 0 {
            iinf.extend_from_slice(&1u16.to_be_bytes());
        } else {
            iinf.extend_from_slice(&1u32.to_be_bytes());
        }
        iinf.extend_from_slice(&infe);
        iinf
    }

    /// `iloc` v1 box (36 bytes): offset/length size 4, base size 4, one item
    /// with one extent located through `base_offset`. `count_override` can
    /// declare more items than the box actually holds.
    fn make_iloc_box(count_override: Option<u16>) -> Vec<u8> {
        let mut iloc = Vec::new();
        iloc.extend_from_slice(&36u32.to_be_bytes());
        iloc.extend_from_slice(b"iloc");
        iloc.extend_from_slice(&[1, 0, 0, 0]); // version 1
        iloc.push(0x44); // offset_size=4, length_size=4
        iloc.push(0x40); // base_size=4, index_size=0
        iloc.extend_from_slice(&count_override.unwrap_or(1).to_be_bytes());
        iloc.extend_from_slice(&1u16.to_be_bytes()); // item_id
        iloc.extend_from_slice(&0u16.to_be_bytes()); // construction_method
        iloc.extend_from_slice(&0u16.to_be_bytes()); // data_reference_index
        iloc.extend_from_slice(&0u32.to_be_bytes()); // base_offset — patched below
        iloc.extend_from_slice(&1u16.to_be_bytes()); // extent_count
        iloc.extend_from_slice(&0u32.to_be_bytes()); // extent_offset
        iloc.extend_from_slice(&64u32.to_be_bytes()); // extent_length
        iloc
    }

    /// ftyp(24) + meta(fullbox: iinf + iloc) + mdat(64 bytes). The iloc item's
    /// base_offset is patched to the absolute mdat payload position.
    fn assemble_meta_heif(iinf: &[u8], iloc: &[u8]) -> Vec<u8> {
        let meta_len = 12 + iinf.len() + iloc.len();
        let mut out = Vec::new();
        out.extend_from_slice(&24u32.to_be_bytes());
        out.extend_from_slice(b"ftyp");
        out.extend_from_slice(b"mif1");
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(b"mif1heic");
        let mdat_pos = (24 + meta_len + 8) as u32;
        out.extend_from_slice(&(meta_len as u32).to_be_bytes());
        out.extend_from_slice(b"meta");
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(iinf);
        out.extend_from_slice(iloc);
        out.extend_from_slice(&(72u32.to_be_bytes()));
        out.extend_from_slice(b"mdat");
        out.resize(out.len() + 64, 0xC3);
        // base_offset field: meta starts at 24, iloc follows the 12-byte meta
        // header plus iinf, and sits 22 bytes into the iloc box.
        let base_pos = 24 + 12 + iinf.len() + 22;
        out[base_pos..base_pos + 4].copy_from_slice(&mdat_pos.to_be_bytes());
        out
    }

    fn synthetic_meta_heif(item_id: u32, infe_version: u8) -> Vec<u8> {
        let iinf = make_iinf(item_id, infe_version);
        let iloc = make_iloc_box(None);
        assemble_meta_heif(&iinf, &iloc)
    }

    #[test]
    fn item_hidden_roundtrips_on_a_synthetic_meta_heif() {
        let host = synthetic_meta_heif(1, 2);
        // Deterministic for this fixture: one 21-byte infe + one 20-byte iloc
        // entry appended to iinf/iloc.
        let delta_meta = 41u64;
        let inject_offset = host.len() as u64 + delta_meta;
        let ube_data_len = 200u64;
        let ube_total = ube_data_len + TRAILER_SIZE as u64;

        let mut ube = vec![0x77u8; ube_data_len as usize];
        ube.extend_from_slice(
            &EnvelopeTrailer::create(inject_offset + 8, ube_total, STANDARD_TRAILER_MAGIC).pack(),
        );

        let mut out = Vec::new();
        let (offset, size, patch_off, orig) = isobmff_inject(
            "HEIF",
            &mut Cursor::new(host.clone()),
            &mut Cursor::new(ube.clone()),
            &mut out,
            "item_hidden",
        )
        .unwrap();
        assert_eq!(offset, inject_offset);
        assert_eq!(size, 8 + ube_total);
        assert_eq!((patch_off, orig), (0, 0));

        let mut cur = Cursor::new(out.clone());
        let (lo, ls, strat) = isobmff_locate(&mut cur, None).unwrap().unwrap();
        assert_eq!(strat, "item_hidden");
        assert_eq!(
            lo,
            inject_offset + 8,
            "trailer records the mdat payload start"
        );
        assert_eq!(ls, ube_total);

        let mut cur = Cursor::new(out.clone());
        let (ok, detail) = isobmff_verify_structure("HEIF", &mut cur).unwrap();
        assert!(ok, "synthetic item_hidden stego must verify: {detail}");

        let header = EnvelopeHeader {
            strategy_id: 12,
            inject_offset: offset,
            inject_size: size,
            ..Default::default()
        };
        let mut restored = Cursor::new(Vec::new());
        isobmff_strip(&mut Cursor::new(out), &mut restored, &header).unwrap();
        assert_eq!(
            restored.into_inner(),
            host,
            "strip must restore the host byte-exactly"
        );
    }

    /// A crafted ultra-short `iloc` (the meta sub-box walk only guarantees
    /// `size >= header_len`) must fail as CorruptedData, never panic on the
    /// bare index reads of the inject-side geometry parse (P1-1).
    #[test]
    fn item_hidden_inject_rejects_an_ultra_short_iloc() {
        let iinf = make_iinf(1, 2);
        for (len, ver) in [
            (8usize, 1u8),
            (12, 1),
            (13, 1),
            (14, 0),
            (15, 1),
            (16, 2),
            (17, 2),
        ] {
            let mut iloc = vec![0u8; len];
            iloc[0..4].copy_from_slice(&(len as u32).to_be_bytes());
            iloc[4..8].copy_from_slice(b"iloc");
            if len > 8 {
                iloc[8] = ver;
            }
            let host = assemble_meta_heif(&iinf, &iloc);
            let err = isobmff_inject(
                "HEIF",
                &mut Cursor::new(host),
                &mut Cursor::new(vec![0u8; 224]),
                &mut Vec::new(),
                "item_hidden",
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("Truncated iloc"),
                "iloc len {len} v{ver}: {err}"
            );
        }
    }

    /// An iloc item count larger than the box contents must be rejected by
    /// both the inject and the strip walk, not panic on the u16 entry reads
    /// (P2-1).
    #[test]
    fn item_hidden_walks_reject_iloc_count_beyond_data() {
        let iinf = make_iinf(1, 2);
        let iloc = make_iloc_box(Some(2)); // declares 2 items, box holds 1

        let err = isobmff_inject(
            "HEIF",
            &mut Cursor::new(assemble_meta_heif(&iinf, &iloc)),
            &mut Cursor::new(vec![0u8; 224]),
            &mut Vec::new(),
            "item_hidden",
        )
        .unwrap_err();
        assert!(err.to_string().contains("Truncated iloc entry"), "{err}");

        // Strip side: take a valid stego and inflate the item count.
        let host = synthetic_meta_heif(1, 2);
        let mut stego = Vec::new();
        let (offset, size, _, _) = isobmff_inject(
            "HEIF",
            &mut Cursor::new(host),
            &mut Cursor::new(vec![0u8; 200]),
            &mut stego,
            "item_hidden",
        )
        .unwrap();
        // In the stego the iloc box sits after the grown iinf (one 21-byte
        // infe added); its 16-bit item count is 14 bytes into the box.
        let count_pos = 24 + 12 + 35 + 21 + 14;
        stego[count_pos..count_pos + 2].copy_from_slice(&5u16.to_be_bytes());
        let header = EnvelopeHeader {
            strategy_id: 12,
            inject_offset: offset,
            inject_size: size,
            ..Default::default()
        };
        let err = isobmff_strip(
            &mut Cursor::new(stego),
            &mut Cursor::new(Vec::new()),
            &header,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Truncated iloc entry"), "{err}");
    }

    /// An infe entry declaring `item_id = u32::MAX` must refuse the carrier:
    /// the old `(max_id + 1).max(1)` wrapped to 1 in release and collided with
    /// the primary image's item id (P2-2).
    #[test]
    fn item_hidden_inject_rejects_item_id_u32_max() {
        let host = synthetic_meta_heif(u32::MAX, 3);
        let err = isobmff_inject(
            "HEIF",
            &mut Cursor::new(host),
            &mut Cursor::new(vec![0u8; 224]),
            &mut Vec::new(),
            "item_hidden",
        )
        .unwrap_err();
        assert!(err.to_string().contains("item_id space exhausted"), "{err}");
    }

    /// The non-AEAD header can be fully forged, so strip must cross-check the
    /// declared coordinates against the actual layout before slicing (P2-3).
    #[test]
    fn item_hidden_strip_rejects_forged_coordinates() {
        let host = synthetic_meta_heif(1, 2);
        let ube_total = 224u64;
        let mut stego = Vec::new();
        isobmff_inject(
            "HEIF",
            &mut Cursor::new(host),
            &mut Cursor::new(vec![0u8; 200]),
            &mut stego,
            "item_hidden",
        )
        .unwrap();

        // (a) inject_offset inside the meta box would slice start > end.
        let mut header = EnvelopeHeader {
            strategy_id: 12,
            inject_offset: 40, // meta spans 24..(24+meta_len)
            inject_size: stego.len() as u64 - 40,
            ..Default::default()
        };
        let err = isobmff_strip(
            &mut Cursor::new(stego.clone()),
            &mut Cursor::new(Vec::new()),
            &header,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("precedes the end of the meta box"),
            "{err}"
        );

        // (b) a size that does not run to the end of the file is equally forged.
        header.inject_offset = stego.len() as u64 - 8 - ube_total;
        header.inject_size = 8 + ube_total - 1;
        let err = isobmff_strip(
            &mut Cursor::new(stego),
            &mut Cursor::new(Vec::new()),
            &header,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the stego file length"),
            "{err}"
        );
    }
}
