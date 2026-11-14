//! Shared ISO Base Media File Format (ISO BMFF / ISOBMFF) utilities.
//!
//! Used by [`super::mp4::Mp4Adapter`] and [`super::heif::HeifAdapter`].

use std::io::{SeekFrom, Write};

use crate::errors::StrHideError;
use crate::structure::adapters::{
    InjectCoordinates, LocatedEnvelope, SeekRead, SeekWrite, StrategyCapacity,
};
use crate::structure::envelope::{EnvelopeHeader, EnvelopeTrailer, HEADER_SIZE, TRAILER_SIZE};

pub const MP4_UUID_NEUTRAL: [u8; 16] = [
    0xd4, 0x1a, 0x8e, 0x9c, 0x4f, 0x21, 0x4e, 0x87, 0x9a, 0x33, 0x5b, 0x6d, 0x12, 0x84, 0xef, 0x70,
];

/// Largest envelope the `item_hidden` strategy can carry: the second `mdat`
/// box writes its size into a 32-bit field (`8 + ube_size <= u32::MAX`) and
/// registers the extent through 32-bit iloc offset/length fields. Capacity
/// text and the auto strategy both derive from this constant.
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
    expected_trailer_magic: Option<&[u8; 4]>,
) -> Option<u64> {
    let remaining = total_size.checked_sub(offset)?;
    if remaining < TRAILER_SIZE as u64 {
        return None;
    }
    if stego_in
        .seek(SeekFrom::End(-(TRAILER_SIZE as i64)))
        .is_err()
    {
        return None;
    }
    let mut tail = [0u8; TRAILER_SIZE];
    if stego_in.read_exact(&mut tail).is_err() {
        return None;
    }
    if stego_in.seek(SeekFrom::Start(offset)).is_err() {
        return None;
    }
    // The 24-byte tail must be an authenticated-shape trailer, not merely
    // plausible integers: any file whose last 16 bytes say "offset 0, total
    // file size" used to make L1 report a hidden envelope. `unpack` checks
    // the magic and the CRC, so a forged tail now falls through to the box
    // walk instead.
    let trailer = EnvelopeTrailer::unpack(&tail, expected_trailer_magic).ok()?;
    if trailer.locate_start(total_size) != Some(offset) {
        return None;
    }
    Some(trailer.ube_total_size)
}

pub fn isobmff_inject(
    format_name: &str,
    host_in: &mut dyn SeekRead,
    ube_in: &mut dyn SeekRead,
    out: &mut dyn Write,
    strategy: &str,
) -> Result<InjectCoordinates, StrHideError> {
    if strategy == "item_hidden" {
        return heif_item_hidden_inject(host_in, ube_in, out);
    }
    if strategy != "box_uuid" && strategy != "free_box" && strategy != "eof" {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Strategy '{strategy}' not supported by {format_name} adapter"
        )));
    }

    host_in.seek(SeekFrom::Start(0))?;
    let host_len = crate::structure::adapters::io::copy_stream(host_in, out)?;

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

    crate::structure::adapters::io::copy_stream(ube_in, out)?;

    Ok(InjectCoordinates {
        offset: inject_offset,
        size: inject_size,
        patch_offset: 0,
        original_patch_value: 0,
    })
}

pub fn isobmff_locate(
    stego_in: &mut dyn SeekRead,
    expected_trailer_magic: Option<&[u8; 4]>,
) -> Result<Option<LocatedEnvelope>, StrHideError> {
    let trailer = match EnvelopeTrailer::read_from_tail(stego_in, expected_trailer_magic)? {
        Some(t) => t,
        None => return Ok(None),
    };

    // Validate that the envelope lies completely within physical file boundaries.
    // ube_total_size and offset are untrusted; unverified offsets could cause OOM or out-of-bounds reads.
    let file_size = stego_in.seek(SeekFrom::End(0))?;
    let min_envelope = (HEADER_SIZE + TRAILER_SIZE) as u64;
    if trailer.ube_total_size < min_envelope
        || trailer
            .ube_offset
            .checked_add(trailer.ube_total_size)
            .is_none_or(|end| end > file_size)
    {
        return Ok(None);
    }

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
                return Ok(Some(LocatedEnvelope {
                    offset: trailer.ube_offset,
                    size: trailer.ube_total_size,
                    strategy: "box_uuid".into(),
                }));
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
                return Ok(Some(LocatedEnvelope {
                    offset: trailer.ube_offset,
                    size: trailer.ube_total_size,
                    strategy: "box_uuid".into(),
                }));
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
                    return Ok(Some(LocatedEnvelope {
                        offset: trailer.ube_offset,
                        size: trailer.ube_total_size,
                        strategy: "free_box".into(),
                    }));
                }
                if box_type == b"mdat"
                    && isobmff_has_iloc_item(stego_in, trailer.ube_offset, trailer.ube_total_size)?
                {
                    return Ok(Some(LocatedEnvelope {
                        offset: trailer.ube_offset,
                        size: trailer.ube_total_size,
                        strategy: "item_hidden".into(),
                    }));
                }
            }
        }
    }

    // 4. Fallback to EOF
    let file_size = stego_in.seek(SeekFrom::End(0))?;
    if let Some(start) = trailer.locate_start(file_size) {
        return Ok(Some(LocatedEnvelope {
            offset: start,
            size: trailer.ube_total_size,
            strategy: "eof".into(),
        }));
    }

    Ok(None)
}

pub fn isobmff_verify_structure(
    format_name: &str,
    stego_in: &mut dyn SeekRead,
    expected_trailer_magic: Option<&[u8; 4]>,
) -> Result<(bool, String), StrHideError> {
    let total_size = stego_in.seek(SeekFrom::End(0))?;
    stego_in.seek(SeekFrom::Start(0))?;

    let mut offset = 0u64;
    let mut box_count = 0u64;
    // A `size == 0` box means "until EOF" and carries no length of its own.
    // Real ISO BMFF files also contain at least one explicitly sized box (the
    // `ftyp` at minimum); a file made only of a size-0 box is not a container
    // we can safely inject into, because any box appended after it would be
    // swallowed by it.
    let mut explicit_boxes = 0u64;
    let mut has_ftyp = false;

    while offset < total_size {
        if let Some(envelope_len) =
            trailing_envelope_len(stego_in, offset, total_size, expected_trailer_magic)
        {
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
        if box_type == *b"ftyp" || box_type == *b"styp" {
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
            explicit_boxes += 1;
            (u64::from_be_bytes(large), 16u64)
        } else if size == 0 {
            (total_size - offset, 8u64)
        } else {
            explicit_boxes += 1;
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

    if explicit_boxes == 0 {
        return Ok((
            false,
            format!(
                "{format_name} has no explicitly sized top-level box (every box uses size 0 / extends to EOF)"
            ),
        ));
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

/// Upper bound on the `meta` box body buffered by `read_meta_box_bytes`.
/// Probes only need the `meta` box, so this bounds memory usage on hostile
/// containers while large `mdat` bodies are skipped with seek.
pub const MAX_ISOBMFF_META_SCAN: u64 = 1024 * 1024 * 1024;

/// Read the top-level `meta` box only, without buffering the file prefix.
/// Walking top-level headers with [`read_stream_box_header`] avoids buffering large preceding boxes.
fn read_meta_box_bytes(reader: &mut dyn SeekRead) -> Result<Option<Vec<u8>>, StrHideError> {
    let file_size = reader.seek(SeekFrom::End(0))?;
    let mut pos = 0u64;
    while pos < file_size {
        let (size, _header_len, tag) = match read_stream_box_header(reader, pos, file_size) {
            Ok(header) => header,
            // A malformed top-level chain means there is no reliable `meta`.
            Err(StrHideError::CorruptedData(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        if tag == *b"meta" {
            if size > MAX_ISOBMFF_META_SCAN {
                return Ok(None);
            }
            let mut data = vec![0u8; size as usize];
            reader.seek(SeekFrom::Start(pos))?;
            reader.read_exact(&mut data)?;
            return Ok(Some(data));
        }
        pos += size;
    }
    Ok(None)
}

/// Admission check for the `item_hidden` rewrite.
///
/// `meta` must start at its own box header. The conditions here mirror what
/// [`heif_item_hidden_inject`] and [`heif_item_hidden_strip`] can physically
/// rewrite — an 8-byte `meta` header, 8-byte `iloc`/`iinf` headers, and the
/// 4/8-byte field widths those writers emit. Both the probe (which `inspect`
/// and `auto` consult) and the writer call it, ensuring strategy compatibility
/// between probing and injection.
fn check_item_hidden_layout(meta: &[u8]) -> Result<(), StrHideError> {
    if meta.len() < 12 {
        return Err(StrHideError::CorruptedData("Truncated meta box".into()));
    }
    if box_header_is_64_bit(meta) {
        return Err(StrHideError::UnsupportedFormat(
            "HEIF carriers with a 64-bit meta box header are not supported for item_hidden".into(),
        ));
    }
    let m_end = meta.len();
    let mut mpos = 12; // size + "meta" + version/flags
    let mut iloc: Option<&[u8]> = None;
    let mut iinf: Option<&[u8]> = None;
    while mpos + 8 <= m_end {
        let (sb_size, _) = read_box_size(meta, mpos)?;
        if sb_size < 8 || sb_size > m_end - mpos {
            return Err(StrHideError::CorruptedData(
                "Invalid sub-box in meta".into(),
            ));
        }
        match &meta[mpos + 4..mpos + 8] {
            b"iloc" => iloc = Some(&meta[mpos..mpos + sb_size]),
            b"iinf" => iinf = Some(&meta[mpos..mpos + sb_size]),
            _ => {}
        }
        mpos += sb_size;
    }
    let iloc =
        iloc.ok_or_else(|| StrHideError::UnsupportedFormat("Missing iloc box in meta".into()))?;
    let iinf =
        iinf.ok_or_else(|| StrHideError::UnsupportedFormat("Missing iinf box in meta".into()))?;
    if box_header_is_64_bit(iloc) || box_header_is_64_bit(iinf) {
        return Err(StrHideError::UnsupportedFormat(
            "HEIF carriers with 64-bit iloc/iinf box headers are not supported for item_hidden"
                .into(),
        ));
    }

    // iloc: v0/v1/v2 are the only layouts the rewriter understands.
    if iloc.len() < 14 {
        return Err(StrHideError::CorruptedData("Truncated iloc box".into()));
    }
    let iloc_ver = iloc[8];
    if iloc_ver > 2 {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported HEIF iloc version {iloc_ver} for item_hidden"
        )));
    }
    if iloc.len() < if iloc_ver < 2 { 16 } else { 18 } {
        return Err(StrHideError::CorruptedData("Truncated iloc box".into()));
    }
    let off_sz = ((iloc[12] >> 4) & 0x0F) as usize;
    let len_sz = (iloc[12] & 0x0F) as usize;
    let base_sz = ((iloc[13] >> 4) & 0x0F) as usize;
    // The writer can only emit 4/8-byte fields (a zero-width offset or length
    // cannot hold the new extent), and `base_offset` may additionally be 0.
    if !matches!(off_sz, 4 | 8) {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported iloc offset field width {off_sz}"
        )));
    }
    if !matches!(len_sz, 4 | 8) {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported iloc length field width {len_sz}"
        )));
    }
    if !matches!(base_sz, 0 | 4 | 8) {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported iloc base-offset field width {base_sz}"
        )));
    }

    // iinf: v0 uses a 16-bit entry count, v1 a 32-bit one; anything else would
    // be read with the wrong width.
    if iinf.len() < 14 {
        return Err(StrHideError::CorruptedData("Truncated iinf box".into()));
    }
    let iinf_ver = iinf[8];
    if iinf_ver > 1 {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Unsupported HEIF iinf version {iinf_ver} for item_hidden"
        )));
    }
    if iinf.len() < if iinf_ver == 0 { 14 } else { 16 } {
        return Err(StrHideError::CorruptedData("Truncated iinf box".into()));
    }
    Ok(())
}

pub fn isobmff_can_item_hidden(reader: &mut dyn SeekRead) -> bool {
    let start_pos = match reader.stream_position() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let data = match read_meta_box_bytes(reader) {
        Ok(Some(data)) => data,
        Ok(None) => {
            let _ = reader.seek(SeekFrom::Start(start_pos));
            return false;
        }
        Err(_) => {
            let _ = reader.seek(SeekFrom::Start(start_pos));
            return false;
        }
    };
    let _ = reader.seek(SeekFrom::Start(start_pos));

    // `data` starts at the `meta` box header. Use the same admission the
    // writer applies, so a carrier that injection would refuse (64-bit header,
    // unsupported field width/version) is not advertised as embeddable.
    check_item_hidden_layout(&data).is_ok()
}

pub fn isobmff_strip(
    stego_in: &mut dyn SeekRead,
    out: &mut dyn SeekWrite,
    header: &EnvelopeHeader,
) -> Result<(), StrHideError> {
    if crate::structure::registry::id_to_strategy(header.strategy_id) == "item_hidden" {
        return heif_item_hidden_strip(stego_in, out, header);
    }
    stego_in.seek(SeekFrom::Start(0))?;
    crate::structure::adapters::io::copy_exact(stego_in, out, header.inject_offset)?;
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
    crate::structure::adapters::io::copy_stream(stego_in, out)?;
    Ok(())
}

/// Whether a stored box uses the 16-byte `largesize` header form.
///
/// The `item_hidden` rewrite patches the 32-bit size word and reads the box
/// version at offset 8, which only describes an 8-byte header; a 64-bit header
/// would be silently mangled.
mod boxes;
mod heif;
mod iloc;
#[cfg(test)]
mod tests;

use self::boxes::{box_header_is_64_bit, read_box_size, read_stream_box_header};
use self::heif::{heif_item_hidden_inject, heif_item_hidden_strip};
#[cfg(test)]
use self::iloc::check_iloc_has_target;
use self::iloc::isobmff_has_iloc_item;
