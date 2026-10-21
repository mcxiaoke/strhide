//! Shared ISO Base Media File Format (ISO BMFF / ISOBMFF) utilities.
//!
//! Used by [`super::mp4::Mp4Adapter`] and [`super::heif::HeifAdapter`].

use std::io::{SeekFrom, Write};

use crate::adapters::{SeekRead, StrategyCapacity};
use crate::envelope::EnvelopeTrailer;
use crate::errors::StrHideError;

pub const MP4_UUID_NEUTRAL: [u8; 16] = [
    0xd4, 0x1a, 0x8e, 0x9c, 0x4f, 0x21, 0x4e, 0x87, 0x9a, 0x33, 0x5b, 0x6d, 0x12, 0x84, 0xef, 0x70,
];

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
    if strategy != "box_uuid" && strategy != "eof" {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Strategy '{strategy}' not supported by {format_name} adapter"
        )));
    }

    host_in.seek(SeekFrom::Start(0))?;
    let mut buf = [0u8; 64 * 1024];
    let mut host_len = 0u64;

    loop {
        let n = host_in.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])?;
        host_len += n as u64;
    }

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
    } else {
        ube_size
    };

    loop {
        let n = ube_in.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])?;
    }

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

    // 3. Fallback to EOF
    let file_size = stego_in.seek(SeekFrom::End(0))?;
    if trailer.ube_offset + trailer.ube_total_size == file_size {
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
        offset += box_size;
        box_count += 1;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{STANDARD_TRAILER_MAGIC, TRAILER_SIZE};
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
}
