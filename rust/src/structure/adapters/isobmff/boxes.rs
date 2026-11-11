//! ISO BMFF box-header and big-endian integer primitives.

use std::io::SeekFrom;

use crate::errors::StrHideError;
use crate::structure::adapters::SeekRead;

pub(super) fn box_header_is_64_bit(buf: &[u8]) -> bool {
    buf.len() >= 4 && u32::from_be_bytes(buf[0..4].try_into().unwrap()) == 1
}

/// Read one top-level box header without buffering the box body.
///
/// Used by the `item_hidden` paths, which only need the bytes up to the end of
/// `meta`; everything after it is streamed.
pub(super) fn read_stream_box_header(
    reader: &mut dyn SeekRead,
    pos: u64,
    file_size: u64,
) -> Result<(u64, usize, [u8; 4]), StrHideError> {
    if pos + 8 > file_size {
        return Err(StrHideError::CorruptedData("Truncated box header".into()));
    }
    reader.seek(SeekFrom::Start(pos))?;
    let mut hdr = [0u8; 8];
    reader.read_exact(&mut hdr)?;
    let mut tag = [0u8; 4];
    tag.copy_from_slice(&hdr[4..8]);
    let size32 = u32::from_be_bytes(hdr[0..4].try_into().unwrap());
    let (size, header_len) = if size32 == 1 {
        if pos + 16 > file_size {
            return Err(StrHideError::CorruptedData(
                "Truncated 64-bit box header".into(),
            ));
        }
        reader.seek(SeekFrom::Start(pos + 8))?;
        let mut largesize = [0u8; 8];
        reader.read_exact(&mut largesize)?;
        let size = u64::from_be_bytes(largesize);
        if size < 16 {
            return Err(StrHideError::CorruptedData(
                "Invalid 64-bit box size".into(),
            ));
        }
        (size, 16)
    } else if size32 == 0 {
        (file_size - pos, 8)
    } else {
        (size32 as u64, 8)
    };
    // A 32-bit size below the header length (8 bytes) would make the three
    // streaming callers advance `pos` by 2..7 bytes and re-parse the same
    // region. Reject it here so all of them share one rule; the 64-bit and
    // size==0 arms already guarantee size >= header_len.
    if size < header_len as u64 {
        return Err(StrHideError::CorruptedData("Invalid box size".into()));
    }
    if size > file_size - pos {
        return Err(StrHideError::CorruptedData("Invalid box size".into()));
    }
    Ok((size, header_len, tag))
}

pub(super) fn read_box_size(bytes: &[u8], pos: usize) -> Result<(usize, usize), StrHideError> {
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
        // `largesize` is attacker-controlled: values exceeding `usize` or smaller
        // than the 16-byte header must be rejected to prevent slice panics.
        let size64 = u64::from_be_bytes(bytes[pos + 8..pos + 16].try_into().unwrap());
        let size64 = usize::try_from(size64)
            .ok()
            .filter(|&s| s >= 16)
            .ok_or_else(|| StrHideError::CorruptedData("Invalid 64-bit box size".into()))?;
        Ok((size64, 16))
    } else if size32 == 0 {
        Ok((bytes.len() - pos, 8))
    } else {
        Ok((size32 as usize, 8))
    }
}

pub(super) fn write_sized_uint(
    buf: &mut Vec<u8>,
    val: u64,
    width: usize,
) -> Result<(), StrHideError> {
    match width {
        // ISO/IEC 14496-12 permits a zero width, which stores the value 0
        // implicitly and occupies no bytes. A non-zero value cannot be
        // represented that way, and silently dropping it would corrupt the
        // iloc table, so refuse instead.
        0 if val == 0 => Ok(()),
        0 => Err(StrHideError::UnsupportedFormat(
            "A zero-width iloc field cannot hold a non-zero value".into(),
        )),
        4 => {
            let v32 = u32::try_from(val).map_err(|_| {
                StrHideError::BufferOverflow(format!("Offset {val} overflows 32-bit iloc field"))
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

pub(super) fn patch_sized_uint(
    buf: &mut [u8],
    pos: usize,
    width: usize,
    val: u64,
) -> Result<(), StrHideError> {
    match width {
        0 if val == 0 => Ok(()),
        0 => Err(StrHideError::UnsupportedFormat(
            "A zero-width iloc field cannot hold a non-zero value".into(),
        )),
        4 => {
            let v32 = u32::try_from(val).map_err(|_| {
                StrHideError::BufferOverflow(format!("Offset {val} overflows 32-bit iloc field"))
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

pub(super) fn read_sized_uint(buf: &[u8], pos: usize, width: usize) -> Result<u64, StrHideError> {
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
