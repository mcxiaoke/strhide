//! Shared EBML (Extensible Binary Meta Language) container utilities.
//!
//! Used by [`super::mkv::MkvAdapter`].

use crate::adapters::SeekRead;
use crate::errors::StrHideError;

pub const EBML_VOID_ID: u8 = 0xEC;
pub const EBML_HEADER_ID: u32 = 0x1A45_DFA3;
pub const MATROSKA_SEGMENT_ID: u32 = 0x1853_8067;

/// Encode an unsigned integer as an EBML VINT.
pub fn encode_vint(val: u64) -> Vec<u8> {
    if val < (1 << 7) - 1 {
        vec![(0x80 | val) as u8]
    } else if val < (1 << 14) - 1 {
        let v = 0x4000 | val;
        vec![(v >> 8) as u8, v as u8]
    } else if val < (1 << 21) - 1 {
        let v = 0x20_0000 | val;
        vec![(v >> 16) as u8, (v >> 8) as u8, v as u8]
    } else if val < (1 << 28) - 1 {
        let v = 0x1000_0000 | val;
        vec![(v >> 24) as u8, (v >> 16) as u8, (v >> 8) as u8, v as u8]
    } else if val < (1 << 35) - 1 {
        let v = 0x08_0000_0000 | val;
        vec![
            (v >> 32) as u8,
            (v >> 24) as u8,
            (v >> 16) as u8,
            (v >> 8) as u8,
            v as u8,
        ]
    } else if val < (1 << 42) - 1 {
        let v = 0x0400_0000_0000 | val;
        vec![
            (v >> 40) as u8,
            (v >> 32) as u8,
            (v >> 24) as u8,
            (v >> 16) as u8,
            (v >> 8) as u8,
            v as u8,
        ]
    } else if val < (1 << 49) - 1 {
        let v = 0x02_0000_0000_0000 | val;
        vec![
            (v >> 48) as u8,
            (v >> 40) as u8,
            (v >> 32) as u8,
            (v >> 24) as u8,
            (v >> 16) as u8,
            (v >> 8) as u8,
            v as u8,
        ]
    } else {
        let v = 0x0100_0000_0000_0000 | val;
        vec![
            (v >> 56) as u8,
            (v >> 48) as u8,
            (v >> 40) as u8,
            (v >> 32) as u8,
            (v >> 24) as u8,
            (v >> 16) as u8,
            (v >> 8) as u8,
            v as u8,
        ]
    }
}

/// Calculate the length of the Void element prefix (1 byte ID + VINT size length).
pub fn calc_prefix_len(ube_size: u64) -> u64 {
    1 + encode_vint(ube_size).len() as u64
}

/// Read an EBML Element ID from reader. Returns (id, id_len).
pub fn read_element_id(reader: &mut dyn SeekRead) -> Result<(u32, usize), StrHideError> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first)?;
    let b = first[0];
    if b == 0 {
        return Err(StrHideError::CorruptedData(
            "Invalid EBML ID with all leading zeros".into(),
        ));
    }
    let len = b.leading_zeros() as usize + 1;
    if len > 4 {
        return Err(StrHideError::CorruptedData(format!(
            "EBML ID length {len} exceeds 4 bytes"
        )));
    }
    let mut id = b as u32;
    for _ in 1..len {
        let mut next = [0u8; 1];
        reader.read_exact(&mut next)?;
        id = (id << 8) | (next[0] as u32);
    }
    Ok((id, len))
}

/// Read an EBML Element Data Size (VINT). Returns (size, vint_len).
/// Note: a VINT with all payload bits set to 1 indicates "unknown size".
pub fn read_vint_size(reader: &mut dyn SeekRead) -> Result<(Option<u64>, usize), StrHideError> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first)?;
    let b = first[0];
    if b == 0 {
        return Err(StrHideError::CorruptedData(
            "Invalid VINT with all leading zeros".into(),
        ));
    }
    let len = b.leading_zeros() as usize + 1;
    if len > 8 {
        return Err(StrHideError::CorruptedData(format!(
            "VINT length {len} exceeds 8 bytes"
        )));
    }
    let mask = (1u8 << (8 - len)) - 1;
    let mut val = (b & mask) as u64;
    let mut all_ones = (b & mask) == mask;

    for _ in 1..len {
        let mut next = [0u8; 1];
        reader.read_exact(&mut next)?;
        val = (val << 8) | (next[0] as u64);
        if next[0] != 0xFF {
            all_ones = false;
        }
    }

    if all_ones {
        Ok((None, len))
    } else {
        Ok((Some(val), len))
    }
}
