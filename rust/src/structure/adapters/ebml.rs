//! Shared EBML (Extensible Binary Meta Language) container utilities.
//!
//! Used by [`super::mkv::MkvAdapter`].

use crate::errors::StrHideError;
use crate::structure::adapters::SeekRead;

pub const EBML_VOID_ID: u8 = 0xEC;
pub const EBML_HEADER_ID: u32 = 0x1A45_DFA3;
pub const MATROSKA_SEGMENT_ID: u32 = 0x1853_8067;

/// Encode an unsigned integer as an EBML VINT.
///
/// Per RFC 8794, an all-ones payload represents an "unknown size" sentinel.
/// Boundary values (127, 16383, etc.) spill into the next width to avoid this sentinel.
/// Returns `None` for values >= 2^56 - 1.
pub fn encode_vint(val: u64) -> Option<Vec<u8>> {
    for len in 1usize..=8 {
        let marker = 1u64 << (7 * len);
        if val < marker - 1 {
            // For an `len`-byte VINT the first byte's leading `len` bits are
            // the length marker, which lands exactly at `1 << (7 * len)` and
            // ORs straight in above the 7*len payload bits.
            let v = marker | val;
            return Some(v.to_be_bytes()[8 - len..].to_vec());
        }
    }
    None
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Verifies that boundary values avoid the RFC 8794 unknown-size all-ones sentinel.
    #[test]
    fn encode_vint_avoids_unknown_size_sentinel() {
        assert_eq!(encode_vint(0).unwrap(), vec![0x80]);
        assert_eq!(encode_vint(126).unwrap(), vec![0xFE]);
        assert_eq!(encode_vint(127).unwrap(), vec![0x40, 0x7F]);
        assert_eq!(encode_vint(128).unwrap(), vec![0x40, 0x80]);
        assert_eq!(encode_vint(16382).unwrap(), vec![0x7F, 0xFE]);
        assert_eq!(encode_vint(16383).unwrap(), vec![0x20, 0x3F, 0xFF]);
        assert_eq!(encode_vint(16384).unwrap(), vec![0x20, 0x40, 0x00]);
        assert_eq!(encode_vint(1 << 20).unwrap(), vec![0x30, 0x00, 0x00]);
        assert_eq!(
            encode_vint((1 << 56) - 2).unwrap(),
            vec![0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]
        );
        assert!(encode_vint((1 << 56) - 1).is_none());
        assert!(encode_vint(1 << 56).is_none());
        assert!(encode_vint(u64::MAX).is_none());
    }

    /// Writer and reader share the encoding: every encodable value reads back
    /// identically, with the VINT length matching the byte count.
    #[test]
    fn encode_vint_roundtrips_through_read_vint_size() {
        for val in [
            0u64,
            1,
            126,
            127,
            128,
            16382,
            16383,
            16384,
            2_097_151,
            2_097_152,
            (1 << 28) - 1,
            (1 << 35) - 1,
            (1 << 49) - 1,
            (1 << 56) - 2,
        ] {
            let vint = encode_vint(val).unwrap_or_else(|| panic!("{val} must encode"));
            let (size, vint_len) = read_vint_size(&mut Cursor::new(vint.clone())).unwrap();
            assert_eq!(size, Some(val), "value {val} must read back");
            assert_eq!(vint_len, vint.len(), "declared length must match bytes");
        }
    }
}
