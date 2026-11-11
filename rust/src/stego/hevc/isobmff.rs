//! Shared ISOBMFF box-header reader for the content-domain parsers.
//!
//! `mp4_boxes`, `heif_boxes` and the HEIF thumbnail bridge all walk the same
//! `size32 | tag | [largesize]` grammar, but each used to carry its own copy
//! of the 32/64-bit/zero-size branches. Three copies meant three places to
//! get the `size == 0` ("extends to end of enclosing box") and
//! `size == 1` (64-bit largesize) rules wrong.
//!
//! This module owns only the header grammar. Callers keep their own policy:
//! strict MP4 walks reject a malformed box, HEIF table walks stop at the
//! first malformed box, and the thumbnail bridge tolerates a truncated tail.

use crate::stego::hevc::error::{HevcError, Result};
use crate::stego::hevc::heif_boxes::{be_u32, be_u64};

/// What a box header means for the caller.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BoxHeader {
    pub tag: [u8; 4],
    /// 8, or 16 for a `largesize` box.
    pub header_len: usize,
    /// Whole box, header included.
    pub total_size: usize,
}

/// Policy for `size == 0`, which the spec defines as "extends to the end of
/// the enclosing box".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZeroSize {
    /// Accept it and make the box run to `limit` (the MP4/HEIF walkers).
    ExtendToLimit,
    /// Reject it (walks that treat it as the end of the table).
    Reject,
}

/// Decoded size fields, before any caller-specific bounds policy.
pub(crate) struct RawBoxSize {
    pub header_len: usize,
    pub total_size: usize,
}

fn decode_size(bytes: &[u8], pos: usize, limit: usize, zero: ZeroSize) -> Result<RawBoxSize> {
    if pos.checked_add(8).is_none_or(|end| end > limit) {
        return Err(HevcError::Truncated);
    }
    let size32 = be_u32(bytes, pos).ok_or(HevcError::Truncated)?;
    let (header_len, total_size) = if size32 == 1 {
        let size64 = be_u64(bytes, pos + 8).ok_or(HevcError::Truncated)?;
        (
            16usize,
            usize::try_from(size64).map_err(|_| {
                HevcError::ContainerMalformed("64-bit box size does not fit in usize")
            })?,
        )
    } else if size32 == 0 {
        match zero {
            ZeroSize::ExtendToLimit => (8usize, limit - pos),
            ZeroSize::Reject => {
                return Err(HevcError::ContainerMalformed("box size is zero"));
            }
        }
    } else {
        (8usize, size32 as usize)
    };
    if total_size < header_len {
        return Err(HevcError::ContainerMalformed("invalid box size"));
    }
    Ok(RawBoxSize {
        header_len,
        total_size,
    })
}

/// Read a header and require the whole box to fit inside `[..limit]`.
///
/// `limit` is clamped to `bytes.len()` so callers may pass an enclosing end
/// without repeating the clamp.
pub(crate) fn read_box_header(
    bytes: &[u8],
    pos: usize,
    limit: usize,
    zero: ZeroSize,
) -> Result<BoxHeader> {
    let limit = limit.min(bytes.len());
    let raw = decode_size(bytes, pos, limit, zero)?;
    if pos
        .checked_add(raw.total_size)
        .is_none_or(|end| end > limit)
    {
        return Err(HevcError::ContainerMalformed("invalid box size"));
    }
    Ok(BoxHeader {
        tag: [
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ],
        header_len: raw.header_len,
        total_size: raw.total_size,
    })
}

/// Read the size fields without requiring the box to fit in the buffer.
///
/// The thumbnail bridge deliberately keeps parsing after a truncated tail and
/// applies its own `size > remaining` check, so it must be able to see a size
/// that exceeds the slice instead of receiving a truncated-input error.
pub(crate) fn read_box_size_unchecked(
    bytes: &[u8],
    pos: usize,
    limit: usize,
) -> Result<RawBoxSize> {
    decode_size(bytes, pos, limit.min(bytes.len()), ZeroSize::ExtendToLimit)
}
