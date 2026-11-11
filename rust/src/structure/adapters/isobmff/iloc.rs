//! `iloc` item-location readers shared by the container walk and the
//! `item_hidden` strategy.

use std::io::SeekFrom;

use crate::errors::StrHideError;
use crate::structure::adapters::SeekRead;

use super::boxes::{box_header_is_64_bit, read_box_size, read_sized_uint};
use super::read_meta_box_bytes;

pub(super) fn isobmff_has_iloc_item(
    stego_in: &mut dyn SeekRead,
    target_off: u64,
    target_len: u64,
) -> Result<bool, StrHideError> {
    let cur_pos = stego_in.stream_position().unwrap_or(0);
    let data = match read_meta_box_bytes(stego_in)? {
        Some(data) => data,
        None => {
            let _ = stego_in.seek(SeekFrom::Start(cur_pos));
            return Ok(false);
        }
    };
    let _ = stego_in.seek(SeekFrom::Start(cur_pos));

    // Same header-length fix as `isobmff_can_item_hidden`.
    let m_end = data.len();
    let mut mpos = if box_header_is_64_bit(&data) { 16 } else { 8 } + 4;
    while mpos + 8 <= m_end {
        let (sb_size, _) = match read_box_size(&data, mpos) {
            Ok(s) => s,
            Err(_) => break,
        };
        if sb_size == 0 || sb_size > m_end - mpos {
            break;
        }
        if &data[mpos + 4..mpos + 8] == b"iloc" {
            return check_iloc_has_target(&data[mpos..mpos + sb_size], target_off, target_len);
        }
        mpos += sb_size;
    }
    Ok(false)
}

pub(super) fn check_iloc_has_target(
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
    // v2+ carries a 32-bit count at +14..18; ensure sufficient buffer length
    // before reading to prevent out-of-bounds access.
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
    // A declared item/extent count is attacker-controlled, and zero-width
    // fields make an extent iteration consume no bytes, so the declared counts
    // alone can drive billions of iterations. Charge one unit per iteration
    // against the box size: every real entry consumes at least that much.
    let mut budget = iloc_box.len();
    for _ in 0..iloc_cnt {
        if budget == 0 || cpos + id_sz > iloc_box.len() {
            break;
        }
        budget -= 1;
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
            if budget == 0 {
                break;
            }
            budget -= 1;
            cpos += idx_sz;
            let ext_off = read_sized_uint(iloc_box, cpos, off_sz)?;
            cpos += off_sz;
            let ext_len = read_sized_uint(iloc_box, cpos, len_sz)?;
            cpos += len_sz;
            // A wrapped sum could alias a genuine target offset, and a
            // debug build would panic outright; saturation keeps both out.
            let abs_off = if cm == 0 {
                b_off.saturating_add(ext_off)
            } else {
                ext_off
            };
            if abs_off == target_off && ext_len == target_len {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
