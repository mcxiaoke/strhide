//! Annex-B (H.265/HEVC bitstream) framing detection.
//!
//! Framing only: start-code form, the two-byte NAL header, and a NAL-type
//! whitelist. Nothing here understands slice syntax, parameter sets or CABAC —
//! that is `stego::hevc`'s job. It lives in the `formats` layer because
//! `FileFormat::HevcAnnexB` is a carrier classification, and the content
//! domain is the only consumer that needs to tell a raw bitstream apart from a
//! container.

/// HEVC NAL Unit Types (ITU-T H.265 Table 7-1).
pub const NAL_TRAIL_N: u8 = 0;
pub const NAL_TRAIL_R: u8 = 1;
pub const NAL_TSA_N: u8 = 2;
pub const NAL_TSA_R: u8 = 3;
pub const NAL_STSA_N: u8 = 4;
pub const NAL_STSA_R: u8 = 5;
pub const NAL_RADL_N: u8 = 6;
pub const NAL_RADL_R: u8 = 7;
pub const NAL_RASL_N: u8 = 8;
pub const NAL_RASL_R: u8 = 9;
pub const NAL_BLA_W_LP: u8 = 16;
pub const NAL_BLA_W_RADL: u8 = 17;
pub const NAL_BLA_N_LP: u8 = 18;
pub const NAL_IDR_W_RADL: u8 = 19;
pub const NAL_IDR_N_LP: u8 = 20;
pub const NAL_CRA_NUT: u8 = 21;
pub const NAL_VPS_NUT: u8 = 32;
pub const NAL_SPS_NUT: u8 = 33;
pub const NAL_PPS_NUT: u8 = 34;
pub const NAL_AUD_NUT: u8 = 35;
pub const NAL_EOS_NUT: u8 = 36;
pub const NAL_EOB_NUT: u8 = 37;
pub const NAL_FD_NUT: u8 = 38;
pub const NAL_PREFIX_SEI_NUT: u8 = 39;
pub const NAL_SUFFIX_SEI_NUT: u8 = 40;

/// Check if bytes form a valid HEVC Annex-B stream by verifying start code and NAL header.
pub fn is_hevc_annexb(bytes: &[u8]) -> bool {
    if bytes.len() < 6 {
        return false;
    }
    let first_start = if bytes.starts_with(&[0, 0, 0, 1]) {
        4
    } else if bytes.starts_with(&[0, 0, 1]) {
        3
    } else {
        return false;
    };

    if first_start + 2 > bytes.len() {
        return false;
    }

    // HEVC NAL Unit Header (2 bytes):
    // bit 0: forbidden_zero_bit (must be 0)
    // bits 1..7: nal_unit_type (6 bits)
    // bits 7..13: nuh_layer_id (6 bits, 0 for base layer)
    // bits 13..16: nuh_temporal_id_plus1 (3 bits, must be > 0)
    let b0 = bytes[first_start];
    let b1 = bytes[first_start + 1];

    if (b0 & 0x80) != 0 {
        return false;
    }
    let nuh_layer_id = ((b0 & 1) << 5) | (b1 >> 3);
    if nuh_layer_id != 0 {
        return false;
    }
    let temporal_id_plus1 = b1 & 0x07;
    if temporal_id_plus1 == 0 {
        return false;
    }

    let nal_type = (b0 >> 1) & 0x3F;
    is_known_nal_type(nal_type)
}

/// Whether `nal_type` is one H.265 Table 7-1 defines (reserved and unspecified
/// ranges excluded).
///
/// A segment or a spliced stream may legitimately begin with any VCL type --
/// `TSA`, `STSA`, `RADL` and `RASL` prefixes appear after random access points
/// in real files, and `BLA` before a broken-link start -- so sniffing on a
/// parameter-set subset alone rejected legal carriers. Reserved types (10..=15,
/// 22..=31, 41..=47) and unspecified ones (48..=63) stay rejected, which keeps
/// the false-positive rate of a random start code bounded.
fn is_known_nal_type(nal_type: u8) -> bool {
    matches!(
        nal_type,
        // VCL, defined range (0..=9).
        NAL_TRAIL_N
            | NAL_TRAIL_R
            | NAL_TSA_N
            | NAL_TSA_R
            | NAL_STSA_N
            | NAL_STSA_R
            | NAL_RADL_N
            | NAL_RADL_R
            | NAL_RASL_N
            | NAL_RASL_R
            // VCL, IRAP/BLA range (16..=21).
            | NAL_BLA_W_LP
            | NAL_BLA_W_RADL
            | NAL_BLA_N_LP
            | NAL_IDR_W_RADL
            | NAL_IDR_N_LP
            | NAL_CRA_NUT
            // Non-VCL: parameter sets, delimiters and SEI (32..=40).
            | NAL_VPS_NUT
            | NAL_SPS_NUT
            | NAL_PPS_NUT
            | NAL_AUD_NUT
            | NAL_EOS_NUT
            | NAL_EOB_NUT
            | NAL_FD_NUT
            | NAL_PREFIX_SEI_NUT
            | NAL_SUFFIX_SEI_NUT
    )
}
