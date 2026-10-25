//! Carrier sniffing for HEVC streams (HEIF container, MP4 container, or raw Annex-B stream).

use crate::sniff::is_heif_bytes;

/// Identified container or stream packaging of an HEVC carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HevcCarrierKind {
    /// ISO BMFF HEIF image container (holding one or more `hvc1` items).
    HeifContainer,
    /// ISO BMFF MP4/MOV video container (holding `hvc1`/`hev1` tracks).
    Mp4Container,
    /// Raw Annex-B HEVC bitstream (delimited by `0x000001` or `0x00000001` start codes).
    AnnexBStream,
}

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

/// Sniff byte slice to determine if it is an HEVC carrier.
pub fn sniff_hevc_carrier(bytes: &[u8]) -> Option<HevcCarrierKind> {
    if is_heif_bytes(bytes) {
        Some(HevcCarrierKind::HeifContainer)
    } else if is_mp4_bytes(bytes) {
        Some(HevcCarrierKind::Mp4Container)
    } else if is_hevc_annexb(bytes) {
        Some(HevcCarrierKind::AnnexBStream)
    } else {
        None
    }
}

/// Check if bytes look like an MP4/MOV container holding video.
pub fn is_mp4_bytes(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let tag = &bytes[4..8];
    (tag == b"ftyp" || tag == b"moov" || tag == b"mdat") && !is_heif_bytes(bytes)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn annexb_with_nal_type(nal_type: u8) -> Vec<u8> {
        // 4-byte start code, 2-byte NAL header (forbidden_zero_bit = 0,
        // temporal_id_plus1 = 1), then a filler payload byte.
        let mut out = vec![0x00, 0x00, 0x00, 0x01];
        out.push(nal_type << 1);
        out.push(0x01);
        out.push(0x00);
        out
    }

    #[test]
    fn every_defined_nal_type_starts_an_annexb_stream() {
        // Regression: a segment starting with TSA/STSA/RADL/RASL or a BLA was
        // rejected as "not HEVC" even though a spliced stream may begin there.
        for nal_type in (0u8..=9).chain(16..=21).chain(32..=40) {
            assert!(
                is_hevc_annexb(&annexb_with_nal_type(nal_type)),
                "nal_type {nal_type} must sniff as Annex-B"
            );
        }
    }

    #[test]
    fn reserved_and_unspecified_nal_types_are_rejected() {
        for nal_type in (10u8..=15).chain(22..=31).chain(41..=63) {
            assert!(
                !is_hevc_annexb(&annexb_with_nal_type(nal_type)),
                "nal_type {nal_type} is reserved/unspecified and must not sniff"
            );
        }
    }

    #[test]
    fn header_flags_still_gate_the_sniff() {
        let mut forbidden = annexb_with_nal_type(NAL_SPS_NUT);
        forbidden[4] |= 0x80;
        assert!(!is_hevc_annexb(&forbidden), "forbidden_zero_bit must be 0");

        let mut zero_tid = annexb_with_nal_type(NAL_SPS_NUT);
        zero_tid[5] &= 0xF8;
        assert!(!is_hevc_annexb(&zero_tid), "temporal_id_plus1 must be > 0");
    }
}
