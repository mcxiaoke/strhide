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
pub const NAL_IDR_W_RADL: u8 = 19;
pub const NAL_IDR_N_LP: u8 = 20;
pub const NAL_CRA_NUT: u8 = 21;
pub const NAL_VPS_NUT: u8 = 32;
pub const NAL_SPS_NUT: u8 = 33;
pub const NAL_PPS_NUT: u8 = 34;
pub const NAL_AUD_NUT: u8 = 35;
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
    matches!(
        nal_type,
        NAL_VPS_NUT
            | NAL_SPS_NUT
            | NAL_PPS_NUT
            | NAL_IDR_W_RADL
            | NAL_IDR_N_LP
            | NAL_CRA_NUT
            | NAL_TRAIL_R
            | NAL_TRAIL_N
            | NAL_AUD_NUT
            | NAL_PREFIX_SEI_NUT
    )
}
