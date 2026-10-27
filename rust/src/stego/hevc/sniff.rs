//! Carrier sniffing for HEVC streams (HEIF container, MP4 container, or raw Annex-B stream).
//!
//! The byte-level probe lives in [`crate::formats::sniff`]: `FileFormat` decides
//! what the file is, and this module only maps that answer onto the three
//! packaging kinds the HEVC engine distinguishes. The NAL-type constants and
//! `is_hevc_annexb` moved to [`crate::formats::annexb`] and are re-exported
//! here so the historical `stego::hevc::sniff::*` paths keep working.

pub use crate::formats::annexb::*;
pub use crate::formats::sniff::is_mp4_bytes;

use crate::formats::sniff::{FileFormat, sniff_bytes};

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

/// Sniff byte slice to determine if it is an HEVC carrier.
pub fn sniff_hevc_carrier(bytes: &[u8]) -> Option<HevcCarrierKind> {
    match sniff_bytes(bytes)? {
        FileFormat::Heif => Some(HevcCarrierKind::HeifContainer),
        FileFormat::Mp4 => Some(HevcCarrierKind::Mp4Container),
        FileFormat::HevcAnnexB => Some(HevcCarrierKind::AnnexBStream),
        _ => None,
    }
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
