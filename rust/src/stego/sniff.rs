//! Carrier format sniffing for content-adaptive steganography.
//!
//! The unified entry points sniff internally; this module exposes the same
//! decision as a public value so a caller can pre-flight a carrier ("is this
//! format supported at all? which engine will handle it?") without attempting
//! an embed and interpreting an error.

use crate::sniff::{is_heif_bytes, is_jpeg_bytes, is_png_bytes};

use crate::stego::hevc::sniff::is_hevc_annexb;

/// Carrier format recognised by the content-domain steganography engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierFormat {
    /// PNG image (spatial domain, HILL/S-UNIWARD cost models).
    Png,
    /// Baseline/progressive JPEG (DCT domain, UERD/J-UNIWARD cost models).
    Jpeg,
    /// ISO-BMFF HEIF/HEIC container (thumbnail bridge or HEVC Scheme C).
    Heif,
    /// Raw Annex-B H.265/HEVC bitstream (Scheme C).
    HevcAnnexB,
    /// Not a carrier any content-domain engine accepts.
    Unsupported,
}

impl CarrierFormat {
    /// Whether any content-domain engine can embed into this format.
    pub fn is_supported(self) -> bool {
        !matches!(self, CarrierFormat::Unsupported)
    }

    /// Stable lowercase name for diagnostics and CLI output.
    pub fn as_str(self) -> &'static str {
        match self {
            CarrierFormat::Png => "png",
            CarrierFormat::Jpeg => "jpeg",
            CarrierFormat::Heif => "heif",
            CarrierFormat::HevcAnnexB => "hevc",
            CarrierFormat::Unsupported => "unsupported",
        }
    }
}

impl std::fmt::Display for CarrierFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Sniff the carrier format of a byte slice.
///
/// The order matters: a HEIF container also starts with an ISO-BMFF `ftyp`
/// box, so it must be tested before the generic MP4 probe, and both before the
/// Annex-B start-code probe (a container's payload can contain start codes).
pub fn sniff_carrier(bytes: &[u8]) -> CarrierFormat {
    if is_png_bytes(bytes) {
        CarrierFormat::Png
    } else if is_jpeg_bytes(bytes) {
        CarrierFormat::Jpeg
    } else if is_heif_bytes(bytes) {
        CarrierFormat::Heif
    } else if is_hevc_annexb(bytes) {
        CarrierFormat::HevcAnnexB
    } else {
        CarrierFormat::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_each_supported_format() {
        assert_eq!(sniff_carrier(b"\x89PNG\r\n\x1a\n rest"), CarrierFormat::Png);
        assert_eq!(sniff_carrier(b"\xFF\xD8\xFF\xE0 rest"), CarrierFormat::Jpeg);

        let mut heic = Vec::new();
        heic.extend_from_slice(&16u32.to_be_bytes());
        heic.extend_from_slice(b"ftypheicmif1");
        assert_eq!(sniff_carrier(&heic), CarrierFormat::Heif);

        // Annex-B: start code + NAL header (forbidden_zero_bit=0, nal_unit_type=1
        // TRAIL_R, then a plausible header byte).
        let annexb = [0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0xAF, 0x00];
        assert_eq!(sniff_carrier(&annexb), CarrierFormat::HevcAnnexB);

        assert_eq!(
            sniff_carrier(b"not a carrier at all"),
            CarrierFormat::Unsupported
        );
        assert!(!CarrierFormat::Unsupported.is_supported());
        assert_eq!(CarrierFormat::HevcAnnexB.as_str(), "hevc");
        assert_eq!(CarrierFormat::Png.to_string(), "png");
    }
}
