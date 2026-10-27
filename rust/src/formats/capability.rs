//! The capability table: one row per carrier format, and the only place that
//! says which domain and which strategies a format supports.
//!
//! Before this table the same facts were spread across three places that could
//! drift: `HostAdapter::supports_content_stego` (five overrides), the content
//! domain's `CarrierFormat` enum, and the CLI's hand-written tables in `list`.
//! Adding a format meant remembering all of them.
//!
//! The table is data, not policy: adapters still own *how* a strategy writes
//! and engines still own *how* an embed works. A consistency test
//! (`tests/test_lifecycle/sniff.rs`) asserts that every adapter's
//! `supported_strategies()` matches its row here, so the two cannot drift
//! silently.

use crate::formats::sniff::FileFormat;

/// The content-domain engines, as advertised to users and dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StegoKind {
    /// PNG spatial domain (HILL / S-UNIWARD + STC).
    PngSpatial,
    /// JPEG DCT domain (UERD / J-UNIWARD + STC-V3).
    JpegDct,
    /// HEVC CABAC bypass channel (Annex-B, MP4/MOV, HEIF Scheme C).
    HevcCabac,
    /// HEIF bridge: embed into an embedded JPEG thumbnail or `unci` item.
    HeifBridge,
}

impl StegoKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            StegoKind::PngSpatial => "png-spatial",
            StegoKind::JpegDct => "jpeg-dct",
            StegoKind::HevcCabac => "hevc-cabac",
            StegoKind::HeifBridge => "heif-bridge",
        }
    }
}

/// One carrier format's capabilities.
pub struct Capability {
    pub format: FileFormat,
    /// Structure-domain strategies, in the adapter's priority order. Empty for
    /// formats that only the content domain can carry (raw Annex-B).
    pub structure: &'static [&'static str],
    /// Content-domain engines. Empty for container-only formats.
    pub stego: &'static [StegoKind],
    /// File extensions, for CLI filtering and future GUI file dialogs.
    pub extensions: &'static [&'static str],
}

/// Every supported format. Order matches [`FileFormat::ALL`].
pub static CAPABILITIES: &[Capability] = &[
    Capability {
        format: FileFormat::Png,
        structure: &["chunk", "eof"],
        stego: &[StegoKind::PngSpatial],
        extensions: &["png"],
    },
    Capability {
        format: FileFormat::Jpeg,
        structure: &["app_segment", "eof"],
        stego: &[StegoKind::JpegDct],
        extensions: &["jpg", "jpeg", "jpe"],
    },
    Capability {
        format: FileFormat::Webp,
        structure: &["riff_chunk", "eof"],
        stego: &[],
        extensions: &["webp"],
    },
    Capability {
        format: FileFormat::Heif,
        structure: &["item_hidden", "free_box", "box_uuid", "eof"],
        stego: &[StegoKind::HevcCabac, StegoKind::HeifBridge],
        extensions: &["heic", "heif", "avif"],
    },
    Capability {
        format: FileFormat::Mp4,
        structure: &["box_uuid", "eof"],
        stego: &[StegoKind::HevcCabac],
        extensions: &["mp4", "mov", "m4v"],
    },
    Capability {
        format: FileFormat::Mkv,
        structure: &["ebml_void", "eof"],
        stego: &[],
        extensions: &["mkv", "webm"],
    },
    Capability {
        format: FileFormat::Wav,
        structure: &["riff_chunk", "eof"],
        stego: &[],
        extensions: &["wav"],
    },
    Capability {
        format: FileFormat::Zip,
        structure: &["pre_cd_inject", "eof"],
        stego: &[],
        extensions: &["zip", "jar"],
    },
    Capability {
        format: FileFormat::Pdf,
        structure: &["incremental", "eof"],
        stego: &[],
        extensions: &["pdf"],
    },
    Capability {
        format: FileFormat::Pe,
        structure: &["pe_codebits", "pe_slack", "pe_overlay", "eof"],
        stego: &[],
        extensions: &["exe", "dll"],
    },
    Capability {
        format: FileFormat::HevcAnnexB,
        structure: &[],
        stego: &[StegoKind::HevcCabac],
        extensions: &["h265", "hevc", "265"],
    },
];

/// The row for `format`.
///
/// Panics on an unlisted format: `FileFormat` and `CAPABILITIES` are both
/// crate-local, and the table has one row per variant, so a missing row is a
/// programming error rather than a user-facing condition. A unit test pins it.
pub fn capability_of(format: FileFormat) -> &'static Capability {
    CAPABILITIES
        .iter()
        .find(|c| c.format == format)
        .unwrap_or_else(|| panic!("no capability row for {format:?}"))
}

impl FileFormat {
    /// Whether the structure domain can inject an envelope into this format.
    pub fn supports_structure(self) -> bool {
        !capability_of(self).structure.is_empty()
    }

    /// Whether any content-domain engine accepts this format.
    pub fn supports_stego(self) -> bool {
        !capability_of(self).stego.is_empty()
    }

    /// Lower-case file extensions, without the dot.
    pub fn extensions(self) -> &'static [&'static str] {
        capability_of(self).extensions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_format_has_exactly_one_row() {
        for format in FileFormat::ALL {
            let rows: Vec<_> = CAPABILITIES
                .iter()
                .filter(|c| c.format == *format)
                .collect();
            assert_eq!(rows.len(), 1, "{format:?} must have one row");
        }
        assert_eq!(CAPABILITIES.len(), FileFormat::ALL.len());
    }

    #[test]
    fn domain_support_matches_the_documented_matrix() {
        // Structure domain: every container, but not a raw Annex-B stream.
        for format in FileFormat::ALL {
            let expected = *format != FileFormat::HevcAnnexB;
            assert_eq!(
                format.supports_structure(),
                expected,
                "{format:?} structure support"
            );
        }
        // Content domain: exactly the five HEVC/PNG/JPEG carriers.
        let stego: Vec<_> = FileFormat::ALL
            .iter()
            .copied()
            .filter(|f| f.supports_stego())
            .collect();
        assert_eq!(
            stego,
            vec![
                FileFormat::Png,
                FileFormat::Jpeg,
                FileFormat::Heif,
                FileFormat::Mp4,
                FileFormat::HevcAnnexB,
            ]
        );
    }

    #[test]
    fn extensions_are_lowercase_and_dotless() {
        for cap in CAPABILITIES {
            for ext in cap.extensions {
                assert!(
                    !ext.starts_with('.')
                        && ext
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                    "{:?} extension {ext:?}",
                    cap.format
                );
            }
        }
    }
}
