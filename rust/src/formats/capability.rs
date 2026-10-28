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

use serde::{Deserialize, Serialize};

use crate::formats::sniff::FileFormat;

/// Memory consumption profile for an operation on a carrier format.
///
/// Used by GUI schedulers to bound worker concurrency: `Streaming` carriers
/// can run with multiple concurrent threads safely, while `WholeFile` carriers
/// (e.g. 50 MP images or HEVC video bitstreams) are scheduled with restricted
/// concurrency to prevent out-of-memory errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryProfile {
    /// Bounded memory stream processing (e.g. ZIP, PDF, PE slack/overlay, WAV, MKV).
    Streaming,
    /// Uncompressed raster/DCT coefficient arrays or CABAC bitstream recording.
    WholeFile,
}

/// The content-domain engines, as advertised to users and dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Capability {
    pub format: FileFormat,
    /// Structure-domain strategies, in the adapter's priority order. Empty for
    /// formats that only the content domain can carry (raw Annex-B).
    pub structure: &'static [&'static str],
    /// Content-domain engines. Empty for container-only formats.
    pub stego: &'static [StegoKind],
    /// File extensions, for CLI filtering and future GUI file dialogs.
    pub extensions: &'static [&'static str],
    /// Concurrency and memory profile.
    pub memory: MemoryProfile,
}

/// Every supported format. Order matches [`FileFormat::ALL`].
pub static CAPABILITIES: &[Capability] = &[
    Capability {
        format: FileFormat::Png,
        #[cfg(feature = "structure-base")]
        structure: &["chunk", "eof"],
        #[cfg(not(feature = "structure-base"))]
        structure: &[],
        #[cfg(feature = "content-png")]
        stego: &[StegoKind::PngSpatial],
        #[cfg(not(feature = "content-png"))]
        stego: &[],
        extensions: &["png"],
        memory: MemoryProfile::WholeFile,
    },
    Capability {
        format: FileFormat::Jpeg,
        #[cfg(feature = "structure-base")]
        structure: &["app_segment", "eof"],
        #[cfg(not(feature = "structure-base"))]
        structure: &[],
        #[cfg(feature = "content-jpeg")]
        stego: &[StegoKind::JpegDct],
        #[cfg(not(feature = "content-jpeg"))]
        stego: &[],
        extensions: &["jpg", "jpeg", "jpe"],
        memory: MemoryProfile::WholeFile,
    },
    Capability {
        format: FileFormat::Webp,
        #[cfg(feature = "structure-base")]
        structure: &["riff_chunk", "eof"],
        #[cfg(not(feature = "structure-base"))]
        structure: &[],
        stego: &[],
        extensions: &["webp"],
        memory: MemoryProfile::Streaming,
    },
    Capability {
        format: FileFormat::Heif,
        #[cfg(feature = "structure-base")]
        structure: &["item_hidden", "free_box", "box_uuid", "eof"],
        #[cfg(not(feature = "structure-base"))]
        structure: &[],
        #[cfg(all(feature = "content-hevc", feature = "content-heif-bridge"))]
        stego: &[StegoKind::HevcCabac, StegoKind::HeifBridge],
        #[cfg(all(feature = "content-hevc", not(feature = "content-heif-bridge")))]
        stego: &[StegoKind::HevcCabac],
        #[cfg(not(feature = "content-hevc"))]
        stego: &[],
        extensions: &["heic", "heif", "avif"],
        memory: MemoryProfile::WholeFile,
    },
    Capability {
        format: FileFormat::Mp4,
        #[cfg(feature = "structure-base")]
        structure: &["box_uuid", "eof"],
        #[cfg(not(feature = "structure-base"))]
        structure: &[],
        #[cfg(feature = "content-hevc")]
        stego: &[StegoKind::HevcCabac],
        #[cfg(not(feature = "content-hevc"))]
        stego: &[],
        extensions: &["mp4", "mov", "m4v"],
        memory: MemoryProfile::WholeFile,
    },
    Capability {
        format: FileFormat::Mkv,
        #[cfg(feature = "structure-base")]
        structure: &["ebml_void", "eof"],
        #[cfg(not(feature = "structure-base"))]
        structure: &[],
        stego: &[],
        extensions: &["mkv", "webm"],
        memory: MemoryProfile::Streaming,
    },
    Capability {
        format: FileFormat::Wav,
        #[cfg(feature = "structure-base")]
        structure: &["riff_chunk", "eof"],
        #[cfg(not(feature = "structure-base"))]
        structure: &[],
        stego: &[],
        extensions: &["wav"],
        memory: MemoryProfile::Streaming,
    },
    Capability {
        format: FileFormat::Zip,
        #[cfg(feature = "structure-base")]
        structure: &["pre_cd_inject", "eof"],
        #[cfg(not(feature = "structure-base"))]
        structure: &[],
        stego: &[],
        extensions: &["zip", "jar"],
        memory: MemoryProfile::Streaming,
    },
    Capability {
        format: FileFormat::Pdf,
        #[cfg(feature = "structure-base")]
        structure: &["incremental", "eof"],
        #[cfg(not(feature = "structure-base"))]
        structure: &[],
        stego: &[],
        extensions: &["pdf"],
        memory: MemoryProfile::Streaming,
    },
    Capability {
        format: FileFormat::Pe,
        #[cfg(all(feature = "structure-base", feature = "structure-pe"))]
        structure: &["pe_codebits", "pe_slack", "pe_overlay", "eof"],
        #[cfg(all(feature = "structure-base", not(feature = "structure-pe")))]
        structure: &["pe_slack", "pe_overlay", "eof"],
        #[cfg(not(feature = "structure-base"))]
        structure: &[],
        stego: &[],
        extensions: &["exe", "dll"],
        memory: MemoryProfile::Streaming,
    },
    Capability {
        format: FileFormat::HevcAnnexB,
        structure: &[],
        #[cfg(feature = "content-hevc")]
        stego: &[StegoKind::HevcCabac],
        #[cfg(not(feature = "content-hevc"))]
        stego: &[],
        extensions: &["h265", "hevc", "265"],
        memory: MemoryProfile::WholeFile,
    },
];

/// The row for `format`.
pub fn capability_of(format: FileFormat) -> &'static Capability {
    match format {
        FileFormat::Png => &CAPABILITIES[0],
        FileFormat::Jpeg => &CAPABILITIES[1],
        FileFormat::Webp => &CAPABILITIES[2],
        FileFormat::Heif => &CAPABILITIES[3],
        FileFormat::Mp4 => &CAPABILITIES[4],
        FileFormat::Mkv => &CAPABILITIES[5],
        FileFormat::Wav => &CAPABILITIES[6],
        FileFormat::Zip => &CAPABILITIES[7],
        FileFormat::Pdf => &CAPABILITIES[8],
        FileFormat::Pe => &CAPABILITIES[9],
        FileFormat::HevcAnnexB => &CAPABILITIES[10],
    }
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
        // Structure domain: every container when structure-base is enabled, but not a raw Annex-B stream.
        for format in FileFormat::ALL {
            let expected = {
                #[cfg(feature = "structure-base")]
                {
                    *format != FileFormat::HevcAnnexB
                }
                #[cfg(not(feature = "structure-base"))]
                {
                    false
                }
            };
            assert_eq!(
                format.supports_structure(),
                expected,
                "{format:?} structure support"
            );
        }
        // Content domain: exactly the enabled HEVC/PNG/JPEG carriers.
        let stego: Vec<_> = FileFormat::ALL
            .iter()
            .copied()
            .filter(|f| f.supports_stego())
            .collect();
        let mut expected = Vec::new();
        #[cfg(feature = "content-png")]
        expected.push(FileFormat::Png);
        #[cfg(feature = "content-jpeg")]
        expected.push(FileFormat::Jpeg);
        #[cfg(feature = "content-hevc")]
        {
            expected.push(FileFormat::Heif);
            expected.push(FileFormat::Mp4);
            expected.push(FileFormat::HevcAnnexB);
        }
        assert_eq!(stego, expected);
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
