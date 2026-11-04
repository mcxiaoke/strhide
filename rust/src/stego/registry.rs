//! Algorithm registry facade for content-adaptive steganography.
//!
//! The per-domain registries live next to their engines
//! ([`crate::stego::png::registry`] for spatial models, with the wire ids the
//! PNG feature word carries, and [`crate::stego::jpeg::registry`] for DCT
//! models). This module is the aggregate the CLI lists: it forwards the
//! lookups and owns the HEVC and audio listing rows.
//!
//! Only algorithms that actually exist are accepted: the earlier "wow" ->
//! HILL and "nsf5" -> UERD silent aliases were removed (2026-10-20) because
//! they let callers believe they had selected a different cost model than
//! the one that ran.

use serde::{Deserialize, Serialize};

use crate::formats::FileFormat;

/// Detailed metadata describing a content-domain steganography algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StegoAlgorithmInfo {
    /// Unique algorithm identifier (e.g. "hill", "uerd", "hevc", "wav_pcm", "flac_residual").
    pub id: String,
    /// Human-friendly algorithm display name (e.g. "HILL", "UERD", "HEVC CABAC", "WAV PCM LSB", "FLAC Residual").
    pub name: String,
    /// Detailed description including principle, paper reference, and characteristics.
    pub desc: String,
    /// Domain category: "spatial" | "dct" | "hevc" | "audio".
    pub domain: String,
    /// Applicable file format identifiers (matching [`FileFormat::as_str`]).
    pub formats: Vec<String>,
    /// Applicable file extensions (e.g. `["png"]`, `["jpg", "jpeg", "jpe"]`).
    pub extensions: Vec<String>,
    /// Whether this algorithm is the default choice for its target format.
    pub is_default: bool,
}

/// Return structured metadata for all available content-domain steganography algorithms.
pub fn list_stego_algorithms() -> Vec<StegoAlgorithmInfo> {
    let mut out = Vec::new();

    #[cfg(feature = "content-png")]
    {
        out.push(StegoAlgorithmInfo {
            id: "hill".into(),
            name: "HILL".into(),
            desc: "High-pass, Low-pass, and Low-pass filtered adaptive spatial cost model (Li et al., ICIP 2014)".into(),
            domain: "spatial".into(),
            formats: vec![FileFormat::Png.as_str().into()],
            extensions: vec!["png".into()],
            is_default: true,
        });
        out.push(StegoAlgorithmInfo {
            id: "suniward".into(),
            name: "S-UNIWARD".into(),
            desc: "Spatial Universal Wavelet Relative Distortion cost model (Holub et al., EURASIP JIS 2014)".into(),
            domain: "spatial".into(),
            formats: vec![FileFormat::Png.as_str().into()],
            extensions: vec!["png".into()],
            is_default: false,
        });
        out.push(StegoAlgorithmInfo {
            id: "mipod".into(),
            name: "MiPOD".into(),
            desc: "Minimizing the Power of Optimal Detector under variance estimation (Sedighi et al., IEEE TIFS 2016)".into(),
            domain: "spatial".into(),
            formats: vec![FileFormat::Png.as_str().into()],
            extensions: vec!["png".into()],
            is_default: false,
        });
    }

    #[cfg(feature = "content-jpeg")]
    {
        out.push(StegoAlgorithmInfo {
            id: "uerd".into(),
            name: "UERD".into(),
            desc: "UERD-inspired variant for JPEG DCT coefficients (Q^1, 8-neighbour average; deviates from Guo et al. 2015)".into(),
            domain: "dct".into(),
            formats: vec![FileFormat::Jpeg.as_str().into()],
            extensions: vec!["jpg".into(), "jpeg".into(), "jpe".into()],
            is_default: true,
        });
        out.push(StegoAlgorithmInfo {
            id: "juniward".into(),
            name: "J-UNIWARD".into(),
            desc: "JPEG Universal Wavelet Relative Distortion cost model (Holub et al., EURASIP JIS 2014)".into(),
            domain: "dct".into(),
            formats: vec![FileFormat::Jpeg.as_str().into()],
            extensions: vec!["jpg".into(), "jpeg".into(), "jpe".into()],
            is_default: false,
        });
        out.push(StegoAlgorithmInfo {
            id: "jmipod".into(),
            name: "J-MiPOD".into(),
            desc: "Joint DCT domain multivariate normal detectability model (Cogranne et al., ACM IH&MMSec 2020)".into(),
            domain: "dct".into(),
            formats: vec![FileFormat::Jpeg.as_str().into()],
            extensions: vec!["jpg".into(), "jpeg".into(), "jpe".into()],
            is_default: false,
        });
    }

    #[cfg(feature = "content-hevc")]
    out.push(StegoAlgorithmInfo {
        id: "hevc".into(),
        name: "HEVC CABAC".into(),
        desc: "H.265 CABAC bypass sign bit in-place steganography (Scheme C, zero expansion)"
            .into(),
        domain: "hevc".into(),
        formats: vec![
            FileFormat::Heif.as_str().into(),
            FileFormat::Mp4.as_str().into(),
            FileFormat::Mkv.as_str().into(),
            FileFormat::HevcAnnexB.as_str().into(),
        ],
        extensions: vec![
            "heic".into(),
            "heif".into(),
            "avif".into(),
            "mp4".into(),
            "mov".into(),
            "m4v".into(),
            "mkv".into(),
            "webm".into(),
            "h265".into(),
            "hevc".into(),
            "265".into(),
            "bin".into(),
        ],
        is_default: true,
    });

    #[cfg(feature = "content-audio")]
    {
        out.push(StegoAlgorithmInfo {
            id: "wav_pcm".into(),
            name: "WAV PCM LSB".into(),
            desc: "Content-adaptive PCM sample matching (perceptual cost + STC, in-place +/-1 LSB)"
                .into(),
            domain: "audio".into(),
            formats: vec![FileFormat::Wav.as_str().into()],
            extensions: vec!["wav".into()],
            is_default: true,
        });
        out.push(StegoAlgorithmInfo {
            id: "flac_residual".into(),
            name: "FLAC Residual".into(),
            desc: "Codeword-length preserving polynomial prediction residual matching".into(),
            domain: "audio".into(),
            formats: vec![FileFormat::Flac.as_str().into()],
            extensions: vec!["flac".into()],
            is_default: true,
        });
    }

    out
}

/// Filter algorithms applicable to a specific carrier [`FileFormat`].
pub fn algorithms_for_format(format: FileFormat) -> Vec<StegoAlgorithmInfo> {
    let name = format.as_str();
    list_stego_algorithms()
        .into_iter()
        .filter(|a| a.formats.iter().any(|f| f.eq_ignore_ascii_case(name)))
        .collect()
}

/// Return list of available algorithm names and descriptions for CLI listing.
#[allow(clippy::vec_init_then_push)]
pub fn list_algorithms() -> Vec<(&'static str, &'static str, &'static str)> {
    let mut out = Vec::new();
    #[cfg(feature = "content-png")]
    out.extend(crate::stego::png::registry::list());
    #[cfg(feature = "content-jpeg")]
    out.extend(crate::stego::jpeg::registry::list());
    #[cfg(feature = "content-hevc")]
    out.push((
        "hevc",
        "HEIF/HEVC",
        "H.265 CABAC bypass sign bit in-place steganography (Scheme C, zero expansion)",
    ));
    #[cfg(feature = "content-audio")]
    {
        out.push((
            "wav_pcm",
            "Audio (WAV)",
            "Content-adaptive PCM sample matching (perceptual cost + STC, in-place +/-1 LSB)",
        ));
        out.push((
            "flac_residual",
            "Audio (FLAC)",
            "Codeword-length preserving polynomial prediction residual matching",
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_algorithm_is_consistent_across_all_lookup_tables() {
        let listed = super::list_algorithms();
        assert!(!listed.is_empty(), "the CLI listing must not be empty");

        #[allow(unused_mut)]
        let mut spatial_seen = 0usize;
        #[allow(unused_mut)]
        let mut jpeg_seen = 0usize;
        #[allow(unused_mut)]
        let mut hevc_seen = 0usize;
        #[allow(unused_mut)]
        let mut audio_seen = 0usize;
        for (name, domain, description) in listed {
            assert!(!description.is_empty(), "{name}: empty description");
            match domain {
                #[cfg(feature = "content-png")]
                "Spatial (PNG)" => {
                    spatial_seen += 1;
                    let model = crate::stego::png::registry::get_spatial_model(Some(name))
                        .unwrap_or_else(|| panic!("{name}: listed but not resolvable"));
                    assert_eq!(model.id(), name, "{name}: list name != model id");
                    let id = crate::stego::png::registry::spatial_wire_id(name)
                        .unwrap_or_else(|| panic!("{name}: no wire id"));
                    assert_eq!(
                        crate::stego::png::registry::spatial_name_from_wire_id(id),
                        Some(name),
                        "{name}: wire id {id} does not map back"
                    );
                }
                #[cfg(feature = "content-jpeg")]
                "JPEG (JPG)" => {
                    jpeg_seen += 1;
                    let model = crate::stego::jpeg::registry::get_jpeg_model(Some(name))
                        .unwrap_or_else(|| panic!("{name}: listed but not resolvable"));
                    assert_eq!(model.id(), name, "{name}: list name != model id");
                }
                // The HEVC Scheme C engine carries no cost-model selection, so
                // this entry only needs to exist for the CLI listing.
                "HEIF/HEVC" => hevc_seen += 1,
                // Audio engine algorithms (WAV PCM, FLAC residual).
                "Audio (WAV)" | "Audio (FLAC)" => audio_seen += 1,
                other => panic!("{name}: unknown domain label {other:?}"),
            }
        }

        #[cfg(feature = "content-png")]
        assert!(spatial_seen > 0, "no spatial algorithm listed");
        #[cfg(feature = "content-jpeg")]
        assert!(jpeg_seen > 0, "no JPEG algorithm listed");
        #[cfg(feature = "content-hevc")]
        assert!(hevc_seen > 0, "no HEVC algorithm listed");
        #[cfg(feature = "content-audio")]
        assert!(audio_seen > 0, "no audio algorithm listed");
    }

    #[test]
    fn test_stego_algorithms_metadata_is_consistent() {
        let all = list_stego_algorithms();
        assert!(!all.is_empty(), "algorithm list must not be empty");

        for algo in &all {
            assert!(!algo.id.is_empty(), "empty algorithm id");
            assert!(!algo.name.is_empty(), "{}: empty name", algo.id);
            assert!(!algo.desc.is_empty(), "{}: empty desc", algo.id);
            assert!(!algo.domain.is_empty(), "{}: empty domain", algo.id);
            assert!(!algo.formats.is_empty(), "{}: empty formats", algo.id);
            assert!(!algo.extensions.is_empty(), "{}: empty extensions", algo.id);
        }

        #[cfg(feature = "content-png")]
        {
            let png_algos = algorithms_for_format(FileFormat::Png);
            assert_eq!(png_algos.len(), 3);
            assert!(png_algos.iter().any(|a| a.id == "hill" && a.is_default));
        }

        #[cfg(feature = "content-jpeg")]
        {
            let jpg_algos = algorithms_for_format(FileFormat::Jpeg);
            assert_eq!(jpg_algos.len(), 3);
            assert!(jpg_algos.iter().any(|a| a.id == "uerd" && a.is_default));
        }

        #[cfg(feature = "content-hevc")]
        {
            let mp4_algos = algorithms_for_format(FileFormat::Mp4);
            assert_eq!(mp4_algos.len(), 1);
            assert_eq!(mp4_algos[0].id, "hevc");
            let mkv_algos = algorithms_for_format(FileFormat::Mkv);
            assert_eq!(mkv_algos.len(), 1);
            assert_eq!(mkv_algos[0].id, "hevc");
        }

        #[cfg(feature = "content-audio")]
        {
            let wav_algos = algorithms_for_format(FileFormat::Wav);
            assert_eq!(wav_algos.len(), 1);
            assert_eq!(wav_algos[0].id, "wav_pcm");

            let flac_algos = algorithms_for_format(FileFormat::Flac);
            assert_eq!(flac_algos.len(), 1);
            assert_eq!(flac_algos[0].id, "flac_residual");
        }
    }
}
