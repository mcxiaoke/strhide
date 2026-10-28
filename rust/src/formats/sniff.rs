//! Carrier format identification: the single source of truth for "what file is
//! this?".
//!
//! Before this module the same magic-byte tests lived in three places
//! (`sniff.rs`, `stego/sniff.rs`, `stego/hevc/sniff.rs`) and disagreed: the
//! content domain's `CarrierFormat` enum never learned about MP4 (so it
//! answered "unsupported" for a format `embed` accepted), and `is_mp4_bytes`
//! accepted only three of the twelve top-level box types the MP4 adapter
//! recognises. [`FileFormat`] is now the only enumeration; each domain maps it
//! to its own engine instead of re-testing bytes.
//!
//! The predicates (`is_png_bytes` and friends) stay public because they answer
//! a narrower question than [`sniff_bytes`] — "is this a PNG?" rather than
//! "which format wins?" — and because the adapters use them directly.

use std::io::{Read, Seek, SeekFrom};

use crate::formats::annexb::is_hevc_annexb;

/// ISO-BMFF `ftyp` brands that identify an HEIF/HEIC (or AVIF) image file.
pub const HEIF_BRANDS: &[[u8; 4]] = &[
    *b"heic", *b"heix", *b"hevc", *b"hevx", *b"mif1", *b"msf1", *b"heim", *b"heis", *b"avif",
    *b"avis",
];

/// PNG magic (8-byte signature).
pub const PNG_MAGIC: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

/// JPEG SOI marker (first two bytes of a JPEG file).
pub const JPEG_MAGIC: &[u8; 2] = b"\xFF\xD8";

/// PDF header magic.
pub const PDF_MAGIC: [u8; 5] = *b"%PDF-";

/// ZIP local-file header, end-of-central-directory, and spanned-archive markers.
pub const ZIP_LOCAL_MAGIC: [u8; 4] = *b"PK\x03\x04";
pub const ZIP_EOCD_MAGIC: [u8; 4] = *b"PK\x05\x06";
pub const ZIP_SPAN_MAGIC: [u8; 4] = *b"PK\x07\x08";

/// EBML header element ID that starts a Matroska/WebM file.
pub const EBML_HEADER_ID: u32 = 0x1A45_DFA3;

/// Top-level ISO-BMFF box types that identify an MP4/MOV-style container.
///
/// The list covers classic files (`ftyp`/`moov`/`mdat`), fragmented/CMAF media
/// whose first box is `styp`, `moof` or `sidx` (ISO/IEC 14496-12 allows a
/// fragmented stream without a leading `ftyp`), and the neutral filler boxes
/// `free`/`skip`/`wide`/`uuid`/`pdin`/`emsg`. Kept as an explicit whitelist:
/// "size + any 4CC" would classify arbitrary binaries as MP4 and defeat the
/// router's explicit-rejection policy.
const MP4_TOP_LEVEL_BOXES: &[[u8; 4]] = &[
    *b"ftyp", *b"styp", *b"moov", *b"moof", *b"mdat", *b"sidx", *b"emsg", *b"free", *b"skip",
    *b"wide", *b"uuid", *b"pdin",
];

/// How many leading bytes [`sniff_stream`] reads before deciding.
///
/// Every container probe here needs at most one box header (HEIF reads a
/// `ftyp` of up to 4096 bytes, PE reads the DOS header plus the PE signature),
/// so 64 KiB is generous; `sniff_bytes` only ever looks at the first few
/// hundred bytes.
pub const SNIFF_PREFIX_BYTES: usize = 64 * 1024;

/// Carrier container formats the tool understands, plus the raw Annex-B stream.
///
/// This is the classification used by the capability table
/// ([`crate::formats::capability`]), the CLI `list` output and both domains'
/// dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileFormat {
    Png,
    Jpeg,
    Webp,
    Heif,
    Mp4,
    Mkv,
    Wav,
    Zip,
    Pdf,
    Pe,
    /// Raw H.265 Annex-B bitstream: a content-domain carrier, never a
    /// structure-domain one.
    HevcAnnexB,
}

impl FileFormat {
    /// Every variant, in the order the router and `list` present them.
    pub const ALL: &'static [FileFormat] = &[
        FileFormat::Png,
        FileFormat::Jpeg,
        FileFormat::Webp,
        FileFormat::Heif,
        FileFormat::Mp4,
        FileFormat::Mkv,
        FileFormat::Wav,
        FileFormat::Zip,
        FileFormat::Pdf,
        FileFormat::Pe,
        FileFormat::HevcAnnexB,
    ];

    /// Display name, identical to [`crate::structure::adapters::HostAdapter::format_name`]
    /// for the container formats (a consistency test asserts it).
    pub const fn as_str(self) -> &'static str {
        match self {
            FileFormat::Png => "PNG",
            FileFormat::Jpeg => "JPEG",
            FileFormat::Webp => "WEBP",
            FileFormat::Heif => "HEIF",
            FileFormat::Mp4 => "MP4",
            FileFormat::Mkv => "MKV",
            FileFormat::Wav => "WAV",
            FileFormat::Zip => "ZIP",
            FileFormat::Pdf => "PDF",
            FileFormat::Pe => "PE",
            FileFormat::HevcAnnexB => "HEVC-AnnexB",
        }
    }

    /// Map an adapter's `format_name()` back to the enum. `None` for the
    /// generic EOF adapter, which is a strategy rather than a format.
    pub fn from_adapter_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|f| f.as_str() == name)
    }
}

impl std::fmt::Display for FileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for FileFormat {
    /// Serialized as its display name (`"PNG"`, `"HEVC-AnnexB"`, ...), which is
    /// what the `--json` output has always carried: making the enum the field
    /// type must not change the on-the-wire spelling (plan §5.3).
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for FileFormat {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::ALL
            .iter()
            .copied()
            .find(|f| f.as_str().eq_ignore_ascii_case(&s))
            .ok_or_else(|| {
                serde::de::Error::unknown_variant(
                    &s,
                    &[
                        "PNG",
                        "JPEG",
                        "WEBP",
                        "HEIF",
                        "MP4",
                        "MKV",
                        "WAV",
                        "ZIP",
                        "PDF",
                        "PE",
                        "HEVC-AnnexB",
                    ],
                )
            })
    }
}

/// Detect whether the byte slice is an ISO BMFF HEIF/HEIC image container based on ftyp brand.
///
/// The first box must be a well-formed `ftyp` whose size is sane, and at least
/// one brand after the major brand must be a known HEIF/AVIF brand.
pub fn is_heif_bytes(bytes: &[u8]) -> bool {
    if bytes.len() < 12 {
        return false;
    }
    let size = match bytes.get(..4) {
        Some(s) => u32::from_be_bytes(s.try_into().unwrap()) as usize,
        None => return false,
    };
    if &bytes[4..8] != b"ftyp" || !(12..=4096).contains(&size) || bytes.len() < size {
        return false;
    }
    let payload = &bytes[8..size];
    let num_brands = payload.len() / 4;
    for i in 0..num_brands {
        if i == 1 {
            continue;
        }
        let brand = &payload[i * 4..(i + 1) * 4];
        if HEIF_BRANDS.iter().any(|b| b == brand) {
            return true;
        }
    }
    false
}

/// Whether the bytes start with the PNG signature.
pub fn is_png_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= PNG_MAGIC.len() && &bytes[..PNG_MAGIC.len()] == PNG_MAGIC
}

/// Whether the bytes start with the JPEG SOI marker.
pub fn is_jpeg_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= JPEG_MAGIC.len() && &bytes[..JPEG_MAGIC.len()] == JPEG_MAGIC
}

/// Whether the bytes look like an MP4/MOV-style container (and not a HEIF image).
pub fn is_mp4_bytes(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let tag: &[u8; 4] = match bytes[4..8].try_into() {
        Ok(tag) => tag,
        Err(_) => return false,
    };
    MP4_TOP_LEVEL_BOXES.contains(tag) && !is_heif_bytes(bytes)
}

fn is_webp_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP"
}

fn is_wav_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WAVE"
}

fn is_mkv_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= 5
        && u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) == EBML_HEADER_ID
}

fn is_zip_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && (bytes[0..4] == ZIP_LOCAL_MAGIC
            || bytes[0..4] == ZIP_EOCD_MAGIC
            || bytes[0..4] == ZIP_SPAN_MAGIC)
}

fn is_pdf_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= PDF_MAGIC.len() && bytes[..PDF_MAGIC.len()] == PDF_MAGIC
}

/// Header-level PE probe: `MZ`, a plausible `e_lfanew`, and the `PE\0\0`
/// signature it points at.
///
/// Deliberately weaker than [`crate::structure::adapters::pe`]'s full header parse (machine
/// type, section table, optional-header size): this answers "which format does
/// this look like", and the adapter still validates before writing anything.
fn is_pe_bytes(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return false;
    }
    let lfanew = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    if lfanew < 0x40 || lfanew + 4 > bytes.len() {
        return false;
    }
    &bytes[lfanew..lfanew + 4] == b"PE\0\0"
}

/// Classify a byte slice, or `None` when no carrier format matches.
///
/// Order matters: HEIF and MP4 both start with an ISO-BMFF box header, so HEIF
/// must be tested first; and the Annex-B probe must come last, because a
/// container payload can itself contain start codes.
pub fn sniff_bytes(bytes: &[u8]) -> Option<FileFormat> {
    if is_jpeg_bytes(bytes) {
        Some(FileFormat::Jpeg)
    } else if is_png_bytes(bytes) {
        Some(FileFormat::Png)
    } else if is_heif_bytes(bytes) {
        Some(FileFormat::Heif)
    } else if is_mp4_bytes(bytes) {
        Some(FileFormat::Mp4)
    } else if is_webp_bytes(bytes) {
        Some(FileFormat::Webp)
    } else if is_wav_bytes(bytes) {
        Some(FileFormat::Wav)
    } else if is_mkv_bytes(bytes) {
        Some(FileFormat::Mkv)
    } else if is_zip_bytes(bytes) {
        Some(FileFormat::Zip)
    } else if is_pdf_bytes(bytes) {
        Some(FileFormat::Pdf)
    } else if is_pe_bytes(bytes) {
        Some(FileFormat::Pe)
    } else if is_hevc_annexb(bytes) {
        Some(FileFormat::HevcAnnexB)
    } else {
        None
    }
}

/// Classify a seekable stream, restoring the caller's position.
///
/// Reads at most [`SNIFF_PREFIX_BYTES`] from the start. The position is
/// restored even when the read fails part-way, mirroring what every adapter's
/// `detect` used to do by hand.
pub fn sniff_stream<R>(reader: &mut R) -> std::io::Result<Option<FileFormat>>
where
    R: Read + Seek + ?Sized,
{
    let restore = reader.stream_position()?;
    let mut buf = Vec::with_capacity(SNIFF_PREFIX_BYTES);
    let outcome = (|| -> std::io::Result<Option<FileFormat>> {
        reader.seek(SeekFrom::Start(0))?;
        let mut chunk = vec![0u8; SNIFF_PREFIX_BYTES];
        let mut filled = 0usize;
        while filled < chunk.len() {
            let n = reader.read(&mut chunk[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        chunk.truncate(filled);
        buf = chunk;
        Ok(sniff_bytes(&buf))
    })();
    let _ = reader.seek(SeekFrom::Start(restore));
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ftyp(major: &[u8; 4], compat: &[[u8; 4]]) -> Vec<u8> {
        let size = 16 + 4 * compat.len() as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(b"ftyp");
        out.extend_from_slice(major);
        out.extend_from_slice(&0u32.to_be_bytes());
        for brand in compat {
            out.extend_from_slice(brand);
        }
        out
    }

    #[test]
    fn heif_brand_detection() {
        // Minimal ftyp box: size(4) + 'ftyp'(4) + major 'heic'(4) + minor 'mif1'(4).
        let mut heic = Vec::new();
        heic.extend_from_slice(&16u32.to_be_bytes());
        heic.extend_from_slice(b"ftyp");
        heic.extend_from_slice(b"heic");
        heic.extend_from_slice(b"mif1");
        assert!(is_heif_bytes(&heic));

        let mut avif = Vec::new();
        avif.extend_from_slice(&16u32.to_be_bytes());
        avif.extend_from_slice(b"ftyp");
        avif.extend_from_slice(b"avif");
        avif.extend_from_slice(b"mif1");
        assert!(is_heif_bytes(&avif));

        // A plain MP4 (isom/mp42) is not HEIF.
        let mut mp4 = Vec::new();
        mp4.extend_from_slice(&16u32.to_be_bytes());
        mp4.extend_from_slice(b"ftyp");
        mp4.extend_from_slice(b"isom");
        mp4.extend_from_slice(b"mp42");
        assert!(!is_heif_bytes(&mp4));
    }

    #[test]
    fn png_and_jpeg_magic() {
        assert!(is_png_bytes(b"\x89PNG\r\n\x1a\n\x00\x00"));
        assert!(!is_png_bytes(b"\x89PNG\r\n\x1a"));
        assert!(is_jpeg_bytes(b"\xFF\xD8\xFF\xE0"));
        assert!(!is_jpeg_bytes(b"\xFF\xD9"));
    }

    #[test]
    fn heif_wins_over_mp4_for_image_brands() {
        let heic = ftyp(b"heic", &[*b"mif1"]);
        assert_eq!(sniff_bytes(&heic), Some(FileFormat::Heif));
        let mp4 = ftyp(b"isom", &[*b"mp42", *b"isom"]);
        assert_eq!(sniff_bytes(&mp4), Some(FileFormat::Mp4));
    }

    #[test]
    fn mp4_accepts_fragmented_and_filler_leading_boxes() {
        // ISO/IEC 14496-12 allows a fragmented stream whose first box is
        // `styp`/`moof`/`sidx`, and filler boxes before the movie box.
        for tag in [b"styp", b"moof", b"sidx", b"free", b"skip", b"uuid"] {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&8u32.to_be_bytes());
            bytes.extend_from_slice(tag);
            assert_eq!(
                sniff_bytes(&bytes),
                Some(FileFormat::Mp4),
                "leading box {}",
                String::from_utf8_lossy(tag)
            );
        }
    }

    #[test]
    fn riff_split_by_form_type() {
        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&16u32.to_le_bytes());
        webp.extend_from_slice(b"WEBPVP8 ");
        assert_eq!(sniff_bytes(&webp), Some(FileFormat::Webp));

        let mut wav = b"RIFF".to_vec();
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        assert_eq!(sniff_bytes(&wav), Some(FileFormat::Wav));
    }

    #[test]
    fn annexb_is_last_and_needs_a_known_nal_type() {
        // A VPS NAL (type 32) after a 4-byte start code.
        let mut vps = vec![0u8, 0, 0, 1];
        vps.push(32 << 1);
        vps.push(0x01);
        vps.push(0x00);
        assert_eq!(sniff_bytes(&vps), Some(FileFormat::HevcAnnexB));

        // A reserved NAL type (10) is not a carrier.
        let mut reserved = vec![0u8, 0, 0, 1];
        reserved.push(10 << 1);
        reserved.push(0x01);
        reserved.push(0x00);
        assert_eq!(sniff_bytes(&reserved), None);
    }

    #[test]
    fn pe_probe_requires_mz_and_pe_signature() {
        let mut exe = vec![0u8; 0x80];
        exe[0..2].copy_from_slice(b"MZ");
        exe[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        exe[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert_eq!(sniff_bytes(&exe), Some(FileFormat::Pe));

        // MZ without a PE signature is a DOS binary, not a PE carrier.
        let mut dos = vec![0u8; 0x80];
        dos[0..2].copy_from_slice(b"MZ");
        dos[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        assert_eq!(sniff_bytes(&dos), None);
    }

    #[test]
    fn stream_sniffing_restores_position() {
        use std::io::Cursor;
        let png = [PNG_MAGIC.as_slice(), &[0u8; 16]].concat();
        let mut cur = Cursor::new(png);
        cur.set_position(3);
        assert_eq!(sniff_stream(&mut cur).unwrap(), Some(FileFormat::Png));
        assert_eq!(cur.position(), 3);
    }
}
