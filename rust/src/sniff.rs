//! Cross-feature carrier sniffing helpers.
//!
//! These byte-level format probes are needed by both the structure-domain
//! adapters (behind the `engine` feature) and the content-domain stego
//! engines (behind the `stego` feature), and either feature may be enabled
//! without the other, so the shared probes live here ungated. Keeping one
//! implementation avoids the classic drift where two brand tables disagree
//! about what a HEIF file is.

/// ISO-BMFF `ftyp` brands that identify an HEIF/HEIC (or AVIF) image file.
pub const HEIF_BRANDS: &[[u8; 4]] = &[
    *b"heic", *b"heix", *b"hevc", *b"hevx", *b"mif1", *b"msf1", *b"heim", *b"heis", *b"avif",
    *b"avis",
];

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

/// PNG magic (8-byte signature).
pub const PNG_MAGIC: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

/// JPEG SOI marker (first two bytes of a JPEG file).
pub const JPEG_MAGIC: &[u8; 2] = b"\xFF\xD8";

/// Whether the bytes start with the PNG signature.
pub fn is_png_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= PNG_MAGIC.len() && &bytes[..PNG_MAGIC.len()] == PNG_MAGIC
}

/// Whether the bytes start with the JPEG SOI marker.
pub fn is_jpeg_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= JPEG_MAGIC.len() && &bytes[..JPEG_MAGIC.len()] == JPEG_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
