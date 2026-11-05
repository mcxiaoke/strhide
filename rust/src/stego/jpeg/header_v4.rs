//! JPEG content-domain V4 superblock (44 bytes / 352 bits).
//!
//! ```text
//! off  size  field
//! 0    1     version               (major << 4) | minor, major must be 4
//! 1    1     flags                 EXT_PRESENT / EXT_CRITICAL
//! 2    2     suite_id              AEAD suite id
//! 4    16    salt                  L3 HKDF salt
//! 20   12    nonce                 AEAD nonce
//! 32   4     body_len              ciphertext length including the tag
//! 36   1     codec_id              0 = ternary STC
//! 37   1     stc_h                 STC constraint height 4..=10
//! 38   1     stc_u                 body group size 1..=64
//! 39   1     ext_len               extension TLV byte count, 0 = none
//! 40   4     header_crc32          CRC32-IEEE over bytes[0..40]
//! ```
//!
//! Every field is covered by the AEAD's associated data (the whole 44 bytes), so
//! a flipped bit anywhere makes decryption fail instead of producing a
//! plausible-but-wrong decode.
//!
//! # Layout is frozen
//!
//! After release the offsets and their meaning never change. New fields go into
//! the extension area as TLVs; only a `format_major` bump may reshape this
//! struct.

use crate::errors::StrHideError;
use crate::stego::header::HEADER_LEN_MAX;

/// Encoded superblock size in bytes.
pub use crate::stego::format::JPEG_SUPERBLOCK_BYTES as SUPERBLOCK_BYTES;

/// Codec id: ternary syndrome-trellis codes.
pub const CODEC_TERNARY_STC: u8 = 0;

// ---------------------------------------------------------------------------
// Content-domain V4 superblock
// ---------------------------------------------------------------------------

/// CRC scope of the 44-byte JPEG superblock.
const V4_CRC_SPAN: usize = 40;

/// 44-byte content header of a JPEG carrier.
///
/// `format_id = 4` and `components_mask = Y` are implied by the carrier and
/// bound through the AAD prefix; they are not stored.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JpegSuperblockV4 {
    /// `(major << 4) | minor`.
    pub version: u8,
    /// `EXT_PRESENT` / `EXT_CRITICAL`.
    pub flags: u8,
    /// AEAD suite id.
    pub suite_id: u16,
    /// L3 HKDF salt.
    pub salt: [u8; 16],
    /// AEAD nonce.
    pub nonce: [u8; 12],
    /// Ciphertext length including the tag.
    pub body_len: u32,
    /// Ternary STC is the only V4 value.
    pub codec_id: u8,
    /// Trellis height (4..=10).
    pub stc_h: u8,
    /// Trellis width (1..=64).
    pub stc_u: u8,
    /// Extension TLV byte count (0..=255).
    pub ext_len: u8,
}

impl JpegSuperblockV4 {
    /// Serialize the superblock, including CRC32-IEEE over `bytes[0..40]`.
    pub fn encode(&self) -> [u8; SUPERBLOCK_BYTES] {
        let mut out = [0u8; SUPERBLOCK_BYTES];
        out[0] = self.version;
        out[1] = self.flags;
        out[2..4].copy_from_slice(&self.suite_id.to_be_bytes());
        out[4..20].copy_from_slice(&self.salt);
        out[20..32].copy_from_slice(&self.nonce);
        out[32..36].copy_from_slice(&self.body_len.to_be_bytes());
        out[36] = self.codec_id;
        out[37] = self.stc_h;
        out[38] = self.stc_u;
        out[39] = self.ext_len;
        let crc = crc32fast::hash(&out[..V4_CRC_SPAN]);
        out[V4_CRC_SPAN..].copy_from_slice(&crc.to_be_bytes());
        out
    }

    /// Parse and validate a JPEG superblock.
    pub fn decode(bytes: &[u8; SUPERBLOCK_BYTES]) -> Result<Self, StrHideError> {
        use crate::stego::header::{FLAG_EXT_CRITICAL, FLAG_EXT_PRESENT, MAX_EXT_BYTES};

        let version = bytes[0];
        let flags = bytes[1];
        let suite_id = u16::from_be_bytes(bytes[2..4].try_into().expect("2-byte suite"));
        let salt = bytes[4..20].try_into().expect("16-byte salt slice");
        let nonce = bytes[20..32].try_into().expect("12-byte nonce slice");
        let body_len = u32::from_be_bytes(bytes[32..36].try_into().expect("4-byte body_len"));
        let codec_id = bytes[36];
        let stc_h = bytes[37];
        let stc_u = bytes[38];
        let ext_len = bytes[39];

        let (major, minor) = (version >> 4, version & 0x0F);
        if major != 4 {
            return Err(StrHideError::UnsupportedVersion(format!(
                "JPEG content envelope major version {major}.{minor} is not supported"
            )));
        }
        if flags & !(FLAG_EXT_PRESENT | FLAG_EXT_CRITICAL) != 0 {
            return Err(StrHideError::CorruptedData(format!(
                "JPEG content envelope flags {flags:#04x} use reserved bits"
            )));
        }
        if flags & FLAG_EXT_PRESENT != (ext_len > 0) as u8 {
            return Err(StrHideError::CorruptedData(
                "JPEG EXT_PRESENT does not match ext_len".into(),
            ));
        }
        if crate::crypto::CipherSuiteId::from_u16(suite_id).is_none() {
            return Err(StrHideError::UnsupportedVersion(format!(
                "Unknown JPEG content cipher suite id {suite_id}"
            )));
        }
        let body_overhead = crate::stego::envelope::BODY_OVERHEAD as u32;
        if body_len < body_overhead || body_len > HEADER_LEN_MAX {
            return Err(StrHideError::CorruptedData(format!(
                "JPEG content body_len {body_len} is outside {body_overhead}..={HEADER_LEN_MAX}"
            )));
        }
        if codec_id != CODEC_TERNARY_STC {
            return Err(StrHideError::CorruptedData(format!(
                "JPEG content codec_id {codec_id} must be {CODEC_TERNARY_STC}"
            )));
        }
        if !(4..=10).contains(&stc_h) || !(1..=64).contains(&stc_u) {
            return Err(StrHideError::CorruptedData(format!(
                "JPEG content STC parameters h={stc_h} u={stc_u} are out of range"
            )));
        }
        if ext_len as usize > MAX_EXT_BYTES {
            return Err(StrHideError::CorruptedData(format!(
                "JPEG content ext_len {ext_len} is above {MAX_EXT_BYTES}"
            )));
        }

        let expected_crc = u32::from_be_bytes(bytes[40..44].try_into().expect("4-byte crc"));
        let actual_crc = crc32fast::hash(&bytes[..V4_CRC_SPAN]);
        if actual_crc != expected_crc {
            return Err(StrHideError::CorruptedData(format!(
                "JPEG content header CRC mismatch: stored {expected_crc:08x}, computed {actual_crc:08x}"
            )));
        }

        Ok(Self {
            version,
            flags,
            suite_id,
            salt,
            nonce,
            body_len,
            codec_id,
            stc_h,
            stc_u,
            ext_len,
        })
    }

    /// Whether the extension area is present.
    pub fn ext_present(&self) -> bool {
        self.flags & crate::stego::header::FLAG_EXT_PRESENT != 0
    }

    /// Whether at least one extension TLV is critical.
    pub fn ext_critical(&self) -> bool {
        self.flags & crate::stego::header::FLAG_EXT_CRITICAL != 0
    }
}

#[cfg(test)]
mod v4_superblock_tests {
    use super::*;

    // Frozen in docs/stego_content_envelope_v4_golden_vectors_20261103.md.
    const GOLDEN: &str = concat!(
        "40010001000102030405060708090a0b",
        "0c0d0e0f202122232425262728292a2b",
        "0000012c000818044d475109",
    );

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2, "hex length");
        let mut out = [0u8; N];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        out
    }

    #[test]
    fn golden_superblock_round_trips_byte_for_byte() {
        let raw = hex::<44>(GOLDEN);
        let header = JpegSuperblockV4::decode(&raw).unwrap();
        assert_eq!(
            header.version,
            crate::stego::header::CONTENT_ENVELOPE_VERSION
        );
        assert_eq!(header.suite_id, 1);
        assert_eq!(header.body_len, 300);
        assert_eq!(header.codec_id, CODEC_TERNARY_STC);
        assert_eq!((header.stc_h, header.stc_u), (8, 24));
        assert_eq!(header.ext_len, 4);
        assert!(header.ext_present());
        assert!(!header.ext_critical());
        assert_eq!(header.encode(), raw);
    }

    #[test]
    fn crc_and_field_ranges_are_enforced() {
        let mut raw = hex::<44>(GOLDEN);
        raw[4] ^= 0x01;
        let err = JpegSuperblockV4::decode(&raw).expect_err("flip must fail CRC");
        assert!(matches!(err, StrHideError::CorruptedData(_)));

        let mut header = JpegSuperblockV4::decode(&hex::<44>(GOLDEN)).unwrap();
        header.version = 0x30;
        let err = JpegSuperblockV4::decode(&header.encode()).expect_err("v3 must fail");
        assert!(matches!(err, StrHideError::UnsupportedVersion(_)));

        let mut header = JpegSuperblockV4::decode(&hex::<44>(GOLDEN)).unwrap();
        header.flags = 0x04;
        assert!(JpegSuperblockV4::decode(&header.encode()).is_err());

        let mut header = JpegSuperblockV4::decode(&hex::<44>(GOLDEN)).unwrap();
        header.ext_len = 0;
        let err = JpegSuperblockV4::decode(&header.encode()).expect_err("EXT_PRESENT mismatch");
        assert!(matches!(err, StrHideError::CorruptedData(_)));

        let mut header = JpegSuperblockV4::decode(&hex::<44>(GOLDEN)).unwrap();
        header.suite_id = 3;
        let err = JpegSuperblockV4::decode(&header.encode()).expect_err("unknown suite");
        assert!(matches!(err, StrHideError::UnsupportedVersion(_)));

        let mut header = JpegSuperblockV4::decode(&hex::<44>(GOLDEN)).unwrap();
        header.codec_id = 1;
        assert!(JpegSuperblockV4::decode(&header.encode()).is_err());

        let mut header = JpegSuperblockV4::decode(&hex::<44>(GOLDEN)).unwrap();
        header.stc_u = 0;
        assert!(JpegSuperblockV4::decode(&header.encode()).is_err());

        let mut header = JpegSuperblockV4::decode(&hex::<44>(GOLDEN)).unwrap();
        header.stc_h = 3;
        assert!(JpegSuperblockV4::decode(&header.encode()).is_err());
    }
}
