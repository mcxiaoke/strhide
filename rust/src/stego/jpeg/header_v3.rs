//! V3 superblock (44 bytes / 352 bits) and the extension TLV area.
//!
//! ```text
//! off  size  field
//! 0    1     version_major        incompatible changes only (1)
//! 1    1     version_minor        optional extensions only (0)
//! 2    2     flags                reserved, must be 0
//! 4    16    salt                 HKDF salt of the payload keys (not the KDF salt)
//! 20   12    nonce                AEAD nonce
//! 32   4     envelope_len         BE, bits 0..26; bits 26..32 must be 0
//! 36   2     suite_id             BE, must equal the suite that located this header
//! 38   1     codec_id             0 = ternary STC
//! 39   1     h                    STC constraint height 4..=10
//! 40   1     u                    body group size 1..=64
//! 41   1     components_mask      bit0 = Y; others reserved
//! 42   2     ext_bytes            extension-area byte count, 0 = none
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
//! struct. [`FIELD_LAYOUT`] is the machine-readable copy of the table above and
//! is asserted against the encoder in the tests.

use crate::errors::StrHideError;
use crate::stego::envelope::MIN_ENVELOPE_LEN;
use crate::stego::format::FormatProfile;

/// Encoded superblock size in bytes.
pub const SUPERBLOCK_BYTES: usize = 44;

/// Largest envelope the 26-bit length field can express (64 MiB).
pub const ENVELOPE_LEN_MAX: u32 = (1 << 26) - 1;

/// Codec id: ternary syndrome-trellis codes.
pub const CODEC_TERNARY_STC: u8 = 0;
/// Codec id: reserved for Hamming matrix embedding.
pub const CODEC_HAMMING: u8 = 1;

/// Byte offsets and widths of every superblock field, in wire order.
///
/// "Documentation as a test": the unit tests encode a `Superblock`, read each
/// field back out of the raw bytes at these offsets, and compare.
pub const FIELD_LAYOUT: &[(&str, usize, usize)] = &[
    ("version_major", 0, 1),
    ("version_minor", 1, 1),
    ("flags", 2, 2),
    ("salt", 4, 16),
    ("nonce", 20, 12),
    ("envelope_len", 32, 4),
    ("suite_id", 36, 2),
    ("codec_id", 38, 1),
    ("h", 39, 1),
    ("u", 40, 1),
    ("components_mask", 41, 1),
    ("ext_bytes", 42, 2),
];

/// Bit 0 of `components_mask`: the luminance component carries the payload.
pub const COMPONENT_Y: u8 = 0x01;

/// Fixed-size V3 header that precedes the payload ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Superblock {
    /// Format major version.
    pub version_major: u8,
    /// Format minor version (forward-compatible: a newer minor is accepted).
    pub version_minor: u8,
    /// Reserved bits; must be zero.
    pub flags: u16,
    /// HKDF salt for the payload keys.
    pub salt: [u8; 16],
    /// AEAD nonce.
    pub nonce: [u8; 12],
    /// Logical envelope length: 28-byte legacy salt/nonce header + ciphertext.
    pub envelope_len: u32,
    /// Cipher suite id; indexes the profile's suite table.
    pub suite_id: u16,
    /// Matrix-coding id.
    pub codec_id: u8,
    /// STC constraint height.
    pub h: u8,
    /// STC group size of the body trellis.
    pub u: u8,
    /// Components carrying payload bits.
    pub components_mask: u8,
    /// Extension-area size in bytes.
    pub ext_bytes: u16,
}

impl Superblock {
    /// Serialize to the 44-byte wire form.
    pub fn encode(&self) -> [u8; SUPERBLOCK_BYTES] {
        let mut out = [0u8; SUPERBLOCK_BYTES];
        out[0] = self.version_major;
        out[1] = self.version_minor;
        out[2..4].copy_from_slice(&self.flags.to_be_bytes());
        out[4..20].copy_from_slice(&self.salt);
        out[20..32].copy_from_slice(&self.nonce);
        out[32..36].copy_from_slice(&self.envelope_len.to_be_bytes());
        out[36..38].copy_from_slice(&self.suite_id.to_be_bytes());
        out[38] = self.codec_id;
        out[39] = self.h;
        out[40] = self.u;
        out[41] = self.components_mask;
        out[42..44].copy_from_slice(&self.ext_bytes.to_be_bytes());
        out
    }

    /// Parse the 44-byte wire form, enforcing every structural invariant that
    /// does not depend on the profile.
    ///
    /// Version and suite agreement are checked by [`Self::validate_against`],
    /// because the trial enumeration has to know which suite it just tried.
    pub fn decode(bytes: &[u8; SUPERBLOCK_BYTES]) -> Result<Self, StrHideError> {
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        let envelope_len = u32::from_be_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
        let sb = Self {
            version_major: bytes[0],
            version_minor: bytes[1],
            flags,
            salt: bytes[4..20].try_into().expect("salt slice"),
            nonce: bytes[20..32].try_into().expect("nonce slice"),
            envelope_len,
            suite_id: u16::from_be_bytes([bytes[36], bytes[37]]),
            codec_id: bytes[38],
            h: bytes[39],
            u: bytes[40],
            components_mask: bytes[41],
            ext_bytes: u16::from_be_bytes([bytes[42], bytes[43]]),
        };
        sb.check_reserved()?;
        Ok(sb)
    }

    /// Field checks that must hold for any version: reserved bits zero, known
    /// codec, in-range trellis parameters, plausible envelope length.
    fn check_reserved(&self) -> Result<(), StrHideError> {
        if self.flags != 0 {
            return Err(StrHideError::CorruptedData(format!(
                "Superblock flags {:#06x} are reserved and must be zero",
                self.flags
            )));
        }
        if self.envelope_len & !ENVELOPE_LEN_MAX != 0 {
            return Err(StrHideError::CorruptedData(
                "Superblock envelope_len has non-zero reserved bits".into(),
            ));
        }
        if (self.envelope_len as usize) < MIN_ENVELOPE_LEN {
            return Err(StrHideError::CorruptedData(format!(
                "Superblock envelope_len {} is below the minimum {MIN_ENVELOPE_LEN}",
                self.envelope_len
            )));
        }
        if self.codec_id != CODEC_TERNARY_STC && self.codec_id != CODEC_HAMMING {
            return Err(StrHideError::UnsupportedVersion(format!(
                "Unknown matrix-coding id {} in superblock",
                self.codec_id
            )));
        }
        if self.codec_id == CODEC_TERNARY_STC {
            if !(4..=10).contains(&self.h) {
                return Err(StrHideError::CorruptedData(format!(
                    "Superblock STC height {} is outside 4..=10",
                    self.h
                )));
            }
            if !(1..=64).contains(&self.u) {
                return Err(StrHideError::CorruptedData(format!(
                    "Superblock STC group size {} is outside 1..=64",
                    self.u
                )));
            }
        }
        if self.components_mask & COMPONENT_Y == 0 {
            return Err(StrHideError::CorruptedData(
                "Superblock declares no luminance payload component".into(),
            ));
        }
        Ok(())
    }

    /// Version / suite checks that need the profile and the suite being tried.
    pub fn validate_against(
        &self,
        fmt: &FormatProfile,
        tried_suite: u16,
    ) -> Result<(), StrHideError> {
        if self.version_major != fmt.format_major {
            return Err(StrHideError::UnsupportedVersion(format!(
                "Superblock major version {} is not supported by this build (expected {})",
                self.version_major, fmt.format_major
            )));
        }
        if self.suite_id != tried_suite {
            return Err(StrHideError::CorruptedData(format!(
                "Superblock suite {} does not match the suite that located it ({tried_suite})",
                self.suite_id
            )));
        }
        Ok(())
    }

    /// Ciphertext length carried by the body: envelope length minus the legacy
    /// 28-byte salt/nonce prefix, which now lives in the superblock.
    pub fn ciphertext_len(&self) -> usize {
        self.envelope_len as usize - crate::stego::envelope::HEADER_OVERHEAD
    }
}

// ---------------------------------------------------------------------------
// Extension area
// ---------------------------------------------------------------------------

/// Bit 7 of a TLV type: unknown types with it set are fatal.
pub const TLV_CRITICAL: u8 = 0x80;

/// Largest value a single TLV can carry.
pub const TLV_MAX_VALUE: usize = 255;

/// Type 0 is reserved for zero padding of the unused extension tail.
pub const TLV_TYPE_PADDING: u8 = 0;

/// One extension record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Tlv {
    /// Type id; bit 7 = critical.
    pub type_id: u8,
    /// Value bytes (0..=255).
    pub value: Vec<u8>,
}

impl Tlv {
    /// Whether an unknown reader must refuse the carrier.
    pub fn is_critical(&self) -> bool {
        self.type_id & TLV_CRITICAL != 0
    }
}

/// Encode TLVs back to back into the extension area.
///
/// The area length is exactly the sum of the records: padding is legal on the
/// wire but never produced here.
pub fn encode_extension(tlvs: &[Tlv]) -> Result<Vec<u8>, StrHideError> {
    let mut out = Vec::new();
    for tlv in tlvs {
        if tlv.type_id == TLV_TYPE_PADDING {
            return Err(StrHideError::General(
                "TLV type 0 is reserved for extension-area padding".into(),
            ));
        }
        if tlv.value.len() > TLV_MAX_VALUE {
            return Err(StrHideError::General(format!(
                "TLV type {:#04x} carries {} bytes, the maximum is {TLV_MAX_VALUE}",
                tlv.type_id,
                tlv.value.len()
            )));
        }
        out.push(tlv.type_id);
        out.push(tlv.value.len() as u8);
        out.extend_from_slice(&tlv.value);
    }
    Ok(out)
}

/// Parse the extension area into `(type, value)` records.
///
/// A `type` byte of 0 starts the padding tail: every remaining byte must then be
/// zero, so a decoder that does not know a future field cannot silently skip
/// over it. Truncated or over-long records are `CorruptedData`.
pub fn parse_extension(area: &[u8]) -> Result<Vec<(u8, &[u8])>, StrHideError> {
    let mut records = Vec::new();
    let mut pos = 0usize;
    while pos < area.len() {
        let type_id = area[pos];
        if type_id == TLV_TYPE_PADDING {
            if area[pos..].iter().any(|&b| b != 0) {
                return Err(StrHideError::CorruptedData(
                    "Extension area has non-zero bytes after the padding marker".into(),
                ));
            }
            break;
        }
        if pos + 2 > area.len() {
            return Err(StrHideError::CorruptedData(
                "Extension area ends inside a TLV header".into(),
            ));
        }
        let len = area[pos + 1] as usize;
        let end = pos + 2 + len;
        if end > area.len() {
            return Err(StrHideError::CorruptedData(format!(
                "TLV type {type_id:#04x} claims {len} bytes past the end of the extension area"
            )));
        }
        records.push((type_id, &area[pos + 2..end]));
        pos = end;
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::format::DEFAULT_FORMAT;

    fn sample() -> Superblock {
        Superblock {
            version_major: 1,
            version_minor: 0,
            flags: 0,
            salt: std::array::from_fn(|i| i as u8),
            nonce: std::array::from_fn(|i| 0xA0 + i as u8),
            envelope_len: 1234,
            suite_id: 1,
            codec_id: CODEC_TERNARY_STC,
            h: 8,
            u: 24,
            components_mask: COMPONENT_Y,
            ext_bytes: 5,
        }
    }

    #[test]
    fn every_field_round_trips_at_its_frozen_offset() {
        let sb = sample();
        let bytes = sb.encode();
        assert_eq!(bytes.len(), SUPERBLOCK_BYTES);
        // Documentation-as-test: read each field straight out of the bytes.
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[1], 0);
        assert_eq!(&bytes[2..4], &[0, 0]);
        assert_eq!(&bytes[4..20], &sb.salt);
        assert_eq!(&bytes[20..32], &sb.nonce);
        assert_eq!(u32::from_be_bytes(bytes[32..36].try_into().unwrap()), 1234);
        assert_eq!(u16::from_be_bytes(bytes[36..38].try_into().unwrap()), 1);
        assert_eq!(bytes[38], CODEC_TERNARY_STC);
        assert_eq!(bytes[39], 8);
        assert_eq!(bytes[40], 24);
        assert_eq!(bytes[41], COMPONENT_Y);
        assert_eq!(u16::from_be_bytes(bytes[42..44].try_into().unwrap()), 5);

        assert_eq!(Superblock::decode(&bytes).unwrap(), sb);
        // The layout table must cover the whole block, without gaps.
        let mut cursor = 0;
        for (name, off, size) in FIELD_LAYOUT {
            assert_eq!(*off, cursor, "field {name} is not contiguous");
            cursor += size;
        }
        assert_eq!(cursor, SUPERBLOCK_BYTES);
    }

    #[test]
    fn reserved_and_out_of_range_fields_are_rejected() {
        let mut bytes = sample().encode();
        bytes[3] = 1; // flags
        assert!(Superblock::decode(&bytes).is_err());

        let mut bytes = sample().encode();
        bytes[32] = 0x04; // envelope_len bit 26
        assert!(Superblock::decode(&bytes).is_err());

        let mut bytes = sample().encode();
        bytes[32..36].copy_from_slice(&(MIN_ENVELOPE_LEN as u32 - 1).to_be_bytes());
        assert!(Superblock::decode(&bytes).is_err());

        let mut bytes = sample().encode();
        bytes[38] = 9; // unknown codec
        assert!(Superblock::decode(&bytes).is_err());

        let mut bytes = sample().encode();
        bytes[39] = 3; // h out of range
        assert!(Superblock::decode(&bytes).is_err());

        let mut bytes = sample().encode();
        bytes[39] = 11;
        assert!(Superblock::decode(&bytes).is_err());

        let mut bytes = sample().encode();
        bytes[40] = 0; // u out of range
        assert!(Superblock::decode(&bytes).is_err());

        let mut bytes = sample().encode();
        bytes[41] = 0; // no Y component
        assert!(Superblock::decode(&bytes).is_err());
    }

    #[test]
    fn version_and_suite_are_checked_against_the_trial() {
        let sb = sample();
        assert!(sb.validate_against(&DEFAULT_FORMAT, 1).is_ok());
        assert!(matches!(
            sb.validate_against(&DEFAULT_FORMAT, 2),
            Err(StrHideError::CorruptedData(_))
        ));

        let mut other_major = sb;
        other_major.version_major = 2;
        assert!(matches!(
            other_major.validate_against(&DEFAULT_FORMAT, 1),
            Err(StrHideError::UnsupportedVersion(_))
        ));

        // A newer minor is forward-compatible.
        let mut newer_minor = sb;
        newer_minor.version_minor = 7;
        assert!(newer_minor.validate_against(&DEFAULT_FORMAT, 1).is_ok());
    }

    #[test]
    fn envelope_len_accounts_for_the_legacy_prefix() {
        let mut sb = sample();
        sb.envelope_len = MIN_ENVELOPE_LEN as u32;
        assert_eq!(sb.ciphertext_len(), MIN_ENVELOPE_LEN - 28);
        assert_eq!(sb.ciphertext_len() + 28, MIN_ENVELOPE_LEN);
    }

    #[test]
    fn tlv_roundtrip_and_skipping() {
        let tlvs = vec![
            Tlv {
                type_id: 0x81,
                value: vec![1, 2, 3],
            },
            Tlv {
                type_id: 0x02,
                value: Vec::new(),
            },
        ];
        let area = encode_extension(&tlvs).unwrap();
        assert_eq!(area, vec![0x81, 3, 1, 2, 3, 0x02, 0]);
        let parsed = parse_extension(&area).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], (0x81, &[1u8, 2, 3][..]));
        assert!(
            Tlv {
                type_id: 0x81,
                value: vec![]
            }
            .is_critical()
        );
        assert!(!tlvs[1].is_critical());
    }

    #[test]
    fn tlv_padding_must_be_zero() {
        let area = [0x02, 1, 9, 0, 0, 0];
        assert_eq!(parse_extension(&area).unwrap().len(), 1);
        let bad = [0x02, 1, 9, 0, 7, 0];
        assert!(matches!(
            parse_extension(&bad),
            Err(StrHideError::CorruptedData(_))
        ));
    }

    #[test]
    fn tlv_truncation_is_rejected() {
        assert!(matches!(
            parse_extension(&[0x02, 5, 1]),
            Err(StrHideError::CorruptedData(_))
        ));
        assert!(matches!(
            parse_extension(&[0x02]),
            Err(StrHideError::CorruptedData(_))
        ));
    }

    #[test]
    fn tlv_encode_rejects_oversize_and_padding_type() {
        let big = Tlv {
            type_id: 1,
            value: vec![0; 256],
        };
        assert!(encode_extension(&[big]).is_err());
        let padding = Tlv {
            type_id: 0,
            value: vec![1],
        };
        assert!(encode_extension(&[padding]).is_err());
    }
}
