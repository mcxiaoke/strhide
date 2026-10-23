//! The final 4-byte word of the 32-byte content-steganography header.
//!
//! Both image engines (spatial/PNG and DCT/JPEG) start their payload with the
//! same 32 bytes:
//!
//! ```text
//! [ 16B salt ][ 12B nonce ][ 4B flags + length ]
//! ```
//!
//! The word used to be the bare envelope length, and an envelope is capped at
//! 64 MiB = 2^26 (see [`HEADER_LEN_MAX`]), so bits 26..32 are always zero for a
//! real envelope — six spare bits. They now carry the matrix-coding parameters:
//!
//! ```text
//! bit 26..28  codec id: 0 = Hamming, 1..=3 = STC with group size u = id
//! bit 28..32  STC constraint height h (0 when unused)
//! bit  0..26  envelope length (unchanged)
//! ```
//!
//! The header stays exactly 32 bytes and no format-version bump is needed: a
//! carrier written before this change has zeros in those bits, which decodes as
//! `Hamming` / no `h` — the behaviour it was written with. Encoding `u` in the
//! codec id keeps the layout intact while making the group size self-describing,
//! which matters because a mismatched `u` shifts every syndrome row.

use crate::errors::StrHideError;
use crate::stego::coding::MAX_STC_U;
use crate::stego::params::StegoCodec;

/// Bits of the header word that hold the envelope length.
pub const HEADER_LEN_BITS: u32 = 26;
/// Mask of the length field inside the header word.
pub const HEADER_LEN_MASK: u32 = (1 << HEADER_LEN_BITS) - 1;
/// Largest envelope the 26-bit length field can express.
pub const HEADER_LEN_MAX: u32 = HEADER_LEN_MASK;

const HEADER_CODEC_SHIFT: u32 = HEADER_LEN_BITS;
const HEADER_CODEC_BITS: u32 = 2;
const HEADER_STC_H_SHIFT: u32 = 28;
const HEADER_STC_H_BITS: u32 = 4;

/// Stable identifier for `(codec, u)` inside the two codec bits.
///
/// `Hamming` is 0 and `STC` starts at 1, so a carrier written before `u`
/// existed (`codec == 1`, implicit `u == 1`) keeps decoding identically.
pub fn codec_header_id(codec: StegoCodec, stc_u: u8) -> u32 {
    match codec {
        StegoCodec::Hamming => 0,
        StegoCodec::Stc | StegoCodec::Auto => 1 + (stc_u.clamp(1, MAX_STC_U) as u32 - 1),
    }
}

/// Inverse of [`codec_header_id`].
///
/// Unknown ids are an error rather than a silent fallback: the extract path
/// folds every failure into the generic "no payload here" message, so a wrong
/// guess can only ever fail downstream anyway.
pub fn codec_from_header_id(id: u32) -> Result<(StegoCodec, u8), StrHideError> {
    match id {
        0 => Ok((StegoCodec::Hamming, 1)),
        id if id <= MAX_STC_U as u32 => Ok((StegoCodec::Stc, id as u8)),
        other => Err(StrHideError::CorruptedData(format!(
            "Unknown matrix-coding identifier {other} in envelope header"
        ))),
    }
}

/// Pack `(length, codec, h, u)` into the header word.
pub fn encode_header_word(len: u32, codec: StegoCodec, stc_h: u8, stc_u: u8) -> u32 {
    debug_assert_eq!(len & !HEADER_LEN_MASK, 0, "envelope length exceeds 26 bits");
    // Canonical form: the `h` field is only meaningful for STC, so a Hamming
    // carrier always writes zero there. That keeps the header word a pure
    // function of what actually matters.
    let stc_h = if stc_h == HEADER_V2_ESCAPE_H {
        HEADER_V2_ESCAPE_H
    } else {
        match codec {
            StegoCodec::Stc | StegoCodec::Auto => stc_h,
            StegoCodec::Hamming => 0,
        }
    };
    (len & HEADER_LEN_MASK)
        | ((codec_header_id(codec, stc_u) & ((1 << HEADER_CODEC_BITS) - 1)) << HEADER_CODEC_SHIFT)
        | (((stc_h as u32) & ((1 << HEADER_STC_H_BITS) - 1)) << HEADER_STC_H_SHIFT)
}

/// Split a header word into `(envelope length, codec id, stc h)`.
///
/// The codec id is returned raw: validation through [`codec_from_header_id`] is
/// the caller's job, because the extract path must fold an unknown id into the
/// generic "no payload here" error instead of reporting it.
pub fn decode_header_word(word: u32) -> (u32, u32, u8) {
    let len = word & HEADER_LEN_MASK;
    let codec_id = (word >> HEADER_CODEC_SHIFT) & ((1 << HEADER_CODEC_BITS) - 1);
    let stc_h = ((word >> HEADER_STC_H_SHIFT) & ((1 << HEADER_STC_H_BITS) - 1)) as u8;
    (len, codec_id, stc_h)
}

/// Special escape value for `stc_h` in word1 signalling a v2 envelope header.
/// Legal STC constraint height is 4..=10, so 15 is unambiguously distinguishable.
pub const HEADER_V2_ESCAPE_H: u8 = 15;

/// Size of the v2 feature word block in bytes.
pub const FEATURE_WORD_BYTES: usize = 32;

/// Number of candidate slots carrying the 32-byte feature word (1 bit per slot).
pub const FEATURE_WORD_SLOTS: usize = FEATURE_WORD_BYTES * 8; // 256 slots

/// Total slots occupied by v2 header (256 basic header slots + 256 feature word slots).
pub const V2_TOTAL_HEADER_SLOTS: usize = 256 + FEATURE_WORD_SLOTS; // 512 slots

/// Self-describing feature descriptor stored in the 32-byte feature word (v2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureWord {
    pub version: u8,
    pub codec: StegoCodec,
    pub u: u8,
    pub h: u8,
    pub channel_mode: u8,
    pub class_rule: u8,
    pub kdf_id: u8,
    pub eligible_min: u8,
    pub eligible_max: u8,
    pub exclusion_permille: u16,
    /// Wire id of the spatial cost model that wrote this carrier.
    ///
    /// Stored so extraction does not need the algorithm out of band: the header
    /// is placed from a cost-free layout, so it can be read before the extractor
    /// knows which model produced the body. See
    /// [`crate::stego::registry::CostModelRegistry::spatial_name_from_wire_id`].
    ///
    /// Lives in `bytes[8]`, which v2 reserved as zero, so the packed `low64`
    /// layout is unchanged.
    pub algorithm_id: u8,
}

impl Default for FeatureWord {
    fn default() -> Self {
        Self {
            version: 2,
            codec: StegoCodec::Stc,
            u: 1,
            h: crate::stego::coding::DEFAULT_STC_H,
            channel_mode: 0, // Green
            class_rule: 1,   // Safe [1, 6] non-boundary
            kdf_id: 0,       // PBKDF2 100k
            eligible_min: 8,
            eligible_max: 247,
            exclusion_permille: 300, // 30%
            algorithm_id: crate::stego::registry::SPATIAL_ALGORITHM_HILL,
        }
    }
}

impl FeatureWord {
    /// Serialize feature word into a 32-byte array (256 bits).
    pub fn encode(&self) -> [u8; FEATURE_WORD_BYTES] {
        let mut bytes = [0u8; FEATURE_WORD_BYTES];
        let codec_id = match self.codec {
            StegoCodec::Hamming => 0u64,
            StegoCodec::Stc | StegoCodec::Auto => 1u64,
        };

        let mut low64 = 0u64;
        low64 |= self.version as u64 & 0x0F;
        low64 |= (codec_id & 0x03) << 4;
        low64 |= (self.u as u64 & 0x07) << 6;
        low64 |= (self.h as u64 & 0x0F) << 9;
        low64 |= (self.channel_mode as u64 & 0x03) << 13;
        low64 |= (self.class_rule as u64 & 0x03) << 15;
        low64 |= (self.kdf_id as u64 & 0x03) << 17;
        low64 |= (self.eligible_min as u64 & 0xFF) << 19;
        low64 |= (self.eligible_max as u64 & 0xFF) << 27;
        low64 |= (self.exclusion_permille as u64 & 0xFFFF) << 35;

        bytes[..8].copy_from_slice(&low64.to_le_bytes());
        bytes[8] = self.algorithm_id;
        // bytes[9..32] remain all zeroes (reserved)
        bytes
    }

    /// Deserialize feature word from 32-byte array with strict validation.
    pub fn decode(bytes: &[u8; FEATURE_WORD_BYTES]) -> Result<Self, StrHideError> {
        let low64 = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        // Upper 13 bits of low64 (bits 51..64) must be zero
        if (low64 >> 51) != 0 {
            return Err(StrHideError::CorruptedData(
                "Non-zero reserved bits in feature word low64".into(),
            ));
        }
        // Bytes 9..32 (bits 72..256) must be all zero; byte 8 carries the
        // algorithm id.
        if bytes[9..].iter().any(|&b| b != 0) {
            return Err(StrHideError::CorruptedData(
                "Non-zero reserved bytes in feature word high bytes".into(),
            ));
        }

        let version = (low64 & 0x0F) as u8;
        if version != 2 {
            return Err(StrHideError::CorruptedData(format!(
                "Unsupported feature word version {version}"
            )));
        }

        let codec_id = ((low64 >> 4) & 0x03) as u8;
        let codec = match codec_id {
            0 => StegoCodec::Hamming,
            1 => StegoCodec::Stc,
            _ => {
                return Err(StrHideError::CorruptedData(format!(
                    "Unknown codec id {codec_id} in feature word"
                )));
            }
        };

        let u = ((low64 >> 6) & 0x07) as u8;
        if codec == StegoCodec::Stc && !(1..=MAX_STC_U).contains(&u) {
            return Err(StrHideError::CorruptedData(format!(
                "Invalid STC u={u} in feature word"
            )));
        }

        let h = ((low64 >> 9) & 0x0F) as u8;
        if codec == StegoCodec::Stc && !(4..=10).contains(&h) {
            return Err(StrHideError::CorruptedData(format!(
                "Invalid STC h={h} in feature word"
            )));
        }

        let channel_mode = ((low64 >> 13) & 0x03) as u8;
        let class_rule = ((low64 >> 15) & 0x03) as u8;
        let kdf_id = ((low64 >> 17) & 0x03) as u8;
        let eligible_min = ((low64 >> 19) & 0xFF) as u8;
        let eligible_max = ((low64 >> 27) & 0xFF) as u8;
        let exclusion_permille = ((low64 >> 35) & 0xFFFF) as u16;

        if (eligible_min != 0 || eligible_max != 0) && eligible_min >= eligible_max {
            return Err(StrHideError::CorruptedData(format!(
                "Invalid eligible range [{eligible_min}, {eligible_max}] in feature word"
            )));
        }
        if exclusion_permille > 900 {
            return Err(StrHideError::CorruptedData(format!(
                "Invalid exclusion permille {exclusion_permille} in feature word"
            )));
        }

        Ok(Self {
            version,
            codec,
            u,
            h,
            channel_mode,
            class_rule,
            kdf_id,
            eligible_min,
            eligible_max,
            exclusion_permille,
            algorithm_id: bytes[8],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::registry::SPATIAL_ALGORITHM_HILL;

    #[test]
    fn length_round_trips_and_leaves_the_codec_bits_alone() {
        for len in [49u32, 4096, HEADER_LEN_MAX] {
            let word = encode_header_word(len, StegoCodec::Hamming, 0, 1);
            let (got, id, h) = decode_header_word(word);
            assert_eq!(got, len);
            assert_eq!(id, 0);
            assert_eq!(h, 0);
            assert_eq!(
                word, len,
                "a default-carrier word must be the bare length, so pre-STC carriers stay identical"
            );
        }
    }

    #[test]
    fn codec_ids_are_backward_compatible() {
        // u = 1 was the only STC form before groups existed: it must keep the
        // historical id 1.
        assert_eq!(codec_header_id(StegoCodec::Stc, 1), 1);
        assert_eq!(codec_from_header_id(1).unwrap(), (StegoCodec::Stc, 1));
        for u in 2..=MAX_STC_U {
            let id = codec_header_id(StegoCodec::Stc, u);
            assert_eq!(codec_from_header_id(id).unwrap(), (StegoCodec::Stc, u));
        }
        assert!(codec_from_header_id(MAX_STC_U as u32 + 1).is_err());
        assert!(codec_from_header_id(3).is_ok());
        assert!(codec_from_header_id(4).is_err());
    }

    #[test]
    fn h_and_u_round_trip_without_touching_the_length() {
        for (h, u) in [(4u8, 1u8), (8, 1), (8, 2), (10, 3)] {
            let word = encode_header_word(1234, StegoCodec::Stc, h, u);
            let (len, id, got_h) = decode_header_word(word);
            assert_eq!(len, 1234);
            assert_eq!(got_h, h);
            assert_eq!(codec_from_header_id(id).unwrap(), (StegoCodec::Stc, u));
        }
    }

    #[test]
    fn feature_word_roundtrip_and_validation() {
        let fw = FeatureWord::default();
        let bytes = fw.encode();
        let decoded = FeatureWord::decode(&bytes).expect("decode default feature word");
        assert_eq!(decoded, fw);

        // Test non-default configurations
        let fw2 = FeatureWord {
            version: 2,
            codec: StegoCodec::Hamming,
            u: 1,
            h: 0,
            channel_mode: 1,
            class_rule: 0,
            kdf_id: 1,
            eligible_min: 16,
            eligible_max: 240,
            exclusion_permille: 500,
            algorithm_id: SPATIAL_ALGORITHM_HILL,
        };
        let bytes2 = fw2.encode();
        let decoded2 = FeatureWord::decode(&bytes2).expect("decode fw2");
        assert_eq!(decoded2, fw2);

        // Corrupted reserved bits in low64
        let mut bad_bytes = bytes;
        bad_bytes[6] |= 0x80; // bit 55
        assert!(FeatureWord::decode(&bad_bytes).is_err());

        // Corrupted reserved bytes in high bytes
        let mut bad_bytes2 = bytes;
        bad_bytes2[20] = 0x01;
        assert!(FeatureWord::decode(&bad_bytes2).is_err());

        // Unsupported version
        let mut bad_version = fw;
        bad_version.version = 3;
        assert!(FeatureWord::decode(&bad_version.encode()).is_err());
    }
}
