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
#[cfg(feature = "content-png")]
pub const FEATURE_WORD_BYTES: usize = 32;

/// Number of candidate slots carrying the 32-byte feature word (1 bit per slot).
#[cfg(feature = "content-png")]
pub const FEATURE_WORD_SLOTS: usize = FEATURE_WORD_BYTES * 8; // 256 slots

/// Total slots occupied by v2 header (256 basic header slots + 256 feature word slots).
#[cfg(feature = "content-png")]
pub const V2_TOTAL_HEADER_SLOTS: usize = 256 + FEATURE_WORD_SLOTS; // 512 slots

/// Self-describing feature descriptor stored in the 32-byte feature word (v3).
///
/// v3 replaces v2's dead fields (`kdf_id`, `eligible_min`, `eligible_max` —
/// decoded but never read back) with the cost-model hyperparameters the
/// extractor must reproduce to rebuild the body ranking: HILL's
/// `p1_window`/`p2_window`/`epsilon` and S-UNIWARD's `sigma`. Two
/// normalisations make the wire values exact instead of approximate:
/// `epsilon` is stored as a power of two (`2^-k`) and the writer quantises
/// the configured value to the nearest power of two before using it, so
/// both ends compute the identical cost map; `sigma` is stored as `f32`
/// and the writer rounds it to `f32` precision for the same reason. The
/// 3x3 high-pass kernel is not carried: it does not fit, so a `kernel_id`
/// names it instead (0 = the built-in KB kernel) and custom kernels remain
/// a same-configuration-on-both-ends expert setting.
#[cfg(feature = "content-png")]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FeatureWord {
    pub version: u8,
    pub codec: StegoCodec,
    pub u: u8,
    pub h: u8,
    pub channel_mode: u8,
    pub class_rule: u8,
    /// First-stage low-pass window (odd, 1..=1023). HILL only.
    pub p1_window: u16,
    /// Second-stage low-pass window (odd, 1..=1023). HILL only.
    pub p2_window: u16,
    /// `epsilon = 2^-neg_log2_epsilon` (k in 1..=127).
    pub neg_log2_epsilon: u16,
    /// Fraction of smoothest pixels excluded from embedding, in per-mille.
    pub exclusion_permille: u16,
    /// Wire id of the spatial cost model that wrote this carrier.
    ///
    /// Stored so extraction does not need the algorithm out of band: the header
    /// is placed from a cost-free layout, so it can be read before the extractor
    /// knows which model produced the body. See
    /// [`crate::stego::png::registry::spatial_name_from_wire_id`].
    ///
    /// Lives in `bytes[8]`, which v2 reserved as zero, so the packed `low64`
    /// layout is unchanged.
    pub algorithm_id: u8,
    /// S-UNIWARD's `sigma` model option, rounded to `f32` precision. Other
    /// models ignore it.
    pub sigma: f32,
    /// High-pass kernel selector: 0 = the built-in normalized KB kernel.
    /// No other kernel has a wire id yet.
    pub kernel_id: u8,
}

#[cfg(feature = "content-png")]
impl Default for FeatureWord {
    fn default() -> Self {
        Self {
            version: 3,
            codec: StegoCodec::Stc,
            u: 1,
            h: crate::stego::coding::DEFAULT_STC_H,
            channel_mode: 0, // Green
            class_rule: 1,   // Safe [1, 6] non-boundary
            p1_window: 3,
            p2_window: 15,
            neg_log2_epsilon: 23,    // f32::EPSILON = 2^-23
            exclusion_permille: 300, // 30%
            algorithm_id: crate::stego::png::registry::SPATIAL_ALGORITHM_HILL,
            sigma: 1.0,
            kernel_id: 0,
        }
    }
}

/// Largest window size the feature word can carry (10 bits).
#[cfg(feature = "content-png")]
pub const FEATURE_WORD_MAX_WINDOW: u16 = 63;

#[cfg(feature = "content-png")]
impl FeatureWord {
    /// The `epsilon` value this word describes (`2^-k`).
    #[must_use]
    pub fn epsilon(&self) -> f64 {
        // k is validated to 1..=127 on decode, so this cannot underflow.
        (0.5f64).powi(self.neg_log2_epsilon as i32)
    }

    /// Quantise an arbitrary epsilon to the nearest power of two, the form
    /// the wire can carry exactly. `f32::EPSILON` and other powers of two
    /// round-trip unchanged.
    #[must_use]
    pub fn quantize_epsilon(epsilon: f64) -> u16 {
        let k = -epsilon.log2().round();
        k.clamp(1.0, 127.0) as u16
    }

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
        low64 |= (self.p1_window as u64 & 0x3FF) << 17;
        low64 |= (self.p2_window as u64 & 0x3FF) << 27;
        low64 |= (self.neg_log2_epsilon as u64 & 0x3FFF) << 37;
        low64 |= (self.exclusion_permille as u64 & 0xFFFF) << 51;

        bytes[..8].copy_from_slice(&low64.to_le_bytes());
        bytes[8] = self.algorithm_id;
        bytes[9..13].copy_from_slice(&self.sigma.to_le_bytes());
        bytes[13] = self.kernel_id;
        // bytes[14..32] remain all zeroes (reserved)
        bytes
    }

    /// Deserialize feature word from 32-byte array with strict validation.
    pub fn decode(bytes: &[u8; FEATURE_WORD_BYTES]) -> Result<Self, StrHideError> {
        let low64 = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let version = (low64 & 0x0F) as u8;
        if version != 3 {
            return Err(StrHideError::CorruptedData(format!(
                "Unsupported feature word version {version}"
            )));
        }
        // Bytes 14..32 (reserved) must be all zero.
        if bytes[14..].iter().any(|&b| b != 0) {
            return Err(StrHideError::CorruptedData(
                "Non-zero reserved bytes in feature word high bytes".into(),
            ));
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
        if class_rule > 1 {
            return Err(StrHideError::CorruptedData(format!(
                "Invalid class_rule {class_rule} in feature word (only 0 and 1 are supported)"
            )));
        }
        let p1_window = ((low64 >> 17) & 0x3FF) as u16;
        let p2_window = ((low64 >> 27) & 0x3FF) as u16;
        let neg_log2_epsilon = ((low64 >> 37) & 0x3FFF) as u16;
        let exclusion_permille = ((low64 >> 51) & 0xFFFF) as u16;

        if p1_window == 0 || p1_window.is_multiple_of(2) || p1_window > FEATURE_WORD_MAX_WINDOW {
            return Err(StrHideError::CorruptedData(format!(
                "Invalid p1_window {p1_window} in feature word (must be odd, 1..={FEATURE_WORD_MAX_WINDOW})"
            )));
        }
        if p2_window == 0 || p2_window.is_multiple_of(2) || p2_window > FEATURE_WORD_MAX_WINDOW {
            return Err(StrHideError::CorruptedData(format!(
                "Invalid p2_window {p2_window} in feature word (must be odd, 1..={FEATURE_WORD_MAX_WINDOW})"
            )));
        }
        if !(1..=127).contains(&neg_log2_epsilon) {
            return Err(StrHideError::CorruptedData(format!(
                "Invalid epsilon exponent {neg_log2_epsilon} in feature word"
            )));
        }
        if exclusion_permille > 900 {
            return Err(StrHideError::CorruptedData(format!(
                "Invalid exclusion permille {exclusion_permille} in feature word"
            )));
        }

        let sigma = f32::from_le_bytes(bytes[9..13].try_into().unwrap());
        if !sigma.is_finite() || sigma <= 0.0 {
            return Err(StrHideError::CorruptedData(
                "Invalid sigma in feature word (must be finite and positive)".into(),
            ));
        }

        let kernel_id = bytes[13];
        if kernel_id != 0 {
            return Err(StrHideError::CorruptedData(format!(
                "Unknown high-pass kernel id {kernel_id} in feature word"
            )));
        }

        Ok(Self {
            version,
            codec,
            u,
            h,
            channel_mode,
            class_rule,
            p1_window,
            p2_window,
            neg_log2_epsilon,
            exclusion_permille,
            algorithm_id: bytes[8],
            sigma,
            kernel_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::png::registry::SPATIAL_ALGORITHM_HILL;

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

    #[cfg(feature = "content-png")]
    #[test]
    fn feature_word_roundtrip_and_validation() {
        let fw = FeatureWord::default();
        let bytes = fw.encode();
        let decoded = FeatureWord::decode(&bytes).expect("decode default feature word");
        assert_eq!(decoded, fw);
        // The defaults must survive the wire exactly: powers-of-two epsilon
        // and f32 sigma round-trip bit-for-bit.
        assert_eq!(fw.epsilon(), f32::EPSILON as f64);

        // Test non-default configurations, including the v3 hyperparameters.
        let fw2 = FeatureWord {
            codec: StegoCodec::Hamming,
            u: 1,
            h: 0,
            channel_mode: 1,
            class_rule: 0,
            p1_window: 5,
            p2_window: 31,
            neg_log2_epsilon: 27,
            exclusion_permille: 500,
            algorithm_id: SPATIAL_ALGORITHM_HILL,
            sigma: 0.75,
            kernel_id: 0,
            ..FeatureWord::default()
        };
        let bytes2 = fw2.encode();
        let decoded2 = FeatureWord::decode(&bytes2).expect("decode fw2");
        assert_eq!(decoded2, fw2);

        // Epsilon quantisation: arbitrary values snap to a power of two that
        // both ends can carry exactly.
        assert_eq!(FeatureWord::quantize_epsilon(1e-8), 27);
        assert_eq!(FeatureWord::quantize_epsilon(f32::EPSILON as f64), 23);

        // Even windows are rejected (HILL requires odd windows).
        let mut bad_window = fw;
        bad_window.p1_window = 4;
        assert!(FeatureWord::decode(&bad_window.encode()).is_err());

        // Corrupted reserved bytes in the high area
        let mut bad_bytes2 = bytes;
        bad_bytes2[20] = 0x01;
        assert!(FeatureWord::decode(&bad_bytes2).is_err());

        // A non-zero kernel id is not decodable by this build.
        let mut bad_kernel = fw;
        bad_kernel.kernel_id = 1;
        assert!(FeatureWord::decode(&bad_kernel.encode()).is_err());

        // Unsupported version
        let mut bad_version = fw;
        bad_version.version = 4;
        assert!(FeatureWord::decode(&bad_version.encode()).is_err());

        // Oversized window (> 63)
        let mut bad_oversized = fw;
        bad_oversized.p1_window = 65;
        assert!(FeatureWord::decode(&bad_oversized.encode()).is_err());

        // Undefined class_rule (> 1)
        let mut bad_rule = fw;
        bad_rule.class_rule = 2;
        assert!(FeatureWord::decode(&bad_rule.encode()).is_err());
    }
}
