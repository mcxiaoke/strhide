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
#[cfg(any(feature = "content-png", feature = "content-audio"))]
pub const FEATURE_WORD_BYTES: usize = 32;

/// Number of candidate slots carrying the 32-byte feature word (1 bit per slot).
#[cfg(any(feature = "content-png", feature = "content-audio"))]
pub const FEATURE_WORD_SLOTS: usize = FEATURE_WORD_BYTES * 8; // 256 slots

/// Total slots occupied by v2 header (256 basic header slots + 256 feature word slots).
#[cfg(any(feature = "content-png", feature = "content-audio"))]
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
#[cfg(any(feature = "content-png", feature = "content-audio"))]
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
    /// S-UNIWARD's `sigma` model option or MiPOD's `alpha` reference payload,
    /// rounded to `f32` precision. Other
    /// models ignore it.
    pub sigma: f32,
    /// High-pass kernel selector: 0 = the built-in normalized KB kernel.
    /// No other kernel has a wire id yet.
    pub kernel_id: u8,
}

#[cfg(any(feature = "content-png", feature = "content-audio"))]
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
            // The built-in spatial model in a PNG build; the audio engine
            // overwrites this field with its own id, so an audio-only build
            // needs no registry to construct a default word.
            #[cfg(feature = "content-png")]
            algorithm_id: crate::stego::png::registry::SPATIAL_ALGORITHM_HILL,
            #[cfg(not(feature = "content-png"))]
            algorithm_id: 0,
            sigma: 1.0,
            kernel_id: 0,
        }
    }
}

/// Largest window size the feature word can carry (10 bits).
#[cfg(any(feature = "content-png", feature = "content-audio"))]
pub const FEATURE_WORD_MAX_WINDOW: u16 = 63;

#[cfg(any(feature = "content-png", feature = "content-audio"))]
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

// ---------------------------------------------------------------------------
// Extension TLV area
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

// ---------------------------------------------------------------------------
// Content-domain V4 header
// ---------------------------------------------------------------------------

/// Base header size of PNG / WAV / FLAC carriers.
pub const PNG_AUDIO_BASE_HEADER_BYTES: usize = 64;

/// Bit slots occupied by the PNG / audio base header.
pub const PNG_AUDIO_BASE_SLOTS: usize = 512;

/// Upper bound of `ext_len` for PNG / WAV / FLAC / JPEG.
pub const MAX_EXT_BYTES: usize = 255;

/// `version` byte of V4.0.
pub const CONTENT_ENVELOPE_VERSION: u8 = 0x40;

/// `flags` bit 0: the extension area carries at least one TLV.
pub const FLAG_EXT_PRESENT: u8 = 0x01;

/// `flags` bit 1: at least one TLV is critical.
pub const FLAG_EXT_CRITICAL: u8 = 0x02;

/// CRC scope of the 64-byte base header.
const SPATIAL_CRC_SPAN: usize = 60;

/// 64-byte content header shared by PNG, WAV and FLAC.
///
/// `reserved` bytes and the CRC itself are not stored as fields: `encode`
/// writes zeros / the checksum, and `decode` rejects anything else.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SpatialHeaderV4 {
    /// L3 HKDF salt.
    pub salt: [u8; 16],
    /// AEAD nonce.
    pub nonce: [u8; 12],
    /// Ciphertext length including the AEAD tag.
    pub body_len: u32,
    /// `(major << 4) | minor`.
    pub version: u8,
    /// [`FLAG_EXT_PRESENT`] / [`FLAG_EXT_CRITICAL`].
    pub flags: u8,
    /// 1 PNG, 2 WAV, 3 FLAC.
    pub format_id: u8,
    /// PNG cost model (1 HILL / 2 SUNIWARD / 3 MiPOD); 0 for audio.
    pub algorithm_id: u8,
    /// AEAD suite id.
    pub suite_id: u16,
    /// 0 Hamming, 1 STC.
    pub codec_id: u8,
    /// Trellis height (0 for Hamming).
    pub stc_h: u8,
    /// Trellis width (0 for Hamming).
    pub stc_u: u8,
    /// PNG channel mode (0 Green / 1 RGB); 0 for audio.
    pub channel_mode: u8,
    /// PNG class rule (0/1); 0 for audio.
    pub class_rule: u8,
    /// HILL p1 window (odd, 1..=63).
    pub p1_window: u16,
    /// HILL p2 window (odd, 1..=63).
    pub p2_window: u16,
    /// `-log2(epsilon)` (1..=127).
    pub neg_log2_epsilon: u16,
    /// Exclusion percentile in permille (0..=900).
    pub exclusion_permille: u16,
    /// HILL sigma (finite, > 0).
    pub sigma: f32,
    /// Cost kernel id (0 = HILL).
    pub kernel_id: u8,
    /// Extension TLV byte count (0..=255).
    pub ext_len: u16,
}

fn major_minor(version: u8) -> (u8, u8) {
    (version >> 4, version & 0x0F)
}

fn validate_common(
    version: u8,
    flags: u8,
    suite_id: u16,
    body_len: u32,
    ext_len: usize,
) -> Result<(), StrHideError> {
    let (major, minor) = major_minor(version);
    if major != 4 {
        return Err(StrHideError::UnsupportedVersion(format!(
            "Content envelope major version {major}.{minor} is not supported"
        )));
    }
    if flags & !(FLAG_EXT_PRESENT | FLAG_EXT_CRITICAL) != 0 {
        return Err(StrHideError::CorruptedData(format!(
            "Content envelope flags {flags:#04x} use reserved bits"
        )));
    }
    if flags & FLAG_EXT_PRESENT != (ext_len > 0) as u8 {
        return Err(StrHideError::CorruptedData(
            "EXT_PRESENT does not match ext_len".into(),
        ));
    }
    if crate::crypto::CipherSuiteId::from_u16(suite_id).is_none() {
        return Err(StrHideError::UnsupportedVersion(format!(
            "Unknown content cipher suite id {suite_id}"
        )));
    }
    let body_overhead = crate::stego::envelope::BODY_OVERHEAD as u32;
    if body_len < body_overhead || body_len > HEADER_LEN_MAX {
        return Err(StrHideError::CorruptedData(format!(
            "Content body_len {body_len} is outside {body_overhead}..={HEADER_LEN_MAX}"
        )));
    }
    Ok(())
}

impl SpatialHeaderV4 {
    /// Serialize the base header, including CRC32-IEEE over `bytes[0..60]`.
    pub fn encode(&self) -> [u8; PNG_AUDIO_BASE_HEADER_BYTES] {
        let mut out = [0u8; PNG_AUDIO_BASE_HEADER_BYTES];
        out[0..16].copy_from_slice(&self.salt);
        out[16..28].copy_from_slice(&self.nonce);
        out[28..32].copy_from_slice(&self.body_len.to_be_bytes());
        out[32] = self.version;
        out[33] = self.flags;
        out[34] = self.format_id;
        out[35] = self.algorithm_id;
        out[36..38].copy_from_slice(&self.suite_id.to_be_bytes());
        out[38] = self.codec_id;
        out[39] = self.stc_h;
        out[40] = self.stc_u;
        out[41] = self.channel_mode;
        out[42] = self.class_rule;
        // out[43] reserved stays 0
        out[44..46].copy_from_slice(&self.p1_window.to_be_bytes());
        out[46..48].copy_from_slice(&self.p2_window.to_be_bytes());
        out[48..50].copy_from_slice(&self.neg_log2_epsilon.to_be_bytes());
        out[50..52].copy_from_slice(&self.exclusion_permille.to_be_bytes());
        out[52..56].copy_from_slice(&self.sigma.to_le_bytes());
        out[56] = self.kernel_id;
        // out[57] reserved stays 0
        out[58..60].copy_from_slice(&self.ext_len.to_be_bytes());
        let crc = crc32fast::hash(&out[..SPATIAL_CRC_SPAN]);
        out[SPATIAL_CRC_SPAN..].copy_from_slice(&crc.to_be_bytes());
        out
    }

    /// Parse and validate a base header for `expected_format`.
    ///
    /// The extension area is **not** read here: `ext_len` is only range-checked
    /// and cross-checked against `FLAG_EXT_PRESENT`.
    pub fn decode(
        bytes: &[u8; PNG_AUDIO_BASE_HEADER_BYTES],
        expected_format: u8,
    ) -> Result<Self, StrHideError> {
        let salt = bytes[0..16].try_into().expect("16-byte salt slice");
        let nonce = bytes[16..28].try_into().expect("12-byte nonce slice");
        let body_len = u32::from_be_bytes(bytes[28..32].try_into().expect("4-byte body_len"));
        let version = bytes[32];
        let flags = bytes[33];
        let format_id = bytes[34];
        let algorithm_id = bytes[35];
        let suite_id = u16::from_be_bytes(bytes[36..38].try_into().expect("2-byte suite"));
        let codec_id = bytes[38];
        let stc_h = bytes[39];
        let stc_u = bytes[40];
        let channel_mode = bytes[41];
        let class_rule = bytes[42];
        let p1_window = u16::from_be_bytes(bytes[44..46].try_into().expect("2-byte p1"));
        let p2_window = u16::from_be_bytes(bytes[46..48].try_into().expect("2-byte p2"));
        let neg_log2_epsilon =
            u16::from_be_bytes(bytes[48..50].try_into().expect("2-byte neg_log2"));
        let exclusion_permille =
            u16::from_be_bytes(bytes[50..52].try_into().expect("2-byte exclusion"));
        let sigma = f32::from_le_bytes(bytes[52..56].try_into().expect("4-byte sigma"));
        let kernel_id = bytes[56];
        let ext_len = u16::from_be_bytes(bytes[58..60].try_into().expect("2-byte ext_len"));

        validate_common(version, flags, suite_id, body_len, ext_len as usize)?;

        if format_id != expected_format || !(1..=3).contains(&expected_format) {
            return Err(StrHideError::CorruptedData(format!(
                "Content header format_id {format_id} does not match carrier format {expected_format}"
            )));
        }
        if format_id == 1 {
            if !(1..=3).contains(&algorithm_id) {
                return Err(StrHideError::CorruptedData(format!(
                    "PNG algorithm_id {algorithm_id} is outside 1..=3"
                )));
            }
            if channel_mode > 1 {
                return Err(StrHideError::CorruptedData(format!(
                    "PNG channel_mode {channel_mode} must be 0 or 1"
                )));
            }
            if class_rule > 1 {
                return Err(StrHideError::CorruptedData(format!(
                    "PNG class_rule {class_rule} must be 0 or 1"
                )));
            }
        } else {
            if algorithm_id != 0 {
                return Err(StrHideError::CorruptedData(format!(
                    "Audio algorithm_id {algorithm_id} must be 0"
                )));
            }
            if channel_mode != 0 {
                return Err(StrHideError::CorruptedData(format!(
                    "Audio channel_mode {channel_mode} must be 0"
                )));
            }
            if class_rule != 0 {
                return Err(StrHideError::CorruptedData(format!(
                    "Audio class_rule {class_rule} must be 0"
                )));
            }
        }

        match codec_id {
            0 => {
                if stc_h != 0 || stc_u != 0 {
                    return Err(StrHideError::CorruptedData(
                        "Hamming header must keep stc_h/stc_u at 0".into(),
                    ));
                }
            }
            1 => {
                if !(4..=10).contains(&stc_h) || !(1..=3).contains(&stc_u) {
                    return Err(StrHideError::CorruptedData(format!(
                        "STC header parameters h={stc_h} u={stc_u} are out of range"
                    )));
                }
            }
            other => {
                return Err(StrHideError::CorruptedData(format!(
                    "Unknown content codec_id {other}"
                )));
            }
        }

        for (name, value) in [("p1_window", p1_window), ("p2_window", p2_window)] {
            if value == 0 || value > 63 || value % 2 == 0 {
                return Err(StrHideError::CorruptedData(format!(
                    "Content header {name} {value} must be odd in 1..=63"
                )));
            }
        }
        if !(1..=127).contains(&neg_log2_epsilon) {
            return Err(StrHideError::CorruptedData(format!(
                "Content header neg_log2_epsilon {neg_log2_epsilon} is outside 1..=127"
            )));
        }
        if exclusion_permille > 900 {
            return Err(StrHideError::CorruptedData(format!(
                "Content header exclusion_permille {exclusion_permille} is above 900"
            )));
        }
        if !sigma.is_finite() || sigma <= 0.0 {
            return Err(StrHideError::CorruptedData(format!(
                "Content header sigma {sigma} must be finite and positive"
            )));
        }
        if kernel_id != 0 {
            return Err(StrHideError::CorruptedData(format!(
                "Content header kernel_id {kernel_id} must be 0"
            )));
        }
        if bytes[43] != 0 || bytes[57] != 0 {
            return Err(StrHideError::CorruptedData(
                "Content header reserved bytes must be 0".into(),
            ));
        }
        if ext_len as usize > MAX_EXT_BYTES {
            return Err(StrHideError::CorruptedData(format!(
                "Content header ext_len {ext_len} is above {MAX_EXT_BYTES}"
            )));
        }

        let expected_crc = u32::from_be_bytes(bytes[60..64].try_into().expect("4-byte crc"));
        let actual_crc = crc32fast::hash(&bytes[..SPATIAL_CRC_SPAN]);
        if actual_crc != expected_crc {
            return Err(StrHideError::CorruptedData(format!(
                "Content header CRC mismatch: stored {expected_crc:08x}, computed {actual_crc:08x}"
            )));
        }

        Ok(Self {
            salt,
            nonce,
            body_len,
            version,
            flags,
            format_id,
            algorithm_id,
            suite_id,
            codec_id,
            stc_h,
            stc_u,
            channel_mode,
            class_rule,
            p1_window,
            p2_window,
            neg_log2_epsilon,
            exclusion_permille,
            sigma,
            kernel_id,
            ext_len,
        })
    }

    /// Whether the extension area is present.
    pub fn ext_present(&self) -> bool {
        self.flags & FLAG_EXT_PRESENT != 0
    }

    /// Whether at least one extension TLV is critical.
    pub fn ext_critical(&self) -> bool {
        self.flags & FLAG_EXT_CRITICAL != 0
    }

    /// Cross-check `FLAG_EXT_CRITICAL` against the parsed TLV list.
    pub fn validate_ext_critical(&self, extension: &[u8]) -> Result<(), StrHideError> {
        let mut any_critical = false;
        for (type_id, _) in parse_extension(extension)? {
            if type_id & TLV_CRITICAL != 0 {
                any_critical = true;
            }
        }
        if any_critical != self.ext_critical() {
            return Err(StrHideError::CorruptedData(
                "EXT_CRITICAL does not match the extension TLVs".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[cfg(any(feature = "content-png", feature = "content-audio"))]
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
            algorithm_id: 1,
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

#[cfg(test)]
mod v4_header_tests {
    use super::*;

    // Frozen in docs/stego_content_envelope_v4_golden_vectors_20261103.md.
    const PNG: &str = concat!(
        "000102030405060708090a0b0c0d0e0f",
        "202122232425262728292a2b0000012c",
        "4001010100010108020101000003000f",
        "0017012c0000803f0000000408d5e33f",
    );
    const WAV: &str = concat!(
        "000102030405060708090a0b0c0d0e0f",
        "202122232425262728292a2b0000012c",
        "4000020000010000000000000003000f",
        "001700000000803f000000007d4b769b",
    );
    const FLAC: &str = concat!(
        "000102030405060708090a0b0c0d0e0f",
        "202122232425262728292a2b0000012c",
        "4000030000010000000000000003000f",
        "001700000000803f000000009a56d00c",
    );

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2, "hex length");
        let mut out = [0u8; N];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        out
    }

    fn golden(bytes: &str, format: u8) -> SpatialHeaderV4 {
        SpatialHeaderV4::decode(&hex::<64>(bytes), format).unwrap()
    }

    #[test]
    fn frozen_headers_decode_and_re_encode_byte_for_byte() {
        for (bytes, format) in [(PNG, 1), (WAV, 2), (FLAC, 3)] {
            let raw = hex::<64>(bytes);
            let header = SpatialHeaderV4::decode(&raw, format).unwrap();
            assert_eq!(header.format_id, format);
            assert_eq!(header.encode(), raw, "format {format} must round-trip");
        }
    }

    #[test]
    fn golden_field_values_are_the_documented_ones() {
        let png = golden(PNG, 1);
        assert_eq!(png.body_len, 300);
        assert_eq!(png.version, CONTENT_ENVELOPE_VERSION);
        assert_eq!(png.algorithm_id, 1);
        assert_eq!(png.codec_id, 1);
        assert_eq!((png.stc_h, png.stc_u), (8, 2));
        assert_eq!(png.channel_mode, 1);
        assert_eq!(png.class_rule, 1);
        assert_eq!(png.p1_window, 3);
        assert_eq!(png.p2_window, 15);
        assert_eq!(png.neg_log2_epsilon, 23);
        assert_eq!(png.exclusion_permille, 300);
        assert_eq!(png.sigma, 1.0);
        assert_eq!(png.ext_len, 4);
        assert!(png.ext_present());
        assert!(!png.ext_critical());

        let wav = golden(WAV, 2);
        assert_eq!(wav.algorithm_id, 0);
        assert_eq!(wav.codec_id, 0);
        assert_eq!((wav.stc_h, wav.stc_u), (0, 0));
        assert_eq!((wav.channel_mode, wav.class_rule), (0, 0));
        assert_eq!(wav.exclusion_permille, 0);
        assert_eq!(wav.ext_len, 0);
        assert!(!wav.ext_present());

        let flac = golden(FLAC, 3);
        assert_eq!(flac.format_id, 3);
        assert_eq!(flac.ext_len, 0);
    }

    #[test]
    fn crc_covers_every_header_byte_before_it() {
        let mut raw = hex::<64>(PNG);
        raw[0] ^= 0x01;
        let err = SpatialHeaderV4::decode(&raw, 1).expect_err("flip must fail CRC");
        assert!(matches!(err, StrHideError::CorruptedData(_)));

        // Rewriting the CRC is not enough: the field itself is still invalid.
        let mut raw = hex::<64>(PNG);
        raw[35] = 0; // algorithm_id = 0 is invalid for PNG
        let crc = crc32fast::hash(&raw[..60]);
        raw[60..].copy_from_slice(&crc.to_be_bytes());
        let err = SpatialHeaderV4::decode(&raw, 1).expect_err("PNG needs algorithm 1..=3");
        assert!(matches!(err, StrHideError::CorruptedData(_)));
    }

    #[test]
    fn version_flags_and_extent_are_validated() {
        let mut header = golden(PNG, 1);
        header.version = 0x30;
        let err = SpatialHeaderV4::decode(&header.encode(), 1).expect_err("v3 must fail");
        assert!(matches!(err, StrHideError::UnsupportedVersion(_)));

        let mut header = golden(PNG, 1);
        header.flags = 0x04;
        let err = SpatialHeaderV4::decode(&header.encode(), 1).expect_err("reserved flag bit");
        assert!(matches!(err, StrHideError::CorruptedData(_)));

        let mut header = golden(PNG, 1);
        header.ext_len = 0;
        let err = SpatialHeaderV4::decode(&header.encode(), 1).expect_err("EXT_PRESENT mismatch");
        assert!(matches!(err, StrHideError::CorruptedData(_)));

        let mut header = golden(PNG, 1);
        header.suite_id = 3;
        let err = SpatialHeaderV4::decode(&header.encode(), 1).expect_err("unknown suite");
        assert!(matches!(err, StrHideError::UnsupportedVersion(_)));
    }

    #[test]
    fn format_and_codec_parameters_are_validated() {
        let png = hex::<64>(PNG);
        let err = SpatialHeaderV4::decode(&png, 2).expect_err("format mismatch");
        assert!(matches!(err, StrHideError::CorruptedData(_)));

        let mut header = golden(PNG, 1);
        header.codec_id = 0;
        let err = SpatialHeaderV4::decode(&header.encode(), 1).expect_err("Hamming keeps h/u=0");
        assert!(matches!(err, StrHideError::CorruptedData(_)));

        let mut header = golden(PNG, 1);
        header.stc_h = 3;
        let err = SpatialHeaderV4::decode(&header.encode(), 1).expect_err("h below 4");
        assert!(matches!(err, StrHideError::CorruptedData(_)));

        let mut header = golden(PNG, 1);
        header.stc_u = 4;
        let err = SpatialHeaderV4::decode(&header.encode(), 1).expect_err("PNG u above 3");
        assert!(matches!(err, StrHideError::CorruptedData(_)));

        let mut header = golden(WAV, 2);
        header.channel_mode = 1;
        let err = SpatialHeaderV4::decode(&header.encode(), 2).expect_err("audio has no RGB mode");
        assert!(matches!(err, StrHideError::CorruptedData(_)));

        for p1 in [0u16, 2, 64] {
            let mut header = golden(PNG, 1);
            header.p1_window = p1;
            let err = SpatialHeaderV4::decode(&header.encode(), 1).expect_err("odd 1..=63");
            assert!(matches!(err, StrHideError::CorruptedData(_)));
        }

        let mut header = golden(PNG, 1);
        header.sigma = f32::NAN;
        let err = SpatialHeaderV4::decode(&header.encode(), 1).expect_err("NaN sigma");
        assert!(matches!(err, StrHideError::CorruptedData(_)));

        let mut header = golden(PNG, 1);
        header.body_len = (crate::stego::envelope::BODY_OVERHEAD - 1) as u32;
        let err = SpatialHeaderV4::decode(&header.encode(), 1).expect_err("body too short");
        assert!(matches!(err, StrHideError::CorruptedData(_)));
    }

    #[test]
    fn ext_critical_flag_must_match_the_tlv_list() {
        let mut header = golden(PNG, 1);
        let extension = [0x02, 0x02, 0xAA, 0xBB];
        assert!(header.validate_ext_critical(&extension).is_ok());
        header.flags |= FLAG_EXT_CRITICAL;
        let err = header
            .validate_ext_critical(&extension)
            .expect_err("non-critical TLVs need flag 0");
        assert!(matches!(err, StrHideError::CorruptedData(_)));

        header.flags &= !FLAG_EXT_CRITICAL;
        let critical = [0x81, 0x03, 0x01, 0x02, 0x03];
        let err = header
            .validate_ext_critical(&critical)
            .expect_err("critical TLVs need flag 1");
        assert!(matches!(err, StrHideError::CorruptedData(_)));
    }

    #[test]
    fn tlv_golden_and_padding_rules() {
        let tlvs = vec![
            Tlv {
                type_id: 0x81,
                value: vec![0x01, 0x02, 0x03],
            },
            Tlv {
                type_id: 0x02,
                value: Vec::new(),
            },
        ];
        assert_eq!(
            encode_extension(&tlvs).unwrap(),
            vec![0x81, 0x03, 0x01, 0x02, 0x03, 0x02, 0x00]
        );
        assert_eq!(
            parse_extension(&[0x81, 0x03, 0x01, 0x02, 0x03, 0x02, 0x00]).unwrap(),
            vec![
                (0x81u8, [0x01, 0x02, 0x03].as_slice()),
                (0x02u8, [].as_slice())
            ]
        );
        assert_eq!(
            parse_extension(&[0x02, 0x01, 0x09, 0x00, 0x00])
                .unwrap()
                .len(),
            1
        );
        assert!(parse_extension(&[0x02, 0x01, 0x09, 0x01]).is_err());
        assert!(parse_extension(&[0x02, 0x05, 0x09]).is_err());
    }
}
