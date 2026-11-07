//! Fixed-size content-envelope headers and the shared extension-TLV codec.
//!
//! Every V4 carrier starts with one of three base headers (64 B spatial,
//! 44 B JPEG, 32 B HEVC). Their `body_len` field is 32 bits on the wire but is
//! validated against [`HEADER_LEN_MAX`]: the envelope is capped at 2^26 - 1
//! bytes, so a forged length above it is rejected before any slot is touched.
//! That cap is also what keeps `max_payload_bytes` meaningful.
//!
//! The old 32-bit word that packed `(length, codec, h, u)` into the first
//! header bytes is gone with the V2/V3 envelopes; V4 stores those fields
//! explicitly in the base header (see [`SpatialHeaderV4`]).

use crate::errors::StrHideError;

/// Bits of the header word that hold the envelope length.
pub const HEADER_LEN_BITS: u32 = 26;
/// Mask of the length field inside the header word.
pub const HEADER_LEN_MASK: u32 = (1 << HEADER_LEN_BITS) - 1;
/// Largest envelope the 26-bit length field can express.
pub const HEADER_LEN_MAX: u32 = HEADER_LEN_MASK;

/// Quantise `epsilon` to the exponent `k` the wire can carry (`epsilon = 2^-k`).
///
/// The base header stores `neg_log2_epsilon` as an integer, so writer, prober
/// and reader must all run on the identical quantised value; otherwise the cost
/// map, and with it the body ranking, disagrees by a rounding step and the
/// payload becomes unreadable. Non-finite or non-positive inputs fall back to
/// the default `f32::EPSILON` exponent instead of panicking.
#[must_use]
pub fn quantize_epsilon_k(epsilon: f64) -> u16 {
    if !epsilon.is_finite() || epsilon <= 0.0 {
        return 23;
    }
    (-crate::stego::detmath::log2(epsilon))
        .round()
        .clamp(1.0, 127.0) as u16
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

/// Encode an extension area for **writing**, refusing unknown critical TLVs.
///
/// V4 defines no critical TLV yet, and every reader (this build included) folds
/// an unknown critical tag into `NoHiddenData`. Accepting one here would let the
/// writer emit a carrier that nobody -- including itself -- can read back, which
/// is worse than a clear error at the call site. A future critical tag becomes
/// writable only after its reader-side semantics exist.
pub fn encode_extension_for_write(tlvs: &[Tlv]) -> Result<Vec<u8>, StrHideError> {
    if let Some(tlv) = tlvs.iter().find(|tlv| tlv.is_critical()) {
        return Err(StrHideError::General(format!(
            "TLV type {:#04x} is marked critical, but this build defines no critical \
             extension; an unknown critical TLV makes the carrier unreadable",
            tlv.type_id
        )));
    }
    encode_extension(tlvs)
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
        validate_ext_critical_flag(self.flags, extension)
    }
}

/// Cross-check a header's `FLAG_EXT_CRITICAL` bit against its extension TLVs.
///
/// Shared by every v4 dialect (spatial PNG/audio, HEVC, JPEG) so a header that
/// declares a critical contract without carrying one — or carries one without
/// declaring it — is rejected identically on extract, inspect and verify.
/// An empty extension area with the bit set is invalid on its own:
/// `FLAG_EXT_PRESENT` must be clear in that case.
pub fn validate_ext_critical_flag(flags: u8, extension: &[u8]) -> Result<(), StrHideError> {
    let declared = flags & FLAG_EXT_CRITICAL != 0;
    if extension.is_empty() {
        return if declared {
            Err(StrHideError::CorruptedData(
                "EXT_CRITICAL is set but there is no extension area".into(),
            ))
        } else {
            Ok(())
        };
    }
    let any_critical = parse_extension(extension)?
        .iter()
        .any(|(type_id, _)| type_id & TLV_CRITICAL != 0);
    if any_critical != declared {
        return Err(StrHideError::CorruptedData(
            "EXT_CRITICAL does not match the extension TLVs".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epsilon_quantisation_is_exact_for_powers_of_two() {
        assert_eq!(quantize_epsilon_k(f32::EPSILON as f64), 23);
        assert_eq!(quantize_epsilon_k(1e-8), 27);
        // Arbitrary values snap to the nearest exponent both ends can carry.
        assert_eq!(quantize_epsilon_k(2f64.powi(-27)), 27);
        assert_eq!(quantize_epsilon_k(1.4e-8), 26);
        // Invalid input falls back to the default exponent instead of panicking.
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(quantize_epsilon_k(bad), 23, "{bad} must fall back");
        }
    }

    #[test]
    fn critical_tlvs_are_refused_at_write_time() {
        let critical = [Tlv {
            type_id: 0x81,
            value: vec![1, 2, 3],
        }];
        let err = encode_extension_for_write(&critical).expect_err("critical must be refused");
        assert!(format!("{err}").contains("critical"), "{err}");

        // Non-critical tags stay writable, and the encoding is unchanged.
        let plain = [Tlv {
            type_id: 0x01,
            value: b"x".to_vec(),
        }];
        assert_eq!(
            encode_extension_for_write(&plain).unwrap(),
            encode_extension(&plain).unwrap()
        );
    }
}

#[cfg(test)]
mod v4_header_tests {
    use super::*;

    // Frozen golden test vectors (see docs/api/WIRE_SPEC_CONTENT.md).
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
