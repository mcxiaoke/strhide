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
        StegoCodec::Stc => 1 + (stc_u.clamp(1, MAX_STC_U) as u32 - 1),
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
    let stc_h = match codec {
        StegoCodec::Stc => stc_h,
        StegoCodec::Hamming => 0,
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
}
