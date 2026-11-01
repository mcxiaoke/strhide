//! Linear PCM sample access: how a slot maps to bytes and to a signed value.
//!
//! A **slot** is one component of one sample frame (one channel of one
//! sample). For a 16-bit stereo file the slot count equals `data_len / 2`, and
//! slot `i` lives at `data_offset + i * 2`.
//!
//! Every supported layout is read into `i32` so the engine has a single
//! arithmetic domain. 8-bit WAV is *unsigned* on disk but offset here is kept
//! out of the value: `U8` reads the raw byte (0..=255) and the cost model
//! normalises by the byte range. Folding in the -128 offset would only move
//! where the asymmetry lives.

use crate::errors::StrHideError;

/// Storage layout of one PCM sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SampleKind {
    /// 8-bit unsigned (WAV `bits_per_sample = 8`).
    U8,
    /// 16-bit signed little-endian.
    I16,
    /// 24-bit signed little-endian packed in three bytes.
    I24,
    /// 32-bit signed little-endian.
    I32,
}

impl SampleKind {
    /// Bytes occupied by one sample component.
    pub(crate) const fn bytes(self) -> usize {
        match self {
            SampleKind::U8 => 1,
            SampleKind::I16 => 2,
            SampleKind::I24 => 3,
            SampleKind::I32 => 4,
        }
    }

    /// Bit depth as written in the container.
    pub(crate) const fn bits(self) -> u32 {
        (self.bytes() * 8) as u32
    }

    /// Smallest representable value.
    pub(crate) const fn min_value(self) -> i32 {
        match self {
            SampleKind::U8 => 0,
            SampleKind::I16 => i16::MIN as i32,
            SampleKind::I24 => -(1 << 23),
            SampleKind::I32 => i32::MIN,
        }
    }

    /// Largest representable value.
    pub(crate) const fn max_value(self) -> i32 {
        match self {
            SampleKind::U8 => 255,
            SampleKind::I16 => i16::MAX as i32,
            SampleKind::I24 => (1 << 23) - 1,
            SampleKind::I32 => i32::MAX,
        }
    }

    /// Build from a container bit depth, rejecting layouts the engine cannot
    /// model (float PCM, 20-bit packed, ...).
    pub(crate) fn from_bits(bits: u16) -> Result<Self, StrHideError> {
        match bits {
            8 => Ok(SampleKind::U8),
            16 => Ok(SampleKind::I16),
            24 => Ok(SampleKind::I24),
            32 => Ok(SampleKind::I32),
            other => Err(StrHideError::UnsupportedFormat(format!(
                "{other}-bit PCM is not supported; content steganography handles \
                 8/16/24/32-bit integer PCM"
            ))),
        }
    }

    /// Read the component at `byte_offset`.
    ///
    /// Callers guarantee the range is inside the buffer (the carrier parser
    /// bounds the data chunk before any slot is addressed).
    #[inline]
    pub(crate) fn read(self, buf: &[u8], byte_offset: usize) -> i32 {
        match self {
            SampleKind::U8 => buf[byte_offset] as i32,
            SampleKind::I16 => i16::from_le_bytes([buf[byte_offset], buf[byte_offset + 1]]) as i32,
            SampleKind::I24 => {
                let raw = (buf[byte_offset] as i32)
                    | ((buf[byte_offset + 1] as i32) << 8)
                    | ((buf[byte_offset + 2] as i32) << 16);
                // Sign-extend the 24-bit payload.
                (raw << 8) >> 8
            }
            SampleKind::I32 => i32::from_le_bytes([
                buf[byte_offset],
                buf[byte_offset + 1],
                buf[byte_offset + 2],
                buf[byte_offset + 3],
            ]),
        }
    }

    /// Write the component at `byte_offset`, ignoring out-of-range values.
    #[inline]
    pub(crate) fn write(self, buf: &mut [u8], byte_offset: usize, value: i32) {
        let clamped = value.clamp(self.min_value(), self.max_value());
        match self {
            SampleKind::U8 => buf[byte_offset] = clamped as u8,
            SampleKind::I16 => {
                let bytes = (clamped as i16).to_le_bytes();
                buf[byte_offset] = bytes[0];
                buf[byte_offset + 1] = bytes[1];
            }
            SampleKind::I24 => {
                let bytes = clamped.to_le_bytes();
                buf[byte_offset] = bytes[0];
                buf[byte_offset + 1] = bytes[1];
                buf[byte_offset + 2] = bytes[2];
            }
            SampleKind::I32 => {
                let bytes = clamped.to_le_bytes();
                buf[byte_offset..byte_offset + 4].copy_from_slice(&bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_layout_including_extremes() {
        for kind in [
            SampleKind::U8,
            SampleKind::I16,
            SampleKind::I24,
            SampleKind::I32,
        ] {
            // 8-bit WAV is unsigned: negatives are simply not representable,
            // so only the in-range candidates are exercised for it.
            let candidates = [
                kind.min_value(),
                kind.min_value() + 1,
                -2,
                -1,
                0,
                1,
                2,
                kind.max_value() - 1,
                kind.max_value(),
            ];
            for value in candidates
                .into_iter()
                .filter(|v| *v >= kind.min_value() && *v <= kind.max_value())
            {
                let mut buf = vec![0u8; kind.bytes()];
                kind.write(&mut buf, 0, value);
                assert_eq!(kind.read(&buf, 0), value, "{kind:?} lost {value}");
            }
        }
    }

    #[test]
    fn rejects_unsupported_depths() {
        assert!(SampleKind::from_bits(20).is_err());
        assert!(SampleKind::from_bits(64).is_err());
        assert_eq!(SampleKind::from_bits(16).unwrap(), SampleKind::I16);
    }

    #[test]
    fn writing_out_of_range_clamps_instead_of_wrapping() {
        let mut buf = vec![0u8; 2];
        SampleKind::I16.write(&mut buf, 0, i32::MAX);
        assert_eq!(SampleKind::I16.read(&buf, 0), i16::MAX as i32);
        SampleKind::I16.write(&mut buf, 0, i32::MIN);
        assert_eq!(SampleKind::I16.read(&buf, 0), i16::MIN as i32);
    }
}
