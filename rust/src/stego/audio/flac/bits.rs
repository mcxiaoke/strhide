//! MSB-first bit reader/writer for the FLAC bitstream.
//!
//! FLAC is a *bit* stream: subframe headers, Rice codewords and sample fields
//! are not byte aligned, and the whole in-place scheme depends on addressing
//! individual bits exactly. Both directions are needed -- the reader to find a
//! codeword, the writer to replace its remainder while leaving the unary part
//! (and therefore the codeword length) untouched.
//!
//! The positions are absolute **bit offsets into the whole file**, not into a
//! per-frame buffer: a slot's address has to survive the frame-by-frame walk
//! so the writer can patch the original carrier bytes directly.

use crate::errors::StrHideError;

/// Read side of the bit stream.
#[derive(Debug, Clone)]
pub(crate) struct BitReader<'a> {
    bytes: &'a [u8],
    /// Absolute bit position.
    pos: usize,
}

/// A read that would run past the end of the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BitEof;

/// Report a read past the end of the buffer, optionally with its position.
pub(crate) fn eof(pos: usize) -> BitEof {
    log::trace!(
        target: "stego::audio::flac",
        "read past end at bit {pos} (byte {})",
        pos / 8
    );
    BitEof
}

impl<'a> BitReader<'a> {
    pub(crate) fn new(bytes: &'a [u8], bit_pos: usize) -> Self {
        Self {
            bytes,
            pos: bit_pos,
        }
    }

    #[inline]
    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    fn bit_at(&self, index: usize) -> Option<u8> {
        self.bytes
            .get(index >> 3)
            .map(|byte| (byte >> (7 - (index & 7))) & 1)
    }

    /// Read `bits` (0..=32) MSB-first.
    #[inline]
    pub(crate) fn read(&mut self, bits: u32) -> Result<u32, BitEof> {
        debug_assert!(bits <= 32);
        if bits == 0 {
            return Ok(0);
        }
        // Whole-byte fast path: the common case for sample fields.
        let mut value = 0u32;
        if (self.pos & 7) == 0 && bits == 8 {
            let byte = *self.bytes.get(self.pos >> 3).ok_or_else(|| eof(self.pos))?;
            self.pos += 8;
            return Ok(byte as u32);
        }
        for _ in 0..bits {
            value = (value << 1) | self.bit_at(self.pos).ok_or_else(|| eof(self.pos))? as u32;
            self.pos += 1;
        }
        Ok(value)
    }

    /// Read `bits` as a two's-complement signed value.
    #[inline]
    pub(crate) fn read_signed(&mut self, bits: u32) -> Result<i64, BitEof> {
        if bits == 0 {
            return Ok(0);
        }
        let raw = self.read(bits)? as u64;
        let shift = 64 - bits;
        Ok(((raw << shift) as i64) >> shift)
    }

    /// Read a unary value: the number of zero bits before the terminating one.
    ///
    /// Scans a whole byte at a time when the position is byte aligned and the
    /// byte is zero, which is the common case for quiet residuals.
    pub(crate) fn unary(&mut self) -> Result<u32, BitEof> {
        let mut count = 0u32;
        loop {
            if (self.pos & 7) == 0
                && let Some(&byte) = self.bytes.get(self.pos >> 3)
                && byte == 0
            {
                count = count.checked_add(8).ok_or_else(|| eof(self.pos))?;
                self.pos += 8;
                continue;
            }
            if self.bit_at(self.pos).ok_or_else(|| eof(self.pos))? == 1 {
                self.pos += 1;
                return Ok(count);
            }
            count = count.checked_add(1).ok_or_else(|| eof(self.pos))?;
            self.pos += 1;
        }
    }

    /// Skip to the next byte boundary.
    pub(crate) fn align(&mut self) {
        self.pos = (self.pos + 7) & !7;
    }
}

/// Write side of the bit stream, over a mutable byte slice.
#[derive(Debug)]
pub(crate) struct BitWriter<'a> {
    bytes: &'a mut [u8],
    /// Absolute bit position.
    pos: usize,
}

impl<'a> BitWriter<'a> {
    pub(crate) fn new(bytes: &'a mut [u8], bit_pos: usize) -> Self {
        Self {
            bytes,
            pos: bit_pos,
        }
    }

    /// Overwrite `bits` (0..=32) MSB-first at the current position.
    pub(crate) fn write(&mut self, bits: u32, value: u32) -> Result<(), StrHideError> {
        if bits > 32 {
            return Err(StrHideError::General("BitWriter: bits exceeds 32".into()));
        }
        for i in (0..bits).rev() {
            let bit = ((value >> i) & 1) as u8;
            let index = self.pos;
            let byte = self.bytes.get_mut(index >> 3).ok_or_else(|| {
                StrHideError::CorruptedData(format!(
                    "FLAC bitstream write out of bounds at bit {index}"
                ))
            })?;
            let mask = 1u8 << (7 - (index & 7));
            if bit == 1 {
                *byte |= mask;
            } else {
                *byte &= !mask;
            }
            self.pos += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_writes_across_byte_boundaries() {
        let data = [0b1011_0010u8, 0b0100_1111, 0b1000_0001];
        let mut reader = BitReader::new(&data, 0);
        assert_eq!(reader.read(3).unwrap(), 0b101);
        assert_eq!(reader.read(7).unwrap(), 0b100_1001);
        assert_eq!(reader.position(), 10);
        // Bits 10..16 of 0b1011_0010_0100_1111_1000_0001.
        assert_eq!(reader.read(6).unwrap(), 0b00_1111);
        assert_eq!(reader.position(), 16);

        let mut copy = data;
        let mut writer = BitWriter::new(&mut copy, 3);
        writer.write(5, 0b00011).unwrap();
        assert_eq!(copy[0], 0b1010_0011);
        let mut reader = BitReader::new(&copy, 3);
        assert_eq!(
            reader.read(5).unwrap(),
            0b00011,
            "what was written reads back"
        );
        assert_eq!(copy[1], 0b0100_1111, "bits past the write are untouched");
    }

    #[test]
    fn signed_reads_sign_extend() {
        let data = [0b1111_1110u8, 0b0000_0111];
        let mut reader = BitReader::new(&data, 0);
        assert_eq!(reader.read_signed(4).unwrap(), -1);
        let mut reader = BitReader::new(&data, 0);
        assert_eq!(reader.read_signed(8).unwrap(), -2);
        let mut reader = BitReader::new(&data, 4);
        assert_eq!(reader.read_signed(4).unwrap(), -2);
    }

    #[test]
    fn unary_counts_zero_bits() {
        // 0b1000_0000 -> 0 zeros then a one; 0b0000_0001 -> 7 zeros.
        let data = [0b1000_0000u8, 0b0000_0001];
        let mut reader = BitReader::new(&data, 0);
        assert_eq!(reader.unary().unwrap(), 0);
        assert_eq!(reader.position(), 1);
        let mut reader = BitReader::new(&data, 0);
        assert_eq!(reader.unary().unwrap(), 0);

        // From bit 1 the stream is 000_0000 (rest of byte 0) then the seven
        // zeros of byte 1: fourteen zeros before the terminating one.
        let mut reader = BitReader::new(&data, 1);
        assert_eq!(reader.unary().unwrap(), 14);
        assert_eq!(reader.position(), 16);
    }

    #[test]
    fn unary_skips_zero_bytes_in_one_step() {
        let data = [0u8, 0u8, 0b0100_0000];
        let mut reader = BitReader::new(&data, 0);
        assert_eq!(reader.unary().unwrap(), 17);
        assert_eq!(reader.position(), 18);
    }

    #[test]
    fn reading_past_the_end_reports_eof_instead_of_panicking() {
        let data = [0u8];
        let mut reader = BitReader::new(&data, 7);
        assert_eq!(reader.read(4), Err(BitEof));
        let mut reader = BitReader::new(&data, 8);
        assert_eq!(reader.read(1), Err(BitEof));
        assert_eq!(reader.unary(), Err(BitEof));
    }

    #[test]
    fn rewriting_a_remainder_keeps_the_codeword_length() {
        // A 3-bit remainder followed by marker bits.
        let mut data = [0b1010_1100u8, 0b1111_0000];
        let mut writer = BitWriter::new(&mut data, 5);
        writer.write(3, 0b011).unwrap();
        assert_eq!(data[0], 0b1010_1011);
        assert_eq!(data[1], 0b1111_0000);
    }
}
