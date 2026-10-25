//! HEVC NAL bitstream parsing, Emulation Prevention Byte (EPB) verification, and Cover Digest.

use sha2::{Digest, Sha256};

use crate::stego::hevc::sniff::{NAL_PPS_NUT, NAL_SPS_NUT, NAL_VPS_NUT};

/// Byte location and metadata of an identified NAL unit in the carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HevcNalSpan {
    /// Start of the NAL unit (including 2-byte header, excluding Annex-B start code or length prefix).
    pub header_offset: usize,
    /// Byte length of the NAL unit (header + RBSP with EPBs).
    pub nal_len: usize,
    /// 6-bit NAL unit type.
    pub nal_type: u8,
    /// 6-bit layer ID (0 for base layer).
    pub layer_id: u8,
    /// Temporal ID (temporal_id_plus1 - 1).
    pub temporal_id: u8,
}

impl HevcNalSpan {
    /// True if this is a VCL (Video Coding Layer / Slice) NAL unit.
    pub fn is_vcl(&self) -> bool {
        self.nal_type <= 31
    }

    /// True if this is a parameter set (VPS, SPS, or PPS).
    pub fn is_param_set(&self) -> bool {
        matches!(self.nal_type, NAL_VPS_NUT | NAL_SPS_NUT | NAL_PPS_NUT)
    }

    /// End offset of this NAL in the container slice.
    pub fn end_offset(&self) -> usize {
        self.header_offset + self.nal_len
    }
}

/// Parse raw Annex-B stream into NAL spans.
pub fn parse_annex_b_spans(data: &[u8]) -> Vec<HevcNalSpan> {
    let mut spans = Vec::new();
    let mut i = match find_start_code(data, 0) {
        Some((pos, _)) => pos,
        None => return spans,
    };

    loop {
        if i >= data.len() {
            break;
        }

        let (nal_end, next_sc) = match find_start_code(data, i) {
            Some((pos, sc_start)) => {
                let mut e = sc_start;
                while e > i && data[e - 1] == 0 {
                    e -= 1;
                }
                (e, Some(pos))
            }
            None => (data.len(), None),
        };

        let len = nal_end.saturating_sub(i);
        if len >= 2 {
            let b0 = data[i];
            let b1 = data[i + 1];
            if (b0 & 0x80) == 0 {
                let nal_type = (b0 >> 1) & 0x3F;
                let layer_id = ((b0 & 0x01) << 5) | (b1 >> 3);
                let tid_plus1 = b1 & 0x07;
                if tid_plus1 > 0 {
                    spans.push(HevcNalSpan {
                        header_offset: i,
                        nal_len: len,
                        nal_type,
                        layer_id,
                        temporal_id: tid_plus1 - 1,
                    });
                }
            }
        }

        match next_sc {
            Some(next_pos) => i = next_pos,
            None => break,
        }
    }

    spans
}

/// Parse HVCC format (big-endian length-prefixed NAL units, typically length_size=4).
pub fn parse_hvcc_spans(data: &[u8], length_size: usize) -> Vec<HevcNalSpan> {
    let mut spans = Vec::new();
    if !(1..=4).contains(&length_size) {
        return spans;
    }

    let mut pos = 0usize;
    while pos + length_size + 2 <= data.len() {
        let nal_len = match length_size {
            1 => data[pos] as usize,
            2 => u16::from_be_bytes([data[pos], data[pos + 1]]) as usize,
            3 => u32::from_be_bytes([0, data[pos], data[pos + 1], data[pos + 2]]) as usize,
            4 => u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                as usize,
            _ => break,
        };

        let nal_start = pos + length_size;
        if nal_start + nal_len > data.len() {
            break;
        }

        if nal_len >= 2 {
            let b0 = data[nal_start];
            let b1 = data[nal_start + 1];
            if (b0 & 0x80) == 0 {
                let nal_type = (b0 >> 1) & 0x3F;
                let layer_id = ((b0 & 0x01) << 5) | (b1 >> 3);
                let tid_plus1 = b1 & 0x07;
                if tid_plus1 > 0 {
                    spans.push(HevcNalSpan {
                        header_offset: nal_start,
                        nal_len,
                        nal_type,
                        layer_id,
                        temporal_id: tid_plus1 - 1,
                    });
                }
            }
        }

        pos = nal_start + nal_len;
    }

    spans
}

/// Check if in-place bit flipping at `pos` (`data[pos] ^ (1 << bit_idx)`) is safe
/// from triggering or corrupting H.265 Emulation Prevention Bytes (EPB `0x000003`).
pub fn is_epb_safe_flip(data: &[u8], pos: usize, bit_idx: u8) -> bool {
    if pos >= data.len() || bit_idx >= 8 {
        return false;
    }

    let orig = data[pos];
    let flipped = orig ^ (1 << bit_idx);

    // If original and flipped byte are neither 0x00 nor in 0x01..=0x03,
    // and neither neighbor is 0x00, it cannot affect any EPB sequence.
    let win_start = pos.saturating_sub(2);
    let win_end = (pos + 3).min(data.len());
    let sub = &data[win_start..win_end];

    // Check if the original window was already part of an EPB sequence (00 00 03)
    for w in sub.windows(3) {
        if w[0] == 0 && w[1] == 0 && w[2] == 3 {
            return false;
        }
    }

    // Check if the modified window creates an illegal start code or EPB boundary
    let mut temp = [0u8; 5];
    let len = win_end - win_start;
    temp[..len].copy_from_slice(sub);
    temp[pos - win_start] = flipped;

    for w in temp[..len].windows(3) {
        if w[0] == 0 && w[1] == 0 && w[2] <= 3 {
            return false;
        }
    }

    true
}

/// Compute an immutable cover digest from the carrier's parameter sets and slice headers.
///
/// This provides a symmetric deterministic key derivation source that remains 100% constant
/// across embedding and extraction, even after residual coefficient signs are flipped.
///
/// Only bytes that are immutable **by construction** are hashed: parameter sets
/// in full, and for VCL NALs the 2-byte NAL header plus the NAL length. A
/// fixed window over the slice header bytes is *not* safe: the first CABAC
/// payload byte sits at `2 + slice_segment_header_bytes` and single-slice
/// I-frame headers are routinely 3-8 bytes, so an 18-byte window covers
/// rewritable CABAC data of the first CTU -- flipping a sign bit there drifted
/// the digest and bricked extraction with the correct password
/// (review 2026-10-25, S2). NAL lengths are stable because the re-encoder
/// guarantees byte-length preservation (Delta = 0).
pub fn compute_hevc_cover_digest(data: &[u8], spans: &[HevcNalSpan], salt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update((spans.len() as u64).to_be_bytes());

    for span in spans {
        if span.is_param_set() {
            // Parameter sets (VPS, SPS, PPS) are completely immutable during steganography
            let end = span.end_offset().min(data.len());
            hasher.update(&data[span.header_offset..end]);
        } else if span.is_vcl() {
            let header_end = (span.header_offset + 2)
                .min(span.end_offset())
                .min(data.len());
            hasher.update(&data[span.header_offset..header_end]);
            hasher.update((span.nal_len as u64).to_be_bytes());
        }
    }

    hasher.finalize().into()
}

/// Package an RBSP into an H.265 NAL unit, inserting emulation prevention bytes (0x03)
/// and a 2-byte NAL header.
pub fn rbsp_to_nal(nal_type: u8, layer_id: u8, temporal_id: u8, rbsp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rbsp.len() + 8);
    let b0 = ((nal_type & 0x3F) << 1) | ((layer_id >> 5) & 0x01);
    let b1 = ((layer_id & 0x1F) << 3) | ((temporal_id + 1) & 0x07);
    out.push(b0);
    out.push(b1);

    let mut zero_count = 0;
    for &b in rbsp {
        if zero_count == 2 && b <= 3 {
            out.push(3); // 0x000003
            zero_count = 0;
        }
        out.push(b);
        if b == 0 {
            zero_count += 1;
        } else {
            zero_count = 0;
        }
    }
    out
}

fn find_start_code(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    let mut i = offset;
    while i + 2 < data.len() {
        if data[i] == 0 && data[i + 1] == 0 {
            if data[i + 2] == 1 {
                return Some((i + 3, i));
            }
            if i + 3 < data.len() && data[i + 2] == 0 && data[i + 3] == 1 {
                return Some((i + 4, i));
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epb_safe_flip_detection() {
        // Safe case: normal coefficients
        let data = vec![0x12, 0x34, 0x56, 0x78];
        assert!(is_epb_safe_flip(&data, 1, 0));

        // Forbidden case 1: modifying creates 00 00 00
        let dangerous_data = vec![0x00, 0x00, 0x01];
        // Flipping bit 0 of index 2 gives 0x00, creating 00 00 00 (illegal)
        assert!(!is_epb_safe_flip(&dangerous_data, 2, 0));

        // Forbidden case 2: modifying existing 00 00 03
        let epb_data = vec![0x00, 0x00, 0x03, 0x10];
        // Flipping any bit of 0x03 breaks existing emulation prevention
        assert!(!is_epb_safe_flip(&epb_data, 2, 0));
    }

    #[test]
    fn test_annex_b_and_hvcc_spans() {
        // Construct minimal Annex B with VPS (32) and SPS (33)
        let mut annex_b = Vec::new();
        // VPS: start code 00 00 00 01, NAL header (32 << 1 = 64 = 0x40, 0x01), payload 4 bytes
        annex_b.extend_from_slice(&[0, 0, 0, 1, 0x40, 0x01, 0xAA, 0xBB, 0xCC, 0xDD]);
        // SPS: start code 00 00 01, NAL header (33 << 1 = 66 = 0x42, 0x01), payload 3 bytes
        annex_b.extend_from_slice(&[0, 0, 1, 0x42, 0x01, 0x11, 0x22, 0x33]);

        let spans = parse_annex_b_spans(&annex_b);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].nal_type, NAL_VPS_NUT);
        assert_eq!(spans[0].nal_len, 6);
        assert_eq!(spans[1].nal_type, NAL_SPS_NUT);
        assert_eq!(spans[1].nal_len, 5);

        // Construct minimal HVCC with 4-byte length prefix
        let mut hvcc = Vec::new();
        hvcc.extend_from_slice(&6u32.to_be_bytes());
        hvcc.extend_from_slice(&[0x40, 0x01, 0xAA, 0xBB, 0xCC, 0xDD]);
        hvcc.extend_from_slice(&5u32.to_be_bytes());
        hvcc.extend_from_slice(&[0x42, 0x01, 0x11, 0x22, 0x33]);

        let hvcc_spans = parse_hvcc_spans(&hvcc, 4);
        assert_eq!(hvcc_spans.len(), 2);
        assert_eq!(hvcc_spans[0].nal_type, NAL_VPS_NUT);
        assert_eq!(hvcc_spans[1].nal_type, NAL_SPS_NUT);
    }

    #[test]
    fn test_cover_digest_stability() {
        let mut annex_b = Vec::new();
        // VPS NAL
        annex_b.extend_from_slice(&[0, 0, 0, 1, 0x40, 0x01, 0x01, 0x02, 0x03, 0x04]);
        // VCL Slice (IDR_W_RADL = 19 << 1 = 38 = 0x26, 0x01)
        annex_b.extend_from_slice(&[0, 0, 0, 1, 0x26, 0x01]);
        // 20 bytes of slice header + residual
        annex_b.extend_from_slice(&[0x55; 20]);

        let spans = parse_annex_b_spans(&annex_b);
        let digest1 = compute_hevc_cover_digest(&annex_b, &spans, b"salt1");

        // Mutating residual bytes anywhere in the VCL NAL -- including the
        // early CABAC region (NAL bytes 3..18) where short slice headers put
        // the first CTU's bins, and the tail -- must leave the digest alone.
        for vcl_byte in [3usize, 5, 10, 17, 21] {
            let mut modified = annex_b.clone();
            let pos = 10 + 4 + vcl_byte; // VPS NAL + start code prefix
            modified[pos] ^= 0x01;
            let digest2 = compute_hevc_cover_digest(&modified, &spans, b"salt1");
            assert_eq!(
                digest1, digest2,
                "digest must ignore VCL NAL byte {vcl_byte} (CABAC payload)"
            );
        }
    }

    /// The digest must still *bind* the carrier: the VCL NAL header byte and
    /// the NAL length both feed it, so two streams that differ there derive
    /// different keys.
    #[test]
    fn test_cover_digest_binds_nal_header_and_length() {
        let mut annex_b = Vec::new();
        annex_b.extend_from_slice(&[0, 0, 0, 1, 0x40, 0x01, 0x01, 0x02, 0x03, 0x04]);
        annex_b.extend_from_slice(&[0, 0, 0, 1, 0x26, 0x01]);
        annex_b.extend_from_slice(&[0x55; 20]);
        let spans = parse_annex_b_spans(&annex_b);
        let base = compute_hevc_cover_digest(&annex_b, &spans, b"salt1");

        // Different slice type (NAL header byte): IDR_W_RADL -> IDR_N_LP.
        let mut other_type = annex_b.clone();
        other_type[14] = 0x28; // (20 << 1)
        let spans2 = parse_annex_b_spans(&other_type);
        assert_ne!(
            base,
            compute_hevc_cover_digest(&other_type, &spans2, b"salt1")
        );

        // Different NAL length (one byte longer CABAC payload).
        let mut longer = annex_b.clone();
        longer.push(0x00);
        let spans3 = parse_annex_b_spans(&longer);
        assert_ne!(base, compute_hevc_cover_digest(&longer, &spans3, b"salt1"));

        // Parameter set bytes still bind as before.
        let mut ps = annex_b.clone();
        ps[6] ^= 0x01;
        let spans4 = parse_annex_b_spans(&ps);
        assert_ne!(base, compute_hevc_cover_digest(&ps, &spans4, b"salt1"));
    }
}
