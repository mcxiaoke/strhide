//! Quantization-table (DQT) segment parsing.
//!
//! Moved out of `analysis::calibration` so the stego side (UERD cost weights)
//! and the steganalysis side (calibrated reference) share one parser instead
//! of two copies drifting apart.

/// One quantization table as stored in a DQT segment, converted to natural
/// (row-major) frequency order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuantTable {
    /// Destination identifier (`Tq`, 0..=3).
    pub id: u8,
    /// 64 quantization steps in natural (row-major) frequency order.
    pub q: [u16; 64],
}

/// Standard baseline JPEG luminance quantization table (ITU-T T.81 Annex K),
/// quality ~50, in **natural** (row-major) order.
///
/// Used as the fallback when a carrier carries no parsable DQT: a baseline
/// JPEG is required to have one, so this only guards against malformed files.
pub const STANDARD_LUMA_QT: [u16; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61, //
    12, 12, 14, 19, 26, 58, 60, 55, //
    14, 13, 16, 24, 40, 57, 69, 56, //
    14, 17, 22, 29, 51, 87, 80, 62, //
    18, 22, 37, 56, 68, 109, 103, 77, //
    24, 35, 55, 64, 81, 104, 113, 92, //
    49, 64, 78, 87, 103, 121, 120, 101, //
    72, 92, 95, 98, 112, 100, 103, 99, //
];

/// Zigzag scan order: zigzag position -> natural `row*8 + col`.
const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// Parse every DQT segment that appears before the scan starts.
///
/// Returns the tables in file order, or `None` when the marker structure is
/// malformed or no DQT appears before SOS/EOI.
pub fn parse_dqt_tables(data: &[u8]) -> Option<Vec<QuantTable>> {
    let mut i = 2usize; // skip SOI
    let mut tables = Vec::new();
    while i + 4 <= data.len() {
        if data[i] != 0xFF {
            i += 1;
            continue;
        }
        let marker = data[i + 1];
        if marker == 0xD8 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            i += 2;
            continue;
        }
        if marker == 0xDA || marker == 0xD9 {
            // Scan started / image ended: no (more) DQT to find.
            break;
        }
        let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        if len < 2 || i + 2 + len > data.len() {
            return None;
        }
        if marker == 0xDB {
            let mut p = i + 4;
            let end = i + 2 + len;
            while p < end {
                let pq_tq = data[p];
                let precision = pq_tq >> 4;
                let id = pq_tq & 0x0F;
                let bytes_per = if precision == 0 { 1 } else { 2 };
                if p + 1 + 64 * bytes_per > end {
                    return None;
                }
                let mut zigzag = [0u16; 64];
                for (z, slot) in zigzag.iter_mut().enumerate() {
                    let off = p + 1 + z * bytes_per;
                    let value = if precision == 0 {
                        data[off] as u16
                    } else {
                        u16::from_be_bytes([data[off], data[off + 1]])
                    };
                    *slot = value;
                }
                // The file stores DQT in zigzag order; keep the table in
                // natural order so it lines up with the coefficients.
                let mut natural = [0u16; 64];
                for (z, &nat) in ZIGZAG.iter().enumerate() {
                    natural[nat] = zigzag[z];
                }
                tables.push(QuantTable { id, q: natural });
                p += 1 + 64 * bytes_per;
            }
        }
        i += 2 + len;
    }
    if tables.is_empty() {
        None
    } else {
        Some(tables)
    }
}

/// First table with `id == 0` (the luminance table by near-universal encoder
/// convention), in natural order. `None` when the file has no parsable DQT.
pub fn parse_luma_dqt(data: &[u8]) -> Option<[u16; 64]> {
    parse_dqt_tables(data)?
        .into_iter()
        .find(|t| t.id == 0)
        .map(|t| t.q)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One DQT marker segment carrying `tables` (zigzag order, 8-bit).
    fn dqt_segment(tables: &[QuantTable]) -> Vec<u8> {
        let mut seg = Vec::new();
        for table in tables {
            seg.push(table.id & 0x0F);
            for &nat in ZIGZAG.iter() {
                seg.push(table.q[nat] as u8);
            }
        }
        let len = (seg.len() + 2) as u16;
        let mut out = vec![0xFF, 0xDB];
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&seg);
        out
    }

    #[test]
    fn parses_luma_table_in_natural_order() {
        let mut q = [0u16; 64];
        for (nat, slot) in q.iter_mut().enumerate() {
            *slot = (nat as u16) + 1; // natural index encoded as the value
        }
        let mut data = vec![0xFF, 0xD8];
        data.extend(dqt_segment(&[QuantTable { id: 0, q }]));
        data.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]); // SOS: stop scanning
        let parsed = parse_luma_dqt(&data).expect("table");
        assert_eq!(parsed, q, "DQT must be returned in natural order");
    }

    #[test]
    fn skips_chroma_table_for_luma_lookup() {
        let chroma = QuantTable {
            id: 1,
            q: [3u16; 64],
        };
        let luma = QuantTable {
            id: 0,
            q: [7u16; 64],
        };
        // Two separate DQT segments (libjpeg's usual layout).
        let mut data = vec![0xFF, 0xD8];
        data.extend(dqt_segment(&[chroma]));
        data.extend(dqt_segment(&[luma]));
        data.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]);
        let tables = parse_dqt_tables(&data).expect("tables");
        assert_eq!(tables.len(), 2);
        assert_eq!(tables[0].id, 1);
        assert_eq!(tables[1].id, 0);
        assert_eq!(parse_luma_dqt(&data), Some([7u16; 64]));

        // Both tables inside a single segment.
        let mut data = vec![0xFF, 0xD8];
        data.extend(dqt_segment(&[chroma, luma]));
        data.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]);
        let tables = parse_dqt_tables(&data).expect("tables");
        assert_eq!(tables.len(), 2);
        assert_eq!(parse_luma_dqt(&data), Some([7u16; 64]));
    }

    #[test]
    fn rejects_data_without_dqt() {
        let data = [0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02];
        assert_eq!(parse_luma_dqt(&data), None);
        assert_eq!(parse_dqt_tables(&data), None);
    }

    #[test]
    fn standard_table_is_annex_k() {
        // Spot-check a few well-known Annex K luma steps.
        assert_eq!(STANDARD_LUMA_QT[0], 16); // DC
        assert_eq!(STANDARD_LUMA_QT[1], 11);
        assert_eq!(STANDARD_LUMA_QT[63], 99);
    }
}
