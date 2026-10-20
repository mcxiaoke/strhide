use std::io::{SeekFrom, Write};

pub use crate::adapters::isobmff::MP4_UUID_NEUTRAL;
use crate::adapters::isobmff::{
    calc_prefix_len, isobmff_inject, isobmff_locate, isobmff_strategy_capacities,
    isobmff_suspicious_structures, isobmff_verify_structure,
};
use crate::adapters::{HostAdapter, SeekRead, StrategyCapacity};
use crate::errors::StrHideError;

/// Recognized HEIF brands in major_brand or compatible_brands list (ISO/IEC 23008-12).
pub const HEIF_BRANDS: &[[u8; 4]] = &[
    *b"heic", *b"heix", *b"hevc", *b"hevx", *b"mif1", *b"msf1", *b"heim", *b"heis", *b"avif",
    *b"avis",
];

pub struct HeifAdapter;

impl HostAdapter for HeifAdapter {
    fn format_name(&self) -> &'static str {
        "HEIF"
    }

    fn detect(&self, reader: &mut dyn SeekRead) -> bool {
        let start_pos = match reader.stream_position() {
            Ok(pos) => pos,
            Err(_) => return false,
        };
        if reader.seek(SeekFrom::Start(0)).is_err() {
            return false;
        }

        let mut header = [0u8; 8];
        let detected = if reader.read_exact(&mut header).is_ok() {
            let size = u32::from_be_bytes(header[0..4].try_into().unwrap()) as u64;
            let tag = &header[4..8];
            if tag == b"ftyp" && (12..=4096).contains(&size) {
                let payload_len = (size - 8) as usize;
                let mut payload = vec![0u8; payload_len];
                if reader.read_exact(&mut payload).is_ok() {
                    // payload contains:
                    // 0..4: major_brand
                    // 4..8: minor_version
                    // 8..: compatible_brands (each 4 bytes)
                    let mut matched = false;
                    let num_brands = payload_len / 4;
                    for i in 0..num_brands {
                        // skip index 1 which is minor_version
                        if i == 1 {
                            continue;
                        }
                        let brand = &payload[i * 4..(i + 1) * 4];
                        if HEIF_BRANDS.iter().any(|b| b == brand) {
                            matched = true;
                            break;
                        }
                    }
                    matched
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        let _ = reader.seek(SeekFrom::Start(start_pos));
        detected
    }

    fn supported_strategies(&self) -> Vec<&'static str> {
        vec!["box_uuid", "eof"]
    }

    fn choose_auto_strategy(&self, _reader: &mut dyn SeekRead, _ube_size: u64) -> &'static str {
        "box_uuid"
    }

    fn strategy_capacities(&self, _reader: Option<&mut dyn SeekRead>) -> Vec<StrategyCapacity> {
        isobmff_strategy_capacities()
    }

    fn inject(
        &self,
        host_in: &mut dyn SeekRead,
        ube_in: &mut dyn SeekRead,
        out: &mut dyn Write,
        strategy: &str,
    ) -> Result<(u64, u64, u32, u32), StrHideError> {
        isobmff_inject(self.format_name(), host_in, ube_in, out, strategy)
    }

    fn locate(
        &self,
        stego_in: &mut dyn SeekRead,
        expected_trailer_magic: Option<&[u8; 4]>,
    ) -> Result<Option<(u64, u64, String)>, StrHideError> {
        isobmff_locate(stego_in, expected_trailer_magic)
    }

    fn verify_structure(
        &self,
        stego_in: &mut dyn SeekRead,
    ) -> Result<(bool, String), StrHideError> {
        isobmff_verify_structure(self.format_name(), stego_in)
    }

    fn suspicious_structures(&self, stego_in: &mut dyn SeekRead) -> Vec<String> {
        isobmff_suspicious_structures(stego_in)
    }

    fn envelope_offset_delta(
        &self,
        _carrier: &mut dyn SeekRead,
        strategy: &str,
        ube_size: u64,
    ) -> Result<u64, StrHideError> {
        if strategy == "box_uuid" {
            Ok(calc_prefix_len(ube_size))
        } else {
            Ok(0)
        }
    }

    fn strategy_note(&self, strategy: &str, _fallback: bool) -> Option<String> {
        if strategy == "box_uuid" {
            Some("Embedded into compliant ISO BMFF uuid Box (32-bit header below 4GB, 64-bit large header at or above 4GB; preserves image item offsets).".into())
        } else if strategy == "eof" {
            Some("Appended after HEIF EOF (EOF overlay).".into())
        } else {
            None
        }
    }
}
