use std::io::{SeekFrom, Write};

pub use crate::structure::adapters::isobmff::{ITEM_HIDDEN_MAX_ENVELOPE, MP4_UUID_NEUTRAL};
use crate::structure::adapters::isobmff::{
    calc_prefix_len, heif_strategy_capacities, isobmff_can_item_hidden, isobmff_inject,
    isobmff_locate, isobmff_strip, isobmff_suspicious_structures, isobmff_verify_structure,
};
use crate::structure::adapters::{HostAdapter, SeekRead, SeekWrite, StrategyCapacity};
use crate::structure::envelope::EnvelopeHeader;

use crate::errors::StrHideError;
pub use crate::formats::sniff::{HEIF_BRANDS, is_heif_bytes};

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
            let size = u32::from_be_bytes(header[0..4].try_into().unwrap()) as usize;
            let tag = &header[4..8];
            if tag == b"ftyp" && (12..=4096).contains(&size) {
                let mut buf = vec![0u8; size];
                buf[0..8].copy_from_slice(&header);
                if reader.read_exact(&mut buf[8..size]).is_ok() {
                    is_heif_bytes(&buf)
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
        vec!["item_hidden", "free_box", "box_uuid", "eof"]
    }

    fn choose_auto_strategy(&self, reader: &mut dyn SeekRead, ube_size: u64) -> &'static str {
        // item_hidden registers the envelope through 32-bit iloc fields and a
        // 32-bit mdat box size, so it has a hard ~4 GiB ceiling the capacity
        // table must not overstate (review P2-4). box_uuid switches to a
        // 64-bit large header and is genuinely unlimited; engine auto is
        // single-shot, so the size check has to happen here.
        if ube_size <= ITEM_HIDDEN_MAX_ENVELOPE && isobmff_can_item_hidden(reader) {
            "item_hidden"
        } else {
            "box_uuid"
        }
    }

    fn strategy_capacities(&self, _reader: Option<&mut dyn SeekRead>) -> Vec<StrategyCapacity> {
        heif_strategy_capacities()
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

    fn strip(
        &self,
        stego_in: &mut dyn SeekRead,
        out: &mut dyn SeekWrite,
        header: &EnvelopeHeader,
    ) -> Result<(), StrHideError> {
        isobmff_strip(stego_in, out, header)
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
        } else if strategy == "item_hidden" || strategy == "free_box" {
            Ok(8)
        } else {
            Ok(0)
        }
    }

    fn strategy_note(&self, strategy: &str, _fallback: bool) -> Option<String> {
        if strategy == "item_hidden" {
            Some("Embedded as a hidden ISO BMFF Item in mdat, registered in iinf/iloc but unreferenced by pitm; primary image and tile grids untouched.".into())
        } else if strategy == "free_box" {
            Some("Embedded into compliant ISO BMFF free Box at EOF (padding box).".into())
        } else if strategy == "box_uuid" {
            Some("Embedded into compliant ISO BMFF uuid Box (32-bit header below 4GB, 64-bit large header at or above 4GB; preserves image item offsets).".into())
        } else if strategy == "eof" {
            Some("Appended after HEIF EOF (EOF overlay).".into())
        } else {
            None
        }
    }
}
