use std::io::Write;

use crate::errors::StrHideError;
pub use crate::structure::adapters::isobmff::MP4_UUID_NEUTRAL;
use crate::structure::adapters::isobmff::{
    calc_prefix_len, isobmff_inject, isobmff_locate, isobmff_strategy_capacities,
    isobmff_suspicious_structures, isobmff_verify_structure,
};
use crate::structure::adapters::{HostAdapter, SeekRead, StrategyCapacity};
use std::io::SeekFrom;

pub struct Mp4Adapter;

impl Mp4Adapter {
    pub fn calc_prefix_len(ube_size: u64) -> u64 {
        calc_prefix_len(ube_size)
    }
}

impl HostAdapter for Mp4Adapter {
    fn format_name(&self) -> &'static str {
        "MP4"
    }

    fn detect(&self, reader: &mut dyn SeekRead) -> bool {
        let start_pos = match reader.stream_position() {
            Ok(pos) => pos,
            Err(_) => return false,
        };
        if reader.seek(SeekFrom::Start(0)).is_err() {
            return false;
        }
        let mut prefix = [0u8; 8];
        let ok = if reader.read_exact(&mut prefix).is_ok() {
            let tag = &prefix[4..8];
            // Top-level ISO-BMFF box types. The list covers classic files
            // (`ftyp`/`moov`/`mdat`), fragmented/CMAF media whose first box is
            // `styp`, `moof` or `sidx` (ISO/IEC 14496-12 allows a fragmented
            // stream without a leading `ftyp`), and the neutral filler boxes
            // `free`/`skip`/`wide`/`uuid`/`pdin`/`emsg`. Kept as an explicit
            // whitelist: "size + any 4CC" would classify arbitrary binaries as
            // MP4 and defeat the router's explicit-rejection policy.
            tag == b"ftyp"
                || tag == b"styp"
                || tag == b"moov"
                || tag == b"moof"
                || tag == b"mdat"
                || tag == b"sidx"
                || tag == b"emsg"
                || tag == b"free"
                || tag == b"skip"
                || tag == b"wide"
                || tag == b"uuid"
                || tag == b"pdin"
        } else {
            false
        };
        let _ = reader.seek(SeekFrom::Start(start_pos));
        ok
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
            Some("Embedded into compliant ISO BMFF uuid Box (32-bit header below 4GB, 64-bit large header at or above 4GB; preserves media frame offsets).".into())
        } else if strategy == "eof" {
            Some("Appended after MP4 EOF (EOF overlay).".into())
        } else {
            None
        }
    }
}
