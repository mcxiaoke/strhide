use std::io::Write;

use crate::errors::StrHideError;
use crate::structure::adapters::riff::{
    riff_can_chunk, riff_detect, riff_inject, riff_locate, riff_strategy_capacities,
    riff_suspicious_structures, riff_verify_structure,
};
use crate::structure::adapters::{
    HostAdapter, InjectCoordinates, LocatedEnvelope, SeekRead, StrategyCapacity,
};

pub struct WavAdapter;

impl HostAdapter for WavAdapter {
    fn format_name(&self) -> &'static str {
        "WAV"
    }

    fn detect(&self, reader: &mut dyn SeekRead) -> bool {
        riff_detect(reader, b"WAVE")
    }

    fn supported_strategies(&self) -> Vec<&'static str> {
        vec!["riff_chunk", "eof"]
    }

    fn choose_auto_strategy(&self, reader: &mut dyn SeekRead, ube_size: u64) -> &'static str {
        // riff_chunk requires the declared boundary to match the physical file end
        // and patched size to stay within u32. Other carriers route to eof.
        if riff_can_chunk(reader, ube_size) {
            "riff_chunk"
        } else {
            "eof"
        }
    }

    fn strategy_capacities(&self, reader: Option<&mut dyn SeekRead>) -> Vec<StrategyCapacity> {
        riff_strategy_capacities("WAV", reader)
    }

    fn inject(
        &self,
        host_in: &mut dyn SeekRead,
        ube_in: &mut dyn SeekRead,
        out: &mut dyn Write,
        strategy: &str,
    ) -> Result<InjectCoordinates, StrHideError> {
        riff_inject(self.format_name(), host_in, ube_in, out, strategy)
    }

    fn locate(
        &self,
        stego_in: &mut dyn SeekRead,
        expected_trailer_magic: Option<&[u8; 4]>,
    ) -> Result<Option<LocatedEnvelope>, StrHideError> {
        riff_locate(stego_in, expected_trailer_magic)
    }

    fn verify_structure(
        &self,
        stego_in: &mut dyn SeekRead,
    ) -> Result<(bool, String), StrHideError> {
        self.verify_structure_with_magic(stego_in, None)
    }

    fn verify_structure_with_magic(
        &self,
        stego_in: &mut dyn SeekRead,
        locator_magic: Option<&[u8; 4]>,
    ) -> Result<(bool, String), StrHideError> {
        riff_verify_structure(
            self.format_name(),
            stego_in,
            b"WAVE",
            locator_magic,
            |chunks| {
                let has_fmt = chunks.iter().any(|(tag, _)| tag == b"fmt ");
                let has_data = chunks.iter().any(|(tag, _)| tag == b"data");
                if !has_fmt {
                    Err("WAV missing 'fmt ' chunk".into())
                } else if !has_data {
                    Err("WAV missing 'data' chunk".into())
                } else {
                    Ok(())
                }
            },
        )
    }

    fn suspicious_structures(&self, stego_in: &mut dyn SeekRead) -> Vec<String> {
        riff_suspicious_structures(stego_in)
    }

    fn envelope_offset_delta(
        &self,
        _carrier: &mut dyn SeekRead,
        strategy: &str,
        _ube_size: u64,
    ) -> Result<u64, StrHideError> {
        if strategy == "riff_chunk" {
            Ok(8)
        } else {
            Ok(0)
        }
    }

    fn strategy_note(&self, strategy: &str, fallback: bool) -> Option<String> {
        if strategy == "riff_chunk" {
            Some("Embedded into compliant WAV private RIFF chunk 'SHRD' (0 trailing bytes).".into())
        } else if strategy == "eof" && fallback {
            Some(
                "Carrier layout or payload did not fit the RIFF chunk strategy (declared \
                 boundary mismatch or 4 GiB limit); automatically fell back to EOF overlay."
                    .into(),
            )
        } else if strategy == "eof" {
            Some("Appended after WAV EOF (EOF overlay).".into())
        } else {
            None
        }
    }
}
