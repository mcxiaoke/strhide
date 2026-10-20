use std::io::Write;

use crate::adapters::riff::{
    riff_detect, riff_inject, riff_locate, riff_strategy_capacities, riff_suspicious_structures,
    riff_verify_structure,
};
use crate::adapters::{HostAdapter, SeekRead, StrategyCapacity};
use crate::errors::StrHideError;

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

    fn choose_auto_strategy(&self, _reader: &mut dyn SeekRead, _ube_size: u64) -> &'static str {
        "riff_chunk"
    }

    fn strategy_capacities(&self, _reader: Option<&mut dyn SeekRead>) -> Vec<StrategyCapacity> {
        riff_strategy_capacities("WAV")
    }

    fn inject(
        &self,
        host_in: &mut dyn SeekRead,
        ube_in: &mut dyn SeekRead,
        out: &mut dyn Write,
        strategy: &str,
    ) -> Result<(u64, u64, u32, u32), StrHideError> {
        riff_inject(self.format_name(), host_in, ube_in, out, strategy)
    }

    fn locate(
        &self,
        stego_in: &mut dyn SeekRead,
        expected_trailer_magic: Option<&[u8; 4]>,
    ) -> Result<Option<(u64, u64, String)>, StrHideError> {
        riff_locate(stego_in, expected_trailer_magic)
    }

    fn verify_structure(
        &self,
        stego_in: &mut dyn SeekRead,
    ) -> Result<(bool, String), StrHideError> {
        riff_verify_structure(self.format_name(), stego_in, b"WAVE", |chunks| {
            let has_fmt = chunks.iter().any(|(tag, _)| tag == b"fmt ");
            let has_data = chunks.iter().any(|(tag, _)| tag == b"data");
            if !has_fmt {
                Err("WAV missing 'fmt ' chunk".into())
            } else if !has_data {
                Err("WAV missing 'data' chunk".into())
            } else {
                Ok(())
            }
        })
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
                "Payload exceeded WAV RIFF 4GB limit; automatically fell back to EOF overlay."
                    .into(),
            )
        } else if strategy == "eof" {
            Some("Appended after WAV EOF (EOF overlay).".into())
        } else {
            None
        }
    }
}
