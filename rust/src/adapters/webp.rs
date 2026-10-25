use std::io::Write;

use crate::adapters::riff::{
    riff_can_chunk, riff_detect, riff_inject, riff_locate, riff_strategy_capacities,
    riff_suspicious_structures, riff_verify_structure,
};
use crate::adapters::{HostAdapter, SeekRead, StrategyCapacity};
use crate::errors::StrHideError;

pub struct WebpAdapter;

impl HostAdapter for WebpAdapter {
    fn format_name(&self) -> &'static str {
        "WEBP"
    }

    fn detect(&self, reader: &mut dyn SeekRead) -> bool {
        riff_detect(reader, b"WEBP")
    }

    fn supported_strategies(&self) -> Vec<&'static str> {
        vec!["riff_chunk", "eof"]
    }

    fn choose_auto_strategy(&self, reader: &mut dyn SeekRead, ube_size: u64) -> &'static str {
        // Mirrors WAV: keep riff_chunk only when write and read agree (declared
        // boundary = physical end, u32 size headroom), else EOF overlay
        // (review P1-2 / P3-17).
        if riff_can_chunk(reader, ube_size) {
            "riff_chunk"
        } else {
            "eof"
        }
    }

    fn strategy_capacities(&self, reader: Option<&mut dyn SeekRead>) -> Vec<StrategyCapacity> {
        riff_strategy_capacities("WebP", reader)
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
        riff_verify_structure(self.format_name(), stego_in, b"WEBP", |chunks| {
            let has_image_chunk = chunks
                .iter()
                .any(|(tag, _)| tag == b"VP8 " || tag == b"VP8L" || tag == b"VP8X");
            if !has_image_chunk {
                Err("WebP missing primary image chunk (VP8, VP8L, or VP8X)".into())
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
            Some(
                "Embedded into compliant WebP private RIFF chunk 'SHRD' (0 trailing bytes).".into(),
            )
        } else if strategy == "eof" && fallback {
            Some(
                "Carrier layout or payload did not fit the RIFF chunk strategy (declared \
                 boundary mismatch or 4 GiB limit); automatically fell back to EOF overlay."
                    .into(),
            )
        } else if strategy == "eof" {
            Some("Appended after WebP EOF (EOF overlay).".into())
        } else {
            None
        }
    }
}
