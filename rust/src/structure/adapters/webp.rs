use std::io::Write;

use crate::errors::StrHideError;
use crate::structure::adapters::riff::{
    riff_can_chunk, riff_detect, riff_inject, riff_locate, riff_starts_with,
    riff_strategy_capacities, riff_suspicious_structures, riff_verify_structure,
};
use crate::structure::adapters::{
    HostAdapter, InjectCoordinates, LocatedEnvelope, SeekRead, StrategyCapacity,
};

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
        // Simple Format WebP (first chunk VP8 or VP8L) has no VP8X; RFC 9649
        // reserves new chunks for the Extended Format, so a private 'SHRD'
        // chunk there would be non-compliant. Keep riff_chunk only for the
        // Extended Format and only when write/read agree (declared boundary =
        // physical end, u32 headroom); everything else uses the EOF overlay.
        if riff_starts_with(reader, b"VP8X") && riff_can_chunk(reader, ube_size) {
            "riff_chunk"
        } else {
            "eof"
        }
    }

    fn strategy_capacities(&self, mut reader: Option<&mut dyn SeekRead>) -> Vec<StrategyCapacity> {
        // `None` means "no carrier to look at", so the report is format-level and
        // a Simple Format carrier cannot be ruled out. Say so rather than
        // implying every WebP accepts the private chunk.
        let known = reader.is_some();
        let simple = match reader.as_mut() {
            Some(r) => !riff_starts_with(&mut **r, b"VP8X"),
            None => false,
        };
        let mut caps = riff_strategy_capacities("WebP", reader);
        if simple {
            caps[0].available = false;
            caps[0].capacity_bytes = None;
            caps[0].note =
                Some("Simple Format WebP has no VP8X chunk; auto falls back to eof".into());
        } else if !known {
            caps[0].note = Some(
                "Extended Format (VP8X) only; a Simple Format carrier has no VP8X and falls back \
                 to eof"
                    .into(),
            );
        }
        caps
    }

    fn inject(
        &self,
        host_in: &mut dyn SeekRead,
        ube_in: &mut dyn SeekRead,
        out: &mut dyn Write,
        strategy: &str,
    ) -> Result<InjectCoordinates, StrHideError> {
        if strategy == "riff_chunk" && !riff_starts_with(host_in, b"VP8X") {
            return Err(StrHideError::UnsupportedFormat(
                "Simple Format WebP has no VP8X chunk; a private RIFF chunk would be invalid \
                 (RFC 9649). Please specify --strategy eof"
                    .into(),
            ));
        }
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
            b"WEBP",
            locator_magic,
            |chunks| {
                let has_image_chunk = chunks
                    .iter()
                    .any(|(tag, _)| tag == b"VP8 " || tag == b"VP8L" || tag == b"VP8X");
                if !has_image_chunk {
                    Err("WebP missing primary image chunk (VP8, VP8L, or VP8X)".into())
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
