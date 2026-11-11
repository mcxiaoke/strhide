//! Fuzz the content-domain inspector and extractor.
//!
//! The format sniffer, PNG/JPEG/HEVC/audio header parsers and the HEIF bridge
//! all read attacker-controlled bytes before any credential check. Inputs are
//! capped so a decode cannot dominate the fuzzing budget.

#![no_main]

use libfuzzer_sys::fuzz_target;
use strhide::StrHide;
use strhide::stego::{ExtractOptions, InspectOptions};

const MAX_INPUT: usize = 4 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let engine = StrHide::new();
    let stego = engine.stego();

    let _ = stego.inspect(data, &InspectOptions::default());
    let _ = stego.extract(data, &ExtractOptions::default());
});
