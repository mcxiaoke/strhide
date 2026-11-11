//! Fuzz the structure-domain read and restore paths in memory.
//!
//! `read_bytes` runs carrier detection, envelope authentication, decompression
//! and payload checks; `restore_bytes` additionally rewrites the host container
//! and re-validates the result. Both are reached from `--extract`/`--restore`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use strhide::StrHide;

const MAX_INPUT: usize = 4 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let engine = StrHide::new();
    let structure = engine.structure();

    let _ = structure.read_bytes(data, None);
    let _ = structure.read_bytes(data, Some("fuzz-password"));
    let _ = structure.restore_bytes(data, None);
    let _ = structure.restore_bytes(data, Some("fuzz-password"));
});
