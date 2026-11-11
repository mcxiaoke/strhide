//! Fuzz the in-memory structure-domain inspectors.
//!
//! The file-based entry points are thin wrappers over these byte paths, so a
//! crash here is reachable from the CLI and the GUI. Inputs are capped because
//! several adapters copy the carrier while probing it.

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

    // Both credential ladders: the default profile secret and an explicit
    // password take different KDF branches.
    let _ = structure.inspect_bytes(data, None);
    let _ = structure.inspect_bytes(data, Some("fuzz-password"));
    let _ = structure.verify_bytes(data, None);
});
