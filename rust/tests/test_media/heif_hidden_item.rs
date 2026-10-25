// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use strhide::engine::{PayloadSource, WriteOptions, read_carrier, write_carrier};

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strhide_test_heif_{name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_heif_synthetic_stub_auto_strategy_fallback() {
    // Tests that a minimal HEIF stub without meta gracefully falls back to box_uuid
    let scratch = scratch_dir("stub_heif");
    let target = scratch.join("minimal.heic");

    // Construct valid 32-byte HEIF stub (ftyp + free)
    let mut stub = Vec::new();
    stub.extend_from_slice(&24u32.to_be_bytes());
    stub.extend_from_slice(b"ftypheic");
    stub.extend_from_slice(&0u32.to_be_bytes());
    stub.extend_from_slice(b"mif1heic");
    stub.extend_from_slice(&8u32.to_be_bytes());
    stub.extend_from_slice(b"free");
    fs::write(&target, &stub).unwrap();

    let payload = b"Fallback Payload for HEIF";
    let write_opts = WriteOptions::default();
    let res = write_carrier(&target, PayloadSource::Bytes(payload), &write_opts);
    assert!(
        res.is_ok(),
        "Writing to minimal HEIF should succeed via fallback: {:?}",
        res.err()
    );

    let read_res = read_carrier(&target, None, None);
    assert!(
        read_res.is_ok(),
        "Reading payload back from fallback HEIF should succeed"
    );
    assert_eq!(read_res.unwrap().data, payload);

    let _ = fs::remove_dir_all(&scratch);
}
