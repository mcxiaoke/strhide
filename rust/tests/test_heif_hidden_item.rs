// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

use strhide::engine::{
    PayloadSource, WriteOptions, inspect_carrier, read_carrier, remove_carrier, verify_carrier,
    write_carrier,
};

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strhide_test_heif_{name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_heif_item_hidden_and_free_box_real_samples() {
    let test_dir = Path::new("..").join("temp").join("testhevc");
    if !test_dir.exists() {
        eprintln!("Skipping test: {:?} does not exist", test_dir);
        return;
    }

    let samples = [
        "test.heic",
        "test.heif",
        "test_nclx.heif",
        "IMG_0874.HEIC",
        "IMG_20261018_113710.HEIC",
    ];

    let scratch = scratch_dir("real_heic");
    let payload = b"Hidden HEIF payload for testing item_hidden & free_box";

    for sample_name in samples {
        let sample_path = test_dir.join(sample_name);
        if !sample_path.exists() {
            continue;
        }

        let orig_bytes = fs::read(&sample_path).unwrap();
        let orig_hash = {
            let h = strhide::crypto::compute_sha256(&orig_bytes);
            h.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };

        // 1. Test strategy: item_hidden
        {
            let target_path = scratch.join(format!("hidden_{sample_name}"));
            fs::copy(&sample_path, &target_path).unwrap();

            let write_res = write_carrier(
                &target_path,
                PayloadSource::Bytes(payload),
                &WriteOptions {
                    password: Some("heif-pass"),
                    strategy: "item_hidden",
                    ..Default::default()
                },
            )
            .unwrap_or_else(|e| panic!("Failed to write item_hidden into {sample_name}: {e}"));

            assert_eq!(write_res.strategy, "item_hidden");

            // Verify structure
            let verify_res = verify_carrier(&target_path, None).expect("verify");
            assert!(
                verify_res.level1_host.ok,
                "Structure verify failed for {sample_name}: {}",
                verify_res.level1_host.detail
            );

            // Inspect
            let insp = inspect_carrier(&target_path, None).expect("inspect");
            assert_eq!(insp.strategy.as_deref(), Some("item_hidden"));

            // Read
            let read_res = read_carrier(&target_path, None, Some("heif-pass")).expect("read");
            assert_eq!(read_res.data, payload);

            // Strip / remove and check 100% bit-exact restoration
            let remove_res = remove_carrier(&target_path, None, None, false).expect("remove");
            assert!(remove_res.verified_identical);

            let restored_bytes = fs::read(&target_path).unwrap();
            let restored_hash = {
                let h = strhide::crypto::compute_sha256(&restored_bytes);
                h.iter().map(|b| format!("{b:02x}")).collect::<String>()
            };
            assert_eq!(
                restored_hash, orig_hash,
                "Bit-exact restore failed for {sample_name} with item_hidden"
            );
        }

        // 2. Test strategy: free_box
        {
            let target_path = scratch.join(format!("free_{sample_name}"));
            fs::copy(&sample_path, &target_path).unwrap();

            let write_res = write_carrier(
                &target_path,
                PayloadSource::Bytes(payload),
                &WriteOptions {
                    password: Some("heif-pass"),
                    strategy: "free_box",
                    ..Default::default()
                },
            )
            .unwrap_or_else(|e| panic!("Failed to write free_box into {sample_name}: {e}"));

            assert_eq!(write_res.strategy, "free_box");

            let read_res = read_carrier(&target_path, None, Some("heif-pass")).expect("read");
            assert_eq!(read_res.data, payload);

            let remove_res = remove_carrier(&target_path, None, None, false).expect("remove");
            assert!(remove_res.verified_identical);

            let restored_bytes = fs::read(&target_path).unwrap();
            let restored_hash = {
                let h = strhide::crypto::compute_sha256(&restored_bytes);
                h.iter().map(|b| format!("{b:02x}")).collect::<String>()
            };
            assert_eq!(
                restored_hash, orig_hash,
                "Bit-exact restore failed for {sample_name} with free_box"
            );
        }

        // 3. Test strategy: auto (should automatically choose item_hidden for real HEIF with meta)
        {
            let target_path = scratch.join(format!("auto_{sample_name}"));
            fs::copy(&sample_path, &target_path).unwrap();

            let write_res = write_carrier(
                &target_path,
                PayloadSource::Bytes(payload),
                &WriteOptions {
                    password: Some("heif-pass"),
                    strategy: "auto",
                    ..Default::default()
                },
            )
            .unwrap_or_else(|e| panic!("Failed to write auto into {sample_name}: {e}"));

            assert_eq!(
                write_res.strategy, "item_hidden",
                "Auto strategy should choose item_hidden for {sample_name}"
            );

            let read_res = read_carrier(&target_path, None, Some("heif-pass")).expect("read");
            assert_eq!(read_res.data, payload);
        }
    }

    let _ = fs::remove_dir_all(&scratch);
}
