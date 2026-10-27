// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Facade ([`StrHide`]) integration tests: the verb × carrier matrix.
//!
//! These verify the facade forwards correctly across both domains and both
//! carrier forms (path / bytes), and that a private dialect bound on an engine
//! is isolated from the official engine.

use strhide::engine::{PayloadSource, WriteOptions};
use strhide::facade::StrHide;
use strhide::params::Profile;
use strhide::stego::StegoOptions;

use crate::common::scratch;

const PNG: &[u8] = include_bytes!("../assets/minimal.png");
const JPG: &[u8] = include_bytes!("../assets/small.jpg");

const STRUCT_PAYLOAD: &[u8] = b"facade structure payload";
const CONTENT_PAYLOAD: &[u8] = b"facade content payload";

// ───────────────────────── structure domain · bytes ─────────────────────────

#[test]
fn structure_bytes_write_read_restore_roundtrip() {
    let engine = StrHide::new();
    let options = WriteOptions::default();

    let (stego, write) = engine
        .write_bytes(PNG, PayloadSource::Bytes(STRUCT_PAYLOAD), &options)
        .expect("write_bytes");
    assert!(write.ube_size > 0);
    assert_ne!(stego, PNG);

    let read = engine.read_bytes(&stego, None).expect("read_bytes");
    assert_eq!(read.data, STRUCT_PAYLOAD);

    let (restored, _remove) = engine.restore_bytes(&stego, None).expect("restore_bytes");
    assert_eq!(
        restored, PNG,
        "restore_bytes must recover the original carrier"
    );
}

#[test]
fn structure_bytes_inspect_and_verify() {
    let engine = StrHide::new();
    let options = WriteOptions::default();
    let (stego, _) = engine
        .write_bytes(PNG, PayloadSource::Bytes(STRUCT_PAYLOAD), &options)
        .expect("write_bytes");

    let inspect = engine.inspect_bytes(&stego, None).expect("inspect_bytes");
    assert!(inspect.has_hidden_data, "inspect must report hidden data");

    let verify = engine.verify_bytes(&stego, None).expect("verify_bytes");
    assert!(strhide::engine::verify_passed(&verify), "verify must pass");
}

// ───────────────────────── structure domain · path ──────────────────────────

#[test]
fn structure_path_write_read_restore_roundtrip() {
    let dir = scratch("facade_struct_path");
    let carrier = dir.join("carrier.png");
    std::fs::write(&carrier, PNG).expect("seed carrier");

    let engine = StrHide::new();
    let options = WriteOptions {
        backup: false,
        ..WriteOptions::default()
    };

    engine
        .write(&carrier, PayloadSource::Bytes(STRUCT_PAYLOAD), &options)
        .expect("write");

    let read = engine.read(&carrier, None, None).expect("read");
    assert_eq!(read.data, STRUCT_PAYLOAD);

    engine
        .restore(&carrier, None, None, false)
        .expect("restore");
    assert_eq!(
        std::fs::read(&carrier).expect("read carrier"),
        PNG,
        "restore must recover the original carrier on disk"
    );
}

#[test]
fn structure_path_inspect_and_verify() {
    let dir = scratch("facade_struct_inspect");
    let carrier = dir.join("carrier.png");
    std::fs::write(&carrier, PNG).expect("seed carrier");

    let engine = StrHide::new();
    let options = WriteOptions {
        backup: false,
        ..WriteOptions::default()
    };
    engine
        .write(&carrier, PayloadSource::Bytes(STRUCT_PAYLOAD), &options)
        .expect("write");

    let inspect = engine.inspect(&carrier, None).expect("inspect");
    assert!(inspect.has_hidden_data);

    let verify = engine.verify(&carrier, None).expect("verify");
    assert!(strhide::engine::verify_passed(&verify));
}

// ───────────────────────── content domain · bytes ───────────────────────────

#[test]
fn content_bytes_embed_extract_roundtrip() {
    let engine = StrHide::new();
    let options = StegoOptions::default();

    let stego = engine.embed(JPG, CONTENT_PAYLOAD, &options).expect("embed");
    assert_ne!(stego, JPG);

    let extracted = engine.extract(&stego, &options).expect("extract");
    assert_eq!(extracted, CONTENT_PAYLOAD);
}

#[test]
fn content_bytes_probe_reports_capacity() {
    let engine = StrHide::new();
    let options = StegoOptions::default();
    let cap = engine.probe(JPG, &options).expect("probe");
    assert!(cap.recommended_max_bytes > 0);
}

// ───────────────────────── content domain · file ────────────────────────────

#[test]
fn content_file_embed_and_extract_roundtrip() {
    let dir = scratch("facade_content_file");
    let carrier = dir.join("carrier.jpg");
    std::fs::write(&carrier, JPG).expect("seed carrier");
    let output = dir.join("extracted.bin");

    let engine = StrHide::new();
    let options = StegoOptions::default();

    engine
        .embed_file(&carrier, None, CONTENT_PAYLOAD, &options, false)
        .expect("embed_file");

    engine
        .extract_file(&carrier, &output, &options, false)
        .expect("extract_file");
    assert_eq!(
        std::fs::read(&output).expect("read output"),
        CONTENT_PAYLOAD
    );
}

#[test]
fn content_file_embed_to_target_leaves_original_untouched() {
    let dir = scratch("facade_content_target");
    let carrier = dir.join("carrier.jpg");
    std::fs::write(&carrier, JPG).expect("seed carrier");
    let target = dir.join("target.jpg");

    let engine = StrHide::new();
    let options = StegoOptions::default();
    engine
        .embed_file(&carrier, Some(&target), CONTENT_PAYLOAD, &options, false)
        .expect("embed_file to target");

    assert_eq!(std::fs::read(&carrier).expect("read carrier"), JPG);
    assert!(target.exists());
}

// ───────────────────────── private dialect isolation ────────────────────────

#[test]
fn private_dialect_engine_is_isolated_from_official() {
    const PRIVATE_ENGINE: StrHide =
        StrHide::new().with_profile(Profile::new().with_default_secret("facade-private-key"));
    assert!(!PRIVATE_ENGINE.profile().is_official());

    let options = WriteOptions::default();
    let (stego, _) = PRIVATE_ENGINE
        .write_bytes(PNG, PayloadSource::Bytes(STRUCT_PAYLOAD), &options)
        .expect("private write");

    // The official engine cannot read a carrier written under the private dialect.
    let official = StrHide::new();
    assert!(
        official.read_bytes(&stego, None).is_err(),
        "official engine must not read a private carrier"
    );

    // The private engine still reads its own carrier.
    let read = PRIVATE_ENGINE
        .read_bytes(&stego, None)
        .expect("private read");
    assert_eq!(read.data, STRUCT_PAYLOAD);
}

#[test]
fn per_op_local_params_override_does_not_mutate_engine() {
    use strhide::params::{CompressionStrategy, LocalParams};

    let engine = StrHide::new();
    let original = *engine.local_params();

    // A per-call override runs on a copied engine; the original is unchanged.
    let tuned =
        engine.with_local_params(LocalParams::new().with_compression(CompressionStrategy::Never));
    assert_eq!(*engine.local_params(), original);
    assert_eq!(tuned.local_params().compression, CompressionStrategy::Never);
}

// ───────────────────── run_cli_from (engine-driven CLI) ─────────────────────

#[test]
fn run_cli_from_version_returns_zero() {
    let engine = StrHide::new();
    let code = engine.run_cli_from(["strhide", "--version"]);
    assert_eq!(code, 0);
}

#[test]
fn run_cli_from_help_returns_zero() {
    let engine = StrHide::new();
    let code = engine.run_cli_from(["strhide", "--help"]);
    assert_eq!(code, 0);
}

#[test]
fn run_cli_from_private_dialect_isolation() {
    let dir = scratch("facade_cli_private");
    let carrier = dir.join("carrier.png");
    std::fs::write(&carrier, PNG).expect("seed carrier");

    const PRIVATE: StrHide =
        StrHide::new().with_profile(Profile::new().with_default_secret("cli-private-key"));
    assert!(!PRIVATE.profile().is_official());

    // The private engine writes through its own command line.
    let carrier_str = carrier.to_str().expect("utf-8 path");
    let write_code = PRIVATE.run_cli_from([
        "strhide",
        "write",
        carrier_str,
        "-t",
        "cli private payload",
        "--in-place",
        "--no-backup",
    ]);
    assert_eq!(write_code, 0, "private write via CLI must succeed");

    // The official engine cannot read the private carrier through its CLI.
    let official = StrHide::new();
    let read_official = official.run_cli_from(["strhide", "read", carrier_str, "--stdout"]);
    assert_ne!(
        read_official, 0,
        "official CLI read must fail on a private carrier"
    );

    // The private engine reads its own carrier.
    let read_private = PRIVATE.run_cli_from(["strhide", "read", carrier_str, "--stdout"]);
    assert_eq!(read_private, 0, "private CLI read must succeed");
}

#[test]
fn run_cli_from_content_domain_private_isolation() {
    let dir = scratch("facade_cli_content");
    let carrier = dir.join("carrier.jpg");
    std::fs::write(&carrier, JPG).expect("seed carrier");

    // A private stego dialect (custom domain + secret).
    const PRIVATE: StrHide = StrHide::new().with_profile(
        Profile::new()
            .with_stego_secret("cli-stego-key")
            .with_stego_domain("cli-stego-domain"),
    );

    let carrier_str = carrier.to_str().expect("utf-8 path");
    let embed_code = PRIVATE.run_cli_from([
        "strhide",
        "embed",
        carrier_str,
        "-t",
        "cli stego payload",
        "--in-place",
        "--no-backup",
    ]);
    assert_eq!(embed_code, 0, "private embed via CLI must succeed");

    // Official extraction must fail on the private stego carrier.
    let official = StrHide::new();
    let extract_official = official.run_cli_from(["strhide", "extract", carrier_str, "--stdout"]);
    assert_ne!(
        extract_official, 0,
        "official CLI extract must fail on a private stego carrier"
    );

    // Private extraction succeeds.
    let extract_private = PRIVATE.run_cli_from(["strhide", "extract", carrier_str, "--stdout"]);
    assert_eq!(extract_private, 0, "private CLI extract must succeed");
}

// ───────────────────────── structure domain · path ─────────────────────────

/// `read` / `restore` used to hard-code `overwrite = false` on the facade, so a
/// caller could not replace an existing destination without dropping down to
/// the five-parameter free functions. Both now have an explicit `_with` form,
/// and the refusing form must leave the existing file untouched.
#[test]
fn structure_read_and_restore_honour_the_overwrite_flag() {
    use strhide::errors::StrHideError;

    let dir = scratch("facade_overwrite");
    let engine = StrHide::new();
    let carrier = dir.join("carrier.png");
    std::fs::write(&carrier, PNG).expect("seed carrier");

    engine
        .write(
            &carrier,
            PayloadSource::Bytes(STRUCT_PAYLOAD),
            &WriteOptions::default(),
        )
        .expect("write");

    let out = dir.join("payload.bin");
    std::fs::write(&out, b"stale").expect("seed output");

    let err = engine
        .read(&carrier, Some(&out), None)
        .expect_err("read must refuse an existing destination");
    assert!(
        matches!(err, StrHideError::Rejection(_)),
        "expected Rejection, got {err:?}"
    );
    assert_eq!(
        std::fs::read(&out).expect("read back"),
        b"stale",
        "a refused read must not truncate the existing file"
    );

    engine
        .read_with(&carrier, Some(&out), None, true)
        .expect("read_with(overwrite)");
    assert_eq!(std::fs::read(&out).expect("read back"), STRUCT_PAYLOAD);

    let restored = dir.join("restored.png");
    std::fs::write(&restored, b"stale").expect("seed restore target");

    let err = engine
        .restore(&carrier, Some(&restored), None, false)
        .expect_err("restore must refuse an existing destination");
    assert!(
        matches!(err, StrHideError::Rejection(_)),
        "expected Rejection, got {err:?}"
    );

    engine
        .restore_with(&carrier, Some(&restored), None, false, true)
        .expect("restore_with(overwrite)");
    assert_eq!(
        std::fs::read(&restored).expect("read back"),
        PNG,
        "restored carrier must be bit-identical to the original"
    );
}
