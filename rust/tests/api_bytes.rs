// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! In-memory carrier API (`*_carrier_bytes`).
//!
//! These cover the contract the file API cannot: no temp file, no rename, no
//! `.bak`, no timestamp cloning — while the envelope itself, the AEAD path, the
//! self-verification and the restore hash check stay identical. Each test
//! therefore cross-checks the byte API against the file API rather than only
//! against itself.

use strhide::engine::{
    PayloadSource, ReadResult, WriteOptions, read_carrier_bytes, read_carrier_with_profile,
    remove_carrier_bytes, remove_carrier_with, write_carrier_bytes, write_carrier_with,
};
use strhide::errors::StrHideError;
use strhide::params::{LocalParams, Profile};

const PNG: &[u8] = include_bytes!("assets/minimal.png");
const PASSWORD: &str = "ByteApiP@ssw0rd2026!";

fn payload(bytes: &[u8]) -> PayloadSource<'_> {
    PayloadSource::Bytes(bytes)
}

/// Write through the bytes API, then read it back through the same API.
#[test]
fn write_read_roundtrip_stays_in_memory() {
    let (stego, result) = write_carrier_bytes(
        PNG,
        payload(b"in-memory payload"),
        &WriteOptions::default(),
        &LocalParams::default(),
        &Profile::default(),
    )
    .expect("write bytes");

    assert!(result.ube_size > 0);
    assert_eq!(result.carrier, "<memory>");
    assert!(result.backup_file.is_none(), "no filesystem, no backup");
    assert_ne!(stego, PNG, "the carrier must actually change");

    let read: ReadResult =
        read_carrier_bytes(&stego, None, &Profile::default()).expect("read bytes");
    assert_eq!(read.data, b"in-memory payload");
    assert_eq!(read.carrier, "<memory>");
    assert!(
        read.written_file.is_none(),
        "read_carrier_bytes must never write a file"
    );
    assert!(read.is_file);
    assert_eq!(read.filename, "payload.bin");
}

/// The byte API and the file API must agree byte for byte on the envelope
/// *format*: a carrier written in memory has to be readable from disk and vice
/// versa, otherwise the two paths have silently drifted.
#[test]
fn byte_api_and_file_api_are_cross_readable() {
    let dir = tempdir();
    let carrier_path = dir.join("carrier.png");
    std::fs::write(&carrier_path, PNG).expect("write carrier");

    // Memory write -> file read
    let (stego_bytes, _) = write_carrier_bytes(
        PNG,
        payload(b"cross-readable"),
        &WriteOptions {
            password: Some(PASSWORD),
            ..WriteOptions::default()
        },
        &LocalParams::default(),
        &Profile::default(),
    )
    .expect("write bytes");
    let stego_path = dir.join("from-memory.png");
    std::fs::write(&stego_path, &stego_bytes).expect("write stego");
    let from_disk = read_carrier_with_profile(
        &stego_path,
        None,
        Some(PASSWORD),
        false,
        &Profile::default(),
    )
    .expect("file read of memory-written carrier");
    assert_eq!(from_disk.data, b"cross-readable");

    // File write -> memory read
    let file_stego = dir.join("from-file.png");
    write_carrier_with(
        &carrier_path,
        payload(b"other-way-around"),
        &WriteOptions {
            output_path: Some(&file_stego),
            password: Some(PASSWORD),
            ..WriteOptions::default()
        },
        &LocalParams::default(),
        &Profile::default(),
    )
    .expect("file write");
    let disk_bytes = std::fs::read(&file_stego).expect("read stego file");
    let from_memory = read_carrier_bytes(&disk_bytes, Some(PASSWORD), &Profile::default())
        .expect("memory read of file-written carrier");
    assert_eq!(from_memory.data, b"other-way-around");

    cleanup(dir);
}

/// The restore path must reproduce the original carrier exactly, and must refuse
/// to pretend otherwise when the hashes do not line up.
#[test]
fn remove_returns_the_original_bytes() {
    let (stego, _) = write_carrier_bytes(
        PNG,
        payload(b"restore me exactly"),
        &WriteOptions::default(),
        &LocalParams::default(),
        &Profile::default(),
    )
    .expect("write bytes");

    let (restored, result) =
        remove_carrier_bytes(&stego, None, &Profile::default()).expect("remove bytes");
    assert_eq!(restored, PNG, "restore must be bit-for-bit lossless");
    assert_eq!(result.restored_size, PNG.len() as u64);
    assert!(result.verified_identical);
    assert!(result.backup_file.is_none());
    assert_eq!(result.carrier, "<memory>");
}

/// A wrong password must fail the same way it does on the file path: a
/// `Password`/`NoHiddenData` error, never payload bytes.
#[test]
fn wrong_password_is_rejected() {
    let (stego, _) = write_carrier_bytes(
        PNG,
        payload(b"secret"),
        &WriteOptions {
            password: Some(PASSWORD),
            ..WriteOptions::default()
        },
        &LocalParams::default(),
        &Profile::default(),
    )
    .expect("write bytes");

    let err = read_carrier_bytes(&stego, Some("not-the-password"), &Profile::default())
        .expect_err("wrong password must fail");
    assert!(
        matches!(
            err,
            StrHideError::Password(_)
                | StrHideError::NoHiddenData(_)
                | StrHideError::CorruptedData(_)
        ),
        "unexpected error variant: {err:?}"
    );

    // No password at all: the envelope declares FLAG_ENCRYPTED, so the reader
    // must ask for one instead of trying the profile secret.
    let err = read_carrier_bytes(&stego, None, &Profile::default()).expect_err("password required");
    assert!(matches!(err, StrHideError::Password(_)));
}

/// `output_path` is meaningless here; silently ignoring it would write files
/// from a "give me bytes" function, so it is rejected.
#[test]
fn output_path_is_rejected_in_the_bytes_api() {
    let dir = tempdir();
    let out = dir.join("nope.png");
    let err = write_carrier_bytes(
        PNG,
        payload(b"x"),
        &WriteOptions {
            output_path: Some(&out),
            ..WriteOptions::default()
        },
        &LocalParams::default(),
        &Profile::default(),
    )
    .expect_err("output_path must be rejected");
    assert!(
        format!("{err}").contains("output_path"),
        "the error must name the offending field: {err}"
    );
    assert!(!out.exists(), "nothing may be written");
    cleanup(dir);
}

/// A carrier that already holds an envelope must be refused, exactly like the
/// file path (stacking a second envelope silently is the bug this prevents).
#[test]
fn already_occupied_carrier_is_refused() {
    let (stego, _) = write_carrier_bytes(
        PNG,
        payload(b"first"),
        &WriteOptions::default(),
        &LocalParams::default(),
        &Profile::default(),
    )
    .expect("write bytes");

    let err = write_carrier_bytes(
        &stego,
        payload(b"second"),
        &WriteOptions::default(),
        &LocalParams::default(),
        &Profile::default(),
    )
    .expect_err("a second envelope must be refused");
    assert!(
        format!("{err}").contains("already contains hidden data"),
        "{err}"
    );
}

/// Stealth mode is a password-derived-magic feature; it must behave identically
/// in memory (and fail fast without a password).
#[test]
fn stealth_works_in_memory_and_requires_a_password() {
    let err = write_carrier_bytes(
        PNG,
        payload(b"x"),
        &WriteOptions {
            stealth: true,
            ..WriteOptions::default()
        },
        &LocalParams::default(),
        &Profile::default(),
    )
    .expect_err("stealth without a password must fail");
    assert!(format!("{err}").contains("Stealth mode requires a password"));

    let (stego, result) = write_carrier_bytes(
        PNG,
        payload(b"stealth payload"),
        &WriteOptions {
            stealth: true,
            password: Some(PASSWORD),
            ..WriteOptions::default()
        },
        &LocalParams::default(),
        &Profile::default(),
    )
    .expect("stealth write bytes");
    assert!(result.is_stealth);
    assert!(result.is_encrypted);

    // A stealth envelope is invisible without the password, so a passwordless
    // read must report "no data" rather than a distinguishable error.
    let err = read_carrier_bytes(&stego, None, &Profile::default()).expect_err("no password");
    assert!(matches!(err, StrHideError::NoHiddenData(_)), "{err:?}");

    let read = read_carrier_bytes(&stego, Some(PASSWORD), &Profile::default()).expect("read");
    assert_eq!(read.data, b"stealth payload");
}

/// Removing through the file API and the byte API must produce identical bytes.
#[test]
fn byte_and_file_remove_agree() {
    let dir = tempdir();
    let carrier_path = dir.join("carrier.png");
    std::fs::write(&carrier_path, PNG).expect("write carrier");

    let stego_path = dir.join("stego.png");
    write_carrier_with(
        &carrier_path,
        payload(b"agree"),
        &WriteOptions {
            output_path: Some(&stego_path),
            ..WriteOptions::default()
        },
        &LocalParams::default(),
        &Profile::default(),
    )
    .expect("file write");

    let file_restored = dir.join("restored.png");
    remove_carrier_with(
        &stego_path,
        Some(&file_restored),
        None,
        false,
        &Profile::default(),
    )
    .expect("file remove");
    let from_file = std::fs::read(&file_restored).expect("read restored");

    let stego_bytes = std::fs::read(&stego_path).expect("read stego");
    let (from_memory, _) =
        remove_carrier_bytes(&stego_bytes, None, &Profile::default()).expect("memory remove");

    assert_eq!(
        from_file, from_memory,
        "both paths must restore identically"
    );
    assert_eq!(from_memory, PNG);
    cleanup(dir);
}

/// Wire-compatibility matrix for the dialect knob.
///
/// Four rows, and all four have to hold at once or the "private dialect" story
/// is a half-truth: same profile interops, private-vs-official must not, and the
/// failure must not be distinguishable from "no envelope here".
#[test]
fn profile_compatibility_matrix() {
    use strhide::params::MagicPair;

    let private = Profile::default()
        .with_default_secret("matrix-private-envelope-key")
        .with_magic(MagicPair {
            header: *b"\xA1\xB2\xC3\xD4\xE5\xF6\x07\x18",
            trailer: *b"\xA1\xB2\xC3\xD4",
        });

    // Row 1 + 2: official<->official and private<->private.
    for (label, profile) in [
        ("official", Profile::default()),
        ("private", private.clone()),
    ] {
        let (stego, _) = write_carrier_bytes(
            PNG,
            payload(b"matrix"),
            &WriteOptions::default(),
            &LocalParams::default(),
            &profile,
        )
        .unwrap_or_else(|e| panic!("{label}: write failed: {e}"));
        let read = read_carrier_bytes(&stego, None, &profile)
            .unwrap_or_else(|e| panic!("{label}: self-read failed: {e}"));
        assert_eq!(read.data, b"matrix", "{label}: same profile must interop");
    }

    // Row 3 + 4: private carrier under the official profile and the reverse
    // must both fail as `NoHiddenData`.
    let (private_stego, _) = write_carrier_bytes(
        PNG,
        payload(b"matrix"),
        &WriteOptions::default(),
        &LocalParams::default(),
        &private,
    )
    .expect("private write");
    let err = read_carrier_bytes(&private_stego, None, &Profile::default())
        .expect_err("official profile must not read a private carrier");
    assert!(
        matches!(err, StrHideError::NoHiddenData(_)),
        "cross-dialect failure must look like 'nothing here', got {err:?}"
    );

    let (official_stego, _) = write_carrier_bytes(
        PNG,
        payload(b"matrix"),
        &WriteOptions::default(),
        &LocalParams::default(),
        &Profile::default(),
    )
    .expect("official write");
    let err = read_carrier_bytes(&official_stego, None, &private)
        .expect_err("private profile must not read an official carrier");
    assert!(
        matches!(err, StrHideError::NoHiddenData(_)),
        "cross-dialect failure must look like 'nothing here', got {err:?}"
    );
}

// --- helpers ---------------------------------------------------------------

fn tempdir() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    p.push(format!("strhide-bytes-api-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&p).expect("create temp dir");
    p
}

fn cleanup(dir: std::path::PathBuf) {
    let _ = std::fs::remove_dir_all(dir);
}
