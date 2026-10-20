//! End-to-end coverage for the compact metadata block (2026-10-18).
//!
//! The metadata block moved from a 137-byte JSON blob to a ~46-byte binary
//! layout (`FLAG_COMPACT_META`). These tests pin the resulting envelope sizes
//! and re-check the full write → read → verify → remove chain, including the
//! `pe_codebits` strategy whose capacity is the reason the change exists.

use crate::common::*;
use std::fs;
use std::path::Path;

use strhide::engine::{
    PayloadSource, WriteOptions, read_carrier, remove_carrier, verify_carrier, write_carrier,
};

fn png() -> Vec<u8> {
    include_bytes!("../assets/minimal.png").to_vec()
}

fn write(
    carrier: &Path,
    payload: &Path,
    password: Option<&str>,
    strategy: &str,
    hint: Option<&str>,
    out: &Path,
) -> u64 {
    write_carrier(
        carrier,
        PayloadSource::File(payload),
        &WriteOptions {
            output_path: Some(out),
            password,
            password_hint: hint,
            strategy,
            backup: false,
            ..Default::default()
        },
    )
    .unwrap()
    .ube_size
}

#[test]
fn smallest_envelopes_match_the_documented_minimums() {
    let dir = scratch("sizes");
    let carrier = dir.join("c.png");
    fs::write(&carrier, png()).unwrap();
    let payload = dir.join("s.txt");
    fs::write(&payload, b"A").unwrap();

    // With uniform encryption (builtin default key for zero-password mode),
    // both default and custom-password modes produce the same encrypted envelope size:
    // 112 header + (46 meta + 16 tag) + (1 payload + 4 chunk len + 16 tag) + 24 trailer = 219.
    let plain = write(
        &carrier,
        &payload,
        None,
        "auto",
        None,
        &dir.join("plain.png"),
    );
    assert_eq!(plain, 219, "default envelope size changed: {plain}");

    // +16 meta tag, +4 chunk length, +16 chunk tag over the plain envelope.
    let enc = write(
        &carrier,
        &payload,
        Some("pw"),
        "auto",
        None,
        &dir.join("enc.png"),
    );
    assert_eq!(enc, 219, "encrypted envelope size changed: {enc}");
    assert!(enc <= strhide::envelope::MIN_UBE_ENCRYPTED as u64 + 10);

    // Hint bytes are stored verbatim in front of the metadata block.
    let hinted = write(
        &carrier,
        &payload,
        Some("pw"),
        "auto",
        Some("abcd"),
        &dir.join("hint.png"),
    );
    assert_eq!(hinted, enc + 4);
}

#[test]
fn compact_metadata_survives_the_full_cycle() {
    let dir = scratch("cycle");
    let carrier = dir.join("c.png");
    fs::write(&carrier, png()).unwrap();
    let payload = dir.join("报告 v2.txt");
    fs::write(&payload, b"hello compact metadata").unwrap();
    let stego = dir.join("stego.png");

    write(&carrier, &payload, Some("pw"), "auto", None, &stego);

    let out = read_carrier(&stego, None, Some("pw")).unwrap();
    assert_eq!(out.data, b"hello compact metadata");
    assert_eq!(out.filename, "报告 v2.txt");

    let v = verify_carrier(&stego, Some("pw")).unwrap();
    assert!(v.level1_host.ok, "{}", v.level1_host.detail);
    assert!(v.level2_envelope.ok, "{}", v.level2_envelope.detail);
    assert!(v.level3_crypto.ok, "{}", v.level3_crypto.detail);

    let restored = dir.join("restored.png");
    remove_carrier(&stego, Some(&restored), Some("pw"), false).unwrap();
    assert_eq!(fs::read(&restored).unwrap(), png());
}
