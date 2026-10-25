// Findings lockdown for the structure-domain code review of 2026-10-25
// (docs/structure_domain_code_review_20261025.md).
//
// Each test pins one P1/P2 finding: the review's malicious/edge-case carriers
// must fail as clean errors (never panic) or fall back to a lossless
// strategy, and the fixed paths must still roundtrip byte-exactly.

use crate::common::*;
use std::fs;
use std::io::Cursor;
use std::path::Path;
use strhide::adapters::{HostAdapter, WavAdapter, ZipAdapter};
use strhide::engine::{PayloadSource, WriteOptions, read_carrier, remove_carrier, write_carrier};
use strhide::envelope::{EnvelopeTrailer, STANDARD_TRAILER_MAGIC};

fn write_carrier_file(
    carrier: &Path,
    payload: PayloadSource,
    password: Option<&str>,
    strategy: &str,
    stealth: bool,
    out: &Path,
) -> strhide::engine::WriteResult {
    write_carrier(
        carrier,
        payload,
        &WriteOptions {
            output_path: Some(out),
            password,
            strategy,
            stealth,
            backup: false,
            ..Default::default()
        },
    )
    .unwrap()
}

/// A 22-byte ZIP consisting of nothing but an EOCD record with a zero Central
/// Directory offset: a legal empty archive whose pre-CD injection point would
/// be file offset 0, overwriting the archive's own magic and leaving the
/// stego undetectable by any adapter (P2-6).
fn make_empty_zip() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&0u16.to_le_bytes()); // entries on this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // entries total
    out.extend_from_slice(&0u32.to_le_bytes()); // cd size
    out.extend_from_slice(&0u32.to_le_bytes()); // cd offset
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    out
}

#[test]
fn zip_empty_archive_auto_falls_back_to_eof() {
    let zip = make_empty_zip();
    assert!(
        ZipAdapter.detect(&mut Cursor::new(zip.clone())),
        "an EOCD-only archive must still be detected as ZIP"
    );
    assert_eq!(
        ZipAdapter.choose_auto_strategy(&mut Cursor::new(zip.clone()), 128),
        "eof",
        "auto must not pick a strategy that would inject at offset 0"
    );

    let err = ZipAdapter
        .inject(
            &mut Cursor::new(zip.clone()),
            &mut Cursor::new(vec![0u8; 128]),
            &mut Vec::new(),
            "pre_cd_inject",
        )
        .unwrap_err();
    assert!(err.to_string().contains("Empty archive"), "{err}");

    // End-to-end: auto writes an EOF envelope that reads and restores cleanly.
    let dir = scratch("rv25_zip_empty");
    let carrier = dir.join("empty.zip");
    fs::write(&carrier, &zip).unwrap();
    let stego = dir.join("s.zip");
    let res = write_carrier_file(
        &carrier,
        PayloadSource::Text("empty zip secret"),
        None,
        "auto",
        false,
        &stego,
    );
    assert_eq!(res.strategy, "eof");
    let out = read_carrier(&stego, None, None).unwrap();
    assert_eq!(out.data, b"empty zip secret");
    let restored = dir.join("r.zip");
    remove_carrier(&stego, Some(&restored), None, false).unwrap();
    assert_eq!(fs::read(&restored).unwrap(), zip);
}

/// A WAV whose declared RIFF boundary is not the physical end of the file
/// (trailing garbage, or a streaming size = 0 header) must be rejected for
/// `riff_chunk`: the SHRD chunk lands past the declared boundary where locate
/// cannot reach it for odd-sized envelopes (P1-2).
#[test]
fn wav_riff_chunk_rejected_when_declared_boundary_mismatches() {
    let mut trailing = make_wav();
    trailing.extend_from_slice(b"ID3JUNK");
    let err = WavAdapter
        .inject(
            &mut Cursor::new(trailing),
            &mut Cursor::new(vec![0u8; 128]),
            &mut Vec::new(),
            "riff_chunk",
        )
        .unwrap_err();
    assert!(err.to_string().contains("declared RIFF size"), "{err}");

    let mut streaming = make_wav();
    streaming[4..8].copy_from_slice(&0u32.to_le_bytes()); // size = 0
    let err = WavAdapter
        .inject(
            &mut Cursor::new(streaming),
            &mut Cursor::new(vec![0u8; 128]),
            &mut Vec::new(),
            "riff_chunk",
        )
        .unwrap_err();
    assert!(err.to_string().contains("declared RIFF size"), "{err}");

    // A clean carrier must still inject, locate, and report the chunk layout.
    let clean = make_wav();
    let ube_total = 100u64 + 24;
    let mut ube = vec![0x5Au8; 100];
    ube.extend_from_slice(
        &EnvelopeTrailer::create(clean.len() as u64 + 8, ube_total, STANDARD_TRAILER_MAGIC).pack(),
    );
    let mut out = Vec::new();
    let (off, size, patch_off, orig) = WavAdapter
        .inject(
            &mut Cursor::new(clean.clone()),
            &mut Cursor::new(ube),
            &mut out,
            "riff_chunk",
        )
        .unwrap();
    assert_eq!(off, clean.len() as u64);
    assert_eq!(patch_off, 4, "the RIFF size field at offset 4 is patched");
    assert_eq!(orig, (clean.len() - 8) as u32);
    assert_eq!(size, 8 + ube_total);

    let (lo, ls, strat) = WavAdapter
        .locate(&mut Cursor::new(out), None)
        .unwrap()
        .unwrap();
    assert_eq!(strat, "riff_chunk");
    assert_eq!((lo, ls), (clean.len() as u64 + 8, ube_total));
}

/// End-to-end roundtrip over the item_hidden iinf/iloc patch and restore core
/// on the only in-CI carrier shape that reaches it (a synthetic meta-HEIF).
/// Covers review finding §7.1: without this fixture the whole strategy had
/// zero regular-suite coverage (P1-1/P2-1/P2-2/P2-3 all live on this path).
#[test]
fn heif_item_hidden_synthetic_roundtrip() {
    let dir = scratch("rv25_heif_meta");
    let carrier = dir.join("c.heif");
    fs::write(&carrier, make_heif_with_meta()).unwrap();
    let stego = dir.join("s.heif");
    let res = write_carrier_file(
        &carrier,
        PayloadSource::Text("meta heif secret"),
        None,
        "auto",
        false,
        &stego,
    );
    assert_eq!(
        res.strategy, "item_hidden",
        "auto must pick item_hidden for a meta-bearing HEIF"
    );
    let out = read_carrier(&stego, None, None).unwrap();
    assert_eq!(out.data, b"meta heif secret");
    let restored = dir.join("r.heif");
    remove_carrier(&stego, Some(&restored), None, false).unwrap();
    assert_eq!(fs::read(&restored).unwrap(), fs::read(&carrier).unwrap());
}

/// A non-item_hidden sanity check: the meta-less HEIF fixture keeps using the
/// uuid box strategy and must be unaffected by the item_hidden gating.
#[test]
fn heif_without_meta_still_uses_box_uuid() {
    let dir = scratch("rv25_heif_plain");
    let carrier = dir.join("c.heif");
    fs::write(&carrier, make_heif()).unwrap();
    let stego = dir.join("s.heif");
    let res = write_carrier_file(
        &carrier,
        PayloadSource::Text("plain heif secret"),
        None,
        "auto",
        false,
        &stego,
    );
    assert_eq!(res.strategy, "box_uuid");
    let out = read_carrier(&stego, None, None).unwrap();
    assert_eq!(out.data, b"plain heif secret");
    let restored = dir.join("r.heif");
    remove_carrier(&stego, Some(&restored), None, false).unwrap();
    assert_eq!(fs::read(&restored).unwrap(), fs::read(&carrier).unwrap());
}
