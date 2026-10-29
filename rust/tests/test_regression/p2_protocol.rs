// Regression tests for P2 protocol/diagnostic fixes (2026-10-17), batch 2.
//
// - #11: `verify_carrier` Level 2 must validate the envelope header (version
//   / hint_len / meta_len consistency) instead of only checking the trailer.
// - #14: xref-stream PDFs (no `trailer` keyword) must derive the next object
//   number from the tail's `N G obj` definitions instead of a hardcoded 9999,
//   must recover `/Root` from the tail, and must be refused when no `/Root`
//   exists at all (incremental would break the document tree).

use crate::common::*;
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use strhide::structure::adapters::pdf::parse_pdf_trailer_info;
use strhide::structure::{
    PayloadSource, ReadOptions, RestoreOptions, WriteOptions, read_carrier, remove_carrier,
    verify_carrier, write_carrier,
};

// --------------------------------------------------------------------------- helpers

/// xref-stream PDF (PDF 1.5+): no `trailer` keyword; the trailer dict lives
/// inside the XRef stream object. Highest object number is 4, so the next free
/// number is 5, and `/Root 1 0 R` is only recoverable from the tail.
fn make_xref_stream_pdf() -> Vec<u8> {
    b"%PDF-1.5\n\
      1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
      2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
      3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n\
      4 0 obj\n<< /Type /XRef /Root 1 0 R /Size 5 /Length 20 >>\nstream\n\
      \x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\n\
      endstream\nendobj\n\
      startxref\n170\n%%EOF\n"
        .to_vec()
}

fn make_minimal_png() -> Vec<u8> {
    include_bytes!("../assets/minimal.png").to_vec()
}

/// Write a plaintext EOF-strategy envelope and return (output path, ube offset).
fn write_eof_envelope(dir: &Path, name: &str) -> (PathBuf, u64) {
    let carrier = dir.join(format!("{name}.png"));
    let out = dir.join(format!("{name}.out"));
    fs::write(&carrier, make_minimal_png()).unwrap();
    write_carrier(
        &carrier,
        PayloadSource::Text("x"),
        &WriteOptions {
            output_path: Some(&out),
            strategy: "eof",
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();
    // EOF strategy appends at the end of the host, so the envelope starts at
    // the original carrier size.
    let ube_offset = fs::metadata(&carrier).unwrap().len();
    (out, ube_offset)
}

/// Patch `len` bytes at `ube_offset + field_offset` inside a written carrier.
fn patch_header_field(out: &Path, ube_offset: u64, field_offset: u64, bytes: &[u8]) {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(out)
        .unwrap();
    f.seek(SeekFrom::Start(ube_offset + field_offset)).unwrap();
    f.write_all(bytes).unwrap();
}

// --------------------------------------------------------------------------- #14: PDF object number derivation

#[test]
fn pdf_xref_stream_object_number_from_tail() {
    let info = parse_pdf_trailer_info(&mut std::io::Cursor::new(make_xref_stream_pdf())).unwrap();
    assert_eq!(info.new_obj_num, 5, "next object number must be max(N)+1");
    assert_eq!(info.root_ref.as_deref(), Some("1 0 R"));
}

#[test]
fn pdf_xref_stream_incremental_write_roundtrip() {
    let dir = scratch("pdf_xref");
    let carrier = dir.join("c.pdf");
    let out = dir.join("o.pdf");
    fs::write(&carrier, make_xref_stream_pdf()).unwrap();

    // auto must still select incremental (trailer info is recoverable)
    let res = write_carrier(
        &carrier,
        PayloadSource::Text("xref stream secret"),
        &WriteOptions {
            output_path: Some(&out),
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(res.strategy.name(), "incremental");

    // The injected object must use the derived number 5, not 9999.
    let stego = fs::read(&out).unwrap();
    assert!(
        stego.windows(9).any(|w| w == b"\n5 0 obj\n"),
        "injected object number not derived from tail scan"
    );
    assert!(
        stego.windows(11).any(|w| w == b"/Root 1 0 R"),
        "incremental trailer missing recovered /Root"
    );

    // Full lossless lifecycle still holds.
    let read = read_carrier(
        &out,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(read.data, b"xref stream secret");
    remove_carrier(
        &out,
        &RestoreOptions {
            output_path: None,
            password: None,
            backup: false,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(fs::read(&out).unwrap(), make_xref_stream_pdf());
}

#[test]
fn pdf_without_root_is_rejected_for_incremental() {
    let broken = make_pdf_without_root();
    assert!(parse_pdf_trailer_info(&mut std::io::Cursor::new(broken.clone())).is_err());

    let dir = scratch("pdf_noroot");
    let carrier = dir.join("c.pdf");
    let out = dir.join("o.pdf");
    fs::write(&carrier, &broken).unwrap();

    // The document is structurally valid: a newest trailer may inherit `/Root`
    // from an earlier revision through `/Prev`. Only the incremental-update
    // *writer* needs the local reference, so L1 must not call this corruption.
    let v = verify_carrier(&carrier, None).unwrap();
    assert!(
        v.level1_host.ok,
        "L1 must accept a /Root-less newest trailer: {}",
        v.level1_host.detail
    );
    assert!(
        v.level1_host.detail.contains("inherited"),
        "detail should explain why: {}",
        v.level1_host.detail
    );

    // auto falls back to the lossless EOF overlay
    let res = write_carrier(
        &carrier,
        PayloadSource::Text("noroot"),
        &WriteOptions {
            output_path: Some(&out),
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(res.strategy.name(), "eof");

    // explicit incremental fails with a clear message
    let err = write_carrier(
        &carrier,
        PayloadSource::Text("noroot"),
        &WriteOptions {
            output_path: Some(&out),
            strategy: "incremental",
            backup: false,
            overwrite: true,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("/Root"), "{err}");
}

// --------------------------------------------------------------------------- large EOF overlay vs. the tail window

/// `verify` used to look for `%%EOF` only in the last 64 KiB, so an EOF-overlay
/// envelope bigger than that pushed the host's marker out of the window and L1
/// reported a carrier strhide had just written as corrupted. The corpus size
/// sweep (`batch_corpus`) hit this at 128 KiB.
#[test]
fn pdf_l1_survives_an_overlay_larger_than_the_tail_window() {
    let dir = scratch("pdf_big_overlay");
    let carrier = dir.join("c.pdf");
    let out = dir.join("o.pdf");
    let restored = dir.join("r.pdf");
    // No `/Root` in the newest trailer, so `auto` falls back to EOF overlay.
    fs::write(&carrier, make_pdf_without_root()).unwrap();

    // 200 KiB: three backwards scan chunks, marker far outside the old window.
    let payload: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
    let res = write_carrier(
        &carrier,
        PayloadSource::Bytes(&payload),
        &WriteOptions {
            output_path: Some(&out),
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(res.strategy.name(), "eof");

    let v = verify_carrier(&out, None).unwrap();
    assert!(
        v.level1_host.ok,
        "L1 must find %%EOF behind the envelope: {}",
        v.level1_host.detail
    );
    assert!(
        v.level2_envelope.ok,
        "L2 must locate the envelope: {}",
        v.level2_envelope.detail
    );

    assert_eq!(
        read_carrier(
            &out,
            &ReadOptions {
                output_path: None,
                password: None,
                overwrite: false,
                ..Default::default()
            }
        )
        .unwrap()
        .data,
        payload
    );
    remove_carrier(
        &out,
        &RestoreOptions {
            output_path: Some(&restored),
            password: None,
            backup: false,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(fs::read(&restored).unwrap(), fs::read(&carrier).unwrap());
}

// --------------------------------------------------------------------------- #11: verify L2 header validation

#[test]
fn verify_detects_unsupported_envelope_version() {
    let dir = scratch("verify_version");
    let (out, ube_offset) = write_eof_envelope(&dir, "v");

    // version field sits at header offset 8
    patch_header_field(&out, ube_offset, 8, &[0x09]);

    let res = verify_carrier(&out, None).unwrap();
    assert!(
        !res.level2_envelope.ok,
        "unsupported version passed Level 2"
    );
    assert!(
        res.level2_envelope.detail.contains("version"),
        "unexpected detail: {}",
        res.level2_envelope.detail
    );
}

#[test]
fn verify_detects_inconsistent_meta_len() {
    let dir = scratch("verify_metalen");
    let (out, ube_offset) = write_eof_envelope(&dir, "m");

    // meta_len field sits at header offset 104; claim far more than the
    // envelope carries so hint+meta+136 exceeds the total size.
    patch_header_field(&out, ube_offset, 104, &0xFFFFFFF0u32.to_le_bytes());

    let res = verify_carrier(&out, None).unwrap();
    assert!(
        !res.level2_envelope.ok,
        "inconsistent meta_len passed Level 2"
    );
    assert!(
        res.level2_envelope.detail.contains("inconsistent"),
        "unexpected detail: {}",
        res.level2_envelope.detail
    );
}

#[test]
fn verify_accepts_untampered_carrier() {
    let dir = scratch("verify_ok");
    let (out, _) = write_eof_envelope(&dir, "ok");

    let res = verify_carrier(&out, None).unwrap();
    assert!(res.level1_host.ok, "{}", res.level1_host.detail);
    assert!(res.level2_envelope.ok, "{}", res.level2_envelope.detail);
    assert!(res.level3_crypto.ok, "{}", res.level3_crypto.detail);
}

// --------------------------------------------------------------------------- #12: default strip patch coordinates

/// The default `strip` implementation must translate the stego-coordinate
/// `patch_offset` into the stripped stream by subtracting `inject_size`.
/// Only the ZIP adapter emits a real patch (and overrides strip), so this is
/// tested directly against the default implementation via the PNG adapter.
#[test]
fn default_strip_restores_patch_in_stripped_coordinates() {
    use std::io::Cursor;
    use strhide::structure::adapters::HostAdapter;
    use strhide::structure::adapters::png::PngAdapter;
    use strhide::structure::envelope::EnvelopeHeader;

    // Host with a 4-byte patchable field at offset 60.
    let mut host = vec![0xAAu8; 100];
    host[60..64].copy_from_slice(&0x11223344u32.to_le_bytes());

    // Stego = host with 10 bytes injected at offset 30, and the field at
    // host offset 60 overwritten by the "patched" value 0x55667788.
    let mut stego = Vec::new();
    stego.extend_from_slice(&host[..30]);
    stego.extend_from_slice(&[0xEEu8; 10]);
    stego.extend_from_slice(&host[30..]);
    // Field now lives at stego offset 70 (30 + 10 + 30).
    stego[70..74].copy_from_slice(&0x55667788u32.to_le_bytes());

    let header = EnvelopeHeader {
        inject_offset: 30,
        inject_size: 10,
        patch_offset: 70,           // stego coordinates
        orig_patch_val: 0x11223344, // value to restore
        ..Default::default()
    };

    let mut stego_in = Cursor::new(stego);
    let mut out = Cursor::new(Vec::new());
    PngAdapter.strip(&mut stego_in, &mut out, &header).unwrap();

    let restored = out.into_inner();
    assert_eq!(restored.len(), host.len(), "stripped size mismatch");
    assert_eq!(
        restored, host,
        "patch was not restored in stripped coordinates"
    );
}
