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
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use strhide::structure::adapters::pdf::parse_pdf_trailer_info;
use strhide::structure::envelope::EnvelopeHeader;
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

/// XRef-stream PDF whose dictionary nests `/DecodeParms << ... >>` *before*
/// `/Size`, `/Root` (and an optional `/Encrypt`). `/Size 20` is deliberately
/// larger than the highest `N G obj` in the tail (4), so a scanner that
/// truncates at the nested `>>` derives the wrong next object number (review
/// P1-3).
fn make_xref_stream_pdf_nested_decode_parms(encrypt: Option<&str>) -> Vec<u8> {
    let mut doc = b"%PDF-1.5\n\
        1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
        2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
        3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        .to_vec();
    let xref_offset = doc.len();
    let enc = encrypt
        .map(|e| format!("/Encrypt {e}\n"))
        .unwrap_or_default();
    let dict = format!(
        "<< /Type /XRef\n/DecodeParms << /Columns 5 /Predictor 12 >>\n\
         /Size 20\n/Root 1 0 R\n{enc}/Length 20\n>>"
    );
    doc.extend_from_slice(format!("4 0 obj\n{dict}\nstream\n").as_bytes());
    doc.extend_from_slice(&[0u8; 20]);
    doc.extend_from_slice(
        format!("\nendstream\nendobj\nstartxref\n{xref_offset}\n%%EOF\n").as_bytes(),
    );
    doc
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

/// Rewrite one header field *logically*.
///
/// The default-mode header is XOR-masked, so writing raw bytes at a field
/// offset does not produce a predictable logical value. This unpacks with the
/// official profile, applies `mutate`, and repacks with the same mask, which is
/// what a forger with the public default key could do.
fn repack_header_field(out: &Path, ube_offset: u64, mutate: impl FnOnce(&mut EnvelopeHeader)) {
    use strhide::structure::envelope::HEADER_SIZE;
    use strhide::structure::params::StructureProfile;
    let mut data = fs::read(out).unwrap();
    let start = ube_offset as usize;
    let mut header =
        EnvelopeHeader::unpack_with_password(&data[start..start + HEADER_SIZE], None).unwrap();
    mutate(&mut header);
    let packed = header
        .pack_with_profile(None, &StructureProfile::default())
        .unwrap();
    data[start..start + HEADER_SIZE].copy_from_slice(&packed);
    fs::write(out, data).unwrap();
}

/// Tamper the envelope version field at `ube_offset + 8` ensuring the write is
/// never a no-op against a masked byte and always yields an unsupported version.
fn tamper_version_field(out: &Path, ube_offset: u64) {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(out)
        .unwrap();
    f.seek(SeekFrom::Start(ube_offset + 8)).unwrap();
    let mut orig = [0u8; 1];
    f.read_exact(&mut orig).unwrap();
    let tampered = if orig[0] == 0x09 { 0x0A } else { 0x09 };
    f.seek(SeekFrom::Start(ube_offset + 8)).unwrap();
    f.write_all(&[tampered]).unwrap();
}

// --------------------------------------------------------------------------- #14: PDF object number derivation

#[test]
fn pdf_xref_stream_object_number_from_tail() {
    let info = parse_pdf_trailer_info(&mut std::io::Cursor::new(make_xref_stream_pdf())).unwrap();
    assert_eq!(info.new_obj_num, 5, "next object number must be max(N)+1");
    assert_eq!(info.root_ref.as_deref(), Some("1 0 R"));
}

#[test]
fn pdf_xref_stream_nested_decode_parms_is_not_truncated() {
    let info = parse_pdf_trailer_info(&mut std::io::Cursor::new(
        make_xref_stream_pdf_nested_decode_parms(None),
    ))
    .unwrap();
    assert_eq!(
        info.new_obj_num, 20,
        "/Size must be read past the nested /DecodeParms dictionary"
    );
    assert_eq!(info.root_ref.as_deref(), Some("1 0 R"));
    assert!(
        info.uses_xref_stream,
        "the newest section is an XRef stream, so the update must be one too"
    );
}

#[test]
fn pdf_xref_stream_nested_decode_parms_still_detects_encryption() {
    let err = match parse_pdf_trailer_info(&mut std::io::Cursor::new(
        make_xref_stream_pdf_nested_decode_parms(Some("9 0 R")),
    )) {
        Ok(_) => panic!("an encrypted XRef-stream document must refuse the incremental update"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("encrypted"),
        "a /Encrypt after a nested dictionary must still refuse the update: {err}"
    );
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
    // The update must repeat the document's dialect: an XRef stream object,
    // never a classic `xref` table after an XRef-stream section (P1-3).
    assert!(
        stego.windows(11).any(|w| w == b"/Type /XRef"),
        "xref-stream document received a classic update"
    );
    assert!(
        stego.windows(9).any(|w| w == b"\n6 0 obj\n"),
        "the new XRef stream object must follow the envelope object"
    );
    assert!(
        !stego.windows(9).any(|w| w == b"\nxref\n5 1\n"),
        "a pure XRef-stream document must not receive a classic xref table"
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

/// The backward `%%EOF` scan is capped at 1 MiB from the effective PDF tail.
/// An overlay *larger* than that cap must still be excluded, otherwise the
/// host's marker sits outside the window and L1 calls a freshly written carrier
/// corrupted (review P1-3, defect 3).
#[test]
fn pdf_l1_survives_an_overlay_beyond_the_one_mib_search_depth() {
    let dir = scratch("pdf_huge_overlay");
    let carrier = dir.join("c.pdf");
    let out = dir.join("o.pdf");
    let restored = dir.join("r.pdf");
    fs::write(&carrier, make_pdf_without_root()).unwrap();

    // 1.3 MiB plaintext → the sealed envelope exceeds the 1 MiB scan depth.
    let payload: Vec<u8> = (0..1300 * 1024).map(|i| (i % 251) as u8).collect();
    let res = write_carrier(
        &carrier,
        PayloadSource::Bytes(&payload),
        &WriteOptions {
            output_path: Some(&out),
            strategy: "eof",
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(res.strategy.name(), "eof");

    let v = verify_carrier(&out, None).unwrap();
    assert!(
        v.level1_host.ok,
        "L1 must anchor the search at the envelope, not at the physical tail: {}",
        v.level1_host.detail
    );
    assert!(v.level2_envelope.ok, "{}", v.level2_envelope.detail);

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

#[test]
fn verify_detects_unsupported_envelope_version() {
    let dir = scratch("verify_version");
    let (out, ube_offset) = write_eof_envelope(&dir, "v");

    // version field sits at header offset 8
    tamper_version_field(&out, ube_offset);

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

    // Claim far more than the envelope carries so hint+meta+136 exceeds the
    // total size. The value stays below `MAX_META_LEN` on purpose: this case is
    // about the size consistency check, not the field-range cap (covered by
    // `verify_rejects_a_meta_len_above_the_metadata_cap`).
    repack_header_field(&out, ube_offset, |header| header.meta_len = 100_000);

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
fn verify_rejects_a_meta_len_above_the_metadata_cap() {
    // A metadata block is at most a filename plus a fixed tail, so the reader
    // refuses anything past `MAX_META_LEN` before it sizes a buffer from the
    // field. Without this cap a forged 4 GiB `meta_len` reached
    // `vec![0u8; meta_len]` and an allocation failure aborted the process
    // (review P0-2).
    let dir = scratch("verify_metalen_cap");
    let (out, ube_offset) = write_eof_envelope(&dir, "mc");

    repack_header_field(&out, ube_offset, |header| header.meta_len = u32::MAX);

    let res = verify_carrier(&out, None).unwrap();
    assert!(
        !res.level2_envelope.ok,
        "meta_len above the metadata cap passed Level 2"
    );
    assert!(
        res.level2_envelope.detail.contains("exceeds maximum"),
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
