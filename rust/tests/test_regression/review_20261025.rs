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
use strhide::structure::adapters::{
    HeifAdapter, HostAdapter, JpegAdapter, PdfAdapter, WavAdapter, WebpAdapter, ZipAdapter,
};
use strhide::structure::envelope::{EnvelopeTrailer, STANDARD_TRAILER_MAGIC};
use strhide::structure::{
    PayloadSource, ReadOptions, RestoreOptions, WriteOptions, read_carrier, remove_carrier,
    verify_carrier, write_carrier,
};

fn write_carrier_file(
    carrier: &Path,
    payload: PayloadSource,
    password: Option<&str>,
    strategy: &str,
    stealth: bool,
    out: &Path,
) -> strhide::structure::WriteResult {
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
    assert_eq!(res.strategy.name(), "eof");
    let out = read_carrier(
        &stego,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(out.data, b"empty zip secret");
    let restored = dir.join("r.zip");
    remove_carrier(
        &stego,
        &RestoreOptions {
            output_path: Some(&restored),
            password: None,
            backup: false,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
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

/// P1-2: a declared RIFF size can match the file length even when the final
/// odd-sized chunk lacks its mandatory pad byte. A spec-compliant walker then
/// steps one byte past EOF, so the SHRD chunk appended by `riff_chunk` would
/// be parsed from its second byte and L1 would reject the stego we just wrote
/// (write succeeded, read/restore worked via the EOF fallback, verify stayed
/// broken). L1 now calls the table malformed, the chunk-table probe routes
/// `auto` away from `riff_chunk`, and the P0-1 pre-write gate rejects every
/// strategy instead of emitting a file we cannot verify.
#[test]
fn wav_missing_final_pad_is_refused_before_write() {
    fn make_odd_wav() -> Vec<u8> {
        let mut out = Vec::new();
        let data = [1u8, 2, 3]; // odd size, pad byte deliberately absent
        let file_size = 12 + (8 + 16) + (8 + data.len());
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&((file_size - 8) as u32).to_le_bytes());
        out.extend_from_slice(b"WAVE");
        out.extend_from_slice(b"fmt ");
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // PCM
        out.extend_from_slice(&1u16.to_le_bytes()); // mono
        out.extend_from_slice(&8000u32.to_le_bytes());
        out.extend_from_slice(&16000u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(b"data");
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&data);
        out
    }

    let wav = make_odd_wav();
    assert_eq!(
        WavAdapter.choose_auto_strategy(&mut Cursor::new(wav.clone()), 128),
        "eof",
        "auto must not pick a chunk layout its own verifier cannot walk"
    );

    let err = WavAdapter
        .inject(
            &mut Cursor::new(wav.clone()),
            &mut Cursor::new(vec![0u8; 128]),
            &mut Vec::new(),
            "riff_chunk",
        )
        .unwrap_err();
    assert!(err.to_string().contains("missing its pad byte"), "{err}");

    // L1 must call the table malformed, so the P0-1 pre-write gate refuses
    // every strategy: the carrier cannot host an envelope that our own
    // verifier would accept.
    let (ok, detail) = WavAdapter
        .verify_structure(&mut Cursor::new(wav.clone()))
        .unwrap();
    assert!(!ok, "missing final pad must fail L1");
    assert!(detail.contains("missing its pad byte"), "{detail}");

    let dir = scratch("rv25_wav_missing_pad");
    let carrier = dir.join("odd.wav");
    fs::write(&carrier, &wav).unwrap();
    let stego = dir.join("s.wav");
    let err = write_carrier(
        &carrier,
        PayloadSource::Text("odd wav secret"),
        &WriteOptions {
            output_path: Some(&stego),
            password: None,
            strategy: "auto",
            stealth: false,
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("malformed WAV carrier"),
        "write must refuse the malformed host: {err}"
    );
    assert!(
        !stego.exists(),
        "a rejected host must not leave an output file behind"
    );
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
        res.strategy.name(),
        "item_hidden",
        "auto must pick item_hidden for a meta-bearing HEIF"
    );
    let out = read_carrier(
        &stego,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(out.data, b"meta heif secret");
    let restored = dir.join("r.heif");
    remove_carrier(
        &stego,
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
    assert_eq!(res.strategy.name(), "box_uuid");
    let out = read_carrier(
        &stego,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(out.data, b"plain heif secret");
    let restored = dir.join("r.heif");
    remove_carrier(
        &stego,
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

// ------------------------------------------------------------------ PDF

/// A PDF whose dirty tail pushes the injected `%%EOF`/`endstream` pair beyond
/// the old fixed 128 KiB locate window used to be written successfully and
/// then be unreadable (P1-4). The growing window must locate it, and remove
/// must still restore byte-exactly.
#[test]
fn pdf_dirty_tail_beyond_128k_window_still_locates() {
    let dir = scratch("rv25_pdf_bigtail");
    let mut pdf = make_pdf();
    pdf.resize(pdf.len() + 200 * 1024, b'#');
    let carrier = dir.join("big.pdf");
    fs::write(&carrier, &pdf).unwrap();
    let stego = dir.join("s.pdf");
    let res = write_carrier_file(
        &carrier,
        PayloadSource::Text("deep tail secret"),
        None,
        "incremental",
        false,
        &stego,
    );
    assert_eq!(res.strategy.name(), "incremental");
    let out = read_carrier(
        &stego,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(out.data, b"deep tail secret");
    let restored = dir.join("r.pdf");
    remove_carrier(
        &stego,
        &RestoreOptions {
            output_path: Some(&restored),
            password: None,
            backup: false,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(fs::read(&restored).unwrap(), pdf);
}

/// Build a minimal incremental-update stego body by hand so the trailer bytes
/// (and therefore the stealth magic) are fully controlled.
fn craft_incremental_stego(magic: [u8; 4]) -> Vec<u8> {
    let ube_data = vec![0x42u8; 120];
    let ube_total = ube_data.len() as u64 + 24;
    let head = b"%PDF-1.4\n1 0 obj\n<</Length 120>>\nstream\n";
    let ube_offset = head.len() as u64;
    let mut body = head.to_vec();
    body.extend_from_slice(&ube_data);
    body.extend_from_slice(&EnvelopeTrailer::create(ube_offset, ube_total, magic).pack());
    body.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<</Size 2>>\nstartxref\n9\n%%EOF\n");
    body
}

/// The writer emits `UBE + "\nendstream"`, so the trailer always ends exactly
/// one EOL before `endstream`. A stealth magic whose own last byte is `\r` or
/// `\n` made the old trim-all loop eat one byte too many, misaligning the
/// trailer window and making the stego unreadable ~0.78% of the time (P2-5).
#[test]
fn pdf_locate_tolerates_eol_terminated_trailer_magic() {
    for last in [0x0Au8, 0x0Du8] {
        let magic = [0xD2, 0x33, 0x44, last];
        let stego = craft_incremental_stego(magic);
        let (lo, ls, strat) = PdfAdapter
            .locate(&mut Cursor::new(stego), Some(&magic))
            .unwrap()
            .unwrap_or_else(|| panic!("magic ending in 0x{last:02X} must still locate"));
        assert_eq!(strat, "incremental");
        assert_eq!(lo, 40, "ube_offset points at the payload start");
        assert_eq!(ls, 144);
    }

    // Control: the standard magic keeps locating through the same code path.
    let stego = craft_incremental_stego(STANDARD_TRAILER_MAGIC);
    let (lo, _, strat) = PdfAdapter
        .locate(&mut Cursor::new(stego), None)
        .unwrap()
        .unwrap();
    assert_eq!(strat, "incremental");
    assert_eq!(lo, 40);
}

/// An encrypted document (`/Encrypt` in the newest trailer) must refuse the
/// incremental strategy — the new trailer would not carry the key forward and
/// readers do not inherit it through `/Prev`, leaving ciphertext bodies
/// undecryptable (P1-3). Auto falls back to the lossless EOF overlay.
fn make_pdf_encrypted() -> Vec<u8> {
    b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n\
      xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n\
      trailer\n<< /Size 2 /Root 1 0 R /Encrypt 99 0 R >>\nstartxref\n9\n%%EOF\n"
        .to_vec()
}

#[test]
fn pdf_encrypted_document_rejects_incremental_and_roundtrips_via_eof() {
    let pdf = make_pdf_encrypted();
    assert_eq!(
        PdfAdapter.choose_auto_strategy(&mut Cursor::new(pdf.clone()), 128),
        "eof",
        "auto must not pick incremental for an encrypted document"
    );

    let dir = scratch("rv25_pdf_enc");
    let carrier = dir.join("enc.pdf");
    fs::write(&carrier, &pdf).unwrap();
    let err = write_carrier(
        &carrier,
        PayloadSource::Text("x"),
        &WriteOptions {
            output_path: Some(&dir.join("o.pdf")),
            strategy: "incremental",
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("encrypted"), "{err}");

    let stego = dir.join("s.pdf");
    let res = write_carrier_file(
        &carrier,
        PayloadSource::Text("enc secret"),
        None,
        "auto",
        false,
        &stego,
    );
    assert_eq!(res.strategy.name(), "eof");
    let out = read_carrier(
        &stego,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(out.data, b"enc secret");
    let restored = dir.join("r.pdf");
    remove_carrier(
        &stego,
        &RestoreOptions {
            output_path: Some(&restored),
            password: None,
            backup: false,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(fs::read(&restored).unwrap(), pdf);
}

// ------------------------------------------------------------------ batch 3

/// A ZIP64 archive with an EOCD64 locator before the classic EOCD (classic
/// fields real, not sentinel). Injection would shift the zip64 records
/// without patching the locator's offset field, so auto must route to eof and
/// explicit pre_cd_inject must be refused (P2-7).
fn make_zip64() -> Vec<u8> {
    let mut zip = make_zip();
    // The zero-comment EOCD is the last 22 bytes; insert before it so the
    // tail order matches APPNOTE: [zip64 record][locator][EOCD].
    let eocd_pos = zip.len() - 22;
    let mut zip64 = Vec::new();
    zip64.extend_from_slice(b"PK\x06\x06");
    zip64.extend_from_slice(&44u64.to_le_bytes()); // size of the remaining fields
    zip64.resize(56, 0); // fields strhide never reads
    zip64.extend_from_slice(b"PK\x06\x07");
    zip64.extend_from_slice(&0u32.to_le_bytes()); // disk number
    zip64.extend_from_slice(&(eocd_pos as u64).to_le_bytes()); // zip64 EOCD offset
    zip64.extend_from_slice(&1u32.to_le_bytes()); // total disks
    zip.splice(eocd_pos..eocd_pos, zip64);
    zip
}

#[test]
fn zip64_locator_routes_auto_to_eof() {
    let zip = make_zip64();
    assert_eq!(
        ZipAdapter.choose_auto_strategy(&mut Cursor::new(zip.clone()), 128),
        "eof",
        "auto must not pick pre_cd_inject when an EOCD64 locator is present"
    );

    let err = ZipAdapter
        .inject(
            &mut Cursor::new(zip.clone()),
            &mut Cursor::new(vec![0u8; 128]),
            &mut Vec::new(),
            "pre_cd_inject",
        )
        .unwrap_err();
    assert!(err.to_string().contains("ZIP64"), "{err}");

    // The eof strategy stays fully functional on ZIP64 carriers.
    let dir = scratch("rv25_zip64");
    let carrier = dir.join("z64.zip");
    fs::write(&carrier, &zip).unwrap();
    let stego = dir.join("s.zip");
    let res = write_carrier_file(
        &carrier,
        PayloadSource::Text("zip64 secret"),
        None,
        "auto",
        false,
        &stego,
    );
    assert_eq!(res.strategy.name(), "eof");
    let out = read_carrier(
        &stego,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(out.data, b"zip64 secret");
    let restored = dir.join("r.zip");
    remove_carrier(
        &stego,
        &RestoreOptions {
            output_path: Some(&restored),
            password: None,
            backup: false,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(fs::read(&restored).unwrap(), zip);
}

/// item_hidden tops out at a ~4 GiB envelope (32-bit mdat size + iloc
/// fields); auto must route anything larger to the genuinely unlimited
/// box_uuid strategy instead of failing the write (P2-4). The threshold is a
/// plain number on a small carrier, so the test needs no huge allocation.
#[test]
fn heif_auto_routes_oversized_envelopes_to_box_uuid() {
    let max = u32::MAX as u64 - 8;
    assert_eq!(
        HeifAdapter.choose_auto_strategy(&mut Cursor::new(make_heif_with_meta()), 1024),
        "item_hidden"
    );
    assert_eq!(
        HeifAdapter.choose_auto_strategy(&mut Cursor::new(make_heif_with_meta()), max),
        "item_hidden",
        "the exact bound is still reachable"
    );
    assert_eq!(
        HeifAdapter.choose_auto_strategy(&mut Cursor::new(make_heif_with_meta()), max + 1),
        "box_uuid",
        "one past the bound must not choose a strategy that cannot write it"
    );
}

/// WAV/WebP auto must keep riff_chunk only when write and read agree (clean
/// declared boundary, u32 headroom) and route everything else to eof, whose
/// write and read are symmetric by construction (P3-17 / P1-2 auto half).
#[test]
fn wav_webp_auto_probe_reports_eof_but_write_rejects_mismatch() {
    assert_eq!(
        WavAdapter.choose_auto_strategy(&mut Cursor::new(make_wav()), 128),
        "riff_chunk"
    );
    assert_eq!(
        WebpAdapter.choose_auto_strategy(&mut Cursor::new(make_webp()), 128),
        "riff_chunk"
    );

    let mut wav = make_wav();
    wav.extend_from_slice(b"JUNK");
    assert_eq!(
        WavAdapter.choose_auto_strategy(&mut Cursor::new(wav), 128),
        "eof",
        "trailing bytes past the declared boundary must route to eof"
    );
    let mut webp = make_webp();
    webp.extend_from_slice(b"JUNK");
    assert_eq!(
        WebpAdapter.choose_auto_strategy(&mut Cursor::new(webp), 128),
        "eof"
    );

    // The 4 GiB patched-size limit is part of the same predicate.
    assert_eq!(
        WavAdapter.choose_auto_strategy(&mut Cursor::new(make_wav()), u32::MAX as u64),
        "eof",
        "envelopes beyond the u32 RIFF size must route to eof"
    );

    // End-to-end: the probe above still reports "eof", but the write path now
    // verifies the host structure first, so a carrier whose chunk table runs
    // past EOF is refused before any output is produced.
    let dir = scratch("rv25_wav_auto");
    let mut carrier_bytes = make_wav();
    carrier_bytes.extend_from_slice(b"ID3JUNK");
    let carrier = dir.join("c.wav");
    fs::write(&carrier, &carrier_bytes).unwrap();
    let stego = dir.join("s.wav");
    let err = write_carrier(
        &carrier,
        PayloadSource::Text("wav auto secret"),
        &WriteOptions {
            output_path: Some(&stego),
            strategy: "auto",
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("malformed"),
        "unexpected error: {err}"
    );
    assert!(!stego.exists(), "a rejected host must not produce output");
}

// ------------------------------------------------------------------ batch 5

/// P1-1: the APP15 chain is inserted *before* SOS, so a large chain pushes SOS
/// past the adapter's 16 MiB marker-scan window. Capacity must be measured
/// against the relocated SOS, and auto must fall back to `eof` instead of
/// producing a carrier that its own verifier cannot locate.
#[test]
fn jpeg_app_segment_capacity_keeps_relocated_sos_in_scan_window() {
    use strhide::structure::adapters::jpeg::{JPEG_MAX_TOTAL_CAPACITY, MAX_JPEG_HEADER_SCAN};

    let carrier = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/assets/minimal.jpg");
    let bytes = fs::read(&carrier).unwrap();
    let adapter = JpegAdapter;
    let two_mib = 2 * 1024 * 1024u64;

    let mut cursor = Cursor::new(&bytes);
    assert_eq!(
        adapter.choose_auto_strategy(&mut cursor, two_mib),
        "app_segment"
    );

    let mut cursor = Cursor::new(&bytes);
    let capacity = adapter
        .strategy_capacities(Some(&mut cursor))
        .into_iter()
        .find(|cap| cap.strategy == "app_segment")
        .and_then(|cap| cap.capacity_bytes)
        .expect("measured APP15 capacity");
    assert!(capacity >= two_mib, "capacity {capacity} below 2 MiB");
    assert!(
        capacity < MAX_JPEG_HEADER_SCAN,
        "capacity {capacity} must account for the relocated SOS"
    );

    for size in [16 * 1024 * 1024u64, JPEG_MAX_TOTAL_CAPACITY + 1] {
        let mut cursor = Cursor::new(&bytes);
        assert_eq!(
            adapter.choose_auto_strategy(&mut cursor, size),
            "eof",
            "a {size}-byte chain would push SOS past the scan window"
        );
    }

    // 2 MiB is inside the measured window: a real write must land in
    // app_segment and still read back, proving the capacity is reachable.
    let dir = scratch("rv25_jpeg_capacity_2mib");
    let stego = dir.join("s.jpg");
    let payload: Vec<u8> = (0..two_mib)
        .map(|i| (i.wrapping_mul(31) % 251) as u8)
        .collect();
    let written = write_carrier(
        &carrier,
        PayloadSource::Bytes(&payload),
        &WriteOptions {
            output_path: Some(&stego),
            strategy: "auto",
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(written.strategy.name(), "app_segment");
    let out = read_carrier(
        &stego,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(out.data, payload);
}

/// Build a JPEG whose header chain runs past the 16 MiB marker-scan limit.
fn make_jpeg_with_giant_header() -> Vec<u8> {
    // 257 max-size APP1 segments: the SOS marker would start at 2 + 256*65535
    // + 65535 = 16,842,497 > MAX_JPEG_HEADER_SCAN (16,777,216).
    let mut out = Vec::new();
    out.extend_from_slice(b"\xff\xd8"); // SOI
    let seg_payload = [0u8; 65533];
    for _ in 0..257 {
        out.extend_from_slice(b"\xff\xe1");
        out.extend_from_slice(&65535u16.to_be_bytes());
        out.extend_from_slice(&seg_payload);
    }
    out.extend_from_slice(b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"); // SOS
    out.extend_from_slice(&[0x12u8; 16]);
    out.extend_from_slice(b"\xff\xd9"); // EOI
    out
}

/// A JPEG whose header chain (EXIF/ICC/…) runs past the 16 MiB marker-scan
/// limit never reaches SOS. The auto probe reports `eof` (P3-19), but the write
/// path's host verification now refuses the malformed carrier outright instead
/// of appending an envelope to a file that cannot be parsed as JPEG.
#[test]
fn jpeg_auto_probe_reports_eof_but_write_rejects_unreachable_sos() {
    let giant = make_jpeg_with_giant_header();
    assert_eq!(
        JpegAdapter.choose_auto_strategy(&mut Cursor::new(giant.clone()), 128),
        "eof",
        "a header chain past the 16 MiB scan limit must not select app_segment"
    );
    // Control: a normal JPEG keeps the segment strategy.
    assert_eq!(
        JpegAdapter.choose_auto_strategy(&mut Cursor::new(make_jpeg()), 128),
        "app_segment"
    );

    // End-to-end: the probe above still reports "eof", but write_core now
    // verifies the host first. A JPEG whose SOS marker is unreachable is
    // malformed as far as strhide is concerned and must be refused rather than
    // have an envelope appended to it.
    let dir = scratch("rv25_jpeg_bigheader");
    let carrier = dir.join("big.jpeg");
    fs::write(&carrier, &giant).unwrap();
    let stego = dir.join("s.jpeg");
    let err = write_carrier(
        &carrier,
        PayloadSource::Text("jpeg tail secret"),
        &WriteOptions {
            output_path: Some(&stego),
            strategy: "auto",
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("malformed"),
        "unexpected error: {err}"
    );
    assert!(!stego.exists(), "a rejected host must not produce output");
}

/// [`make_heif_with_meta`] with `pad` zero bytes appended inside the meta box
/// (after iloc, before mdat): the <8-byte residue the inject/strip pair must
/// carry through verbatim (P3-4).
fn make_heif_with_meta_tail(pad: usize) -> Vec<u8> {
    let mut v = make_heif_with_meta();
    // Layout: [ftyp 24][meta][mdat 8+64]; meta starts at 24.
    let mdat_pos = v.len() - 8 - 64;
    let meta_len = u32::from_be_bytes(v[24..28].try_into().unwrap()) + pad as u32;
    v[24..28].copy_from_slice(&meta_len.to_be_bytes());
    // The iloc base_offset names the absolute mdat payload position; it moves
    // back by `pad` once the residue joins the meta box.
    const ILOC_BASE_FIELD: usize = 24 + 12 + 35 + 22; // ftyp + meta hdr/ver + iinf + base field in iloc
    let base = u32::from_be_bytes(v[ILOC_BASE_FIELD..ILOC_BASE_FIELD + 4].try_into().unwrap())
        + pad as u32;
    v[ILOC_BASE_FIELD..ILOC_BASE_FIELD + 4].copy_from_slice(&base.to_be_bytes());
    v.splice(mdat_pos..mdat_pos, vec![0u8; pad]);
    v
}

/// Dropping the meta residue used to shift every later offset: inject
/// succeeded but remove hit RestoreMismatch. The residue must roundtrip
/// byte-exactly (P3-4).
#[test]
fn heif_meta_tail_residual_roundtrips() {
    let carrier_bytes = make_heif_with_meta_tail(5);
    let dir = scratch("rv25_heif_tail");
    let carrier = dir.join("c.heif");
    fs::write(&carrier, &carrier_bytes).unwrap();
    let stego = dir.join("s.heif");
    let res = write_carrier_file(
        &carrier,
        PayloadSource::Text("tail secret"),
        None,
        "auto",
        false,
        &stego,
    );
    assert_eq!(res.strategy.name(), "item_hidden");
    let out = read_carrier(
        &stego,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(out.data, b"tail secret");
    let restored = dir.join("r.heif");
    remove_carrier(
        &stego,
        &RestoreOptions {
            output_path: Some(&restored),
            password: None,
            backup: false,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(fs::read(&restored).unwrap(), carrier_bytes);
}

/// An iinf declaring more entries than it carries used to end the max_id scan
/// silently, and the minted new_id could collide with an item declared after
/// the break. The walk must reject the carrier instead (P3-5).
#[test]
fn heif_truncated_iinf_entry_rejected() {
    let mut v = make_heif_with_meta();
    // iinf entry_count: ftyp(24) + meta hdr/ver(12) + iinf hdr(8) + ver/flags(4).
    const IINF_COUNT: usize = 48;
    assert_eq!(
        u16::from_be_bytes(v[IINF_COUNT..IINF_COUNT + 2].try_into().unwrap()),
        1
    );
    v[IINF_COUNT..IINF_COUNT + 2].copy_from_slice(&2u16.to_be_bytes());
    let err = HeifAdapter
        .inject(
            &mut Cursor::new(v),
            &mut Cursor::new(vec![0u8; 128]),
            &mut Vec::new(),
            "item_hidden",
        )
        .unwrap_err();
    assert!(err.to_string().contains("iinf"), "{err}");
}

/// A 64-bit iloc extent offset with no headroom for the meta growth used to
/// wrap silently and write a bogus offset into the stego (P3-3, inject-side
/// add). The carrier must be rejected as corrupted.
#[test]
fn heif_iloc_offset_overflow_rejected() {
    let mut v = make_heif_with_meta();
    const ILOC: usize = 24 + 12 + 35; // ftyp + meta hdr/ver + iinf
    v[ILOC + 12] = 0x84; // offset_size=8, length_size=4
    v[ILOC + 13] = 0x00; // base_size=0, index_size=0
    // base_offset(4) + extent_count(2) become extent_count(2) + a 64-bit
    // extent_offset with no headroom for the meta growth (delta = 41).
    v[ILOC + 22..ILOC + 24].copy_from_slice(&1u16.to_be_bytes());
    v[ILOC + 24..ILOC + 32].copy_from_slice(&(u64::MAX - 10).to_be_bytes());
    let err = HeifAdapter
        .inject(
            &mut Cursor::new(v),
            &mut Cursor::new(vec![0u8; 128]),
            &mut Vec::new(),
            "item_hidden",
        )
        .unwrap_err();
    assert!(err.to_string().contains("overflow"), "{err}");
}

/// Two concatenated PNGs. The write side inserts before the LAST IEND while
/// locate/verify/suspicious used to stop at the FIRST one, so the payload was
/// written into a place nothing scanned (P3-18). A single traversal now walks
/// every stream and the whole lifecycle must round-trip.
#[test]
fn png_concatenated_streams_roundtrip_through_the_last_iend() {
    let mut concatenated = make_png();
    concatenated.extend_from_slice(&make_png());
    let dir = scratch("rv25_png_concat");
    let carrier = dir.join("c.png");
    let out = dir.join("o.png");
    fs::write(&carrier, &concatenated).unwrap();

    let res = write_carrier(
        &carrier,
        PayloadSource::Text("png secret"),
        &WriteOptions {
            output_path: Some(&out),
            strategy: "chunk",
            backup: false,
            ..Default::default()
        },
    )
    .expect("concatenated PNG must accept a chunk envelope");
    assert_eq!(res.strategy.name(), "chunk");

    let read = read_carrier(
        &out,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .expect("locate must reach the chunk before the last IEND");
    assert_eq!(read.data, b"png secret");

    let verified = verify_carrier(&out, None).expect("verify");
    assert!(
        verified.level1_host.ok && verified.level2_envelope.ok && verified.level3_crypto.ok,
        "structure verification failed: {:?}",
        verified
    );

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
    .expect("restore");
    assert_eq!(fs::read(&out).unwrap(), concatenated);
}
