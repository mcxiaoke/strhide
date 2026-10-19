//! Format x strategy x password x stealth matrix coverage
//! (gap report 2026-10-19, gaps #13-#17).
//!
//! Every cell runs the same table-driven lifecycle:
//! write -> inspect -> verify (L1/L2/L3) -> read -> remove -> byte-exact
//! restore, so a gap in any one operation for a combination is caught.
//!
//! Fills the previously empty cells:
//! - `eof` on JPEG / MP4 / PE (the per-format fallback strategy, previously
//!   only exercised on PNG and ZIP);
//! - stealth on JPEG / MP4 / PDF (previously only PNG / ZIP / PE);
//! - explicitly named non-default strategies `chunk`, `box_uuid`,
//!   `pre_cd_inject`, `pe_overlay` (previously only `auto`-selected ones);
//! - password-less (`BUILTIN_DEFAULT_KEY`) round trips on JPEG and MP4;
//! - `stealth + eof`, `password_hint` on a non-PNG format, and the
//!   stealth-requires-password guard on every supported format.

use std::fs;
use std::path::{Path, PathBuf};

use strhide::engine::{
    PayloadSource, WriteOptions, inspect_carrier, read_carrier, remove_carrier, verify_carrier,
    write_carrier,
};
use strhide::errors::StrHideError;

// --------------------------------------------------------------------------- synthetic carriers

/// Minimal valid PNG (IHDR + IEND, CRCs valid).
fn make_png() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let ihdr_data: [u8; 13] = [1, 0, 0, 0, 1, 0, 0, 0, 8, 2, 0, 0, 0];
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&(ihdr_data.len() as u32).to_be_bytes());
    chunk.extend_from_slice(b"IHDR");
    chunk.extend_from_slice(&ihdr_data);
    let crc = crc32fast::hash(&chunk[4..]);
    chunk.extend_from_slice(&crc.to_be_bytes());
    out.extend_from_slice(&chunk);
    out.extend_from_slice(b"\x00\x00\x00\x00IEND\xaeB`\x82");
    out
}

/// Minimal JPEG: SOI, JFIF APP0, DQT, SOF0, SOS, entropy data, EOI.
fn make_jpeg() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\xff\xd8");
    let app0 = b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0";
    out.extend_from_slice(b"\xff\xe0");
    out.extend_from_slice(&(2u16 + app0.len() as u16).to_be_bytes());
    out.extend_from_slice(app0);
    out.extend_from_slice(b"\xff\xdb\x00\x43\x00");
    out.extend_from_slice(&[16u8; 64]);
    out.extend_from_slice(b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00");
    out.extend_from_slice(b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00");
    out.extend_from_slice(&[0x12u8; 32]);
    out.extend_from_slice(b"\xff\xd9");
    out
}

/// Minimal ISO BMFF: one `ftyp` box followed by a `free` box.
fn make_mp4() -> Vec<u8> {
    let mut out = Vec::new();
    let ftyp = b"isom\x00\x00\x02\x00isom";
    out.extend_from_slice(&(8u32 + ftyp.len() as u32).to_be_bytes());
    out.extend_from_slice(b"ftyp");
    out.extend_from_slice(ftyp);
    out.extend_from_slice(&8u32.to_be_bytes());
    out.extend_from_slice(b"free");
    out
}

/// Minimal stored-entry ZIP: local header, central directory, EOCD.
fn make_zip() -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    let name = "hello.txt";
    let data = b"hello in zip payload";
    let crc = crc32fast::hash(data);
    let local_off = out.len() as u32;

    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // stored
    out.extend_from_slice(&0u16.to_le_bytes()); // time
    out.extend_from_slice(&0u16.to_le_bytes()); // date
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // extra
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(data);

    cd.extend_from_slice(b"PK\x01\x02");
    cd.extend_from_slice(&20u16.to_le_bytes());
    cd.extend_from_slice(&20u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&crc.to_le_bytes());
    cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
    cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
    cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(&local_off.to_le_bytes());
    cd.extend_from_slice(name.as_bytes());

    let cd_off = out.len() as u32;
    let cd_size = cd.len() as u32;
    out.extend_from_slice(&cd);

    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Minimal PDF 1.4 with a classic xref table and a `/Root` trailer entry.
fn make_pdf() -> Vec<u8> {
    b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n\
      xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n\
      trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n"
        .to_vec()
}

/// 23-byte pattern yielding 7 instrumentable positions (same generator as the
/// pe_codebits suite: see its `TEXT_PATTERN` rationale).
const TEXT_PATTERN: &[u8] = &[
    0x89, 0xD8, 0x89, 0xCA, 0x8B, 0xD1, 0x89, 0x18, 0x85, 0xC3, 0x85, 0xD8, 0x85, 0xC0, 0x01, 0xD8,
    0x3B, 0xC3, 0x90, 0x90, 0x48, 0x89, 0x00,
];

/// Minimal PE64 with a `.text` of instrumentable instructions and zero slack
/// padding after it. `text_len` sizes `.text`; slack is the section tail.
fn make_pe(text_len: usize) -> Vec<u8> {
    let opt_size: u16 = 240;
    let e_lfanew: u32 = 0x80;
    let sec_table = e_lfanew as usize + 24 + opt_size as usize;
    let raw_ptr: u32 = 0x400;
    let raw_size = (text_len as u32).div_ceil(0x200) * 0x200;

    let mut img = vec![0u8; raw_ptr as usize];
    img[0..2].copy_from_slice(b"MZ");
    img[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    img[0x80..0x84].copy_from_slice(b"PE\0\0");
    img[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // machine: x86-64
    img[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // one section
    img[0x94..0x96].copy_from_slice(&opt_size.to_le_bytes());
    img[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes()); // executable
    let opt = 0x98;
    img[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+

    let sec = sec_table;
    img[sec..sec + 8].copy_from_slice(b".text\0\0\0");
    img[sec + 8..sec + 12].copy_from_slice(&(text_len as u32).to_le_bytes());
    img[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    img[sec + 16..sec + 20].copy_from_slice(&raw_size.to_le_bytes());
    img[sec + 20..sec + 24].copy_from_slice(&raw_ptr.to_le_bytes());
    img[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    let mut text = Vec::with_capacity(text_len);
    while text.len() < text_len {
        text.extend_from_slice(TEXT_PATTERN);
    }
    text.truncate(text_len);
    img.extend_from_slice(&text);
    img.resize(raw_ptr as usize + raw_size as usize, 0); // zero-value slack
    img
}

// --------------------------------------------------------------------------- matrix table

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fmt {
    Png,
    Jpeg,
    Mp4,
    Zip,
    Pdf,
    Pe,
}

impl Fmt {
    fn name(self) -> &'static str {
        match self {
            Fmt::Png => "PNG",
            Fmt::Jpeg => "JPEG",
            Fmt::Mp4 => "MP4",
            Fmt::Zip => "ZIP",
            Fmt::Pdf => "PDF",
            Fmt::Pe => "PE",
        }
    }

    fn ext(self) -> &'static str {
        match self {
            Fmt::Png => "png",
            Fmt::Jpeg => "jpg",
            Fmt::Mp4 => "mp4",
            Fmt::Zip => "zip",
            Fmt::Pdf => "pdf",
            Fmt::Pe => "exe",
        }
    }

    /// Bytes for this format's carrier.
    fn carrier(self) -> Vec<u8> {
        match self {
            Fmt::Png => make_png(),
            Fmt::Jpeg => make_jpeg(),
            Fmt::Mp4 => make_mp4(),
            Fmt::Zip => make_zip(),
            Fmt::Pdf => make_pdf(),
            // ~12 kB of code: enough for the smallest envelope even encrypted.
            Fmt::Pe => make_pe(0x3000),
        }
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strhide_mtx_{}_{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn cell_name(fmt: Fmt, strategy: &str, password: Option<&str>, stealth: bool) -> String {
    let pwd = if password.is_some() { "pw" } else { "nopw" };
    let st = if stealth { "stealth" } else { "plain" };
    format!("{}_{}_{}_{}", fmt.name().to_lowercase(), strategy, pwd, st)
}

/// One matrix cell: full lifecycle with byte-exact restore.
fn run_cell(
    fmt: Fmt,
    strategy: &str,
    password: Option<&str>,
    stealth: bool,
    expect_strategy: &str,
) {
    let label = cell_name(fmt, strategy, password, stealth);
    let dir = scratch(&label);
    let carrier = dir.join(format!("c.{}", fmt.ext()));
    let original = fmt.carrier();
    fs::write(&carrier, &original).unwrap();

    let out = dir.join(format!("c.steg.{}", fmt.ext()));
    let write = write_carrier(
        &carrier,
        PayloadSource::Text("matrix payload 中文 🚀"),
        &WriteOptions {
            output_path: Some(&out),
            password,
            strategy,
            stealth,
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("{label}: write failed: {e}"));

    assert_eq!(
        write.strategy,
        expect_strategy,
        "{label}: unexpected strategy (note: {})",
        write.strategy_note.as_deref().unwrap_or("-")
    );
    assert_eq!(write.format, fmt.name(), "{label}: format");
    assert_eq!(write.is_stealth, stealth, "{label}: is_stealth flag");
    assert_eq!(
        write.is_encrypted,
        password.is_some(),
        "{label}: is_encrypted tracks a custom password"
    );

    // inspect
    let insp =
        inspect_carrier(&out, password).unwrap_or_else(|e| panic!("{label}: inspect failed: {e}"));
    assert!(insp.has_hidden_data, "{label}: inspect found nothing");
    assert_eq!(
        insp.strategy.as_deref(),
        Some(expect_strategy),
        "{label}: inspect strategy"
    );
    assert_eq!(
        insp.is_stealth,
        Some(stealth),
        "{label}: inspect is_stealth"
    );
    assert_eq!(
        insp.is_encrypted,
        Some(password.is_some()),
        "{label}: inspect is_encrypted"
    );
    assert!(
        insp.metadata.is_some(),
        "{label}: metadata must be readable"
    );

    // verify: all three levels must pass (the password is supplied when the
    // envelope is encrypted, so Level 3 is always actually run).
    let v =
        verify_carrier(&out, password).unwrap_or_else(|e| panic!("{label}: verify failed: {e}"));
    assert!(v.level1_host.ok, "{label}: L1 {}", v.level1_host.detail);
    assert!(
        v.level2_envelope.ok,
        "{label}: L2 {}",
        v.level2_envelope.detail
    );
    assert!(v.level3_crypto.ok, "{label}: L3 {}", v.level3_crypto.detail);

    // read
    let read =
        read_carrier(&out, None, password).unwrap_or_else(|e| panic!("{label}: read failed: {e}"));
    assert_eq!(
        String::from_utf8(read.data).unwrap(),
        "matrix payload 中文 🚀",
        "{label}: payload round-trip"
    );

    // remove -> byte-exact restore
    let restored = dir.join(format!("c.restored.{}", fmt.ext()));
    let rem = remove_carrier(&out, Some(&restored), password, false)
        .unwrap_or_else(|e| panic!("{label}: remove failed: {e}"));
    assert!(rem.verified_identical, "{label}: remove must verify");
    assert_eq!(
        fs::read(&restored).unwrap(),
        original,
        "{label}: restored carrier must be byte-identical"
    );
}

// --------------------------------------------------------------------------- eof on every format

/// Like `run_cell`, but tolerates the write-time / locate-time strategy name
/// differing. Used for PE `eof`: writing appends after the PE image exactly
/// like `pe_overlay`, and `PeAdapter::locate` (pe.rs:364-372) classifies any
/// envelope at/after `pe_image_end` as `pe_overlay`, so the two are
/// indistinguishable in the produced file. Data integrity is unaffected.
fn run_cell_any_reported_strategy(
    fmt: Fmt,
    write_strategy: &str,
    password: Option<&str>,
    stealth: bool,
) {
    let label = format!(
        "{}__any_reported",
        cell_name(fmt, write_strategy, password, stealth)
    );
    let dir = scratch(&label);
    let carrier = dir.join(format!("c.{}", fmt.ext()));
    let original = fmt.carrier();
    fs::write(&carrier, &original).unwrap();

    let out = dir.join(format!("c.steg.{}", fmt.ext()));
    let write = write_carrier(
        &carrier,
        PayloadSource::Text("matrix payload"),
        &WriteOptions {
            output_path: Some(&out),
            password,
            strategy: write_strategy,
            stealth,
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("{label}: write failed: {e}"));
    assert_eq!(write.strategy, write_strategy, "{label}: write strategy");

    let read =
        read_carrier(&out, None, password).unwrap_or_else(|e| panic!("{label}: read failed: {e}"));
    assert_eq!(
        String::from_utf8(read.data).unwrap(),
        "matrix payload",
        "{label}"
    );

    let restored = dir.join(format!("c.restored.{}", fmt.ext()));
    remove_carrier(&out, Some(&restored), password, false)
        .unwrap_or_else(|e| panic!("{label}: remove failed: {e}"));
    assert_eq!(
        fs::read(&restored).unwrap(),
        original,
        "{label}: byte-exact restore"
    );
}

#[test]
fn eof_strategy_roundtrips_on_every_format() {
    for fmt in [Fmt::Png, Fmt::Jpeg, Fmt::Mp4, Fmt::Zip, Fmt::Pdf] {
        run_cell(fmt, "eof", Some("eof-pw"), false, "eof");
    }
    // PE eof is reported as pe_overlay on locate (see helper doc).
    run_cell_any_reported_strategy(Fmt::Pe, "eof", Some("eof-pw"), false);
}

#[test]
fn eof_strategy_without_password_roundtrips() {
    for fmt in [Fmt::Png, Fmt::Jpeg, Fmt::Mp4, Fmt::Zip, Fmt::Pdf] {
        run_cell(fmt, "eof", None, false, "eof");
    }
    run_cell_any_reported_strategy(Fmt::Pe, "eof", None, false);
}

// --------------------------------------------------------------------------- explicitly named strategies

#[test]
fn explicit_non_default_strategies_roundtrip() {
    // One cell per non-eof, non-default strategy in the whole adapter table.
    run_cell(Fmt::Png, "chunk", Some("chunk-pw"), false, "chunk");
    run_cell(
        Fmt::Jpeg,
        "app_segment",
        Some("app-pw"),
        false,
        "app_segment",
    );
    run_cell(Fmt::Mp4, "box_uuid", Some("uuid-pw"), false, "box_uuid");
    run_cell(
        Fmt::Zip,
        "pre_cd_inject",
        Some("zip-pw"),
        false,
        "pre_cd_inject",
    );
    run_cell(
        Fmt::Pdf,
        "incremental",
        Some("pdf-pw"),
        false,
        "incremental",
    );
    run_cell(
        Fmt::Pe,
        "pe_overlay",
        Some("overlay-pw"),
        false,
        "pe_overlay",
    );
    run_cell(Fmt::Pe, "pe_slack", Some("slack-pw"), false, "pe_slack");
    run_cell(
        Fmt::Pe,
        "pe_codebits",
        Some("codebits-pw"),
        false,
        "pe_codebits",
    );
}

#[test]
fn explicit_strategies_without_password_roundtrip() {
    run_cell(Fmt::Png, "chunk", None, false, "chunk");
    run_cell(Fmt::Jpeg, "app_segment", None, false, "app_segment");
    run_cell(Fmt::Mp4, "box_uuid", None, false, "box_uuid");
    run_cell(Fmt::Zip, "pre_cd_inject", None, false, "pre_cd_inject");
    run_cell(Fmt::Pdf, "incremental", None, false, "incremental");
}

// --------------------------------------------------------------------------- stealth on every format

#[test]
fn stealth_roundtrips_on_every_format() {
    for fmt in [Fmt::Png, Fmt::Jpeg, Fmt::Mp4, Fmt::Zip, Fmt::Pdf, Fmt::Pe] {
        run_cell(
            fmt,
            "auto",
            Some("stealth-pw"),
            true,
            match fmt {
                Fmt::Png => "chunk",
                Fmt::Jpeg => "app_segment",
                Fmt::Mp4 => "box_uuid",
                Fmt::Zip => "pre_cd_inject",
                Fmt::Pdf => "incremental",
                Fmt::Pe => "pe_codebits",
            },
        );
    }
}

#[test]
fn stealth_with_eof_strategy_roundtrips() {
    // The combination was never exercised: stealth magics + EOF placement.
    run_cell(Fmt::Png, "eof", Some("st-eof-pw"), true, "eof");
    run_cell(Fmt::Jpeg, "eof", Some("st-eof-pw"), true, "eof");
}

#[test]
fn stealth_envelope_is_invisible_without_its_password() {
    // The stealth magics are password-derived, so a password-less read must
    // not locate the envelope at all — plausible deniability.
    //
    // Only the formats whose adapter implements `suspicious_structures` can
    // add guidance to the error (PNG prIv chunk, JPEG APP15/COM, MP4 uuid
    // box); ZIP and PDF use the trait default (no opinion), so their error is
    // the plain "no hidden data" message. PE's scan only recognizes a *trailing
    // overlay*; stealth `pe_codebits` writes no overlay (the channel lives in
    // .text), so it has nothing to report either.
    let guided = [Fmt::Png, Fmt::Jpeg, Fmt::Mp4];
    for fmt in [Fmt::Png, Fmt::Jpeg, Fmt::Mp4, Fmt::Zip, Fmt::Pdf, Fmt::Pe] {
        let label = format!("invisible_{}", fmt.name().to_lowercase());
        let dir = scratch(&label);
        let carrier = dir.join(format!("c.{}", fmt.ext()));
        fs::write(&carrier, fmt.carrier()).unwrap();
        let out = dir.join(format!("c.steg.{}", fmt.ext()));

        write_carrier(
            &carrier,
            PayloadSource::Text("deniable"),
            &WriteOptions {
                output_path: Some(&out),
                password: Some("secret-stealth-pw"),
                stealth: true,
                backup: false,
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("{label}: write failed: {e}"));

        let err = read_carrier(&out, None, None).unwrap_err();
        assert!(
            matches!(err, StrHideError::NoHiddenData(_)),
            "{label}: expected NoHiddenData without the password, got {err:?}"
        );
        assert!(
            err.to_string().contains("No hidden strhide data found"),
            "{label}: base message missing: {err}"
        );
        if guided.contains(&fmt) {
            assert!(
                err.to_string().contains("stealth envelope"),
                "{label}: guidance missing: {err}"
            );
        }

        // The wrong password is equally invisible (not a Password error).
        let wrong = read_carrier(&out, None, Some("wrong-pw")).unwrap_err();
        assert!(
            matches!(wrong, StrHideError::NoHiddenData(_)),
            "{label}: wrong password must not locate the envelope, got {wrong:?}"
        );
    }
}

#[test]
fn stealth_requires_a_password_on_every_format() {
    for fmt in [Fmt::Png, Fmt::Jpeg, Fmt::Mp4, Fmt::Zip, Fmt::Pdf, Fmt::Pe] {
        let dir = scratch(&format!("stealth_guard_{}", fmt.name().to_lowercase()));
        let carrier = dir.join(format!("c.{}", fmt.ext()));
        fs::write(&carrier, fmt.carrier()).unwrap();
        let out = dir.join(format!("c.steg.{}", fmt.ext()));

        let err = write_carrier(
            &carrier,
            PayloadSource::Text("x"),
            &WriteOptions {
                output_path: Some(&out),
                stealth: true,
                backup: false,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("requires a password"),
            "{}: {err}",
            fmt.name()
        );
        assert!(!out.exists(), "{}: nothing must be written", fmt.name());
    }
}

#[test]
fn stealth_and_password_hint_are_mutually_exclusive_on_every_format() {
    for fmt in [Fmt::Png, Fmt::Jpeg, Fmt::Mp4, Fmt::Zip, Fmt::Pdf, Fmt::Pe] {
        let dir = scratch(&format!("hint_guard_{}", fmt.name().to_lowercase()));
        let carrier = dir.join(format!("c.{}", fmt.ext()));
        fs::write(&carrier, fmt.carrier()).unwrap();
        let out = dir.join(format!("c.steg.{}", fmt.ext()));

        let err = write_carrier(
            &carrier,
            PayloadSource::Text("x"),
            &WriteOptions {
                output_path: Some(&out),
                password: Some("pw"),
                password_hint: Some("a hint"),
                stealth: true,
                backup: false,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not supported in --stealth"),
            "{}: {err}",
            fmt.name()
        );
    }
}

// --------------------------------------------------------------------------- password hints on non-PNG formats

#[test]
fn password_hint_roundtrips_on_every_format() {
    for fmt in [Fmt::Png, Fmt::Jpeg, Fmt::Mp4, Fmt::Zip, Fmt::Pdf, Fmt::Pe] {
        let label = format!("hint_{}", fmt.name().to_lowercase());
        let dir = scratch(&label);
        let carrier = dir.join(format!("c.{}", fmt.ext()));
        fs::write(&carrier, fmt.carrier()).unwrap();
        let out = dir.join(format!("c.steg.{}", fmt.ext()));
        let hint = "3班1975";

        let res = write_carrier(
            &carrier,
            PayloadSource::Text("hinted"),
            &WriteOptions {
                output_path: Some(&out),
                password: Some("hint-pw"),
                password_hint: Some(hint),
                backup: false,
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("{label}: write failed: {e}"));
        assert_eq!(res.password_hint.as_deref(), Some(hint), "{label}");

        // The hint is visible without the password...
        let insp = inspect_carrier(&out, None).expect("inspect");
        assert_eq!(
            insp.password_hint.as_deref(),
            Some(hint),
            "{label}: inspect hint"
        );

        // ...and appears in the password error.
        let err = read_carrier(&out, None, None).unwrap_err();
        assert!(
            matches!(err, StrHideError::Password(_)),
            "{label}: expected Password variant, got {err:?}"
        );
        assert!(err.to_string().contains(hint), "{label}: {err}");

        // With the password the payload still reads back.
        let read = read_carrier(&out, None, Some("hint-pw")).expect("read");
        assert_eq!(String::from_utf8(read.data).unwrap(), "hinted", "{label}");
    }
}

// --------------------------------------------------------------------------- password-less (default key) round trips

#[test]
fn password_less_roundtrips_on_every_format() {
    for fmt in [Fmt::Png, Fmt::Jpeg, Fmt::Mp4, Fmt::Zip, Fmt::Pdf, Fmt::Pe] {
        run_cell(
            fmt,
            "auto",
            None,
            false,
            match fmt {
                Fmt::Png => "chunk",
                Fmt::Jpeg => "app_segment",
                Fmt::Mp4 => "box_uuid",
                Fmt::Zip => "pre_cd_inject",
                Fmt::Pdf => "incremental",
                Fmt::Pe => "pe_codebits",
            },
        );
    }
}

// --------------------------------------------------------------------------- multi-payload stacking guard

#[test]
fn second_write_into_a_filled_carrier_is_refused_on_every_format() {
    for fmt in [Fmt::Png, Fmt::Jpeg, Fmt::Mp4, Fmt::Zip, Fmt::Pdf, Fmt::Pe] {
        let label = format!("double_{}", fmt.name().to_lowercase());
        let dir = scratch(&label);
        let carrier = dir.join(format!("c.{}", fmt.ext()));
        fs::write(&carrier, fmt.carrier()).unwrap();
        let first = dir.join(format!("c1.{}", fmt.ext()));
        let second = dir.join(format!("c2.{}", fmt.ext()));

        fn opts(out: &Path) -> WriteOptions<'_> {
            WriteOptions {
                output_path: Some(out),
                backup: false,
                ..Default::default()
            }
        }
        write_carrier(&carrier, PayloadSource::Text("first"), &opts(&first))
            .unwrap_or_else(|e| panic!("{label}: first write failed: {e}"));

        let err = write_carrier(&first, PayloadSource::Text("second"), &opts(&second)).unwrap_err();
        assert!(
            err.to_string().contains("already contains hidden data"),
            "{}: {err}",
            fmt.name()
        );
        assert!(
            !second.exists(),
            "{}: no output must be produced",
            fmt.name()
        );
    }
}

// --------------------------------------------------------------------------- capacity reporting per format

#[test]
fn inspect_reports_all_strategies_for_every_format() {
    for fmt in [Fmt::Png, Fmt::Jpeg, Fmt::Mp4, Fmt::Zip, Fmt::Pdf, Fmt::Pe] {
        let dir = scratch(&format!("caps_{}", fmt.name().to_lowercase()));
        let carrier = dir.join(format!("c.{}", fmt.ext()));
        fs::write(&carrier, fmt.carrier()).unwrap();

        let insp = inspect_carrier(&carrier, None).expect("inspect");
        let names: Vec<&str> = insp
            .strategies
            .iter()
            .map(|c| c.strategy.as_str())
            .collect();
        let expected: Vec<&str> = match fmt {
            Fmt::Png => vec!["chunk", "eof"],
            Fmt::Jpeg => vec!["app_segment", "eof"],
            Fmt::Mp4 => vec!["box_uuid", "eof"],
            Fmt::Zip => vec!["pre_cd_inject", "eof"],
            Fmt::Pdf => vec!["incremental", "eof"],
            Fmt::Pe => vec!["pe_codebits", "pe_slack", "pe_overlay", "eof"],
        };
        assert_eq!(names, expected, "{}: strategy order", fmt.name());
        for c in &insp.strategies {
            assert!(!c.limit.is_empty(), "{}: empty limit", fmt.name());
        }
        // At least one strategy must be usable, otherwise nothing can be done.
        assert!(
            insp.strategies.iter().any(|c| c.available),
            "{}: no available strategy",
            fmt.name()
        );
    }
}

#[test]
fn verify_structure_passes_for_a_pristine_carrier_of_every_format() {
    for fmt in [Fmt::Png, Fmt::Jpeg, Fmt::Mp4, Fmt::Zip, Fmt::Pdf, Fmt::Pe] {
        let dir = scratch(&format!("verify_clean_{}", fmt.name().to_lowercase()));
        let carrier = dir.join(format!("c.{}", fmt.ext()));
        fs::write(&carrier, fmt.carrier()).unwrap();

        let v = verify_carrier(&carrier, None).expect("verify");
        assert!(
            v.level1_host.ok,
            "{}: L1 must pass on a pristine carrier: {}",
            fmt.name(),
            v.level1_host.detail
        );
        assert!(!v.level2_envelope.ok, "{}: no envelope yet", fmt.name());
    }
}
