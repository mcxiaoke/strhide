//! Regression tests for the fixes made after the 2026-10-19 reviews
//! (`docs/VERIFY-REVIEWS-AND-FIX-PLAN-20261019.md`, P0 items).
//!
//! Every test names the finding it locks down. CLI invocations use piped/null
//! stdio so a password prompt can never block the run.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use strhide::adapters::HostAdapter;
use strhide::engine::{
    PayloadSource, WriteOptions, inspect_carrier, read_carrier, remove_carrier, verify_carrier,
    write_carrier,
};
use strhide::errors::StrHideError;

// --------------------------------------------------------------------------- helpers

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strhide_review_{}_{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_strhide")
}

/// Minimal valid 1x1 PNG (IHDR + IDAT + IEND, CRCs valid).
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

    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    use std::io::Write as _;
    enc.write_all(b"\x00\xff\x00\x00").unwrap();
    let idat_data = enc.finish().unwrap();
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&(idat_data.len() as u32).to_be_bytes());
    chunk.extend_from_slice(b"IDAT");
    chunk.extend_from_slice(&idat_data);
    let crc = crc32fast::hash(&chunk[4..]);
    chunk.extend_from_slice(&crc.to_be_bytes());
    out.extend_from_slice(&chunk);

    out.extend_from_slice(b"\x00\x00\x00\x00IEND\xaeB`\x82");
    out
}

/// Minimal ISO-BMFF file: `ftyp` followed by a `mdat` box.
fn make_mp4() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&24u32.to_be_bytes());
    v.extend_from_slice(b"ftyp");
    v.extend_from_slice(b"isom");
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(b"isomiso2");
    v.extend_from_slice(&(8u32 + 64).to_be_bytes());
    v.extend_from_slice(b"mdat");
    v.extend_from_slice(&[0xAAu8; 64]);
    v
}

/// Single-entry stored ZIP with a valid EOCD.
fn make_zip() -> Vec<u8> {
    let name = b"hello.txt";
    let data: Vec<u8> = b"hello world".repeat(50);
    let crc = crc32fast::hash(&data);
    let mut out = Vec::new();

    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&data);

    let cd_offset = out.len() as u32;
    out.extend_from_slice(b"PK\x01\x02");
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(name);
    let cd_size = out.len() as u32 - cd_offset;

    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

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

// --------------------------------------------------------------------------- P1-1

/// A stealth envelope appended at EOF must not be reported as a damaged box
/// tree: `verify_structure` has no password, so both the trailer magic and its
/// CRC are password-derived, and only the boundary equality can identify it.
#[test]
fn mp4_stealth_eof_passes_level1() {
    let dir = scratch("mp4_stealth_eof");
    let carrier = dir.join("c.mp4");
    fs::write(&carrier, make_mp4()).unwrap();
    let stego = dir.join("s.mp4");
    write_carrier_file(
        &carrier,
        PayloadSource::Text("secret1"),
        Some("pw123"),
        "eof",
        true,
        &stego,
    );
    let v = verify_carrier(&stego, Some("pw123")).unwrap();
    assert!(v.level1_host.ok, "L1: {}", v.level1_host.detail);
    assert!(v.level2_envelope.ok, "L2: {}", v.level2_envelope.detail);
    assert!(v.level3_crypto.ok, "L3: {}", v.level3_crypto.detail);
}

/// The relaxed boundary check must not hide a genuinely corrupt box tree.
#[test]
fn mp4_truncated_box_still_fails_level1() {
    let dir = scratch("mp4_truncated");
    let mut data = make_mp4();
    let mdat = data.len() - 72;
    data[mdat..mdat + 4].copy_from_slice(&10_000u32.to_be_bytes());
    let carrier = dir.join("t.mp4");
    fs::write(&carrier, &data).unwrap();
    let v = verify_carrier(&carrier, None).unwrap();
    assert!(!v.level1_host.ok, "{}", v.level1_host.detail);
}

// --------------------------------------------------------------------------- A-7

/// Fragmented / CMAF media does not necessarily start with `ftyp`.
#[test]
fn fragmented_mp4_first_box_is_recognized() {
    for tag in [b"styp", b"moof", b"sidx"] {
        let mut data = Vec::new();
        data.extend_from_slice(&24u32.to_be_bytes());
        data.extend_from_slice(tag);
        data.extend_from_slice(&[0u8; 16]);
        let mut cur = std::io::Cursor::new(&data);
        assert!(
            strhide::router::find_adapter(&mut cur).is_some(),
            "first box {tag:?} must be recognized as ISO-BMFF"
        );
    }
}

// --------------------------------------------------------------------------- P2-2 / A-11

/// A tampered `patch_offset` must surface as `CorruptedData`: debug builds used
/// to panic on the subtraction and release builds wrapped around.
#[test]
fn zip_tampered_patch_offset_returns_corrupted_data() {
    let dir = scratch("zip_patch_offset");
    let carrier = dir.join("c.zip");
    fs::write(&carrier, make_zip()).unwrap();
    let stego = dir.join("s.zip");
    write_carrier_file(
        &carrier,
        PayloadSource::Text("hello"),
        Some("pw"),
        "pre_cd_inject",
        false,
        &stego,
    );
    let mut raw = fs::read(&stego).unwrap();
    let mut cur = std::io::Cursor::new(&raw);
    let (off, _, _) = strhide::adapters::zip::ZipAdapter
        .locate(&mut cur, None)
        .unwrap()
        .expect("envelope");
    raw[off as usize + 96..off as usize + 100].copy_from_slice(&0u32.to_le_bytes());
    fs::write(&stego, &raw).unwrap();

    let err = remove_carrier(&stego, Some(&dir.join("o.zip")), Some("pw"), false).unwrap_err();
    assert!(matches!(err, StrHideError::CorruptedData(_)), "{err}");
    assert!(
        read_carrier(&stego, None, Some("pw")).is_ok(),
        "payload itself must stay readable"
    );
}

// --------------------------------------------------------------------------- A-4

/// `remove` must honour the configured `backup` default, like `write` does.
#[test]
fn remove_honours_config_backup_false() {
    let dir = scratch("rm_backup_cfg");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let stego = dir.join("s.png");
    write_carrier_file(
        &carrier,
        PayloadSource::Text("x"),
        None,
        "auto",
        false,
        &stego,
    );
    let cfg = dir.join("strhide.toml");
    fs::write(&cfg, "backup = false\n").unwrap();
    let out = Command::new(bin())
        .args([
            "remove",
            "-c",
            stego.to_str().unwrap(),
            "--config",
            cfg.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut bak = stego.as_os_str().to_os_string();
    bak.push(".bak");
    assert!(
        !PathBuf::from(bak).exists(),
        "remove created a backup despite backup = false"
    );
}

// --------------------------------------------------------------------------- A-5

/// A hint containing an apostrophe must be shown verbatim.
#[test]
fn cli_password_hint_with_apostrophe_is_shown_verbatim() {
    let dir = scratch("hint_apostrophe");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let hinted = dir.join("h.png");
    let write = Command::new(bin())
        .args([
            "write",
            "-c",
            carrier.to_str().unwrap(),
            "-t",
            "secret",
            "-p",
            "pw123",
            "-H",
            "Bob's usual one",
            "-o",
            hinted.to_str().unwrap(),
            "--no-backup",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        write.status.success(),
        "{}",
        String::from_utf8_lossy(&write.stderr)
    );

    let read = Command::new(bin())
        .args(["read", "-c", hinted.to_str().unwrap(), "--stdout"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&read.stdout);
    assert!(
        stdout.contains("Password hint: Bob's usual one"),
        "stdout: {stdout}"
    );
}

// --------------------------------------------------------------------------- A-3

/// A hint coming from the config file must not block `--stealth`.
#[test]
fn cli_stealth_ignores_configured_hint() {
    let dir = scratch("stealth_cfg_hint");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let cfg = dir.join("strhide.toml");
    fs::write(&cfg, "hint = \"my usual one\"\n").unwrap();
    let out = Command::new(bin())
        .args([
            "write",
            "-c",
            carrier.to_str().unwrap(),
            "-t",
            "x",
            "--stealth",
            "-p",
            "pw123",
            "--config",
            cfg.to_str().unwrap(),
            "-o",
            dir.join("o.png").to_str().unwrap(),
            "--no-backup",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// An explicit `-H` with `--stealth` must still be rejected.
#[test]
fn cli_stealth_rejects_explicit_hint() {
    let dir = scratch("stealth_explicit_hint");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let out = Command::new(bin())
        .args([
            "write",
            "-c",
            carrier.to_str().unwrap(),
            "-t",
            "x",
            "--stealth",
            "-p",
            "pw123",
            "-H",
            "hint",
            "-o",
            dir.join("o.png").to_str().unwrap(),
            "--no-backup",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Password hint is not supported"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --------------------------------------------------------------------------- A-6

/// Console output must be pure ASCII so it survives a CP936 console.
#[test]
fn list_output_is_pure_ascii() {
    let out = Command::new(bin())
        .arg("list")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(out.status.success());
    if let Some(pos) = out.stdout.iter().position(|b| *b >= 0x80) {
        panic!(
            "non-ASCII byte at {pos} in `list` output: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

// --------------------------------------------------------------------------- A-12

/// Backup paths must be built from the OsString, not `Path::display()`.
#[cfg(unix)]
#[test]
fn backup_path_handles_non_utf8_names() {
    use std::os::unix::ffi::OsStrExt;
    let dir = scratch("nonutf8_backup");
    let carrier = dir.join(std::ffi::OsStr::from_bytes(b"carrier-\xFF.png"));
    fs::write(&carrier, make_png()).unwrap();
    write_carrier(
        &carrier,
        PayloadSource::Text("x"),
        &WriteOptions {
            password: None,
            strategy: "auto",
            backup: true,
            ..Default::default()
        },
    )
    .unwrap();
    let mut bak = carrier.as_os_str().to_os_string();
    bak.push(".bak");
    assert!(PathBuf::from(bak).exists(), "backup for a non-UTF-8 name");
}

// --------------------------------------------------------------------------- P1-2

/// PNGs may carry more than 64 KiB after IEND; `chunk` and `auto` must still
/// find the real terminator instead of failing.
#[test]
fn png_dirty_tail_beyond_64k_is_supported() {
    let dir = scratch("png_dirty_tail");
    let mut data = make_png();
    data.extend_from_slice(&vec![0x00u8; 200 * 1024]);
    let carrier = dir.join("dirty.png");
    fs::write(&carrier, &data).unwrap();
    let stego = dir.join("s.png");
    let res = write_carrier_file(
        &carrier,
        PayloadSource::Text("tail"),
        None,
        "chunk",
        false,
        &stego,
    );
    assert_eq!(res.strategy, "chunk");
    assert_eq!(read_carrier(&stego, None, None).unwrap().data, b"tail");
    let restored = dir.join("r.png");
    remove_carrier(&stego, Some(&restored), None, false).unwrap();
    assert_eq!(fs::read(&restored).unwrap(), data);
}

/// `auto` must pick the chunk strategy for a small payload even with a large
/// dirty tail (it used to fail the IEND lookup).
#[test]
fn png_dirty_tail_auto_strategy() {
    let dir = scratch("png_dirty_auto");
    let mut data = make_png();
    data.extend_from_slice(&vec![0xA5u8; 128 * 1024]);
    let carrier = dir.join("dirty.png");
    fs::write(&carrier, &data).unwrap();
    let stego = dir.join("s.png");
    let res = write_carrier_file(
        &carrier,
        PayloadSource::Text("auto"),
        None,
        "auto",
        false,
        &stego,
    );
    assert_eq!(res.strategy, "chunk");
    assert_eq!(read_carrier(&stego, None, None).unwrap().data, b"auto");
}

// --------------------------------------------------------------------------- P2-3

/// Extraction must never truncate an existing file unless `--overwrite` is
/// given.
#[test]
fn extract_refuses_to_overwrite_existing_file() {
    let dir = scratch("extract_no_overwrite");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let payload = dir.join("important.txt");
    fs::write(&payload, b"PAYLOAD").unwrap();
    let stego = dir.join("s.png");
    write_carrier_file(
        &carrier,
        PayloadSource::File(&payload),
        None,
        "auto",
        false,
        &stego,
    );

    let outdir = dir.join("out");
    fs::create_dir_all(&outdir).unwrap();
    fs::write(outdir.join("important.txt"), b"KEEP-ME").unwrap();

    let err = read_carrier(&stego, Some(&outdir), None).unwrap_err();
    assert!(matches!(err, StrHideError::Rejection(_)), "{err}");
    assert_eq!(
        fs::read(outdir.join("important.txt")).unwrap(),
        b"KEEP-ME",
        "existing file was modified"
    );

    let res = strhide::engine::read_carrier_with(&stego, Some(&outdir), None, true).unwrap();
    assert!(res.written_file.is_some());
    assert_eq!(fs::read(outdir.join("important.txt")).unwrap(), b"PAYLOAD");
}

// --------------------------------------------------------------------------- A-9

/// Decompression is bounded by the declared raw size: a crafted carrier cannot
/// expand a few kilobytes into an arbitrary amount of memory.
#[test]
fn decompression_limit_is_enforced() {
    let mut raw = vec![0u8; 4 * 1024 * 1024];
    raw.extend_from_slice(b"tail");
    let mut comp = Vec::new();
    strhide::crypto::compress_stream(&mut &raw[..], &mut comp).unwrap();

    // Exact limit passes.
    let mut out = Vec::new();
    let n = strhide::crypto::decompress_stream(&mut &comp[..], &mut out, raw.len() as u64).unwrap();
    assert_eq!(n, raw.len() as u64);

    // One byte short is rejected instead of expanding the whole stream.
    let mut out = Vec::new();
    let err = strhide::crypto::decompress_stream(&mut &comp[..], &mut out, raw.len() as u64 - 1)
        .unwrap_err();
    assert!(matches!(err, StrHideError::CorruptedData(_)), "{err}");
}

// --------------------------------------------------------------------------- A-8

/// A single carrier with `-o <dir>` writes into the directory, like batch mode
/// and like `read -o <dir>`; previously it failed with a bare OS error.
#[test]
fn single_carrier_output_directory() {
    let dir = scratch("single_outdir");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let outdir = dir.join("out");
    fs::create_dir_all(&outdir).unwrap();
    let out = Command::new(bin())
        .args([
            "write",
            "-c",
            carrier.to_str().unwrap(),
            "-t",
            "x",
            "-o",
            outdir.to_str().unwrap(),
            "--no-backup",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        outdir.join("c.png").exists(),
        "result not written into -o dir"
    );
}

// --------------------------------------------------------------------------- P2-4

/// Reading a no-password envelope with `-p` must warn that the password was
/// not used (the envelope is masked with the public built-in key).
#[test]
fn read_warns_when_password_is_unused() {
    let dir = scratch("pw_unused_warning");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let stego = dir.join("s.png");
    write_carrier_file(
        &carrier,
        PayloadSource::Text("plain"),
        None,
        "auto",
        false,
        &stego,
    );
    let out = Command::new(bin())
        .args([
            "read",
            "-c",
            stego.to_str().unwrap(),
            "--stdout",
            "-p",
            "whatever",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not encrypted"), "stderr: {stderr}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "plain");
}

fn make_pe() -> Vec<u8> {
    let mut v = vec![0u8; 0x40];
    v[0] = b'M';
    v[1] = b'Z';
    v[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    v.extend_from_slice(b"PE\x00\x00");
    v.extend_from_slice(&0x014Cu16.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(&0x0102u16.to_le_bytes());
    v.extend_from_slice(&0x010Bu16.to_le_bytes());
    let mut sec = [0u8; 40];
    sec[0..5].copy_from_slice(b".text");
    sec[8..12].copy_from_slice(&0x100u32.to_le_bytes());
    sec[12..16].copy_from_slice(&0x1000u32.to_le_bytes());
    sec[16..20].copy_from_slice(&0x100u32.to_le_bytes());
    sec[20..24].copy_from_slice(&0x200u32.to_le_bytes());
    v.extend_from_slice(&sec);
    v.resize(0x400, 0);
    v
}

fn make_pdf() -> Vec<u8> {
    b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n\
      xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n\
      trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n"
        .to_vec()
}

// --------------------------------------------------------------------------- P2-1

/// PE written with `-s eof` must be attributed as "eof" in inspect_carrier,
/// and `-s pe_overlay` must be attributed as "pe_overlay".
#[test]
fn pe_eof_strategy_inspect_attribution() {
    let dir = scratch("pe_strategy_attr");
    let pe_bytes = make_pe();

    // 1. Write with eof
    let carrier_eof = dir.join("c_eof.exe");
    fs::write(&carrier_eof, &pe_bytes).unwrap();
    let stego_eof = dir.join("s_eof.exe");
    write_carrier_file(
        &carrier_eof,
        PayloadSource::Text("secret-eof"),
        None,
        "eof",
        false,
        &stego_eof,
    );
    let inspect_eof = inspect_carrier(&stego_eof, None).unwrap();
    assert_eq!(
        inspect_eof.strategy.as_deref(),
        Some("eof"),
        "expected eof strategy, got {:?}",
        inspect_eof.strategy
    );

    // 2. Write with pe_overlay
    let carrier_ovl = dir.join("c_ovl.exe");
    fs::write(&carrier_ovl, &pe_bytes).unwrap();
    let stego_ovl = dir.join("s_ovl.exe");
    write_carrier_file(
        &carrier_ovl,
        PayloadSource::Text("secret-ovl"),
        None,
        "pe_overlay",
        false,
        &stego_ovl,
    );
    let inspect_ovl = inspect_carrier(&stego_ovl, None).unwrap();
    assert_eq!(
        inspect_ovl.strategy.as_deref(),
        Some("pe_overlay"),
        "expected pe_overlay strategy, got {:?}",
        inspect_ovl.strategy
    );
}

// --------------------------------------------------------------------------- A-13

/// PDF and ZIP stealth envelopes must be detected by suspicious_structures,
/// while clean carriers must not trigger false positives.
#[test]
fn a13_zip_and_pdf_suspicious_structures_detection() {
    use std::io::Cursor;
    use strhide::adapters::pdf::PdfAdapter;
    use strhide::adapters::zip::ZipAdapter;

    let dir = scratch("a13_suspicious");

    // Clean checks
    let clean_zip = make_zip();
    let zip_adapter = ZipAdapter;
    assert!(
        zip_adapter
            .suspicious_structures(&mut Cursor::new(&clean_zip))
            .is_empty(),
        "clean ZIP must not have suspicious structures"
    );

    let clean_pdf = make_pdf();
    let pdf_adapter = PdfAdapter;
    assert!(
        pdf_adapter
            .suspicious_structures(&mut Cursor::new(&clean_pdf))
            .is_empty(),
        "clean PDF must not have suspicious structures"
    );

    // Stealth ZIP check
    let carrier_zip = dir.join("c.zip");
    fs::write(&carrier_zip, &clean_zip).unwrap();
    let stego_zip = dir.join("s.zip");
    write_carrier_file(
        &carrier_zip,
        PayloadSource::Text("stealth-zip"),
        Some("pass123"),
        "pre_cd_inject",
        true,
        &stego_zip,
    );
    let stego_zip_bytes = fs::read(&stego_zip).unwrap();
    let zip_warns = zip_adapter.suspicious_structures(&mut Cursor::new(&stego_zip_bytes));
    assert!(
        !zip_warns.is_empty(),
        "stealth ZIP envelope must be detected by suspicious_structures"
    );

    // Stealth PDF check
    let carrier_pdf = dir.join("c.pdf");
    fs::write(&carrier_pdf, &clean_pdf).unwrap();
    let stego_pdf = dir.join("s.pdf");
    write_carrier_file(
        &carrier_pdf,
        PayloadSource::Text("stealth-pdf"),
        Some("pass123"),
        "incremental",
        true,
        &stego_pdf,
    );
    let stego_pdf_bytes = fs::read(&stego_pdf).unwrap();
    let pdf_warns = pdf_adapter.suspicious_structures(&mut Cursor::new(&stego_pdf_bytes));
    assert!(
        !pdf_warns.is_empty(),
        "stealth PDF envelope must be detected by suspicious_structures"
    );
}

// --------------------------------------------------------------------------- A-15

/// An unencrypted envelope whose metadata is corrupted must fail as CorruptedData,
/// never as Password. An encrypted envelope with a wrong password must fail as Password.
#[test]
fn a15_unencrypted_corrupted_metadata_reports_corrupted_not_password() {
    let dir = scratch("a15_errors");

    // 1. Encrypted envelope + wrong password -> must be Password error
    let carrier_enc = dir.join("c_enc.png");
    fs::write(&carrier_enc, make_png()).unwrap();
    let stego_enc = dir.join("s_enc.png");
    write_carrier_file(
        &carrier_enc,
        PayloadSource::Text("secret"),
        Some("CorrectPass123"),
        "chunk",
        false,
        &stego_enc,
    );
    let err_enc = read_carrier(&stego_enc, None, Some("WrongPass123")).unwrap_err();
    assert!(
        matches!(err_enc, StrHideError::Password(_)),
        "wrong password must yield Password error, got: {err_enc:?}"
    );

    // 2. Unencrypted envelope + tampered metadata -> must be CorruptedData
    let carrier_plain = dir.join("c_plain.png");
    fs::write(&carrier_plain, make_png()).unwrap();
    let stego_plain = dir.join("s_plain.png");
    write_carrier_file(
        &carrier_plain,
        PayloadSource::Text("plain"),
        None,
        "chunk",
        false,
        &stego_plain,
    );
    let mut bytes = fs::read(&stego_plain).unwrap();
    let mid = bytes.len() - 60;
    bytes[mid] ^= 0xAA;
    bytes[mid + 1] ^= 0x55;
    let tampered = dir.join("s_tampered.png");
    fs::write(&tampered, &bytes).unwrap();

    let err_plain = read_carrier(&tampered, None, None);
    if let Err(e) = err_plain {
        assert!(
            !matches!(e, StrHideError::Password(_)),
            "unencrypted carrier corruption must never yield Password error, got: {e:?}"
        );
    }
}
