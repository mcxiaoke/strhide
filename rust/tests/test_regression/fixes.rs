// Regression tests for the P0/P1 security and correctness fixes (2026-10-17).
//
// Mirrors `python/tests/test_security_fixes.py`. All CLI invocations use
// piped/null stdio so a password prompt can never block the test run.

use crate::common::*;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Stdio;

#[cfg_attr(not(unix), allow(dead_code))]
fn make_minimal_png() -> Vec<u8> {
    include_bytes!("../assets/minimal.png").to_vec()
}

use rand::RngExt;

use strhide::adapters::zip::find_eocd_offset;
use strhide::engine::{
    PayloadSource, WriteOptions, read_carrier, remove_carrier, sanitize_filename, verify_carrier,
    write_carrier,
};
use strhide::envelope::{EnvelopeHeader, EnvelopeTrailer, MAX_HINT_LEN};
use strhide::errors::StrHideError;

// --------------------------------------------------------------------------- helpers

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

// --------------------------------------------------------------------------- R1 / P0-3

#[test]
fn stealth_requires_password() {
    let dir = scratch("stealth_pwd");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let err = write_carrier(
        &carrier,
        PayloadSource::Text("x"),
        &WriteOptions {
            output_path: Some(&dir.join("o.png")),
            stealth: true,
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("requires a password"), "{err}");
}

#[test]
fn cli_stealth_without_password_fails_fast() {
    let dir = scratch("cli_stealth");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let out = base_cmd()
        .args([
            "write",
            carrier.to_str().unwrap(),
            "-t",
            "x",
            "--stealth",
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
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Password required"), "{stderr}");
}

#[test]
fn cli_no_preserve_time_flag_accepted() {
    let dir = scratch("cli_npt");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let out = base_cmd()
        .args([
            "write",
            carrier.to_str().unwrap(),
            "-t",
            "x",
            "--no-preserve-time",
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

// --------------------------------------------------------------------------- R2 / P0-2

#[test]
fn sanitize_filename_unit() {
    assert_eq!(sanitize_filename("../x.txt"), "x.txt");
    assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
    assert_eq!(sanitize_filename("a/b/c.bin"), "c.bin");
    assert_eq!(sanitize_filename(""), "extracted.bin");
    assert_eq!(sanitize_filename(".."), "extracted.bin");
    assert_eq!(sanitize_filename("."), "extracted.bin");
    assert_eq!(sanitize_filename("..\\..\\evil.exe"), "evil.exe");
    // Cross-platform determinism: separators are sanitized identically on every host.
    assert_eq!(
        sanitize_filename("C:\\Windows\\System32\\evil.dll"),
        "evil.dll"
    );
    assert_eq!(sanitize_filename("mixed/dir\\evil.txt"), "evil.txt");
    assert_eq!(sanitize_filename("/"), "extracted.bin");
    assert_eq!(sanitize_filename("..\\"), "extracted.bin");
    assert_eq!(sanitize_filename("C:"), "extracted.bin");
}

#[test]
fn path_traversal_sanitized() {
    let dir = scratch("traversal");
    let carrier = dir.join("c.zip");
    fs::write(&carrier, make_zip()).unwrap();
    let payload = dir.join("payload.bin");
    fs::write(&payload, b"poc-data").unwrap();
    let stego = dir.join("evil.zip");
    write_carrier_file(
        &carrier,
        PayloadSource::File(&payload),
        None,
        "auto",
        false,
        &stego,
    );

    // Re-encrypt evil metadata filename under BUILTIN_DEFAULT_KEY.
    // The metadata block uses the compact binary layout (FLAG_COMPACT_META).
    use strhide::adapters::HostAdapter;
    let mut data = fs::read(&stego).unwrap();
    let mut cf = std::io::Cursor::new(&data);
    let adapter = strhide::adapters::zip::ZipAdapter;
    let (offset, _, _) = adapter.locate(&mut cf, None).unwrap().unwrap();
    let hdr_bytes = &data[offset as usize..offset as usize + strhide::envelope::HEADER_SIZE];
    let header = EnvelopeHeader::unpack_with_password(hdr_bytes, None).unwrap();

    let (_, meta_key) =
        strhide::crypto::derive_keys(strhide::crypto::BUILTIN_DEFAULT_KEY, &header.salt).unwrap();
    let sha_hex = strhide::crypto::compute_sha256(b"poc-data")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let evil_meta = strhide::engine::CarrierMetadata {
        filename: "../EVIL.txt".into(),
        raw_size: b"poc-data".len() as u64,
        raw_sha256: sha_hex,
        created_at: 1_700_000_000,
    };
    let evil_compact = evil_meta.encode_compact().unwrap();
    let enc_meta = strhide::crypto::encrypt_metadata(
        &evil_compact,
        &meta_key,
        &header.base_nonce,
        &header.get_aad(),
    )
    .unwrap();
    assert_eq!(enc_meta.len(), header.meta_len as usize);

    let meta_pos = offset as usize + strhide::envelope::HEADER_SIZE + header.hint_len as usize;
    data[meta_pos..meta_pos + enc_meta.len()].copy_from_slice(&enc_meta);
    fs::write(&stego, &data).unwrap();

    let outdir = dir.join("out");
    fs::create_dir_all(&outdir).unwrap();
    let res = read_carrier(&stego, Some(&outdir), None).unwrap();
    assert!(outdir.join("EVIL.txt").exists());
    assert!(!dir.join("EVIL.txt").exists());
    assert_eq!(res.filename, "../EVIL.txt"); // metadata preserved verbatim
}

// --------------------------------------------------------------------------- R3 / P0-4

#[test]
fn double_injection_rejected_same_password() {
    let dir = scratch("double_inject");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let stego = dir.join("d.png");
    write_carrier_file(
        &carrier,
        PayloadSource::Text("first"),
        Some("pw1"),
        "auto",
        true,
        &stego,
    );
    let err = write_carrier(
        &stego,
        PayloadSource::Text("second"),
        &WriteOptions {
            output_path: Some(&stego),
            password: Some("pw1"),
            stealth: true,
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("already contains hidden data"),
        "{err}"
    );
}

#[test]
fn structural_warning_for_unknown_password_envelope() {
    let dir = scratch("struct_warn");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let stego = dir.join("w.png");
    write_carrier_file(
        &carrier,
        PayloadSource::Text("first"),
        Some("pw1"),
        "auto",
        true,
        &stego,
    );
    let res = write_carrier_file(
        &stego,
        PayloadSource::Text("second"),
        None,
        "auto",
        false,
        &dir.join("w2.png"),
    );
    assert!(
        res.warning
            .as_deref()
            .unwrap_or("")
            .contains("consistent with a hidden envelope")
    );
}

#[test]
fn double_envelope_reverse_order_removal() {
    let dir = scratch("double_remove");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let orig = fs::read(&carrier).unwrap();
    let stego = dir.join("de.png");
    write_carrier_file(
        &carrier,
        PayloadSource::Text("inner"),
        Some("pw1"),
        "auto",
        true,
        &stego,
    );
    write_carrier_file(
        &stego,
        PayloadSource::Text("outer"),
        None,
        "auto",
        false,
        &stego,
    );

    let s1 = dir.join("s1.png");
    remove_carrier(&stego, Some(&s1), None, false).unwrap();
    let s2 = dir.join("s2.png");
    remove_carrier(&s1, Some(&s2), Some("pw1"), false).unwrap();
    assert_eq!(fs::read(&s2).unwrap(), orig);
}

#[test]
fn double_envelope_inner_first_removal_diagnosed() {
    let dir = scratch("double_diag");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let stego = dir.join("de2.png");
    write_carrier_file(
        &carrier,
        PayloadSource::Text("inner"),
        Some("pw1"),
        "auto",
        true,
        &stego,
    );
    write_carrier_file(
        &stego,
        PayloadSource::Text("outer"),
        None,
        "auto",
        false,
        &stego,
    );
    let err = remove_carrier(&stego, Some(&dir.join("x.png")), Some("pw1"), false).unwrap_err();
    assert!(
        err.to_string().contains("reverse order of injection"),
        "{err}"
    );
}

// --------------------------------------------------------------------------- P0-1

#[test]
fn pdf_dirty_tail_lossless() {
    let dir = scratch("pdf_dirty");
    let carrier = dir.join("dirty.pdf");
    fs::write(&carrier, make_pdf_with_dirty_tail()).unwrap();
    let stego = dir.join("s.pdf");
    write_carrier_file(
        &carrier,
        PayloadSource::Text("hello secret"),
        None,
        "auto",
        false,
        &stego,
    );
    let res = read_carrier(&stego, None, None).unwrap();
    assert_eq!(res.data, b"hello secret");
    let restored = dir.join("r.pdf");
    remove_carrier(&stego, Some(&restored), None, false).unwrap();
    assert_eq!(fs::read(&restored).unwrap(), fs::read(&carrier).unwrap());
}

// --------------------------------------------------------------------------- R4 / P1-5

/// Envelope size for an encrypted write of `payload_len` incompressible bytes,
/// measured against the *current* writer. The metadata block is now the compact
/// binary layout (46 bytes) instead of the 137-byte JSON form, so capacity
/// boundary tests must calibrate against reality instead of predicting the size
/// from a formula. The payload is written as `payload.bin` in both the probe
/// and the real run so the metadata length (filename included) stays identical.
fn measured_encrypted_ube_size(carrier: &Path, payload_len: usize, out: &Path) -> u64 {
    let dir = carrier.parent().unwrap();
    let payload = dir.join("payload.bin");
    let mut buf = vec![0u8; payload_len];
    rand::rng().fill(&mut buf); // incompressible: payload passes through
    fs::write(&payload, &buf).unwrap();
    let res = write_carrier_file(
        carrier,
        PayloadSource::File(&payload),
        Some("pw"),
        "auto",
        false,
        out,
    );
    res.ube_size
}

#[test]
fn auto_capacity_boundary_uses_multisegment_app15() {
    let dir = scratch("auto_boundary");
    let target = 65534u64; // one byte over the JPEG single-segment limit
    let carrier = dir.join("b.jpg");
    fs::write(&carrier, make_jpeg()).unwrap();

    // Calibrate the fixed overhead of an encrypted envelope with one real write.
    let probe_len: usize = 65_000;
    let probe_ube = measured_encrypted_ube_size(&carrier, probe_len, &dir.join("cal.jpg"));
    let overhead = probe_ube - probe_len as u64;
    let payload_len = (target - overhead) as usize;
    // The only way the calibration can drift is a change in the LEB128 width of
    // `raw_size` (16384..2097151 share the 3-byte form), so a generous bound is
    // enough; the exact value is asserted right after the real write.
    assert!(
        payload_len.abs_diff(probe_len) < 1024,
        "calibration drifted: probe {probe_len} -> payload {payload_len}"
    );

    let payload = dir.join("payload.bin");
    let mut buf = vec![0u8; payload_len];
    rand::rng().fill(&mut buf); // incompressible
    fs::write(&payload, &buf).unwrap();

    let res = write_carrier_file(
        &carrier,
        PayloadSource::File(&payload),
        Some("pw"),
        "auto",
        false,
        &dir.join("bs.jpg"),
    );
    // Multi-segment chain now handles >64KB payloads without degrading to eof
    assert_eq!(res.strategy, "app_segment");
    assert_eq!(res.ube_size, target);
    let out = read_carrier(&dir.join("bs.jpg"), None, Some("pw")).unwrap();
    assert_eq!(out.data.len(), payload_len);

    // Verify 100% loss-free restore
    let restored = dir.join("restored.jpg");
    remove_carrier(&dir.join("bs.jpg"), Some(&restored), Some("pw"), false).unwrap();
    assert_eq!(fs::read(&restored).unwrap(), fs::read(&carrier).unwrap());
}

#[test]
fn explicit_oversize_strategy_rejected_without_tmp() {
    let dir = scratch("oversize");
    let payload = dir.join("payload.bin");
    fs::write(&payload, b"test").unwrap();
    let carrier = dir.join("b.jpg");
    fs::write(&carrier, make_jpeg()).unwrap();
    let out = dir.join("bs.jpg");
    let err = write_carrier(
        &carrier,
        PayloadSource::File(&payload),
        &WriteOptions {
            output_path: Some(&out),
            password: Some("pw"),
            strategy: "invalid_strat",
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("not supported by adapter"),
        "{err}"
    );
    assert!(!out.with_extension("jpg.strhide.tmp").exists());
    assert!(!PathBuf::from(format!("{}.strhide.tmp", out.display())).exists());
}

// --------------------------------------------------------------------------- P1-6

#[test]
fn zip_fake_eocd_comment_located_correctly() {
    let dir = scratch("zip_fake");
    let carrier = dir.join("fc.zip");
    fs::write(&carrier, make_zip_with_fake_eocd_comment()).unwrap();
    let mut f = fs::File::open(&carrier).unwrap();
    let (eocd_pos, cd_offset, cd_size) = find_eocd_offset(&mut f).unwrap();
    let size = fs::metadata(&carrier).unwrap().len();
    f.seek(SeekFrom::Start(eocd_pos + 20)).unwrap();
    let mut cl = [0u8; 2];
    f.read_exact(&mut cl).unwrap();
    let comment_len = u16::from_le_bytes(cl) as u64;
    assert_eq!(eocd_pos + 22 + comment_len, size);
    assert!(cd_offset + cd_size <= eocd_pos);
}

#[test]
fn zip_fake_eocd_comment_lifecycle() {
    let dir = scratch("zip_fake_life");
    let carrier = dir.join("fc.zip");
    fs::write(&carrier, make_zip_with_fake_eocd_comment()).unwrap();
    let stego = dir.join("fcs.zip");
    let res = write_carrier_file(
        &carrier,
        PayloadSource::Text("test"),
        None,
        "auto",
        false,
        &stego,
    );
    assert_eq!(res.strategy, "pre_cd_inject");
    let v = verify_carrier(&stego, None).unwrap();
    assert!(v.level2_envelope.ok);
    let restored = dir.join("fcr.zip");
    remove_carrier(&stego, Some(&restored), None, false).unwrap();
    assert_eq!(fs::read(&restored).unwrap(), fs::read(&carrier).unwrap());
}

#[test]
fn zip_eof_stego_still_locatable() {
    let dir = scratch("zip_eof");
    let carrier = dir.join("c.zip");
    fs::write(&carrier, make_zip()).unwrap();
    let stego = dir.join("e.zip");
    write_carrier_file(
        &carrier,
        PayloadSource::Text("x"),
        None,
        "eof",
        false,
        &stego,
    );
    let res = read_carrier(&stego, None, None).unwrap();
    assert_eq!(res.data, b"x");
    let restored = dir.join("er.zip");
    remove_carrier(&stego, Some(&restored), None, false).unwrap();
    assert_eq!(fs::read(&restored).unwrap(), fs::read(&carrier).unwrap());
}

// --------------------------------------------------------------------------- R6

fn stego_with_trailer(name: &str) -> (PathBuf, Vec<u8>, u64) {
    let dir = scratch(name);
    let carrier = dir.join("c.zip");
    fs::write(&carrier, make_zip()).unwrap();
    let stego = dir.join("t.zip");
    write_carrier_file(
        &carrier,
        PayloadSource::Text("t"),
        None,
        "eof",
        false,
        &stego,
    );
    let mut f = fs::File::open(&stego).unwrap();
    let trailer = EnvelopeTrailer::read_from_tail(&mut f, None)
        .unwrap()
        .expect("trailer at EOF");
    let raw = fs::read(&stego).unwrap();
    (dir, raw, trailer.ube_offset)
}

#[test]
fn tampered_version_rejected() {
    let (dir, mut raw, off) = stego_with_trailer("tamper_ver");
    raw[off as usize + 8] = 0x09;
    fs::write(dir.join("t.zip"), &raw).unwrap();
    let err = read_carrier(&dir.join("t.zip"), None, None).unwrap_err();
    assert!(err.to_string().contains("version"), "{err}");
}

#[test]
fn tampered_meta_len_rejected() {
    let (dir, mut raw, off) = stego_with_trailer("tamper_meta");
    let p = off as usize + 104;
    raw[p..p + 4].copy_from_slice(&0xFFFFFFF0u32.to_le_bytes());
    fs::write(dir.join("t.zip"), &raw).unwrap();
    assert!(read_carrier(&dir.join("t.zip"), None, None).is_err());
}

#[test]
fn tampered_hint_len_rejected() {
    let (dir, mut raw, off) = stego_with_trailer("tamper_hint");
    let p = off as usize + 108;
    raw[p..p + 4].copy_from_slice(&0xFFFFFFF0u32.to_le_bytes());
    fs::write(dir.join("t.zip"), &raw).unwrap();
    assert!(read_carrier(&dir.join("t.zip"), None, None).is_err());
}

#[test]
fn header_validate_against_rejects_oversized_hint() {
    let h = EnvelopeHeader {
        hint_len: MAX_HINT_LEN + 1,
        ..Default::default()
    };
    assert!(h.validate_against(1 << 20).is_err());
}

#[test]
fn chunk_len_upper_bound_enforced() {
    // A crafted chunk header claiming a huge length must be rejected before
    // any allocation attempt.
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xFFFFFFF0u32.to_le_bytes());
    buf.extend_from_slice(&[0u8; 64]);
    let mut out = Vec::new();
    let err = strhide::crypto::decrypt_stream_from_chunks(
        &mut &buf[..],
        &mut out,
        &[0u8; 32],
        &[0u8; 12],
        &[0u8; 80],
        1 << 30,
    )
    .unwrap_err();
    assert!(err.to_string().contains("exceeds maximum"), "{err}");
}

// --------------------------------------------------------------------------- permissions

#[cfg(unix)]
#[test]
fn permissions_preserved_on_write() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("perm");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_minimal_png()).unwrap();
    fs::set_permissions(&carrier, fs::Permissions::from_mode(0o755)).unwrap();
    let stego = dir.join("s.bin");
    write_carrier_file(
        &carrier,
        PayloadSource::Text("x"),
        None,
        "auto",
        false,
        &stego,
    );
    let mode = fs::metadata(&stego).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755);
}

#[test]
fn tmp_guard_removes_uncommitted_temp() {
    // A failing inject (explicit oversize JPEG strategy) must not leave
    // *.strhide.tmp behind; covered here as a file-system level assertion.
    let dir = scratch("tmp_guard");
    let carrier = dir.join("c.jpg");
    fs::write(&carrier, make_jpeg()).unwrap();
    let payload = dir.join("payload.bin");
    let mut buf = vec![0u8; 65229];
    rand::rng().fill(&mut buf); // incompressible
    fs::write(&payload, buf).unwrap();
    let out = dir.join("o.jpg");
    let _ = write_carrier(
        &carrier,
        PayloadSource::File(&payload),
        &WriteOptions {
            output_path: Some(&out),
            password: Some("pw"),
            strategy: "app_segment",
            backup: false,
            ..Default::default()
        },
    );
    for entry in fs::read_dir(&dir).unwrap() {
        let name = entry.unwrap().file_name();
        assert!(
            !name.to_string_lossy().contains(".strhide.tmp"),
            "leftover temp file: {name:?}"
        );
    }
}

#[test]
fn error_type_is_still_strhide_error() {
    let dir = scratch("errtype");
    let err = read_carrier(&dir.join("nonexistent.bin"), None, None).unwrap_err();
    assert!(matches!(err, StrHideError::General(_)));
}
