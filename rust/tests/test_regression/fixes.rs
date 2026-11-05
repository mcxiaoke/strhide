// Regression tests for the P0/P1 security and correctness fixes (2026-10-17).
//
// Mirrors `python/tests/test_security_fixes.py`. All CLI invocations use
// piped/null stdio so a password prompt can never block the test run.

use crate::common::*;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
#[cfg(feature = "cli")]
use std::process::Stdio;

#[cfg_attr(not(unix), allow(dead_code))]
fn make_minimal_png() -> Vec<u8> {
    include_bytes!("../assets/minimal.png").to_vec()
}

use rand::RngExt;

use strhide::core::payload::Payload;
use strhide::crypto::{compute_sha256, decrypt_metadata, derive_keys, encrypt_metadata};
use strhide::errors::StrHideError;
use strhide::params::{LocalParams, MagicPair};
use strhide::stego::{EmbedOptions, embed_carrier};
use strhide::structure::adapters::zip::find_eocd_offset;
use strhide::structure::envelope::{
    EnvelopeHeader, EnvelopeTrailer, HEADER_SIZE as ENVELOPE_HEADER_SIZE, MAX_HINT_LEN,
};
use strhide::structure::params::StructureProfile;
use strhide::structure::{
    PayloadSource, ReadOptions, RestoreOptions, WriteOptions, inspect_carrier_bytes, read_carrier,
    read_carrier_bytes, remove_carrier, remove_carrier_bytes, sanitize_filename, verify_carrier,
    verify_carrier_bytes, write_carrier, write_carrier_bytes,
};

// --------------------------------------------------------------------------- helpers

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

#[cfg(feature = "cli")]
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

#[cfg(feature = "cli")]
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

/// `read_carrier*` must never hand back the raw metadata filename: every
/// consumer (CLI, library, Tauri) writes the payload out under it.
#[test]
fn read_result_filename_is_sanitized() {
    let dir = scratch("read_filename_sanitized");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let stego = dir.join("evil.png");
    let data = b"poc".to_vec();
    write_carrier_file(
        &carrier,
        PayloadSource::Buffered {
            data: &data,
            filename: "../../../evil.sh",
            is_file: true,
        },
        None,
        "chunk",
        false,
        &stego,
    );
    let res = read_carrier(&stego, &ReadOptions::default()).unwrap();
    assert_eq!(
        res.filename, "evil.sh",
        "a recorded name must be reduced to its bare basename"
    );
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
    use strhide::structure::adapters::HostAdapter;
    let mut data = fs::read(&stego).unwrap();
    let mut cf = std::io::Cursor::new(&data);
    let adapter = strhide::structure::adapters::zip::ZipAdapter;
    let (offset, _, _) = adapter.locate(&mut cf, None).unwrap().unwrap();
    let hdr_bytes =
        &data[offset as usize..offset as usize + strhide::structure::envelope::HEADER_SIZE];
    let header = EnvelopeHeader::unpack_with_password(hdr_bytes, None).unwrap();

    let (_, meta_key) =
        strhide::crypto::derive_keys(strhide::crypto::BUILTIN_DEFAULT_KEY, &header.salt).unwrap();
    let sha_hex = strhide::crypto::compute_sha256(b"poc-data")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let evil_meta = strhide::structure::CarrierMetadata {
        filename: "../EVIL.txt".into(),
        raw_size: b"poc-data".len() as u64,
        raw_sha256: sha_hex,
        created_at: 1_700_000_000,
    };
    let evil_compact = evil_meta.encode_compact().unwrap();
    let hint_start = offset as usize + strhide::structure::envelope::HEADER_SIZE;
    let hint = &data[hint_start..hint_start + header.hint_len as usize];
    let enc_meta = strhide::crypto::encrypt_metadata(
        &evil_compact,
        &meta_key,
        &header.base_nonce,
        &header.auth_aad(hint),
    )
    .unwrap();
    assert_eq!(enc_meta.len(), header.meta_len as usize);

    let meta_pos =
        offset as usize + strhide::structure::envelope::HEADER_SIZE + header.hint_len as usize;
    data[meta_pos..meta_pos + enc_meta.len()].copy_from_slice(&enc_meta);
    fs::write(&stego, &data).unwrap();

    let outdir = dir.join("out");
    fs::create_dir_all(&outdir).unwrap();
    let res = read_carrier(
        &stego,
        &ReadOptions {
            output_path: Some(&outdir),
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(outdir.join("EVIL.txt").exists());
    assert!(!dir.join("EVIL.txt").exists());
    // The API returns the sanitised basename, not the attacker-controlled raw
    // field: Tauri and library callers write the payload out under it.
    assert_eq!(res.filename, "EVIL.txt");
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
        res.warnings
            .iter()
            .any(|w| w.message().contains("consistent with a hidden envelope")),
        "expected a SuspiciousStructures warning, got {:?}",
        res.warnings
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
    remove_carrier(
        &stego,
        &RestoreOptions {
            output_path: Some(&s1),
            password: None,
            backup: false,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    let s2 = dir.join("s2.png");
    remove_carrier(
        &s1,
        &RestoreOptions {
            output_path: Some(&s2),
            password: Some("pw1"),
            backup: false,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
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
    let err = remove_carrier(
        &stego,
        &RestoreOptions {
            output_path: Some(&dir.join("x.png")),
            password: Some("pw1"),
            backup: false,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap_err();
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
    let res = read_carrier(
        &stego,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(res.data, b"hello secret");
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
    assert_eq!(res.strategy.name(), "app_segment");
    assert_eq!(res.ube_size, target);
    let out = read_carrier(
        &dir.join("bs.jpg"),
        &ReadOptions {
            output_path: None,
            password: Some("pw"),
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(out.data.len(), payload_len);

    // Verify 100% loss-free restore
    let restored = dir.join("restored.jpg");
    remove_carrier(
        &dir.join("bs.jpg"),
        &RestoreOptions {
            output_path: Some(&restored),
            password: Some("pw"),
            backup: false,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
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
    assert_eq!(res.strategy.name(), "pre_cd_inject");
    let v = verify_carrier(&stego, None).unwrap();
    assert!(v.level2_envelope.ok);
    let restored = dir.join("fcr.zip");
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
    let res = read_carrier(
        &stego,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(res.data, b"x");
    let restored = dir.join("er.zip");
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
fn tampered_meta_len_rejected() {
    let (dir, mut raw, off) = stego_with_trailer("tamper_meta");
    let p = off as usize + 104;
    raw[p..p + 4].copy_from_slice(&0xFFFFFFF0u32.to_le_bytes());
    fs::write(dir.join("t.zip"), &raw).unwrap();
    assert!(
        read_carrier(
            &dir.join("t.zip"),
            &ReadOptions {
                output_path: None,
                password: None,
                overwrite: false,
                ..Default::default()
            }
        )
        .is_err()
    );
}

#[test]
fn tampered_hint_len_rejected() {
    let (dir, mut raw, off) = stego_with_trailer("tamper_hint");
    let p = off as usize + 108;
    raw[p..p + 4].copy_from_slice(&0xFFFFFFF0u32.to_le_bytes());
    fs::write(dir.join("t.zip"), &raw).unwrap();
    assert!(
        read_carrier(
            &dir.join("t.zip"),
            &ReadOptions {
                output_path: None,
                password: None,
                overwrite: false,
                ..Default::default()
            }
        )
        .is_err()
    );
}

#[test]
fn header_validate_against_rejects_oversized_hint() {
    let h = EnvelopeHeader {
        hint_len: MAX_HINT_LEN + 1,
        ..Default::default()
    };
    assert!(h.validate_against(1 << 20, 1 << 21).is_err());
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
            !name.to_string_lossy().contains(".strhide."),
            "leftover temp file: {name:?}"
        );
    }
}

#[test]
fn error_type_is_still_strhide_error() {
    let dir = scratch("errtype");
    let err = read_carrier(
        &dir.join("nonexistent.bin"),
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(matches!(err, StrHideError::General(_)));
}

// --------------------------------------------------------------------------- P0-1 write-path host verification

/// Detection is magic-only: any file starting with `FF D8` is routed to the
/// JPEG adapter. Before the fix, `write_core` never called `verify_structure`,
/// so `auto` fell back to `eof` and appended an envelope to a file that was not
/// a JPEG at all. The malformed host must now be rejected before any output is
/// produced.
#[test]
fn write_rejects_truncated_jpeg_lookalike() {
    let dir = scratch("write_verify_jpeg");
    let carrier = dir.join("fake.jpg");
    fs::write(&carrier, [0xFF, 0xD8, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]).unwrap();
    let out = dir.join("out.jpg");
    let err = write_carrier(
        &carrier,
        PayloadSource::Text("payload"),
        &WriteOptions {
            output_path: Some(&out),
            strategy: "auto",
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_err();
    let message = err.to_string().to_lowercase();
    assert!(
        message.contains("malformed") && message.contains("jpeg"),
        "unexpected error: {err}"
    );
    assert!(!out.exists(), "a rejected host must not produce output");
}

/// Locate a PNG chunk by type: `(chunk_start, data_start, data_len)`.
fn find_png_chunk(data: &[u8], wanted: &[u8; 4]) -> Option<(usize, usize, u32)> {
    let mut pos = 8usize;
    while pos.checked_add(8)? <= data.len() {
        let len = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?);
        if &data[pos + 4..pos + 8] == wanted {
            return Some((pos, pos + 8, len));
        }
        pos = pos.checked_add(12 + len as usize)?;
    }
    None
}

/// Remove one complete PNG chunk (`length + type + data + crc`).
fn remove_png_chunk(data: &[u8], chunk_start: usize, len: u32) -> Vec<u8> {
    let end = chunk_start + 12 + len as usize;
    let mut out = Vec::with_capacity(data.len().saturating_sub(end - chunk_start));
    out.extend_from_slice(&data[..chunk_start]);
    out.extend_from_slice(&data[end..]);
    out
}

/// P1-6: EOF-overlay carriers (RIFF/WAV, MKV, PDF) must pass L1 for stealth
/// and private envelopes. `verify_structure` used to tail-scan with the
/// standard trailer magic only, so `verify` reported the host as corrupted
/// even though `read`/`restore` worked.
#[test]
fn eof_overlay_dialects_pass_l1_on_riff_mkv_pdf() {
    let private = StructureProfile::new()
        .with_default_secret("p1-6-private-secret")
        .with_magic(MagicPair {
            header: *b"p1six-hd",
            trailer: *b"p1s6",
        });
    let official = StructureProfile::default();

    for (label, bytes) in [
        ("wav", make_wav()),
        ("mkv", make_mkv()),
        ("pdf", make_pdf()),
    ] {
        for (dialect, password, profile) in [
            ("stealth", Some("p1-6-stealth"), &official),
            ("private", None, &private),
        ] {
            let (stego, _) = write_carrier_bytes(
                &bytes,
                PayloadSource::Text("eof dialect secret"),
                &WriteOptions {
                    output_path: None,
                    password,
                    strategy: "eof",
                    stealth: password.is_some(),
                    backup: false,
                    ..Default::default()
                },
                &LocalParams::new(),
                profile,
            )
            .unwrap_or_else(|e| panic!("{label}/{dialect}: write failed: {e}"));

            let result = verify_carrier_bytes(&stego, password, profile)
                .unwrap_or_else(|e| panic!("{label}/{dialect}: verify failed: {e}"));
            assert!(
                result.level1_host.ok,
                "{label}/{dialect}: L1 must accept the EOF envelope: {}",
                result.level1_host.detail
            );
            assert!(
                result.level2_envelope.ok,
                "{label}/{dialect}: L2 must accept the envelope: {}",
                result.level2_envelope.detail
            );
            assert!(
                result.level3_crypto.ok,
                "{label}/{dialect}: L3 must accept the payload: {}",
                result.level3_crypto.detail
            );
        }
    }
}

/// P0-2: a PNG `chunk` envelope written first, then content-domain embedding,
/// re-compresses IDAT and moves the private chunk. Before the fix the shifted
/// chunk was only recognised with the *standard* header magic (stealth and
/// private dialects became unreadable), Level 2 rejected the stale coordinates,
/// and `strip` cut at the old offset. Read/verify/restore must work in all
/// three dialects.
#[test]
fn png_chunk_envelope_survives_content_recompression_in_all_dialects() {
    let private = StructureProfile::new()
        .with_default_secret("p0-2-private-secret")
        .with_magic(MagicPair {
            header: *b"p0two-hd",
            trailer: *b"p0t2",
        });
    let official = StructureProfile::default();
    let cover = include_bytes!("../assets/small.png").to_vec();
    let struct_payload = b"structure payload under content";

    for (label, password, profile) in [
        ("official", None, &official),
        ("stealth", Some("p0-2-stealth"), &official),
        ("private", None, &private),
    ] {
        let (stego1, _) = write_carrier_bytes(
            &cover,
            PayloadSource::Text("structure payload under content"),
            &WriteOptions {
                output_path: None,
                password,
                strategy: "chunk",
                stealth: password.is_some(),
                backup: false,
                ..Default::default()
            },
            &LocalParams::new(),
            profile,
        )
        .unwrap_or_else(|e| panic!("{label}: write failed: {e}"));

        let stego2 = embed_carrier(
            &stego1,
            &Payload::bytes(b"content"),
            &EmbedOptions::default(),
        )
        .unwrap_or_else(|e| panic!("{label}: content embed failed: {e}"));

        let (chunk_start, data_off, chunk_len) =
            find_png_chunk(&stego2, b"prIv").expect("private chunk in stego2");
        let (_, data_off_before, _) =
            find_png_chunk(&stego1, b"prIv").expect("private chunk in stego1");
        let header1 = EnvelopeHeader::unpack_with_profile(
            &stego1[data_off_before..data_off_before + 112],
            password,
            profile,
        )
        .expect("unpack header1");
        assert_eq!(
            header1.inject_offset + header1.offset_delta as u64,
            data_off_before as u64
        );
        assert_ne!(
            data_off, data_off_before,
            "{label}: content embedding did not relocate the chunk; the test would not exercise the fix"
        );

        // Read: stealth/custom-magic dialects must find the relocated chunk.
        let read = read_carrier_bytes(&stego2, password, profile)
            .unwrap_or_else(|e| panic!("{label}: read failed: {e}"));
        assert_eq!(read.data, struct_payload, "{label}: payload mismatch");

        // Verify: Level 2 must accept the write-time coordinates plus shift.
        let verified = verify_carrier_bytes(&stego2, password, profile).unwrap();
        assert!(
            verified.level1_host.ok,
            "{label}: L1 failed: {}",
            verified.level1_host.detail
        );
        assert!(
            verified.level2_envelope.ok,
            "{label}: L2 failed: {}",
            verified.level2_envelope.detail
        );

        // The content envelope changed the host, so only the unmodified header
        // can be honestly reported as a mismatch.
        let err = remove_carrier_bytes(&stego2, password, profile).unwrap_err();
        assert!(
            matches!(err, StrHideError::RestoreMismatch { .. }),
            "{label}: expected RestoreMismatch, got {err}"
        );

        // Prove `strip` uses the *located* offset: rewrite the recorded host to
        // the content-stego carrier (stego2 minus the private chunk) and retry.
        // Stale coordinates would cut at the old offset and still mismatch.
        // The digest sits inside the metadata AAD, so re-sealing is mandatory:
        // remove rejects a header whose metadata tag no longer opens.
        let expected_host = remove_png_chunk(&stego2, chunk_start, chunk_len);
        let mut patched = stego2.clone();
        let mut header2 = EnvelopeHeader::unpack_with_profile(
            &patched[data_off..data_off + 112],
            password,
            profile,
        )
        .expect("unpack header2");
        let old_aad = header2.auth_aad(&[]);
        let meta_off = data_off + 112;
        let meta_len = header2.meta_len as usize;
        let meta_key = match password {
            Some(pwd) => derive_keys(pwd, &header2.salt).expect("derive keys").1,
            None => {
                derive_keys(profile.secret(), &header2.salt)
                    .expect("derive keys")
                    .1
            }
        };
        let meta_plain = decrypt_metadata(
            &patched[meta_off..meta_off + meta_len],
            &meta_key,
            &header2.base_nonce,
            &old_aad,
        )
        .expect("decrypt metadata");
        header2.orig_host_size = expected_host.len() as u64;
        header2.orig_host_sha256 = compute_sha256(&expected_host);
        let new_aad = header2.auth_aad(&[]);
        let meta_cipher = encrypt_metadata(&meta_plain, &meta_key, &header2.base_nonce, &new_aad)
            .expect("re-seal metadata");
        let packed = header2
            .pack_with_profile(password, profile)
            .expect("repack header");
        patched[data_off..data_off + 112].copy_from_slice(&packed);
        patched[meta_off..meta_off + meta_len].copy_from_slice(&meta_cipher);

        let (restored, result) = remove_carrier_bytes(&patched, password, profile)
            .unwrap_or_else(|e| panic!("{label}: restore failed after header patch: {e}"));
        assert_eq!(
            restored, expected_host,
            "{label}: strip used stale coordinates"
        );
        assert_eq!(result.restored_size, expected_host.len() as u64);
    }
}

/// `size == 0` means "this box extends to EOF", so a file consisting only of
/// such a box cannot safely receive another top-level box. The old verifier
/// accepted `[size=0][ftyp]` because it only required `ftyp` somewhere.
#[test]
fn write_rejects_bmff_host_without_explicit_sized_box() {
    let dir = scratch("write_verify_bmff");
    let carrier = dir.join("fake.mp4");
    let mut fake = Vec::new();
    fake.extend_from_slice(&0u32.to_be_bytes());
    fake.extend_from_slice(b"ftyp");
    fs::write(&carrier, &fake).unwrap();
    let out = dir.join("out.mp4");
    let err = write_carrier(
        &carrier,
        PayloadSource::Text("payload"),
        &WriteOptions {
            output_path: Some(&out),
            strategy: "auto",
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_err();
    let message = err.to_string().to_lowercase();
    assert!(
        message.contains("malformed") && message.contains("explicitly sized"),
        "unexpected error: {err}"
    );
    assert!(!out.exists(), "a rejected host must not produce output");
}

/// F-02: the restored output is committed only after the envelope metadata
/// AEAD opens. A forged `orig_host_sha256` (which is inside the AAD) must be
/// rejected before the temp file replaces the carrier.
#[test]
fn remove_rejects_forged_host_digest_before_rename() {
    let dir = scratch("f02_forged_digest");
    let profile = StructureProfile::default();
    let cover = include_bytes!("../assets/small.png").to_vec();
    let (stego, _) = write_carrier_bytes(
        &cover,
        PayloadSource::Text("f02 digest payload"),
        &WriteOptions {
            output_path: None,
            strategy: "auto",
            ..Default::default()
        },
        &LocalParams::new(),
        &profile,
    )
    .expect("write envelope");

    let inspected =
        inspect_carrier_bytes(&stego, None, &profile).expect("inspect forged-free carrier");
    let ube_offset = inspected.ube_offset.expect("envelope offset") as usize;
    let mut header = EnvelopeHeader::unpack_with_profile(
        &stego[ube_offset..ube_offset + ENVELOPE_HEADER_SIZE],
        None,
        &profile,
    )
    .expect("unpack header");
    header.orig_host_sha256[0] ^= 0x01;
    let mut forged = stego.clone();
    forged[ube_offset..ube_offset + ENVELOPE_HEADER_SIZE]
        .copy_from_slice(&header.pack_with_profile(None, &profile).expect("repack"));

    let carrier = dir.join("carrier.png");
    fs::write(&carrier, &forged).unwrap();
    let forged_sha = compute_sha256(&fs::read(&carrier).unwrap());
    let out = dir.join("restored.png");

    let err = remove_carrier(
        &carrier,
        &RestoreOptions {
            output_path: Some(&out),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        matches!(err, StrHideError::Password(_)),
        "forged digest must fail metadata authentication, got {err}"
    );
    assert!(!out.exists(), "no restored file may exist after rejection");
    assert_eq!(
        compute_sha256(&fs::read(&carrier).unwrap()),
        forged_sha,
        "the carrier must not be modified before authentication"
    );
}

/// F-02: `patch_offset` and the injection geometry are outside the AAD, so
/// they need explicit physical bounds. Values at or near 4 GiB must be
/// rejected by `validate_against`, never handed to `strip`.
#[test]
fn remove_rejects_out_of_bounds_patch_offset_and_injection_region() {
    let profile = StructureProfile::default();
    let zip = include_bytes!("../assets/small.zip").to_vec();
    let (stego, _) = write_carrier_bytes(
        &zip,
        PayloadSource::Text("f02 zip payload"),
        &WriteOptions {
            output_path: None,
            password: Some("f02-zip-pw"),
            strategy: "auto",
            ..Default::default()
        },
        &LocalParams::new(),
        &profile,
    )
    .expect("write zip envelope");
    let inspected =
        inspect_carrier_bytes(&stego, Some("f02-zip-pw"), &profile).expect("inspect zip carrier");
    let ube_offset = inspected.ube_offset.expect("envelope offset") as usize;
    let base_header = EnvelopeHeader::unpack_with_profile(
        &stego[ube_offset..ube_offset + ENVELOPE_HEADER_SIZE],
        Some("f02-zip-pw"),
        &profile,
    )
    .expect("unpack zip header");
    assert_ne!(base_header.patch_offset, 0, "zip must carry a patch field");

    let host_len = stego.len() as u32;
    for forged_patch in [u32::MAX - 3, u32::MAX, host_len + 100] {
        let mut header = base_header.clone();
        header.patch_offset = forged_patch;
        let mut forged = stego.clone();
        forged[ube_offset..ube_offset + ENVELOPE_HEADER_SIZE].copy_from_slice(
            &header
                .pack_with_profile(Some("f02-zip-pw"), &profile)
                .unwrap(),
        );
        let err = remove_carrier_bytes(&forged, Some("f02-zip-pw"), &profile).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("Patch field at offset"),
            "patch_offset {forged_patch} must fail the physical bound, got {err}"
        );
    }

    // A geometry whose end overflows or lands past the carrier must also fail.
    // The offset must still agree with the located envelope; only the size is
    // inflated, so the rejection comes from the EOF bound rather than the
    // coordinate-agreement check.
    let declared_offset = ube_offset as u64 - u64::from(base_header.offset_delta);
    for (inject_offset, inject_size) in [
        (u64::MAX - 63, 200u64),
        (declared_offset, stego.len() as u64 + 1000),
    ] {
        let mut header = base_header.clone();
        header.inject_offset = inject_offset;
        header.inject_size = inject_size;
        let mut forged = stego.clone();
        forged[ube_offset..ube_offset + ENVELOPE_HEADER_SIZE].copy_from_slice(
            &header
                .pack_with_profile(Some("f02-zip-pw"), &profile)
                .unwrap(),
        );
        let err = remove_carrier_bytes(&forged, Some("f02-zip-pw"), &profile).unwrap_err();
        let message = err.to_string().to_lowercase();
        assert!(
            (message.contains("injected") || message.contains("injection"))
                && (message.contains("past the end")
                    || message.contains("overflow")
                    || message.contains("inconsistent injection coordinates")),
            "injection ({inject_offset}, {inject_size}) must fail the physical bound, got {err}"
        );
    }

    // The untouched carrier still restores normally.
    let (restored, result) =
        remove_carrier_bytes(&stego, Some("f02-zip-pw"), &profile).expect("normal restore");
    assert_eq!(restored, zip);
    assert!(result.verified_identical);
}

// --------------------------------------------------------------------------- F-05

#[allow(clippy::permissions_set_readonly_false)]
#[test]
fn in_place_write_to_a_read_only_carrier_reports_a_permission_error() {
    // Windows rejects a rename over a read-only file with ERROR_ACCESS_DENIED,
    // which the retry loop used to surface as "target busy". The write is
    // refused up front with a permission error, and the carrier is untouched.
    let dir = scratch("f16_read_only_carrier");
    let carrier = dir.join("small.zip");
    fs::write(&carrier, include_bytes!("../assets/small.zip")).unwrap();

    let mut permissions = fs::metadata(&carrier).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&carrier, permissions).unwrap();
    let before = fs::read(&carrier).unwrap();

    let err = write_carrier(
        &carrier,
        PayloadSource::Text("payload"),
        &WriteOptions {
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_err();

    let mut permissions = fs::metadata(&carrier).unwrap().permissions();
    permissions.set_readonly(false);
    fs::set_permissions(&carrier, permissions).unwrap();
    let after = fs::read(&carrier).unwrap();
    let _ = fs::remove_dir_all(&dir);

    assert!(
        matches!(&err, StrHideError::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "a read-only carrier must not be reported as busy: {err:?}"
    );
    assert_eq!(
        after, before,
        "the refused write must leave the carrier intact"
    );
}

#[test]
fn write_rejects_payload_above_the_reader_limit_and_accepts_the_boundary() {
    // `structure_payload_limit` floors at 64 MiB for small carriers. The
    // writer applies the same bound the reader enforces; without it a
    // highly-compressible payload could be written and then never read back.
    const LIMIT: usize = 64 * 1024 * 1024;

    let dir = scratch("f05_payload_limit");
    let carrier = dir.join("small.zip");
    fs::write(&carrier, include_bytes!("../assets/small.zip")).unwrap();

    let too_big = vec![b'a'; LIMIT + 1];
    let rejected = dir.join("too-big.zip");
    let err = write_carrier(
        &carrier,
        PayloadSource::Bytes(&too_big),
        &WriteOptions {
            output_path: Some(&rejected),
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("exceeds the maximum supported by this carrier"),
        "over-limit payload must be refused with the shared limit: {err}"
    );
    assert!(!rejected.exists(), "no output on rejection");

    // Exactly at the limit. Compressible zeros keep the injected stream small
    // while still exercising the 64 MiB raw-size boundary on read.
    let boundary = vec![0u8; LIMIT];
    let accepted = dir.join("boundary.zip");
    write_carrier(
        &carrier,
        PayloadSource::Bytes(&boundary),
        &WriteOptions {
            output_path: Some(&accepted),
            backup: false,
            ..Default::default()
        },
    )
    .expect("boundary payload must be writable");
    let read_back = read_carrier(
        &accepted,
        &ReadOptions {
            output_path: None,
            overwrite: false,
            ..Default::default()
        },
    )
    .expect("boundary payload must be readable");
    assert_eq!(read_back.data.len(), LIMIT);
    assert!(read_back.data.iter().all(|b| *b == 0));
}
