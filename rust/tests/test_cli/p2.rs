//! Regression tests for P2 CLI/security alignment (2026-10-17), batch 3.
//!
//! - #15: `verify` must exit non-zero when Level 1 or Level 2 fails, matching
//!   the Python CLI (Level 3 crypto failures are reported only).
//! - #16: the read password retry must discriminate on the error variant, not
//!   on message text; a stealth envelope read without its password must
//!   produce actionable guidance instead of a bare "not found".
//! - #18: the JAR signature guard must be content-based so a signed archive
//!   renamed to `.zip` cannot bypass it.
//! - #19: `--unescape` must support the full escape set (\xHH, \uXXXX, \U...,
//!   octal, \a\b\f\v) identically in both implementations.

use crate::common::*;
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::process::{Command, Stdio};

use strhide::engine::{PayloadSource, WriteOptions, read_carrier, write_carrier};
use strhide::errors::StrHideError;

// --------------------------------------------------------------------------- helpers

fn make_zip_with_entries(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, data) in entries {
        let crc = crc32fast::hash(data);
        let local_off = out.len() as u32;
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
    }
    let cd_offset = out.len() as u32;
    let cd_size = cd.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn make_minimal_png() -> Vec<u8> {
    include_bytes!("../assets/minimal.png").to_vec()
}

fn patch_header_field(out: &std::path::Path, ube_offset: u64, field_offset: u64, bytes: &[u8]) {
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(out)
        .unwrap();
    f.seek(SeekFrom::Start(ube_offset + field_offset)).unwrap();
    f.write_all(bytes).unwrap();
}

// --------------------------------------------------------------------------- #15 verify exit code

#[test]
fn verify_exit_code_zero_for_valid_carrier() {
    let dir = scratch("verify_exit_ok");
    let carrier = dir.join("c.png");
    let out = dir.join("o.png");
    fs::write(&carrier, make_png()).unwrap();
    write_carrier(
        &carrier,
        PayloadSource::Text("payload"),
        &WriteOptions {
            output_path: Some(&out),
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();

    let status = Command::new(bin())
        .args(["verify", out.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(0), "valid carrier must exit 0");
}

#[test]
fn verify_exit_code_one_when_envelope_header_invalid() {
    let dir = scratch("verify_exit_l2");
    let carrier = dir.join("c.png");
    let out = dir.join("o.png");
    fs::write(&carrier, make_minimal_png()).unwrap();
    write_carrier(
        &carrier,
        PayloadSource::Text("payload"),
        &WriteOptions {
            output_path: Some(&out),
            strategy: "eof",
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();
    let ube_offset = fs::metadata(&carrier).unwrap().len();
    // Unsupported version -> Level 2 fails.
    patch_header_field(&out, ube_offset, 8, &[0x09]);

    let status = Command::new(bin())
        .args(["verify", out.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1), "Level 2 failure must exit 1");
}

#[test]
fn verify_exit_code_one_when_host_structure_broken() {
    let dir = scratch("verify_exit_l1");
    let carrier = dir.join("c.png");
    let out = dir.join("o.png");
    fs::write(&carrier, make_png()).unwrap();
    write_carrier(
        &carrier,
        PayloadSource::Text("payload"),
        &WriteOptions {
            output_path: Some(&out),
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();
    // Flip a byte inside the injected IHDR-like region of the host: simplest
    // structural break is truncating the file mid-envelope is bad; instead
    // corrupt the IEND marker so Level 1 fails while Level 2 stays intact.
    let mut data = fs::read(&out).unwrap();
    let len = data.len();
    data[len - 8..len - 4].copy_from_slice(b"XXXX"); // break IEND type
    fs::write(&out, &data).unwrap();

    let status = Command::new(bin())
        .args(["verify", out.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1), "Level 1 failure must exit 1");
}

// --------------------------------------------------------------------------- #16 stealth guidance + password error variant

#[test]
fn read_stealth_without_password_reports_guidance() {
    let dir = scratch("stealth_guidance");
    let carrier = dir.join("c.png");
    let out = dir.join("o.png");
    fs::write(&carrier, make_png()).unwrap();
    write_carrier(
        &carrier,
        PayloadSource::Text("stealth secret"),
        &WriteOptions {
            output_path: Some(&out),
            password: Some("pw12345"),
            stealth: true,
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();

    // Engine level: NoHiddenDataError carrying actionable guidance.
    let err = read_carrier(&out, None, None).unwrap_err();
    assert!(
        matches!(err, StrHideError::NoHiddenData(_)),
        "expected NoHiddenData variant, got {err:?}"
    );
    assert!(
        err.to_string().contains("stealth envelope"),
        "missing guidance: {err}"
    );

    // CLI level: non-TTY run must fail fast with the guidance in stderr and
    // exit code 1 (no hang, no bare "not found").
    let res = Command::new(bin())
        .args(["read", out.to_str().unwrap(), "--stdout"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(res.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&res.stderr).to_lowercase();
    assert!(
        stderr.contains("stealth envelope"),
        "CLI stderr lacks guidance: {stderr}"
    );
}

#[test]
fn read_encrypted_without_password_raises_password_variant() {
    let dir = scratch("password_variant");
    let carrier = dir.join("c.png");
    let out = dir.join("o.png");
    fs::write(&carrier, make_png()).unwrap();
    write_carrier(
        &carrier,
        PayloadSource::Text("encrypted secret"),
        &WriteOptions {
            output_path: Some(&out),
            password: Some("pw12345"),
            password_hint: Some("the hint"),
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();

    let err = read_carrier(&out, None, None).unwrap_err();
    assert!(
        matches!(err, StrHideError::Password(_)),
        "expected Password variant, got {err:?}"
    );
    assert!(err.to_string().contains("the hint"), "{err}");
}

// --------------------------------------------------------------------------- #18 JAR signature guard decoupled from extension

#[test]
fn signed_zip_renamed_to_zip_is_rejected() {
    let dir = scratch("jar_rename");
    let carrier = dir.join("signed_archive.zip");
    let zip = make_zip_with_entries(&[
        ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n"),
        ("META-INF/SIGNER.SF", b"Signature-Version: 1.0\r\n"),
        ("classes/Dummy.class", b"\xca\xfe\xba\xbe"),
    ]);
    fs::write(&carrier, &zip).unwrap();

    let err = write_carrier(
        &carrier,
        PayloadSource::Text("payload"),
        &WriteOptions {
            output_path: Some(&dir.join("o.zip")),
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        matches!(err, StrHideError::Rejection(_)),
        "expected Rejection variant, got {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("digital signature") && msg.contains("META-INF"),
        "unexpected rejection message: {msg}"
    );
}

#[test]
fn clean_zip_is_still_accepted() {
    let dir = scratch("zip_clean");
    let carrier = dir.join("clean.zip");
    let zip = make_zip_with_entries(&[("hello.txt", b"hello world")]);
    fs::write(&carrier, &zip).unwrap();

    let out = dir.join("o.zip");
    let res = write_carrier(
        &carrier,
        PayloadSource::Text("payload"),
        &WriteOptions {
            output_path: Some(&out),
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(res.strategy, "pre_cd_inject");
    let read = read_carrier(&out, None, None).unwrap();
    assert_eq!(read.data, b"payload");
}

// --------------------------------------------------------------------------- #19 unescape escape set

#[test]
fn cli_unescape_supports_full_escape_set() {
    let dir = scratch("unescape");
    let carrier = dir.join("c.png");
    let out = dir.join("o.png");
    fs::write(&carrier, make_png()).unwrap();

    // Raw string: the CLI receives literal backslash sequences.
    let payload = r"A\x42C\u4E2D\101\tD\U0001F680E\q\a\x4b\xz\g";
    let res = Command::new(bin())
        .args([
            "write",
            carrier.to_str().unwrap(),
            "-t",
            payload,
            "--unescape",
            "-o",
            out.to_str().unwrap(),
            "--no-backup",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(
        res.status.code(),
        Some(0),
        "write failed: {}",
        String::from_utf8_lossy(&res.stderr)
    );

    let read = read_carrier(&out, None, None).unwrap();
    // \x42 -> 'B', \u4E2D -> '中', \101 -> 'A' (octal), \t -> tab,
    // \U0001F680 -> 🚀, \q -> literal backslash-q, \a -> BEL,
    // \x4b -> 'K' (exactly two hex digits), \xz -> verbatim, \g -> verbatim.
    assert_eq!(
        read.data,
        b"ABC\xE4\xB8\xADA\tD\xF0\x9F\x9A\x80E\\q\x07K\\xz\\g".to_vec()
    );
}

#[test]
fn cli_unescape_combines_surrogate_pair() {
    let dir = scratch("unescape_surrogate");
    let carrier = dir.join("c.png");
    let out = dir.join("o.png");
    fs::write(&carrier, make_png()).unwrap();

    // UTF-16 surrogate pair written as two \u escapes must combine into one
    // scalar (and must not leave the trailing digits behind).
    let res = Command::new(bin())
        .args([
            "write",
            carrier.to_str().unwrap(),
            "-t",
            r"P\uD83D\uDE80Q\uD83D\uZZZZ",
            "--unescape",
            "-o",
            out.to_str().unwrap(),
            "--no-backup",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(
        res.status.code(),
        Some(0),
        "write failed: {}",
        String::from_utf8_lossy(&res.stderr)
    );

    let read = read_carrier(&out, None, None).unwrap();
    assert_eq!(read.data, "P\u{1F680}Q\u{FFFD}\\uZZZZ".as_bytes().to_vec());
}

#[test]
fn cli_unescape_keeps_non_ascii_input_intact() {
    let dir = scratch("unescape_cjk");
    let carrier = dir.join("c.png");
    let out = dir.join("o.png");
    fs::write(&carrier, make_png()).unwrap();

    let res = Command::new(bin())
        .args([
            "write",
            carrier.to_str().unwrap(),
            "-t",
            "中文\\n行",
            "--unescape",
            "-o",
            out.to_str().unwrap(),
            "--no-backup",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(res.status.code(), Some(0));

    let read = read_carrier(&out, None, None).unwrap();
    // NFC normalization applies to the text payload; the escapes are decoded
    // and the CJK characters survive unmangled.
    assert_eq!(read.data, "中文\n行".as_bytes().to_vec());
}

// --------------------------------------------------------------------------- #17 parent directory write probe (Unix only)

#[cfg(unix)]
#[test]
fn readonly_parent_directory_is_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch("readonly_parent");
    let sub = dir.join("ro");
    fs::create_dir_all(&sub).unwrap();
    let carrier = sub.join("c.png");
    fs::write(&carrier, make_png()).unwrap();

    fs::set_permissions(&sub, fs::Permissions::from_mode(0o555)).unwrap();
    let res = write_carrier(
        &carrier,
        PayloadSource::Text("payload"),
        &WriteOptions {
            backup: false,
            ..Default::default()
        },
    );
    // Restore permissions so the scratch dir can be cleaned up.
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o755)).unwrap();

    let err = res.unwrap_err();
    assert!(
        err.to_string().contains("directory"),
        "expected a parent-directory rejection, got: {err}"
    );
}

// --------------------------------------------------------------------------- #20 .bak collision protection

#[test]
fn backup_collision_uses_timestamped_name() {
    use strhide::engine::remove_carrier;

    let dir = scratch("bak_collision");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let original = fs::read(&carrier).unwrap();

    // First in-place write creates the plain .bak
    let w1 = write_carrier(
        &carrier,
        PayloadSource::Text("first"),
        &WriteOptions::default(),
    )
    .unwrap();
    let bak1 = w1.backup_file.expect("backup created");
    assert!(bak1.ends_with(".bak"), "{bak1}");
    assert_eq!(fs::read(&bak1).unwrap(), original);

    // Removing in place would previously overwrite that .bak, destroying the
    // only pre-write copy of the carrier.
    let r1 = remove_carrier(&carrier, None, None, true).unwrap();
    let bak2 = r1.backup_file.expect("backup created");
    assert_ne!(bak1, bak2, "backup path was reused");
    assert!(bak2.contains(".bak-"), "{bak2}");
    assert!(
        fs::metadata(&bak1).is_ok(),
        "first backup must be preserved"
    );
    assert!(fs::metadata(&bak2).is_ok(), "second backup must exist");
}
