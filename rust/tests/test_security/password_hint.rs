use crate::common::*;
// Integration tests for password hint functionality (ported from Python `test_password_hint.py`).

use std::fs;

use strhide::crypto::compute_file_sha256;
use strhide::errors::StrHideError;
use strhide::structure::{
    PayloadSource, ReadOptions, RestoreOptions, WriteOptions, inspect_carrier, read_carrier,
    remove_carrier, write_carrier,
};

fn make_dummy_png() -> Vec<u8> {
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

    // IDAT with some padding
    let mut raw = vec![0u8; 2000];
    raw[0] = 0;
    raw[1] = 0xff;
    let mut comp = Vec::new();
    {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let mut encoder = ZlibEncoder::new(&mut comp, Compression::fast());
        encoder.write_all(&raw).unwrap();
        encoder.finish().unwrap();
    }
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&(comp.len() as u32).to_be_bytes());
    chunk.extend_from_slice(b"IDAT");
    chunk.extend_from_slice(&comp);
    let crc = crc32fast::hash(&chunk[4..]);
    chunk.extend_from_slice(&crc.to_be_bytes());
    out.extend_from_slice(&chunk);

    out.extend_from_slice(b"\x00\x00\x00\x00IEND\xaeB`\x82");
    out
}

#[test]
fn test_password_hint_lifecycle() {
    let dir = scratch("lifecycle");
    let carrier = dir.join("test.png");
    fs::write(&carrier, make_dummy_png()).unwrap();
    let orig_sha = compute_file_sha256(&carrier).unwrap();

    let hint_text = "高中班级号+母亲生日年份（如：3班1975）";
    let pwd = "MySecretPassword_2026!";
    let secret = "This is a very top secret message.";

    // 1. Write with password and hint
    let opts = WriteOptions::default()
        .with_password(pwd)
        .with_password_hint(hint_text)
        .with_backup(false);
    let res_w =
        write_carrier(&carrier, PayloadSource::Text(secret), &opts).expect("write with hint");
    assert_eq!(res_w.password_hint.as_deref(), Some(hint_text));
    assert!(res_w.is_encrypted);

    // 2. Inspect carrier without password: hint must be visible!
    let res_insp = inspect_carrier(&carrier, None).expect("inspect");
    assert_eq!(res_insp.is_encrypted, Some(true));
    assert_eq!(res_insp.password_hint.as_deref(), Some(hint_text));

    // 3. Read carrier without password: the error carries the hint as a
    // structured field (and still renders it into the message).
    let err = read_carrier(
        &carrier,
        &ReadOptions::default()
            .with_output_option(None)
            .with_password_option(None)
            .with_overwrite(false),
    )
    .unwrap_err();
    assert_eq!(err.hint(), Some(hint_text), "structured hint: {err:?}");
    assert!(
        err.to_string().contains(hint_text),
        "error message must contain hint: '{err}'"
    );

    // 4. Read carrier with correct password: must extract successfully!
    let res_r = read_carrier(
        &carrier,
        &ReadOptions::default()
            .with_output_option(None)
            .with_password(pwd)
            .with_overwrite(false),
    )
    .expect("read");
    assert_eq!(String::from_utf8(res_r.data).unwrap(), secret);

    // 5. Remove carrier: 100% loss-free restore
    let restored = dir.join("test.restored.png");
    remove_carrier(
        &carrier,
        &RestoreOptions::default()
            .with_output(&restored)
            .with_password(pwd)
            .with_backup(false)
            .with_overwrite(false),
    )
    .expect("remove");
    assert_eq!(compute_file_sha256(&restored).unwrap(), orig_sha);
}

#[test]
fn test_stealth_mode_rejects_hint() {
    let dir = scratch("stealth_reject");
    let carrier = dir.join("test.png");
    fs::write(&carrier, make_dummy_png()).unwrap();

    let opts = WriteOptions::default()
        .with_password("pwd")
        .with_password_hint("some hint")
        .with_stealth(true)
        .with_backup(false);
    let err = write_carrier(&carrier, PayloadSource::Text("secret"), &opts).unwrap_err();
    match err {
        StrHideError::General(msg) => {
            assert!(
                msg.contains("stealth"),
                "expected stealth hint error, got '{msg}'"
            );
        }
        other => panic!("expected General error for stealth hint, got {other:?}"),
    }
}

#[test]
fn test_no_hint_behavior() {
    let dir = scratch("no_hint");
    let carrier = dir.join("test.png");
    fs::write(&carrier, make_dummy_png()).unwrap();
    let orig_sha = compute_file_sha256(&carrier).unwrap();

    let opts = WriteOptions::default()
        .with_password("pwd123")
        .with_password_hint_option(None)
        .with_backup(false);
    write_carrier(&carrier, PayloadSource::Text("no hint secret"), &opts).expect("write");

    // Inspect without password: password_hint is None
    let res_i = inspect_carrier(&carrier, None).expect("inspect");
    assert_eq!(res_i.password_hint, None);

    // Read without password: fails with password required, but NO hint
    let err = read_carrier(
        &carrier,
        &ReadOptions::default()
            .with_output_option(None)
            .with_password_option(None)
            .with_overwrite(false),
    )
    .unwrap_err();
    assert_eq!(err.hint(), None, "no hint should be present: {err:?}");
    assert!(
        !err.to_string().contains("Hint:"),
        "no hint should be present in message: '{err}'"
    );

    // Read with password
    let res_r = read_carrier(
        &carrier,
        &ReadOptions::default()
            .with_output_option(None)
            .with_password("pwd123")
            .with_overwrite(false),
    )
    .expect("read");
    assert_eq!(String::from_utf8(res_r.data).unwrap(), "no hint secret");

    // Remove
    let restored = dir.join("test.restored.png");
    remove_carrier(
        &carrier,
        &RestoreOptions::default()
            .with_output(&restored)
            .with_password("pwd123")
            .with_backup(false)
            .with_overwrite(false),
    )
    .expect("remove");
    assert_eq!(compute_file_sha256(&restored).unwrap(), orig_sha);
}

#[test]
fn test_hint_size_limit() {
    let dir = scratch("hint_size");
    let carrier = dir.join("test.png");
    fs::write(&carrier, make_dummy_png()).unwrap();

    // Oversized hint (> 1024 bytes)
    let long_hint = "H".repeat(1025);
    let opts = WriteOptions::default()
        .with_password("pwd")
        .with_password_hint(&long_hint)
        .with_backup(false);
    let err = write_carrier(&carrier, PayloadSource::Text("secret"), &opts).unwrap_err();
    match err {
        StrHideError::General(msg) => {
            assert!(
                msg.contains("1024") || msg.contains("hint"),
                "expected size limit error, got '{msg}'"
            );
        }
        other => panic!("expected size limit error, got {other:?}"),
    }
}

/// P0-3: the hint is plaintext (it has to be readable without the password),
/// so it is bound into the AEAD instead of being trusted as-is. Its bytes are
/// part of `EnvelopeHeader::auth_aad`, which means an attacker who rewrites the
/// hint -- the classic social-engineering / terminal-escape vector -- breaks
/// both the metadata seal and every payload chunk seal.
#[test]
fn tampered_hint_breaks_authentication() {
    use strhide::structure::envelope::{EnvelopeTrailer, HEADER_SIZE, TRAILER_SIZE};

    let dir = scratch("hint_tamper");
    let carrier = dir.join("c.png");
    let stego = dir.join("s.png");
    fs::write(&carrier, make_dummy_png()).unwrap();
    write_carrier(
        &carrier,
        PayloadSource::Text("hint-bound payload"),
        &WriteOptions::default()
            .with_output(&stego)
            .with_password("hint-pw")
            .with_password_hint("remember the cat")
            .with_strategy("eof")
            .with_backup(false),
    )
    .unwrap();

    // Flip one byte of the hint body, keeping everything else (offsets, lengths,
    // trailer) untouched -- the tamper the AAD extension has to catch.
    let mut data = fs::read(&stego).unwrap();
    let n = data.len();
    let trailer = EnvelopeTrailer::unpack(&data[n - TRAILER_SIZE..], None).unwrap();
    let hint_pos = trailer.ube_offset as usize + HEADER_SIZE + 2;
    data[hint_pos] ^= 0x01;
    fs::write(&stego, data).unwrap();

    let err = read_carrier(
        &stego,
        &ReadOptions::default()
            .with_output(&dir.join("out.bin"))
            .with_password("hint-pw"),
    )
    .expect_err("a tampered hint must not decrypt");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("password") || msg.contains("corrupt"),
        "unexpected error: {msg}"
    );

    let verified = strhide::structure::verify_carrier(&stego, Some("hint-pw")).unwrap();
    assert!(
        !verified.level3_crypto.ok,
        "verify accepted a tampered hint: {}",
        verified.level3_crypto.detail
    );

    // The untampered carrier still works: the change is about tamper evidence,
    // not about rejecting hints in general.
    let clean = dir.join("clean.png");
    write_carrier(
        &carrier,
        PayloadSource::Text("hint-bound payload"),
        &WriteOptions::default()
            .with_output(&clean)
            .with_password("hint-pw")
            .with_password_hint("remember the cat")
            .with_strategy("eof")
            .with_backup(false),
    )
    .unwrap();
    let res = read_carrier(
        &clean,
        &ReadOptions::default()
            .with_output(&dir.join("clean.out"))
            .with_password("hint-pw"),
    )
    .unwrap();
    assert_eq!(res.data.as_slice(), b"hint-bound payload");
}
