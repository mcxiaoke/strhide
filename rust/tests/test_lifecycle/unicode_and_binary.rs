//! Integration tests for Unicode text, binary payloads of various sizes,
//! and Unicode/Chinese passwords (ported from Python `test_unicode_and_binary.py`).

use crate::common::*;
use std::fs;
use std::path::PathBuf;

use strhide::crypto::compute_file_sha256;
use strhide::errors::StrHideError;
use strhide::structure::{
    PayloadSource, ReadOptions, RestoreOptions, WriteOptions, inspect_carrier, read_carrier,
    remove_carrier, verify_carrier, write_carrier,
};

fn testfiles_dir() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest_dir.parent()?.join("temp").join("testfiles");
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

#[test]
fn test_chinese_and_emoji_text_with_chinese_password() {
    let dir = scratch("chinese_emoji");
    let carrier = dir.join("test_chinese.png");

    let src = testfiles_dir().map(|d| d.join("file-02.png"));
    if let Some(ref p) = src
        && p.exists()
    {
        fs::copy(p, &carrier).unwrap();
    } else {
        fs::write(&carrier, make_png()).unwrap();
    }

    let orig_sha = compute_file_sha256(&carrier).unwrap();
    let chinese_text = "【机密文件】\n\
赵客缦胡缨，吴钩霜雪明。银鞍照白马，飒沓如流星。\n\
十步杀一人，千里不留行。事了拂衣去，深藏身与名。\n\
特殊字符与表情符号：🎯 🚀 👨‍👩‍👧‍👦 \u{200b}\u{feff}\n\
日文与韩文：こんにちは 世界！ 안녕하세요 세계!";
    let chinese_password = "芝麻开门！🔑🔒测试密码_2026年";

    // 1. Write
    let opts = WriteOptions {
        password: Some(chinese_password),
        backup: false,
        ..Default::default()
    };
    let res_w = write_carrier(&carrier, PayloadSource::Text(chinese_text), &opts)
        .expect("write chinese text");
    assert!(res_w.is_encrypted);

    // 2. Inspect with password
    let res_i = inspect_carrier(&carrier, Some(chinese_password)).expect("inspect");
    assert!(res_i.has_hidden_data);
    assert_eq!(res_i.is_encrypted, Some(true));

    // 3. Verify
    let res_v = verify_carrier(&carrier, Some(chinese_password)).expect("verify");
    assert!(res_v.level1_host.ok, "L1: {}", res_v.level1_host.detail);
    assert!(
        res_v.level2_envelope.ok,
        "L2: {}",
        res_v.level2_envelope.detail
    );
    assert!(res_v.level3_crypto.ok, "L3: {}", res_v.level3_crypto.detail);

    // 4. Wrong password test
    let err = read_carrier(
        &carrier,
        &ReadOptions {
            output_path: None,
            password: Some("错误的密码_2026"),
            overwrite: false,
        },
    )
    .unwrap_err();
    match err {
        StrHideError::Password(_) => {}
        other => panic!("expected PasswordError on wrong password, got {other:?}"),
    }

    // 5. Read and check 100% exact byte and string match
    let res_r = read_carrier(
        &carrier,
        &ReadOptions {
            output_path: None,
            password: Some(chinese_password),
            overwrite: false,
        },
    )
    .expect("read");
    let extracted_str = String::from_utf8(res_r.data.clone()).expect("valid utf-8");
    assert_eq!(extracted_str, chinese_text);
    assert_eq!(res_r.data, chinese_text.as_bytes());

    // 6. Remove and check 100% bit-for-bit restoration
    let restored = dir.join("test_chinese.restored.png");
    remove_carrier(
        &carrier,
        &RestoreOptions {
            output_path: Some(&restored),
            password: Some(chinese_password),
            backup: false,
            overwrite: false,
        },
    )
    .expect("remove");
    let restored_sha = compute_file_sha256(&restored).unwrap();
    assert_eq!(restored_sha, orig_sha);
}

#[test]
fn test_arbitrary_binary_payload_with_all_bytes() {
    let dir = scratch("arbitrary_binary");
    let carrier = dir.join("test_binary.jpg");

    let src = testfiles_dir().map(|d| d.join("file-06.jpg"));
    if let Some(ref p) = src
        && p.exists()
    {
        fs::copy(p, &carrier).unwrap();
    } else {
        fs::write(&carrier, make_jpeg()).unwrap();
    }

    let orig_sha = compute_file_sha256(&carrier).unwrap();

    // Generate binary data covering all 256 bytes repeated 64 times
    let mut raw_binary = Vec::with_capacity(256 * 64 + 4096);
    for _ in 0..64 {
        for b in 0..=255u8 {
            raw_binary.push(b);
        }
    }
    // Add deterministic pseudo-random bytes
    for i in 0..4096 {
        raw_binary.push(((i * 73 + 19) & 0xFF) as u8);
    }
    let unicode_password = "P@ss_Пароль_مرحبا_🔐";

    // Write binary
    let opts = WriteOptions {
        password: Some(unicode_password),
        backup: false,
        ..Default::default()
    };
    let res_w = write_carrier(&carrier, PayloadSource::Bytes(&raw_binary), &opts)
        .expect("write raw binary");
    assert_eq!(res_w.raw_size, raw_binary.len() as u64);

    // Read binary
    let res_r = read_carrier(
        &carrier,
        &ReadOptions {
            output_path: None,
            password: Some(unicode_password),
            overwrite: false,
        },
    )
    .expect("read raw binary");
    assert_eq!(res_r.data.len(), raw_binary.len());
    assert_eq!(res_r.data, raw_binary);

    // Remove & check exact bit match
    let restored = dir.join("test_binary.restored.jpg");
    remove_carrier(
        &carrier,
        &RestoreOptions {
            output_path: Some(&restored),
            password: Some(unicode_password),
            backup: false,
            overwrite: false,
        },
    )
    .expect("remove");
    assert_eq!(compute_file_sha256(&restored).unwrap(), orig_sha);
}

#[test]
fn test_large_binary_file_crossing_chunks() {
    let dir = scratch("large_chunks");
    let carrier = dir.join("test_large.mp4");

    let src = testfiles_dir().map(|d| d.join("file-00.mp4"));
    if let Some(ref p) = src
        && p.exists()
    {
        fs::copy(p, &carrier).unwrap();
    } else {
        fs::write(&carrier, make_mp4()).unwrap();
    }

    let orig_carrier_sha = compute_file_sha256(&carrier).unwrap();

    // 5.5 MB payload (crosses 2MB chunk boundary multiple times)
    let large_size = (5.5 * 1024.0 * 1024.0) as usize;
    let mut large_payload = Vec::with_capacity(large_size);
    for i in 0..large_size {
        large_payload.push(((i * 37 + 11) & 0xFF) as u8);
    }
    let complex_password = "复杂中文字符串🔑+Special#Chars@!~";

    let payload_file = dir.join("机密数据_backup.bin");
    fs::write(&payload_file, &large_payload).unwrap();
    let payload_sha = compute_file_sha256(&payload_file).unwrap();

    // 1. Write large file
    let opts = WriteOptions {
        password: Some(complex_password),
        backup: false,
        ..Default::default()
    };
    let res_w = write_carrier(&carrier, PayloadSource::File(&payload_file), &opts)
        .expect("write large file");
    assert_eq!(res_w.raw_size, large_size as u64);

    // 2. Verify level 1, 2, 3
    let res_v = verify_carrier(&carrier, Some(complex_password)).expect("verify large file");
    assert!(res_v.level1_host.ok, "L1: {}", res_v.level1_host.detail);
    assert!(
        res_v.level2_envelope.ok,
        "L2: {}",
        res_v.level2_envelope.detail
    );
    assert!(res_v.level3_crypto.ok, "L3: {}", res_v.level3_crypto.detail);

    // 3. Read out to file
    let extract_dir = dir.join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();
    let res_r = read_carrier(
        &carrier,
        &ReadOptions {
            output_path: Some(&extract_dir),
            password: Some(complex_password),
            overwrite: false,
        },
    )
    .expect("read large file");
    let written_str = res_r.written_file.expect("written file path");
    let extracted_file = PathBuf::from(&written_str);
    assert!(extracted_file.exists());
    assert_eq!(
        extracted_file.file_name().unwrap().to_str().unwrap(),
        "机密数据_backup.bin"
    );

    // Byte-for-byte SHA256 equality check
    let extracted_sha = compute_file_sha256(&extracted_file).unwrap();
    assert_eq!(extracted_sha, payload_sha);
    assert_eq!(
        fs::metadata(&extracted_file).unwrap().len(),
        large_size as u64
    );

    // Compare raw content
    assert_eq!(fs::read(&extracted_file).unwrap(), large_payload);

    // 4. Remove & check carrier 100% restored
    let restored = dir.join("test_large.restored.mp4");
    remove_carrier(
        &carrier,
        &RestoreOptions {
            output_path: Some(&restored),
            password: Some(complex_password),
            backup: false,
            overwrite: false,
        },
    )
    .expect("remove");
    assert_eq!(compute_file_sha256(&restored).unwrap(), orig_carrier_sha);
}

#[test]
fn test_chinese_filename_and_unicode_stealth_mode() {
    let dir = scratch("chinese_stealth");
    let carrier = dir.join("test_stealth.zip");

    let src = testfiles_dir().map(|d| d.join("file-18.zip"));
    if let Some(ref p) = src
        && p.exists()
    {
        fs::copy(p, &carrier).unwrap();
    } else {
        fs::write(&carrier, make_zip()).unwrap();
    }

    let orig_sha = compute_file_sha256(&carrier).unwrap();
    let stealth_password = "绝密_Stealth_密码_👻";
    let mut secret_text = String::from("绝密协议内容：");
    for _ in 0..1024 {
        secret_text.push('A');
    }
    for _ in 0..128 {
        secret_text.push('🌟');
    }
    let secret_bytes = secret_text.into_bytes();

    let secret_file = dir.join("绝密报告.docx");
    fs::write(&secret_file, &secret_bytes).unwrap();

    // 1. Write in stealth mode with File payload source (preserves filename)
    let opts = WriteOptions {
        password: Some(stealth_password),
        stealth: true,
        backup: false,
        ..Default::default()
    };
    let res_w = write_carrier(&carrier, PayloadSource::File(&secret_file), &opts)
        .expect("write stealth ZIP");
    assert!(res_w.is_stealth);

    // 2. Inspect with password
    let res_i = inspect_carrier(&carrier, Some(stealth_password)).expect("inspect stealth");
    assert!(res_i.has_hidden_data);
    assert_eq!(res_i.is_stealth, Some(true));

    // 3. Read in stealth mode
    let res_r = read_carrier(
        &carrier,
        &ReadOptions {
            output_path: None,
            password: Some(stealth_password),
            overwrite: false,
        },
    )
    .expect("read stealth");
    assert_eq!(res_r.data, secret_bytes);
    assert_eq!(res_r.filename, "绝密报告.docx");

    // 4. Remove in stealth mode
    let restored = dir.join("test_stealth.restored.zip");
    remove_carrier(
        &carrier,
        &RestoreOptions {
            output_path: Some(&restored),
            password: Some(stealth_password),
            backup: false,
            overwrite: false,
        },
    )
    .expect("remove");
    assert_eq!(compute_file_sha256(&restored).unwrap(), orig_sha);
}

#[test]
fn test_tiny_and_empty_payloads() {
    let dir = scratch("tiny_empty");
    let carrier1 = dir.join("tiny1.exe");
    let carrier2 = dir.join("empty.exe");

    let src = testfiles_dir().map(|d| d.join("xxhsum.exe"));
    if let Some(ref p) = src
        && p.exists()
    {
        fs::copy(p, &carrier1).unwrap();
        fs::copy(p, &carrier2).unwrap();
    } else {
        let pe_data = make_pe(64);
        fs::write(&carrier1, &pe_data).unwrap();
        fs::write(&carrier2, &pe_data).unwrap();
    }

    let orig_sha1 = compute_file_sha256(&carrier1).unwrap();
    let orig_sha2 = compute_file_sha256(&carrier2).unwrap();

    // Test 1 byte
    let opts1 = WriteOptions {
        password: Some("密_1"),
        backup: false,
        ..Default::default()
    };
    write_carrier(&carrier1, PayloadSource::Bytes(b"X"), &opts1).expect("write 1 byte");
    let res1 = read_carrier(
        &carrier1,
        &ReadOptions {
            output_path: None,
            password: Some("密_1"),
            overwrite: false,
        },
    )
    .expect("read 1 byte");
    assert_eq!(res1.data, b"X");

    let restored1 = dir.join("tiny1.restored.exe");
    remove_carrier(
        &carrier1,
        &RestoreOptions {
            output_path: Some(&restored1),
            password: Some("密_1"),
            backup: false,
            overwrite: false,
        },
    )
    .expect("remove 1 byte");
    assert_eq!(compute_file_sha256(&restored1).unwrap(), orig_sha1);

    // Test empty text
    let opts2 = WriteOptions {
        password: Some("密_2"),
        backup: false,
        ..Default::default()
    };
    write_carrier(&carrier2, PayloadSource::Text(""), &opts2).expect("write empty text");
    let res2 = read_carrier(
        &carrier2,
        &ReadOptions {
            output_path: None,
            password: Some("密_2"),
            overwrite: false,
        },
    )
    .expect("read empty text");
    assert_eq!(res2.data, b"");

    let restored2 = dir.join("empty.restored.exe");
    remove_carrier(
        &carrier2,
        &RestoreOptions {
            output_path: Some(&restored2),
            password: Some("密_2"),
            backup: false,
            overwrite: false,
        },
    )
    .expect("remove empty text");
    assert_eq!(compute_file_sha256(&restored2).unwrap(), orig_sha2);
}
