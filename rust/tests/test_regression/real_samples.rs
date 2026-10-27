// Integration tests using real-world files from `temp/real_samples`
// (ported from Python `test_real_samples.py`).

use crate::common::*;
use std::fs;
use std::path::PathBuf;

use strhide::crypto::compute_file_sha256;
use strhide::errors::StrHideError;
use strhide::structure::{
    PayloadSource, ReadOptions, RestoreOptions, WriteOptions, inspect_carrier, read_carrier,
    remove_carrier, verify_carrier, write_carrier,
};

fn samples_dir() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest_dir.parent()?.join("temp").join("real_samples");
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

#[test]
fn test_real_apk_rejection() {
    let sdir = match samples_dir() {
        Some(d) => d,
        None => return,
    };
    let apk_src = sdir.join("sample.apk");
    if !apk_src.exists() {
        return;
    }

    let dir = scratch("apk_reject");
    let carrier = dir.join("test.apk");
    fs::copy(&apk_src, &carrier).unwrap();

    let opts = WriteOptions {
        password: Some("pwd"),
        backup: false,
        ..Default::default()
    };
    let res = write_carrier(&carrier, PayloadSource::Text("Secret to APK"), &opts);
    match res {
        Err(StrHideError::Rejection(msg)) | Err(StrHideError::UnsupportedFormat(msg)) => {
            assert!(
                msg.contains("APK") || msg.contains("support"),
                "unexpected rejection message: {msg}"
            );
        }
        other => panic!("expected rejection for real APK, got {other:?}"),
    }
}

#[test]
fn test_real_signed_pe_rejection() {
    let sdir = match samples_dir() {
        Some(d) => d,
        None => return,
    };
    let exe_src = sdir.join("signed_sample.exe");
    if !exe_src.exists() {
        return;
    }

    let dir = scratch("signed_pe_reject");
    let carrier = dir.join("signed_test.exe");
    fs::copy(&exe_src, &carrier).unwrap();

    let opts = WriteOptions {
        password: Some("pwd"),
        backup: false,
        ..Default::default()
    };
    let res = write_carrier(&carrier, PayloadSource::Text("Secret to signed EXE"), &opts);
    match res {
        Err(StrHideError::Rejection(msg)) | Err(StrHideError::UnsupportedFormat(msg)) => {
            assert!(
                msg.contains("Authenticode") || msg.contains("signature"),
                "unexpected rejection message: {msg}"
            );
        }
        other => panic!("expected rejection for signed PE, got {other:?}"),
    }
}

#[test]
fn test_real_png_full_lifecycle() {
    let sdir = match samples_dir() {
        Some(d) => d,
        None => return,
    };
    let png_src = sdir.join("sample.png");
    if !png_src.exists() {
        return;
    }

    let dir = scratch("real_png");
    let carrier = dir.join("sample.png");
    fs::copy(&png_src, &carrier).unwrap();
    let orig_sha = compute_file_sha256(&carrier).unwrap();
    let secret = "Real PNG Secret Content 2026! 🚀";
    let pwd = "RealPass!PNG";

    // 1. Write
    let opts = WriteOptions {
        password: Some(pwd),
        backup: false,
        ..Default::default()
    };
    let res_w = write_carrier(&carrier, PayloadSource::Text(secret), &opts).expect("write PNG");
    assert_eq!(res_w.format.as_str(), "PNG");
    assert_eq!(res_w.strategy.name(), "chunk");

    // 2. Inspect
    let res_i = inspect_carrier(&carrier, Some(pwd)).expect("inspect PNG");
    assert!(res_i.has_hidden_data);
    assert_eq!(res_i.format.as_str(), "PNG");

    // 3. Verify
    let res_v = verify_carrier(&carrier, Some(pwd)).expect("verify PNG");
    assert!(res_v.level1_host.ok, "L1: {}", res_v.level1_host.detail);
    assert!(
        res_v.level2_envelope.ok,
        "L2: {}",
        res_v.level2_envelope.detail
    );
    assert!(res_v.level3_crypto.ok, "L3: {}", res_v.level3_crypto.detail);

    // 4. Read
    let res_r = read_carrier(
        &carrier,
        &ReadOptions {
            output_path: None,
            password: Some(pwd),
            overwrite: false,
        },
    )
    .expect("read PNG");
    assert_eq!(String::from_utf8(res_r.data).unwrap(), secret);

    // 5. Remove & bit-for-bit restore
    let restored = dir.join("sample.restored.png");
    remove_carrier(
        &carrier,
        &RestoreOptions {
            output_path: Some(&restored),
            password: Some(pwd),
            backup: false,
            overwrite: false,
        },
    )
    .expect("remove PNG");
    let restored_sha = compute_file_sha256(&restored).unwrap();
    assert_eq!(restored_sha, orig_sha);
}

#[test]
fn test_real_jpg_full_lifecycle() {
    let sdir = match samples_dir() {
        Some(d) => d,
        None => return,
    };
    let jpg_src = sdir.join("sample.jpg");
    if !jpg_src.exists() {
        return;
    }

    let dir = scratch("real_jpg");
    let carrier = dir.join("sample.jpg");
    fs::copy(&jpg_src, &carrier).unwrap();
    let orig_sha = compute_file_sha256(&carrier).unwrap();
    let secret = "Real JPEG Secret Payload 2026!";
    let pwd = "RealPass!JPG";

    // 1. Write
    let opts = WriteOptions {
        password: Some(pwd),
        backup: false,
        ..Default::default()
    };
    let res_w = write_carrier(&carrier, PayloadSource::Text(secret), &opts).expect("write JPG");
    assert_eq!(res_w.format.as_str(), "JPEG");

    // 2. Verify
    let res_v = verify_carrier(&carrier, Some(pwd)).expect("verify JPG");
    assert!(res_v.level1_host.ok, "L1: {}", res_v.level1_host.detail);
    assert!(
        res_v.level2_envelope.ok,
        "L2: {}",
        res_v.level2_envelope.detail
    );
    assert!(res_v.level3_crypto.ok, "L3: {}", res_v.level3_crypto.detail);

    // 3. Read
    let res_r = read_carrier(
        &carrier,
        &ReadOptions {
            output_path: None,
            password: Some(pwd),
            overwrite: false,
        },
    )
    .expect("read JPG");
    assert_eq!(String::from_utf8(res_r.data).unwrap(), secret);

    // 4. Remove & bit-for-bit restore
    let restored = dir.join("sample.restored.jpg");
    remove_carrier(
        &carrier,
        &RestoreOptions {
            output_path: Some(&restored),
            password: Some(pwd),
            backup: false,
            overwrite: false,
        },
    )
    .expect("remove JPG");
    let restored_sha = compute_file_sha256(&restored).unwrap();
    assert_eq!(restored_sha, orig_sha);
}

#[test]
fn test_real_mp4_full_lifecycle() {
    let sdir = match samples_dir() {
        Some(d) => d,
        None => return,
    };
    let mp4_src = sdir.join("sample.mp4");
    if !mp4_src.exists() {
        return;
    }

    let dir = scratch("real_mp4");
    let carrier = dir.join("sample.mp4");
    fs::copy(&mp4_src, &carrier).unwrap();
    let orig_sha = compute_file_sha256(&carrier).unwrap();
    let secret = "Real MP4 Secret Audio/Video Key!";
    let pwd = "RealPass!MP4";

    // 1. Write
    let opts = WriteOptions {
        password: Some(pwd),
        backup: false,
        ..Default::default()
    };
    let res_w = write_carrier(&carrier, PayloadSource::Text(secret), &opts).expect("write MP4");
    assert_eq!(res_w.format.as_str(), "MP4");
    assert_eq!(res_w.strategy.name(), "box_uuid");

    // 2. Verify
    let res_v = verify_carrier(&carrier, Some(pwd)).expect("verify MP4");
    assert!(res_v.level1_host.ok, "L1: {}", res_v.level1_host.detail);
    assert!(
        res_v.level2_envelope.ok,
        "L2: {}",
        res_v.level2_envelope.detail
    );
    assert!(res_v.level3_crypto.ok, "L3: {}", res_v.level3_crypto.detail);

    // 3. Read
    let res_r = read_carrier(
        &carrier,
        &ReadOptions {
            output_path: None,
            password: Some(pwd),
            overwrite: false,
        },
    )
    .expect("read MP4");
    assert_eq!(String::from_utf8(res_r.data).unwrap(), secret);

    // 4. Remove & bit-for-bit restore
    let restored = dir.join("sample.restored.mp4");
    remove_carrier(
        &carrier,
        &RestoreOptions {
            output_path: Some(&restored),
            password: Some(pwd),
            backup: false,
            overwrite: false,
        },
    )
    .expect("remove MP4");
    let restored_sha = compute_file_sha256(&restored).unwrap();
    assert_eq!(restored_sha, orig_sha);
}

#[test]
fn test_real_zip_full_lifecycle() {
    let sdir = match samples_dir() {
        Some(d) => d,
        None => return,
    };
    let zip_src = sdir.join("sample.zip");
    if !zip_src.exists() {
        return;
    }

    let dir = scratch("real_zip");
    let carrier = dir.join("sample.zip");
    fs::copy(&zip_src, &carrier).unwrap();
    let orig_sha = compute_file_sha256(&carrier).unwrap();
    let secret = "Real ZIP Archive Hidden Data in Central Directory!";
    let pwd = "RealPass!ZIP";

    // 1. Write
    let opts = WriteOptions {
        password: Some(pwd),
        backup: false,
        ..Default::default()
    };
    let res_w = write_carrier(&carrier, PayloadSource::Text(secret), &opts).expect("write ZIP");
    assert_eq!(res_w.format.as_str(), "ZIP");
    assert_eq!(res_w.strategy.name(), "pre_cd_inject");

    // 2. Verify
    let res_v = verify_carrier(&carrier, Some(pwd)).expect("verify ZIP");
    assert!(res_v.level1_host.ok, "L1: {}", res_v.level1_host.detail);
    assert!(
        res_v.level2_envelope.ok,
        "L2: {}",
        res_v.level2_envelope.detail
    );
    assert!(res_v.level3_crypto.ok, "L3: {}", res_v.level3_crypto.detail);

    // 3. Read
    let res_r = read_carrier(
        &carrier,
        &ReadOptions {
            output_path: None,
            password: Some(pwd),
            overwrite: false,
        },
    )
    .expect("read ZIP");
    assert_eq!(String::from_utf8(res_r.data).unwrap(), secret);

    // 4. Remove & bit-for-bit restore
    let restored = dir.join("sample.restored.zip");
    remove_carrier(
        &carrier,
        &RestoreOptions {
            output_path: Some(&restored),
            password: Some(pwd),
            backup: false,
            overwrite: false,
        },
    )
    .expect("remove ZIP");
    let restored_sha = compute_file_sha256(&restored).unwrap();
    assert_eq!(restored_sha, orig_sha);
}

#[test]
fn test_real_pdf_full_lifecycle() {
    let sdir = match samples_dir() {
        Some(d) => d,
        None => return,
    };
    let pdf_src = sdir.join("sample.pdf");
    if !pdf_src.exists() {
        return;
    }

    let dir = scratch("real_pdf");
    let carrier = dir.join("sample.pdf");
    fs::copy(&pdf_src, &carrier).unwrap();
    let orig_sha = compute_file_sha256(&carrier).unwrap();
    let secret = "Secret hidden inside real PDF document!";
    let pwd = "RealPass!PDF";

    // 1. Write
    let opts = WriteOptions {
        password: Some(pwd),
        backup: false,
        ..Default::default()
    };
    let res_w = write_carrier(&carrier, PayloadSource::Text(secret), &opts).expect("write PDF");
    assert_eq!(res_w.format.as_str(), "PDF");
    assert_eq!(res_w.strategy.name(), "incremental");

    // 2. Verify
    let res_v = verify_carrier(&carrier, Some(pwd)).expect("verify PDF");
    assert!(res_v.level1_host.ok, "L1: {}", res_v.level1_host.detail);
    assert!(
        res_v.level2_envelope.ok,
        "L2: {}",
        res_v.level2_envelope.detail
    );
    assert!(res_v.level3_crypto.ok, "L3: {}", res_v.level3_crypto.detail);

    // 3. Read
    let res_r = read_carrier(
        &carrier,
        &ReadOptions {
            output_path: None,
            password: Some(pwd),
            overwrite: false,
        },
    )
    .expect("read PDF");
    assert_eq!(String::from_utf8(res_r.data).unwrap(), secret);

    // 4. Remove & bit-for-bit restore
    let restored = dir.join("sample.restored.pdf");
    remove_carrier(
        &carrier,
        &RestoreOptions {
            output_path: Some(&restored),
            password: Some(pwd),
            backup: false,
            overwrite: false,
        },
    )
    .expect("remove PDF");
    let restored_sha = compute_file_sha256(&restored).unwrap();
    assert_eq!(restored_sha, orig_sha);
}
