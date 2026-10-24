use std::fs;
use std::path::{Path, PathBuf};

use strhide::errors::StrHideError;
use strhide::stego::{StegoOptions, embed_carrier, extract_carrier, probe_carrier_capacity};

fn resolve_hevc_corpus() -> Option<PathBuf> {
    if let Ok(val) = std::env::var("STRHIDE_HEVC_CORPUS") {
        let p = PathBuf::from(val);
        if p.is_dir() {
            return Some(p);
        }
    }
    let p1 = Path::new("..").join("temp").join("testhevc");
    if p1.is_dir() {
        return Some(p1);
    }
    let p2 = Path::new("temp").join("testhevc");
    if p2.is_dir() {
        return Some(p2);
    }
    None
}

fn find_python_command() -> Option<String> {
    if let Ok(p) = std::env::var("PYTHON") {
        return Some(p);
    }
    if cfg!(windows) && Path::new("C:\\Home\\Develop\\venv\\Scripts\\python.exe").exists() {
        return Some("C:\\Home\\Develop\\venv\\Scripts\\python.exe".into());
    }
    for candidate in &["python3", "python"] {
        if let Ok(out) = std::process::Command::new(candidate)
            .arg("--version")
            .output()
            && out.status.success()
        {
            return Some((*candidate).into());
        }
    }
    None
}

#[test]
#[ignore = "requires local temp/testhevc corpus: run with cargo test --test test_heif_stego_bridge -- --ignored"]
fn test_heif_jpeg_thumbnail_bridge_lifecycle() {
    let corpus = match resolve_hevc_corpus() {
        Some(d) => d,
        None => {
            eprintln!("[SKIP] HEVC corpus not found");
            return;
        }
    };
    let sample_path = corpus.join("IMG_20261018_113710.HEIC");
    if !sample_path.exists() {
        eprintln!("Sample {:?} does not exist, skipping test.", sample_path);
        return;
    }

    let orig_bytes = fs::read(sample_path).expect("read original HEIC");

    // 1. Probe capacity
    let options = StegoOptions::default();
    let cap = probe_carrier_capacity(&orig_bytes, &options).expect("probe capacity");
    assert_eq!(cap.format, "HEIF (JPEG Thumbnail Bridge)");
    assert!(
        cap.available_slots > 500,
        "Should have sufficient slots for embedding"
    );
    assert!(cap.max_raw_payload_bytes > 32);

    // 2. Embed payload
    let payload = b"Hello from strhide content-domain bridge steganography in HEIC thumbnail!";
    let embed_opts = StegoOptions {
        password: Some("bridge_pass_2026".into()),
        ..Default::default()
    };

    let stego_bytes = embed_carrier(&orig_bytes, payload, &embed_opts)
        .expect("embed carrier into HEIF thumbnail bridge");

    assert!(!stego_bytes.is_empty());
    // Primary content is preserved; file size should remain close to original (slight delta for JPEG Huffman re-encoding)
    let delta = (stego_bytes.len() as i64) - (orig_bytes.len() as i64);
    assert!(
        delta.abs() < 10000,
        "Length change should be modest, got {}",
        delta
    );

    // 3. Extract payload with matching password
    let extract_opts = StegoOptions {
        password: Some("bridge_pass_2026".into()),
        ..Default::default()
    };
    let extracted =
        extract_carrier(&stego_bytes, &extract_opts).expect("extract with correct password");
    assert_eq!(
        extracted, payload,
        "Extracted payload must match original 100%"
    );

    // 4. Extract with wrong password must fail cleanly as NoHiddenData
    let wrong_opts = StegoOptions {
        password: Some("wrong_password".into()),
        ..Default::default()
    };
    let wrong_res = extract_carrier(&stego_bytes, &wrong_opts);
    assert!(
        matches!(wrong_res, Err(StrHideError::NoHiddenData(_))),
        "Wrong password must report NoHiddenData, got {:?}",
        wrong_res
    );

    // 5. Structure domain orthogonality: no suspicious UUID or trailing junk
    let mut cursor = std::io::Cursor::new(&stego_bytes);
    let warnings = strhide::adapters::isobmff::isobmff_suspicious_structures(&mut cursor);
    assert!(
        warnings.is_empty(),
        "Stego HEIF must have zero suspicious structural warnings, got: {:?}",
        warnings
    );
}

#[test]
fn test_heif_bridge_unsupported_carrier_fails_gracefully() {
    // Synthetic minimal HEIF container without any bridgeable item (ftyp + free)
    let mut stub = Vec::new();
    stub.extend_from_slice(&24u32.to_be_bytes());
    stub.extend_from_slice(b"ftypheic");
    stub.extend_from_slice(&0u32.to_be_bytes());
    stub.extend_from_slice(b"mif1heic");
    stub.extend_from_slice(&8u32.to_be_bytes());
    stub.extend_from_slice(b"free");

    let payload = b"test payload";
    let opts = StegoOptions::default();
    let res = embed_carrier(&stub, payload, &opts);
    assert!(
        matches!(res, Err(StrHideError::UnsupportedFormat(_))),
        "HEIF with no bridgeable thumbnail must return UnsupportedFormat, got {:?}",
        res
    );

    let ext_res = extract_carrier(&stub, &opts);
    assert!(
        matches!(ext_res, Err(StrHideError::NoHiddenData(_))),
        "Extracting from HEIF with no bridgeable thumbnail must return NoHiddenData, got {:?}",
        ext_res
    );
}

#[test]
#[ignore = "requires local temp/testhevc corpus: run with cargo test --test test_heif_stego_bridge -- --ignored"]
fn test_heif_jpeg_thumbnail_bridge_multiple_samples() {
    let corpus = match resolve_hevc_corpus() {
        Some(d) => d,
        None => {
            eprintln!("[SKIP] HEVC corpus not found");
            return;
        }
    };

    let sample_names = &[
        "IMG_20261018_113710.HEIC",
        "IMG_20261018_113725.HEIC",
        "IMG_20261007_174602.HEIC",
        "IMG_20261016_115109.HEIC",
        "IMG_20260101_151231.HEIC",
    ];

    let mut tested_count = 0;

    for &name in sample_names {
        let sample_path = corpus.join(name);
        if !sample_path.exists() {
            continue;
        }

        let orig_bytes = fs::read(&sample_path).expect("read sample");
        let payload = format!("Batch test payload for {}", name).into_bytes();

        let embed_opts = StegoOptions {
            password: Some("batch_test_pass".into()),
            ..Default::default()
        };

        let stego_bytes = embed_carrier(&orig_bytes, &payload, &embed_opts)
            .unwrap_or_else(|e| panic!("Failed to embed in {}: {}", name, e));

        let extract_opts = StegoOptions {
            password: Some("batch_test_pass".into()),
            ..Default::default()
        };
        let extracted = extract_carrier(&stego_bytes, &extract_opts)
            .unwrap_or_else(|e| panic!("Failed to extract from {}: {}", name, e));

        assert_eq!(extracted, payload, "Payload mismatch for {}", name);
        tested_count += 1;
    }

    println!(
        "Successfully tested {} real camera HEIC samples",
        tested_count
    );
    assert!(
        tested_count >= 2,
        "Should test at least 2 real camera samples"
    );
}

#[test]
#[ignore = "requires local temp/testhevc corpus and python pylibheif: run with cargo test --test test_heif_stego_bridge -- --ignored"]
fn test_heif_bridge_bit_exact_primary_decode() {
    let corpus = match resolve_hevc_corpus() {
        Some(d) => d,
        None => {
            eprintln!("[SKIP] HEVC corpus not found");
            return;
        }
    };
    let sample_path = corpus.join("IMG_20261018_113710.HEIC");
    if !sample_path.exists() {
        return;
    }
    let orig_bytes = fs::read(&sample_path).expect("read original HEIC");

    let payload = b"Bit-exact visual fidelity test";
    let opts = StegoOptions {
        password: Some("fidelity_pw".into()),
        ..Default::default()
    };
    let stego_bytes = embed_carrier(&orig_bytes, payload, &opts).expect("embed");

    let py_bin = match find_python_command() {
        Some(bin) => bin,
        None => {
            println!("[SKIP] Python not found; skipping pylibheif decode verification");
            return;
        }
    };

    let temp_dir = std::env::temp_dir().join(format!("strhide_heif_verify_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let orig_file = temp_dir.join("orig_verify.heic");
    let stego_file = temp_dir.join("stego_verify.heic");

    fs::write(&orig_file, &orig_bytes).expect("write orig");
    fs::write(&stego_file, &stego_bytes).expect("write stego");

    let orig_str = orig_file.to_string_lossy().replace('\\', "/");
    let stego_str = stego_file.to_string_lossy().replace('\\', "/");

    let py_cmd = format!(
        r#"
try:
    import pylibheif, numpy as np, sys
except ImportError:
    print("[SKIP] pylibheif or numpy not installed", file=sys.stderr)
    sys.exit(3)

def get_pixels(path):
    ctx = pylibheif.HeifContext()
    ctx.read_from_file(path)
    h = ctx.get_primary_image_handle()
    return h.decode_to_srgb()

try:
    orig = get_pixels("{orig_str}")
    stego = get_pixels("{stego_str}")
    diff = np.max(np.abs(orig.astype(np.int32) - stego.astype(np.int32)))
    if diff != 0:
        print(f"PIXEL MISMATCH: {{diff}}", file=sys.stderr)
        sys.exit(1)
    print("PIXELS BIT-EXACT")
except Exception as e:
    print(f"Python decode error: {{e}}", file=sys.stderr)
    sys.exit(2)
"#
    );

    let output = std::process::Command::new(&py_bin)
        .arg("-c")
        .arg(&py_cmd)
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            println!("pylibheif verified primary image pixels bit-exact!");
        } else if out.status.code() == Some(3) {
            println!("pylibheif not installed in Python environment, skipping check");
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            panic!("pylibheif verification failed: {}", stderr);
        }
    } else {
        println!("Failed to spawn Python process; skipping pylibheif external check");
    }

    let _ = fs::remove_file(orig_file);
    let _ = fs::remove_file(stego_file);
    let _ = fs::remove_dir(temp_dir);
}
