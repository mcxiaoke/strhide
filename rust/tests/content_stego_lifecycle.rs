//! Integration tests for content-adaptive steganography (HILL, UERD, LSB/DCT Matching).

use std::fs;
use std::path::PathBuf;

use strhide::analysis::scan_file;
use strhide::stego::{
    StegoOptions, embed_carrier, extract_carrier,
    spatial::{RawImage, encode_png},
};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "strhide_stego_test_{}_{}",
        std::process::id(),
        name
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Generate a synthetic texture PNG image with gradients and noise (128x128).
fn generate_texture_png(w: u32, h: u32) -> Vec<u8> {
    let mut pixels = Vec::with_capacity((w * h * 3) as usize);
    for y in 0..h {
        for x in 0..w {
            // Complex high-frequency texture pattern
            let r = ((x * 17) ^ (y * 31) ^ ((x + y) * 7)) as u8;
            let g = ((x * 23 + y * 19) % 256) as u8;
            let b = ((x * 13) ^ (y * 29)) as u8;
            pixels.push(r);
            pixels.push(g);
            pixels.push(b);
        }
    }
    let img = RawImage {
        width: w,
        height: h,
        channels: 3,
        pixels,
    };
    encode_png(&img).expect("encode png")
}

#[test]
fn test_png_hill_content_stego_roundtrip() {
    let png_bytes = generate_texture_png(128, 128);
    let secret = b"Hello from HILL content-adaptive steganography! 2026";
    let password = "SecretPassword123!";

    let mut opts = StegoOptions {
        algorithm: Some("hill".into()),
        password: Some(password.into()),
        ..Default::default()
    };

    // 1. Embed
    let stego_png = embed_carrier(&png_bytes, secret, &opts).expect("embed png");
    assert_ne!(png_bytes, stego_png, "stego png should modify pixel values");

    // 2. Extract with correct password
    let extracted = extract_carrier(&stego_png, &opts).expect("extract png");
    assert_eq!(extracted, secret, "extracted payload must match original");

    // 3. Extract with wrong password must fail
    opts.password = Some("WrongPassword999!".into());
    assert!(
        extract_carrier(&stego_png, &opts).is_err(),
        "wrong password must fail"
    );
}

#[test]
fn test_png_hill_fine_tuning_parameters() {
    let png_bytes = generate_texture_png(128, 128);
    let secret = b"Fine-tuned parameters test";

    let mut opts = StegoOptions {
        algorithm: Some("hill".into()),
        password: Some("pwd".into()),
        ..Default::default()
    };
    // Customize parameters: exclude top 40% smoothest pixels, customize filters
    opts.spatial_params.exclusion_percentile = 0.40;
    opts.spatial_params.p1_window = 3;
    opts.spatial_params.p2_window = 15;

    let stego_png = embed_carrier(&png_bytes, secret, &opts).expect("embed tuned");
    let extracted = extract_carrier(&stego_png, &opts).expect("extract tuned");
    assert_eq!(extracted, secret);
}

#[test]
fn test_png_hill_scan_analysis_pass() {
    let png_bytes = generate_texture_png(160, 160);
    let secret = b"Steganalysis resistance test under scan_file";

    let opts = StegoOptions {
        algorithm: Some("hill".into()),
        password: Some("Pass!".into()),
        ..Default::default()
    };

    let stego_png = embed_carrier(&png_bytes, secret, &opts).expect("embed");

    let dir = scratch("png_scan");
    let file_path = dir.join("stego.png");
    fs::write(&file_path, &stego_png).unwrap();

    // Run strhide scan on the generated stego PNG
    let report = scan_file(&file_path).expect("scan_file");
    println!(
        "Scan report verdict: {}, risk: {}",
        report.verdict, report.risk_score
    );
    for finding in &report.findings {
        println!("  Finding: [{}] {}", finding.detector, finding.detail);
    }

    // HILL + LSB Matching preserves histogram smoothness and does not trigger chi2 or SPA
    assert!(
        report.verdict == "clean" || report.verdict == "low",
        "Stego PNG should not trigger suspicious or likely-hidden verdicts! Got: {}",
        report.verdict
    );
}

#[test]
fn test_jpeg_uerd_content_stego_roundtrip() {
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("temp")
        .join("testfiles")
        .join("file-08.jpg");

    if !candidate.exists() {
        eprintln!("[SKIP] temp/testfiles/file-06.jpg not found");
        return;
    }

    let jpeg_bytes = fs::read(&candidate).expect("read sample jpeg");
    let secret = b"JPEG UERD content-adaptive secret message 2026!";
    let password = "JpegPassword2026#";

    let mut opts = StegoOptions {
        algorithm: Some("uerd".into()),
        password: Some(password.into()),
        ..Default::default()
    };

    // 1. Embed into JPEG DCT coefficients
    let stego_jpeg = embed_carrier(&jpeg_bytes, secret, &opts).expect("embed jpeg");
    assert_ne!(
        jpeg_bytes, stego_jpeg,
        "stego jpeg should differ from original"
    );

    // 2. Extract with correct password
    let extracted = extract_carrier(&stego_jpeg, &opts).expect("extract jpeg");
    assert_eq!(extracted, secret, "extracted payload must match original");

    // 3. Extract with wrong password must fail
    opts.password = Some("WrongPassword!".into());
    assert!(
        extract_carrier(&stego_jpeg, &opts).is_err(),
        "wrong password must fail"
    );
}

#[test]
fn test_jpeg_uerd_fine_tuning() {
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("temp")
        .join("testfiles")
        .join("file-08.jpg");

    if !candidate.exists() {
        return;
    }

    let jpeg_bytes = fs::read(&candidate).unwrap();
    let secret = b"Customized UERD neighbor weight test";

    let mut opts = StegoOptions {
        algorithm: Some("uerd".into()),
        password: Some("p1".into()),
        ..Default::default()
    };
    opts.jpeg_params.neighbor_weight = 0.35;
    opts.jpeg_params.block_exclusion_percentile = 0.25;

    let stego_jpeg = embed_carrier(&jpeg_bytes, secret, &opts).unwrap();
    let extracted = extract_carrier(&stego_jpeg, &opts).unwrap();
    assert_eq!(extracted, secret);
}

#[test]
fn test_cli_embed_and_extract_roundtrip() {
    let dir = scratch("cli_roundtrip");
    let carrier_png = dir.join("carrier.png");
    let stego_png = dir.join("stego.png");
    let out_txt = dir.join("out.txt");

    // Write a synthetic carrier PNG
    let png_bytes = generate_texture_png(128, 128);
    fs::write(&carrier_png, &png_bytes).unwrap();

    let bin = env!("CARGO_BIN_EXE_strhide");

    // 1. Embed via CLI: strhide embed carrier.png -t "CLI Test Message" -p "TestPW123" -o stego.png
    let embed_status = std::process::Command::new(bin)
        .arg("embed")
        .arg(&carrier_png)
        .arg("-t")
        .arg("CLI Test Message")
        .arg("-p")
        .arg("TestPW123")
        .arg("-o")
        .arg(&stego_png)
        .status()
        .expect("run embed CLI");
    assert!(embed_status.success(), "embed command should succeed");
    assert!(stego_png.exists(), "stego file must be created");

    // 2. Extract via CLI: strhide extract stego.png -p "TestPW123" -o out.txt
    let extract_status = std::process::Command::new(bin)
        .arg("extract")
        .arg(&stego_png)
        .arg("-p")
        .arg("TestPW123")
        .arg("-o")
        .arg(&out_txt)
        .status()
        .expect("run extract CLI");
    assert!(extract_status.success(), "extract command should succeed");

    let read_back = fs::read_to_string(&out_txt).expect("read extracted output");
    assert_eq!(read_back, "CLI Test Message");

    // 3. Scan the stego file: strhide scan stego.png
    let scan_status = std::process::Command::new(bin)
        .arg("scan")
        .arg(&stego_png)
        .status()
        .expect("run scan CLI");
    // Scan exits 0 on clean/low verdicts
    assert!(
        scan_status.success(),
        "scan command should not fail on clean/low"
    );
}
