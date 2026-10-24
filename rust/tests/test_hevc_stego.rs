use std::fs;
use std::path::Path;

use strhide::stego::hevc::h265::decoder::Decoder;
use strhide::stego::hevc::h265::nal::parse_nal;
use strhide::stego::hevc::heif_boxes::parse_heif_targets;
use strhide::stego::hevc::{embed_hevc, extract_hevc, probe_hevc_capacity};

/// Verify that an HEIC file can be decoded to a valid frame by rust_h265.
fn verify_frame_decodes(carrier_bytes: &[u8]) {
    let target = parse_heif_targets(carrier_bytes).expect("parse targets");
    let mut decoder = Decoder::new();
    for ps in &target.parameter_sets {
        if let Some(unit) = parse_nal(ps) {
            let _ = decoder.decode_nal(&unit);
        }
    }
    let mut decoded_any = false;
    for span in &target.slice_spans {
        let slice_bytes = &carrier_bytes[span.start..span.end()];
        if let Some(unit) = parse_nal(slice_bytes)
            && let Ok(Some(frame)) = decoder.decode_nal(&unit)
        {
            assert!(frame.width > 0 && frame.height > 0);
            decoded_any = true;
            break;
        }
    }
    assert!(
        decoded_any,
        "Failed to decode at least one full frame from carrier!"
    );
}

#[test]
fn test_hevc_capacity_and_roundtrip_gradient() {
    let file_path = "../temp/github/heic-rs/tests/fixtures/gradient-512.heic";
    if !Path::new(file_path).exists() {
        return;
    }
    let orig_carrier = fs::read(file_path).expect("read carrier");
    let orig_len = orig_carrier.len();

    // 1. Probe capacity
    let cap = probe_hevc_capacity(&orig_carrier).expect("probe capacity");
    println!("gradient-512.heic capacity: {} bytes", cap);
    assert!(
        cap >= 100,
        "Capacity should be at least 100 bytes for gradient-512"
    );

    // 2. Test multiple payload sizes
    let test_payloads: Vec<Vec<u8>> = vec![
        b"X".to_vec(),                 // 1 byte minimal
        b"Hello HEVC Stego!".to_vec(), // 17 bytes small
        b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Integer nec odio.".to_vec(), // 75 bytes
        vec![0xAA; 120], // 120 bytes near capacity
    ];

    let password = "MySecretHevcPassword2026!";

    for payload in test_payloads {
        println!("Testing payload len: {} bytes...", payload.len());

        // A. Embed with password
        let stego_carrier =
            embed_hevc(&orig_carrier, &payload, Some(password)).expect("embed should succeed");

        // Verify zero bitrate expansion (Δ = 0)
        assert_eq!(
            stego_carrier.len(),
            orig_len,
            "Carrier length must be strictly preserved (Δ = 0)!"
        );

        // B. Extract with correct password
        let extracted = extract_hevc(&stego_carrier, Some(password))
            .expect("extract with correct password should succeed");
        assert_eq!(extracted, payload, "Extracted payload must match 100%!");

        // C. Extract with wrong password must fail
        let wrong_res = extract_hevc(&stego_carrier, Some("WrongPassword!"));
        assert!(
            wrong_res.is_err(),
            "Extraction with wrong password must fail!"
        );

        // D. Verify stego carrier decodes cleanly to video frame without crashing
        verify_frame_decodes(&stego_carrier);
    }
    println!("gradient-512.heic ALL PAYLOAD SIZES PASSED!");
}

#[test]
#[ignore = "requires local testhevc corpus"]
fn test_hevc_corpus_real_photos_batch() {
    let corpus_files = [
        "../temp/testhevc/test.heic",
        "../temp/testhevc/IMG_5887.HEIC",
        "../temp/testhevc/IMG_1904.HEIC",
        "../temp/testhevc/IMG_0874.HEIC",
        "../temp/testhevc/IMG_2887.HEIC",
    ];

    let payload = b"StrHide HEVC Scheme C Certified Zero-Expansion In-Place Steganography";
    let password = "CorpusBatchTestPassword#2026";

    for path in corpus_files {
        if !Path::new(path).exists() {
            println!("Skipping missing: {}", path);
            continue;
        }
        let orig = fs::read(path).expect("read");
        let orig_len = orig.len();
        let cap = probe_hevc_capacity(&orig).expect("probe capacity");
        println!(
            "File: {}, size = {} bytes, capacity = {} bytes",
            path, orig_len, cap
        );

        if cap < payload.len() {
            println!(
                "  Carrier capacity {} < payload {}, skipping embed",
                cap,
                payload.len()
            );
            continue;
        }

        let stego = embed_hevc(&orig, payload, Some(password)).expect("embed");
        assert_eq!(stego.len(), orig_len, "Length must be bit-exact identical!");

        let extracted = extract_hevc(&stego, Some(password)).expect("extract");
        assert_eq!(extracted, payload);

        verify_frame_decodes(&stego);
        println!("  100% roundtrip & frame decode OK for {}", path);
    }
}

#[test]
#[ignore = "requires local testhevc corpus"]
fn test_hevc_img_1842_payload_32k() {
    let path = "../temp/testhevc/IMG_1842.HEIC";
    let payload_path = "../temp/testpayload/payload-32k.bin";
    if !Path::new(path).exists() || !Path::new(payload_path).exists() {
        return;
    }
    let orig = fs::read(path).expect("read");
    let payload = fs::read(payload_path).expect("read payload");
    let password = "StrHide-Matrix-Benchmark-Password#2026";

    let stego = embed_hevc(&orig, &payload, Some(password)).expect("embed 32k into IMG_1842");
    assert_eq!(stego.len(), orig.len(), "Carrier len must be bit-exact!");

    let extracted = extract_hevc(&stego, Some(password)).expect("extract 32k from IMG_1842");
    assert_eq!(extracted, payload, "Payload must match bit-for-bit!");

    verify_frame_decodes(&stego);
    println!("IMG_1842 with 32KB payload PASSED 100%!");
}
