use std::fs;
use std::path::Path;

use rusty_h265::Decoder;
use strhide::stego::hevc::heif_boxes::parse_heif_targets;
use strhide::stego::hevc::{embed_hevc, extract_hevc, probe_hevc_capacity};

/// Verify that an HEIC file can be decoded to a valid frame by rusty_h265.
fn verify_frame_decodes(carrier_bytes: &[u8]) {
    let target = parse_heif_targets(carrier_bytes).expect("parse targets");
    let mut decoder = Decoder::new();
    for ps in &target.parameter_sets {
        let _ = decoder.push_nal(ps, None);
    }
    for span in &target.slice_spans {
        let _ = decoder.push_nal(&carrier_bytes[span.start..span.end()], None);
    }
    // A picture is only handed out once the decoder sees the *next* one start,
    // so a still image needs `flush` before `next_frame` yields anything.
    decoder.flush();
    let frame = decoder.next_frame().expect("decoded frame");
    assert!(frame.width > 0 && frame.height > 0);
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
    let cap = probe_hevc_capacity(&orig_carrier, &strhide::stego::format::DEFAULT_HEVC_FORMAT)
        .expect("probe capacity");
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
        let stego_carrier = embed_hevc(
            &orig_carrier,
            &payload,
            Some(password),
            None,
            &strhide::stego::format::DEFAULT_HEVC_FORMAT,
            strhide::stego::Freshness::Random,
        )
        .expect("embed should succeed");

        // Verify zero bitrate expansion (Δ = 0)
        assert_eq!(
            stego_carrier.len(),
            orig_len,
            "Carrier length must be strictly preserved (Δ = 0)!"
        );

        // B. Extract with correct password
        let extracted = extract_hevc(
            &stego_carrier,
            Some(password),
            None,
            &strhide::stego::format::DEFAULT_HEVC_FORMAT,
        )
        .expect("extract with correct password should succeed");
        assert_eq!(extracted, payload, "Extracted payload must match 100%!");

        // C. Extract with wrong password must fail
        let wrong_res = extract_hevc(
            &stego_carrier,
            Some("WrongPassword!"),
            None,
            &strhide::stego::format::DEFAULT_HEVC_FORMAT,
        );
        assert!(
            wrong_res.is_err(),
            "Extraction with wrong password must fail!"
        );

        // D. Verify stego carrier decodes cleanly to video frame without crashing
        verify_frame_decodes(&stego_carrier);
    }
    println!("gradient-512.heic ALL PAYLOAD SIZES PASSED!");
}

/// A raw Annex-B stream rebuilt from the HEIC fixture's NAL units must survive
/// a full embed/extract round trip.
///
/// The Annex-B cover digest used to hash an 18-byte window over every VCL NAL
/// on the assumption that the first 16 bytes after the NAL header are slice
/// header. On short slice headers (single-slice I frames: typically 3-6
/// bytes) most of that window is the first CTU's CABAC payload, which
/// embedding *does* rewrite, so the digest drifted and extraction failed with
/// the correct password (review 2026-10-25, S2). The payload here is large
/// enough that the STC solution flips sign bits inside the first CTU of the
/// first slice -- exactly the region the old digest wrongly covered.
#[test]
fn test_hevc_annexb_roundtrip_from_heic_nals() {
    let file_path = "../temp/github/heic-rs/tests/fixtures/gradient-512.heic";
    if !Path::new(file_path).exists() {
        return;
    }
    let heic = fs::read(file_path).expect("read carrier");

    // Rebuild the HEVC bitstream as Annex-B: parameter sets first, then the
    // slice segments, each behind a 4-byte start code.
    let target = parse_heif_targets(&heic).expect("parse heif targets");
    let mut annexb: Vec<u8> = Vec::new();
    for ps in &target.parameter_sets {
        annexb.extend_from_slice(&[0, 0, 0, 1]);
        annexb.extend_from_slice(ps);
    }
    for span in &target.slice_spans {
        annexb.extend_from_slice(&[0, 0, 0, 1]);
        annexb.extend_from_slice(&heic[span.start..span.end()]);
    }
    assert!(
        strhide::stego::hevc::sniff::is_hevc_annexb(&annexb),
        "rebuilt stream must sniff as Annex-B HEVC"
    );

    let cap = probe_hevc_capacity(&annexb, &strhide::stego::format::DEFAULT_HEVC_FORMAT)
        .expect("probe annex-b capacity");
    assert!(cap >= 64, "gradient fixture should offer real capacity");
    let len = cap.min(120);
    let payload: Vec<u8> = (0..len).map(|i| (i * 37 % 251) as u8).collect();
    let password = "AnnexBRoundTrip#2026";

    let stego = embed_hevc(
        &annexb,
        &payload,
        Some(password),
        None,
        &strhide::stego::format::DEFAULT_HEVC_FORMAT,
        strhide::stego::Freshness::Random,
    )
    .expect("embed into Annex-B stream");
    assert_eq!(stego.len(), annexb.len(), "Delta = 0 must hold");

    let extracted = extract_hevc(
        &stego,
        Some(password),
        None,
        &strhide::stego::format::DEFAULT_HEVC_FORMAT,
    )
    .expect("extract with the correct password must succeed");
    assert_eq!(extracted, payload, "Annex-B round trip must be exact");

    let wrong = extract_hevc(
        &stego,
        Some("WrongPassword!"),
        None,
        &strhide::stego::format::DEFAULT_HEVC_FORMAT,
    );
    assert!(wrong.is_err(), "wrong password must be rejected");
}

/// Deterministic regression for the Annex-B cover-digest window bug
/// (review 2026-10-25, S2): `henc-133.hevc` has a 5-byte slice segment
/// header, so the old 18-byte hash window covered ~11 bytes of the first
/// CTU's CABAC payload. With this carrier, payload and seed the STC solution
/// flips a sign bit inside that window: on the old code extraction fails with
/// "Invalid HEVC stego signature" even though the password is correct.
#[test]
fn test_hevc_annexb_short_slice_header_roundtrip() {
    let file_path = "../temp/github/oxideav-h265/tests/fixture_bytes/r460/henc-133.hevc";
    if !Path::new(file_path).exists() {
        return;
    }
    let annexb = fs::read(file_path).expect("read carrier");
    assert!(strhide::stego::hevc::sniff::is_hevc_annexb(&annexb));

    let payload: Vec<u8> = (0..200usize).map(|i| (i * 37 % 251) as u8).collect();
    let password = "pw";
    let stego = embed_hevc(
        &annexb,
        &payload,
        Some(password),
        None,
        &strhide::stego::format::DEFAULT_HEVC_FORMAT,
        strhide::stego::Freshness::Seeded([2u8; 32]),
    )
    .expect("embed into short-header Annex-B stream");
    assert_eq!(stego.len(), annexb.len(), "Delta = 0 must hold");

    let extracted = extract_hevc(
        &stego,
        Some(password),
        None,
        &strhide::stego::format::DEFAULT_HEVC_FORMAT,
    )
    .expect("correct password must extract a short-slice-header carrier");
    assert_eq!(extracted, payload);
}

/// The capacity probe must not advertise more than the embedder accepts
/// (audit 2026-10-24 2.1: the old `total_slots / 2` rate ignored the trellis
/// warm-up rows and over-reported by h-1 bits, crossing the byte boundary on
/// most carriers -- 9 of 14 corpus files advertised one byte too many).
#[test]
fn test_hevc_capacity_is_reachable() {
    let fixtures = [
        "../temp/github/heic-rs/tests/fixtures/gradient-512.heic",
        "../temp/github/oxideav-h265/tests/fixture_bytes/r460/henc-133.hevc",
    ];
    for file_path in fixtures {
        if !Path::new(file_path).exists() {
            continue;
        }
        let carrier = fs::read(file_path).expect("read carrier");
        let cap = probe_hevc_capacity(&carrier, &strhide::stego::format::DEFAULT_HEVC_FORMAT)
            .expect("probe capacity");
        assert!(cap >= 1, "{file_path}: expected real capacity");

        // A payload of exactly the advertised capacity must embed.
        let payload: Vec<u8> = (0..cap).map(|i| (i * 37 % 251) as u8).collect();
        let stego = embed_hevc(
            &carrier,
            &payload,
            Some("capacity-check"),
            None,
            &strhide::stego::format::DEFAULT_HEVC_FORMAT,
            strhide::stego::Freshness::Random,
        )
        .unwrap_or_else(|e| {
            panic!("{file_path}: embedding the advertised {cap} bytes failed: {e}")
        });
        let back = extract_hevc(
            &stego,
            Some("capacity-check"),
            None,
            &strhide::stego::format::DEFAULT_HEVC_FORMAT,
        )
        .unwrap_or_else(|e| {
            panic!("{file_path}: extracting the full-capacity carrier failed: {e}")
        });
        assert_eq!(back, payload);
    }
}

#[test]
fn test_hevc_capacity_safety_scaling_and_sps_dimensions() {
    let file_path = "../temp/github/heic-rs/tests/fixtures/gradient-512.heic";
    if !Path::new(file_path).exists() {
        return;
    }
    let orig_carrier = fs::read(file_path).expect("read carrier");

    // 1. Dimensions parsed from SPS
    let (w, h) = strhide::stego::hevc::extract_hevc_dimensions(&orig_carrier)
        .expect("extract hevc dimensions from SPS");
    assert_eq!(
        (w, h),
        (512, 512),
        "Expected 512x512 from gradient-512 fixture"
    );

    // 2. Capacity probe info with different safety levels
    let levels = [
        strhide::stego::SafetyLevel::Paranoid,
        strhide::stego::SafetyLevel::High,
        strhide::stego::SafetyLevel::Balanced,
    ];

    let mut prev_rec = 0;
    for &lvl in &levels {
        let options = strhide::stego::StegoOptions::default()
            .with_algorithm("hevc")
            .with_safety(lvl, strhide::stego::SafetyEnforcement::Advisory);
        let profile = strhide::params::Profile::default();
        let info =
            strhide::stego::probe_carrier_capacity_with_profile(&orig_carrier, &options, &profile)
                .expect("probe capacity info");

        assert_eq!(info.total_elements, 512 * 512);
        assert!(info.available_slots > 0);
        assert!(info.max_raw_payload_bytes > 0);
        assert!(info.recommended_max_bytes <= info.max_raw_payload_bytes);
        assert!(info.recommended_max_bytes >= prev_rec);
        prev_rec = info.recommended_max_bytes;
    }
}
