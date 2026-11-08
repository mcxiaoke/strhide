use std::fs;
use std::path::Path;

use rusty_h265::Decoder;
use strhide::core::control::Control;
use strhide::core::crypto::Credential;
use strhide::core::payload::Payload;
use strhide::stego::Freshness;
use strhide::stego::header::Tlv;
use strhide::stego::hevc::heif_boxes::parse_heif_targets;
use strhide::stego::hevc::{
    embed_hevc, embed_hevc_with_info, embed_hevc_with_info_v4, extract_hevc, extract_hevc_v4,
    probe_hevc_capacity, probe_hevc_capacity_ext, probe_hevc_capacity_info,
};
use strhide::stego::params::{ExtractParams, SafetyPolicy};
use strhide::{StrHideError, stego::format::DEFAULT_HEVC_FORMAT};

/// In-repo fixture, independent of the developer's `../temp` corpus.
fn asset(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/assets")
        .join(name)
}

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
fn test_hevc_capacity_and_roundtrip_small_heic() {
    let file_path = asset("small.heic");
    let orig_carrier = fs::read(&file_path).expect("read small.heic");
    let orig_len = orig_carrier.len();

    // 1. Probe capacity
    let cap = probe_hevc_capacity(&orig_carrier, &strhide::stego::format::DEFAULT_HEVC_FORMAT)
        .expect("probe capacity");
    println!("small.heic capacity: {} bytes", cap);
    assert!(
        cap >= 100,
        "Capacity should be at least 100 bytes for small.heic"
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
            &Control::none(),
        )
        .expect("extract with correct password should succeed");
        assert_eq!(extracted, payload, "Extracted payload must match 100%!");

        // C. Extract with wrong password must fail
        let wrong_res = extract_hevc(
            &stego_carrier,
            Some("WrongPassword!"),
            None,
            &strhide::stego::format::DEFAULT_HEVC_FORMAT,
            &Control::none(),
        );
        let err = wrong_res.expect_err("Extraction with wrong password must fail");
        assert!(
            matches!(err, StrHideError::NoHiddenData(_)),
            "wrong password must be indistinguishable from no payload, got: {err:?}"
        );

        // D. Verify stego carrier decodes cleanly to video frame without crashing
        verify_frame_decodes(&stego_carrier);
    }
    println!("small.heic ALL PAYLOAD SIZES PASSED!");
}

/// A raw Annex-B stream rebuilt from the HEIC fixture's NAL units must survive
/// a full embed/extract round trip.
///
/// The Annex-B cover digest used to hash an 18-byte window over every VCL NAL
/// on the assumption that the first 16 bytes after the NAL header are slice
/// header. On short slice headers (single-slice I frames: typically 3-6
/// bytes) most of that window is the first CTU's CABAC payload, which
/// embedding rewrites, which would cause digest drift and extraction failure.
/// The payload here verifies that STC modifications in the first CTU of the
/// first slice do not affect cover digest stability.
#[test]
fn test_hevc_annexb_roundtrip_from_heic_nals() {
    let file_path = asset("small.heic");
    let heic = fs::read(&file_path).expect("read small.heic");

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
    assert!(cap >= 64, "small.heic should offer real capacity");
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
        &Control::none(),
    )
    .expect("extract with the correct password must succeed");
    assert_eq!(extracted, payload, "Annex-B round trip must be exact");

    let wrong = extract_hevc(
        &stego,
        Some("WrongPassword!"),
        None,
        &strhide::stego::format::DEFAULT_HEVC_FORMAT,
        &Control::none(),
    );
    let err = wrong.expect_err("wrong password must be rejected");
    assert!(
        matches!(err, StrHideError::NoHiddenData(_)),
        "wrong password must be indistinguishable from no payload, got: {err:?}"
    );
}

/// Verifies Annex-B cover-digest stability on short slice segment headers
/// where the first CTU's CABAC payload begins early.
#[ignore = "requires the external oxideav-h265 fixture henc-133.hevc"]
#[test]
fn test_hevc_annexb_short_slice_header_roundtrip() {
    let file_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../temp/github/oxideav-h265/tests/fixture_bytes/r460/henc-133.hevc");
    assert!(
        file_path.exists(),
        "external corpus missing: {}",
        file_path.display()
    );
    let annexb = fs::read(&file_path).expect("read carrier");
    assert!(strhide::stego::hevc::sniff::is_hevc_annexb(&annexb));

    // V4 body = frame (5 bytes) + payload + 16-byte tag inside the same
    // capacity budget as the old v2 header; keep the payload under that.
    let payload: Vec<u8> = (0..180usize).map(|i| (i * 37 % 251) as u8).collect();
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
        &Control::none(),
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
    let fixtures = [asset("small.heic"), asset("minimal.heic")];
    for file_path in fixtures {
        let carrier = fs::read(&file_path).expect("read fixture");
        let cap = probe_hevc_capacity(&carrier, &strhide::stego::format::DEFAULT_HEVC_FORMAT)
            .expect("probe capacity");
        assert!(cap >= 1, "{}: expected real capacity", file_path.display());

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
            panic!(
                "{}: embedding the advertised {cap} bytes failed: {e}",
                file_path.display()
            )
        });
        let back = extract_hevc(
            &stego,
            Some("capacity-check"),
            None,
            &strhide::stego::format::DEFAULT_HEVC_FORMAT,
            &Control::none(),
        )
        .unwrap_or_else(|e| {
            panic!(
                "{}: extracting the full-capacity carrier failed: {e}",
                file_path.display()
            )
        });
        assert_eq!(back, payload);
    }
}

#[test]
fn test_hevc_capacity_incompressible_boundary_rejection() {
    let file_path = asset("minimal.heic");
    let carrier = fs::read(&file_path).expect("read fixture");
    let cap = probe_hevc_capacity(&carrier, &strhide::stego::format::DEFAULT_HEVC_FORMAT)
        .expect("probe capacity");
    assert_eq!(cap, 260);

    // Incompressible payload using SHA-256 blocks so Deflate cannot shrink it.
    let make_incompressible = |len: usize| -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut out = Vec::with_capacity(len);
        let mut counter = 0u64;
        while out.len() < len {
            let mut hasher = Sha256::new();
            hasher.update(b"incompressible-boundary-seed");
            hasher.update(counter.to_le_bytes());
            let hash = hasher.finalize();
            let take = (len - out.len()).min(hash.len());
            out.extend_from_slice(&hash[..take]);
            counter += 1;
        }
        out
    };

    // Exactly advertised raw cap: fits and roundtrips
    let payload = make_incompressible(cap);
    let stego = embed_hevc(
        &carrier,
        &payload,
        Some("hevc-boundary-check"),
        None,
        &strhide::stego::format::DEFAULT_HEVC_FORMAT,
        strhide::stego::Freshness::Random,
    )
    .expect("advertised cap of incompressible payload must fit");
    let back = extract_hevc(
        &stego,
        Some("hevc-boundary-check"),
        None,
        &strhide::stego::format::DEFAULT_HEVC_FORMAT,
        &Control::none(),
    )
    .expect("extract must succeed");
    assert_eq!(back, payload);

    // Advertised cap + 1: must be rejected with capacity exceeded (PayloadTooLarge)
    let too_large = make_incompressible(cap + 1);
    let err = embed_hevc(
        &carrier,
        &too_large,
        Some("hevc-boundary-check"),
        None,
        &strhide::stego::format::DEFAULT_HEVC_FORMAT,
        strhide::stego::Freshness::Random,
    )
    .unwrap_err();
    assert!(
        matches!(err, StrHideError::PayloadTooLarge(_)),
        "expected PayloadTooLarge on cap + 1 incompressible, got: {err:?}"
    );
}

#[test]
fn test_hevc_capacity_safety_scaling_and_sps_dimensions() {
    let file_path = asset("small.heic");
    let orig_carrier = fs::read(&file_path).expect("read small.heic");

    // 1. Dimensions parsed from SPS
    let (w, h) = strhide::stego::hevc::extract_hevc_dimensions(&orig_carrier)
        .expect("extract hevc dimensions from SPS");
    assert_eq!(
        (w, h),
        (320, 240),
        "Expected 320x240 from small.heic fixture"
    );

    // 2. Capacity probe info with different safety levels
    let levels = [
        strhide::stego::SafetyLevel::Paranoid,
        strhide::stego::SafetyLevel::High,
        strhide::stego::SafetyLevel::Balanced,
    ];

    let mut prev_rec = 0;
    for &lvl in &levels {
        let options = strhide::stego::ProbeOptions::default()
            .with_tuning(strhide::stego::StegoTuning::hevc(
                strhide::stego::HevcMode::Cabac,
            ))
            .with_safety(lvl, strhide::stego::SafetyEnforcement::Advisory);
        let profile = strhide::stego::params::StegoProfile::default();
        let info =
            strhide::stego::probe_carrier_capacity_with_dialect(&orig_carrier, &options, &profile)
                .expect("probe capacity info");

        assert_eq!(info.total_elements, 320 * 240);
        assert!(
            info.available_slots > 2048,
            "a 320x240 HEIC must expose more than the reader's 2048-slot header pool, got {}",
            info.available_slots
        );
        assert!(
            info.max_raw_payload_bytes >= 120,
            "small.heic must hold the 120-byte payload exercised above, got {}",
            info.max_raw_payload_bytes
        );
        assert!(info.recommended_max_bytes <= info.max_raw_payload_bytes);
        assert!(info.recommended_max_bytes >= prev_rec);
        prev_rec = info.recommended_max_bytes;
    }
}

#[test]
fn test_hevc_inspect_and_verify() {
    let file_path = asset("small.heic");
    let orig_carrier = fs::read(&file_path).expect("read small.heic");

    // 1. Clean carrier
    let inspect_clean =
        strhide::stego::inspect_carrier(&orig_carrier, &strhide::stego::InspectOptions::new())
            .expect("inspect clean heic");
    assert!(!inspect_clean.has_hidden_data);
    assert_eq!(
        inspect_clean.media_info.map(|m| m.to_string()).as_deref(),
        Some("320x240")
    );

    let verify_clean =
        strhide::stego::verify_carrier(&orig_carrier, &strhide::stego::VerifyOptions::new())
            .expect("verify clean heic");
    assert!(verify_clean.levels[0].ok);
    assert!(!verify_clean.levels[1].ok);
    assert!(!verify_clean.is_all_ok());

    // 2. Embedded carrier
    let payload = strhide::core::payload::Payload::file(
        "hevc_note.txt",
        b"Hidden payload inside HEVC gradient",
    );
    let embed_opts = strhide::stego::EmbedOptions::default().with_password("hevc-secret");
    let stego = strhide::stego::embed_carrier(&orig_carrier, &payload, &embed_opts)
        .expect("embed carrier heic");

    // Inspect with password
    let inspect_opts = strhide::stego::InspectOptions::new().with_password("hevc-secret");
    let inspect_stego =
        strhide::stego::inspect_carrier(&stego, &inspect_opts).expect("inspect stego heic");
    assert!(inspect_stego.has_hidden_data);
    assert!(inspect_stego.algorithm.is_some());
    assert_eq!(
        inspect_stego.media_info.map(|m| m.to_string()).as_deref(),
        Some("320x240")
    );

    // Verify with password
    let verify_opts = strhide::stego::VerifyOptions::new().with_password("hevc-secret");
    let verify_stego =
        strhide::stego::verify_carrier(&stego, &verify_opts).expect("verify stego heic");
    assert!(verify_stego.is_all_ok());

    // Verify with wrong password
    let verify_wrong_opts = strhide::stego::VerifyOptions::new().with_password("bad-pass");
    let verify_wrong =
        strhide::stego::verify_carrier(&stego, &verify_wrong_opts).expect("verify wrong password");
    assert!(!verify_wrong.is_all_ok());
}

/// V4: the capacity probe with an extension area must be exactly the budget the
/// writer can fill; and a wrong credential must fold to `NoHiddenData`.
#[test]
fn test_hevc_v4_extension_probe_matches_embed() {
    let file_path = asset("small.heic");
    let carrier = fs::read(&file_path).expect("read small.heic");
    let fmt = &DEFAULT_HEVC_FORMAT;
    let extensions = vec![Tlv {
        type_id: 0x07,
        value: vec![0xAA, 0xBB],
    }];

    let cap = probe_hevc_capacity_ext(&carrier, &extensions, fmt).expect("probe with ext");
    assert!(
        cap > 120,
        "probed capacity must cover the payload used below, got {cap}"
    );

    let payload = vec![0x5A; cap];
    let suite = fmt.cipher.default_suite.as_u16();
    let (stego, info, _stats) = embed_hevc_with_info_v4(
        &carrier,
        &Payload::bytes(&payload),
        Credential::Password("v4-ext-pw"),
        None,
        suite,
        &extensions,
        fmt,
        Freshness::Random,
        SafetyPolicy::new(),
        &Control::none(),
    )
    .expect("embed at the probed capacity");
    assert_eq!(stego.len(), carrier.len(), "Δ = 0");
    assert_eq!(info.max_raw_payload_bytes, cap);

    let extracted = extract_hevc_v4(
        &stego,
        Credential::Password("v4-ext-pw"),
        None,
        fmt,
        &ExtractParams::default(),
        &Control::none(),
    )
    .expect("extract v4 with extensions");
    assert_eq!(extracted.as_bytes(), payload.as_slice());

    // Wrong password: never a `Password` oracle, always `NoHiddenData`.
    let wrong = extract_hevc_v4(
        &stego,
        Credential::Password("wrong-pw"),
        None,
        fmt,
        &ExtractParams::default(),
        &Control::none(),
    );
    assert!(matches!(wrong, Err(StrHideError::NoHiddenData(_))));
}

/// V4 negative: a carrier whose trailing scan data was cut must never yield a
/// payload. The header may still be readable, so this exercises the body
/// budget/frame failure path rather than the container parser.
#[test]
fn test_hevc_v4_truncated_body_is_rejected() {
    let file_path = asset("small.heic");
    let carrier = fs::read(&file_path).expect("read small.heic");
    let fmt = &DEFAULT_HEVC_FORMAT;
    let payload = vec![0x5A; 64];
    let (stego, _, _) = embed_hevc_with_info_v4(
        &carrier,
        &Payload::bytes(&payload),
        Credential::Password("v4-trunc-pw"),
        None,
        fmt.cipher.default_suite.as_u16(),
        &[],
        fmt,
        Freshness::Random,
        SafetyPolicy::new(),
        &Control::none(),
    )
    .expect("embed");
    let truncated = &stego[..stego.len() - stego.len() / 8];
    let res = extract_hevc_v4(
        truncated,
        Credential::Password("v4-trunc-pw"),
        None,
        fmt,
        &ExtractParams::default(),
        &Control::none(),
    );
    let err = res.expect_err("truncated carrier must not extract");
    assert!(
        matches!(&err, StrHideError::UnsupportedFormat(msg) if msg.contains("truncated")),
        "a truncated carrier must be rejected as unsupported, got: {err:?}"
    );
}

/// Verifies the writer's decode window does not stop below the reader's fixed
/// `HEVC_SUPERBLOCK_POOL_SLOTS` (2048) header pool on small payloads.
///
/// The assertion on `available_slots > 2048` keeps the case honest: a fixture
/// that fits inside the reader pool cannot exercise the mismatch at all.
#[test]
fn test_hevc_balanced_small_payload_roundtrip() {
    // Build a multi-picture Annex-B stream by repeating a 40x40 HEVC picture
    // (~650 sign slots). A single picture is smaller than the reader's 2048-slot
    // pool, so the old write window stopped after one picture and derived the
    // header permutation from ~650 slots, while extraction derived it from 2048.
    // A single still image cannot stop the window early at all, so the mismatch
    // needs a multi-picture carrier.
    let frame_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/assets/tiny40.hevc");
    let frame = fs::read(&frame_path).expect("read tiny40.hevc");
    let mut carrier = Vec::new();
    for _ in 0..64 {
        carrier.extend_from_slice(&frame);
    }
    let fmt = &DEFAULT_HEVC_FORMAT;
    let policy = (SafetyPolicy::new()).with_level(strhide::stego::SafetyLevel::Balanced);
    let payload = b"balanced-small";
    let (stego, info, _stats) = embed_hevc_with_info(
        &carrier,
        &Payload::bytes(payload),
        Some("balanced-pw"),
        None,
        fmt,
        Freshness::Random,
        policy,
        &Control::none(),
    )
    .expect("balanced small payload must embed");
    assert!(
        info.available_slots > 2048,
        "fixture must exceed the reader pool to exercise the window/pool mismatch, got {} slots",
        info.available_slots
    );
    assert_eq!(stego.len(), carrier.len(), "Δ = 0 must hold");
    let extracted = extract_hevc(&stego, Some("balanced-pw"), None, fmt, &Control::none())
        .expect("balanced small payload must be extractable");
    assert_eq!(extracted.as_bytes(), payload);
}

/// N-01: the embed capacity report must agree with the unified `probe` entry.
///
/// File level: the MP4/Annex-B patch branch must apply the same filename-safe
/// capacity adjustment as `probe`, otherwise `sth embed x.mp4` and
/// `sth capacity x.mp4` disagree by 256 bytes.
///
/// The same check guards the whole-carrier pool: the writer window stops
/// recording once the payload fits, so reporting that window made a 59-byte
/// payload on a 12 MB MKV claim 117,000 slots / 1.40 KiB safe against a real
/// 13,141,628 slots / 70.04 KiB (112x under-report). A single still image
/// cannot stop the window early at all, so the file-level case uses a
/// multi-picture Annex-B carrier where the early stop is reachable; the HEIC
/// case below keeps the image-container path covered.
#[test]
fn embed_capacity_report_matches_probe_for_annex_b_and_heic() {
    use strhide::commit::FileTarget;
    use strhide::core::payload::Payload;
    use strhide::stego::io::embed_carrier_file;
    use strhide::stego::params::StegoProfile;
    use strhide::stego::{EmbedOptions, ProbeOptions, probe_carrier_capacity_with_dialect};

    let dir = crate::common::scratch("patch_capacity");
    let carrier = dir.join("carrier.hevc");
    // One 40x40 frame is below the reader's 2048-slot header pool; repeat it
    // so the Annex-B carrier can actually carry the V4 envelope.
    let frame = fs::read(asset("tiny40.hevc")).expect("read tiny40.hevc");
    let mut orig = Vec::new();
    for _ in 0..64 {
        orig.extend_from_slice(&frame);
    }
    fs::write(&carrier, &orig).unwrap();

    let dialect = StegoProfile::default();
    let probe = probe_carrier_capacity_with_dialect(&orig, &ProbeOptions::default(), &dialect)
        .expect("probe");

    let target = FileTarget::new()
        .with_backup(false)
        .with_preserve_time(false)
        .with_overwrite(true);
    let res = embed_carrier_file(
        &carrier,
        &Payload::bytes(b"n-01"),
        &EmbedOptions::default(),
        &dialect,
        &target,
    )
    .expect("embed");
    let reported = res.capacity.expect("capacity report");
    assert_eq!(reported.total_elements, probe.total_elements);
    assert_eq!(reported.available_slots, probe.available_slots);
    assert_eq!(reported.max_raw_payload_bytes, probe.max_raw_payload_bytes);
    assert_eq!(reported.tier_limits, probe.tier_limits);
    assert_eq!(reported.recommended_max_bytes, probe.recommended_max_bytes);

    // HEIC image container: the report must match the probe here too.
    let heic = fs::read(asset("small.heic")).expect("read small.heic");
    let fmt = &DEFAULT_HEVC_FORMAT;
    let policy = SafetyPolicy::new();
    let probed_heic =
        probe_hevc_capacity_info(&heic, &[], fmt, policy.level, false, &Control::none())
            .expect("probe heic");
    let (_, embedded_heic, _stats) = embed_hevc_with_info_v4(
        &heic,
        &Payload::bytes(b"abc"),
        Credential::Password("l02-pw"),
        None,
        fmt.cipher.default_suite.as_u16(),
        &[],
        fmt,
        Freshness::Random,
        policy,
        &Control::none(),
    )
    .expect("embed heic");
    assert_eq!(embedded_heic.total_elements, probed_heic.total_elements);
    assert_eq!(embedded_heic.available_slots, probed_heic.available_slots);
    assert_eq!(
        embedded_heic.max_raw_payload_bytes,
        probed_heic.max_raw_payload_bytes
    );
    assert_eq!(embedded_heic.tier_limits, probed_heic.tier_limits);
    assert_eq!(
        embedded_heic.recommended_max_bytes,
        probed_heic.recommended_max_bytes
    );

    let _ = fs::remove_dir_all(&dir);
}
