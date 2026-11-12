use super::*;
use crate::formats::capability::CAPABILITIES;
#[test]
#[cfg(feature = "content")]
fn every_content_capable_format_has_an_engine() {
    for cap in CAPABILITIES {
        if cap.stego.is_empty() {
            continue;
        }
        assert!(
            engine_for(cap.format).is_some(),
            "{} is advertised as a content carrier with no engine",
            cap.format.as_str()
        );
    }
}

#[test]
fn no_engine_claims_a_format_the_capability_table_rejects() {
    for engine in ENGINES {
        let format = engine.format();
        let cap = CAPABILITIES
            .iter()
            .find(|c| c.format == format)
            .unwrap_or_else(|| panic!("{} has no capability row", format.as_str()));
        assert!(
            !cap.stego.is_empty(),
            "{} has an engine but the capability table says no",
            format.as_str()
        );
    }
}

#[test]
fn the_registry_has_no_duplicate_formats() {
    let mut seen = std::collections::HashSet::new();
    for format in supported_formats() {
        assert!(seen.insert(format), "{:?} is registered twice", format);
    }
    assert_eq!(seen.len(), ENGINES.len());
}

/// The error message must name what this build accepts, and nothing else:
/// an omission sends users looking for a converter they do not need, an
/// over-claim sends them to a write that cannot work.
#[test]
fn the_carrier_list_names_every_compiled_engine() {
    let list = supported_carrier_list();
    #[cfg(feature = "content-png")]
    assert!(list.contains("PNG"), "{list}");
    #[cfg(feature = "content-jpeg")]
    assert!(list.contains("JPEG"), "{list}");
    #[cfg(feature = "content-audio")]
    {
        assert!(list.contains("WAV"), "{list}");
        assert!(list.contains("FLAC"), "{list}");
    }
    #[cfg(feature = "content-hevc")]
    {
        assert!(list.contains("HEIF/HEIC"), "{list}");
        assert!(list.contains("MP4/MOV"), "{list}");
        assert!(list.contains("MKV/WebM"), "{list}");
    }
    for absent in ["ZIP", "PDF", "WEBP", "Executable"] {
        assert!(!list.contains(absent), "{absent} is not a content carrier");
    }
}

#[test]
fn container_formats_without_a_content_engine_have_none() {
    // Formats with no content engine. Both WAV (PCM engine) and MKV (HEVC
    // container) have left this list; a format only belongs here when the
    // sniffer recognises it but the content domain refuses it.
    for format in [
        FileFormat::Zip,
        FileFormat::Pdf,
        FileFormat::Pe,
        FileFormat::Webp,
    ] {
        assert!(
            engine_for(format).is_none(),
            "{} must not have a content engine",
            format.as_str()
        );
    }
}

#[test]
#[cfg(feature = "content-png")]
fn test_png_inspect_and_verify() {
    let carrier_bytes = include_bytes!("../../../tests/assets/small.png");
    let profile = StegoProfile::default();

    // 1. Clean carrier
    let inspect_clean = PngEngine
        .inspect(carrier_bytes, &InspectOptions::new(), &profile)
        .expect("inspect clean png");
    assert_eq!(inspect_clean.format, "PNG");
    assert!(!inspect_clean.has_hidden_data);

    let verify_clean = PngEngine
        .verify(carrier_bytes, &VerifyOptions::new(), &profile)
        .expect("verify clean png");
    assert_eq!(verify_clean.format, "PNG");
    assert!(verify_clean.levels[0].ok);
    assert!(!verify_clean.levels[1].ok);
    assert!(!verify_clean.is_all_ok());

    // 2. Embedded carrier
    let payload = Payload::file("hello.txt", b"Secret data embedded in PNG carrier");
    let embed_opts = EmbedOptions::default().with_password("png-pass");
    let stego_bytes = PngEngine
        .embed(carrier_bytes, &payload, &embed_opts, &profile)
        .expect("embed png")
        .bytes;

    // Inspect with matching password
    let inspect_opts = InspectOptions::new().with_password("png-pass");
    let inspect_stego = PngEngine
        .inspect(&stego_bytes, &inspect_opts, &profile)
        .expect("inspect stego png");
    assert!(inspect_stego.has_hidden_data);
    assert_eq!(inspect_stego.format, "PNG");
    assert!(inspect_stego.algorithm.is_some());
    assert!(inspect_stego.codec.is_some());
    assert!(inspect_stego.envelope_len.unwrap_or(0) > 0);

    // Verify with matching password
    let verify_opts = VerifyOptions::new().with_password("png-pass");
    let verify_stego = PngEngine
        .verify(&stego_bytes, &verify_opts, &profile)
        .expect("verify stego png");
    assert!(verify_stego.is_all_ok());
    assert_eq!(verify_stego.levels.len(), 3);
    assert!(verify_stego.levels.iter().all(|l| l.ok));

    // Verify with wrong password
    let verify_wrong_opts = VerifyOptions::new().with_password("wrong-pass");
    let verify_wrong = PngEngine
        .verify(&stego_bytes, &verify_wrong_opts, &profile)
        .expect("verify wrong password");
    assert!(!verify_wrong.is_all_ok());
}

#[test]
#[cfg(feature = "content-jpeg")]
fn test_jpeg_inspect_and_verify() {
    let carrier_bytes = include_bytes!("../../../tests/assets/small.jpg");
    let profile = StegoProfile::default();

    // 1. Clean carrier
    let inspect_clean = JpegEngine
        .inspect(carrier_bytes, &InspectOptions::new(), &profile)
        .expect("inspect clean jpeg");
    assert_eq!(inspect_clean.format, "JPEG");
    assert!(!inspect_clean.has_hidden_data);

    let verify_clean = JpegEngine
        .verify(carrier_bytes, &VerifyOptions::new(), &profile)
        .expect("verify clean jpeg");
    assert_eq!(verify_clean.format, "JPEG");
    assert!(verify_clean.levels[0].ok);
    assert!(!verify_clean.levels[1].ok);
    assert!(!verify_clean.is_all_ok());

    // 2. Embedded carrier
    let payload = Payload::file("note.txt", b"Stego message inside JPEG carrier");
    let embed_opts = EmbedOptions::default().with_password("jpeg-pass");
    let stego_bytes = JpegEngine
        .embed(carrier_bytes, &payload, &embed_opts, &profile)
        .expect("embed jpeg")
        .bytes;

    // Inspect with matching password
    let inspect_opts = InspectOptions::new().with_password("jpeg-pass");
    let inspect_stego = JpegEngine
        .inspect(&stego_bytes, &inspect_opts, &profile)
        .expect("inspect stego jpeg");
    assert!(inspect_stego.has_hidden_data);
    assert_eq!(inspect_stego.format, "JPEG");
    assert!(inspect_stego.algorithm.is_some());
    assert!(inspect_stego.codec.is_some());
    assert!(inspect_stego.envelope_len.unwrap_or(0) > 0);

    // Verify with matching password
    let verify_opts = VerifyOptions::new().with_password("jpeg-pass");
    let verify_stego = JpegEngine
        .verify(&stego_bytes, &verify_opts, &profile)
        .expect("verify stego jpeg");
    assert!(verify_stego.is_all_ok());
    assert_eq!(verify_stego.levels.len(), 3);
    assert!(verify_stego.levels.iter().all(|l| l.ok));

    // Verify with wrong password
    let verify_wrong_opts = VerifyOptions::new().with_password("wrong-pass");
    let verify_wrong = JpegEngine
        .verify(&stego_bytes, &verify_wrong_opts, &profile)
        .expect("verify wrong password");
    assert!(!verify_wrong.is_all_ok());
}

#[test]
#[cfg(feature = "content-hevc")]
fn only_a_not_a_scheme_c_carrier_may_fall_back_to_the_bridge() {
    // "Not a Scheme C carrier" and "no CABAC bypass run left": the bridge
    // is the documented second choice for both.
    assert!(should_try_bridge(&StrHideError::NoHiddenData("x".into())));
    assert!(should_try_bridge(&StrHideError::UnsupportedFormat(
        "x".into()
    )));
    assert!(should_try_bridge(&StrHideError::TrellisInfeasible {
        cause: crate::errors::TrellisCause::ExhaustedSlots,
        detail: "x".into(),
    }));

    // Everything else keeps its own diagnosis instead of being replaced by
    // the bridge's "no bridgeable item".
    assert!(!should_try_bridge(&StrHideError::Cancelled));
    assert!(!should_try_bridge(&StrHideError::General("x".into())));
    assert!(!should_try_bridge(&StrHideError::CorruptedData("x".into())));
    assert!(!should_try_bridge(&StrHideError::UnsupportedVersion(
        "x".into()
    )));
    assert!(!should_try_bridge(&StrHideError::Password("x".into())));
    assert!(!should_try_bridge(&StrHideError::Io(
        std::io::Error::other("x")
    )));
    assert!(!should_try_bridge(&StrHideError::SafetyThreshold {
        tier: crate::stego::SafetyLevel::Balanced,
        required_bytes: 10,
        available_bytes: 1,
    }));
}

#[test]
#[cfg(feature = "content")]
fn test_top_level_inspect_and_verify() {
    let carrier_bytes = include_bytes!("../../../tests/assets/small.png");
    let payload = Payload::bytes(b"Top level content test");
    let embed_opts = EmbedOptions::default();
    let stego_bytes = crate::stego::embed_carrier(carrier_bytes, &payload, &embed_opts)
        .expect("embed png top level");

    let inspect_info = crate::stego::inspect_carrier(&stego_bytes, &InspectOptions::new())
        .expect("inspect top level");
    assert!(inspect_info.has_hidden_data);

    let verify_res = crate::stego::verify_carrier(&stego_bytes, &VerifyOptions::new())
        .expect("verify top level");
    assert!(verify_res.is_all_ok());
}
