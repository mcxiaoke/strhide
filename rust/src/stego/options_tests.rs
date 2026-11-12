use super::*;

#[test]
fn auto_tuning_accepts_every_format() {
    let tuning = StegoTuning::Auto;
    for format in [
        FileFormat::Png,
        FileFormat::Jpeg,
        FileFormat::Heif,
        FileFormat::Mp4,
        FileFormat::HevcAnnexB,
    ] {
        assert!(
            tuning.applicable_to(format).is_ok(),
            "Auto must be usable on {format:?}"
        );
    }
}

#[test]
fn format_specific_tuning_rejects_the_wrong_carrier() {
    let png = StegoTuning::Png {
        model: SpatialAlgorithm::Suniward,
        params: PngParams::default(),
    };
    assert!(png.applicable_to(FileFormat::Png).is_ok());
    let err = png.applicable_to(FileFormat::Jpeg).expect_err("mismatch");
    assert!(
        err.to_string().contains("suniward") && err.to_string().contains("JPEG"),
        "the message must name both sides: {err}"
    );

    let jpeg = StegoTuning::jpeg(JpegParams::default());
    assert!(jpeg.applicable_to(FileFormat::Jpeg).is_ok());
    assert!(jpeg.applicable_to(FileFormat::Png).is_err());

    let hevc = StegoTuning::hevc(HevcMode::Cabac);
    for format in [
        FileFormat::Heif,
        FileFormat::Mp4,
        FileFormat::Mkv,
        FileFormat::HevcAnnexB,
    ] {
        assert!(hevc.applicable_to(format).is_ok());
    }
    assert!(hevc.applicable_to(FileFormat::Png).is_err());
}

#[cfg(feature = "content-audio")]
#[test]
fn audio_tuning_pins_wav_and_flac() {
    let audio = StegoTuning::audio(AudioParams::default());
    assert!(audio.applicable_to(FileFormat::Wav).is_ok());
    assert!(audio.applicable_to(FileFormat::Flac).is_ok());
    let err = audio.applicable_to(FileFormat::Png).expect_err("mismatch");
    assert!(
        err.to_string().contains("audio") && err.to_string().contains("PNG"),
        "the message must name both sides: {err}"
    );
    assert_eq!(format!("{audio:?}"), "Audio");
}

#[test]
fn resolve_fills_the_halves_the_tuning_does_not_name() {
    let tuning = StegoTuning::Png {
        model: SpatialAlgorithm::Suniward,
        params: PngParams::default().with_stc_h(6),
    };
    let resolved = tuning.resolve();
    assert_eq!(resolved.png_model.id(), "suniward");
    assert_eq!(resolved.png_params.stc_h, 6);
    // The JPEG half stays at its defaults so the HEIF bridge still works.
    assert_eq!(resolved.jpeg_model.id(), "uerd");
    assert_eq!(resolved.jpeg_params, JpegParams::default());
    assert_eq!(resolved.hevc_mode, HevcMode::Auto);
}

#[test]
fn params_mut_helpers_install_the_right_arm() {
    let mut opts = EmbedOptions::default();
    opts.png_params_mut().stc_h = 5;
    match &opts.tuning {
        StegoTuning::Png { params, .. } => assert_eq!(params.stc_h, 5),
        other => panic!("expected the PNG arm, got {other:?}"),
    }
    // Switching to the other half keeps the value already set.
    opts.jpeg_params_mut().stc_h = 7;
    match &opts.tuning {
        StegoTuning::Jpeg { params, .. } => assert_eq!(params.stc_h, 7),
        other => panic!("expected the JPEG arm, got {other:?}"),
    }
}

#[test]
fn an_empty_password_does_not_mask_the_dialect_secret() {
    let dialect = StegoProfile::new().with_default_secret("org-key");
    let opts = EmbedOptions::default().with_password("");
    assert_eq!(opts.secret(&dialect), Some("org-key"));

    let opts = EmbedOptions::default().with_password("user-pw");
    assert_eq!(opts.secret(&dialect), Some("user-pw"));

    let official = StegoProfile::new();
    assert_eq!(EmbedOptions::default().secret(&official), None);
}

#[test]
fn domain_falls_back_to_the_dialect() {
    let dialect = StegoProfile::new().with_stego_domain("org/domain");
    assert_eq!(ProbeOptions::default().domain(&dialect), Some("org/domain"));
    assert_eq!(
        ProbeOptions::default().with_domain("call").domain(&dialect),
        Some("call")
    );
}

#[test]
fn algorithm_names_round_trip_through_the_public_parsers() {
    for name in ["hill", "suniward", "mipod"] {
        let model = SpatialAlgorithm::from_name(name).expect(name);
        assert_eq!(model.id(), name);
        assert_eq!(model.model().id(), name);
    }
    for name in ["uerd", "juniward", "jmipod"] {
        let model = JpegAlgorithm::from_name(name).expect(name);
        assert_eq!(model.id(), name);
        assert_eq!(model.model().id(), name);
    }
    assert_eq!(SpatialAlgorithm::from_name("auto").unwrap().id(), "hill");
    assert_eq!(JpegAlgorithm::from_name("auto").unwrap().id(), "uerd");
    assert!(SpatialAlgorithm::from_name("juniward").is_none());
    assert!(JpegAlgorithm::from_name("hill").is_none());
    assert!(HevcMode::from_name("cabac").is_some());
    assert!(HevcMode::from_name("nope").is_none());
}

#[test]
fn password_is_redacted_in_debug() {
    let opts = EmbedOptions::default().with_password("super-secret-password");
    let debug = format!("{opts:?}");
    assert!(!debug.contains("super-secret-password"));
    assert!(debug.contains("<redacted>"));

    let probe = ProbeOptions::default().with_password("super-secret-password");
    let debug_probe = format!("{probe:?}");
    assert!(!debug_probe.contains("super-secret-password"));
    assert!(debug_probe.contains("<redacted>"));

    let extract = ExtractOptions::default().with_password("super-secret-password");
    let debug_extract = format!("{extract:?}");
    assert!(!debug_extract.contains("super-secret-password"));
    assert!(debug_extract.contains("<redacted>"));

    let inspect = InspectOptions::default().with_password("super-secret-password");
    let debug_inspect = format!("{inspect:?}");
    assert!(!debug_inspect.contains("super-secret-password"));
    assert!(debug_inspect.contains("<redacted>"));

    let verify = VerifyOptions::default().with_password("super-secret-password");
    let debug_verify = format!("{verify:?}");
    assert!(!debug_verify.contains("super-secret-password"));
    assert!(debug_verify.contains("<redacted>"));
}

#[test]
fn key_is_redacted_in_debug() {
    let key = [0x11u8; 32];
    for debug in [
        format!("{:?}", EmbedOptions::default().with_key(&key)),
        format!("{:?}", ProbeOptions::default().with_key(&key)),
        format!("{:?}", ExtractOptions::default().with_key(&key)),
        format!("{:?}", InspectOptions::default().with_key(&key)),
        format!("{:?}", VerifyOptions::default().with_key(&key)),
    ] {
        assert!(!debug.contains("11111111"), "key bytes leaked: {debug}");
        assert!(debug.contains("<redacted>"));
    }
}

#[test]
fn resolve_credential_applies_the_documented_priority() {
    let key = [0x11u8; 32];
    let profile = StegoProfile::new();

    let credential = resolve_credential(Some("pw"), None, &profile).unwrap();
    assert!(matches!(credential, Credential::Password("pw")));

    let credential = resolve_credential(None, Some(&key), &profile).unwrap();
    assert!(matches!(credential, Credential::FileKey(&_)));

    let err = match resolve_credential(Some("pw"), Some(&key), &profile) {
        Ok(_) => panic!("password and key must be mutually exclusive"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("mutually exclusive"));

    // An empty password counts as not supplied and falls back to the
    // dialect secret, then to the public constant.
    let credential = resolve_credential(Some(""), Some(&key), &profile).unwrap();
    assert!(matches!(credential, Credential::FileKey(_)));

    let private = StegoProfile::new().with_default_secret("dialect-secret");
    let credential = resolve_credential(Some(""), None, &private).unwrap();
    assert!(matches!(credential, Credential::Password("dialect-secret")));

    let credential = resolve_credential(None, None, &profile).unwrap();
    assert!(matches!(
        credential,
        Credential::Password(crate::stego::envelope::PUBLIC_DEFAULT_SECRET)
    ));
}

#[test]
fn max_payload_builder_reaches_the_limits() {
    let opts = ExtractOptions::new().with_max_payload_bytes(4096);
    assert_eq!(opts.limits.max_payload_bytes, 4096);
}
