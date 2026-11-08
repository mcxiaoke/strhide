// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Content-domain provenance isolation.
//!
//! The goal these tests defend is **attribution**, not detectability: a third
//! party holding the official build must not be able to read a private carrier
//! even when the password is known, and must not be able to tell a private
//! carrier from an untouched one. Everything that makes that true lives on the
//! derivation chain — the label table, the per-carrier salts, the AEAD prefix
//! and the no-password secret — so each assertion below pins one of them:
//!
//! 1. a private dialect round-trips with itself;
//! 2. the official dialect must report `NoHiddenData` on a private carrier,
//!    with the same password and without one;
//! 3. changing **only** the AEAD prefix must already break readability, which
//!    proves the prefix is hashed into the tags instead of being a dead field;
//! 4. the HEVC `Option<&str>` entry points must reject an absent secret instead
//!    of quietly keying the carrier with the public default.
//!
//! None of this touches the embedding geometry: statistically, a private
//! carrier is as visible as an official one. That is the intended trade.

use strhide::core::crypto::CipherSuiteId;
use strhide::core::payload::Payload;
use strhide::errors::StrHideError;
use strhide::facade::{Dialect, StrHide};
use strhide::stego::EmbedOptions;
use strhide::stego::Freshness;
use strhide::stego::format::{
    AudioFormatProfile, DEFAULT_HEVC_FORMAT, DEFAULT_JPEG_FORMAT, GridRule, JpegFormatProfile,
    PngFormatProfile, WireCipherProfile,
};
use strhide::stego::hevc::embed_hevc;
use strhide::stego::params::StegoProfile;

const PNG: &[u8] = include_bytes!("assets/minimal.png");
const JPG: &[u8] = include_bytes!("assets/small.jpg");
const WAV: &[u8] = include_bytes!("assets/small.wav");
const FLAC: &[u8] = include_bytes!("assets/small-wasted.flac");

const PAYLOAD: &[u8] = b"acme internal payload 2026";
const PASSWORD: &str = "acme-shared-password";
const PRIVATE_SECRET: &str = "acme-no-password-content-key-2026";

/// A private label table: every field differs from the official one.
const PRIVATE_CIPHER: WireCipherProfile = WireCipherProfile {
    domain_label: b"acme-stego-domain-v1",
    hpos_label: b"acme-stego-hpos-v1",
    enc_label: b"acme-enc-v1",
    perm_label: b"acme-perm-v1",
    stc_label: b"acme-stc-v1",
    hdr_stc_label: b"acme-hdr-stc-v1",
    ext_stc_label: b"acme-ext-stc-v1",
    aad_prefix: b"acme-content-envelope-v4\0",
    default_suite: CipherSuiteId::Aes256Gcm,
};

/// Same table, different AEAD prefix only.
const PRIVATE_CIPHER_PREFIX_B: WireCipherProfile = WireCipherProfile {
    aad_prefix: b"acme-content-envelope-v5\0",
    ..PRIVATE_CIPHER
};

const PRIVATE_PNG: PngFormatProfile = PngFormatProfile {
    hpos_salt: b"acme-png-hpos-salt-2026",
    cipher: &PRIVATE_CIPHER,
};

const PRIVATE_JPEG: JpegFormatProfile = JpegFormatProfile {
    cover_digest_tag: b"acme-jpeg-cover-salt-2026",
    cipher: &PRIVATE_CIPHER,
    sb_bytes: DEFAULT_JPEG_FORMAT.sb_bytes,
    sb_h: DEFAULT_JPEG_FORMAT.sb_h,
    sb_u: DEFAULT_JPEG_FORMAT.sb_u,
    ext_h: DEFAULT_JPEG_FORMAT.ext_h,
    ext_u: DEFAULT_JPEG_FORMAT.ext_u,
    grid_rule: GridRule::ALL_AC,
};

const PRIVATE_WAV: AudioFormatProfile = AudioFormatProfile {
    hpos_salt: b"acme-wav-hpos-salt-2026",
    cipher: &PRIVATE_CIPHER,
    flac_body_phase_label: b"acme-flac-body-phase-2026",
};

const PRIVATE_FLAC: AudioFormatProfile = AudioFormatProfile {
    hpos_salt: b"acme-flac-hpos-salt-2026",
    cipher: &PRIVATE_CIPHER,
    flac_body_phase_label: b"acme-flac-body-phase-2026",
};

const PRIVATE_DIALECT: Dialect = Dialect::new().with_stego_profile(
    StegoProfile::new()
        .with_default_secret(PRIVATE_SECRET)
        .with_stego_domain("acme-domain-v1")
        .with_png_format(PRIVATE_PNG)
        .with_jpeg_format(PRIVATE_JPEG)
        .with_audio_format(PRIVATE_WAV)
        .with_flac_format(PRIVATE_FLAC),
);

fn private_engine() -> StrHide {
    StrHide::new().with_dialect(PRIVATE_DIALECT)
}

fn official_engine() -> StrHide {
    StrHide::new()
}

fn embed_options(password: Option<&str>) -> EmbedOptions<'_> {
    EmbedOptions::default().with_password_option(password)
}

/// Private write → private read.
fn assert_roundtrip(carrier: &[u8], label: &str, password: Option<&str>) {
    let options = embed_options(password);
    let stego = private_engine()
        .stego()
        .embed(carrier, &Payload::bytes(PAYLOAD), &options)
        .unwrap_or_else(|e| panic!("{label}: private embed failed: {e}"));

    let read = private_engine()
        .stego()
        .extract(&stego, &options.extract_options())
        .unwrap_or_else(|e| panic!("{label}: private extract failed: {e}"));
    assert_eq!(read.data.as_ref(), PAYLOAD, "{label}: payload mismatch");
}

/// Private write → official read must look exactly like "nothing here".
fn assert_official_cannot_read(carrier: &[u8], label: &str, password: Option<&str>) {
    let options = embed_options(password);
    let stego = private_engine()
        .stego()
        .embed(carrier, &Payload::bytes(PAYLOAD), &options)
        .unwrap_or_else(|e| panic!("{label}: private embed failed: {e}"));

    match official_engine()
        .stego()
        .extract(&stego, &options.extract_options())
    {
        Err(StrHideError::NoHiddenData(_)) => {}
        other => panic!("{label}: official read must report NoHiddenData, got {other:?}"),
    }
}

#[test]
fn private_content_carriers_roundtrip() {
    for (label, carrier) in [("png", PNG), ("jpeg", JPG), ("wav", WAV), ("flac", FLAC)] {
        assert_roundtrip(carrier, label, Some(PASSWORD));
        assert_roundtrip(carrier, label, None);
    }
}

#[test]
fn official_content_dialect_cannot_read_private_carriers_with_the_password() {
    for (label, carrier) in [("png", PNG), ("jpeg", JPG), ("wav", WAV), ("flac", FLAC)] {
        assert_official_cannot_read(carrier, label, Some(PASSWORD));
    }
}

#[test]
fn official_content_dialect_cannot_read_private_carriers_without_the_password() {
    for (label, carrier) in [("png", PNG), ("jpeg", JPG), ("wav", WAV), ("flac", FLAC)] {
        assert_official_cannot_read(carrier, label, None);
    }
}

/// The AEAD prefix is wired into the tags, not a decorative field.
///
/// Two dialects identical except for `aad_prefix` must not interoperate: if this
/// passes, the prefix reaches `build_v4_aad_with` from the profile on both the
/// write and the read path.
#[test]
fn aad_prefix_alone_separates_two_dialects() {
    const PREFIX_B_PNG: PngFormatProfile = PngFormatProfile {
        hpos_salt: PRIVATE_PNG.hpos_salt,
        cipher: &PRIVATE_CIPHER_PREFIX_B,
    };
    const PREFIX_B: Dialect = Dialect::new().with_stego_profile(
        StegoProfile::new()
            .with_default_secret(PRIVATE_SECRET)
            .with_stego_domain("acme-domain-v1")
            .with_png_format(PREFIX_B_PNG),
    );

    let options = embed_options(Some(PASSWORD));
    let stego = private_engine()
        .stego()
        .embed(PNG, &Payload::bytes(PAYLOAD), &options)
        .expect("private embed");

    let other = StrHide::new().with_dialect(PREFIX_B);
    match other.stego().extract(&stego, &options.extract_options()) {
        Err(StrHideError::NoHiddenData(_)) => {}
        Ok(_) => panic!("a different AAD prefix must not decode the same carrier"),
        Err(e) => panic!("expected NoHiddenData, got {e}"),
    }
}

/// Only the L2 trellis labels differ: still a different dialect.
///
/// `hdr_stc_label` / `ext_stc_label` are derived **before** the header is
/// readable, so they cannot be recovered from the carrier. JPEG is the carrier
/// used here because it is the one whose superblock is trellis-coded: the PNG
/// and audio engines read their base header by direct LSB and never build this
/// trellis, so for them the two labels are inert (documented on
/// `WireCipherProfile::hdr_stc_label`).
#[test]
fn l2_trellis_labels_alone_separate_two_dialects() {
    const L2_CIPHER: WireCipherProfile = WireCipherProfile {
        domain_label: PRIVATE_CIPHER.domain_label,
        hpos_label: PRIVATE_CIPHER.hpos_label,
        enc_label: PRIVATE_CIPHER.enc_label,
        perm_label: PRIVATE_CIPHER.perm_label,
        stc_label: PRIVATE_CIPHER.stc_label,
        hdr_stc_label: b"acme-hdr-stc-v2",
        ext_stc_label: b"acme-ext-stc-v2",
        aad_prefix: PRIVATE_CIPHER.aad_prefix,
        default_suite: CipherSuiteId::Aes256Gcm,
    };
    const L2_JPEG: JpegFormatProfile = JpegFormatProfile {
        cover_digest_tag: PRIVATE_JPEG.cover_digest_tag,
        cipher: &L2_CIPHER,
        sb_bytes: PRIVATE_JPEG.sb_bytes,
        sb_h: PRIVATE_JPEG.sb_h,
        sb_u: PRIVATE_JPEG.sb_u,
        ext_h: PRIVATE_JPEG.ext_h,
        ext_u: PRIVATE_JPEG.ext_u,
        grid_rule: GridRule::ALL_AC,
    };
    const L2_DIALECT: Dialect = Dialect::new().with_stego_profile(
        StegoProfile::new()
            .with_default_secret(PRIVATE_SECRET)
            .with_stego_domain("acme-domain-v1")
            .with_jpeg_format(L2_JPEG),
    );

    let options = embed_options(Some(PASSWORD));
    let stego = private_engine()
        .stego()
        .embed(JPG, &Payload::bytes(PAYLOAD), &options)
        .expect("private embed");

    let other = StrHide::new().with_dialect(L2_DIALECT);
    match other.stego().extract(&stego, &options.extract_options()) {
        Err(StrHideError::NoHiddenData(_)) => {}
        Ok(_) => panic!("different L2 trellis labels must not decode the same carrier"),
        Err(e) => panic!("expected NoHiddenData, got {e}"),
    }
}

/// Only the FLAC body-phase label differs.
///
/// The phase picks the body slot subset for each embed attempt; a reader with a
/// different label reads different samples, so the AEAD tag fails and the
/// carrier looks empty.
#[test]
fn flac_body_phase_label_alone_separates_two_dialects() {
    const PHASE_B_FLAC: AudioFormatProfile = AudioFormatProfile {
        hpos_salt: PRIVATE_FLAC.hpos_salt,
        cipher: PRIVATE_FLAC.cipher,
        flac_body_phase_label: b"acme-flac-body-phase-2027",
    };
    const PHASE_B: Dialect = Dialect::new().with_stego_profile(
        StegoProfile::new()
            .with_default_secret(PRIVATE_SECRET)
            .with_stego_domain("acme-domain-v1")
            .with_flac_format(PHASE_B_FLAC),
    );

    let options = embed_options(Some(PASSWORD));
    let stego = private_engine()
        .stego()
        .embed(FLAC, &Payload::bytes(PAYLOAD), &options)
        .expect("private embed");

    let other = StrHide::new().with_dialect(PHASE_B);
    match other.stego().extract(&stego, &options.extract_options()) {
        Err(StrHideError::NoHiddenData(_)) => {}
        Ok(_) => panic!("a different FLAC body phase must not decode the same carrier"),
        Err(e) => panic!("expected NoHiddenData, got {e}"),
    }
}

/// The pre-V4 HEVC entry points take `Option<&str>` and never see a
/// `StegoProfile`; an absent secret must therefore be an error, not a silent
/// fallback to the public default key.
#[test]
fn legacy_hevc_entry_point_rejects_an_absent_secret() {
    for secret in [None, Some("")] {
        let err = embed_hevc(
            &[],
            PAYLOAD,
            secret,
            None,
            &DEFAULT_HEVC_FORMAT,
            Freshness::Random,
        )
        .expect_err("an absent secret must not fall back to the public key");
        assert!(
            !matches!(err, StrHideError::NoHiddenData(_)),
            "the rejection must be an explicit error, not 'no payload': {err}"
        );
    }

    // A present secret still goes through (and fails later, on the empty
    // carrier, which is not what this test is about).
    let err = embed_hevc(
        &[],
        PAYLOAD,
        Some("acme-hevc-secret"),
        None,
        &DEFAULT_HEVC_FORMAT,
        Freshness::Random,
    )
    .expect_err("an empty carrier cannot hold a payload");
    assert!(
        !matches!(
            err,
            StrHideError::NoHiddenData(_) | StrHideError::General(_)
        ),
        "a provided secret must not be rejected as a credential problem: {err}"
    );
}

/// FLAC's default AEAD suite must come from the FLAC profile, not the WAV one.
///
/// `with_flac_format` and `with_audio_format` are separate knobs, so a dialect
/// that moves WAV onto a different default suite must not change what a FLAC
/// embed writes. Restricting the reader to AES-256-GCM is the observable: the
/// carrier is only readable when the FLAC profile's suite (AES) is the one the
/// writer chose.
#[test]
fn flac_default_suite_comes_from_the_flac_profile() {
    const WAV_CHACHA_CIPHER: WireCipherProfile = WireCipherProfile {
        default_suite: CipherSuiteId::ChaCha20Poly1305,
        ..PRIVATE_CIPHER
    };
    const WAV_CHACHA: AudioFormatProfile = AudioFormatProfile {
        hpos_salt: PRIVATE_WAV.hpos_salt,
        cipher: &WAV_CHACHA_CIPHER,
        flac_body_phase_label: PRIVATE_WAV.flac_body_phase_label,
    };
    const SPLIT_DIALECT: Dialect = Dialect::new().with_stego_profile(
        StegoProfile::new()
            .with_default_secret(PRIVATE_SECRET)
            .with_stego_domain("acme-domain-v1")
            .with_audio_format(WAV_CHACHA)
            .with_flac_format(PRIVATE_FLAC),
    );

    let options = embed_options(Some(PASSWORD));
    let stego = StrHide::new()
        .with_dialect(SPLIT_DIALECT)
        .stego()
        .embed(FLAC, &Payload::bytes(PAYLOAD), &options)
        .expect("flac embed");

    let mut read_opts = options.extract_options();
    read_opts.limits.allowed_suites = Some(vec![CipherSuiteId::Aes256Gcm.as_u16()]);
    let read = StrHide::new()
        .with_dialect(SPLIT_DIALECT)
        .stego()
        .extract(&stego, &read_opts)
        .expect("the FLAC profile default suite (AES-256-GCM) must be the one in use");
    assert_eq!(read.data.as_ref(), PAYLOAD, "payload mismatch");
}
