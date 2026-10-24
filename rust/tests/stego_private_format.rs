// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Private [`JpegFormatProfile`] end-to-end pass-through.
//!
//! Regression for the gap where the high-level `stego` entry points hard-coded
//! `DEFAULT_JPEG_FORMAT` in all three paths (embed / extract / probe). A private
//! wire-format identity must flow through every entry point: a carrier
//! embedded under it must extract back, the capacity probe must use its
//! geometry, and an official profile must fail to read it.

use strhide::params::Profile;
use strhide::stego::{
    StegoOptions, embed_carrier_with_profile, extract_carrier_with_profile,
    probe_carrier_capacity_with_profile,
};
use strhide::{DEFAULT_JPEG_FORMAT, GridRule, JpegFormatProfile};

const COVER: &[u8] = include_bytes!("assets/small.jpg");
const PAYLOAD: &[u8] = b"private-format-roundtrip";

/// A private wire format: same geometry as the default, distinct derivation
/// labels, so it is a different format that still passes self-validation.
const PRIVATE_FORMAT: JpegFormatProfile = JpegFormatProfile {
    format_major: 1,
    format_minor: 0,
    cover_digest_tag: b"private-cover-v1",
    hpos_label: b"private-hpos",
    stc_label: b"private-stc",
    enc_label: b"private-enc",
    perm_label: b"private-perm",
    sb_bytes: 44,
    sb_h: 8,
    sb_u: 2,
    ext_h: 8,
    ext_u: 4,
    grid_rule: GridRule::ALL_AC,
    suites: DEFAULT_JPEG_FORMAT.suites,
};

/// The dialect is declared entirely at compile time, including the format.
const PRIVATE_PROFILE: Profile = Profile::new().with_jpeg_format(PRIVATE_FORMAT);

#[test]
fn private_format_embed_extract_roundtrip() {
    let options = StegoOptions::default();

    let stego = embed_carrier_with_profile(COVER, PAYLOAD, &options, &PRIVATE_PROFILE)
        .expect("embed under private format");
    assert_ne!(stego, COVER, "the carrier must change");

    let extracted = extract_carrier_with_profile(&stego, &options, &PRIVATE_PROFILE)
        .expect("extract under private format");
    assert_eq!(extracted, PAYLOAD);
}

#[test]
fn private_format_probe_uses_private_geometry() {
    let options = StegoOptions::default();

    let cap = probe_carrier_capacity_with_profile(COVER, &options, &PRIVATE_PROFILE)
        .expect("probe under private format");
    assert!(
        cap.recommended_max_bytes > 0,
        "the probe must report capacity"
    );
    // The private format is what the profile resolves to.
    assert_eq!(PRIVATE_PROFILE.jpeg_format(), &PRIVATE_FORMAT);
}

#[test]
fn official_profile_cannot_read_private_format() {
    let options = StegoOptions::default();
    let stego = embed_carrier_with_profile(COVER, PAYLOAD, &options, &PRIVATE_PROFILE)
        .expect("embed under private format");

    // An official-profile extraction must fail -- the same indistinguishable
    // shape as a wrong password, never a distinguishable error.
    let official = Profile::default();
    assert!(
        extract_carrier_with_profile(&stego, &options, &official).is_err(),
        "an official profile must not read a private-format carrier"
    );
}

#[test]
fn private_format_is_a_non_official_dialect() {
    assert!(!PRIVATE_PROFILE.is_official());
    assert!(Profile::default().is_official());
}
