// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! A private *wire format*: carriers only your own build can read.
//!
//! ```text
//! cargo run --release --example private_format
//! ```
//!
//! [`JpegFormatProfile`] is the compile-time identity of the JPEG V3 wire format:
//! the derivation labels that feed every KDF, the header geometry, the slot
//! grid rule and the suite whitelist. Changing one byte of a label moves the
//! header slots, the trellis and every key — the carrier becomes unreadable to
//! the official build, and the failure is reported as `NoHiddenData`, exactly
//! like a wrong password.
//!
//! This is deliberately **not** a CLI switch: a format you can toggle is a
//! format a detector can enumerate. Change the literal, rebuild, keep the
//! binary to yourself.
//!
//! Everything the demo prints is asserted, so it doubles as a test of the
//! public surface a private build actually needs.

use strhide::core::control::Control;
use strhide::core::crypto::Credential;
use strhide::errors::StrHideError;
use strhide::stego::format::{DEFAULT_JPEG_FORMAT, JpegFormatProfile};
use strhide::stego::jpeg::cost::UerdCostModel;
use strhide::stego::jpeg::engine::{embed_jpeg, extract_jpeg};
use strhide::stego::params::{ExtractParams, JpegParams};

/// A private profile: same geometry, different derivation labels.
///
/// In a real private build these strings would be yours alone; the geometry is
/// only repeated here to keep the demo short.
const ACME_CIPHER: strhide::stego::format::WireCipherProfile =
    strhide::stego::format::WireCipherProfile {
        domain_label: b"acme-domain",
        hpos_label: b"acme-hpos",
        enc_label: b"acme-enc",
        perm_label: b"acme-perm",
        stc_label: b"acme-trellis",
        default_suite: strhide::core::crypto::CipherSuiteId::Aes256Gcm,
    };

const ACME_FORMAT: JpegFormatProfile = JpegFormatProfile {
    cover_digest_tag: b"acme-cover-v1",
    cipher: &ACME_CIPHER,
    sb_bytes: 44,
    sb_h: 8,
    sb_u: 2,
    ext_h: 8,
    ext_u: 4,
    grid_rule: strhide::stego::format::GridRule::ALL_AC,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let carrier = std::fs::read("rust/tests/assets/small.jpg")
        .or_else(|_| std::fs::read("tests/assets/small.jpg"))?;
    let payload = b"only the private build can read this";
    let password = "private-format-demo";

    ACME_FORMAT.validate()?;
    let params = JpegParams::default();
    let cost = UerdCostModel;

    // 1. Embed with the private profile.
    let stego = embed_jpeg(
        &carrier,
        payload,
        Credential::Password(password),
        None,
        0x0001,
        &[],
        &ACME_FORMAT,
        &params,
        strhide::stego::SafetyPolicy::default(),
        &cost,
        strhide::stego::Freshness::Random,
        &Control::none(),
    )?;
    println!(
        "embedded {} bytes, {} -> {} bytes",
        payload.len(),
        carrier.len(),
        stego.len()
    );

    // 2. The private build reads it back.
    let recovered = extract_jpeg(
        &stego,
        Credential::Password(password),
        None,
        &ACME_FORMAT,
        &ExtractParams::default(),
        &Control::none(),
    )?;
    assert_eq!(recovered.as_bytes(), payload);
    println!("private profile: payload recovered");

    // 3. The official build finds nothing -- and cannot tell it apart from a
    //    carrier with no payload at all.
    match extract_jpeg(
        &stego,
        Credential::Password(password),
        None,
        &DEFAULT_JPEG_FORMAT,
        &ExtractParams::default(),
        &Control::none(),
    ) {
        Err(StrHideError::NoHiddenData(_)) => {
            println!("official profile: NoHiddenData (indistinguishable from 'empty')");
        }
        other => panic!("official profile must not read a private carrier: {other:?}"),
    }

    // 4. A carrier written by the official build stays unreadable here, too.
    let official = embed_jpeg(
        &carrier,
        payload,
        Credential::Password(password),
        None,
        0x0001,
        &[],
        &DEFAULT_JPEG_FORMAT,
        &params,
        strhide::stego::SafetyPolicy::default(),
        &cost,
        strhide::stego::Freshness::Random,
        &Control::none(),
    )?;
    let err = extract_jpeg(
        &official,
        Credential::Password(password),
        None,
        &ACME_FORMAT,
        &ExtractParams::default(),
        &Control::none(),
    )
    .expect_err("the official dialect must not read an ACME carrier");
    assert!(
        matches!(err, StrHideError::NoHiddenData(_)),
        "isolation must look like 'nothing here', got: {err:?}"
    );
    println!("both directions are isolated");
    Ok(())
}
