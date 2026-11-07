//! V4 credential, policy and error-semantics contract.
//!
//! These cases are the ones the earlier suites missed entirely:
//!
//! * `Credential::FileKey` end to end (it existed only as a KDF golden vector),
//!   including the "wrong key is indistinguishable from no payload" rule;
//! * the writer refusing an unknown critical TLV instead of emitting a carrier
//!   nobody -- including itself -- can read;
//! * `verify` deriving the L1 master exactly once (plan M-14);
//! * AEAD success followed by a policy failure surfacing as `CorruptedData`,
//!   not as "no payload here" (plan §4.3).

use strhide::core::payload::Payload;
use strhide::stego::header::Tlv;
use strhide::stego::png::{RawImage, encode_png};
use strhide::stego::{
    EmbedOptions, ExtractOptions, embed_carrier, extract_carrier, verify_carrier,
};

/// Deterministic high-frequency texture, so the carrier is embeddable.
fn texture_png(w: u32, h: u32) -> Vec<u8> {
    let mut pixels = Vec::with_capacity((w * h * 3) as usize);
    for y in 0..h {
        for x in 0..w {
            pixels.push(((x * 17) ^ (y * 31) ^ ((x + y) * 7)) as u8);
            pixels.push(((x * 23 + y * 19) % 256) as u8);
            pixels.push(((x * 13) ^ (y * 29)) as u8);
        }
    }
    encode_png(&RawImage {
        width: w,
        height: h,
        channels: 3,
        bit_depth: 8,
        color_type: 2,
        pixels,
        chunks: Vec::new(),
        idat_sizes: Vec::new(),
        row_filters: Vec::new(),
        idat_info: None,
        tail: Vec::new(),
    })
    .expect("encode png")
}

const KEY: [u8; 32] = [0x11; 32];
const OTHER_KEY: [u8; 32] = [0x22; 32];
const PAYLOAD: &[u8] = b"file-key payload";

#[test]
fn file_key_round_trips_and_a_wrong_key_is_no_payload() {
    let png = texture_png(96, 96);
    let stego = embed_carrier(
        &png,
        &Payload::bytes(PAYLOAD),
        &EmbedOptions::default().with_key(&KEY),
    )
    .expect("embed with a file key");

    let got = extract_carrier(&stego, &ExtractOptions::new().with_key(&KEY))
        .expect("extract with the same key");
    assert_eq!(got.as_slice(), PAYLOAD);

    // A different key must look exactly like "nothing hidden here".
    let err = extract_carrier(&stego, &ExtractOptions::new().with_key(&OTHER_KEY))
        .expect_err("a wrong key must not read the carrier");
    assert!(
        matches!(err, strhide::StrHideError::NoHiddenData(_)),
        "{err:?}"
    );

    // The password path must not read a file-key carrier either.
    let err = extract_carrier(
        &stego,
        &ExtractOptions::new().with_password(strhide::stego::envelope::PUBLIC_DEFAULT_SECRET),
    )
    .expect_err("the default password must not read a keyed carrier");
    assert!(
        matches!(err, strhide::StrHideError::NoHiddenData(_)),
        "{err:?}"
    );
}

#[test]
fn password_and_key_together_are_rejected() {
    let png = texture_png(64, 64);
    let err = embed_carrier(
        &png,
        &Payload::bytes(b"both"),
        &EmbedOptions::default().with_password("pw").with_key(&KEY),
    )
    .expect_err("password and key are mutually exclusive");
    assert!(format!("{err}").contains("mutually exclusive"), "{err}");
}

#[test]
fn unknown_critical_tlv_is_refused_at_write_time() {
    let png = texture_png(96, 96);
    let critical = vec![Tlv {
        type_id: 0x81,
        value: vec![1, 2, 3],
    }];
    let err = embed_carrier(
        &png,
        &Payload::bytes(b"critical"),
        &EmbedOptions::default().with_extensions(critical.clone()),
    )
    .expect_err("critical TLVs must be refused");
    assert!(format!("{err}").contains("critical"), "{err}");

    // A non-critical tag stays writable and round-trips.
    let plain = vec![Tlv {
        type_id: 0x02,
        value: b"x".to_vec(),
    }];
    let stego = embed_carrier(
        &png,
        &Payload::bytes(b"non-critical"),
        &EmbedOptions::default().with_extensions(plain),
    )
    .expect("embed with a non-critical extension");
    let got = extract_carrier(&stego, &ExtractOptions::new()).expect("extract");
    assert_eq!(got.as_slice(), b"non-critical");
}

#[test]
fn verify_derives_the_l1_master_exactly_once() {
    let png = texture_png(96, 96);
    let stego = embed_carrier(
        &png,
        &Payload::bytes(PAYLOAD),
        &EmbedOptions::default().with_password("verify-once"),
    )
    .expect("embed");

    strhide::stego::format::reset_locator_derivation_count();
    let result = verify_carrier(
        &stego,
        &strhide::stego::VerifyOptions::default().with_password("verify-once"),
    )
    .expect("verify");
    assert!(result.is_all_ok(), "verify must pass: {result:?}");
    assert_eq!(
        strhide::stego::format::locator_derivation_count(),
        1,
        "verify must reuse one L1 derivation for both its header and payload levels"
    );
}

#[test]
fn oversized_plaintext_after_aead_is_corrupted_data_not_no_payload() {
    // Highly compressible, so `body_len` fits the (tiny) policy ceiling while
    // the declared plaintext length does not: the failure can only be detected
    // after the AEAD tag verifies.
    let png = texture_png(96, 96);
    let payload = vec![0x21u8; 4096];
    let stego = embed_carrier(
        &png,
        &Payload::bytes(&payload),
        &EmbedOptions::default().with_password("limit"),
    )
    .expect("embed");

    let mut opts = ExtractOptions::new().with_password("limit");
    opts.limits.max_payload_bytes = 100;
    let err = extract_carrier(&stego, &opts).expect_err("policy must refuse the payload");
    assert!(
        matches!(err, strhide::StrHideError::CorruptedData(_)),
        "an authenticated carrier with an over-limit payload must report corruption/limit, \
         got {err:?}"
    );
    assert!(
        format!("{err}").contains("100"),
        "the message must name the policy ceiling: {err}"
    );
}
