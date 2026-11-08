//! JPEG V4 envelope contract.
//!
//! Pins the wire-level invariants that must hold while the JPEG engine moves
//! from the V3 superblock to the shared V4 content envelope: authenticated
//! header/extension, probe/embed agreement, and indistinguishable failures.

use strhide::core::payload::Payload;
use strhide::errors::StrHideError;
use strhide::stego::header::Tlv;
use strhide::stego::{
    EmbedOptions, ExtractOptions, InspectOptions, ProbeOptions, VerifyOptions, embed_carrier,
    extract_carrier, inspect_carrier, probe_carrier_capacity, verify_carrier,
};

const CARRIER: &[u8] = include_bytes!("../assets/small.jpg");
const PASSWORD: &str = "jpeg-v4-test-password";
const PAYLOAD: &[u8] = b"jpeg v4 envelope roundtrip payload";

fn credits() -> EmbedOptions<'static> {
    EmbedOptions::default().with_password(PASSWORD)
}

#[test]
fn v4_roundtrip_default_suite() {
    let stego = embed_carrier(
        CARRIER,
        &Payload::bytes(PAYLOAD),
        &(credits()).with_suite_id(1),
    )
    .expect("suite 1 embed");
    let extracted = extract_carrier(&stego, &ExtractOptions::default().with_password(PASSWORD))
        .expect("suite 1 extract");
    assert_eq!(extracted, PAYLOAD);
}

#[test]
fn v4_chacha_suite_roundtrip_and_tamper_rejected() {
    let stego = embed_carrier(
        CARRIER,
        &Payload::bytes(PAYLOAD),
        &(credits()).with_suite_id(2),
    )
    .expect("suite 2 embed");
    let extracted = extract_carrier(&stego, &ExtractOptions::default().with_password(PASSWORD))
        .expect("suite 2 extract");
    assert_eq!(extracted, PAYLOAD);

    // The suite id in the authenticated header must gate the trial: asking for
    // AES only cannot return a ChaCha carrier's payload.
    let only_aes = extract_carrier(
        &stego,
        &ExtractOptions::default()
            .with_password(PASSWORD)
            .with_limits(
                strhide::stego::ExtractParams::default().with_allowed_suites(Some(vec![1])),
            ),
    );
    assert!(
        matches!(only_aes, Err(StrHideError::NoHiddenData(_))),
        "{only_aes:?}"
    );

    // A scan-data flip invalidates the Poly1305 tag and must not leak bytes.
    let mut flipped = stego;
    let idx = (flipped_sos_offset(&flipped) + 16).min(flipped.len() - 1);
    flipped[idx] ^= 0x01;
    let err = extract_carrier(&flipped, &ExtractOptions::default().with_password(PASSWORD))
        .expect_err("scan-data flip must fail");
    assert!(
        matches!(err, StrHideError::CorruptedData(_)),
        "a corrupted scan must report CorruptedData, got: {err:?}"
    );
}

#[test]
fn v4_extensions_roundtrip_and_inspect_reports_header() {
    let options = (credits()).with_extensions(vec![Tlv {
        type_id: 0x01,
        value: b"jpeg-v4-ext".to_vec(),
    }]);
    let stego = embed_carrier(CARRIER, &Payload::bytes(PAYLOAD), &options).expect("embed");

    let info = inspect_carrier(&stego, &InspectOptions::default().with_password(PASSWORD))
        .expect("inspect");
    assert!(info.has_hidden_data);
    assert_eq!(info.format, "JPEG");
    assert!(
        info.codec
            .as_deref()
            .unwrap_or_default()
            .contains("Ternary STC")
    );
    assert!(info.envelope_len.unwrap_or(0) >= PAYLOAD.len());

    let extracted = extract_carrier(&stego, &ExtractOptions::default().with_password(PASSWORD))
        .expect("extract");
    assert_eq!(extracted, PAYLOAD);
}

#[test]
fn v4_probe_and_embed_agree_on_extensions() {
    let tlv = vec![Tlv {
        type_id: 0x01,
        value: b"probe-ext".to_vec(),
    }];
    let with_ext = probe_carrier_capacity(
        CARRIER,
        &ProbeOptions::default()
            .with_password(PASSWORD)
            .with_extensions(tlv.clone()),
    )
    .expect("probe with extension");
    let without_ext =
        probe_carrier_capacity(CARRIER, &ProbeOptions::default().with_password(PASSWORD))
            .expect("probe without extension");
    assert!(
        with_ext.recommended_max_bytes <= without_ext.recommended_max_bytes,
        "the extension area must not increase capacity"
    );

    let payload = vec![0x5Au8; with_ext.recommended_max_bytes];
    let stego = embed_carrier(
        CARRIER,
        &Payload::bytes(&payload),
        &(credits()).with_extensions(tlv),
    )
    .expect("embed at the probe size");
    let extracted = extract_carrier(&stego, &ExtractOptions::default().with_password(PASSWORD))
        .expect("extract");
    assert_eq!(extracted, payload);
}

#[test]
fn v4_wrong_password_and_clean_carrier_are_indistinguishable() {
    let stego = embed_carrier(CARRIER, &Payload::bytes(PAYLOAD), &credits()).expect("embed");
    let wrong = extract_carrier(
        &stego,
        &ExtractOptions::default().with_password("wrong-password"),
    )
    .expect_err("wrong password");
    let clean = extract_carrier(CARRIER, &ExtractOptions::default().with_password(PASSWORD))
        .expect_err("clean carrier");
    assert!(
        matches!(wrong, StrHideError::NoHiddenData(_)),
        "wrong password must collapse to NoHiddenData: {wrong:?}"
    );
    assert!(
        matches!(clean, StrHideError::NoHiddenData(_)),
        "clean carrier must be NoHiddenData: {clean:?}"
    );
}

#[test]
fn v4_inspect_and_extract_agree_under_a_tightened_policy() {
    // Ensure `inspect` and `extract` enforce limits consistently (e.g. `max_payload_bytes`),
    // preventing inspect from reporting success when extract would reject the policy.
    use strhide::stego::params::ExtractParams;

    let stego = embed_carrier(CARRIER, &Payload::bytes(PAYLOAD), &credits()).expect("embed");
    let tight = ExtractParams::default().with_max_payload_bytes(1);

    let open = inspect_carrier(&stego, &InspectOptions::default().with_password(PASSWORD))
        .expect("inspect with the default policy");
    assert!(open.has_hidden_data);

    let refused = inspect_carrier(
        &stego,
        &InspectOptions::default()
            .with_password(PASSWORD)
            .with_limits(tight.clone()),
    )
    .expect("inspect with a tight policy");
    assert!(
        !refused.has_hidden_data,
        "inspect must not advertise a payload the extractor refuses"
    );

    let extracted = extract_carrier(
        &stego,
        &ExtractOptions::default()
            .with_password(PASSWORD)
            .with_limits(tight),
    )
    .expect_err("extract under the same tight policy");
    assert!(
        matches!(extracted, StrHideError::NoHiddenData(_)),
        "extract must collapse to NoHiddenData: {extracted:?}"
    );

    // Same disagreement check for the PBKDF2 ceiling: both ends refuse before
    // doing any key derivation.
    let low_kdf = ExtractParams::default().with_max_pbkdf2_iterations(1_000);
    let refused = inspect_carrier(
        &stego,
        &InspectOptions::default()
            .with_password(PASSWORD)
            .with_limits(low_kdf.clone()),
    )
    .expect("inspect with a low KDF ceiling");
    assert!(
        !refused.has_hidden_data,
        "inspect must honour the KDF ceiling"
    );
    assert!(
        extract_carrier(
            &stego,
            &ExtractOptions::default()
                .with_password(PASSWORD)
                .with_limits(low_kdf),
        )
        .is_err(),
        "extract must refuse the same carrier"
    );
}

#[test]
fn v4_verify_explains_levels_and_wrong_password_fails_l2() {
    let stego = embed_carrier(CARRIER, &Payload::bytes(PAYLOAD), &credits()).expect("embed");

    let ok =
        verify_carrier(&stego, &VerifyOptions::default().with_password(PASSWORD)).expect("verify");
    assert!(ok.is_all_ok(), "levels: {:?}", ok.levels);

    let bad = verify_carrier(
        &stego,
        &VerifyOptions::default().with_password("wrong-password"),
    )
    .expect("verify runs");
    assert!(!bad.is_all_ok(), "levels: {:?}", bad.levels);
}

#[test]
fn v4_tampered_carrier_never_panics() {
    let stego = embed_carrier(CARRIER, &Payload::bytes(PAYLOAD), &credits()).expect("embed");
    // Cut the scan data: the decoder must report an error, never panic.
    let truncated = &stego[..stego.len().saturating_sub(32)];
    assert!(
        extract_carrier(
            truncated,
            &ExtractOptions::default().with_password(PASSWORD),
        )
        .is_err(),
        "a truncated carrier must not extract"
    );

    // A one-byte flip in the entropy-coded scan must not yield the payload.
    // The flip has to land in scan data: the last bytes of a JPEG can be
    // padding the decoder ignores, which made the old fixed tail offset
    // intermittently inert. Start just past the SOS marker instead.
    let sos = flipped_sos_offset(&stego);
    let mut flipped = stego.clone();
    let idx = (sos + 16).min(flipped.len() - 1);
    flipped[idx] ^= 0x01;
    let result = extract_carrier(&flipped, &ExtractOptions::default().with_password(PASSWORD));
    let err = result.expect_err("one-byte scan flip must fail");
    assert!(
        matches!(err, StrHideError::CorruptedData(_)),
        "a corrupted scan must report CorruptedData, got: {err:?}"
    );
}

/// Byte offset of the first SOS (`FF DA`) marker, i.e. the start of the
/// entropy-coded scan.
fn flipped_sos_offset(jpeg: &[u8]) -> usize {
    jpeg.windows(2)
        .position(|w| w == [0xFF, 0xDA])
        .expect("JPEG has an SOS marker")
}
