use super::*;

fn stego(payload: PayloadSource<'_>, password: Option<&str>, stealth: bool) -> Vec<u8> {
    let carrier = include_bytes!("../../../tests/assets/minimal.png").to_vec();
    let (bytes, _) = write_carrier_bytes(
        &carrier,
        payload,
        &WriteOptions::default()
            .with_password_option(password)
            .with_stealth(stealth),
        &LocalParams::default(),
        &StructureProfile::new(),
    )
    .unwrap();
    bytes
}

/// Verifies that verification derives password secrets once and reuses them
/// across Level 2 and Level 3 checks.
#[test]
fn verify_derives_the_password_pair_once_beyond_the_locator() {
    let bytes = stego(PayloadSource::Text("p1-7"), Some("pw"), true);
    crate::crypto::reset_pbkdf2_calls();
    let res = verify_carrier_bytes(&bytes, Some("pw"), &StructureProfile::new()).unwrap();
    assert!(verify_passed(&res), "{res:?}");
    assert_eq!(crate::crypto::pbkdf2_calls(), 2, "unexpected PBKDF2 count");
}

/// Verifies that an empty password string does not create a stealth envelope.
#[test]
fn empty_password_does_not_create_a_stealth_envelope() {
    let carrier = include_bytes!("../../../tests/assets/minimal.png").to_vec();
    let err = write_carrier_bytes(
        &carrier,
        PayloadSource::Text("p2-12"),
        &WriteOptions::default().with_password("").with_stealth(true),
        &LocalParams::default(),
        &StructureProfile::new(),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("Stealth mode requires a password"),
        "unexpected error: {err}"
    );
}

/// Verifies that the unencrypted path derives default secrets once across checks.
#[test]
fn verify_derives_the_default_pair_once() {
    let bytes = stego(PayloadSource::Text("p1-7"), None, false);
    crate::crypto::reset_pbkdf2_calls();
    let res = verify_carrier_bytes(&bytes, None, &StructureProfile::new()).unwrap();
    assert!(verify_passed(&res), "{res:?}");
    assert_eq!(crate::crypto::pbkdf2_calls(), 1, "unexpected PBKDF2 count");
}

/// Verifies that advertised strategy capacities never exceed the payload limit
/// enforced by the engine for the host format.
#[test]
fn strategy_capacities_never_exceed_engine_payload_limit() {
    use crate::structure::adapters::StrategyCapacity;

    let mk = |capacity_bytes: Option<u64>| StrategyCapacity {
        strategy: "x".into(),
        capacity_bytes,
        available: true,
        limit: "native".into(),
        note: None,
    };

    // 86,854-byte host: 256x is below the 64 MiB floor, so every strategy
    // is capped at 64 MiB; lower native ceilings keep their own text.
    let mut caps = vec![mk(None), mk(Some(u32::MAX as u64)), mk(Some(100))];
    apply_engine_payload_limit(&mut caps, 86_854);
    assert_eq!(caps[0].capacity_bytes, Some(64 * 1024 * 1024));
    assert_eq!(caps[1].capacity_bytes, Some(64 * 1024 * 1024));
    assert_eq!(caps[2].capacity_bytes, Some(100), "lower native stays");
    assert!(caps[0].limit.contains("67,108,864"), "{}", caps[0].limit);
    assert_eq!(caps[2].limit, "native");

    // 8 MiB host: 256x = 2 GiB, clamped to the 1 GiB ceiling.
    let mut caps = vec![mk(None)];
    apply_engine_payload_limit(&mut caps, 8 * 1024 * 1024);
    assert_eq!(
        caps[0].capacity_bytes,
        Some(crate::crypto::MAX_VERIFY_PAYLOAD_SIZE)
    );

    // 8 GiB host: 256x is above the ceiling; still the ceiling.
    let mut caps = vec![mk(None)];
    apply_engine_payload_limit(&mut caps, 8u64 << 30);
    assert_eq!(
        caps[0].capacity_bytes,
        Some(crate::crypto::MAX_VERIFY_PAYLOAD_SIZE)
    );
}
