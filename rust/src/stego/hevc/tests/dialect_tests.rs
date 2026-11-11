use super::*;
use crate::stego::format::DEFAULT_HEVC_FORMAT;
use crate::stego::hevc::sniff::{NAL_IDR_W_RADL, NAL_TRAIL_R};

/// The literals below are pinned to `docs/api/WIRE_SPEC_CONTENT.md` §13.4.5. The
/// spec is the only reproduction recipe a private build has; if an
/// implementation constant changes without the doc (or vice versa),
/// third-party rebuilds silently produce mutually unreadable carriers.
#[test]
fn default_format_literals_match_the_wire_spec() {
    let fmt = &DEFAULT_HEVC_FORMAT;
    assert_eq!(fmt.magic_label, b"strhide-hevc-magic-v4");
    assert_eq!(fmt.cover_salt, b"strhide-hevc-cover-v1");
    assert_eq!(fmt.stc_h, 7);
    assert_eq!(fmt.stc_u, 2);
    assert_eq!(fmt.cipher.default_suite, CipherSuiteId::Aes256Gcm);
}

/// The V4 magic comes out of the L2 locator keys, so it changes with the
/// credential and with the domain; it is not a searchable constant.
#[test]
fn magic_is_derived_from_the_credential_and_domain() {
    let fmt = &DEFAULT_HEVC_FORMAT;
    let salt = [0x11u8; 32];
    let magic_for = |pw: &str, domain: Option<&str>| {
        let master = derive_locator_master(Credential::Password(pw), domain, fmt.cipher, &salt)
            .expect("master");
        derive_l2_locator_keys(&master, fmt.cipher, fmt.magic_label, domain)
            .expect("locator")
            .magic4
    };
    let m1 = magic_for("secret-one", None);
    let m2 = magic_for("secret-two", None);
    assert_ne!(m1, m2, "different credentials must yield different magics");
    assert_eq!(m1, magic_for("secret-one", None), "stable for same inputs");
    assert_ne!(m1, magic_for("secret-one", Some("org.acme")));
}

/// An absent secret is rejected instead of falling back to the shared
/// public constant.
///
/// These pre-V4 wrappers cannot see a `StegoProfile`, so a fallback would
/// key the carrier with [`crate::stego::envelope::PUBLIC_DEFAULT_SECRET`] and hand
/// out a file any
/// strhide build can read -- exactly the provenance leak a private dialect
/// exists to prevent.
#[test]
fn absent_secret_is_rejected() {
    assert!(
        legacy_credential(None).is_err(),
        "no secret must not silently fall back to the public key"
    );
    assert!(
        legacy_credential(Some("")).is_err(),
        "an empty secret is the same as no secret"
    );
    assert!(matches!(
        legacy_credential(Some("pw")),
        Ok(Credential::Password(pw)) if pw == "pw"
    ));
}

/// Domain isolation subkeys the credential: same secret, different domain,
/// unrelated locator master.
#[test]
fn domain_changes_the_derived_keys() {
    let digest = [7u8; 32];
    let fmt = &DEFAULT_HEVC_FORMAT;
    let k_none = derive_locator_master(Credential::Password("pw"), None, fmt.cipher, &digest)
        .expect("master");
    let k_domain = derive_locator_master(
        Credential::Password("pw"),
        Some("org.acme"),
        fmt.cipher,
        &digest,
    )
    .expect("master");
    assert_ne!(k_none, k_domain);
}

/// The ladder is stateless and depends only on the NAL type sequence: a
/// non-reference picture sits on the drift-free rung, a reference non-IRAP
/// picture on the second rung, an IRAP is excluded. An all-intra stream
/// (still image, all-IDR video) has nothing predicted from anything, so
/// every picture is drift-free.
#[test]
fn ladder_is_stateless_and_has_two_rungs() {
    // Inter stream: non-reference -> band 0, reference -> band 1.
    assert_eq!(picture_band(NAL_TRAIL_N, true), Some(BAND_NON_REFERENCE));
    assert_eq!(picture_band(NAL_TSA_N, true), Some(BAND_NON_REFERENCE));
    assert_eq!(picture_band(NAL_RASL_N, true), None);
    assert_eq!(picture_band(NAL_RASL_R, true), None);
    assert_eq!(picture_band(NAL_TRAIL_R, true), Some(BAND_REFERENCE));
    // IRAP is the prediction root of a whole GOP: never carries slots when
    // the stream has inter pictures.
    assert_eq!(picture_band(NAL_IDR_W_RADL, true), None);
    assert_eq!(picture_band(21, true), None);

    // All-intra: nothing predicts from anything, so everything is band 0 --
    // that is the still-image case and the all-IDR video case.
    assert_eq!(picture_band(NAL_TRAIL_R, false), Some(BAND_NON_REFERENCE));
    assert_eq!(
        picture_band(NAL_IDR_W_RADL, false),
        Some(BAND_NON_REFERENCE)
    );
    assert_eq!(picture_band(NAL_TRAIL_N, false), Some(BAND_NON_REFERENCE));
}

/// Band order is the drift ladder: element 0..len(band0) all land in band 0,
/// so a 40-byte header and a small payload never touch a reference picture.
#[test]
fn band_positions_exhaust_the_drift_free_rung_first() {
    let seed = [3u8; 32];
    let bands = vec![0..10usize, 10..40];
    let positions = band_positions(&bands, 10, &seed);
    assert_eq!(positions.len(), 10);
    assert!(positions.iter().all(|p| *p < 10));
    // Every slot of the band is used exactly once (a permutation).
    let mut seen = positions.clone();
    seen.sort_unstable();
    assert_eq!(seen, (0..10).collect::<Vec<_>>());

    // Spilling into band 1 happens only after band 0 is exhausted.
    let wide = band_positions(&bands, 25, &seed);
    assert!(wide[..10].iter().all(|p| *p < 10));
    assert!(wide[10..].iter().all(|p| (10..40).contains(p)));
}

/// The body slot order must depend on the session `perm_seed`; a fixed
/// Weyl order would let an analyst reproduce it from the public build.
#[test]
fn band_positions_are_keyed_by_perm_seed() {
    let bands = vec![0..16usize, 16..40];
    let a = band_positions(&bands, 20, &[1u8; 32]);
    let b = band_positions(&bands, 20, &[2u8; 32]);
    assert_ne!(a, b, "different session seeds must reorder the slots");
    // Both remain valid per-band permutations.
    for (positions, band) in [(&a, &bands[0]), (&b, &bands[0])] {
        let mut prefix = positions[..16].to_vec();
        prefix.sort_unstable();
        assert_eq!(prefix, (0..16).collect::<Vec<_>>());
        assert!(positions[16..].iter().all(|p| (16..40).contains(p)));
        let _ = band;
    }
}

/// Element `i` must map to the same slot no matter how many elements are
/// requested -- the extractor reads the header with a short prefix and then
/// the whole message with a longer one.
#[test]
fn band_positions_are_prefix_stable() {
    let seed = [5u8; 32];
    let bands = vec![0..7usize, 7..23, 23..24];
    let full = band_positions(&bands, 24, &seed);
    for count in [1usize, 5, 7, 12, 23] {
        assert_eq!(band_positions(&bands, count, &seed), full[..count].to_vec());
    }
    // Empty bands (no slots recorded) must not shift the mapping.
    let with_empty = vec![0..0usize, 0..7, 7..7, 7..23];
    assert_eq!(band_positions(&with_empty, 12, &seed), full[..12].to_vec());
}

#[test]
fn non_reference_types_are_the_even_vcl_range() {
    for t in 0u8..=9 {
        assert_eq!(is_non_reference_vcl(t), t % 2 == 0, "nal_type {t}");
    }
    // 16..=21 (BLA/IDR/CRA) are all reference pictures.
    for t in 16u8..=21 {
        assert!(!is_non_reference_vcl(t), "nal_type {t} is an IRAP");
    }
}
