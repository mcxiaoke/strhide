//! Library parameters and private-dialect profiles.
//!
//! M1 of `docs/library_api_practical_plan_20261020.md`: `LocalParams` (L class,
//! writer-only) and `Profile` (P class, read/write must agree) threaded through
//! every engine entry point, with **zero** wire-format changes.
//!
//! The central claim under test is the *separation*, not just the round trip:
//!
//! - an L-class knob must never make an envelope unreadable, so every
//!   `LocalParams` variation is read back with `LocalParams::default()`;
//! - a P-class knob must make the envelope unreadable to anyone who does not
//!   have the same profile — including a reader that holds the correct password.

use crate::common::*;
use std::fs;
use std::path::Path;

use strhide::engine::{
    PayloadSource, WriteOptions, inspect_carrier_with, read_carrier_with_profile,
    remove_carrier_with, verify_carrier_with, write_carrier_with,
};
use strhide::errors::StrHideError;
use strhide::params::{CompressionStrategy, LocalParams, MagicPair, Profile};

fn profile_with_secret(secret: &'static str) -> Profile {
    Profile::default().with_default_secret(secret)
}

fn profile_with_magic() -> Profile {
    Profile::default().with_magic(MagicPair {
        header: *b"PRIVHDR1",
        trailer: *b"PRVT",
    })
}

/// Write `payload` from `carrier` into `out` under `local` + `profile`.
fn write(
    carrier: &Path,
    out: &Path,
    payload: &[u8],
    password: Option<&str>,
    local: &LocalParams,
    profile: &Profile,
) -> u64 {
    write_carrier_with(
        carrier,
        PayloadSource::Bytes(payload),
        &WriteOptions {
            output_path: Some(out),
            password,
            backup: false,
            ..WriteOptions::default()
        },
        local,
        profile,
    )
    .unwrap()
    .ube_size
}

/// Assert the read fails *and* yields no payload bytes.
///
/// The concrete error differs by path and must not be pinned: a private magic
/// or a stealth domain simply hides the envelope (`NoHiddenData`), while the
/// same magics with a different secret are found and then fail to decode
/// (`CorruptedData` / `Password`). What matters is that nothing comes out.
fn assert_unreadable(carrier: &Path, password: Option<&str>, profile: &Profile) {
    match read_carrier_with_profile(carrier, None, password, false, profile) {
        Ok(res) => panic!(
            "a mismatched profile must not decode anything, got {} bytes",
            res.data.len()
        ),
        Err(e) => assert!(
            matches!(
                e,
                StrHideError::NoHiddenData(_)
                    | StrHideError::CorruptedData(_)
                    | StrHideError::Password(_)
            ),
            "unexpected error for a mismatched profile: {e}"
        ),
    }
}

#[test]
fn private_default_secret_is_unreadable_with_the_official_profile() {
    let dir = scratch("profile_secret");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let stego = dir.join("stego.png");

    let profile = profile_with_secret("my-private-dialect");
    write(
        &carrier,
        &stego,
        b"hidden payload",
        None,
        &LocalParams::default(),
        &profile,
    );

    // Same profile: normal round trip.
    let res = read_carrier_with_profile(&stego, None, None, false, &profile).unwrap();
    assert_eq!(res.data, b"hidden payload");

    // Official profile: the envelope is found (standard magics) but the header
    // mask and both keys derive from the other secret, so nothing decodes.
    assert_unreadable(&stego, None, &Profile::default());

    // A different private dialect is equally locked out.
    assert_unreadable(&stego, None, &profile_with_secret("another-dialect"));

    // The carrier still restores bit-for-bit through the dialect.
    let restored = dir.join("restored.png");
    let removed = remove_carrier_with(&stego, Some(&restored), None, false, &profile).unwrap();
    assert!(removed.verified_identical);
    assert_eq!(fs::read(&restored).unwrap(), fs::read(&carrier).unwrap());
}

#[test]
fn explicit_password_still_wins_over_the_private_secret() {
    let dir = scratch("profile_pw");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let stego = dir.join("stego.png");

    // `default_secret` keys only the *no-password* mode; with a user password
    // the keys come from that password alone, so the official reader can open
    // the envelope. This is intended: the private secret must not silently
    // change the meaning of a user password.
    write(
        &carrier,
        &stego,
        b"pw payload",
        Some("pw"),
        &LocalParams::default(),
        &profile_with_secret("my-private-dialect"),
    );

    let res = read_carrier_with_profile(&stego, None, Some("pw"), false, &Profile::default())
        .expect("explicit password must not depend on the profile's default secret");
    assert_eq!(res.data, b"pw payload");
}

#[test]
fn custom_magic_is_invisible_to_the_official_reader() {
    let dir = scratch("profile_magic");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let stego = dir.join("stego.png");

    let profile = profile_with_magic();
    write(
        &carrier,
        &stego,
        b"magic payload",
        None,
        &LocalParams::default(),
        &profile,
    );

    // `locate` searches for the dialect's own trailer magic, so the official
    // reader does not even see an envelope.
    assert_unreadable(&stego, None, &Profile::default());
    let official = inspect_carrier_with(&stego, None, &Profile::default()).unwrap();
    assert!(
        !official.has_hidden_data,
        "official inspect must not report a private-magic envelope"
    );

    // The dialect reader sees and decodes it.
    let mine = inspect_carrier_with(&stego, None, &profile).unwrap();
    assert!(mine.has_hidden_data);
    assert_eq!(
        read_carrier_with_profile(&stego, None, None, false, &profile)
            .unwrap()
            .data,
        b"magic payload"
    );
}

#[test]
fn custom_stealth_domain_changes_the_derived_magic() {
    let dir = scratch("profile_stealth");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let stego = dir.join("stego.png");

    let profile = Profile::default().with_stealth_domain(&b"acme-stealth-v1"[..]);
    write_carrier_with(
        &carrier,
        PayloadSource::Bytes(b"stealth payload"),
        &WriteOptions {
            output_path: Some(&stego),
            password: Some("pw"),
            stealth: true,
            backup: false,
            ..WriteOptions::default()
        },
        &LocalParams::default(),
        &profile,
    )
    .unwrap();

    // Correct password, same domain: readable.
    assert_eq!(
        read_carrier_with_profile(&stego, None, Some("pw"), false, &profile)
            .unwrap()
            .data,
        b"stealth payload"
    );

    // Correct password, official domain: the derived magic differs, so the
    // envelope is invisible rather than mis-decoded.
    assert_unreadable(&stego, Some("pw"), &Profile::default());
}

#[test]
fn chunk_size_is_a_writer_only_knob() {
    let dir = scratch("local_chunk");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let payload = vec![0x5Au8; 5_000];

    let never = LocalParams::default().with_compression(CompressionStrategy::Never);
    let small = never.clone().with_chunk_size(512);

    let baseline = dir.join("baseline.png");
    let base_size = write(
        &carrier,
        &baseline,
        &payload,
        None,
        &never,
        &Profile::default(),
    );

    let chunked = dir.join("chunked.png");
    let small_size = write(
        &carrier,
        &chunked,
        &payload,
        None,
        &small,
        &Profile::default(),
    );

    // 5000 bytes / 512 = 10 chunks instead of 1, i.e. +9 * 20 bytes of framing.
    assert_eq!(small_size, base_size + 9 * 20);

    // Both are read with the default LocalParams: the reader is never told the
    // chunk size, and does not need to be.
    for path in [&baseline, &chunked] {
        let res = read_carrier_with_profile(path, None, None, false, &Profile::default()).unwrap();
        assert_eq!(res.data, payload);
    }
}

#[test]
fn compression_strategy_is_a_writer_only_knob() {
    let dir = scratch("local_compress");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let payload = vec![b'a'; 4_096];

    let never = LocalParams::default().with_compression(CompressionStrategy::Never);
    let out = dir.join("never.png");
    write(&carrier, &out, &payload, None, &never, &Profile::default());
    let info = inspect_carrier_with(&out, None, &Profile::default()).unwrap();
    assert_eq!(
        info.is_compressed,
        Some(false),
        "Never must leave FLAG_COMPRESSED clear"
    );

    // `Always` compresses even a payload that does not benefit; the reader only
    // follows FLAG_COMPRESSED and never learns the level.
    let always = LocalParams::default().with_compression(CompressionStrategy::Always { level: 1 });
    let out = dir.join("always.png");
    write(&carrier, &out, &payload, None, &always, &Profile::default());
    let info = inspect_carrier_with(&out, None, &Profile::default()).unwrap();
    assert_eq!(info.is_compressed, Some(true));
    assert_eq!(
        read_carrier_with_profile(&out, None, None, false, &Profile::default())
            .unwrap()
            .data,
        payload
    );
}

#[test]
fn invalid_local_params_fail_before_touching_the_carrier() {
    let dir = scratch("local_invalid");
    let carrier = dir.join("c.png");
    let original = make_png();
    fs::write(&carrier, &original).unwrap();
    let payload = b"x";

    for bad in [
        LocalParams::default().with_chunk_size(0),
        LocalParams::default().with_chunk_size(strhide::crypto::MAX_CHUNK_SIZE + 1),
        LocalParams::default().with_compression(CompressionStrategy::Always { level: 10 }),
    ] {
        let err = write_carrier_with(
            &carrier,
            PayloadSource::Bytes(payload),
            &WriteOptions {
                backup: false,
                ..WriteOptions::default()
            },
            &bad,
            &Profile::default(),
        )
        .unwrap_err();
        assert!(matches!(err, StrHideError::General(_)), "{err}");
        assert_eq!(
            fs::read(&carrier).unwrap(),
            original,
            "an invalid LocalParams must be rejected before the carrier is written"
        );
    }
}

#[test]
fn rejection_policy_governs_filename_checks() {
    let dir = scratch("local_rejection");
    // Valid PNG content behind an unsupported extension: only the filename
    // policy refuses it.
    let carrier = dir.join("carrier.apk");
    fs::write(&carrier, make_png()).unwrap();

    let err = write_carrier_with(
        &carrier,
        PayloadSource::Bytes(b"x"),
        &WriteOptions {
            backup: false,
            ..WriteOptions::default()
        },
        &LocalParams::default(),
        &Profile::default(),
    )
    .unwrap_err();
    assert!(matches!(err, StrHideError::Rejection(_)), "{err}");

    let skip = LocalParams::default().with_rejection(strhide::params::RejectionPolicy::Skip);
    write_carrier_with(
        &carrier,
        PayloadSource::Bytes(b"x"),
        &WriteOptions {
            backup: false,
            ..WriteOptions::default()
        },
        &skip,
        &Profile::default(),
    )
    .unwrap();
    assert_eq!(
        read_carrier_with_profile(&carrier, None, None, false, &Profile::default())
            .unwrap()
            .data,
        b"x"
    );
}

#[test]
fn verify_accepts_the_profile() {
    let dir = scratch("profile_verify");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let stego = dir.join("stego.png");

    let profile = profile_with_secret("verify-dialect");
    write(
        &carrier,
        &stego,
        b"verify payload",
        None,
        &LocalParams::default(),
        &profile,
    );

    let verified = verify_carrier_with(&stego, None, &profile).unwrap();
    assert!(verified.level1_host.ok, "{}", verified.level1_host.detail);
    assert!(
        verified.level2_envelope.ok,
        "{}",
        verified.level2_envelope.detail
    );
    assert!(
        verified.level3_crypto.ok,
        "{}",
        verified.level3_crypto.detail
    );

    // Without the profile, level 2 cannot even parse the header.
    let official = verify_carrier_with(&stego, None, &Profile::default()).unwrap();
    assert!(!official.level2_envelope.ok);
    assert!(!official.level3_crypto.ok);
}
