//! Library parameters and private-dialect profiles.
//!
//! M1 of `docs/library_api_practical_plan_20261020.md`: `LocalParams` (L class,
//! writer-only) and `StructureProfile` (P class, read/write must agree) threaded through
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

use strhide::errors::StrHideError;
use strhide::params::{CompressionStrategy, LocalParams, MagicPair};
use strhide::stego::params::StegoProfile;
use strhide::structure::StructureProfile;
use strhide::structure::{
    PayloadSource, ReadOptions, RestoreOptions, WriteOptions, inspect_carrier_with,
    read_carrier_with_dialect, remove_carrier_with_dialect, verify_carrier_with,
    write_carrier_with,
};

fn profile_with_secret(secret: &'static str) -> StructureProfile {
    StructureProfile::default().with_default_secret(secret)
}

fn profile_with_magic() -> StructureProfile {
    StructureProfile::default().with_magic(MagicPair {
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
    profile: &StructureProfile,
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
fn assert_unreadable(carrier: &Path, password: Option<&str>, profile: &StructureProfile) {
    match read_carrier_with_dialect(
        carrier,
        &ReadOptions {
            output_path: None,
            password,
            overwrite: false,
            ..Default::default()
        },
        profile,
    ) {
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
    let res = read_carrier_with_dialect(
        &stego,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
        &profile,
    )
    .unwrap();
    assert_eq!(res.data, b"hidden payload");

    // Official profile: the envelope is found (standard magics) but the header
    // mask and both keys derive from the other secret, so nothing decodes.
    assert_unreadable(&stego, None, &StructureProfile::default());

    // Inspect must report "nothing here" for a dialect it cannot open, not an
    // error: a private dialect is meant to be invisible (review B-06), and
    // `inspect_any`/`smart_extract` must be able to fall through to the content
    // domain instead of aborting.
    let inspected = inspect_carrier_with(&stego, None, &StructureProfile::default())
        .expect("inspect must not fail on a foreign private dialect");
    assert!(
        !inspected.has_hidden_data,
        "a foreign private dialect must not be reported as hidden data"
    );
    assert!(inspected.strategy.is_none());
    assert!(inspected.ube_offset.is_none());

    // A different private dialect is equally locked out.
    assert_unreadable(&stego, None, &profile_with_secret("another-dialect"));
    let inspected = inspect_carrier_with(&stego, None, &profile_with_secret("another-dialect"))
        .expect("inspect must not fail on a foreign private dialect");
    assert!(!inspected.has_hidden_data);

    // The carrier still restores bit-for-bit through the dialect.
    let restored = dir.join("restored.png");
    let removed = remove_carrier_with_dialect(
        &stego,
        &RestoreOptions {
            output_path: Some(&restored),
            password: None,
            backup: false,
            overwrite: false,
            ..Default::default()
        },
        &profile,
    )
    .unwrap();
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

    let res = read_carrier_with_dialect(
        &stego,
        &ReadOptions {
            output_path: None,
            password: Some("pw"),
            overwrite: false,
            ..Default::default()
        },
        &StructureProfile::default(),
    )
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
    assert_unreadable(&stego, None, &StructureProfile::default());
    let official = inspect_carrier_with(&stego, None, &StructureProfile::default()).unwrap();
    assert!(
        !official.has_hidden_data,
        "official inspect must not report a private-magic envelope"
    );

    // The dialect reader sees and decodes it.
    let mine = inspect_carrier_with(&stego, None, &profile).unwrap();
    assert!(mine.has_hidden_data);
    assert_eq!(
        read_carrier_with_dialect(
            &stego,
            &ReadOptions {
                output_path: None,
                password: None,
                overwrite: false,
                ..Default::default()
            },
            &profile
        )
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

    let profile = StructureProfile::default().with_stealth_domain(&b"acme-stealth-v1"[..]);
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
        read_carrier_with_dialect(
            &stego,
            &ReadOptions {
                output_path: None,
                password: Some("pw"),
                overwrite: false,
                ..Default::default()
            },
            &profile
        )
        .unwrap()
        .data,
        b"stealth payload"
    );

    // Correct password, official domain: the derived magic differs, so the
    // envelope is invisible rather than mis-decoded.
    assert_unreadable(&stego, Some("pw"), &StructureProfile::default());
}

#[test]
fn chunk_size_is_a_writer_only_knob() {
    let dir = scratch("local_chunk");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let payload = vec![0x5Au8; 5_000];

    let never = LocalParams::default().with_compression(CompressionStrategy::Never);
    let small = never.with_chunk_size(512);

    let baseline = dir.join("baseline.png");
    let base_size = write(
        &carrier,
        &baseline,
        &payload,
        None,
        &never,
        &StructureProfile::default(),
    );

    let chunked = dir.join("chunked.png");
    let small_size = write(
        &carrier,
        &chunked,
        &payload,
        None,
        &small,
        &StructureProfile::default(),
    );

    // 5000 bytes / 512 = 10 chunks instead of 1, i.e. +9 * 20 bytes of framing.
    assert_eq!(small_size, base_size + 9 * 20);

    // Both are read with the default LocalParams: the reader is never told the
    // chunk size, and does not need to be.
    for path in [&baseline, &chunked] {
        let res = read_carrier_with_dialect(
            path,
            &ReadOptions {
                output_path: None,
                password: None,
                overwrite: false,
                ..Default::default()
            },
            &StructureProfile::default(),
        )
        .unwrap();
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
    write(
        &carrier,
        &out,
        &payload,
        None,
        &never,
        &StructureProfile::default(),
    );
    let info = inspect_carrier_with(&out, None, &StructureProfile::default()).unwrap();
    assert_eq!(
        info.is_compressed,
        Some(false),
        "Never must leave FLAG_COMPRESSED clear"
    );

    // `Always` compresses even a payload that does not benefit; the reader only
    // follows FLAG_COMPRESSED and never learns the level.
    let always = LocalParams::default().with_compression(CompressionStrategy::Always { level: 1 });
    let out = dir.join("always.png");
    write(
        &carrier,
        &out,
        &payload,
        None,
        &always,
        &StructureProfile::default(),
    );
    let info = inspect_carrier_with(&out, None, &StructureProfile::default()).unwrap();
    assert_eq!(info.is_compressed, Some(true));
    assert_eq!(
        read_carrier_with_dialect(
            &out,
            &ReadOptions {
                output_path: None,
                password: None,
                overwrite: false,
                ..Default::default()
            },
            &StructureProfile::default()
        )
        .unwrap()
        .data,
        payload
    );
}

#[test]
fn large_incompressible_payload_is_stored_without_the_compressed_flag() {
    let dir = scratch("local_compress_probe_incompressible");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let payload = pseudo_random(2 * 1024 * 1024);

    let out = dir.join("out.png");
    write(
        &carrier,
        &out,
        &payload,
        None,
        &LocalParams::default(),
        &StructureProfile::default(),
    );

    let info = inspect_carrier_with(&out, None, &StructureProfile::default()).unwrap();
    assert_eq!(
        info.is_compressed,
        Some(false),
        "a payload whose sample does not beat the 2% rule must be stored raw"
    );
    let read = read_carrier_with_dialect(
        &out,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
        &StructureProfile::default(),
    )
    .unwrap();
    assert_eq!(read.data, payload);
}

#[test]
fn large_compressible_payload_is_still_deflated() {
    let dir = scratch("local_compress_probe_compressible");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let payload = vec![b'a'; 2 * 1024 * 1024];

    let out = dir.join("out.png");
    write(
        &carrier,
        &out,
        &payload,
        None,
        &LocalParams::default(),
        &StructureProfile::default(),
    );

    let info = inspect_carrier_with(&out, None, &StructureProfile::default()).unwrap();
    assert_eq!(
        info.is_compressed,
        Some(true),
        "a payload whose sample beats the 2% rule must still be deflated"
    );
    let read = read_carrier_with_dialect(
        &out,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
        &StructureProfile::default(),
    )
    .unwrap();
    assert_eq!(read.data, payload);
}

#[test]
fn compressibility_probe_sees_a_compressible_tail() {
    let dir = scratch("local_compress_probe_tail");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();

    // Random prefix, compressible suffix: a prefix-only probe would call this
    // incompressible, but the stratified sample includes the tail.
    let mut payload = pseudo_random(1024 * 1024);
    payload.extend_from_slice(&vec![b'b'; 1024 * 1024]);

    let out = dir.join("out.png");
    write(
        &carrier,
        &out,
        &payload,
        None,
        &LocalParams::default(),
        &StructureProfile::default(),
    );

    let info = inspect_carrier_with(&out, None, &StructureProfile::default()).unwrap();
    assert_eq!(info.is_compressed, Some(true));
    let read = read_carrier_with_dialect(
        &out,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
        &StructureProfile::default(),
    )
    .unwrap();
    assert_eq!(read.data, payload);
}

#[test]
fn compressed_envelopes_remain_readable_after_the_probe_gate() {
    let dir = scratch("local_compress_probe_legacy_read");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    // `Always` produces a compressed stream exactly as the pre-probe writer
    // did; the reader follows FLAG_COMPRESSED and never learns the decision.
    let payload = pseudo_random(2 * 1024 * 1024);

    let out = dir.join("out.png");
    write(
        &carrier,
        &out,
        &payload,
        None,
        &LocalParams::default().with_compression(CompressionStrategy::Always { level: 6 }),
        &StructureProfile::default(),
    );

    let info = inspect_carrier_with(&out, None, &StructureProfile::default()).unwrap();
    assert_eq!(info.is_compressed, Some(true));
    let read = read_carrier_with_dialect(
        &out,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
        &StructureProfile::default(),
    )
    .unwrap();
    assert_eq!(read.data, payload);
}

#[test]
fn tiny_payloads_keep_the_historical_compression_decision() {
    let dir = scratch("local_compress_probe_tiny");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();

    // Below COMPRESSION_PROBE_MIN_BYTES the full deflate pass runs as before:
    // incompressible stays raw, compressible is deflated.
    for (name, payload, expected) in [
        ("random.png", pseudo_random(1024), false),
        ("text.png", vec![b'a'; 1024], true),
    ] {
        let out = dir.join(name);
        write(
            &carrier,
            &out,
            &payload,
            None,
            &LocalParams::default(),
            &StructureProfile::default(),
        );
        let info = inspect_carrier_with(&out, None, &StructureProfile::default()).unwrap();
        assert_eq!(info.is_compressed, Some(expected), "{name}");
        let read = read_carrier_with_dialect(
            &out,
            &ReadOptions {
                output_path: None,
                password: None,
                overwrite: false,
                ..Default::default()
            },
            &StructureProfile::default(),
        )
        .unwrap();
        assert_eq!(read.data, payload, "{name}");
    }
}

#[test]
#[ignore = "writes a 64 MiB payload; run with the local_ suite"]
fn local_large_incompressible_payload_at_the_payload_limit_is_uncompressed() {
    const LIMIT: usize = 64 * 1024 * 1024;
    let dir = scratch("local_compress_probe_limit");
    let carrier = dir.join("c.zip");
    fs::write(&carrier, include_bytes!("../assets/small.zip")).unwrap();
    let payload = pseudo_random(LIMIT);

    let out = dir.join("out.zip");
    write(
        &carrier,
        &out,
        &payload,
        None,
        &LocalParams::default(),
        &StructureProfile::default(),
    );

    let info = inspect_carrier_with(&out, None, &StructureProfile::default()).unwrap();
    assert_eq!(info.is_compressed, Some(false));
    let read = read_carrier_with_dialect(
        &out,
        &ReadOptions {
            output_path: None,
            password: None,
            overwrite: false,
            ..Default::default()
        },
        &StructureProfile::default(),
    )
    .unwrap();
    assert_eq!(read.data, payload);
}

fn pseudo_random(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    while v.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.push((x >> 24) as u8);
    }
    v
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
        LocalParams::default().with_chunk_size(1),
        LocalParams::default().with_chunk_size(strhide::params::MIN_CHUNK_SIZE - 1),
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
            &StructureProfile::default(),
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
        &StructureProfile::default(),
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
        &StructureProfile::default(),
    )
    .unwrap();
    assert_eq!(
        read_carrier_with_dialect(
            &carrier,
            &ReadOptions {
                output_path: None,
                password: None,
                overwrite: false,
                ..Default::default()
            },
            &StructureProfile::default()
        )
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
    let official = verify_carrier_with(&stego, None, &StructureProfile::default()).unwrap();
    assert!(!official.level2_envelope.ok);
    assert!(!official.level3_crypto.ok);
}

// --------------------------------------------------------------------------- stego private format

const PRIVATE_CIPHER: strhide::stego::format::WireCipherProfile =
    strhide::stego::format::WireCipherProfile {
        domain_label: b"private-domain",
        hpos_label: b"private-hpos",
        enc_label: b"private-enc",
        perm_label: b"private-perm",
        stc_label: b"private-stc",
        default_suite: strhide::core::crypto::CipherSuiteId::Aes256Gcm,
    };

const PRIVATE_FORMAT: strhide::JpegFormatProfile = strhide::JpegFormatProfile {
    cover_digest_tag: b"private-cover-v1",
    cipher: &PRIVATE_CIPHER,
    sb_bytes: 44,
    sb_h: 8,
    sb_u: 2,
    ext_h: 8,
    ext_u: 4,
    grid_rule: strhide::GridRule::ALL_AC,
};

const PRIVATE_JPEG_PROFILE: StegoProfile = StegoProfile::new().with_jpeg_format(PRIVATE_FORMAT);
const SMALL_JPG: &[u8] = include_bytes!("../assets/small.jpg");
const PRIVATE_PAYLOAD: &[u8] = b"private-format-roundtrip";

#[test]
fn private_format_embed_extract_roundtrip() {
    use strhide::core::payload::Payload;
    use strhide::stego::{EmbedOptions, embed_carrier_with_dialect, extract_carrier_with_dialect};

    let options = EmbedOptions::default();
    let stego = embed_carrier_with_dialect(
        SMALL_JPG,
        &Payload::bytes(PRIVATE_PAYLOAD),
        &options,
        &PRIVATE_JPEG_PROFILE,
    )
    .expect("embed under private format");
    assert_ne!(stego, SMALL_JPG, "the carrier must change");

    let extracted =
        extract_carrier_with_dialect(&stego, &options.extract_options(), &PRIVATE_JPEG_PROFILE)
            .expect("extract under private format");
    assert_eq!(extracted, PRIVATE_PAYLOAD);
}

#[test]
fn private_format_probe_uses_private_geometry() {
    use strhide::stego::{ProbeOptions, probe_carrier_capacity_with_dialect};

    let options = ProbeOptions::default();
    let cap = probe_carrier_capacity_with_dialect(SMALL_JPG, &options, &PRIVATE_JPEG_PROFILE)
        .expect("probe under private format");
    assert!(
        cap.recommended_max_bytes > 0,
        "the probe must report capacity"
    );
    assert_eq!(PRIVATE_JPEG_PROFILE.jpeg_format(), &PRIVATE_FORMAT);
}

#[test]
fn official_profile_cannot_read_private_format() {
    use strhide::core::payload::Payload;
    use strhide::stego::{EmbedOptions, embed_carrier_with_dialect, extract_carrier_with_dialect};

    let options = EmbedOptions::default();
    let stego = embed_carrier_with_dialect(
        SMALL_JPG,
        &Payload::bytes(PRIVATE_PAYLOAD),
        &options,
        &PRIVATE_JPEG_PROFILE,
    )
    .expect("embed under private format");

    let official = StegoProfile::default();
    assert!(
        extract_carrier_with_dialect(&stego, &options.extract_options(), &official).is_err(),
        "an official profile must not read a private-format carrier"
    );
}

#[test]
fn private_format_is_a_non_official_dialect() {
    assert!(!PRIVATE_JPEG_PROFILE.is_official());
    assert!(StegoProfile::default().is_official());
}
