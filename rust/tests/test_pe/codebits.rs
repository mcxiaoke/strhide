//! Integration tests for the `pe_codebits` strategy (design doc v1.0, §14).
//!
//! Carriers are synthetic PE images built in-memory: a `.text` section filled
//! with a repeating pattern of instrumentable instructions (semantic pairs +
//! commutative TEST), plus header/section-tail zero padding for the restore
//! diff. This keeps the suite hermetic (no dependency on host binaries) while
//! exercising the real engine flow: write -> read -> inspect -> verify ->
//! remove, with byte-exact restore assertions.

use crate::common::{make_pe_custom as make_pe, scratch};
use std::fs;
use std::path::Path;

use strhide::engine::{
    PayloadSource, WriteOptions, inspect_carrier, read_carrier, remove_carrier, verify_carrier,
    write_carrier,
};
use strhide::errors::StrHideError;

// --------------------------------------------------------------------------- helpers

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::new()
        .chain_update(data)
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn write_opts<'a>(out: &'a Path, strategy: &'a str) -> WriteOptions<'a> {
    WriteOptions {
        output_path: Some(out),
        strategy,
        backup: false,
        ..Default::default()
    }
}

// --------------------------------------------------------------------------- tests

/// T4: auto selects pe_codebits, the full flow round-trips, the carrier size
/// is unchanged, and remove restores the carrier byte-for-byte.
#[test]
fn codebits_auto_roundtrip_and_byte_exact_restore() {
    let dir = scratch("auto");
    let carrier = dir.join("app.exe");
    let original = make_pe(0x8664, 0x20B, 0x3000, false); // ~2.4k positions
    fs::write(&carrier, &original).unwrap();
    let orig_sha = sha256_hex(&original);

    let out = dir.join("app.steg.exe");
    let result = write_carrier(
        &carrier,
        PayloadSource::Text("meet at the old bridge, 9pm"),
        &write_opts(&out, "auto"),
    )
    .expect("write");
    assert_eq!(
        result.strategy, "pe_codebits",
        "auto must pick pe_codebits: {:?}",
        result.strategy_note
    );
    assert_eq!(
        fs::metadata(&out).unwrap().len(),
        original.len() as u64,
        "pe_codebits must not change the file size"
    );

    // read back
    let read = read_carrier(&out, None, None).expect("read");
    assert_eq!(read.data, b"meet at the old bridge, 9pm");

    // inspect + verify
    let ins = inspect_carrier(&out, None).expect("inspect");
    assert_eq!(ins.strategy.as_deref(), Some("pe_codebits"));
    assert!(ins.has_hidden_data);
    let v = verify_carrier(&out, None).expect("verify");
    assert!(v.level1_host.ok, "L1: {}", v.level1_host.detail);
    assert!(v.level2_envelope.ok, "L2: {}", v.level2_envelope.detail);
    assert!(v.level3_crypto.ok, "L3: {}", v.level3_crypto.detail);

    // remove -> byte-exact restore
    let restored = dir.join("app.restored.exe");
    let rem = remove_carrier(&out, Some(&restored), None, false).expect("remove");
    assert!(rem.verified_identical);
    let restored_bytes = fs::read(&restored).unwrap();
    assert_eq!(restored_bytes.len(), original.len());
    assert_eq!(
        sha256_hex(&restored_bytes),
        orig_sha,
        "restore must be bit-exact"
    );

    // idempotency: a second write on the restored file works again
    let out2 = dir.join("app2.steg.exe");
    let r2 = write_carrier(
        &restored,
        PayloadSource::Text("again"),
        &write_opts(&out2, "auto"),
    )
    .expect("re-write after remove");
    assert_eq!(r2.strategy, "pe_codebits");
}

/// T6: encrypted payload round-trips through the bit channel.
#[test]
fn codebits_encrypted_roundtrip() {
    let dir = scratch("enc");
    let carrier = dir.join("enc.exe");
    fs::write(&carrier, make_pe(0x8664, 0x20B, 0x3000, false)).unwrap();

    let out = dir.join("enc.steg.exe");
    let opts = WriteOptions {
        output_path: Some(&out),
        strategy: "pe_codebits",
        password: Some("correct horse battery staple"),
        backup: false,
        ..Default::default()
    };
    write_carrier(&carrier, PayloadSource::Text("encrypted secret"), &opts).expect("write");

    // Wrong password must fail cleanly.
    assert!(read_carrier(&out, None, Some("wrong pw")).is_err());
    // Right password round-trips.
    let read = read_carrier(&out, None, Some("correct horse battery staple")).expect("read");
    assert_eq!(read.data, b"encrypted secret");

    let restored = dir.join("enc.restored.exe");
    let rem = remove_carrier(
        &out,
        Some(&restored),
        Some("correct horse battery staple"),
        false,
    )
    .expect("remove");
    assert!(rem.verified_identical);
}

/// T6: stealth mode — the channel is invisible without the password and fully
/// functional with it.
#[test]
fn codebits_stealth_denies_without_password() {
    let dir = scratch("stealth");
    let carrier = dir.join("s.exe");
    let original = make_pe(0x8664, 0x20B, 0x3000, false);
    fs::write(&carrier, &original).unwrap();

    let out = dir.join("s.steg.exe");
    let opts = WriteOptions {
        output_path: Some(&out),
        strategy: "pe_codebits",
        password: Some("stealth pw"),
        stealth: true,
        backup: false,
        ..Default::default()
    };
    write_carrier(&carrier, PayloadSource::Text("invisible"), &opts).expect("write");

    // No password: nothing to find (plausible deniability).
    let err = read_carrier(&out, None, None).unwrap_err();
    assert!(
        matches!(err, strhide::errors::StrHideError::NoHiddenData(_)),
        "expected NoHiddenData, got {err:?}"
    );
    // Wrong password: same.
    assert!(read_carrier(&out, None, Some("nope")).is_err());

    // Right password: full round-trip and byte-exact restore.
    let read = read_carrier(&out, None, Some("stealth pw")).expect("read");
    assert_eq!(read.data, b"invisible");
    let restored = dir.join("s.restored.exe");
    let rem = remove_carrier(&out, Some(&restored), Some("stealth pw"), false).expect("remove");
    assert!(rem.verified_identical);
    assert_eq!(
        sha256_hex(&fs::read(&restored).unwrap()),
        sha256_hex(&original)
    );
}

/// T8: a `.text` too small for the channel *and* zero padding makes auto fall
/// back to pe_overlay, which still round-trips normally.
#[test]
fn auto_falls_back_to_overlay_on_tiny_text() {
    let dir = scratch("fallback");
    let carrier = dir.join("tiny.exe");
    // Tight layout (.text starts right after the section table, raw size ==
    // virtual size) so neither pe_codebits nor pe_slack has a zero run, and
    // `.text` is too small for the instruction channel.
    let original = make_pe(0x8664, 0x20B, 0x200, true);
    fs::write(&carrier, &original).unwrap();
    let orig_sha = sha256_hex(&original);

    let out = dir.join("tiny.steg.exe");
    let result = write_carrier(
        &carrier,
        PayloadSource::Text("hi"),
        &write_opts(&out, "auto"),
    )
    .expect("write");
    assert_eq!(
        result.strategy, "pe_overlay",
        "a slack-free tiny .text must fall back to overlay"
    );

    let read = read_carrier(&out, None, None).expect("read");
    assert_eq!(read.data, b"hi");
    let restored = dir.join("tiny.restored.exe");
    let rem = remove_carrier(&out, Some(&restored), None, false).expect("remove");
    assert!(rem.verified_identical);
    assert_eq!(sha256_hex(&fs::read(&restored).unwrap()), orig_sha);
}

/// T8: explicitly requesting pe_codebits on an incapable carrier is a hard
/// error (no silent downgrade).
#[test]
fn explicit_codebits_rejects_incapable_carriers() {
    let dir = scratch("reject");

    // Too little capacity.
    let tiny = dir.join("tiny2.exe");
    fs::write(&tiny, make_pe(0x8664, 0x20B, 0x40, false)).unwrap();
    let out = dir.join("tiny2.steg.exe");
    let err = write_carrier(
        &tiny,
        PayloadSource::Text("hi"),
        &write_opts(&out, "pe_codebits"),
    )
    .unwrap_err();
    assert!(
        matches!(err, strhide::errors::StrHideError::UnsupportedFormat(_)),
        "expected UnsupportedFormat, got {err:?}"
    );

    // Enough capacity but no zero-value slack run (tight layout).
    let tight = dir.join("tight.exe");
    fs::write(&tight, make_pe(0x8664, 0x20B, 0x3000, true)).unwrap();
    let out2 = dir.join("tight.steg.exe");
    let err2 = write_carrier(
        &tight,
        PayloadSource::Text("hi"),
        &write_opts(&out2, "pe_codebits"),
    )
    .unwrap_err();
    assert!(
        matches!(err2, strhide::errors::StrHideError::UnsupportedFormat(_)),
        "expected UnsupportedFormat, got {err2:?}"
    );
}

/// T8: a second injection on a channel carrier is refused.
#[test]
fn double_write_refused() {
    let dir = scratch("double");
    let carrier = dir.join("d.exe");
    fs::write(&carrier, make_pe(0x8664, 0x20B, 0x3000, false)).unwrap();

    let out = dir.join("d.steg.exe");
    write_carrier(
        &carrier,
        PayloadSource::Text("first"),
        &write_opts(&out, "pe_codebits"),
    )
    .expect("first write");

    let out2 = dir.join("d.steg2.exe");
    assert!(
        write_carrier(
            &out,
            PayloadSource::Text("second"),
            &write_opts(&out2, "auto")
        )
        .is_err(),
        "writing over an existing envelope must be refused"
    );
}

/// T9: corrupting a byte inside the channel region must fail cleanly (never
/// silently produce garbage or a wrong restore).
#[test]
fn corrupted_text_fails_cleanly() {
    let dir = scratch("corrupt");
    let carrier = dir.join("c.exe");
    fs::write(&carrier, make_pe(0x8664, 0x20B, 0x3000, false)).unwrap();

    let out = dir.join("c.steg.exe");
    write_carrier(
        &carrier,
        PayloadSource::Text("do not tamper"),
        &write_opts(&out, "pe_codebits"),
    )
    .expect("write");

    // Flip a byte well inside the .text channel region (offset 0x400 + 0x100).
    let mut bytes = fs::read(&out).unwrap();
    bytes[0x400 + 0x100] ^= 0xFF;
    let tampered = dir.join("c.tampered.exe");
    fs::write(&tampered, &bytes).unwrap();

    assert!(
        read_carrier(&tampered, None, None).is_err(),
        "read must fail on a tampered channel"
    );
    let restored = dir.join("c.tampered.restored.exe");
    assert!(
        remove_carrier(&tampered, Some(&restored), None, false).is_err(),
        "remove must fail (or refuse) on a tampered channel"
    );
}

/// T4: the 32-bit (PE32) path round-trips as well.
#[test]
fn codebits_32bit_pe_roundtrip() {
    let dir = scratch("pe32");
    let carrier = dir.join("x32.exe");
    let original = make_pe(0x14C, 0x10B, 0x3000, false);
    fs::write(&carrier, &original).unwrap();
    let orig_sha = sha256_hex(&original);

    let out = dir.join("x32.steg.exe");
    let result = write_carrier(
        &carrier,
        PayloadSource::Text("thirty-two bits"),
        &write_opts(&out, "auto"),
    )
    .expect("write");
    assert_eq!(result.strategy, "pe_codebits");
    assert_eq!(fs::metadata(&out).unwrap().len(), original.len() as u64);

    let read = read_carrier(&out, None, None).expect("read");
    assert_eq!(read.data, b"thirty-two bits");
    let restored = dir.join("x32.restored.exe");
    let rem = remove_carrier(&out, Some(&restored), None, false).expect("remove");
    assert!(rem.verified_identical);
    assert_eq!(sha256_hex(&fs::read(&restored).unwrap()), orig_sha);
}

/// Guard: the strategy registry knows pe_codebits (id 8) and all registered entries roundtrip.
#[test]
fn strategy_registry_roundtrip() {
    use strhide::envelope::MAX_KNOWN_STRATEGY_ID;
    use strhide::router::{STRATEGY_REGISTRY, id_to_strategy, strategy_to_id};

    assert_eq!(strategy_to_id("pe_codebits").unwrap(), 8);
    assert_eq!(id_to_strategy(8), "pe_codebits");

    let mut max_id = 0u8;
    for &(name, id) in STRATEGY_REGISTRY {
        assert_eq!(strategy_to_id(name).unwrap(), id);
        assert_eq!(id_to_strategy(id), name);
        if id > max_id {
            max_id = id;
        }
    }
    assert!(
        MAX_KNOWN_STRATEGY_ID >= max_id,
        "MAX_KNOWN_STRATEGY_ID ({MAX_KNOWN_STRATEGY_ID}) must be >= maximum registered id ({max_id})"
    );
    assert_eq!(id_to_strategy(255), "unknown");
    assert!(strategy_to_id("non_existent_strategy").is_err());
}

/// Unrecognized files must be rejected outright (no silent EOF fallback):
/// appending an envelope to an arbitrary file can corrupt it.
#[test]
fn unrecognized_carriers_are_rejected() {
    let dir = scratch("reject_unknown");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "generic.bin",
            b"just some generic host bytes, not a PE at all".to_vec(),
        ),
        ("empty.bin", Vec::new()),
        (
            "text.txt",
            b"plain text file
with two lines
"
            .to_vec(),
        ),
        (
            "gzip.gz",
            vec![0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03],
        ),
        (
            "elf.bin",
            vec![0x7F, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00],
        ),
    ];
    for (name, bytes) in cases {
        let carrier = dir.join(name);
        fs::write(&carrier, &bytes).unwrap();
        let out = dir.join(format!("{name}.steg"));

        let write_err = write_carrier(
            &carrier,
            PayloadSource::Text("x"),
            &write_opts(&out, "auto"),
        )
        .unwrap_err();
        assert!(
            matches!(write_err, StrHideError::UnsupportedFormat(_)),
            "{name}: write should reject, got {write_err:?}"
        );
        assert!(
            write_err.to_string().contains("not a supported carrier"),
            "{name}: {write_err}"
        );

        // Explicit eof must not bypass the format check either.
        let eof_err = write_carrier(&carrier, PayloadSource::Text("x"), &write_opts(&out, "eof"))
            .unwrap_err();
        assert!(
            matches!(eof_err, StrHideError::UnsupportedFormat(_)),
            "{name}: explicit eof should still reject, got {eof_err:?}"
        );

        assert!(
            matches!(
                read_carrier(&carrier, None, None).unwrap_err(),
                StrHideError::UnsupportedFormat(_)
            ),
            "{name}: read should reject"
        );
        assert!(
            matches!(
                remove_carrier(&carrier, Some(&out), None, false).unwrap_err(),
                StrHideError::UnsupportedFormat(_)
            ),
            "{name}: remove should reject"
        );
        assert!(
            matches!(
                inspect_carrier(&carrier, None).unwrap_err(),
                StrHideError::UnsupportedFormat(_)
            ),
            "{name}: inspect should reject"
        );
        assert!(
            matches!(
                verify_carrier(&carrier, None).unwrap_err(),
                StrHideError::UnsupportedFormat(_)
            ),
            "{name}: verify should reject"
        );

        // The carrier must be left untouched.
        assert_eq!(
            fs::read(&carrier).unwrap(),
            bytes,
            "{name}: carrier modified!"
        );
    }
}

/// The `eof` *strategy* still works on supported formats (only the format
/// catch-all was removed; adapters keep delegating eof to EofAdapter).
#[test]
fn eof_strategy_still_works_on_supported_formats() {
    let dir = scratch("eof_strategy");
    let carrier = dir.join("c.png");
    let original = include_bytes!("../assets/minimal.png").to_vec();
    fs::write(&carrier, &original).unwrap();

    let out = dir.join("c.steg.png");
    let result = write_carrier(
        &carrier,
        PayloadSource::Text("eof on png"),
        &write_opts(&out, "eof"),
    )
    .expect("eof strategy on a supported carrier");
    assert_eq!(result.strategy, "eof");
    assert_eq!(result.format, "PNG");
    assert!(fs::metadata(&out).unwrap().len() > original.len() as u64);

    let read = read_carrier(&out, None, None).expect("read");
    assert_eq!(read.data, b"eof on png");
    let restored = dir.join("c.restored.png");
    let rem = remove_carrier(&out, Some(&restored), None, false).expect("remove");
    assert!(rem.verified_identical);
    assert_eq!(fs::read(&restored).unwrap(), original);
}

/// Sanity: helpers agree on the carrier shape the tests rely on.
#[test]
fn synthetic_carrier_shape() {
    let img = make_pe(0x8664, 0x20B, 0x3000, false);
    assert!(img.len() > 0x1F00);
    // Header padding [sec_table_end, 0x400) must exist and be zero.
    assert!(img[0x188 + 40..0x400].iter().all(|&b| b == 0));
    // .text starts at 0x400 with the instrumentable pattern.
    assert_eq!(&img[0x400..0x400 + 4], &[0x89, 0xD8, 0x89, 0xCA]);
}

// --------------------------------------------------------------------------- capacity reporting

/// `inspect` reports an exact `pe_codebits` capacity for a capable carrier and
/// keeps the strategies in recommended priority order.
#[test]
fn inspect_reports_exact_codebits_capacity() {
    let dir = scratch("capacity_pe");
    let carrier = dir.join("cap.exe");
    fs::write(&carrier, make_pe(0x8664, 0x20B, 0x3000, false)).unwrap();

    let res = inspect_carrier(&carrier, None).expect("inspect");
    assert_eq!(res.format, "PE");
    assert!(!res.has_hidden_data);

    assert_eq!(
        res.strategies
            .iter()
            .map(|c| c.strategy.as_str())
            .collect::<Vec<_>>(),
        vec!["pe_codebits", "pe_slack", "pe_overlay", "eof"],
        "priority order must match supported_strategies"
    );
    let codebits = &res.strategies[0];
    assert!(codebits.available);
    let cap = codebits.capacity_bytes.expect("measured capacity");
    assert!(
        cap >= 136,
        "capable carrier must hold at least a bare envelope"
    );
    assert!(codebits.limit.contains("file size unchanged"));

    // The reported bound must admit an actual write: a short payload goes
    // through pe_codebits and its envelope stays inside the reported capacity.
    let out = dir.join("cap.steg.exe");
    let written = write_carrier(
        &carrier,
        PayloadSource::Text("fits"),
        &write_opts(&out, "auto"),
    )
    .expect("write");
    assert_eq!(written.strategy, "pe_codebits");
    assert!(
        written.ube_size <= cap,
        "envelope {} B exceeded reported capacity {} B",
        written.ube_size,
        cap
    );
}

/// A PE whose `.text` is too small (and has no usable slack) reports
/// `pe_codebits` as unavailable, and the auto preference falls to the first
/// available strategy (`pe_overlay`).
#[test]
fn inspect_marks_codebits_unavailable_on_tiny_text() {
    let dir = scratch("capacity_tiny");
    let carrier = dir.join("tiny.exe");
    // Tight layout: no header padding, no section-tail padding.
    fs::write(&carrier, make_pe(0x8664, 0x20B, 0x200, true)).unwrap();

    let res = inspect_carrier(&carrier, None).expect("inspect");
    let codebits = &res.strategies[0];
    assert_eq!(codebits.strategy, "pe_codebits");
    assert!(!codebits.available, "tiny .text cannot host a channel");
    assert!(
        codebits.capacity_bytes.is_some(),
        "capacity is still reported"
    );

    let slack = res
        .strategies
        .iter()
        .find(|c| c.strategy == "pe_slack")
        .expect("pe_slack is listed");
    assert_eq!(slack.capacity_bytes, Some(0), "no padding to measure");
    assert!(!slack.available);

    let first_available = res.strategies.iter().find(|c| c.available).unwrap();
    assert_eq!(first_available.strategy, "pe_overlay");
}

/// Static capacities of formats with fixed limits survive without a carrier,
/// and the JSON schema exposes the `strategies` array.
#[test]
fn inspect_reports_png_capacity_and_json_schema() {
    let dir = scratch("capacity_png");
    let carrier = dir.join("c.png");
    fs::write(&carrier, include_bytes!("../assets/minimal.png")).unwrap();

    let res = inspect_carrier(&carrier, None).expect("inspect");
    assert_eq!(res.format, "PNG");
    assert_eq!(res.strategies[0].strategy, "chunk");
    assert_eq!(res.strategies[0].capacity_bytes, Some(0x7FFF_FFFF));
    assert!(res.strategies[0].available);

    let json = serde_json::to_value(&res).expect("serialize");
    assert!(json.get("strategies").is_some());
    assert!(json.get("supported_strategies").is_none());
    assert_eq!(json["strategies"][0]["capacity_bytes"], 0x7FFF_FFFFu64);
}

/// The static `list` table is generated from the adapters, not hard-coded:
/// every registered format must report at least one strategy with a non-empty
/// limit, and carrier-dependent strategies must not claim an exact number.
#[test]
fn static_capacity_table_covers_all_adapters() {
    let mut formats = Vec::new();
    for adapter in strhide::router::ADAPTERS {
        let name = adapter.format_name();
        formats.push(name);
        let caps = adapter.strategy_capacities(None);
        assert!(!caps.is_empty(), "{name} must list at least one strategy");
        assert_eq!(
            caps.iter().map(|c| c.strategy.as_str()).collect::<Vec<_>>(),
            adapter.supported_strategies(),
            "{name}: capacity order must match supported_strategies"
        );
        for c in caps {
            assert!(!c.limit.is_empty(), "{name}/{}: empty limit", c.strategy);
            assert!(
                c.available,
                "{name}/{}: static mode must be available",
                c.strategy
            );
            if c.limit.starts_with("carrier-dependent") {
                assert!(
                    c.capacity_bytes.is_none(),
                    "{name}/{}: carrier-dependent limit must not carry a number",
                    c.strategy
                );
            }
        }
    }
    let expected_names: Vec<&str> = strhide::router::ADAPTERS
        .iter()
        .map(|a| a.format_name())
        .collect();
    for expected in &expected_names {
        assert!(formats.contains(expected), "missing format {expected}");
    }
    // Unrecognized files are not a format: no catch-all adapter may appear.
    assert!(
        !formats.contains(&"GENERIC"),
        "GENERIC must not be registered"
    );
}

/// Compact-metadata regression (2026-10-18): a carrier whose `.text` only holds
/// ~238 bytes of channel was unusable while the envelope carried a 137-byte JSON
/// metadata block (310-byte encrypted envelope). The 46-byte compact block
/// (219-byte encrypted envelope) makes exactly this band usable, so the test
/// pins both the reported capacity and the end-to-end flow.
#[test]
fn compact_metadata_makes_marginal_carriers_usable() {
    let dir = scratch("compact_marginal");
    let original = make_pe(0x8664, 0x20B, 0x1A00, false);
    let carrier = dir.join("marginal.exe");
    fs::write(&carrier, &original).unwrap();

    let report = inspect_carrier(&carrier, None).expect("inspect");
    let cap = report
        .strategies
        .iter()
        .find(|c| c.strategy == "pe_codebits")
        .and_then(|c| c.capacity_bytes)
        .expect("capacity");
    assert!(
        (219..310).contains(&cap),
        "capacity {cap} must sit between the compact (219) and JSON (310) envelope sizes"
    );

    let out = dir.join("marginal.steg.exe");
    let opts = WriteOptions {
        output_path: Some(&out),
        strategy: "pe_codebits",
        password: Some("pw"),
        backup: false,
        ..Default::default()
    };
    let res = write_carrier(&carrier, PayloadSource::Text("hi"), &opts).expect("write must fit");
    assert!(
        res.ube_size <= cap as u64,
        "envelope {} exceeds capacity {cap}",
        res.ube_size
    );
    assert!(res.ube_size < 310);
    assert_eq!(
        fs::metadata(&out).unwrap().len(),
        fs::metadata(&carrier).unwrap().len()
    );

    let read = read_carrier(&out, None, Some("pw")).expect("read");
    assert_eq!(read.data, b"hi");

    let restored = dir.join("marginal.restored.exe");
    remove_carrier(&out, Some(&restored), Some("pw"), false).expect("remove");
    assert_eq!(fs::read(&restored).unwrap(), original);
}

#[test]
fn codebits_channel_header_keystream_masking_verified() {
    let dir = scratch("header_masking");
    let original = make_pe(0x8664, 0x20B, 0x2000, false);
    let carrier = dir.join("masked_sample.exe");
    fs::write(&carrier, &original).unwrap();

    let out = dir.join("masked_sample.steg.exe");
    let opts = WriteOptions {
        output_path: Some(&out),
        strategy: "pe_codebits",
        backup: false,
        ..Default::default()
    };
    write_carrier(
        &carrier,
        PayloadSource::Text("secret codebits payload"),
        &opts,
    )
    .expect("write must succeed");

    // Inspect the generated carrier at the codebits bitstream layer
    let steg_data = fs::read(&out).unwrap();
    let layout = strhide::adapters::pe_codebits::pe_code_layout(&steg_data).expect("pe layout");
    let text = &steg_data
        [layout.text_offset as usize..(layout.text_offset + layout.text_scan_len) as usize];
    let prof = strhide::adapters::pe_codebits::profile(text, layout.bitness);

    // Extract the 112 bits (14 bytes) of ChannelHeader directly from the code positions
    let mut header_bytes = Vec::new();
    for chunk in prof
        .iter()
        .take(112)
        .map(|p| p.bit)
        .collect::<Vec<_>>()
        .chunks(8)
    {
        let mut b = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit {
                b |= 1 << (7 - i);
            }
        }
        header_bytes.push(b);
    }
    assert_eq!(header_bytes.len(), 14);

    // 1. Magic must match CHANNEL_MAGIC
    let magic: [u8; 4] = header_bytes[0..4].try_into().unwrap();
    assert_eq!(magic, strhide::adapters::pe_codebits::CHANNEL_MAGIC);

    // 2. Version byte at index 4 must be keystream-masked (NOT raw 0x01)
    let mask = strhide::crypto::derive_channel_header_mask(&magic);
    assert_ne!(
        header_bytes[4],
        strhide::adapters::pe_codebits::CHANNEL_VERSION
    );
    assert_eq!(
        header_bytes[4] ^ mask[0],
        strhide::adapters::pe_codebits::CHANNEL_VERSION
    );

    // 3. Flags byte at index 5 must unmask to 0
    assert_eq!(header_bytes[5] ^ mask[1], 0);

    // 4. Engine lifecycle (read, verify, strip) must succeed 100% and be bit-exact
    let read = read_carrier(&out, None, None).expect("read");
    assert_eq!(read.data, b"secret codebits payload");

    let v = verify_carrier(&out, None).expect("verify");
    assert!(v.level1_host.ok, "L1: {}", v.level1_host.detail);
    assert!(v.level2_envelope.ok, "L2: {}", v.level2_envelope.detail);
    assert!(v.level3_crypto.ok, "L3: {}", v.level3_crypto.detail);

    let restored = dir.join("masked_sample.restored.exe");
    remove_carrier(&out, Some(&restored), None, false).expect("remove");
    assert_eq!(
        fs::read(&restored).unwrap(),
        original,
        "restored PE must be bit-for-bit identical"
    );
}

#[test]
fn codebits_rejects_authenticode_signed_pe() {
    let dir = scratch("signed_reject");
    let carrier = dir.join("signed.exe");
    let mut original = make_pe(0x8664, 0x20B, 0x3000, false);

    // Patch Security Data Directory (entry 4) in PE32+:
    // e_lfanew = 0x80 (from make_pe), opt_offset = 0x80 + 24 = 0x98.
    // data_dirs_offset = 0x98 + 112 = 0x108.
    // entry 4 offset = 0x108 + 4 * 8 = 0x128.
    // Set VirtualAddress = 0x5000, Size = 0x200.
    let sec_dir_offset = 0x128;
    assert!(original.len() > sec_dir_offset + 8);
    original[sec_dir_offset..sec_dir_offset + 4].copy_from_slice(&0x5000u32.to_le_bytes());
    original[sec_dir_offset + 4..sec_dir_offset + 8].copy_from_slice(&0x200u32.to_le_bytes());

    // 1. Direct adapter.inject must reject with UnsupportedFormat (was previously bypassed)
    let mut cur = std::io::Cursor::new(original.clone());
    let mut ube = std::io::Cursor::new(vec![1u8; 100]);
    let mut sink = Vec::new();
    let direct_err = strhide::adapters::HostAdapter::inject(
        &strhide::adapters::pe::PeAdapter,
        &mut cur,
        &mut ube,
        &mut sink,
        "pe_codebits",
    )
    .unwrap_err();
    match direct_err {
        StrHideError::UnsupportedFormat(msg) => {
            assert!(msg.contains("Authenticode"));
        }
        other => panic!("expected UnsupportedFormat from direct inject, got {other:?}"),
    }

    // 2. High-level write_carrier also rejects
    fs::write(&carrier, &original).unwrap();
    let out = dir.join("signed.steg.exe");
    let err = write_carrier(
        &carrier,
        PayloadSource::Text("should fail"),
        &write_opts(&out, "pe_codebits"),
    )
    .unwrap_err();

    match err {
        StrHideError::Rejection(msg) | StrHideError::UnsupportedFormat(msg) => {
            assert!(
                msg.contains("Authenticode") || msg.contains("signature"),
                "error must mention Authenticode, got: {msg}"
            );
        }
        other => panic!("expected Rejection or UnsupportedFormat, got {other:?}"),
    }
}

#[test]
fn codebits_double_injection_stealth_fails_safely_and_preserves_carrier() {
    let dir = scratch("double_stealth");
    let carrier = dir.join("clean.exe");
    let original = make_pe(0x8664, 0x20B, 0x3000, false);
    fs::write(&carrier, &original).unwrap();

    // 1. First injection: stealth mode with password
    let steg1 = dir.join("steg1.exe");
    let mut opts1 = write_opts(&steg1, "pe_codebits");
    opts1.stealth = true;
    opts1.password = Some("stealth_pass_1");
    write_carrier(&carrier, PayloadSource::Text("first secret"), &opts1).unwrap();

    // 2. Second injection without knowledge of first password (explicit pe_codebits)
    // Must be rejected because slack ranges contain non-zero data (P1-1 protection)
    let steg2 = dir.join("steg2.exe");
    let mut opts2 = write_opts(&steg2, "pe_codebits");
    opts2.stealth = true;
    opts2.password = Some("different_pass_2");
    let err = write_carrier(&steg1, PayloadSource::Text("second secret"), &opts2).unwrap_err();
    assert!(
        err.to_string().contains("already contains hidden data")
            || err.to_string().contains("padding contains non-zero data"),
        "expected double injection rejection, got: {err}"
    );

    // 3. First payload is intact and carrier can be bit-exactly restored
    let read = read_carrier(&steg1, None, Some("stealth_pass_1")).unwrap();
    assert_eq!(read.data, b"first secret");

    let restored = dir.join("restored.exe");
    remove_carrier(&steg1, Some(&restored), Some("stealth_pass_1"), false).unwrap();
    assert_eq!(
        fs::read(&restored).unwrap(),
        original,
        "first envelope must be removed and carrier restored bit-for-bit"
    );
}
