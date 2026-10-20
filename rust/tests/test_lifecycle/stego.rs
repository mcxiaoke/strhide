//! Integration tests for content-adaptive steganography (HILL, UERD, LSB/DCT Matching).

use crate::common::*;
use std::fs;
use std::path::PathBuf;

use strhide::analysis::scan_file;
use strhide::stego::{
    SpatialParams, StegoOptions, embed_carrier, extract_carrier, probe_carrier_capacity,
    spatial::{HillCostModel, RawImage, decode_png, encode_png},
    traits::SpatialCostModel,
};

/// Generate a synthetic texture PNG image with gradients and noise (128x128).
fn generate_texture_png(w: u32, h: u32) -> Vec<u8> {
    let mut pixels = Vec::with_capacity((w * h * 3) as usize);
    for y in 0..h {
        for x in 0..w {
            // Complex high-frequency texture pattern
            let r = ((x * 17) ^ (y * 31) ^ ((x + y) * 7)) as u8;
            let g = ((x * 23 + y * 19) % 256) as u8;
            let b = ((x * 13) ^ (y * 29)) as u8;
            pixels.push(r);
            pixels.push(g);
            pixels.push(b);
        }
    }
    let img = RawImage {
        width: w,
        height: h,
        channels: 3,
        pixels,
    };
    encode_png(&img).expect("encode png")
}

/// Incompressible deterministic payload.
///
/// A constant-byte payload is squeezed by the envelope's Deflate pass, so a
/// test that uses `vec![0xAA; n]` and calls it "high load" is actually loading
/// the carrier with a few dozen bytes. Every load-sensitive test in this file
/// must use this generator.
fn incompressible(len: usize, seed: u32) -> Vec<u8> {
    let mut s = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        out.push((s & 0xFF) as u8);
    }
    out
}

fn median(values: &[f64]) -> f64 {
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v.get(v.len() / 2).copied().unwrap_or(0.0)
}

/// Recompute the header slot positions exactly as `spatial::engine` does.
///
/// Deliberately duplicates the engine pipeline: the property under test (the
/// header position is a function of the secret, not of the per-embed salt) is
/// only observable from outside if we can reproduce the slot set.
fn header_slots_of(png: &[u8], password: Option<&str>) -> Vec<usize> {
    let img = decode_png(png).expect("decode png");
    let (w, h, ch) = (img.width as usize, img.height as usize, img.channels);
    let params = SpatialParams::default();
    let costs = HillCostModel.compute_cost(&img.pixels, w, h, ch, &params);
    let off = if ch >= 3 { 1 } else { 0 };
    let mut eligible: Vec<usize> = (0..w * h)
        .filter(|&i| (2..=253).contains(&img.pixels[i * ch + off]))
        .collect();
    eligible.sort_by(|&a, &b| {
        costs[a]
            .partial_cmp(&costs[b])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let allowed = ((eligible.len() as f64) * (1.0 - params.exclusion_percentile)) as usize;
    let mut candidates = eligible[..allowed].to_vec();
    strhide::stego::prng::permute_indices(
        &mut candidates,
        &strhide::stego::envelope::derive_header_perm_seed(password),
    );
    candidates[..256].to_vec()
}

/// Read the 32-byte header the way the extractor does, for a known slot set.
fn read_header(png: &[u8], slots: &[usize]) -> [u8; 32] {
    let img = decode_png(png).expect("decode png");
    let ch = img.channels;
    let off = if ch >= 3 { 1 } else { 0 };
    let mut out = [0u8; 32];
    for byte_i in 0..32 {
        let mut b = 0u8;
        for bit_i in 0..8 {
            b = (b << 1) | (img.pixels[slots[byte_i * 8 + bit_i] * ch + off] & 1);
        }
        out[byte_i] = b;
    }
    out
}

#[test]
fn test_png_hill_content_stego_roundtrip() {
    let png_bytes = generate_texture_png(128, 128);
    let secret = b"Hello from HILL content-adaptive steganography! 2026";
    let password = "SecretPassword123!";

    let mut opts = StegoOptions {
        algorithm: Some("hill".into()),
        password: Some(password.into()),
        ..Default::default()
    };

    // 1. Embed
    let stego_png = embed_carrier(&png_bytes, secret, &opts).expect("embed png");
    assert_ne!(png_bytes, stego_png, "stego png should modify pixel values");

    // 2. Extract with correct password
    let extracted = extract_carrier(&stego_png, &opts).expect("extract png");
    assert_eq!(extracted, secret, "extracted payload must match original");

    // 3. Extract with wrong password must fail
    opts.password = Some("WrongPassword999!".into());
    assert!(
        extract_carrier(&stego_png, &opts).is_err(),
        "wrong password must fail"
    );
}

#[test]
fn test_png_hill_fine_tuning_parameters() {
    let png_bytes = generate_texture_png(128, 128);
    let secret = b"Fine-tuned parameters test";

    let mut opts = StegoOptions {
        algorithm: Some("hill".into()),
        password: Some("pwd".into()),
        ..Default::default()
    };
    // Customize parameters: exclude top 40% smoothest pixels, customize filters
    opts.spatial_params.exclusion_percentile = 0.40;
    opts.spatial_params.p1_window = 3;
    opts.spatial_params.p2_window = 15;

    let stego_png = embed_carrier(&png_bytes, secret, &opts).expect("embed tuned");
    let extracted = extract_carrier(&stego_png, &opts).expect("extract tuned");
    assert_eq!(extracted, secret);
}

#[test]
fn test_png_hill_scan_analysis_pass() {
    let png_bytes = generate_texture_png(160, 160);
    let secret = b"Steganalysis resistance test under scan_file";

    let opts = StegoOptions {
        algorithm: Some("hill".into()),
        password: Some("Pass!".into()),
        ..Default::default()
    };

    let stego_png = embed_carrier(&png_bytes, secret, &opts).expect("embed");

    let dir = scratch("png_scan");
    let file_path = dir.join("stego.png");
    fs::write(&file_path, &stego_png).unwrap();

    // Run strhide scan on the generated stego PNG
    let report = scan_file(&file_path).expect("scan_file");
    println!(
        "Scan report verdict: {}, risk: {}",
        report.verdict, report.risk_score
    );
    for finding in &report.findings {
        println!("  Finding: [{}] {}", finding.detector, finding.detail);
    }

    // HILL + LSB Matching preserves histogram smoothness and does not trigger chi2 or SPA
    assert!(
        report.verdict == "clean" || report.verdict == "low",
        "Stego PNG should not trigger suspicious or likely-hidden verdicts! Got: {}",
        report.verdict
    );
}

#[test]
fn test_jpeg_uerd_content_stego_roundtrip() {
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("temp")
        .join("testfiles")
        .join("file-08.jpg");

    if !candidate.exists() {
        eprintln!("[SKIP] temp/testfiles/file-06.jpg not found");
        return;
    }

    let jpeg_bytes = fs::read(&candidate).expect("read sample jpeg");
    let secret = b"JPEG UERD content-adaptive secret message 2026!";
    let password = "JpegPassword2026#";

    let mut opts = StegoOptions {
        algorithm: Some("uerd".into()),
        password: Some(password.into()),
        ..Default::default()
    };

    // 1. Embed into JPEG DCT coefficients
    let stego_jpeg = embed_carrier(&jpeg_bytes, secret, &opts).expect("embed jpeg");
    assert_ne!(
        jpeg_bytes, stego_jpeg,
        "stego jpeg should differ from original"
    );

    // 2. Extract with correct password
    let extracted = extract_carrier(&stego_jpeg, &opts).expect("extract jpeg");
    assert_eq!(extracted, secret, "extracted payload must match original");

    // 3. Extract with wrong password must fail
    opts.password = Some("WrongPassword!".into());
    assert!(
        extract_carrier(&stego_jpeg, &opts).is_err(),
        "wrong password must fail"
    );
}

#[test]
fn test_jpeg_uerd_fine_tuning() {
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("temp")
        .join("testfiles")
        .join("file-08.jpg");

    if !candidate.exists() {
        return;
    }

    let jpeg_bytes = fs::read(&candidate).unwrap();
    let secret = b"Customized UERD neighbor weight test";

    let mut opts = StegoOptions {
        algorithm: Some("uerd".into()),
        password: Some("p1".into()),
        ..Default::default()
    };
    opts.jpeg_params.neighbor_weight = 0.35;
    opts.jpeg_params.block_exclusion_percentile = 0.25;

    let stego_jpeg = embed_carrier(&jpeg_bytes, secret, &opts).unwrap();
    let extracted = extract_carrier(&stego_jpeg, &opts).unwrap();
    assert_eq!(extracted, secret);
}

#[test]
fn test_cli_embed_and_extract_roundtrip() {
    let dir = scratch("cli_roundtrip");
    let carrier_png = dir.join("carrier.png");
    let stego_png = dir.join("stego.png");
    let out_txt = dir.join("out.txt");

    // Write a synthetic carrier PNG
    let png_bytes = generate_texture_png(128, 128);
    fs::write(&carrier_png, &png_bytes).unwrap();

    let bin = env!("CARGO_BIN_EXE_strhide");

    // 1. Embed via CLI: strhide embed carrier.png -t "CLI Test Message" -p "TestPW123" -o stego.png
    let embed_status = std::process::Command::new(bin)
        .arg("embed")
        .arg(&carrier_png)
        .arg("-t")
        .arg("CLI Test Message")
        .arg("-p")
        .arg("TestPW123")
        .arg("-o")
        .arg(&stego_png)
        .status()
        .expect("run embed CLI");
    assert!(embed_status.success(), "embed command should succeed");
    assert!(stego_png.exists(), "stego file must be created");

    // 2. Extract via CLI: strhide extract stego.png -p "TestPW123" -o out.txt
    let extract_status = std::process::Command::new(bin)
        .arg("extract")
        .arg(&stego_png)
        .arg("-p")
        .arg("TestPW123")
        .arg("-o")
        .arg(&out_txt)
        .status()
        .expect("run extract CLI");
    assert!(extract_status.success(), "extract command should succeed");

    let read_back = fs::read_to_string(&out_txt).expect("read extracted output");
    assert_eq!(read_back, "CLI Test Message");

    // 3. Scan the stego file: strhide scan stego.png
    let scan_status = std::process::Command::new(bin)
        .arg("scan")
        .arg(&stego_png)
        .status()
        .expect("run scan CLI");
    // Scan exits 0 on clean/low verdicts
    assert!(
        scan_status.success(),
        "scan command should not fail on clean/low"
    );
}

#[test]
fn test_stego_saturation_exclusion() {
    // Every boundary the candidate filter cares about, on its own row of the
    // green channel: 0 and 1 are excluded, 2 is the first embeddable value,
    // 253 is the last, 254 and 255 are excluded again.
    let w = 64usize;
    let h = 64usize;
    let mut pixels = vec![128u8; w * h * 3];
    let rows = [(0usize, 0u8), (1, 1), (2, 2), (3, 253), (4, 254), (5, 255)];
    for (y, v) in rows {
        for x in 0..w {
            pixels[(y * w + x) * 3 + 1] = v;
        }
    }
    // Middle region with varied textures [50, 200] so there is capacity.
    for y in 6..h {
        for x in 0..w {
            pixels[(y * w + x) * 3 + 1] = (50 + ((x * 17 + y * 31) % 150)) as u8;
        }
    }

    let png_bytes = encode_png(&RawImage {
        width: w as u32,
        height: h as u32,
        channels: 3,
        pixels,
    })
    .unwrap();

    let secret = b"Saturation boundary protection verified!";
    let opts = StegoOptions {
        password: Some("SaturationSecret123".into()),
        ..Default::default()
    };

    let stego_png = embed_carrier(&png_bytes, secret, &opts).expect("embed carrier");
    assert_eq!(
        extract_carrier(&stego_png, &opts).expect("extract carrier"),
        secret
    );

    let stego_pixels = decode_png(&stego_png).unwrap().pixels;

    // 0, 1, 254, 255 must be untouched.
    for (y, v) in [(0usize, 0u8), (1, 1), (4, 254), (5, 255)] {
        for x in 0..w {
            assert_eq!(
                stego_pixels[(y * w + x) * 3 + 1],
                v,
                "excluded value {v} at row {y} was modified"
            );
        }
    }

    // 2 and 253 are the boundaries that ARE embeddable: they may flip, but only
    // within their LSB pair, so they can never reach 0/1 or 254/255.
    for x in 0..w {
        let v2 = stego_pixels[(2 * w + x) * 3 + 1];
        assert!(
            v2 == 2 || v2 == 3,
            "value 2 must stay in {{2,3}} after LSB replacement, got {v2}"
        );
        let v253 = stego_pixels[(3 * w + x) * 3 + 1];
        assert!(
            v253 == 252 || v253 == 253,
            "value 253 must stay in {{252,253}} after LSB replacement, got {v253}"
        );
    }
}

#[test]
fn test_stego_keyed_permutation_property() {
    let png_bytes = generate_texture_png(64, 64);
    let secret = b"Keyed permutation isolates passwords completely";

    let opts_a = StegoOptions {
        password: Some("AliceSecret2026".into()),
        ..Default::default()
    };
    let opts_b = StegoOptions {
        password: Some("BobSecret2026".into()),
        ..Default::default()
    };

    let stego_a = embed_carrier(&png_bytes, secret, &opts_a).expect("embed with Alice");

    // Alice extracts successfully
    let res_a = extract_carrier(&stego_a, &opts_a).expect("Alice extracts");
    assert_eq!(res_a, secret);

    // Bob cannot extract (must return NoHiddenData error, not panic)
    let res_b = extract_carrier(&stego_a, &opts_b);
    assert!(
        matches!(res_b, Err(strhide::errors::StrHideError::NoHiddenData(_))),
        "Bob must receive NoHiddenData, got: {res_b:?}"
    );
}

#[test]
fn test_stego_high_load_steganalysis_response() {
    // Uses a real photographic carrier: the synthetic texture used by the other
    // tests is itself flagged by SPA (pseudo-random LSBs), so it has no clean
    // baseline to rise from and cannot distinguish "clean" from "loaded".
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("temp")
        .join("teststego")
        .join("ref_minimal_peach.png");
    if !candidate.exists() {
        eprintln!("[SKIP] temp/teststego/ref_minimal_peach.png not found");
        return;
    }
    let png_bytes = fs::read(&candidate).expect("read carrier");
    let opts = StegoOptions::default();
    let cap = probe_carrier_capacity(&png_bytes, &opts).expect("probe");

    let dir = scratch("steganalysis_response");
    let clean_path = dir.join("clean.png");
    let low_path = dir.join("low.png");
    let high_path = dir.join("high.png");
    fs::write(&clean_path, &png_bytes).unwrap();

    let low_stego = embed_carrier(&png_bytes, b"16 bytes message", &opts).unwrap();
    // Full capacity AND incompressible: a constant-byte payload would be
    // squeezed by the envelope's Deflate pass and would not load the carrier.
    let high_secret = incompressible(cap.max_raw_payload_bytes, 0x5A5A);
    let high_stego = embed_carrier(&png_bytes, &high_secret, &opts).unwrap();

    fs::write(&low_path, &low_stego).unwrap();
    fs::write(&high_path, &high_stego).unwrap();

    let clean_scan = strhide::analysis::scan_file(&clean_path).unwrap();
    let low_scan = strhide::analysis::scan_file(&low_path).unwrap();
    let high_scan = strhide::analysis::scan_file(&high_path).unwrap();

    // Low load must not inflate the score.
    assert!(
        low_scan.risk_score <= clean_scan.risk_score + 10,
        "Low load should maintain clean baseline (clean={}, low={})",
        clean_scan.risk_score,
        low_scan.risk_score
    );

    // Full load must be visible to our own detector. This assertion was missing:
    // the test used to compare `high >= low`, which holds even when the detector
    // reports nothing at all.
    assert_eq!(extract_carrier(&high_stego, &opts).unwrap(), high_secret);
    assert!(
        !high_scan.findings.is_empty(),
        "Full-capacity load ({} bytes) produced no detector findings at all (risk={}, verdict={})",
        high_secret.len(),
        high_scan.risk_score,
        high_scan.verdict
    );
    assert!(
        high_scan.risk_score > clean_scan.risk_score,
        "Full load must raise the risk score above the clean carrier (clean={}, high={})",
        clean_scan.risk_score,
        high_scan.risk_score
    );
}

/// The capacity probe must be *tight*: the reported maximum embeds, one byte
/// more is rejected.
///
/// This is the test that catches the old `MIN_ENVELOPE_LEN` subtraction, which
/// under-reported every carrier by exactly 28 bytes (the salt/nonce is paid for
/// by the header slots, not by the body).
#[test]
fn test_stego_capacity_model_is_tight() {
    let png_bytes = generate_texture_png(128, 128);
    let opts = StegoOptions::default();
    let cap = probe_carrier_capacity(&png_bytes, &opts).expect("probe");

    assert!(
        cap.max_raw_payload_bytes > 0,
        "synthetic texture must hold data"
    );

    let exact = incompressible(cap.max_raw_payload_bytes, 0x1234);
    let stego = embed_carrier(&png_bytes, &exact, &opts).expect("probe max must embed");
    assert_eq!(extract_carrier(&stego, &opts).expect("extract"), exact);

    let over = incompressible(cap.max_raw_payload_bytes + 1, 0x1234);
    let res = embed_carrier(&png_bytes, &over, &opts);
    assert!(
        matches!(res, Err(strhide::errors::StrHideError::General(ref m)) if m.contains("capacity exceeded")),
        "probe max + 1 byte must be rejected as over capacity, got: {res:?}"
    );
}

/// The body slots must keep HILL's cost ordering.
///
/// An earlier version selected the body as "first N of the fully permuted
/// candidate set", i.e. a random subset, which measured ~4.3x the median HILL
/// cost of the cheapest equivalent slots at 50% load. This test pins the
/// cost-ordered behaviour down.
#[test]
fn test_stego_body_slots_follow_cost_order() {
    let png_bytes = generate_texture_png(128, 128);
    let opts = StegoOptions::default();
    let cap = probe_carrier_capacity(&png_bytes, &opts).expect("probe");

    let payload = incompressible(cap.max_raw_payload_bytes / 2, 0xBEEF);
    let stego = embed_carrier(&png_bytes, &payload, &opts).expect("embed");

    let before = decode_png(&png_bytes).unwrap();
    let after = decode_png(&stego).unwrap();
    let w = before.width as usize;
    let n = w * before.height as usize;
    let ch = before.channels;
    let off = if ch >= 3 { 1 } else { 0 };

    // Header slots are keyed random, not cost-ordered; exclude them so only the
    // body's slot choice is measured.
    let header: std::collections::HashSet<usize> =
        header_slots_of(&png_bytes, None).into_iter().collect();

    let changed: Vec<usize> = (0..n)
        .filter(|&i| {
            !header.contains(&i) && before.pixels[i * ch + off] != after.pixels[i * ch + off]
        })
        .collect();
    assert!(
        !changed.is_empty(),
        "50% load must modify at least one body pixel"
    );

    let params = SpatialParams::default();
    let costs = HillCostModel.compute_cost(&before.pixels, w, n / w, ch, &params);
    let mut eligible: Vec<usize> = (0..n)
        .filter(|&i| (2..=253).contains(&before.pixels[i * ch + off]))
        .collect();
    eligible.sort_by(|&a, &b| {
        costs[a]
            .partial_cmp(&costs[b])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let cheapest = &eligible[..changed.len().min(eligible.len())];

    let changed_cost = median(&changed.iter().map(|&i| costs[i]).collect::<Vec<_>>());
    let cheapest_cost = median(&cheapest.iter().map(|&i| costs[i]).collect::<Vec<_>>());
    assert!(
        cheapest_cost > 0.0 && changed_cost / cheapest_cost < 1.5,
        "body slots must be the cheapest ones: median cost of modified pixels {changed_cost:.4} vs cheapest {} slots {cheapest_cost:.4} (ratio {:.2}x)",
        changed.len(),
        changed_cost / cheapest_cost
    );
}

/// The header position must depend on the secret only -- never on the per-embed
/// salt.
///
/// This is the corrected form of the plan's original acceptance criterion
/// ("two embeds must place the header differently because the salt is random"),
/// which is impossible by design: the header carries the salt, so its position
/// cannot be derived from it.
#[test]
fn test_stego_header_slots_are_keyed_and_salt_independent() {
    let png_bytes = generate_texture_png(64, 64);
    let payload = incompressible(64, 0x77);

    // No password -> public default secret.
    let first = embed_carrier(&png_bytes, &payload, &StegoOptions::default()).unwrap();
    let second = embed_carrier(&png_bytes, &payload, &StegoOptions::default()).unwrap();
    assert_ne!(
        first, second,
        "two embeds must differ (random salt/nonce), otherwise nothing below is meaningful"
    );

    // Same secret, same carrier -> same header slots, even though the salt (and
    // therefore the whole ciphertext) changed.
    let slots_a = header_slots_of(&png_bytes, None);
    assert_eq!(slots_a, header_slots_of(&png_bytes, None));

    // The model matches the engine: the header read from those slots must parse
    // as the real envelope length (payload + 49 for an incompressible body).
    let header = read_header(&first, &slots_a);
    let total_len = u32::from_be_bytes([header[28], header[29], header[30], header[31]]) as usize;
    assert_eq!(
        total_len,
        payload.len() + 49,
        "header at the computed slots must carry the real envelope length"
    );
    let header2 = read_header(&second, &slots_a);
    let total_len2 =
        u32::from_be_bytes([header2[28], header2[29], header2[30], header2[31]]) as usize;
    assert_eq!(total_len2, total_len, "header position is salt independent");

    // A different secret moves the header: parsing the same carrier as if the
    // other secret had been used yields garbage.
    let slots_b = header_slots_of(&png_bytes, Some("another-secret-2026"));
    assert_ne!(slots_a, slots_b, "header slots must be keyed");
    let foreign = read_header(&first, &slots_b);
    let foreign_len =
        u32::from_be_bytes([foreign[28], foreign[29], foreign[30], foreign[31]]) as usize;
    assert!(
        foreign_len != total_len,
        "a foreign secret must not land on the real header"
    );
}

/// A private `default_secret` must create a private dialect: the official
/// public constant, or any other secret, must not be able to read it.
///
/// This is the regression guard for the "public code can decode every
/// no-password carrier" flaw: before it, the key and the header-slot
/// permutation were both derived from a constant in the source tree.
#[test]
fn test_stego_private_default_secret_isolation() {
    let png_bytes = generate_texture_png(128, 128);
    let secret = b"Private dialect payload, 2026-10-20";

    let private = StegoOptions {
        default_secret: Some("acme-private-dialect-2026".into()),
        ..Default::default()
    };
    let other = StegoOptions {
        default_secret: Some("someone-elses-dialect-2026".into()),
        ..Default::default()
    };
    let official = StegoOptions::default();

    // 1. Round trip with the private secret and no password.
    let stego = embed_carrier(&png_bytes, secret, &private).expect("embed with private secret");
    assert_eq!(
        extract_carrier(&stego, &private).expect("private extract"),
        secret
    );

    // 2. The official public constant must NOT read it.
    let res_official = extract_carrier(&stego, &official);
    assert!(
        matches!(
            res_official,
            Err(strhide::errors::StrHideError::NoHiddenData(_))
        ),
        "official default secret must fail on a private-dialect carrier, got: {res_official:?}"
    );

    // 3. A different private secret must NOT read it.
    let res_other = extract_carrier(&stego, &other);
    assert!(
        matches!(
            res_other,
            Err(strhide::errors::StrHideError::NoHiddenData(_))
        ),
        "a foreign private secret must fail, got: {res_other:?}"
    );

    // 4. Symmetry: an official carrier stays readable only with official opts.
    let official_stego = embed_carrier(&png_bytes, secret, &official).expect("embed official");
    assert_eq!(
        extract_carrier(&official_stego, &official).expect("official extract"),
        secret
    );
    assert!(
        matches!(
            extract_carrier(&official_stego, &private),
            Err(strhide::errors::StrHideError::NoHiddenData(_))
        ),
        "private secret must not read an official carrier"
    );

    // 5. An explicit password outranks the private default secret.
    let mut with_password = private.clone();
    with_password.password = Some("UserChosenPassword1".into());
    let pw_stego = embed_carrier(&png_bytes, secret, &with_password).expect("embed with password");
    assert_ne!(
        pw_stego, stego,
        "password must take precedence over default_secret"
    );
    assert_eq!(
        extract_carrier(&pw_stego, &with_password).expect("password extract"),
        secret
    );
    // Neither the private default secret alone nor the official constant may
    // stand in for the password.
    assert!(extract_carrier(&pw_stego, &private).is_err());
    assert!(extract_carrier(&pw_stego, &official).is_err());
}

/// The JPEG (UERD) engine must honour the private secret too. Skipped when the
/// sample corpus is not present, like the other JPEG lifecycle tests.
#[test]
fn test_jpeg_private_default_secret_isolation() {
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("temp")
        .join("testfiles")
        .join("file-08.jpg");
    if !candidate.exists() {
        eprintln!("[SKIP] temp/testfiles/file-08.jpg not found");
        return;
    }
    let jpeg_bytes = fs::read(&candidate).expect("read sample jpeg");
    let secret = b"Private JPEG dialect payload";

    let private = StegoOptions {
        algorithm: Some("uerd".into()),
        default_secret: Some("acme-jpeg-dialect-2026".into()),
        ..Default::default()
    };
    let official = StegoOptions {
        algorithm: Some("uerd".into()),
        ..Default::default()
    };

    let stego = embed_carrier(&jpeg_bytes, secret, &private).expect("embed jpeg private");
    assert_eq!(
        extract_carrier(&stego, &private).expect("private jpeg extract"),
        secret
    );
    assert!(
        matches!(
            extract_carrier(&stego, &official),
            Err(strhide::errors::StrHideError::NoHiddenData(_))
        ),
        "official secret must fail on a private-dialect JPEG carrier"
    );
}

/// The calibrated DCT detector must separate a clean JPEG from the same JPEG
/// carrying a full-capacity payload, and must not fire on the clean one.
///
/// Skipped when the sample corpus is absent, like the other JPEG tests.
#[test]
fn test_jpeg_calibration_detector_clean_vs_loaded() {
    // A carrier with normal quantization: `bg_320_03_R.jpg` is quality-100
    // (all quantization steps == 1) and is deliberately excluded from
    // calibration -- see `test_jpeg_calibration_skips_unquantized_carrier`.
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("temp")
        .join("teststego")
        .join("DSC_20260403_161503_1794.jpg");
    if !candidate.exists() {
        eprintln!("[SKIP] temp/teststego/DSC_20260403_161503_1794.jpg not found");
        return;
    }
    let jpeg_bytes = fs::read(&candidate).expect("read carrier");
    let dir = scratch("calibration_detector");
    let clean_path = dir.join("clean.jpg");
    fs::write(&clean_path, &jpeg_bytes).unwrap();

    let clean = strhide::analysis::scan_file(&clean_path).unwrap();
    assert!(
        !clean
            .findings
            .iter()
            .any(|f| f.detector == "dct:calibration"),
        "calibrated detector fired on a clean carrier (risk={}, findings={:?})",
        clean.risk_score,
        clean.findings
    );

    let opts = StegoOptions::default();
    let cap = probe_carrier_capacity(&jpeg_bytes, &opts).expect("probe");
    let payload = incompressible(cap.max_raw_payload_bytes, 0xCAFE);
    let stego = embed_carrier(&jpeg_bytes, &payload, &opts).expect("embed full capacity");
    assert_eq!(extract_carrier(&stego, &opts).expect("extract"), payload);
    let stego_path = dir.join("loaded.jpg");
    fs::write(&stego_path, &stego).unwrap();

    let loaded = strhide::analysis::scan_file(&stego_path).unwrap();
    assert!(
        loaded
            .findings
            .iter()
            .any(|f| f.detector == "dct:calibration"),
        "calibrated detector missed a full-capacity carrier (risk={}, findings={:?})",
        loaded.risk_score,
        loaded.findings
    );
    assert!(
        loaded.risk_score > clean.risk_score,
        "full load must raise the risk score (clean={}, loaded={})",
        clean.risk_score,
        loaded.risk_score
    );
}

/// A clean JPEG that no detector flags must still carry the "clean is not
/// proof" caveat, so the verdict cannot be read as evidence of absence.
#[test]
fn test_scan_clean_jpeg_emits_caveat_note() {
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("temp")
        .join("teststego")
        .join("bg_320_03_R.jpg");
    if !candidate.exists() {
        eprintln!("[SKIP] temp/teststego/bg_320_03_R.jpg not found");
        return;
    }
    let report = strhide::analysis::scan_file(&candidate).unwrap();
    if report.risk_score < 10 {
        assert!(
            report.notes.iter().any(|n| n.contains("NOT evidence")),
            "clean JPEG must explain what the verdict does not prove, got {:?}",
            report.notes
        );
    }
}

/// Calibration must refuse carriers whose quantization is too fine to support it.
///
/// A quality-100 image (all quantization steps = 1) makes the calibrated
/// reference dominated by IDCT round-trip error: measured on the bundled
/// sample, the estimator reported 0.659 ("66% embedded") on a *clean* file.
/// The gate is `mean luma step < 2`, and the carrier must fall back to the
/// pixel-domain detectors plus the explicit caveat instead of producing a bogus
/// finding.
#[test]
fn test_jpeg_calibration_skips_unquantized_carrier() {
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("temp")
        .join("real_samples")
        .join("sample.jpg");
    if !candidate.exists() {
        eprintln!("[SKIP] temp/real_samples/sample.jpg not found");
        return;
    }
    let bytes = fs::read(&candidate).expect("read sample");
    assert!(
        strhide::analysis::calibration::estimate(&bytes).is_none(),
        "an all-ones quantization table must disable calibration, not produce an estimate"
    );

    let report = strhide::analysis::scan_file(&candidate).unwrap();
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.detector == "dct:calibration"),
        "calibration must not report on an uncalibratable carrier, got {:?}",
        report.findings
    );
}
