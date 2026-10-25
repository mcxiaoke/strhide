//! Integration tests for content-adaptive steganography (HILL, UERD, LSB/DCT Matching).

use crate::common::*;
use std::fs;
use std::path::PathBuf;

use strhide::analysis::scan_file;
use strhide::params::Profile;
use strhide::stego::{
    PngParams, StegoOptions, embed_carrier, embed_carrier_with_profile, extract_carrier,
    extract_carrier_with_profile,
    png::{HillCostModel, RawImage, decode_png, encode_png},
    probe_carrier_capacity,
    traits::PngCostModel,
};

/// Private content-domain dialect: the secret now lives in the shared
/// `Profile`, not in `StegoOptions`.
fn stego_profile(secret: &'static str) -> Profile {
    Profile::default().with_stego_secret(secret)
}

/// Resolves a fixture file bundled in `tests/fixtures/`.
fn fixture_file(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(rel)
}

/// Resolves a test corpus file from local temp/ or environment variables.
fn find_corpus_file(rel: &str) -> Option<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let local = root.join("temp").join(rel);
    if local.exists() {
        return Some(local);
    }
    if let Ok(corpus) = std::env::var("STRHIDE_CORPUS") {
        let p = PathBuf::from(&corpus).join(rel);
        if p.exists() {
            return Some(p);
        }
        if let Some(name) = std::path::Path::new(rel).file_name() {
            let p2 = PathBuf::from(&corpus).join(name);
            if p2.exists() {
                return Some(p2);
            }
        }
    }
    if let Ok(corpus) = std::env::var("STRHIDE_STEGO_CORPUS") {
        let p = PathBuf::from(&corpus).join(rel);
        if p.exists() {
            return Some(p);
        }
        if let Some(name) = std::path::Path::new(rel).file_name() {
            let p2 = PathBuf::from(&corpus).join(name);
            if p2.exists() {
                return Some(p2);
            }
        }
    }
    None
}

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
        chunks: Vec::new(),
        idat_sizes: Vec::new(),
        row_filters: Vec::new(),
        idat_info: None,
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

/// Recompute the header slot positions exactly as `png::engine` does.
///
/// Deliberately duplicates the engine pipeline: the property under test (the
/// header position is a function of the secret, not of the per-embed salt) is
/// only observable from outside if we can reproduce the slot set.
/// Recompute the header slot layout the way the extractor does.
///
/// Deliberately **cost-free**: the header is placed from the eligible pixels in
/// ascending order and then keyed-permuted, so a reader can find it without
/// knowing which cost model wrote the body. This used to sort candidates by
/// HILL cost and drop the smoothest 30%, which made the header unreachable
/// before the algorithm was known.
fn header_slots_of(png: &[u8], password: Option<&str>) -> Vec<usize> {
    let img = decode_png(png).expect("decode png");
    let (w, h, ch) = (img.width as usize, img.height as usize, img.channels);
    let off = if ch >= 3 { 1 } else { 0 };
    let mut eligible: Vec<usize> = (0..w * h)
        .filter(|&i| {
            (strhide::stego::png::engine::SPATIAL_ELIGIBLE_MIN
                ..=strhide::stego::png::engine::SPATIAL_ELIGIBLE_MAX)
                .contains(&img.pixels[i * ch + off])
        })
        .collect();
    assert_eq!(
        eligible.len(),
        eligible.iter().filter(|&&i| i < w * h).count()
    );
    strhide::stego::prng::permute_prefix(
        &mut eligible,
        strhide::stego::header::V2_TOTAL_HEADER_SLOTS,
        &strhide::stego::envelope::derive_header_perm_seed(password, None),
    );
    eligible[..strhide::stego::header::V2_TOTAL_HEADER_SLOTS].to_vec()
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
    opts.png_params.exclusion_percentile = 0.40;
    opts.png_params.p1_window = 3;
    opts.png_params.p2_window = 15;

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
    let candidate = fixture_file("carrier.jpg");
    let jpeg_bytes = fs::read(&candidate).expect("read carrier jpeg");
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
    // The V3 knob that replaces the old pool/truncation parameters: a larger
    // slot budget spreads the payload over more coefficients.
    opts.jpeg_params.slot_budget = Some(200_000);

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

    // 1. Embed via CLI: strhide embed carrier.png -t "CLI Test Message" -p "TestPW123" -o stego.png
    let embed_status = base_cmd()
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
    let extract_status = base_cmd()
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
    let scan_status = base_cmd()
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
        chunks: Vec::new(),
        idat_sizes: Vec::new(),
        row_filters: Vec::new(),
        idat_info: None,
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
    let png_bytes = {
        let fix = fixture_file("carrier.png");
        if fix.exists() {
            fs::read(fix).expect("read fixture carrier png")
        } else {
            match find_corpus_file("teststego/ref_minimal_peach.png") {
                Some(p) => fs::read(p).expect("read carrier"),
                None => generate_texture_png(128, 128),
            }
        }
    };
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

    // High load roundtrip must extract 100% losslessly.
    assert_eq!(extract_carrier(&high_stego, &opts).unwrap(), high_secret);

    // Monotonicity: high load risk score must never be less than clean carrier.
    assert!(
        high_scan.risk_score >= clean_scan.risk_score,
        "Full load must not drop risk score below clean carrier (clean={}, high={})",
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

    let params = PngParams::default();
    let costs = HillCostModel.compute_cost(&before.pixels, w, n / w, ch, &params);
    let mut eligible: Vec<usize> = (0..n)
        .filter(|&i| {
            (strhide::stego::png::engine::SPATIAL_ELIGIBLE_MIN
                ..=strhide::stego::png::engine::SPATIAL_ELIGIBLE_MAX)
                .contains(&before.pixels[i * ch + off])
        })
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
    // The header word also carries the codec/h flags in its top bits, so the
    // length has to be decoded rather than read as a bare u32.
    let header = read_header(&first, &slots_a[..256]);
    let word = u32::from_be_bytes([header[28], header[29], header[30], header[31]]);
    let (total_len, _codec_id, stc_h) = strhide::stego::png::engine::decode_header_word(word);
    assert_eq!(
        total_len as usize,
        payload.len() + 49,
        "header at the computed slots must carry the real envelope length"
    );
    // In v2, word1 writes HEADER_V2_ESCAPE_H (15) for stc_h
    assert_eq!(
        stc_h,
        strhide::stego::header::HEADER_V2_ESCAPE_H,
        "v2 header writes escape h=15"
    );
    // And feature word carries codec, h, and u
    let feature_bytes = read_header(&first, &slots_a[256..512]);
    let fw =
        strhide::stego::header::FeatureWord::decode(&feature_bytes).expect("decode feature word");
    assert_eq!(fw.version, 3);
    assert_eq!(fw.codec, strhide::stego::StegoCodec::Stc);
    assert_eq!(fw.h, 8, "v3 FeatureWord carries real constraint height h=8");

    // Explicit Hamming embed must declare escape h=15 in word1, and codec Hamming in FeatureWord
    let hamming_opts = StegoOptions {
        png_params: PngParams {
            codec: strhide::stego::StegoCodec::Hamming,
            ..PngParams::default()
        },
        ..StegoOptions::default()
    };
    let hamming_stego = embed_carrier(&png_bytes, &payload, &hamming_opts).unwrap();
    let hamming_hdr = read_header(&hamming_stego, &slots_a[..256]);
    let hamming_word = u32::from_be_bytes([
        hamming_hdr[28],
        hamming_hdr[29],
        hamming_hdr[30],
        hamming_hdr[31],
    ]);
    let (_, _h_codec, h_h) = strhide::stego::png::engine::decode_header_word(hamming_word);
    assert_eq!(h_h, strhide::stego::header::HEADER_V2_ESCAPE_H);
    let hamming_feat = read_header(&hamming_stego, &slots_a[256..512]);
    let fw_hamming = strhide::stego::header::FeatureWord::decode(&hamming_feat)
        .expect("decode hamming feature word");
    assert_eq!(fw_hamming.codec, strhide::stego::StegoCodec::Hamming);
    assert_eq!(fw_hamming.u, 0);

    let header2 = read_header(&second, &slots_a[..256]);
    let word2 = u32::from_be_bytes([header2[28], header2[29], header2[30], header2[31]]);
    assert_eq!(
        word2 & strhide::stego::png::engine::HEADER_LEN_MASK,
        total_len,
        "header position is salt independent"
    );

    // A different secret moves the header: parsing the same carrier as if the
    // other secret had been used yields garbage.
    let slots_b = header_slots_of(&png_bytes, Some("another-secret-2026"));
    assert_ne!(slots_a, slots_b, "header slots must be keyed");
    let foreign = read_header(&first, &slots_b);
    let foreign_word = u32::from_be_bytes([foreign[28], foreign[29], foreign[30], foreign[31]]);
    let (foreign_len, _, _) = strhide::stego::png::engine::decode_header_word(foreign_word);
    assert!(
        foreign_len != total_len,
        "a foreign secret must not land on the real header"
    );
}

/// A private `Profile::stego` secret must create a private dialect: the official
/// public constant, or any other secret, must not be able to read it.
///
/// This is the regression guard for the "public code can decode every
/// no-password carrier" flaw: before it, the key and the header-slot
/// permutation were both derived from a constant in the source tree.
///
/// The secret is carried by `Profile` (M1b), so the *profile* is what has to
/// match — `StegoOptions` no longer has a `default_secret` field at all.
#[test]
fn test_stego_private_default_secret_isolation() {
    let png_bytes = generate_texture_png(128, 128);
    let secret = b"Private dialect payload, 2026-10-20";

    let official = Profile::default();
    let private = stego_profile("acme-private-dialect-2026");
    let other = stego_profile("someone-elses-dialect-2026");
    let opts = StegoOptions::default();

    // 1. Round trip with the private secret and no password.
    let stego = embed_carrier_with_profile(&png_bytes, secret, &opts, &private)
        .expect("embed with private secret");
    assert_eq!(
        extract_carrier_with_profile(&stego, &opts, &private).expect("private extract"),
        secret
    );

    // 2. The official public constant must NOT read it.
    let res_official = extract_carrier_with_profile(&stego, &opts, &official);
    assert!(
        matches!(
            res_official,
            Err(strhide::errors::StrHideError::NoHiddenData(_))
        ),
        "official default secret must fail on a private-dialect carrier, got: {res_official:?}"
    );

    // 3. A different private secret must NOT read it.
    let res_other = extract_carrier_with_profile(&stego, &opts, &other);
    assert!(
        matches!(
            res_other,
            Err(strhide::errors::StrHideError::NoHiddenData(_))
        ),
        "a foreign private secret must fail, got: {res_other:?}"
    );

    // 4. Symmetry: an official carrier stays readable only with official opts.
    let official_stego =
        embed_carrier_with_profile(&png_bytes, secret, &opts, &official).expect("embed official");
    assert_eq!(
        extract_carrier_with_profile(&official_stego, &opts, &official).expect("official extract"),
        secret
    );
    assert!(
        matches!(
            extract_carrier_with_profile(&official_stego, &opts, &private),
            Err(strhide::errors::StrHideError::NoHiddenData(_))
        ),
        "private secret must not read an official carrier"
    );

    // 5. An explicit password outranks the private default secret.
    let with_password = StegoOptions {
        password: Some("UserChosenPassword1".into()),
        ..Default::default()
    };
    let pw_stego = embed_carrier_with_profile(&png_bytes, secret, &with_password, &private)
        .expect("embed with password");
    assert_ne!(
        pw_stego, stego,
        "password must take precedence over the profile secret"
    );
    assert_eq!(
        extract_carrier_with_profile(&pw_stego, &with_password, &private)
            .expect("password extract"),
        secret
    );
    // Neither the private default secret alone nor the official constant may
    // stand in for the password.
    assert!(extract_carrier_with_profile(&pw_stego, &opts, &private).is_err());
    assert!(extract_carrier_with_profile(&pw_stego, &opts, &other).is_err());
    assert!(extract_carrier_with_profile(&pw_stego, &opts, &official).is_err());
}

/// The legacy `embed_carrier` / `extract_carrier` entries are the official
/// dialect: they must keep working for official carriers and must stay unable
/// to read a private-dialect one.
#[test]
fn test_stego_legacy_entries_use_the_official_profile() {
    let png_bytes = generate_texture_png(96, 96);
    let secret = b"Legacy entry points stay official";
    let opts = StegoOptions::default();

    let official_stego = embed_carrier(&png_bytes, secret, &opts).expect("embed legacy");
    assert_eq!(
        extract_carrier(&official_stego, &opts).expect("extract legacy"),
        secret
    );

    let private = stego_profile("acme-private-dialect-2026");
    let private_stego =
        embed_carrier_with_profile(&png_bytes, secret, &opts, &private).expect("embed private");
    assert!(
        extract_carrier(&private_stego, &opts).is_err(),
        "the legacy entry must not pick up a private dialect implicitly"
    );
}

/// The JPEG (UERD) engine must honour the private secret too. Skipped when the
/// sample corpus is not present, like the other JPEG lifecycle tests.
#[test]
fn test_jpeg_private_default_secret_isolation() {
    let candidate = fixture_file("carrier.jpg");
    let jpeg_bytes = fs::read(&candidate).expect("read carrier jpeg");
    let secret = b"Private JPEG dialect payload";

    let opts = StegoOptions {
        algorithm: Some("uerd".into()),
        ..Default::default()
    };
    let official = Profile::default();
    let private = stego_profile("acme-jpeg-dialect-2026");

    let stego = embed_carrier_with_profile(&jpeg_bytes, secret, &opts, &private)
        .expect("embed jpeg private");
    assert_eq!(
        extract_carrier_with_profile(&stego, &opts, &private).expect("private jpeg extract"),
        secret
    );
    assert!(
        matches!(
            extract_carrier_with_profile(&stego, &opts, &official),
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
    // The calibrated estimator is fitted on camera photos; the bundled fixture
    // is a 256x256 synthetic gradient whose quantization table makes the
    // reference dominated by IDCT rounding.
    //
    // `0003.jpg` is used because its full-capacity signal is unambiguous
    // (measured 0.70 against a 0.05 threshold); `0001.jpg` sits at 0.07, i.e.
    // just above the gate, and the random salt would make the test flaky.
    let Some(candidate) = find_corpus_file("images/jpg/0003.jpg") else {
        return;
    };
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
    let candidate = fixture_file("carrier.jpg");
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
    let candidate = fixture_file("carrier_q100.jpg");
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

/// V3 JPEG: the group size is derived from the embed-side slot budget and
/// travels in the superblock, so extraction needs no parameters at all -- and a
/// wider budget really does spread the same payload over more coefficients.
///
/// This is the contract that replaced "the extractor must repeat `--stc-u`":
/// the extractor is handed default options and still succeeds.
#[test]
fn test_jpeg_v3_slot_budget_controls_the_change_rate() {
    let candidate = fixture_file("carrier_photo.jpg");
    let jpeg_bytes = fs::read(&candidate).expect("read carrier jpeg");
    let payload = b"JPEG V3 ternary STC payload 2026!";
    let password = "JpegStcPassword#2026";

    let extract_opts = StegoOptions {
        algorithm: Some("uerd".into()),
        password: Some(password.into()),
        ..Default::default()
    };

    let mut changed_counts = Vec::new();
    let mut group_sizes = Vec::new();
    for budget in [2_000usize, 800_000] {
        let mut opts = StegoOptions {
            algorithm: Some("uerd".into()),
            password: Some(password.into()),
            ..Default::default()
        };
        opts.jpeg_params.stc_h = 8;
        opts.jpeg_params.slot_budget = Some(budget);

        let stego = embed_carrier(&jpeg_bytes, payload, &opts)
            .unwrap_or_else(|e| panic!("budget={budget}: embed failed: {e}"));
        assert_ne!(stego, jpeg_bytes, "budget={budget}: stego must differ");

        let extracted = extract_carrier(&stego, &extract_opts)
            .unwrap_or_else(|e| panic!("budget={budget}: extract failed: {e}"));
        assert_eq!(extracted, payload, "budget={budget}: payload mismatch");

        let before = dct_io::read_coefficients(&jpeg_bytes).expect("cover coefficients");
        let after = dct_io::read_coefficients(&stego).expect("stego coefficients");
        let mut changed = 0usize;
        for (cb, ca) in before.components[0]
            .blocks
            .iter()
            .zip(after.components[0].blocks.iter())
        {
            changed += cb.iter().zip(ca.iter()).filter(|(x, y)| x != y).count();
        }
        assert!(changed > 0, "budget={budget}: nothing was modified");
        // DC is never a target: the header digest depends on it.
        for (cb, ca) in before.components[0]
            .blocks
            .iter()
            .zip(after.components[0].blocks.iter())
        {
            assert_eq!(cb[0], ca[0], "budget={budget}: DC coefficient changed");
        }
        changed_counts.push(changed);

        let layout = strhide::stego::jpeg::engine::layout_for_payload(
            &jpeg_bytes,
            payload.len(),
            &opts.jpeg_params,
            &strhide::stego::format::DEFAULT_JPEG_FORMAT,
        )
        .expect("layout");
        group_sizes.push(layout.u);
    }

    assert!(
        group_sizes[0] < group_sizes[1],
        "the slot budget must control the group size: {group_sizes:?}"
    );
    assert!(
        changed_counts[1] < changed_counts[0],
        "a wider budget must change fewer coefficients: {changed_counts:?}"
    );
}

/// Tampering with the FeatureWord reserved bits in a v2 carrier must safely collapse to NoHiddenData.
#[test]
fn test_stego_v2_feature_word_tamper_fails_safely() {
    let png_bytes = generate_texture_png(128, 128);
    let opts = StegoOptions::default();
    let payload = b"secret payload testing feature word integrity";
    let stego = embed_carrier(&png_bytes, payload, &opts).expect("embed v2 stego");

    let slots = header_slots_of(&png_bytes, None);
    assert!(slots.len() >= 512);

    let mut img = decode_png(&stego).expect("decode");
    let ch = img.channels;
    let off = if ch >= 3 { 1 } else { 0 };

    // Tamper with a bit in the high reserved bytes of the feature word (slot index 256 + 128)
    let tamper_slot = slots[256 + 128];
    img.pixels[tamper_slot * ch + off] ^= 1;

    let tampered_bytes = encode_png(&img).expect("encode");
    let res = extract_carrier(&tampered_bytes, &opts);
    assert!(
        matches!(res, Err(strhide::errors::StrHideError::NoHiddenData(_))),
        "Tampered FeatureWord must yield NoHiddenData, got: {res:?}"
    );
}

#[test]
fn stego_domain_isolation_lifecycle() {
    let png = generate_texture_png(128, 128);
    let payload = b"cross-domain-isolation-integration-test";

    // 1. Profile domain isolation
    let prof_a = Profile::default().with_stego_domain("org.enterprise.vault-a");
    let prof_b = Profile::default().with_stego_domain("org.enterprise.vault-b");
    let prof_default = Profile::default();

    let opts = StegoOptions::default();
    let stego_a = embed_carrier_with_profile(&png, payload, &opts, &prof_a)
        .expect("embed with profile domain-a");

    // Matching profile extracts losslessly
    let rec_a = extract_carrier_with_profile(&stego_a, &opts, &prof_a)
        .expect("extract with matching profile domain-a");
    assert_eq!(rec_a, payload);

    // Mismatched profile (domain-b) fails with NoHiddenData
    let err_b = extract_carrier_with_profile(&stego_a, &opts, &prof_b);
    assert!(
        matches!(err_b, Err(strhide::errors::StrHideError::NoHiddenData(_))),
        "mismatched profile domain must fail"
    );

    // Default profile (no domain) fails with NoHiddenData
    let err_def = extract_carrier_with_profile(&stego_a, &opts, &prof_default);
    assert!(
        matches!(err_def, Err(strhide::errors::StrHideError::NoHiddenData(_))),
        "default profile on domain-isolated carrier must fail"
    );

    // 2. Options stego_domain overrides profile stego_domain
    let opts_override = StegoOptions {
        domain: Some("org.enterprise.vault-a".into()),
        ..Default::default()
    };
    // Even if prof_b is passed, opts_override wins
    let rec_override = extract_carrier_with_profile(&stego_a, &opts_override, &prof_b)
        .expect("options domain must override profile domain");
    assert_eq!(rec_override, payload);

    // 3. Password + domain isolation
    let opts_pwd_a = StegoOptions {
        password: Some("SharedPassword123".into()),
        domain: Some("org.enterprise.vault-a".into()),
        ..Default::default()
    };
    let stego_pwd_a =
        embed_carrier(&png, payload, &opts_pwd_a).expect("embed with password + domain");

    let rec_pwd_a =
        extract_carrier(&stego_pwd_a, &opts_pwd_a).expect("extract with same password + domain");
    assert_eq!(rec_pwd_a, payload);

    let opts_pwd_b = StegoOptions {
        password: Some("SharedPassword123".into()),
        domain: Some("org.enterprise.vault-b".into()),
        ..Default::default()
    };
    let err_pwd_b = extract_carrier(&stego_pwd_a, &opts_pwd_b);
    assert!(
        matches!(
            err_pwd_b,
            Err(strhide::errors::StrHideError::NoHiddenData(_))
        ),
        "same password with mismatched domain must fail"
    );
}

#[test]
fn stego_safety_level_and_enforcement_lifecycle() {
    use strhide::stego::{SafetyEnforcement, SafetyLevel, SafetyPolicy};

    let png = generate_texture_png(128, 128); // 16,384 pixels

    let cap_paranoid = probe_carrier_capacity(
        &png,
        &StegoOptions {
            safety: SafetyPolicy {
                level: SafetyLevel::Paranoid,
                ..SafetyPolicy::default()
            },
            ..Default::default()
        },
    )
    .expect("probe paranoid");

    let cap_high = probe_carrier_capacity(
        &png,
        &StegoOptions {
            safety: SafetyPolicy {
                level: SafetyLevel::High,
                ..SafetyPolicy::default()
            },
            ..Default::default()
        },
    )
    .expect("probe high");

    let cap_balanced = probe_carrier_capacity(
        &png,
        &StegoOptions {
            safety: SafetyPolicy {
                level: SafetyLevel::Balanced,
                ..SafetyPolicy::default()
            },
            ..Default::default()
        },
    )
    .expect("probe balanced");

    assert!(cap_paranoid.recommended_max_bytes <= cap_high.recommended_max_bytes);
    assert!(cap_high.recommended_max_bytes <= cap_balanced.recommended_max_bytes);
    assert_eq!(cap_high.safety_level, "high");
    assert_eq!(cap_high.safety_bpp_limit, 0.10);

    // Payload exceeding Paranoid tier
    let payload = vec![0x33; cap_balanced.recommended_max_bytes];

    // Enforced mode on Paranoid tier MUST reject
    let opts_enforced = StegoOptions {
        safety: SafetyPolicy {
            level: SafetyLevel::Paranoid,
            enforcement: SafetyEnforcement::Enforced,
        },
        ..Default::default()
    };
    let res_enforced = embed_carrier(&png, &payload, &opts_enforced);
    assert!(
        res_enforced.is_err(),
        "Enforced mode must reject payload exceeding safety tier"
    );

    // Advisory mode on Paranoid tier MUST succeed
    let opts_advisory = StegoOptions {
        safety: SafetyPolicy {
            level: SafetyLevel::Paranoid,
            enforcement: SafetyEnforcement::Advisory,
        },
        ..Default::default()
    };
    let res_advisory = embed_carrier(&png, &payload, &opts_advisory);
    assert!(
        res_advisory.is_ok(),
        "Advisory mode must not reject payload within physical capacity"
    );
    let stego = res_advisory.unwrap();
    let extracted = extract_carrier(&stego, &opts_advisory).expect("extract");
    assert_eq!(extracted, payload);
}
