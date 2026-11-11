use std::io::Write;

use flate2::Compression;
use flate2::write::ZlibEncoder;

use super::*;
use crate::stego::params::PngParams;
use crate::stego::png::cost::HillCostModel;

#[test]
fn trace_call_sites_do_not_format_eagerly() {
    // Verifies trace call sites pass `format_args!` rather than allocating eagerly with `format!`.
    let source = include_str!("engine.rs");
    // Split so this test's own source does not contain the needle.
    let eager_pattern = concat!("trace", "(&format!(");
    assert!(
        !source.contains(eager_pattern),
        "trace must receive format_args!, not an eagerly formatted String"
    );
}

/// Test-side credential shim: the pre-V4 tests pass `None` to mean the
/// profile's public fallback secret, which V4 expresses as a password
/// credential.
fn test_cred<'a>(password: Option<&'a str>) -> Credential<'a> {
    match password {
        Some(password) => Credential::Password(password),
        None => Credential::Password(crate::stego::envelope::PUBLIC_DEFAULT_SECRET),
    }
}

#[allow(clippy::too_many_arguments)]
fn embed_png(
    carrier_bytes: &[u8],
    payload: &[u8],
    password: Option<&str>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    safety: SafetyPolicy,
    freshness: Freshness,
    control: &Control<'_>,
) -> Result<Vec<u8>, StrHideError> {
    super::embed_png(
        carrier_bytes,
        payload,
        test_cred(password),
        domain,
        crate::stego::format::OFFICIAL_PNG_CIPHER
            .default_suite
            .as_u16(),
        &[],
        spatial,
        cost_model,
        params,
        safety,
        freshness,
        control,
    )
}

fn extract_png(
    carrier_bytes: &[u8],
    password: Option<&str>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    control: &Control<'_>,
) -> Result<Vec<u8>, StrHideError> {
    super::extract_png(
        carrier_bytes,
        test_cred(password),
        domain,
        spatial,
        cost_model,
        params,
        &ExtractParams::default(),
        control,
    )
    .map(Payload::into_bytes)
}

#[allow(clippy::too_many_arguments)]
fn probe_png_capacity(
    carrier_bytes: &[u8],
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    safety_level: crate::stego::SafetyLevel,
    password: Option<&str>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    super::probe_png_capacity(
        carrier_bytes,
        cost_model,
        params,
        safety_level,
        test_cred(password),
        domain,
        &[],
        spatial,
        control,
    )
}

/// Craft a PNG: IHDR + ancillary chunks + one IDAT + IEND, with the
/// given per-row filters applied to `pixels` (RGB, 8-bit).
fn craft_png(
    width: u32,
    height: u32,
    pixels: &[u8],
    row_filters: &[u8],
    ancillary: &[(&[u8; 4], &[u8])],
    idat_parts: usize,
) -> Vec<u8> {
    craft_png_at_level(
        width,
        height,
        pixels,
        row_filters,
        ancillary,
        idat_parts,
        Compression::default().level(),
    )
}

/// [`craft_png`] with an explicit zlib level, so the level-matching path
/// can be exercised against carriers written the way real tools write them.
fn craft_png_at_level(
    width: u32,
    height: u32,
    pixels: &[u8],
    row_filters: &[u8],
    ancillary: &[(&[u8; 4], &[u8])],
    idat_parts: usize,
    level: u32,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(2); // color type: RGB
    ihdr.push(0); // compression
    ihdr.push(0); // filter method
    ihdr.push(0); // interlace
    write_chunk(&mut out, b"IHDR", &ihdr).expect("IHDR");
    for (ty, body) in ancillary {
        write_chunk(&mut out, ty, body).expect("ancillary chunk");
    }
    let stride = width as usize * 3;
    let zero_row = vec![0u8; stride];
    let mut filtered = Vec::with_capacity((stride + 1) * height as usize);
    for (y, row) in pixels.chunks_exact(stride).enumerate() {
        let prev: &[u8] = if y == 0 {
            &zero_row
        } else {
            &pixels[(y - 1) * stride..y * stride]
        };
        filtered.push(row_filters[y]);
        filtered.extend_from_slice(&filter_row(prev, row, row_filters[y], 3));
    }
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(&filtered).expect("deflate");
    let idat = encoder.finish().expect("deflate finish");
    // Split the compressed stream into `idat_parts` IDAT chunks.
    let parts = idat_parts.max(1);
    let chunk_len = idat.len().div_ceil(parts);
    for piece in idat.chunks(chunk_len.max(1)) {
        write_chunk(&mut out, b"IDAT", piece).expect("IDAT");
    }
    write_chunk(&mut out, b"IEND", &[]).expect("IEND");
    out
}

/// Vertical gradient (constant along x): the ideal case for filter 2.
fn gradient_pixels(w: usize, h: usize) -> Vec<u8> {
    let mut px = vec![0u8; w * h * 3];
    for y in 0..h {
        let v = (y * 4) as u8;
        for x in 0..w {
            let i = (y * w + x) * 3;
            px[i] = v;
            px[i + 1] = v;
            px[i + 2] = v;
        }
    }
    px
}

/// Row-correlated noisy image: each row continues the previous one plus a
/// small deterministic jitter. Filter 2 removes the row trend; filter 0
/// has to entropy-code the full 0..250 spread -- the situation where
/// forcing filter 0 inflates the IDAT.
fn row_correlated_pixels(w: usize, h: usize) -> Vec<u8> {
    let mut px = vec![0u8; w * h * 3];
    for y in 0..h {
        for x in 0..w {
            let i = (y * w + x) * 3;
            let base = (x * 5 + y * 3) % 251;
            let jitter = (x * 31 + y * 17) % 7;
            let v = (base + jitter) as u8;
            px[i] = v;
            px[i + 1] = v;
            px[i + 2] = v;
        }
    }
    px
}

fn chunk_types(img: &RawImage) -> Vec<[u8; 4]> {
    img.chunks.iter().map(|c| c.ty).collect()
}

#[test]
fn decode_captures_ancillary_chunks_and_row_filters() {
    let (w, h) = (16usize, 16usize);
    let pixels = gradient_pixels(w, h);
    let bkgd = [0u8, 0, 0, 0, 0, 0]; // bKGD body for RGB
    let text = b"Comment\0crafted-for-test".to_vec();
    let gama = 45455u32.to_be_bytes();
    let png = craft_png(
        w as u32,
        h as u32,
        &pixels,
        &vec![2u8; h], // filter 2 (Up) everywhere
        &[(b"bKGD", &bkgd), (b"gAMA", &gama), (b"tEXt", &text)],
        1,
    );

    let img = decode_png(&png).expect("decode");
    assert_eq!(
        chunk_types(&img),
        vec![*b"IHDR", *b"bKGD", *b"gAMA", *b"tEXt", *b"IDAT", *b"IEND"]
    );
    assert_eq!(img.row_filters, vec![2u8; h]);
    assert_eq!(img.pixels, pixels, "pixels must decode identically");
}

#[test]
fn reencode_replays_chunks_and_filters() {
    let (w, h) = (16usize, 16usize);
    let pixels = gradient_pixels(w, h);
    let text = b"Comment\0crafted-for-test".to_vec();
    let png = craft_png(
        w as u32,
        h as u32,
        &pixels,
        &vec![2u8; h],
        &[(b"tEXt", &text)],
        1,
    );

    let img = decode_png(&png).expect("decode");
    let re = encode_png(&img).expect("encode");
    let img2 = decode_png(&re).expect("re-decode");
    assert_eq!(chunk_types(&img), chunk_types(&img2));
    assert_eq!(
        img.chunks, img2.chunks,
        "chunk bodies must be byte-identical"
    );
    assert_eq!(img2.row_filters, vec![2u8; h]);
    assert_eq!(img2.pixels, pixels);
}

#[test]
fn filter_preservation_keeps_idat_small() {
    // The regression that motivated chunk/filter passthrough: a smooth
    // carrier re-encoded with filter 0 on every row inflated by ~23% on
    // the real corpus sample.
    let (w, h) = (128usize, 128usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(
        w as u32,
        h as u32,
        &pixels,
        &vec![2u8; h],
        &[(b"tEXt", b"Comment\0noise".as_slice())],
        1,
    );

    let img = decode_png(&png).expect("decode");
    let preserved = encode_png(&img).expect("encode");

    // Same image, but with the recorded filters discarded (old behaviour).
    let mut flat = img.clone();
    flat.row_filters = Vec::new();
    let filter0 = encode_png(&flat).expect("encode");

    assert!(
        preserved.len() < filter0.len(),
        "preserved filters must not inflate: {} vs {} bytes",
        preserved.len(),
        filter0.len()
    );
    assert_eq!(
        decode_png(&preserved).expect("decode").pixels,
        pixels,
        "pixels must survive the filtered re-encode"
    );
}

/// v3 feature word: hyperparameters the extractor does not have to be
/// told about — non-default HILL windows, a non-power-of-two epsilon and
/// a non-default S-UNIWARD sigma must round-trip through the carrier
/// alone. Under v2 this silently returned `NoHiddenData` because the
/// extractor rebuilt the ranking with its own defaults.
#[test]
fn nondefault_hyperparameters_roundtrip_via_feature_word() {
    let (w, h) = (96usize, 96usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
    let payload = b"v3-hyperparameters";

    let hill_params = PngParams::default()
        .with_p1_window(5)
        .with_p2_window(7)
        // not a power of two: must be quantised on both ends
        .with_epsilon(1e-8);
    let stego = embed_png(
        &png,
        payload,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &hill_params,
        SafetyPolicy::default(),
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed with non-default HILL parameters");
    // The extractor passes *defaults*: the carrier is authoritative.
    let extracted = extract_png(
        &stego,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &PngParams::default(),
        &Control::none(),
    )
    .expect("extract rebuilds the ranking from the feature word");
    assert_eq!(extracted, payload);

    let mut suniward_params = PngParams::default();
    suniward_params
        .algorithm_options
        .insert("sigma".to_string(), 0.8);
    let stego = embed_png(
        &png,
        payload,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &crate::stego::png::cost::SuniwardCostModel,
        &suniward_params,
        SafetyPolicy::default(),
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed with non-default sigma");
    let extracted = extract_png(
        &stego,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &crate::stego::png::cost::SuniwardCostModel,
        &PngParams::default(),
        &Control::none(),
    )
    .expect("extract rebuilds sigma from the feature word");
    assert_eq!(extracted, payload);
}

#[test]
fn out_of_range_sigma_is_rejected_before_embedding() {
    // `sigma` is stored in the feature word as an f32. NaN, infinities and
    // values outside the supported range used to be written as-is, which
    // made the cost map unusable or made extraction read a different
    // number, so embedding succeeded but the payload could never be read.
    let mut params = PngParams::default();
    for bad in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        -1.0,
        1e300,
        0.05,
        11.0,
    ] {
        params.algorithm_options.insert("sigma".to_string(), bad);
        let err = params.validate().unwrap_err();
        assert!(
            err.to_string().contains("'sigma'"),
            "sigma={bad} must name the parameter: {err}"
        );
    }

    let (w, h) = (64usize, 64usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
    let payload = b"sigma-boundary";
    for sigma in [0.1, 1.0, 10.0] {
        let mut legal = PngParams::default();
        legal.algorithm_options.insert("sigma".to_string(), sigma);
        let stego = embed_png(
            &png,
            payload,
            None,
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &crate::stego::png::cost::SuniwardCostModel,
            &legal,
            SafetyPolicy::default(),
            Freshness::Random,
            &Control::none(),
        )
        .unwrap_or_else(|e| panic!("sigma={sigma} must embed: {e}"));
        let extracted = extract_png(
            &stego,
            None,
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &crate::stego::png::cost::SuniwardCostModel,
            &PngParams::default(),
            &Control::none(),
        )
        .unwrap_or_else(|e| panic!("sigma={sigma} must extract: {e}"));
        assert_eq!(extracted, payload, "sigma={sigma} must round-trip");
    }
}

#[test]
fn embed_extract_roundtrip_preserves_container() {
    let (w, h) = (64usize, 64usize);
    let pixels = row_correlated_pixels(w, h);
    let text = b"Comment\0roundtrip".to_vec();
    let exif = vec![0x45u8, 0x78, 0x69, 0x66, 0x00, 0x00]; // fake eXIf body
    let png = craft_png(
        w as u32,
        h as u32,
        &pixels,
        &vec![2u8; h],
        &[(b"tEXt", &text), (b"eXIf", &exif)],
        1,
    );

    let payload = b"container-fidelity-payload";
    let params = PngParams::default();
    let stego = embed_png(
        &png,
        payload,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        SafetyPolicy::default(),
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed");
    let extracted = extract_png(
        &stego,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        &Control::none(),
    )
    .expect("extract");
    assert_eq!(extracted, payload);

    let before = decode_png(&png).expect("decode");
    let after = decode_png(&stego).expect("decode stego");
    assert_eq!(chunk_types(&before), chunk_types(&after));
    assert_eq!(
        before.chunks, after.chunks,
        "every ancillary chunk must survive embedding"
    );
    // Only LSBs may move (in any channel position the engine touches).
    let changed = before
        .pixels
        .iter()
        .zip(after.pixels.iter())
        .filter(|(a, b)| a != b)
        .count();
    assert!(changed > 0, "embedding must modify the carrier");
    for (a, b) in before.pixels.iter().zip(after.pixels.iter()) {
        assert!(
            a.abs_diff(*b) <= 1,
            "a write moves a pixel by at most one: {a} -> {b}"
        );
        assert_eq!(
            a & 0xF8,
            b & 0xF8,
            "a write must stay inside the eight-value class: {a} -> {b}"
        );
    }
}

#[test]
fn stc_codec_roundtrips_and_stays_in_class() {
    let (w, h) = (96usize, 96usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(
        w as u32,
        h as u32,
        &pixels,
        &vec![2u8; h],
        &[(b"tEXt", b"Comment\x00stc".as_slice())],
        1,
    );

    let payload = b"stc-roundtrip-payload";
    let params = PngParams::default()
        .with_codec(StegoCodec::Stc)
        .with_stc_h(8);
    let stego = embed_png(
        &png,
        payload,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        SafetyPolicy::default(),
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed");

    // The codec travels in the header, so an extractor configured with Hamming
    // must still read the carrier correctly via header self-description.
    let extract_params = PngParams::default().with_codec(StegoCodec::Hamming);
    let extracted = extract_png(
        &stego,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &extract_params,
        &Control::none(),
    )
    .expect("extract");
    assert_eq!(extracted, payload, "STC must be self-describing");

    // Same selftest as the Hamming path: +/-1 inside the class, never more.
    let before = decode_png(&png).expect("decode");
    let after = decode_png(&stego).expect("decode stego");
    assert!(
        before.chunks == after.chunks,
        "container must survive STC embedding"
    );
    let changed = before
        .pixels
        .iter()
        .zip(after.pixels.iter())
        .filter(|(a, b)| a != b)
        .count();
    assert!(changed > 0, "embedding must modify the carrier");
    for (a, b) in before.pixels.iter().zip(after.pixels.iter()) {
        assert!(a.abs_diff(*b) <= 1, "move too large: {a} -> {b}");
        assert_eq!(a & 0xF8, b & 0xF8, "class left: {a} -> {b}");
    }
}

#[test]
fn exclusion_rate_off_the_permille_grid_roundtrips() {
    // The feature word can only carry integer permille, so the embedder has
    // to rank candidates with the same quantised rate the extractor will
    // reconstruct. Before the fix, 0.0123 wrote 12 permille but ranked with
    // 0.0123, and the payload became silently unreadable.
    let (w, h) = (96usize, 96usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
    let payload = b"permille-quantised-roundtrip";
    let params = PngParams::default().with_exclusion_percentile(0.0123);
    let stego = embed_png(
        &png,
        payload,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        SafetyPolicy::default(),
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed");
    let extracted = extract_png(
        &stego,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &PngParams::default(),
        &Control::none(),
    )
    .expect("extract");
    assert_eq!(extracted, payload, "the wire value must round-trip");
}

#[test]
fn bytes_after_iend_survive_a_round_trip() {
    // Producers append signatures or vendor trailers after IEND. The
    // decoder stops at IEND, so before `RawImage::tail` existed a re-encode
    // silently truncated them -- a lie for a format-preserving tool.
    let (w, h) = (32usize, 32usize);
    let pixels = row_correlated_pixels(w, h);
    let mut png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
    let trailer = b"\x00STRHIDE-TRAILER\xff\x00".to_vec();
    png.extend_from_slice(&trailer);

    let decoded = decode_png(&png).expect("decode");
    assert_eq!(decoded.tail, trailer, "decoder must keep the trailer");
    let reencoded = encode_png(&decoded).expect("encode");
    assert!(reencoded.ends_with(&trailer), "re-encode must put it back");

    let payload = b"tail-preserved-payload";
    let params = PngParams::default();
    let stego = embed_png(
        &png,
        payload,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        SafetyPolicy::default(),
        Freshness::Seeded([0x21; 32]),
        &Control::none(),
    )
    .expect("embed");
    assert!(
        stego.ends_with(&trailer),
        "the stego carrier must keep the trailer too"
    );
    let extracted = extract_png(
        &stego,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        &Control::none(),
    )
    .expect("extract");
    assert_eq!(extracted, payload);
}

#[test]
fn decode_rejects_a_chunk_whose_crc_no_longer_matches() {
    let img = RawImage {
        width: 4,
        height: 4,
        channels: 3,
        bit_depth: 8,
        color_type: 2,
        pixels: vec![10u8; 4 * 4 * 3],
        chunks: Vec::new(),
        idat_sizes: Vec::new(),
        row_filters: Vec::new(),
        idat_info: None,
        tail: Vec::new(),
    };
    let png = encode_png(&img).expect("encode");
    assert!(
        decode_png(&png).is_ok(),
        "the untouched carrier must decode"
    );

    // Flip one bit inside the IDAT body and leave its CRC alone -- exactly
    // what a truncated download or a byte-level tamper looks like.
    let mut pos = 8usize;
    let mut tampered = None;
    while pos + 12 <= png.len() {
        let len = u32::from_be_bytes([png[pos], png[pos + 1], png[pos + 2], png[pos + 3]]) as usize;
        if &png[pos + 4..pos + 8] == b"IDAT" && len > 0 {
            let mut copy = png.clone();
            copy[pos + 8] ^= 0x01;
            tampered = Some(copy);
            break;
        }
        pos += 12 + len;
    }
    let tampered = tampered.expect("the encoder must emit a non-empty IDAT");
    assert!(matches!(
        decode_png(&tampered),
        Err(StrHideError::CorruptedData(_))
    ));
}

#[test]
fn decode_rejects_structurally_impossible_chunks() {
    let sig: &[u8] = b"\x89PNG\r\n\x1a\n";

    // 1) A chunk before IHDR. `decode_png` reads width/height out of the
    //    header, so anything earlier means the stream is not a PNG.
    let mut out_of_order = Vec::from(sig);
    let text = PngChunk {
        ty: *b"tEXt",
        data: b"k\0v".to_vec(),
    };
    write_chunk(&mut out_of_order, &text.ty, &text.data).unwrap();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&4u32.to_be_bytes());
    ihdr.extend_from_slice(&4u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    write_chunk(&mut out_of_order, b"IHDR", &ihdr).unwrap();
    assert!(matches!(
        decode_png(&out_of_order),
        Err(StrHideError::CorruptedData(_))
    ));

    // 2) IHDR with a 14-byte body.
    let mut long_ihdr = Vec::from(sig);
    let mut body = ihdr.clone();
    body.push(0);
    write_chunk(&mut long_ihdr, b"IHDR", &body).unwrap();
    assert!(matches!(
        decode_png(&long_ihdr),
        Err(StrHideError::CorruptedData(_))
    ));

    // 3) A compression method other than 0.
    let mut bad_method = Vec::from(sig);
    let mut body = ihdr.clone();
    body[10] = 1;
    write_chunk(&mut bad_method, b"IHDR", &body).unwrap();
    assert!(matches!(
        decode_png(&bad_method),
        Err(StrHideError::UnsupportedFormat(_))
    ));

    // 4) A declared length over the ceiling is rejected from the header
    //    alone, without waiting for (or allocating) the body.
    let mut huge = Vec::from(sig);
    huge.extend_from_slice(&0x7FFF_FFFFu32.to_be_bytes());
    huge.extend_from_slice(b"IDAT");
    assert!(matches!(
        decode_png(&huge),
        Err(StrHideError::CorruptedData(_))
    ));

    // 5) A non-alphabetic chunk type.
    let mut bad_type = Vec::from(sig);
    bad_type.extend_from_slice(&0u32.to_be_bytes());
    bad_type.extend_from_slice(b"IH1R");
    bad_type.extend_from_slice(&[0, 0, 0, 0]);
    assert!(matches!(
        decode_png(&bad_type),
        Err(StrHideError::CorruptedData(_))
    ));
}

#[test]
fn handbuilt_image_without_chunks_still_encodes() {
    let img = RawImage {
        width: 4,
        height: 4,
        channels: 3,
        bit_depth: 8,
        color_type: 2,
        pixels: vec![10u8; 4 * 4 * 3],
        chunks: Vec::new(),
        idat_sizes: Vec::new(),
        row_filters: Vec::new(),
        idat_info: None,
        tail: Vec::new(),
    };
    let png = encode_png(&img).expect("encode");
    let decoded = decode_png(&png).expect("decode");
    assert_eq!(decoded.pixels, img.pixels);
    assert!(decoded.row_filters.iter().all(|&f| f == 0));
}

#[test]
fn multi_idat_chunking_is_preserved() {
    // A carrier whose IDAT run is split into several chunks (typical for
    // large encoders, e.g. 32 KiB per IDAT) must keep the same chunk
    // count after an embed round-trip.
    let (w, h) = (96usize, 96usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(
        w as u32,
        h as u32,
        &pixels,
        &vec![2u8; h],
        &[(b"tEXt", b"Comment\x00split".as_slice())],
        4,
    );

    let img = decode_png(&png).expect("decode");
    let orig_idat_count = chunk_types(&img).iter().filter(|&&t| t == *b"IDAT").count();
    assert_eq!(orig_idat_count, 4, "crafted carrier must have 4 IDATs");
    assert_eq!(img.idat_sizes.len(), 4);

    let re = encode_png(&img).expect("encode");
    let img2 = decode_png(&re).expect("re-decode");
    assert_eq!(chunk_types(&img), chunk_types(&img2));
    assert_eq!(img2.pixels, pixels);
    assert_eq!(
        img2.idat_sizes.len(),
        4,
        "IDAT chunk count must survive re-encoding"
    );

    // And through a full embed/extract round-trip.
    let params = PngParams::default();
    let stego = embed_png(
        &png,
        b"split-idat",
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        SafetyPolicy::default(),
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed");
    let after = decode_png(&stego).expect("decode stego");
    assert_eq!(
        after.idat_sizes.len(),
        4,
        "embedding must not collapse the IDAT run"
    );
    let extracted = extract_png(
        &stego,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        &Control::none(),
    )
    .expect("extract");
    assert_eq!(extracted, b"split-idat");
}

/// Group size `u` must be self-describing and must actually change fewer
/// pixels per bit: two independent properties that a whole-matrix change can
/// break in opposite directions.
#[test]
fn stc_group_sizes_roundtrip_and_trade_capacity_for_fewer_changes() {
    let (w, h) = (128usize, 128usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(
        w as u32,
        h as u32,
        &pixels,
        &vec![2u8; h],
        &[(b"tEXt", b"Comment\x00stc-groups".as_slice())],
        1,
    );
    let payload = b"stc-group-roundtrip-payload-2026";
    let bits = payload.len() * 8;

    let mut change_rates = Vec::new();
    let mut capacities = Vec::new();
    for stc_u in [1u8, 2, 3] {
        let params = PngParams::default()
            .with_codec(StegoCodec::Stc)
            .with_stc_h(8)
            .with_stc_u(stc_u);
        // Seeded, not random: the salt drives the slot permutation and the
        // trellis columns, so a random draw left the change counts (and
        // this test's outcome) to luck. Same inputs now give the same file.
        let stego = embed_png(
            &png,
            payload,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            SafetyPolicy::default(),
            Freshness::Seeded([0x5A; 32]),
            &Control::none(),
        )
        .unwrap_or_else(|e| panic!("u={stc_u}: embed failed: {e}"));

        // The extractor still defaults to Hamming: `u` and `h` must arrive
        // through the header.
        let extracted = extract_png(
            &stego,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &PngParams::default(),
            &Control::none(),
        )
        .unwrap_or_else(|e| panic!("u={stc_u}: extract failed: {e}"));
        assert_eq!(extracted, payload, "u={stc_u}: must be self-describing");

        let before = decode_png(&png).expect("decode");
        let after = decode_png(&stego).expect("decode stego");
        let changed = before
            .pixels
            .iter()
            .zip(after.pixels.iter())
            .filter(|(a, b)| a != b)
            .count();
        for (a, b) in before.pixels.iter().zip(after.pixels.iter()) {
            assert!(a.abs_diff(*b) <= 1, "u={stc_u}: move too large: {a} -> {b}");
            assert_eq!(a & 0xF8, b & 0xF8, "u={stc_u}: class left: {a} -> {b}");
        }
        change_rates.push(changed as f64 / bits as f64);

        let cap = probe_png_capacity(
            &png,
            &HillCostModel,
            &params,
            crate::stego::SafetyLevel::High,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &Control::none(),
        )
        .expect("capacity probe");
        capacities.push(cap.max_raw_payload_bytes);
    }

    // u=2 vs u=3 differ by only a few percent on this payload, too fine to
    // pin down here -- that comparison lives in the trellis test
    // (`coding::stc::tests::larger_groups_lower_the_change_rate`).
    assert!(
        change_rates[1] < change_rates[0] * 0.85,
        "u=2 must cut the change count per bit: {change_rates:?}"
    );
    assert!(
        change_rates[2] < change_rates[0] * 0.85,
        "u=3 must cut the change count per bit: {change_rates:?}"
    );
    assert!(
        capacities[0] > capacities[1] && capacities[1] > capacities[2],
        "capacity must fall as u grows: {capacities:?}"
    );
}

#[test]
fn auto_codec_adaptive_selection_roundtrips() {
    let (w, h) = (128usize, 128usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);

    let auto_params = PngParams::default();
    assert_eq!(auto_params.codec, StegoCodec::Auto);

    // Light payload: automatically selects STC u=3
    let light_payload = b"short-auto-payload";
    let stego_light = embed_png(
        &png,
        light_payload,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &auto_params,
        SafetyPolicy::default(),
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed light");
    let rec_light = extract_png(
        &stego_light,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &PngParams::default(),
        &Control::none(),
    )
    .expect("extract light");
    assert_eq!(rec_light, light_payload);

    // Verify that capacity probe reports recommended bytes anchored to high-stealth
    let cap = probe_png_capacity(
        &png,
        &HillCostModel,
        &auto_params,
        crate::stego::SafetyLevel::High,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &Control::none(),
    )
    .expect("probe");
    assert!(cap.recommended_max_bytes > 0);
    assert!(cap.recommended_max_bytes <= cap.max_raw_payload_bytes / 2);
}

/// Colour types 0/2 use `tRNS` as a transparent colour key: every pixel
/// equal to the key is fully transparent, so a class-internal `±1` on one of
/// them makes it opaque. The engine used to keep the chunk verbatim and embed
/// anyway, i.e. visibly damage a carrier it promised to preserve.
#[test]
fn trns_colour_key_is_refused() {
    let (w, h) = (32usize, 32usize);
    let pixels = vec![0x80u8; w * h * 3];
    // Six bytes: the RGB triple that is fully transparent.
    let key = [0u8, 0x80, 0, 0x80, 0, 0x80];
    let png = craft_png(
        w as u32,
        h as u32,
        &pixels,
        &vec![0u8; h],
        &[(b"tRNS", &key)],
        1,
    );

    match decode_png(&png) {
        Ok(_) => panic!("a tRNS colour key must be refused, not embedded into"),
        Err(StrHideError::UnsupportedFormat(msg)) => {
            assert!(msg.contains("tRNS"), "error must name the chunk: {msg}");
        }
        Err(other) => panic!("unexpected error kind: {other}"),
    }
}

/// The budget must be checked before trellis allocation: 64 MP RGB with
/// a 1.5e8-slot body would allocate tens of GiB for bitmap alone.
/// The spatial cap (`MAX_PNG_PIXELS`) alone does not bound it.
#[test]
fn pipeline_budget_rejects_oversized_trellis_work() {
    let total_pixels = 64 * 1024 * 1024;

    assert!(check_pipeline_budget(total_pixels, 1_000_000, Some(8)).is_ok());
    assert!(
        check_pipeline_budget(total_pixels, 150_000_000, Some(8)).is_err(),
        "a 1.5e8-slot STC solve must be refused, not attempted"
    );
    // The same slot count is affordable for Hamming: no bitmap.
    assert!(check_pipeline_budget(total_pixels, 50_000_000, None).is_ok());

    let stc = max_body_slots_within_pipeline(total_pixels, Some(8));
    let hamming = max_body_slots_within_pipeline(total_pixels, None);
    assert!(stc < 150_000_000);
    assert!(
        stc < hamming,
        "the bitmap must cost slots: {stc} vs {hamming}"
    );
}

/// Verifies that probe `max_raw_payload_bytes` never exceeds what the pipeline budget accepts.
#[test]
fn probe_capacity_never_exceeds_pipeline_budget() {
    let params = PngParams::default();
    let total_pixels = 8192 * 7680; // 62,914,560
    let pool_green = 40_000_000usize;
    let pool_rgb = Some(99_082_944usize); // test carrier pool size

    // The exact size the pre-fix probe advertised: slots fit the pool, but
    // the STC working set does not fit the budget.
    assert!(
        !body_payload_fits(&params, pool_green, pool_rgb, 12_385_345, total_pixels)
            .expect("fits check"),
        "a payload whose solve needs ~9 GiB must not be advertised"
    );

    let max = max_raw_payload_for_pools(&params, pool_green, pool_rgb, total_pixels)
        .expect("max raw payload");
    assert!(max > 0, "the carrier still holds a large payload: {max}");
    assert!(max < 12_385_345, "budget clamps the advertised max: {max}");

    // The advertised maximum must pass the same budget gate the embedder
    // enforces, under the same codec/u resolution.
    let bits = (max + crate::stego::envelope::BODY_OVERHEAD) * 8;
    let (codec, u) = crate::stego::coding::auto_select_codec(99_082_944, bits);
    let slots = crate::stego::coding::slots_for_codec(bits, codec, params.stc_h, u).expect("slots");
    let trellis_h = match codec {
        StegoCodec::Hamming => None,
        _ => Some(params.stc_h),
    };
    check_pipeline_budget(total_pixels, slots, trellis_h)
        .expect("advertised maximum must pass the embedder's budget gate");
}

/// G1 regression for small carriers: the budget clamp must not shrink a
/// carrier whose working set is far below the budget (pool-limited, not
/// budget-limited).
#[test]
fn probe_capacity_stays_pool_limited_below_the_budget() {
    let params = PngParams::default();
    let total_pixels = 600 * 600;
    let pool_green = 100_000usize;
    let pool_rgb = Some(250_000usize);

    let max = max_raw_payload_for_pools(&params, pool_green, pool_rgb, total_pixels)
        .expect("max raw payload");
    assert!(max > 0);
    assert!(body_payload_fits(&params, pool_green, pool_rgb, max, total_pixels).expect("fits"));
    assert!(
        !body_payload_fits(&params, pool_green, pool_rgb, max + 1, total_pixels).expect("fits"),
        "max + 1 must not fit, by definition of the binary search"
    );
}

/// Verifies that IDAT-only recompression preserves payload readability.
#[test]
fn idat_only_recompression_keeps_payload_readable() {
    let (w, h) = (96usize, 96usize);
    let pixels = row_correlated_pixels(w, h);
    let text = b"Comment\0keep-me".to_vec();
    let png = craft_png(
        w as u32,
        h as u32,
        &pixels,
        &vec![2u8; h],
        &[(b"tEXt", &text)],
        1,
    );
    let params = PngParams::default();
    let payload = b"re-encode me".to_vec();

    let stego = embed_png(
        &png,
        &payload,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        SafetyPolicy::default(),
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed");

    let img = decode_png(&stego).expect("decode stego");
    let reencoded = encode_png(&img).expect("IDAT-only recompression");
    let out = extract_png(
        &reencoded,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        &Control::none(),
    )
    .expect("payload must survive an IDAT-only recompression");
    assert_eq!(out, payload);
}

/// Verifies that ancillary chunk changes (e.g. metadata edits via exiftool/tinypng)
/// leave the stego payload intact and readable.
#[test]
fn ancillary_chunk_change_keeps_payload_readable() {
    let (w, h) = (96usize, 96usize);
    let pixels = row_correlated_pixels(w, h);
    let text = b"Comment\0original".to_vec();
    let png = craft_png(
        w as u32,
        h as u32,
        &pixels,
        &vec![2u8; h],
        &[(b"tEXt", &text)],
        1,
    );
    let params = PngParams::default();
    let payload = b"metadata-independent".to_vec();

    let stego = embed_png(
        &png,
        &payload,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        SafetyPolicy::default(),
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed");

    let mut img = decode_png(&stego).expect("decode stego");
    // Same pixels, same geometry: only the metadata stream changes.
    let chunk = img
        .chunks
        .iter_mut()
        .find(|c| c.ty == *b"tEXt")
        .expect("tEXt chunk present");
    chunk.data = b"Comment\0edited-afterwards".to_vec();
    // Something an ICC-aware tool might also add while it is there.
    img.chunks.push(PngChunk {
        ty: *b"iCCP",
        data: b"profile\0\0fake-icc".to_vec(),
    });
    let reencoded = encode_png(&img).expect("re-encode");

    let out = extract_png(
        &reencoded,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        &Control::none(),
    )
    .expect("metadata edits must not destroy the payload");
    assert_eq!(out, payload);
}

/// The narrowed salt still has to bind something: geometry and palette are
/// part of the carrier's identity, so changing them must break locators.
#[test]
fn pre_salt_ignores_ancillary_chunks_but_binds_geometry_and_palette() {
    let (w, h) = (16usize, 16usize);
    let pixels = row_correlated_pixels(w, h);
    let base = decode_png(&craft_png(
        w as u32,
        h as u32,
        &pixels,
        &vec![0u8; h],
        &[(b"tEXt", b"K\0v")],
        1,
    ))
    .expect("decode");
    let spatial = crate::stego::format::OFFICIAL_PNG_FORMAT;
    let reference = png_pre_salt(&base, &spatial);

    // 1. Metadata only: same salt.
    let mut metadata_edit = base.clone();
    metadata_edit
        .chunks
        .iter_mut()
        .find(|c| c.ty == *b"tEXt")
        .expect("tEXt")
        .data = b"K\0different".to_vec();
    metadata_edit.chunks.push(PngChunk {
        ty: *b"tIME",
        data: vec![7, 230, 11, 7, 12, 0, 0],
    });
    assert_eq!(png_pre_salt(&metadata_edit, &spatial), reference);

    // 2. Geometry: different salt, or the locator would survive a crop.
    let mut resized = base.clone();
    resized.width -= 1;
    assert_ne!(png_pre_salt(&resized, &spatial), reference);

    // 3. Palette: different salt.
    let mut repalettised = base.clone();
    repalettised.chunks.insert(
        1,
        PngChunk {
            ty: *b"PLTE",
            data: vec![0, 0, 0, 255, 255, 255],
        },
    );
    assert_ne!(png_pre_salt(&repalettised, &spatial), reference);
}

/// The tier table is what hosts read instead of re-deriving the budget, so
/// it has to agree with `recommended_max_bytes` for the probed tier and be
/// ordered strictest-to-loosest. The Tauri capacity card used to keep its
/// own copy of these formulas and drifted (it matched `info.format` against
/// "hevc"/"mp4", which no engine ever reports).
#[test]
fn tier_limits_agree_with_probe_and_are_monotonic() {
    use crate::stego::SafetyLevel;

    let (w, h) = (128usize, 128usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
    let params = PngParams::default();

    for level in SafetyLevel::ALL {
        let cap = probe_png_capacity(
            &png,
            &HillCostModel,
            &params,
            level,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &Control::none(),
        )
        .expect("probe");

        assert_eq!(
            cap.tier_limit(level),
            cap.recommended_max_bytes,
            "probed tier {level:?} must match its slot in the table"
        );
        assert!(
            cap.tier_limit(SafetyLevel::Paranoid) <= cap.tier_limit(SafetyLevel::High)
                && cap.tier_limit(SafetyLevel::High) <= cap.tier_limit(SafetyLevel::Balanced),
            "tiers must widen from paranoid to balanced: {:?}",
            cap.tier_limits
        );
    }
}

/// The probe's answer must be reachable by the embedder: they have to agree
/// on the slot plan, including the credential-keyed header permutation.
/// This is the regression guard for the drift between the two.
#[test]
fn probe_capacity_is_reachable_by_embed() {
    let (w, h) = (128usize, 128usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
    let params = PngParams::default();

    for password in [None, Some("pw"), Some("a-completely-different-password")] {
        let cap = probe_png_capacity(
            &png,
            &HillCostModel,
            &params,
            crate::stego::SafetyLevel::Balanced,
            password,
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &Control::none(),
        )
        .expect("probe");
        assert!(cap.max_raw_payload_bytes > 0);
        // Noise does not compress, so this exercises the raw boundary that
        // the capacity accounting claims. The probe and the embedder now
        // share `body_payload_fits`, so the value must be exactly reachable.
        let payload = noise_payload(cap.max_raw_payload_bytes);
        let stego = embed_png(
            &png,
            &payload,
            password,
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            SafetyPolicy::default(),
            Freshness::Random,
            &Control::none(),
        )
        .unwrap_or_else(|e| {
            panic!(
                "password {password:?}: probe reported {} bytes fit but embed failed: {e}",
                payload.len()
            )
        });
        let extracted = extract_png(
            &stego,
            password,
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            &Control::none(),
        )
        .expect("payload at the advertised capacity must be readable");
        assert_eq!(extracted, payload);

        let over = noise_payload(cap.max_raw_payload_bytes + 1);
        let rejected = embed_png(
            &png,
            &over,
            password,
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            SafetyPolicy::default(),
            Freshness::Random,
            &Control::none(),
        );
        assert!(
            rejected.is_err(),
            "password {password:?}: capacity+1 must not fit"
        );
    }
}

#[test]
fn spatial_stego_domain_isolation_e2e() {
    let (w, h) = (128usize, 128usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);

    let params = PngParams::default();
    let payload = b"cross-domain-isolation-test";

    // Embed under domain "finance.sec"
    let stego = embed_png(
        &png,
        payload,
        Some("shared-pwd"),
        Some("finance.sec"),
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        SafetyPolicy::default(),
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed with domain");

    // Extract with matching domain succeeds
    let recovered = extract_png(
        &stego,
        Some("shared-pwd"),
        Some("finance.sec"),
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        &Control::none(),
    )
    .expect("extract with same domain");
    assert_eq!(recovered, payload);

    // Extract with default domain (None) fails
    let err_default = extract_png(
        &stego,
        Some("shared-pwd"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        &Control::none(),
    );
    assert!(
        matches!(err_default, Err(StrHideError::NoHiddenData(_))),
        "extracting with default domain must fail as NoHiddenData"
    );

    // Extract with different domain fails
    let err_other = extract_png(
        &stego,
        Some("shared-pwd"),
        Some("hr.records"),
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        &Control::none(),
    );
    assert!(
        matches!(err_other, Err(StrHideError::NoHiddenData(_))),
        "extracting with different domain must fail as NoHiddenData"
    );
}

#[test]
fn safety_tier_probe_and_enforcement() {
    use crate::stego::params::{SafetyEnforcement, SafetyLevel};

    let (w, h) = (128usize, 128usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);

    let cap_paranoid = probe_png_capacity(
        &png,
        &HillCostModel,
        &PngParams::default(),
        SafetyLevel::Paranoid,
        Some("test-pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &Control::none(),
    )
    .expect("probe paranoid");
    let cap_high = probe_png_capacity(
        &png,
        &HillCostModel,
        &PngParams::default(),
        SafetyLevel::High,
        Some("test-pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &Control::none(),
    )
    .expect("probe high");
    let cap_balanced = probe_png_capacity(
        &png,
        &HillCostModel,
        &PngParams::default(),
        SafetyLevel::Balanced,
        Some("test-pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &Control::none(),
    )
    .expect("probe balanced");

    assert!(
        cap_paranoid.recommended_max_bytes <= cap_high.recommended_max_bytes,
        "Paranoid <= High"
    );
    assert!(
        cap_high.recommended_max_bytes <= cap_balanced.recommended_max_bytes,
        "High <= Balanced"
    );

    // Test enforcement: the policy is a call argument now, not a params field.
    let enforced = SafetyPolicy::default()
        .with_level(SafetyLevel::Paranoid)
        .with_enforcement(SafetyEnforcement::Enforced);

    // Oversize for Paranoid
    let large_payload = vec![0x42; cap_balanced.recommended_max_bytes];
    let res = embed_png(
        &png,
        &large_payload,
        Some("test-pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &PngParams::default(),
        enforced,
        Freshness::Random,
        &Control::none(),
    );
    assert!(
        res.is_err(),
        "Enforced safety policy must reject oversized payload"
    );

    // Same payload with Advisory succeeds
    let ok_res = embed_png(
        &png,
        &large_payload,
        Some("test-pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &PngParams::default(),
        SafetyPolicy::default(),
        Freshness::Random,
        &Control::none(),
    );
    assert!(
        ok_res.is_ok(),
        "Advisory safety policy must not block embedding"
    );
}

/// Incompressible bytes: the envelope deflates the payload, so a repeated
/// byte pattern would shrink to a fraction of its size and never exercise
/// the capacity ceiling.
fn noise_payload(len: usize) -> Vec<u8> {
    let mut s = 0x1234_5678u32;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        out.push((s & 0xFF) as u8);
    }
    out
}

/// The zlib header is captured at decode time: `FLEVEL` and the IDAT total.
///
/// The end-to-end size behaviour is not asserted here because the writer's
/// deflate backend (miniz) does not reproduce another tool's level 1 byte
/// count -- on a synthetic fixture it can be twice as good as zlib's. The
/// decision is covered by [`level_choice_follows_the_measured_size`], and
/// the real-corpus effect is measured separately.
#[test]
fn decode_captures_the_zlib_header() {
    let (w, h) = (32usize, 32usize);
    let pixels = row_correlated_pixels(w, h);
    for (level, flevel) in [(1u32, 0u8), (6, 2), (9, 3)] {
        let png = craft_png_at_level(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1, level);
        let img = decode_png(&png).expect("decode");
        let info = img.idat_info.expect("idat header must be captured");
        assert_eq!(
            info.flevel, flevel,
            "level {level} must map to FLEVEL {flevel}"
        );
        assert_eq!(info.orig_len, img.idat_sizes.iter().sum::<usize>());
    }
    // A hand-built image carries no hint and must encode at the default.
    let handbuilt = RawImage {
        width: 4,
        height: 4,
        channels: 3,
        bit_depth: 8,
        color_type: 2,
        pixels: vec![10u8; 4 * 4 * 3],
        chunks: Vec::new(),
        idat_sizes: Vec::new(),
        row_filters: Vec::new(),
        idat_info: None,
        tail: Vec::new(),
    };
    assert!(!encode_png(&handbuilt).expect("encode").is_empty());
}

/// The level decision itself: whichever candidate matches the source length
/// wins, and a carrier without an `IdatInfo` keeps the default level.
#[test]
fn level_choice_follows_the_measured_size() {
    // Repetitive text-like rows: level 1 and level 6 differ by a lot, which
    // is what makes the two candidates distinguishable at all.
    let (row_len, height) = (48usize, 48usize);
    let mut data = Vec::new();
    for y in 0..height {
        for x in 0..row_len {
            data.push(((x * 7 + y * 3) % 61 + 40) as u8);
        }
    }
    let fast = deflate_len(&data, 1);
    let default = deflate_len(&data, 6);
    assert!(fast > default, "fixture must separate the two levels");

    let pick = |orig: usize| {
        choose_deflate_level(
            &data,
            row_len,
            height,
            Some(IdatInfo {
                flevel: 0,
                orig_len: orig,
            }),
        )
        .0
    };
    assert_eq!(pick(fast), 1, "a fast-compressed source must pick level 1");
    assert_eq!(pick(default), 6, "a default-compressed source must pick 6");

    // No header hint: default level, no probing.
    let (level, projected) = choose_deflate_level(&data, row_len, height, None);
    assert_eq!(level, Compression::default().level());
    assert_eq!(projected, [0, 0]);
}

/// A payload that fits one channel must keep the historical layout: only
/// green changes. This is what makes the single-channel path bit-compatible
/// with everything measured before multi-channel existed.
#[test]
fn single_channel_mode_leaves_red_and_blue_untouched() {
    let (w, h) = (128usize, 128usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
    let params = PngParams::default();
    let payload = b"single-channel-layout";
    let stego = embed_png(
        &png,
        payload,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        SafetyPolicy::default(),
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed");
    let back = extract_png(
        &stego,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        &Control::none(),
    )
    .expect("extract");
    assert_eq!(back, payload);

    let before = decode_png(&png).expect("decode");
    let after = decode_png(&stego).expect("decode stego");
    let mut per_channel = [0usize; 3];
    for (i, (a, b)) in before.pixels.iter().zip(after.pixels.iter()).enumerate() {
        if a != b {
            per_channel[i % 3] += 1;
        }
    }
    assert!(per_channel[1] > 0, "green must carry the payload");
    assert_eq!(
        (per_channel[0], per_channel[2]),
        (0, 0),
        "a small payload must not touch red/blue: {per_channel:?}"
    );
}

/// Exceeding the single-channel pool must switch to RGB, round-trip, and
/// actually use the extra channels.
#[test]
fn three_channel_mode_roundtrips_at_full_capacity() {
    let (w, h) = (192usize, 192usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
    let params = PngParams::default();
    let cap = probe_png_capacity(
        &png,
        &HillCostModel,
        &params,
        crate::stego::SafetyLevel::Balanced,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &Control::none(),
    )
    .expect("probe");

    // The probe reports the three-channel ceiling, so this payload can only
    // fit with `ChannelMode::Rgb`.
    let payload = noise_payload(cap.max_raw_payload_bytes);
    let stego = embed_png(
        &png,
        &payload,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        SafetyPolicy::default(),
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed at the reported ceiling");
    let back = extract_png(
        &stego,
        Some("pw"),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        &Control::none(),
    )
    .expect("extract");
    assert_eq!(back, payload, "three-channel payload must round-trip");

    let before = decode_png(&png).expect("decode");
    let after = decode_png(&stego).expect("decode stego");
    let mut per_channel = [0usize; 3];
    for (i, (a, b)) in before.pixels.iter().zip(after.pixels.iter()).enumerate() {
        if a == b {
            continue;
        }
        assert!(a.abs_diff(*b) <= 1, "move too large: {a} -> {b}");
        assert_eq!(a & 0xF8, b & 0xF8, "class left: {a} -> {b}");
        per_channel[i % 3] += 1;
    }
    assert!(
        per_channel.iter().all(|&n| n > 0),
        "three-channel mode must write all three channels: {per_channel:?}"
    );
}

/// Verifies that RGB body slots filter each channel while sharing the candidate pool.
#[test]
fn rgb_body_slots_filter_each_channel_but_share_the_green_candidate_pool() {
    let image = RawImage {
        width: 4,
        height: 1,
        channels: 3,
        bit_depth: 8,
        color_type: 2,
        pixels: vec![
            0, 100, 100, // R ineligible, B eligible
            100, 0, 100, // green ineligible: whole pixel is not a candidate
            100, 100, 0, // R eligible, B ineligible
            0, 0, 0, // nothing eligible
        ],
        chunks: Vec::new(),
        idat_sizes: Vec::new(),
        row_filters: vec![0],
        idat_info: None,
        tail: Vec::new(),
    };

    // Pixel 1 carries legal R/B values but fails the green precondition,
    // so it never enters the candidate pool (the reported "miss").
    assert_eq!(header_pool(&image), vec![0, 2]);

    let costs = vec![0.0; image.width as usize];
    let seed = [7u8; 32];
    // permutation id 0, then exclusion permille 0 (keep every candidate).
    let plan = SlotPlan::build(&image, &costs, &seed, 0, 0).expect("plan");
    assert_eq!(plan.candidates, vec![0, 2]);

    // Both candidates are header pixels, so their green slots are
    // reserved; only the per-channel-eligible R/B slots remain.
    let slots = plan.body_slots_upto(&image, 0, ChannelMode::Rgb, usize::MAX);
    assert_eq!(slots, vec![2, 6], "only the eligible R/B slots are used");
    for slot in slots {
        assert!(
            (SPATIAL_ELIGIBLE_MIN..=SPATIAL_ELIGIBLE_MAX).contains(&image.pixels[slot]),
            "every body slot must stay class-interior"
        );
    }
}

/// The smooth-area cut is integer arithmetic on the wire permille.
///
/// `WIRE_SPEC_CONTENT §13.11.3` fixes `allowed = n * (1000 - p) / 1000`.
/// The previous `n * (1.0 - p/1000.0)` rounds in the last bit and lands one
/// element short exactly when the true quotient is an integer: with
/// `p = 900‰` and `n = 1000` it selects 99 candidates instead of 100, so a
/// reader following the spec would rebuild a different body pool.
#[test]
fn exclusion_cut_uses_integer_arithmetic() {
    let w = 1000usize;
    let image = RawImage {
        width: w as u32,
        height: 1,
        bit_depth: 8,
        color_type: 0,
        channels: 1,
        pixels: vec![128u8; w],
        chunks: Vec::new(),
        idat_sizes: Vec::new(),
        row_filters: Vec::new(),
        idat_info: None,
        tail: Vec::new(),
    };
    let costs = vec![0.0f64; w];
    let seed = [9u8; 32];

    // 900‰ excluded, 1000 eligible -> 100 candidates (not 99).
    let plan = SlotPlan::build(&image, &costs, &seed, 0, 900).expect("plan");
    assert_eq!(plan.candidates.len(), 100);

    // Degenerate end: nothing excluded keeps every eligible pixel.
    let plan = SlotPlan::build(&image, &costs, &seed, 0, 0).expect("plan");
    assert_eq!(plan.candidates.len(), 1000);

    // The helper is the inverse of the header field, for every value it can carry.
    for permille in 0..=900u16 {
        assert_eq!(exclusion_permille(f64::from(permille) / 1000.0), permille);
    }
}

#[test]
fn unknown_channel_modes_are_rejected() {
    assert_eq!(ChannelMode::from_wire(0), Some(ChannelMode::Green));
    assert_eq!(ChannelMode::from_wire(1), Some(ChannelMode::Rgb));
    for bad in [2u8, 3, 255] {
        assert!(
            ChannelMode::from_wire(bad).is_none(),
            "{bad} must be rejected"
        );
    }
    assert!(
        ChannelMode::Green.available(1),
        "grayscale supports green mode"
    );
    assert!(
        !ChannelMode::Rgb.available(2),
        "gray+alpha has no third channel"
    );
    assert_eq!(ChannelMode::Green.channels(1), &[0usize]);
    assert_eq!(ChannelMode::Green.channels(4), &[1usize]);
    assert_eq!(ChannelMode::Rgb.channels(3), &[0usize, 1, 2]);
}

/// The `(cost bits, pixel)` total order plus `select_nth_unstable` must be
/// exactly what the previous stable `sort_by` produced -- including the
/// flat regions, where thousands of costs are exactly `1 / epsilon` and the
/// tie-breaking order is load-bearing.
#[test]
fn slot_ranking_matches_the_stable_sort_it_replaced() {
    let (w, h) = (64usize, 64usize);
    // Half gradient, half constant: the constant half ties on cost.
    let mut pixels = gradient_pixels(w, h);
    for y in h / 2..h {
        for x in 0..w {
            let i = (y * w + x) * 3;
            pixels[i..i + 3].fill(120);
        }
    }
    let png = craft_png(w as u32, h as u32, &pixels, &vec![0u8; h], &[], 1);
    let img = decode_png(&png).expect("decode");
    let params = PngParams::default();
    let costs = HillCostModel.compute_cost(&img.pixels, w, h, 3, &params);
    let pre_salt = png_pre_salt(&img, &crate::stego::format::OFFICIAL_PNG_FORMAT);
    let master = derive_locator_master(
        Credential::Password(crate::stego::envelope::PUBLIC_DEFAULT_SECRET),
        None,
        &crate::stego::format::OFFICIAL_PNG_CIPHER,
        &pre_salt,
    )
    .expect("master");
    let locator = derive_l2_locator_keys(
        &master,
        &crate::stego::format::OFFICIAL_PNG_CIPHER,
        b"strhide-v4-hdr-magic",
        None,
    )
    .expect("locator");
    let plan = SlotPlan::build(
        &img,
        &costs,
        &locator.locate_seed,
        0,
        exclusion_permille(params.exclusion_percentile),
    )
    .expect("plan");

    let mut eligible: Vec<usize> = (0..w * h)
        .filter(|&i| (SPATIAL_ELIGIBLE_MIN..=SPATIAL_ELIGIBLE_MAX).contains(&img.pixels[i * 3 + 1]))
        .collect();
    eligible.sort_by(|&a, &b| {
        costs[a]
            .partial_cmp(&costs[b])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let allowed =
        eligible.len() * (1000 - exclusion_permille(params.exclusion_percentile) as usize) / 1000;
    assert_eq!(
        plan.candidates,
        eligible[..allowed].to_vec(),
        "selection must be identical to the stable sort"
    );
    assert!(
        costs[plan.candidates[0]].to_bits() == costs[plan.candidates[1]].to_bits(),
        "this fixture must contain cost ties for the assertion to mean anything"
    );
}

#[test]
fn private_png_format_bidirectional_isolation() {
    let (w, h) = (128usize, 128usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
    let payload = b"private-spatial-dialect-content-2026";
    let params = PngParams::default();

    // A private build changes *every* derivation label, exactly as
    // `WIRE_SPEC_CONTENT §13.11` promises. `hpos_salt` alone would leave the KDF
    // labels official, which is what the old profile shape did.
    const PRIVATE_CIPHER: crate::stego::format::WireCipherProfile =
        crate::stego::format::WireCipherProfile {
            domain_label: b"private-domain-label",
            hpos_label: b"private-hpos-label-xyz",
            enc_label: b"private-enc-label",
            perm_label: b"private-perm-label",
            stc_label: b"private-stc-label-xyz",
            hdr_stc_label: b"private-hdr-stc-label",
            ext_stc_label: b"private-ext-stc-label",
            aad_prefix: b"private-aad-prefix\0",
            default_suite: crate::crypto::CipherSuiteId::Aes256Gcm,
        };
    let private_spatial = crate::stego::format::PngFormatProfile {
        hpos_salt: b"private-hpos-salt-xyz",
        cipher: &PRIVATE_CIPHER,
    };

    // 1. Embed with private dialect
    let stego_bytes = embed_png(
        &png,
        payload,
        None,
        None,
        &private_spatial,
        &HillCostModel,
        &params,
        SafetyPolicy::default(),
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed with private profile");

    // 2. Extract with same private dialect -> Success
    let extracted = extract_png(
        &stego_bytes,
        None,
        None,
        &private_spatial,
        &HillCostModel,
        &params,
        &Control::none(),
    )
    .expect("extract with matching private profile");
    assert_eq!(extracted, payload);

    // 3. Extract with official dialect -> Fail with NoHiddenData
    let official_err = extract_png(
        &stego_bytes,
        None,
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        &Control::none(),
    );
    assert!(
        matches!(official_err, Err(StrHideError::NoHiddenData(_))),
        "official reader must see private stego as NoHiddenData, got {official_err:?}"
    );

    // 4. Official embed read by private reader -> Fail
    let official_stego = embed_png(
        &png,
        payload,
        None,
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        SafetyPolicy::default(),
        Freshness::Random,
        &Control::none(),
    )
    .expect("official embed");

    let private_err = extract_png(
        &official_stego,
        None,
        None,
        &private_spatial,
        &HillCostModel,
        &params,
        &Control::none(),
    );
    assert!(
        matches!(private_err, Err(StrHideError::NoHiddenData(_))),
        "private reader must see official stego as NoHiddenData, got {private_err:?}"
    );
}

#[test]
fn embed_capacity_matches_probed_capacity() {
    let (w, h) = (96usize, 96usize);
    let pixels = row_correlated_pixels(w, h);
    let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
    let params = PngParams::default();
    let spatial = crate::stego::format::OFFICIAL_PNG_FORMAT;
    let cost_model = HillCostModel;

    let probed = probe_png_capacity(
        &png,
        &cost_model,
        &params,
        crate::stego::SafetyLevel::High,
        Some("pw"),
        None,
        &spatial,
        &Control::none(),
    )
    .expect("probe capacity");

    let (_stego, stats, embedded_cap) = embed_png_with_stats(
        &png,
        b"test payload",
        test_cred(Some("pw")),
        None,
        crate::stego::format::OFFICIAL_PNG_CIPHER
            .default_suite
            .as_u16(),
        &[],
        &spatial,
        &cost_model,
        &params,
        SafetyPolicy::default()
            .with_level(crate::stego::SafetyLevel::High)
            .with_enforcement(crate::stego::SafetyEnforcement::Advisory),
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed with stats");

    assert_eq!(embedded_cap.format, probed.format);
    assert_eq!(embedded_cap.algorithm, probed.algorithm);
    assert_eq!(embedded_cap.total_elements, probed.total_elements);
    assert_eq!(embedded_cap.available_slots, probed.available_slots);
    assert_eq!(
        embedded_cap.max_raw_payload_bytes,
        probed.max_raw_payload_bytes
    );
    assert_eq!(
        embedded_cap.recommended_max_bytes,
        probed.recommended_max_bytes
    );
    assert_eq!(embedded_cap.tier_limits, probed.tier_limits);
    assert_eq!(stats.total_candidate_slots, probed.total_elements);
}

// -----------------------------------------------------------------
// V4 envelope: negative paths
// -----------------------------------------------------------------

fn v4_cred(password: &str) -> Credential<'_> {
    Credential::Password(password)
}

fn base_header_slots_for(image: &RawImage, password: &str) -> Vec<usize> {
    let spatial = crate::stego::format::OFFICIAL_PNG_FORMAT;
    let pre_salt = png_pre_salt(image, &spatial);
    let master = derive_locator_master(
        v4_cred(password),
        None,
        &crate::stego::format::OFFICIAL_PNG_CIPHER,
        &pre_salt,
    )
    .expect("master");
    let locator = derive_l2_locator_keys(
        &master,
        &crate::stego::format::OFFICIAL_PNG_CIPHER,
        b"strhide-v4-hdr-magic",
        None,
    )
    .expect("locator");
    header_layout(image, &locator.locate_seed, 0)[..PNG_AUDIO_BASE_SLOTS].to_vec()
}

fn rewrite_base_header(image: &mut RawImage, slots: &[usize], bytes: &[u8; 64]) {
    let channel = embed_channel(image);
    for byte_i in 0..64 {
        for bit_i in 0..8 {
            let bit = (bytes[byte_i] >> (7 - bit_i)) & 1;
            let idx = slots[byte_i * 8 + bit_i] * image.channels + channel;
            image.pixels[idx] = (image.pixels[idx] & 0xfe) | bit;
        }
    }
}

fn extract_with(
    carrier: &[u8],
    password: &str,
    limits: &ExtractParams,
) -> Result<Vec<u8>, StrHideError> {
    super::extract_png(
        carrier,
        v4_cred(password),
        None,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &PngParams::default(),
        limits,
        &Control::none(),
    )
    .map(Payload::into_bytes)
}

#[test]
fn v4_extension_roundtrip_and_unknown_critical_are_rejected() {
    let (w, h) = (96usize, 96usize);
    let png = craft_png(
        w as u32,
        h as u32,
        &row_correlated_pixels(w, h),
        &vec![2u8; h],
        &[],
        1,
    );
    let params = PngParams::default();
    let safety = SafetyPolicy::default()
        .with_level(crate::stego::SafetyLevel::High)
        .with_enforcement(crate::stego::SafetyEnforcement::Advisory);

    // Non-critical unknown TLV: ignored, payload still readable.
    let ext = [Tlv {
        type_id: 0x02,
        value: vec![1, 2, 3],
    }];
    let stego = super::embed_png(
        &png,
        b"extension payload",
        v4_cred("pw"),
        None,
        crate::stego::format::OFFICIAL_PNG_CIPHER
            .default_suite
            .as_u16(),
        &ext,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        safety,
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed with non-critical extension");
    let got = extract_with(&stego, "pw", &ExtractParams::default()).expect("extract");
    assert_eq!(got, b"extension payload");

    // Unknown critical TLV: the writer refuses it outright, because V4
    // defines no critical extension and every reader (this one included)
    // folds an unknown critical tag into `NoHiddenData`.
    let critical = [Tlv {
        type_id: 0x81,
        value: vec![9],
    }];
    let err = super::embed_png(
        &png,
        b"critical extension payload",
        v4_cred("pw"),
        None,
        crate::stego::format::OFFICIAL_PNG_CIPHER
            .default_suite
            .as_u16(),
        &critical,
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        safety,
        Freshness::Random,
        &Control::none(),
    )
    .unwrap_err();
    assert!(matches!(err, StrHideError::General(_)), "{err:?}");

    // A hostile writer bypasses that check; the reader must still refuse.
    let forged = forge_header_area(&stego, &[0x81, 0x01, 9]);
    assert!(
        matches!(
            extract_with(&forged, "pw", &ExtractParams::default()),
            Err(StrHideError::NoHiddenData(_))
        ),
        "an unknown critical TLV must fail closed"
    );
}

/// Rewrite a PNG carrier's base header and extension area so it declares
/// the given (critical) TLV bytes, the way a writer that ignored the
/// fail-closed validation would have produced it.
fn forge_header_area(stego: &[u8], extension: &[u8]) -> Vec<u8> {
    use crate::stego::header::{
        CONTENT_ENVELOPE_VERSION, FLAG_EXT_CRITICAL, FLAG_EXT_PRESENT, SpatialHeaderV4,
    };

    let mut image = decode_png(stego).expect("decode");
    let spatial = &crate::stego::format::OFFICIAL_PNG_FORMAT;
    let keys = png_keys(&image, v4_cred("pw"), None, spatial).expect("keys");
    let header = SpatialHeaderV4 {
        salt: [1u8; 16],
        nonce: [2u8; 12],
        body_len: 64,
        version: CONTENT_ENVELOPE_VERSION,
        flags: FLAG_EXT_PRESENT | FLAG_EXT_CRITICAL,
        format_id: PNG_FORMAT_ID,
        algorithm_id: 1,
        suite_id: 1,
        codec_id: 1,
        stc_h: 8,
        stc_u: 1,
        channel_mode: 0,
        class_rule: 1,
        p1_window: 3,
        p2_window: 15,
        neg_log2_epsilon: 23,
        exclusion_permille: 300,
        sigma: 1.0,
        kernel_id: 0,
        ext_len: extension.len() as u16,
    };
    let layout = header_layout(&image, &keys.locator.locate_seed, extension.len());
    let channel = embed_channel(&image);
    let bytes = header.encode();
    for (i, slot) in layout[..PNG_AUDIO_BASE_SLOTS].iter().enumerate() {
        let bit = (bytes[i / 8] >> (7 - (i % 8))) & 1;
        set_parity(&mut image.pixels[slot * image.channels + channel], bit);
    }
    for (i, slot) in layout[PNG_AUDIO_BASE_SLOTS..PNG_AUDIO_BASE_SLOTS + 8 * extension.len()]
        .iter()
        .enumerate()
    {
        let bit = (extension[i / 8] >> (7 - (i % 8))) & 1;
        set_parity(&mut image.pixels[slot * image.channels + channel], bit);
    }
    encode_png(&image).expect("encode")
}

/// Force the low bit of `value` without crossing the class-interior rule.
fn set_parity(value: &mut u8, bit: u8) {
    if (*value & 1) != bit {
        *value ^= 1;
    }
}

#[test]
fn v4_unknown_suite_and_low_pbkdf2_policy_fail_closed() {
    let (w, h) = (96usize, 96usize);
    let png = craft_png(
        w as u32,
        h as u32,
        &row_correlated_pixels(w, h),
        &vec![2u8; h],
        &[],
        1,
    );
    let params = PngParams::default();
    let safety = SafetyPolicy::default()
        .with_level(crate::stego::SafetyLevel::High)
        .with_enforcement(crate::stego::SafetyEnforcement::Advisory);
    assert!(matches!(
        super::embed_png(
            &png,
            b"x",
            v4_cred("pw"),
            None,
            999,
            &[],
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            safety,
            Freshness::Random,
            &Control::none(),
        ),
        Err(StrHideError::UnsupportedVersion(_))
    ));

    let stego = super::embed_png(
        &png,
        b"policy",
        v4_cred("pw"),
        None,
        crate::stego::format::OFFICIAL_PNG_CIPHER
            .default_suite
            .as_u16(),
        &[],
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        safety,
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed");
    let strict = ExtractParams::default().with_max_pbkdf2_iterations(100_000);
    assert!(
        matches!(
            extract_with(&stego, "pw", &strict),
            Err(StrHideError::NoHiddenData(_))
        ),
        "a policy below the fixed V4 L1 cost must fail before PBKDF2"
    );
}

#[test]
fn v4_header_crc_and_aead_reject_tampering() {
    let (w, h) = (96usize, 96usize);
    let png = craft_png(
        w as u32,
        h as u32,
        &row_correlated_pixels(w, h),
        &vec![2u8; h],
        &[],
        1,
    );
    let params = PngParams::default();
    let safety = SafetyPolicy::default()
        .with_level(crate::stego::SafetyLevel::High)
        .with_enforcement(crate::stego::SafetyEnforcement::Advisory);
    let stego = super::embed_png(
        &png,
        b"tamper",
        v4_cred("pw"),
        None,
        crate::stego::format::OFFICIAL_PNG_CIPHER
            .default_suite
            .as_u16(),
        &[],
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        safety,
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed");

    let mut image = decode_png(&stego).expect("decode");
    let slots = base_header_slots_for(&image, "pw");
    let mut header_bytes: [u8; 64] = read_slot_bytes(&image, &slots, 64)
        .try_into()
        .expect("64 bytes");
    let mut header = SpatialHeaderV4::decode(&header_bytes, PNG_FORMAT_ID).expect("header");

    // 1) Flip a byte without recomputing the CRC: caught before body slots.
    header_bytes[32] ^= 0x01; // version
    rewrite_base_header(&mut image, &slots, &header_bytes);
    let tampered_crc = encode_png(&image).expect("encode");
    assert!(matches!(
        extract_with(&tampered_crc, "pw", &ExtractParams::default()),
        Err(StrHideError::NoHiddenData(_))
    ));

    // 2) Flip an authenticated field and recompute the CRC: only the AEAD
    //    tag can catch it, and it must look like "no payload".
    header.salt[0] ^= 0x01;
    let forged = header.encode();
    rewrite_base_header(&mut image, &slots, &forged);
    let tampered_aead = encode_png(&image).expect("encode");
    assert!(matches!(
        extract_with(&tampered_aead, "pw", &ExtractParams::default()),
        Err(StrHideError::NoHiddenData(_))
    ));
}

#[test]
fn v4_forged_body_len_is_rejected_before_body_allocation() {
    let (w, h) = (96usize, 96usize);
    let png = craft_png(
        w as u32,
        h as u32,
        &row_correlated_pixels(w, h),
        &vec![2u8; h],
        &[],
        1,
    );
    let params = PngParams::default();
    let safety = SafetyPolicy::default()
        .with_level(crate::stego::SafetyLevel::High)
        .with_enforcement(crate::stego::SafetyEnforcement::Advisory);
    let stego = super::embed_png(
        &png,
        b"body_len",
        v4_cred("pw"),
        None,
        crate::stego::format::OFFICIAL_PNG_CIPHER
            .default_suite
            .as_u16(),
        &[],
        &crate::stego::format::OFFICIAL_PNG_FORMAT,
        &HillCostModel,
        &params,
        safety,
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed");

    let mut image = decode_png(&stego).expect("decode");
    let slots = base_header_slots_for(&image, "pw");
    let header_bytes: [u8; 64] = read_slot_bytes(&image, &slots, 64)
        .try_into()
        .expect("64 bytes");
    let header = SpatialHeaderV4::decode(&header_bytes, PNG_FORMAT_ID).expect("header");

    for forged_len in [0u32, 21, 0x03ff_ffff] {
        let mut forged = header;
        forged.body_len = forged_len;
        rewrite_base_header(&mut image, &slots, &forged.encode());
        let carrier = encode_png(&image).expect("encode");
        assert!(
            matches!(
                extract_with(&carrier, "pw", &ExtractParams::default()),
                Err(StrHideError::NoHiddenData(_))
            ),
            "body_len={forged_len} must not be accepted"
        );
    }
}

#[test]
fn v4_truncated_or_tiny_carriers_report_no_payload() {
    let tiny = craft_png(8, 8, &[120u8; 8 * 8 * 3], &[0u8; 8], &[], 1);
    assert!(matches!(
        extract_with(&tiny, "pw", &ExtractParams::default()),
        Err(StrHideError::NoHiddenData(_))
    ));
}
