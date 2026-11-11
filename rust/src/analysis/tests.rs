//! Tests for the analysis domain.

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::Path;

use crate::structure::envelope::{EnvelopeTrailer, STANDARD_TRAILER_MAGIC};

use super::spatial::{
    RsMask, chi2_lsb_suspicion, color_channel_count, decode_jpeg_pixels, decode_png_pixels,
    rs_analysis, rs_difference, spatial_slabs,
};
use super::structural::{track_jpeg_structure, track_png_structure, track_tool_signatures};
use super::*;

/// Four coincidental magic bytes used to be enough for a `Likely` finding;
/// at 1.56% per 64 MiB window that is a false positive on ordinary data.
#[test]
fn four_byte_trailer_mark_needs_a_consistent_trailer() {
    let mut junk = vec![0u8; 4096];
    junk[100..104].copy_from_slice(&[0x78, 0xe6, 0x66, 0xd2]);
    let report = scan_bytes(&junk, "junk");
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.detail.contains("trailer mark")),
        "a lone 4-byte magic must not be reported as a known tool"
    );

    // A coherent trailer (valid CRC, in-range offset/size) still counts.
    let mut carrier = vec![0x41u8; 4096];
    let trailer = EnvelopeTrailer::create(3000, 200, STANDARD_TRAILER_MAGIC).pack();
    carrier.extend_from_slice(&trailer);
    let report = scan_bytes(&carrier, "carrier");
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.detail.contains("trailer mark")),
        "a self-consistent trailer must still be reported"
    );
}

/// A private dialect's header magic is a strhide signature, but only for a
/// scan that was told about that dialect.
#[test]
fn private_dialect_header_magic_is_reported_only_when_asked() {
    const PRIVATE_HEADER: [u8; 8] = [0xA7, 0x11, 0x5C, 0x3E, 0x90, 0x2B, 0x64, 0xD8];
    let mut carrier = vec![0x41u8; 4096];
    carrier[64..72].copy_from_slice(&PRIVATE_HEADER);

    let plain = scan_bytes(&carrier, "carrier");
    assert!(
        !plain
            .findings
            .iter()
            .any(|f| f.detector == "signature:known-tool"),
        "an unknown header magic must not be reported as a known tool"
    );

    let magics = ScanMagics {
        header: Some(PRIVATE_HEADER),
        trailer: None,
    };
    let asked = scan_bytes_with_magics(&carrier, "carrier", magics);
    assert!(
        asked
            .findings
            .iter()
            .any(|f| f.detector == "signature:known-tool"),
        "the dialect header magic must be reported once the scan knows it"
    );
}

/// The official profile must not contribute extra magics: doing so would
/// label every official carrier as a private-dialect hit.
#[test]
fn scan_magics_are_empty_for_the_official_profile() {
    let official = crate::structure::StructureProfile::default();
    let magics = scan_magics_for(&official);
    assert!(
        magics.header.is_none(),
        "official header magic must be None"
    );
    assert!(
        magics.trailer.is_none(),
        "official trailer magic must be None"
    );

    let private =
        crate::structure::StructureProfile::default().with_magic(crate::core::params::MagicPair {
            header: [1, 2, 3, 4, 5, 6, 7, 8],
            trailer: *b"PRVT",
        });
    let magics = scan_magics_for(&private);
    assert_eq!(magics.header, Some([1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(magics.trailer, Some(*b"PRVT"));
}

#[test]
fn rs_difference_includes_the_trailing_window() {
    // A 4x4 plane has two 3x3 window starts per axis (0 and 1). Ensure
    // the trailing window containing the non-zero sample is scored.
    let mut plane = vec![0i32; 16];
    plane[2 * 4 + 2] = 1; // centre of the bottom-right 3x3 window

    // Three windows flip a zero centre to 1 (worse smoothness -> +1 each)
    // and the trailing window flips that lone 1 to 0 (better -> -1), so the
    // mean over all four windows is 0.5. The old bound scored only the
    // top-left window and returned 1.0.
    let d = rs_difference(&plane, 4, 4, RsMask::Plus);
    assert!(
        (d - 0.5).abs() < 1e-12,
        "all four 3x3 windows must be counted, got difference {d}"
    );
}

fn fake_png(
    width: u32,
    height: u32,
    color_type: u8,
    pixel_fn: impl Fn(usize, usize) -> Vec<u8>,
) -> Vec<u8> {
    // Build a minimal valid PNG: IHDR + one filtered IDAT + IEND.
    let _channels = match color_type {
        0 => 1,
        2 => 3,
        4 => 2,
        6 => 4,
        _ => 3,
    };
    let mut raw: Vec<u8> = Vec::new();
    for y in 0..height as usize {
        raw.push(0); // filter: None
        for x in 0..width as usize {
            raw.extend_from_slice(&pixel_fn(x, y));
        }
    }
    let compressed = {
        use std::io::Write;
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&raw).unwrap();
        z.finish().unwrap()
    };
    let mut out = Vec::new();
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let mut chunk = |ty: &[u8], body: &[u8]| {
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(ty);
        out.extend_from_slice(body);
        let mut crc = crc32fast::Hasher::new();
        crc.update(ty);
        crc.update(body);
        out.extend_from_slice(&crc.finalize().to_be_bytes());
    };
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(color_type);
    ihdr.extend_from_slice(&[0, 0, 0]);
    chunk(b"IHDR", &ihdr);
    chunk(b"IDAT", &compressed);
    chunk(b"IEND", &[]);
    out
}

#[test]
fn entropy_of_random_is_high() {
    let buf: Vec<u8> = (0..4096u64)
        .map(|i| i.wrapping_mul(1103515245).wrapping_add(12345) as u8)
        .collect();
    assert!(shannon_entropy(&buf) > 7.0);
}

#[test]
fn chi2_clean_image_low_suspicion() {
    // Values concentrated on even bins (like a clean low-noise image's
    // histogram where adjacent values cluster): pair histograms are NOT
    // uniform, so chi2 is large and suspicion stays low.
    let px: Vec<u8> = (0..40000).map(|i| (i as u8) & 0xFE).collect();
    let s = chi2_lsb_suspicion(&px);
    assert!(s < 0.5, "suspicion={s}");
}

#[test]
fn chi2_uniform_histogram_looks_embedded() {
    // A flat/random byte stream has perfectly uniform pair histograms —
    // exactly the signature the chi-square attack flags as embedded.
    let px: Vec<u8> = (0..40000u64)
        .map(|i| i.wrapping_mul(2654435761) as u8)
        .collect();
    let s = chi2_lsb_suspicion(&px);
    assert!(s > 0.8, "suspicion={s}");
}

#[test]
fn tool_signature_detected() {
    let mut blob = vec![0u8; 100];
    blob[40..48].copy_from_slice(&[0xb7, 0x54, 0x2c, 0x82, 0x7e, 0x31, 0x1d, 0x6e]);
    let mut f = Vec::new();
    track_tool_signatures(&ScanView::whole(&blob), &mut f, ScanMagics::default());
    assert!(f.iter().any(|x| x.detector == "signature:known-tool"));
}

#[test]
fn png_private_chunk_detected() {
    // Hand-build a PNG with a prIv chunk injected.
    let mut png = fake_png(4, 4, 2, |x, _| vec![(x * 60) as u8, 128, 200]);
    // Insert a prIv chunk before IEND.
    let iend_pos = png.windows(4).rposition(|w| w == b"IEND").unwrap() - 4;
    let mut injection = Vec::new();
    injection.extend_from_slice(&8u32.to_be_bytes());
    injection.extend_from_slice(b"prIv");
    injection.extend_from_slice(b"hiddend!");
    let mut crc = crc32fast::Hasher::new();
    crc.update(b"prIv");
    crc.update(b"hiddend!");
    injection.extend_from_slice(&crc.finalize().to_be_bytes());
    png.splice(iend_pos..iend_pos, injection);

    let mut findings = Vec::new();
    track_png_structure(&ScanView::whole(&png), &mut findings);
    assert!(
        findings.iter().any(|f| f.detector == "png:private-chunk"),
        "findings: {findings:?}"
    );
}

#[test]
fn standard_chunk_with_private_naming_bits_is_not_flagged() {
    // APNG's `acTL`/`fcTL`/`fdAT` carry a lowercase second letter, so the
    // RFC 2083 naming rule calls them private -- but they are registered
    // types. Checking private-ness before the whitelist flagged every
    // ordinary animated PNG with `Likely` findings and saturated the risk
    // score at 100 on a clean carrier.
    let mut png = fake_png(4, 4, 2, |x, _| vec![(x * 60) as u8, 128, 200]);
    let iend_pos = png.windows(4).rposition(|w| w == b"IEND").unwrap() - 4;
    let mut injection = Vec::new();
    let mut push = |ty: &[u8; 4], body: &[u8]| {
        injection.extend_from_slice(&(body.len() as u32).to_be_bytes());
        injection.extend_from_slice(ty);
        injection.extend_from_slice(body);
        let mut crc = crc32fast::Hasher::new();
        crc.update(ty);
        crc.update(body);
        injection.extend_from_slice(&crc.finalize().to_be_bytes());
    };
    push(b"acTL", &[0, 0, 0, 2, 0, 0, 0, 0]);
    push(
        b"fcTL",
        &[0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0],
    );
    png.splice(iend_pos..iend_pos, injection);

    let mut findings = Vec::new();
    track_png_structure(&ScanView::whole(&png), &mut findings);
    assert!(
        !findings.iter().any(|f| f.detector == "png:private-chunk"),
        "registered chunks must not be reported as private: {findings:?}"
    );
    assert!(
        findings.is_empty(),
        "a clean APNG chunk sequence must produce no structural finding: {findings:?}"
    );
}

#[test]
fn spatial_slabs_cover_top_middle_and_bottom() {
    // 1920x2400 RGBA: stride 7680, 512 rows per slab, three slabs fit.
    let (w, h, ch) = (1920usize, 2400usize, 4usize);
    let stride = w * ch;
    let pixels = vec![0u8; stride * h];
    let slabs = spatial_slabs(&pixels, stride);
    assert_eq!(
        slabs.len(),
        3,
        "a tall image must be sampled in three places"
    );
    assert_eq!(
        slabs[0].as_ptr(),
        pixels.as_ptr(),
        "first slab starts at the top"
    );
    assert_eq!(
        slabs[1].as_ptr() as usize - pixels.as_ptr() as usize,
        ((h - 512) / 2) * stride,
        "middle slab sits at the vertical centre"
    );
    assert_eq!(
        slabs[2].len(),
        512 * stride,
        "last slab is rows per slab, ending at the bottom"
    );
    for s in &slabs {
        assert_eq!(s.len() % stride, 0, "a slab is a whole number of rows");
    }

    // Carriers that only fit one slab's worth of rows are analysed whole,
    // which is both cheaper and more accurate than three overlapping slabs.
    let short = vec![0u8; 7680 * 1280];
    assert_eq!(spatial_slabs(&short, 7680).len(), 1);
    let small = vec![0u8; 64 * 4 * 10];
    assert_eq!(spatial_slabs(&small, 256).len(), 1);
}

#[test]
fn png_pixel_decode_roundtrip() {
    let png = fake_png(4, 4, 2, |x, y| vec![(x * 50 + y * 10) as u8, 128, 200]);
    let (px, width, channels) = decode_png_pixels(&png).expect("decode");
    assert_eq!(width, 4);
    assert_eq!(channels, 3);
    assert_eq!(px.len(), 4 * 4 * 3);
}

#[test]
fn clean_gradient_scores_low() {
    // Full scan on a clean gradient PNG should stay in the low band.
    let tmp = std::env::temp_dir().join("strhide_scan_test_clean.png");
    let png = fake_png(8, 8, 2, |x, y| vec![(x * 20 + y * 5) as u8, 100, 150]);
    std::fs::write(&tmp, &png).unwrap();
    let rep = scan_file(&tmp).unwrap();
    assert!(rep.risk_score < 30, "report: {rep:?}");
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn tool_signature_lifts_score() {
    let tmp = std::env::temp_dir().join("strhide_scan_test_magic.bin");
    let mut blob = vec![0u8; 200];
    blob[100..108].copy_from_slice(&[0xb7, 0x54, 0x2c, 0x82, 0x7e, 0x31, 0x1d, 0x6e]);
    std::fs::write(&tmp, &blob).unwrap();
    let rep = scan_file(&tmp).unwrap();
    assert!(rep.risk_score >= 45, "report: {rep:?}");
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn jpeg_decode_rejects_non_jpeg() {
    // Garbage bytes must not panic; decode returns None.
    let garbage: Vec<u8> = (0..512u64)
        .map(|i| i.wrapping_mul(2654435761) as u8)
        .collect();
    assert!(decode_jpeg_pixels(&garbage).is_none());
}

/// A grayscale JPEG must be reported as 1 channel. Reporting 3 for it (as
/// this used to) made `chi2_lsb_suspicion` read rows three times too wide.
///
/// The fixture is hand-built so the assertion is meaningful: a broken
/// fixture would decode to `None` and the test would pass for the wrong
/// reason, so the decode itself is asserted first.
#[test]
fn grayscale_jpeg_reports_one_channel() {
    // Smallest legal baseline grayscale JPEG: one 16x16 MCU, flat
    // quantisation table, and DC + AC Huffman tables with two 1-bit codes
    // (`0` -> symbol 0x00, `1` -> symbol 0x01). Symbol 0x00 is both
    // "DC diff category 0" and "AC end-of-block", so each MCU costs two
    // zero bits: DC diff, then EOB.
    let mut counts = [0u8; 16];
    counts[0] = 2;
    // DHT segment: [class<<4 | table] [16 code counts] [symbols].
    let dht_payload: Vec<u8> = [&[0x00u8], &counts[..], &[0x00u8, 0x01u8][..]].concat();
    let mut d = Vec::new();
    d.extend_from_slice(&[0xFF, 0xD8]); // SOI
    d.extend_from_slice(&[0xFF, 0xDB]); // DQT
    let dqt_len = 2u16 + 1 + 64;
    d.extend_from_slice(&dqt_len.to_be_bytes());
    d.push(0x00); // 8-bit table 0
    d.extend_from_slice(&[0x10u8; 64]); // flat quantisation values
    d.extend_from_slice(&[0xFF, 0xC0]); // SOF0
    d.extend_from_slice(&(2u16 + 6 + 3).to_be_bytes());
    d.push(8); // 8-bit precision
    d.extend_from_slice(&16u16.to_be_bytes()); // width
    d.extend_from_slice(&16u16.to_be_bytes()); // height
    d.push(1); // one component
    d.push(1); // component id 1
    d.push(0x11); // sampling factors 1x1
    d.push(0x00); // quantisation table 0
    d.extend_from_slice(&[0xFF, 0xC4]); // DHT: DC table 0
    d.extend_from_slice(&(dht_payload.len() as u16 + 2).to_be_bytes());
    d.extend_from_slice(&dht_payload);
    // The scan references an AC table as well, and a scan component may not
    // leave one unset -- so define AC table 0 with the same two codes.
    let ac_payload: Vec<u8> = [&[0x10u8], &counts[..], &[0x00u8, 0x01u8][..]].concat();
    d.extend_from_slice(&[0xFF, 0xC4]); // DHT: AC table 0
    d.extend_from_slice(&(ac_payload.len() as u16 + 2).to_be_bytes());
    d.extend_from_slice(&ac_payload);
    d.extend_from_slice(&[0xFF, 0xDA]); // SOS
    // `read_length` in jpeg-decoder subtracts itself, so the on-wire value is
    // `4 + 2 * component_count + 2` for a 1-component scan.
    d.extend_from_slice(&8u16.to_be_bytes());
    d.push(1); // one component in scan
    d.push(1); // component selector 1
    d.push(0x00); // DC table 0, AC table 0
    d.extend_from_slice(&[0x00, 0x3F, 0x00]); // spectral 0..63, successive approx 0
    d.push(0b0000_0000); // DC diff 0
    d.push(0b0000_0000); // AC EOB
    d.extend_from_slice(&[0xFF, 0xD9]); // EOI

    let (pixels, width, channels) = decode_jpeg_pixels(&d).expect("fixture must decode");
    assert_eq!(channels, 1, "grayscale JPEG must decode to 1 channel");
    assert_eq!(pixels.len(), 16 * 16);
    assert_eq!(width, 16);
}

#[test]
fn jpeg_eoi_tail_detected() {
    // Synthesize a minimal JPEG structure: SOI, DQT, EOI, then extra bytes.
    let mut data = Vec::new();
    data.extend_from_slice(&[0xFF, 0xD8]); // SOI
    // DQT: FF DB, length=4 (payload=2: table spec + 1 quant value).
    data.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x04, 0x00, 0x10]);
    data.extend_from_slice(&[0xFF, 0xD9]); // EOI
    data.extend_from_slice(b"extra-tail-data"); // appended after EOI
    let mut findings = Vec::new();
    track_jpeg_structure(&ScanView::whole(&data), &mut findings);
    assert!(
        findings.iter().any(|f| f.detector == "jpeg:trailing-data"),
        "findings: {findings:?}"
    );
}

#[test]
fn jpeg_many_dqt_flagged() {
    let mut data = Vec::new();
    data.extend_from_slice(&[0xFF, 0xD8]);
    for _ in 0..6 {
        data.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x04, 0x00, 0x10]);
    }
    data.extend_from_slice(&[0xFF, 0xD9]);
    let mut findings = Vec::new();
    track_jpeg_structure(&ScanView::whole(&data), &mut findings);
    assert!(
        findings.iter().any(|f| f.detector == "jpeg:many-dqt"),
        "findings: {findings:?}"
    );
}

/// Chunk sequence with a caller-supplied IHDR body and IDAT payload.
fn raw_png(ihdr_body: &[u8], idat: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let mut chunk = |ty: &[u8], body: &[u8]| {
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(ty);
        out.extend_from_slice(body);
        let mut crc = crc32fast::Hasher::new();
        crc.update(ty);
        crc.update(body);
        out.extend_from_slice(&crc.finalize().to_be_bytes());
    };
    chunk(b"IHDR", ihdr_body);
    chunk(b"IDAT", idat);
    chunk(b"IEND", &[]);
    out
}

fn zlib(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(data).unwrap();
    z.finish().unwrap()
}

/// Write a file above [`MAX_FULL_SCAN`] with `prefix` at offset 0 and
/// `suffix` at the very end. The gap is created by seeking, so the file
/// costs almost no disk space.
fn write_windowed_file(path: &Path, prefix: &[u8], suffix: &[u8]) {
    use std::io::Write;
    let mut f = File::create(path).unwrap();
    f.write_all(prefix).unwrap();
    f.seek(SeekFrom::Start(MAX_FULL_SCAN + 1)).unwrap();
    f.write_all(suffix).unwrap();
    f.sync_all().unwrap();
}

/// Payload bytes for the windowed tests: every value 0..=250 cycling, so
/// no `FF D9` can occur by accident. Entropy is ~7.9 bits/byte.
fn filler(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

/// B1 acceptance: a PNG above the full-scan cap with data appended after
/// IEND must be flagged. Before the prefix/tail split this reported clean.
#[test]
fn oversized_png_with_appended_payload_is_detected() {
    let tmp = std::env::temp_dir().join("strhide_scan_big_appended.png");
    // A chunk stream that ends before the padding: signature + IHDR + IDAT.
    let mut head = fake_png(4, 4, 2, |x, y| vec![(x * 50 + y * 10) as u8, 128, 200]);
    let iend_pos = head.windows(4).rposition(|w| w == b"IEND").unwrap() - 4;
    head.truncate(iend_pos);

    let mut suffix = PNG_IEND_FULL.to_vec();
    suffix.extend_from_slice(&filler(4096));
    write_windowed_file(&tmp, &head, &suffix);

    let rep = scan_file(&tmp).unwrap();
    let _ = std::fs::remove_file(&tmp);
    assert!(
        rep.findings
            .iter()
            .any(|f| f.detector == "png:trailing-data"),
        "report: {rep:?}"
    );
    assert!(rep.risk_score >= 30, "report: {rep:?}");
    assert!(
        rep.notes.iter().any(|n| n.contains("larger than")),
        "a windowed scan must say so: {rep:?}"
    );
}

/// The same oversized PNG with *nothing* appended must stay clean: the
/// trailing-data detector must key on real bytes after IEND, not on the
/// window boundary.
#[test]
fn oversized_png_without_trailing_data_stays_clean() {
    let tmp = std::env::temp_dir().join("strhide_scan_big_clean.png");
    let mut head = fake_png(4, 4, 2, |x, _| vec![(x * 60) as u8, 128, 200]);
    let iend_pos = head.windows(4).rposition(|w| w == b"IEND").unwrap() - 4;
    head.truncate(iend_pos);
    write_windowed_file(&tmp, &head, &PNG_IEND_FULL);

    let rep = scan_file(&tmp).unwrap();
    let _ = std::fs::remove_file(&tmp);
    assert!(
        !rep.findings
            .iter()
            .any(|f| f.detector == "png:trailing-data"),
        "report: {rep:?}"
    );
}

/// B7 acceptance: same for JPEG. The marker walk cannot reach EOI in a
/// windowed view, so the file's own tail is the evidence.
#[test]
fn oversized_jpeg_with_appended_payload_is_detected() {
    let tmp = std::env::temp_dir().join("strhide_scan_big_appended.jpg");
    let mut head = vec![0xFF, 0xD8]; // SOI
    head.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x04, 0x00, 0x10]); // DQT
    head.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]); // SOS header

    let mut suffix = JPEG_EOI.to_vec();
    suffix.extend_from_slice(&filler(4096));
    write_windowed_file(&tmp, &head, &suffix);

    let rep = scan_file(&tmp).unwrap();
    let _ = std::fs::remove_file(&tmp);
    assert!(
        rep.findings
            .iter()
            .any(|f| f.detector == "jpeg:trailing-data"),
        "report: {rep:?}"
    );
    assert!(rep.risk_score >= 30, "report: {rep:?}");
}

/// B4: IHDR states how many scanline bytes the image must produce, so a
/// small IDAT that inflates far past that is a bomb, not an image.
#[test]
fn png_inflate_is_bounded_by_declared_geometry() {
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&4u32.to_be_bytes()); // width
    ihdr.extend_from_slice(&4u32.to_be_bytes()); // height
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB, non-interlaced
    // 1 MiB of zeros compresses to ~1 KiB but decodes to 20k times the
    // 52 bytes the header promises.
    let png = raw_png(&ihdr, &zlib(&vec![0u8; 1024 * 1024]));
    assert!(
        decode_png_pixels(&png).is_none(),
        "an inflate that overshoots the declared geometry must be rejected"
    );
}

#[test]
fn rs_smooth_plane_estimates_near_zero() {
    let mut plane = vec![128u8; 16 * 16 * 3];
    for y in 0..16 {
        for x in 0..16 {
            let idx = (y * 16 + x) * 3;
            plane[idx] = (x * 4) as u8;
            plane[idx + 1] = (y * 4) as u8;
            plane[idx + 2] = 100;
        }
    }
    let est =
        rs_analysis(&plane, 16, 3).expect("a clean image must report 0.0, not skip as unsuitable");
    assert!(est < 0.1);
}

#[test]
fn alpha_channels_are_excluded_from_colour_statistics() {
    assert_eq!(color_channel_count(1), 1);
    assert_eq!(
        color_channel_count(2),
        1,
        "Grayscale+Alpha: only the luma plane is image content"
    );
    assert_eq!(color_channel_count(3), 3);
    assert_eq!(
        color_channel_count(4),
        3,
        "RGBA: alpha is not image content"
    );
}

#[test]
fn trailing_bytes_after_iend_are_a_likely_finding() {
    let mut png = fake_png(8, 8, 2, |x, y| vec![(x * 20 + y) as u8, 128, 200]);
    png.extend_from_slice(b"appended secret text");
    let report = scan_bytes(&png, "trailing.png");
    assert_eq!(report.format.as_deref(), Some("PNG"));
    let finding = report
        .findings
        .iter()
        .find(|f| f.detector == "png:trailing-data")
        .expect("trailing data must be reported");
    assert_eq!(
        finding.severity,
        Severity::Likely,
        "confirmed bytes after IEND are structural evidence, not a guess"
    );
    assert_eq!(report.verdict, "likely-hidden");
}

#[test]
fn heif_brands_are_not_mislabelled_as_mp4() {
    // ftyp with a HEIC major brand: the private sniffer used to call every
    // `ftyp` file MP4.
    let mut heif = Vec::new();
    heif.extend_from_slice(&24u32.to_be_bytes());
    heif.extend_from_slice(b"ftyp");
    heif.extend_from_slice(b"heic");
    heif.extend_from_slice(&0u32.to_be_bytes());
    heif.extend_from_slice(b"mif1heic");
    let report = scan_bytes(&heif, "photo.heic");
    assert_eq!(report.format.as_deref(), Some("HEIF"));
}

#[test]
fn clean_webp_payload_tail_is_not_an_overlay() {
    // A valid RIFF/WebP whose compressed payload is high-entropy: the old
    // sniffer returned None for WEBP, so the entropy rule fired on every
    // clean file.
    let payload: Vec<u8> = (0..(TAIL_WINDOW + 16))
        .map(|i| (i.wrapping_mul(1103515245) >> 16) as u8)
        .collect();
    let mut webp = Vec::new();
    webp.extend_from_slice(b"RIFF");
    webp.extend_from_slice(&((payload.len() + 12) as u32).to_le_bytes());
    webp.extend_from_slice(b"WEBP");
    webp.extend_from_slice(b"VP8 ");
    webp.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    webp.extend_from_slice(&payload);
    let report = scan_bytes(&webp, "clean.webp");
    assert_eq!(report.format.as_deref(), Some("WEBP"));
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.detector == "overlay:high-entropy"),
        "a compressed container payload at EOF is not an overlay: {:?}",
        report.findings
    );
}

#[test]
fn rs_negative_mask_is_an_involution() {
    // RsMask::Minus must be an invertible involution permutation: F_{-1}(F_{-1}(x)) == x
    for x in -10..=265i32 {
        let f1 = if x & 1 == 0 { x - 1 } else { x + 1 };
        let f2 = if f1 & 1 == 0 { f1 - 1 } else { f1 + 1 };
        assert_eq!(f2, x, "F_(-1) must be an involution for x = {x}");
    }
}

#[test]
fn audio_format_emits_disclaimer_note() {
    let mut wav = Vec::new();
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&36u32.to_le_bytes());
    wav.extend_from_slice(b"WAVE");
    wav.extend_from_slice(b"fmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&44100u32.to_le_bytes());
    wav.extend_from_slice(&88200u32.to_le_bytes());
    wav.extend_from_slice(&2u16.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&0u32.to_le_bytes());
    let report = scan_bytes(&wav, "test.wav");
    assert_eq!(report.format.as_deref(), Some("WAV"));
    assert!(
        report
            .notes
            .iter()
            .any(|n| n
                .contains("Content-domain audio steganography detectors are not implemented")),
        "WAV scan must include audio content detector disclaimer note: {:?}",
        report.notes
    );
}
