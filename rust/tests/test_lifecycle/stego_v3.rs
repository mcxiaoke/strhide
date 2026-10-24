//! STC-V3 wire-format conformance tests (JPEG).
//!
//! These tests pin down the parts of the format that must never drift: the
//! geometric slot contract, the superblock's field binding, the extension
//! rules, the cipher-suite trial enumeration, and the absence of a cheap
//! password oracle.
//!
//! Several of them reproduce the derivation on the test side on purpose (cover
//! digest, header slots, header STC pass). That duplication *is* the contract:
//! two independent implementations must agree, otherwise carriers written today
//! stop decoding tomorrow.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rayon::prelude::*;
use sha2::{Digest, Sha256};

use strhide::errors::StrHideError;
use strhide::stego::coding::{Move, StcTrellis};
use strhide::stego::format::{
    DEFAULT_JPEG_FORMAT, JpegFormatProfile, derive_master, extension_stc_seed, header_perm_seed,
    header_stc_seed,
};
use strhide::stego::jpeg::cost::UerdCostModel;
use strhide::stego::jpeg::engine::{embed_jpeg, extract_jpeg, probe_jpeg_capacity};
use strhide::stego::jpeg::header_v3::{SUPERBLOCK_BYTES, Superblock, Tlv};
use strhide::stego::jpeg::v3_layout::{grid_indices, slot_to_coeff};
use strhide::stego::prng::permute_prefix;
use strhide::stego::{
    ExtractParams, JpegParams, SafetyLevel, StegoOptions, embed_carrier, extract_carrier,
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Resolve a file from the local `temp/` corpus (absent in CI).
fn corpus(rel: &str) -> Option<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let local = root.join("temp").join(rel);
    if local.exists() {
        return Some(local);
    }
    for key in ["STRHIDE_CORPUS", "STRHIDE_STEGO_CORPUS"] {
        if let Ok(dir) = std::env::var(key) {
            let p = PathBuf::from(&dir).join(rel);
            if p.exists() {
                return Some(p);
            }
            if let Some(name) = std::path::Path::new(rel).file_name() {
                let p = PathBuf::from(&dir).join(name);
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }
    None
}

fn incompressible(len: usize, seed: u64) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ seed;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

// ---------------------------------------------------------------------------
// Test-side reproduction of the derivation
// ---------------------------------------------------------------------------

/// `SHA-256(tag || u32 block_count || u32 component_count || all DC, i16 BE)`.
fn cover_digest(fmt: &JpegFormatProfile, coeffs: &dct_io::JpegCoefficients) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(fmt.cover_digest_tag);
    let block_count = coeffs.components.first().map_or(0, |c| c.blocks.len());
    hasher.update((block_count as u32).to_be_bytes());
    hasher.update((coeffs.components.len() as u32).to_be_bytes());
    for component in &coeffs.components {
        for block in &component.blocks {
            hasher.update(block[0].to_be_bytes());
        }
    }
    hasher.finalize().into()
}

/// Header slots for a carrier, exactly as the engine derives them.
fn header_slots(jpeg: &[u8], password: &str, ext_bytes: usize) -> Vec<u32> {
    header_slots_with_suite(jpeg, password, 1, ext_bytes)
}

/// Header slots located with a specific cipher suite.
fn header_slots_with_suite(
    jpeg: &[u8],
    password: &str,
    suite_id: u16,
    ext_bytes: usize,
) -> Vec<u32> {
    let coeffs = dct_io::read_coefficients(jpeg).expect("cover coefficients");
    let block_count = coeffs.components[0].blocks.len();
    let digest = cover_digest(&DEFAULT_JPEG_FORMAT, &coeffs);
    let suite = DEFAULT_JPEG_FORMAT.suite(suite_id).expect("suite");
    let master = derive_master(suite, password, &digest).unwrap();
    let seed = header_perm_seed(&DEFAULT_JPEG_FORMAT, &master, None);
    let mut slots = grid_indices(block_count, DEFAULT_JPEG_FORMAT.grid_rule);
    permute_prefix(
        &mut slots,
        DEFAULT_JPEG_FORMAT.header_slots(ext_bytes),
        &seed,
    );
    slots.truncate(DEFAULT_JPEG_FORMAT.header_slots(ext_bytes));
    slots
}

#[inline]
fn parity(value: i16) -> u8 {
    2 | (value & 1) as u8
}

/// Read the superblock bits straight out of the header slots.
fn read_superblock(jpeg: &[u8], password: &str) -> [u8; SUPERBLOCK_BYTES] {
    read_superblock_with_suite(jpeg, password, 1)
}

/// Read the superblock located with a specific cipher suite.
fn read_superblock_with_suite(
    jpeg: &[u8],
    password: &str,
    suite_id: u16,
) -> [u8; SUPERBLOCK_BYTES] {
    let coeffs = dct_io::read_coefficients(jpeg).expect("coefficients");
    let slots = header_slots_with_suite(jpeg, password, suite_id, 0);
    let digest = cover_digest(&DEFAULT_JPEG_FORMAT, &coeffs);
    let suite = DEFAULT_JPEG_FORMAT.suite(suite_id).expect("suite");
    let master = derive_master(suite, password, &digest).unwrap();
    let seed = header_perm_seed(&DEFAULT_JPEG_FORMAT, &master, None);
    let trellis = StcTrellis::from_seed_grouped(
        header_stc_seed(&DEFAULT_JPEG_FORMAT, &seed, None),
        DEFAULT_JPEG_FORMAT.sb_h,
        DEFAULT_JPEG_FORMAT.sb_u,
    )
    .unwrap();
    let vals: Vec<u8> = slots[..DEFAULT_JPEG_FORMAT.superblock_slots()]
        .iter()
        .map(|&idx| {
            let (bi, k) = slot_to_coeff(idx, DEFAULT_JPEG_FORMAT.grid_rule);
            parity(coeffs.components[0].blocks[bi][k])
        })
        .collect();
    let bits = trellis.extract(&vals, DEFAULT_JPEG_FORMAT.superblock_bits());
    let mut raw = [0u8; SUPERBLOCK_BYTES];
    raw.copy_from_slice(&bits[..SUPERBLOCK_BYTES]);
    raw
}

/// Embed `message` into `slots` through the same STC kernel, writing the
/// resulting parities back into the coefficients.
fn stc_write(jpeg: &[u8], slots: &[u32], seed: u64, h: u8, u: u8, message: &[u8]) -> Vec<u8> {
    let mut coeffs = dct_io::read_coefficients(jpeg).expect("coefficients");
    let blocks = &mut coeffs.components[0].blocks;
    let vals: Vec<u8> = slots
        .iter()
        .map(|&idx| {
            let (bi, k) = slot_to_coeff(idx, DEFAULT_JPEG_FORMAT.grid_rule);
            parity(blocks[bi][k])
        })
        .collect();
    let trellis = StcTrellis::from_seed_grouped(seed, h, u).unwrap();
    let n = vals.len();
    let mut deltas = vec![0i8; n];
    trellis
        .embed_with_deltas(
            &vals,
            &vec![Move::Both; n],
            &vec![1.0; n],
            &vec![1.0; n],
            message,
            &mut deltas,
        )
        .expect("header re-embed");
    for (&idx, &delta) in slots.iter().zip(deltas.iter()) {
        if delta == 0 {
            continue;
        }
        let (bi, k) = slot_to_coeff(idx, DEFAULT_JPEG_FORMAT.grid_rule);
        let updated = blocks[bi][k] as i32 + delta as i32;
        assert!(updated.abs() <= 1023);
        blocks[bi][k] = updated as i16;
    }
    dct_io::write_coefficients(jpeg, &coeffs).expect("rewrite")
}

/// Rewrite the superblock of an existing carrier (and optionally its extension
/// area) with mutated field values.
///
/// The AEAD associated data is the superblock itself, so a field change here
/// makes decryption fail -- which is exactly what the binding tests assert.
fn amend_superblock(
    jpeg: &[u8],
    password: &str,
    mutate: impl FnOnce(&mut Superblock),
    extension_area: Option<&[u8]>,
) -> Vec<u8> {
    let raw = read_superblock(jpeg, password);
    let mut sb = Superblock::decode(&raw).expect("decode superblock");
    mutate(&mut sb);
    let encoded = sb.encode();
    let slots = header_slots(jpeg, password, sb.ext_bytes as usize);
    let coeffs = dct_io::read_coefficients(jpeg).expect("coefficients");
    let digest = cover_digest(&DEFAULT_JPEG_FORMAT, &coeffs);
    let master = derive_master(DEFAULT_JPEG_FORMAT.default_suite(), password, &digest).unwrap();
    let seed = header_perm_seed(&DEFAULT_JPEG_FORMAT, &master, None);

    let mut out = stc_write(
        jpeg,
        &slots[..DEFAULT_JPEG_FORMAT.superblock_slots()],
        header_stc_seed(&DEFAULT_JPEG_FORMAT, &seed, None),
        DEFAULT_JPEG_FORMAT.sb_h,
        DEFAULT_JPEG_FORMAT.sb_u,
        &encoded,
    );
    if sb.ext_bytes > 0
        && let Some(area) = extension_area
    {
        {
            assert_eq!(area.len(), sb.ext_bytes as usize);
            out = stc_write(
                &out,
                &slots[DEFAULT_JPEG_FORMAT.superblock_slots()..],
                extension_stc_seed(&DEFAULT_JPEG_FORMAT, &seed, None),
                DEFAULT_JPEG_FORMAT.ext_h,
                DEFAULT_JPEG_FORMAT.ext_u,
                area,
            );
        }
    }
    out
}

fn extract_opts(password: &str) -> StegoOptions {
    StegoOptions {
        password: Some(password.into()),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Roundtrip and the slot contract
// ---------------------------------------------------------------------------

/// 4 KiB / 16 KiB / 64 KiB must round-trip bit for bit on a real photo, and the
/// change rate must fall as the payload shrinks (larger `u`).
#[test]
fn v3_payload_sizes_roundtrip_on_a_photo() {
    let Some(path) = corpus("images/jpg/0001.jpg") else {
        return;
    };
    let cover = fs::read(&path).expect("read cover");
    let password = "V3PayloadSizes#2026";

    for size in [4096usize, 16384, 65536] {
        let payload = incompressible(size, size as u64);
        let stego_opts = StegoOptions {
            algorithm: Some("uerd".into()),
            password: Some(password.into()),
            ..Default::default()
        };
        let stego = embed_carrier(&cover, &payload, &stego_opts)
            .unwrap_or_else(|e| panic!("{size} B: embed failed: {e}"));
        let recovered = extract_carrier(&stego, &stego_opts)
            .unwrap_or_else(|e| panic!("{size} B: extract failed: {e}"));
        assert_eq!(recovered, payload, "{size} B: payload mismatch");

        // DC never moves: the header digest depends on it.
        let before = dct_io::read_coefficients(&cover).expect("cover coefficients");
        let after = dct_io::read_coefficients(&stego).expect("stego coefficients");
        for (cb, ca) in before.components[0]
            .blocks
            .iter()
            .zip(after.components[0].blocks.iter())
        {
            assert_eq!(cb[0], ca[0], "{size} B: DC changed");
            for k in 1..64 {
                assert!(
                    ca[k].abs() <= 1023,
                    "{size} B: coefficient left the baseline range"
                );
                assert!(
                    (ca[k] as i32 - cb[k] as i32).abs() <= 1,
                    "{size} B: move > 1"
                );
            }
        }
    }
}

/// The full Phase 2 gate: 4 KiB / 16 KiB / 64 KiB across 20 corpus photos,
/// bit-for-bit roundtrip. Ignored by default because it embeds 60 carriers.
///
/// ```text
/// cargo test --release --test test_lifecycle v3_payload_matrix -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn v3_payload_matrix_twenty_images() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("temp")
        .join("images")
        .join("jpg");
    let mut files: Vec<PathBuf> = match std::fs::read_dir(&root) {
        Ok(entries) => entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("jpg")))
            .collect(),
        Err(_) => return,
    };
    files.sort();
    files.truncate(20);
    if files.is_empty() {
        return;
    }

    let password = "MatrixGate#2026";
    let opts = StegoOptions {
        algorithm: Some("uerd".into()),
        password: Some(password.into()),
        ..Default::default()
    };
    let done = AtomicUsize::new(0);
    files.par_iter().for_each(|path| {
        let cover = std::fs::read(path).expect("read cover");
        for size in [4096usize, 16384, 65536] {
            let payload = incompressible(size, (size as u64) ^ 0x5EED);
            let stego = match embed_carrier(&cover, &payload, &opts) {
                Ok(stego) => stego,
                // A 64 KiB payload legitimately exceeds small carriers.
                Err(StrHideError::General(message)) if message.contains("Capacity exceeded") => {
                    continue;
                }
                Err(e) => panic!("{}: {size} B: embed failed: {e}", path.display()),
            };
            let recovered = extract_carrier(&stego, &opts)
                .unwrap_or_else(|e| panic!("{}: {size} B: extract failed: {e}", path.display()));
            assert_eq!(recovered, payload, "{}: {size} B", path.display());
            done.fetch_add(1, Ordering::Relaxed);
        }
    });
    let done_count = done.load(Ordering::Relaxed);
    println!("{done_count} roundtrips across {} carriers", files.len());
    assert!(
        done_count >= 30,
        "expected at least 30 roundtrips, got {done_count}"
    );
}

/// The cover digest must be identical before and after embedding: it salts the
/// KDF that locates the header, so any drift would make the carrier unreadable
/// by its own writer.
#[test]
fn v3_cover_digest_is_stable_across_embedding() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let password = "DigestStability#1";
    let stego = embed_carrier(&cover, b"digest stability", &extract_opts(password)).expect("embed");

    let before = dct_io::read_coefficients(&cover).expect("cover coefficients");
    let after = dct_io::read_coefficients(&stego).expect("stego coefficients");
    assert_eq!(
        cover_digest(&DEFAULT_JPEG_FORMAT, &before),
        cover_digest(&DEFAULT_JPEG_FORMAT, &after),
        "the DC-based digest changed"
    );
    // And the digest really covers the DC values: changing one must move it.
    let mut tampered = before.clone();
    tampered.components[0].blocks[0][0] = tampered.components[0].blocks[0][0].wrapping_add(1);
    assert_ne!(
        cover_digest(&DEFAULT_JPEG_FORMAT, &before),
        cover_digest(&DEFAULT_JPEG_FORMAT, &tampered)
    );
}

/// `body_grid` must keep the grid's ascending order and drop exactly the header
/// slots -- a golden check, because a hashed container here would silently
/// reorder the sequence between two processes.
#[test]
fn v3_body_grid_is_an_ordered_set_difference() {
    let grid = grid_indices(4, DEFAULT_JPEG_FORMAT.grid_rule);
    let hdr = vec![3u32, 0, 63, 100];
    let body = strhide::stego::jpeg::v3_layout::body_grid(&grid, &hdr, 4);
    assert_eq!(&body[..4], &[1, 2, 4, 5]);
    assert_eq!(*body.last().unwrap(), grid[grid.len() - 1]);
    assert_eq!(body.len(), grid.len() - hdr.len());
    assert_eq!(
        body,
        strhide::stego::jpeg::v3_layout::body_grid(&grid, &hdr, 4)
    );
}

/// A carrier whose Huffman table is over-optimised must either write the
/// carrier or refuse with a diagnostic that names the missing symbol -- never a
/// bare `CorruptEntropy`, and never a silently broken file.
#[test]
fn v3_sparse_huffman_table_never_fails_silently() {
    // `carrier.jpg` is a synthetic cover whose luma AC table defines only the
    // symbols its own coefficients needed (34 of 162).
    let cover = fs::read(fixture("carrier.jpg")).expect("read carrier");
    let symbols = strhide::stego::jpeg::dht::luma_ac_symbols(&cover).expect("parse DHT");
    assert!(
        !symbols.is_complete(),
        "fixture must be a sparse-table carrier"
    );

    let password = "SparseTable#1";
    let mut written = 0usize;
    for size in [32usize, 256, 1024, 3000] {
        let payload = incompressible(size, size as u64);
        match embed_carrier(&cover, &payload, &extract_opts(password)) {
            Ok(stego) => {
                let recovered = extract_carrier(&stego, &extract_opts(password)).expect("extract");
                assert_eq!(recovered, payload, "{size} B roundtrip");
                written += 1;
            }
            Err(StrHideError::UnsupportedFormat(message)) => {
                assert!(
                    message.contains("Huffman table is over-optimised"),
                    "{size} B: unexpected diagnostic: {message}"
                );
            }
            Err(e) => panic!("{size} B: unexpected error: {e:?}"),
        }
    }
    assert!(
        written > 0,
        "the fixture can carry at least a small payload"
    );
}

/// An over-optimised Huffman table cannot host `u = 1` -- a `(1,1)` parity
/// code has no routing freedom around dead slots and cross-zero chains, so
/// the outcome is a per-salt lottery. The engine must lift the body to a
/// grouped code instead. An explicit tiny slot budget is what pins the old
/// layout to `u = 1` here; the grouped floor overrides it.
#[test]
fn v3_over_optimised_table_keeps_a_grouped_body() {
    // `carrier.jpg` is a synthetic cover whose luma AC table defines only the
    // symbols its own coefficients needed (34 of 162).
    let cover = fs::read(fixture("carrier.jpg")).expect("read carrier");
    let payload = incompressible(8, 0x6C0B_51DE);
    let password = "GroupedBody#1";
    let options = StegoOptions {
        password: Some(password.into()),
        jpeg_params: JpegParams {
            slot_budget: Some(300), // u_budget = 1 without the grouped floor
            ..JpegParams::default()
        },
        ..Default::default()
    };
    let stego = embed_carrier(&cover, &payload, &options).expect("embed must lift u to >= 2");
    let recovered = extract_carrier(&stego, &extract_opts(password)).expect("extract");
    assert_eq!(recovered, payload, "grouped body must round-trip");
}

/// When not even `u = 3` fits the carrier, the embed must refuse immediately
/// with the actionable diagnostic instead of running a lottery it cannot
/// win: 5 KiB on the 256x256 fixture leaves room for `u = 1` only, and the
/// fixture's table is far too sparse for that.
#[test]
fn v3_over_optimised_table_refuses_when_no_group_fits() {
    let cover = fs::read(fixture("carrier.jpg")).expect("read carrier");
    let payload = incompressible(5_000, 0x5A22_0FFE);
    let err = embed_carrier(&cover, &payload, &extract_opts("RefuseEarly#1"))
        .expect_err("must refuse, not gamble");
    match err {
        StrHideError::UnsupportedFormat(message) => {
            assert!(
                message.contains("Huffman table is over-optimised"),
                "{message}"
            );
            assert!(message.contains("reduce payload"), "{message}");
        }
        other => panic!("unexpected error: {other:?}"),
    }

    // layout_for_payload must refuse with the exact same diagnostic
    let layout_err = strhide::stego::jpeg::engine::layout_for_payload(
        &cover,
        payload.len(),
        &JpegParams::default(),
        &strhide::stego::format::DEFAULT_JPEG_FORMAT,
    )
    .expect_err("layout_for_payload must also refuse");
    match layout_err {
        StrHideError::UnsupportedFormat(message) => {
            assert!(message.contains("Huffman table is over-optimised"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

/// An explicit budget that lands on `u = 2` must also be lifted to `u = 3`
/// on an over-optimised carrier because `u = 2` has insufficient degrees
/// of freedom to avoid dead slots reliably.
#[test]
fn v3_over_optimised_table_lifts_u_two_to_u_three() {
    let cover = fs::read(fixture("carrier.jpg")).expect("read carrier");
    let payload = incompressible(8, 0x1234_5678);
    let password = "LiftU2#1";
    // window for 8 bytes is (8 + 21)*8 + 7 = 239 slots.
    // budget = 500 gives u_budget = 500 / 239 = 2.
    let options = StegoOptions {
        password: Some(password.into()),
        jpeg_params: JpegParams {
            slot_budget: Some(500),
            ..JpegParams::default()
        },
        ..Default::default()
    };
    let stego = embed_carrier(&cover, &payload, &options).expect("embed must lift u to 3");
    let recovered = extract_carrier(&stego, &extract_opts(password)).expect("extract");
    assert_eq!(recovered, payload, "round-trip bit-exact");

    let layout = strhide::stego::jpeg::engine::layout_for_payload(
        &cover,
        payload.len(),
        &options.jpeg_params,
        &strhide::stego::format::DEFAULT_JPEG_FORMAT,
    )
    .expect("layout");
    assert_eq!(layout.u, 3, "layout_for_payload must also report u = 3");
}

/// The over-optimised-Huffman corpus gate: `std` tables take the fast path,
/// `opt` tables take the symbol-checked path, and both round-trip at 4 KiB.
/// Ignored by default: the corpus lives in `temp/` (or `$STRHIDE_STEGO_CORPUS`).
#[test]
#[ignore]
fn v3_huffman_corpus_roundtrips() {
    let Some(std_dir) = corpus("jpeg_huffman/std") else {
        return;
    };
    let Some(opt_dir) = corpus("jpeg_huffman/opt") else {
        return;
    };
    let payload = incompressible(4096, 0xC0FFEE);
    let password = "HuffmanCorpus#1";

    let mut checked = 0usize;
    let mut groups: Vec<(Vec<PathBuf>, Option<bool>)> = Vec::new();
    for (dir, expect_complete) in [(std_dir, true), (opt_dir, false)] {
        let mut files: Vec<PathBuf> = fs::read_dir(&dir)
            .expect("read dir")
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("jpg")))
            .collect();
        files.sort();
        assert!(!files.is_empty(), "no JPEGs in {}", dir.display());
        groups.push((files, Some(expect_complete)));
    }
    // The real-world sparse-table samples: a 24 MP camera-and-ffmpeg export and
    // a small web sample. Their table completeness differs, so it is not
    // asserted -- only that they round-trip.
    let extras: Vec<PathBuf> = ["testfiles/file-08.jpg", "real_samples/sample.jpg"]
        .iter()
        .filter_map(|rel| corpus(rel))
        .collect();
    if !extras.is_empty() {
        groups.push((extras, None));
    }

    for (files, expect_complete) in groups {
        for path in files {
            let cover = fs::read(&path).expect("read");
            let symbols = strhide::stego::jpeg::dht::luma_ac_symbols(&cover).expect("parse DHT");
            if let Some(expected) = expect_complete {
                assert_eq!(
                    symbols.is_complete(),
                    expected,
                    "{}: table completeness",
                    path.display()
                );
            }
            let stego = embed_carrier(&cover, &payload, &extract_opts(password))
                .unwrap_or_else(|e| panic!("{}: embed failed: {e}", path.display()));
            let recovered = extract_carrier(&stego, &extract_opts(password))
                .unwrap_or_else(|e| panic!("{}: extract failed: {e}", path.display()));
            assert_eq!(recovered, payload, "{}", path.display());
            checked += 1;
        }
    }
    println!("{checked} over-optimised/standard table carriers round-tripped");
}

/// `BodyGrid = Grid \ HdrSlots`: the two sets must be disjoint and their union
/// must be the whole grid, for every extension size.
#[test]
fn v3_header_and_body_slots_are_disjoint() {
    let jpeg = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    for ext_bytes in [0usize, 3, 40] {
        let slots = header_slots(&jpeg, "pw", ext_bytes);
        assert_eq!(slots.len(), DEFAULT_JPEG_FORMAT.header_slots(ext_bytes));
        let coeffs = dct_io::read_coefficients(&jpeg).expect("coefficients");
        let grid = grid_indices(
            coeffs.components[0].blocks.len(),
            DEFAULT_JPEG_FORMAT.grid_rule,
        );
        let body = strhide::stego::jpeg::v3_layout::body_grid(
            &grid,
            &slots,
            coeffs.components[0].blocks.len(),
        );
        assert_eq!(body.len(), grid.len() - slots.len());
        for idx in &slots {
            assert!(!body.contains(idx), "slot {idx} is in both sets");
        }
        // The body grid keeps the engine's ascending order; the header set is a
        // permutation and is deliberately stored in random order.
        assert!(body.is_sorted());
    }
}

/// The header slots must depend on the password (and the cover), not on the
/// embedded payload: two carriers of the same cover share their header slots.
#[test]
fn v3_header_slots_are_keyed_by_password_only() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let a = incompressible(32, 1);
    let b = incompressible(48, 2);
    let opts_a = extract_opts("shared-password");
    let opts_b = extract_opts("other-password");
    let stego_a = embed_carrier(&cover, &a, &opts_a).expect("embed a");
    let stego_b = embed_carrier(&cover, &b, &opts_a).expect("embed b");
    assert_eq!(
        header_slots(&stego_a, "shared-password", 0),
        header_slots(&cover, "shared-password", 0)
    );
    assert_eq!(
        header_slots(&stego_b, "shared-password", 0),
        header_slots(&cover, "shared-password", 0)
    );
    assert_ne!(
        header_slots(&cover, "shared-password", 0),
        header_slots(&cover, "other-password", 0)
    );
    assert!(extract_carrier(&stego_b, &opts_b).is_err());
}

// ---------------------------------------------------------------------------
// Superblock binding
// ---------------------------------------------------------------------------

/// A field that passes the structural checks but differs from the one used at
/// embed time must fail the AEAD: the whole superblock is associated data.
#[test]
fn v3_superblock_is_bound_by_aad() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let password = "AadBinding#1";
    let payload = b"aad binding payload";
    let stego = embed_carrier(&cover, payload, &extract_opts(password)).expect("embed");

    // `version_minor` is not validated, so only the AAD can catch it.
    let tampered = amend_superblock(&stego, password, |sb| sb.version_minor = 9, None);
    let err = extract_carrier(&tampered, &extract_opts(password)).unwrap_err();
    assert!(
        matches!(err, StrHideError::NoHiddenData(_)),
        "AAD must reject a changed minor version, got {err:?}"
    );

    // `u` is validated, but it is also AAD-covered: either way, no garbage.
    let tampered = amend_superblock(
        &stego,
        password,
        |sb| sb.u = sb.u.wrapping_add(1).max(1),
        None,
    );
    let err = extract_carrier(&tampered, &extract_opts(password)).unwrap_err();
    assert!(matches!(err, StrHideError::NoHiddenData(_)), "{err:?}");
}

/// Reserved flags must be rejected outright.
#[test]
fn v3_reserved_flags_are_rejected() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let password = "ReservedFlags#1";
    let stego = embed_carrier(&cover, b"flags payload", &extract_opts(password)).expect("embed");
    let tampered = amend_superblock(&stego, password, |sb| sb.flags = 1, None);
    assert!(extract_carrier(&tampered, &extract_opts(password)).is_err());
}

/// A carrier written with a newer minor version still decodes: minor versions
/// only add optional extensions.
#[test]
fn v3_newer_minor_version_is_accepted() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let password = "MinorCompat#1";
    let payload = b"minor version forward compatibility";
    let mut fmt = DEFAULT_JPEG_FORMAT;
    fmt.format_minor = 7;
    let params = JpegParams::default();
    let stego = embed_jpeg(
        &cover,
        payload,
        Some(password),
        None,
        &fmt,
        &params,
        &UerdCostModel,
        strhide::stego::Freshness::Random,
    )
    .expect("embed with minor=7");

    let raw = read_superblock(&stego, password);
    assert_eq!(raw[1], 7);
    let recovered = extract_carrier(&stego, &extract_opts(password)).expect("extract");
    assert_eq!(recovered, payload);
}

/// A different major version is a different format; it must not decode.
#[test]
fn v3_other_major_version_is_not_decodable() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let password = "MajorCompat#1";
    let mut fmt = DEFAULT_JPEG_FORMAT;
    fmt.format_major = 2;
    let stego = embed_jpeg(
        &cover,
        b"major version mismatch",
        Some(password),
        None,
        &fmt,
        &JpegParams::default(),
        &UerdCostModel,
        strhide::stego::Freshness::Random,
    )
    .expect("embed with major=2");
    // The other build's header is located by a different label set, so the
    // default build simply finds nothing -- no distinguishable error.
    let err = extract_carrier(&stego, &extract_opts(password)).unwrap_err();
    assert!(matches!(err, StrHideError::NoHiddenData(_)), "{err:?}");
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

/// Extension records round-trip, and unknown non-critical records are skipped.
#[test]
fn v3_extensions_roundtrip_and_skip_unknowns() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let password = "Extensions#1";
    let payload = b"payload with extension area";
    let params = JpegParams {
        extensions: vec![
            Tlv {
                type_id: 0x01,
                value: vec![1, 2, 3, 4],
            },
            // Non-critical, unknown to every build: must be skipped.
            Tlv {
                type_id: 0x42,
                value: b"future".to_vec(),
            },
        ],
        ..JpegParams::default()
    };
    let stego = embed_jpeg(
        &cover,
        payload,
        Some(password),
        None,
        &DEFAULT_JPEG_FORMAT,
        &params,
        &UerdCostModel,
        strhide::stego::Freshness::Random,
    )
    .expect("embed with extensions");
    let raw = read_superblock(&stego, password);
    let sb = Superblock::decode(&raw).expect("decode");
    assert_eq!(sb.ext_bytes as usize, 6 + 8);
    let recovered = extract_carrier(&stego, &extract_opts(password)).expect("extract");
    assert_eq!(recovered, payload);
}

/// An unknown *critical* record must stop the decoder instead of being ignored.
#[test]
fn v3_unknown_critical_extension_is_rejected() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let password = "CriticalExt#1";
    let params = JpegParams {
        extensions: vec![Tlv {
            type_id: 0x81,
            value: vec![9],
        }],
        ..JpegParams::default()
    };
    let stego = embed_jpeg(
        &cover,
        b"critical extension",
        Some(password),
        None,
        &DEFAULT_JPEG_FORMAT,
        &params,
        &UerdCostModel,
        strhide::stego::Freshness::Random,
    )
    .expect("embed with critical extension");
    let err = extract_carrier(&stego, &extract_opts(password)).unwrap_err();
    assert!(
        matches!(err, StrHideError::UnsupportedVersion(_)),
        "critical extension must be refused, got {err:?}"
    );
}

/// A malformed extension area is reported as corruption, not as "no payload":
/// the payload already decrypted, so the carrier is known to be ours.
#[test]
fn v3_malformed_extension_area_is_reported() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let password = "MalformedExt#1";
    let params = JpegParams {
        extensions: vec![Tlv {
            type_id: 0x01,
            value: vec![1, 2, 3],
        }],
        ..JpegParams::default()
    };
    let stego = embed_jpeg(
        &cover,
        b"malformed extension",
        Some(password),
        None,
        &DEFAULT_JPEG_FORMAT,
        &params,
        &UerdCostModel,
        strhide::stego::Freshness::Random,
    )
    .expect("embed");

    // Claim a 200-byte TLV inside a 5-byte area.
    let slots = header_slots(&stego, password, 5);
    let coeffs = dct_io::read_coefficients(&stego).expect("coefficients");
    let digest = cover_digest(&DEFAULT_JPEG_FORMAT, &coeffs);
    let master = derive_master(DEFAULT_JPEG_FORMAT.default_suite(), password, &digest).unwrap();
    let seed = header_perm_seed(&DEFAULT_JPEG_FORMAT, &master, None);
    let broken = stc_write(
        &stego,
        &slots[DEFAULT_JPEG_FORMAT.superblock_slots()..],
        extension_stc_seed(&DEFAULT_JPEG_FORMAT, &seed, None),
        DEFAULT_JPEG_FORMAT.ext_h,
        DEFAULT_JPEG_FORMAT.ext_u,
        &[0x01, 200, 1, 2, 3],
    );
    let err = extract_carrier(&broken, &extract_opts(password)).unwrap_err();
    assert!(
        matches!(err, StrHideError::CorruptedData(_)),
        "malformed extension must be CorruptedData, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Cipher suites
// ---------------------------------------------------------------------------

/// Both implemented suites round-trip, and extraction identifies the suite from
/// the carrier alone.
#[test]
fn v3_suite_matrix_roundtrips() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    for suite_id in [1u16, 2] {
        let password = format!("SuiteMatrix#{suite_id}");
        let payload = b"suite matrix payload";
        let params = JpegParams {
            cipher_suite: suite_id,
            ..JpegParams::default()
        };
        let stego = embed_jpeg(
            &cover,
            payload,
            Some(&password),
            None,
            &DEFAULT_JPEG_FORMAT,
            &params,
            &UerdCostModel,
            strhide::stego::Freshness::Random,
        )
        .unwrap_or_else(|e| panic!("suite {suite_id}: embed failed: {e}"));
        let raw = read_superblock_with_suite(&stego, &password, suite_id);
        assert_eq!(u16::from_be_bytes([raw[36], raw[37]]), suite_id);
        let recovered = extract_carrier(&stego, &extract_opts(&password))
            .unwrap_or_else(|e| panic!("suite {suite_id}: extract failed: {e}"));
        assert_eq!(recovered, payload);
    }
}

/// A suite the extract policy does not allow is simply not tried.
#[test]
fn v3_extract_policy_can_exclude_a_suite() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let password = "PolicySuite#2";
    let params = JpegParams {
        cipher_suite: 2,
        ..JpegParams::default()
    };
    let stego = embed_jpeg(
        &cover,
        b"suite policy",
        Some(password),
        None,
        &DEFAULT_JPEG_FORMAT,
        &params,
        &UerdCostModel,
        strhide::stego::Freshness::Random,
    )
    .expect("embed suite 2");

    let mut opts = extract_opts(password);
    opts.extract_params.allowed_suites = Some(vec![1]);
    let err = extract_carrier(&stego, &opts).unwrap_err();
    assert!(matches!(err, StrHideError::NoHiddenData(_)), "{err:?}");

    // ... and works again when the suite is allowed.
    assert!(extract_carrier(&stego, &extract_opts(password)).is_ok());
}

/// A KDF-cost ceiling below the suite's cost means "do not run it".
#[test]
fn v3_kdf_cost_ceiling_is_enforced() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let password = "CostCeiling#1";
    let stego = embed_carrier(&cover, b"cost ceiling", &extract_opts(password)).expect("embed");

    let mut opts = extract_opts(password);
    opts.extract_params.max_pbkdf2_iterations = 100_000; // suite 1 needs 200k
    let started = Instant::now();
    let err = extract_carrier(&stego, &opts).unwrap_err();
    let elapsed = started.elapsed();
    assert!(matches!(err, StrHideError::NoHiddenData(_)), "{err:?}");
    assert!(
        elapsed.as_millis() < 150,
        "the ceiling must skip the KDF, took {elapsed:?}"
    );
}

/// A wrong password must cost a full KDF per suite attempt: there is no cheap
/// structural path that can reject a guess.
#[test]
fn v3_wrong_password_costs_a_kdf_each_time() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let password = "OracleGate#1";
    let stego = embed_carrier(&cover, b"oracle cost gate", &extract_opts(password)).expect("embed");

    let single_kdf = {
        let started = Instant::now();
        let _ = derive_master(DEFAULT_JPEG_FORMAT.default_suite(), "probe", b"digest").unwrap();
        started.elapsed()
    };

    const ATTEMPTS: u32 = 8;
    let started = Instant::now();
    for attempt in 0..ATTEMPTS {
        let opts = extract_opts(&format!("wrong-{attempt}"));
        assert!(extract_carrier(&stego, &opts).is_err());
    }
    let per_attempt = started.elapsed() / ATTEMPTS;
    assert!(
        per_attempt.as_secs_f64() >= single_kdf.as_secs_f64() * 0.9,
        "a failed guess took {per_attempt:?}, less than one KDF ({single_kdf:?})"
    );
}

/// A correct password costs one KDF (the default suite is tried first).
#[test]
fn v3_correct_password_costs_one_kdf() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let password = "OneKdf#1";
    let stego = embed_carrier(&cover, b"one kdf", &extract_opts(password)).expect("embed");
    let single_kdf = {
        let started = Instant::now();
        let _ = derive_master(DEFAULT_JPEG_FORMAT.default_suite(), "probe", b"digest").unwrap();
        started.elapsed()
    };
    let started = Instant::now();
    let recovered = extract_carrier(&stego, &extract_opts(password)).expect("extract");
    let elapsed = started.elapsed();
    assert_eq!(recovered, b"one kdf");
    assert!(
        elapsed.as_secs_f64() < single_kdf.as_secs_f64() * 3.0,
        "correct password took {elapsed:?} for a {single_kdf:?} KDF"
    );
}

/// Wrong password and non-carrier must produce the same error kind.
#[test]
fn v3_wrong_password_and_clean_carrier_look_identical() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let stego = embed_carrier(&cover, b"indistinguishable", &extract_opts("right")).expect("embed");

    let wrong = extract_carrier(&stego, &extract_opts("wrong")).unwrap_err();
    let clean = extract_carrier(&cover, &extract_opts("right")).unwrap_err();
    assert!(matches!(wrong, StrHideError::NoHiddenData(_)), "{wrong:?}");
    assert!(matches!(clean, StrHideError::NoHiddenData(_)), "{clean:?}");
    assert!(extract_carrier(&cover, &extract_opts("wrong")).is_err());
}

// ---------------------------------------------------------------------------
// Coefficient bounds and capacity
// ---------------------------------------------------------------------------

/// `|c| = 1023` may only shrink: `category(1024) == 11` is not encodable, and
/// the write-back must never produce it.
#[test]
fn v3_ac_boundary_never_overflows() {
    let source = fixture("carrier_q100.jpg");
    let cover = fs::read(&source).expect("read carrier");
    // Push some AC positions to the boundary; the table is complete, so the
    // re-encode is safe.
    let mut coeffs = dct_io::read_coefficients(&cover).expect("coefficients");
    for (bi, block) in coeffs.components[0].blocks.iter_mut().enumerate() {
        block[5] = if bi % 2 == 0 { 1023 } else { -1023 };
        block[10] = 1022;
    }
    let boundary_cover = dct_io::write_coefficients(&cover, &coeffs).expect("write boundary cover");

    let password = "Boundary1023#1";
    let payload = incompressible(64, 5);
    let stego = embed_carrier(&boundary_cover, &payload, &extract_opts(password)).expect("embed");
    let after = dct_io::read_coefficients(&stego).expect("stego coefficients");
    for block in &after.components[0].blocks {
        for (k, &value) in block.iter().enumerate().skip(1) {
            assert!(
                value.abs() <= 1023,
                "coefficient {k} reached {value} (category 11)"
            );
        }
    }
    let recovered = extract_carrier(&stego, &extract_opts(password)).expect("extract");
    assert_eq!(recovered, payload);
}

/// Nearly every AC position must be movable: only `|c| = 1023` is restricted.
#[test]
fn v3_movable_slot_density_is_above_99_percent() {
    let cover = fs::read(fixture("carrier_q100.jpg")).expect("read carrier");
    let coeffs = dct_io::read_coefficients(&cover).expect("coefficients");
    let mut boundary = 0usize;
    let mut total = 0usize;
    for block in &coeffs.components[0].blocks {
        for &value in block.iter().skip(1) {
            total += 1;
            if value.abs() == 1023 {
                boundary += 1;
            }
        }
    }
    assert!(total > 0);
    assert!(
        boundary as f64 / total as f64 <= 0.01,
        "wet points: {boundary}/{total}"
    );
}

/// The capacity probe must be tight: the reported maximum embeds, one byte more
/// does not.
#[test]
fn v3_capacity_probe_is_tight() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let params = JpegParams::default();
    let cap = probe_jpeg_capacity(
        &cover,
        &UerdCostModel,
        &params,
        SafetyLevel::High,
        &strhide::stego::format::DEFAULT_JPEG_FORMAT,
    )
    .expect("probe");
    assert!(cap.available_slots > 0);
    assert_eq!(cap.total_elements, 256 * 64);

    let exact = incompressible(cap.max_raw_payload_bytes, 9);
    let stego = embed_jpeg(
        &cover,
        &exact,
        Some("tight"),
        None,
        &DEFAULT_JPEG_FORMAT,
        &params,
        &UerdCostModel,
        strhide::stego::Freshness::Random,
    )
    .expect("probe maximum must embed");
    let recovered = extract_jpeg(
        &stego,
        Some("tight"),
        None,
        &DEFAULT_JPEG_FORMAT,
        &ExtractParams::default(),
    )
    .expect("extract");
    assert_eq!(recovered, exact);

    let over = incompressible(cap.max_raw_payload_bytes + 32, 10);
    assert!(
        embed_jpeg(
            &cover,
            &over,
            Some("tight"),
            None,
            &DEFAULT_JPEG_FORMAT,
            &params,
            &UerdCostModel,
            strhide::stego::Freshness::Random
        )
        .is_err(),
        "one payload step above the maximum must fail"
    );
}

/// Extraction must work with a *different* embed-time configuration: `u` comes
/// from the superblock, not from the local slot budget.
#[test]
fn v3_extraction_ignores_the_embed_side_budget() {
    let cover = fs::read(fixture("carrier_photo.jpg")).expect("read carrier");
    let password = "BudgetIndependence#1";
    let payload = b"budget independence";
    let params = JpegParams {
        slot_budget: Some(1_000),
        ..JpegParams::default()
    };
    let stego = embed_jpeg(
        &cover,
        payload,
        Some(password),
        None,
        &DEFAULT_JPEG_FORMAT,
        &params,
        &UerdCostModel,
        strhide::stego::Freshness::Random,
    )
    .expect("embed with a tiny budget");

    let other = JpegParams {
        slot_budget: Some(4_000_000),
        ..JpegParams::default()
    };
    assert_ne!(other, params);
    let recovered = extract_carrier(&stego, &extract_opts(password)).expect("extract");
    assert_eq!(recovered, payload);
}
