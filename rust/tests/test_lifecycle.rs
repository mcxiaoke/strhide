//! Unified carrier lifecycle integration tests suite.
//!
//! Submodules:
//! - `matrix`: format-preserving injection & bit-for-bit restore matrix across carriers and strategies.
//! - `stego`: content-adaptive pixel/DCT steganography lifecycle (HILL, UERD, STC).
//! - `stego_jpeg_v4`: JPEG V4 envelope contract (superblock, extensions, suites, slots).
//! - `compact_meta`: compact metadata envelope encoding on marginal carriers.
//! - `jpeg_multisegment`: multi-segment JPEG APP15 payload splitting.
//! - `unicode_and_binary`: UTF-8/Unicode and arbitrary binary payloads.
//! - `profile`: `LocalParams` / `StructureProfile` plumbing and dialect isolation (M1).
//! - `jpeg_juniward`: J-UNIWARD cost model integration.
//! - `jpeg_jmipod`: J-MiPOD cost model integration.
//! - `png_mipod`: MiPOD cost model integration and self-describing carrier.
//! - `jpeg_polarization`: Cost polarization end-to-end behavior.
//! - `png_self_describing`: PNG self-describing wire format.
//! - `reproducible`: Seeded deterministic embedding reproducibility.
//! - `api_bytes`: In-memory carrier bytes API.
//! - `facade`: StrHide facade integration tests.

#[path = "common/mod.rs"]
pub mod common;

#[path = "test_lifecycle/api_bytes.rs"]
mod api_bytes;
#[path = "test_lifecycle/cancellation.rs"]
mod cancellation;
#[path = "test_lifecycle/compact_meta.rs"]
mod compact_meta;
#[path = "test_lifecycle/facade.rs"]
mod facade;
#[path = "test_lifecycle/jpeg_jmipod.rs"]
mod jpeg_jmipod;
#[path = "test_lifecycle/jpeg_juniward.rs"]
mod jpeg_juniward;
#[path = "test_lifecycle/jpeg_multisegment.rs"]
mod jpeg_multisegment;
#[path = "test_lifecycle/jpeg_polarization.rs"]
mod jpeg_polarization;
#[path = "test_lifecycle/matrix.rs"]
mod matrix;
#[path = "test_lifecycle/png_mipod.rs"]
mod png_mipod;
#[path = "test_lifecycle/png_self_describing.rs"]
mod png_self_describing;
#[path = "test_lifecycle/profile.rs"]
mod profile;
#[path = "test_lifecycle/reproducible.rs"]
mod reproducible;
#[path = "test_lifecycle/sniff.rs"]
mod sniff;
#[path = "test_lifecycle/stego.rs"]
mod stego;
#[path = "test_lifecycle/stego_credentials.rs"]
mod stego_credentials;
#[path = "test_lifecycle/stego_jpeg_v4.rs"]
mod stego_jpeg_v4;
#[path = "test_lifecycle/unicode_and_binary.rs"]
mod unicode_and_binary;

// Shared-fixture self-checks run exactly once for the whole suite. They used to
// live in `common/mod.rs`, which is `#[path]`-included by seven targets, so each
// check executed seven times; CI runs all targets in one command, so a single
// execution is enough.
#[test]
fn make_png_fixture_is_decodable_as_1x1() {
    let png = common::make_png();
    let image = strhide::stego::png::decode_png(&png).expect("fixture must decode");
    assert_eq!((image.width, image.height), (1, 1));
    assert_eq!(image.channels, 3);
    assert_eq!(image.pixels, vec![255, 255, 255]);
}

#[test]
fn verify_test_threads_limit() {
    if let Ok(threads) = std::env::var("RUST_TEST_THREADS") {
        assert_eq!(threads, "8", "RUST_TEST_THREADS should be set to 8");
    }
    if let Ok(rayon_threads) = std::env::var("RAYON_NUM_THREADS") {
        assert_eq!(rayon_threads, "8", "RAYON_NUM_THREADS should be set to 8");
    }
    assert!(
        rayon::current_num_threads() <= 8,
        "Rayon thread pool exceeds 8: {}",
        rayon::current_num_threads()
    );
}
