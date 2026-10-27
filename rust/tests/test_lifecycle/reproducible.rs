//! Reproducibility contract for seeded embeddings.
//!
//! `Freshness::Seeded` exists so a run can be replayed: same carrier, payload,
//! password and seed must produce the same stego file. These tests pin that, and
//! pin that the default path still varies.

use strhide::core::payload::Payload;
use strhide::stego::prng::deterministic_payload;
use strhide::stego::{EmbedOptions, ExtractOptions, Freshness, embed_carrier, extract_carrier};

const JPG: &[u8] = include_bytes!("../assets/small.jpg");
// `minimal.png` is 1x1 and has no capacity; this one is a real carrier.
const PNG: &[u8] = include_bytes!("../fixtures/carrier.png");

fn seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0x5a;
    s[31] = 0xa5;
    s
}

fn seeded() -> EmbedOptions<'static> {
    EmbedOptions {
        freshness: Freshness::Seeded(seed()),
        ..Default::default()
    }
}

#[test]
fn jpeg_seeded_embedding_is_byte_identical() {
    let payload = deterministic_payload(4096, 3);
    let first = embed_carrier(JPG, &Payload::bytes(&payload), &seeded()).expect("first embed");
    let second = embed_carrier(JPG, &Payload::bytes(&payload), &seeded()).expect("second embed");

    assert_eq!(
        first, second,
        "a seeded run must not depend on wall-clock or OS randomness"
    );

    let back = extract_carrier(&first, &ExtractOptions::default()).expect("extract");
    assert_eq!(back, payload, "reproducible output must still round-trip");
}

#[test]
fn png_seeded_embedding_is_byte_identical() {
    let payload = deterministic_payload(64, 11);
    let first = embed_carrier(PNG, &Payload::bytes(&payload), &seeded()).expect("first embed");
    let second = embed_carrier(PNG, &Payload::bytes(&payload), &seeded()).expect("second embed");

    assert_eq!(first, second);
    let back = extract_carrier(&first, &ExtractOptions::default()).expect("extract");
    assert_eq!(back, payload);
}

#[test]
fn seeds_select_different_embeddings() {
    let payload = deterministic_payload(1024, 5);

    let mut other = seed();
    other[0] ^= 0xff;
    let options = EmbedOptions {
        freshness: Freshness::Seeded(other),
        ..Default::default()
    };

    let a = embed_carrier(JPG, &Payload::bytes(&payload), &seeded()).expect("seed A");
    let b = embed_carrier(JPG, &Payload::bytes(&payload), &options).expect("seed B");
    assert_ne!(a, b, "different seeds must not collapse to the same stego");

    // Both must decode: the salt travels in the superblock, so the reader never
    // needs to know which seed was used.
    assert_eq!(
        extract_carrier(&a, &ExtractOptions::default()).unwrap(),
        payload
    );
    assert_eq!(
        extract_carrier(&b, &ExtractOptions::default()).unwrap(),
        payload
    );
}

#[test]
fn payload_generator_is_stable_across_runs() {
    let a = deterministic_payload(1000, 42);
    let b = deterministic_payload(1000, 42);
    assert_eq!(a, b);
    assert_eq!(a.len(), 1000);
    assert_ne!(a, deterministic_payload(1000, 43));
    assert_eq!(deterministic_payload(0, 1).len(), 0);
}

#[test]
fn default_freshness_still_varies() {
    // The production path must stay random: two embeddings of the same payload
    // into the same carrier with the same password differ only by salt/nonce.
    let payload = deterministic_payload(1024, 9);
    let a =
        embed_carrier(JPG, &Payload::bytes(&payload), &EmbedOptions::default()).expect("embed A");
    let b =
        embed_carrier(JPG, &Payload::bytes(&payload), &EmbedOptions::default()).expect("embed B");
    assert_ne!(
        a, b,
        "Freshness::Random must draw fresh salt and nonce per call"
    );
}
