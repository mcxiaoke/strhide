//! Security tests: envelope locator must not be usable as an allocation primitive.
//!
//! An attacker who can edit a carrier can rewrite the 24-byte trailer at EOF.
//! Its `ube_offset` / `ube_total_size` are protected by CRC-32 only — a
//! checksum, not a MAC — so both are free to change. Combined with a forged
//! `meta_len` in the (equally editable) header, uncontrolled allocation
//! must be prevented to avoid denial of service.
//!
//! The fix has two independent layers, and these tests exercise both: every
//! located envelope must fit inside the physical file before any buffer is
//! sized from it, and `meta_len` has an absolute cap.

use crate::common::*;
use std::fs;
use std::path::{Path, PathBuf};

use strhide::crypto::{decrypt_metadata, derive_keys, encrypt_metadata};
use strhide::structure::envelope::{
    EnvelopeHeader, EnvelopeTrailer, HEADER_SIZE, MAX_META_LEN, STANDARD_TRAILER_MAGIC,
    TRAILER_SIZE,
};
use strhide::structure::params::StructureProfile;
use strhide::structure::{
    CarrierMetadata, PayloadSource, ReadOptions, WriteOptions, inspect_carrier, read_carrier,
    verify_carrier, write_carrier,
};

/// Offset of the envelope inside a freshly written `eof`/append-strategy carrier.
fn envelope_offset(path: &Path) -> u64 {
    let data = fs::read(path).unwrap();
    let tail = &data[data.len() - TRAILER_SIZE..];
    EnvelopeTrailer::unpack(tail, None)
        .expect("a fresh carrier must carry a valid trailer")
        .ube_offset
}

/// Rewrite `meta_len` *logically* (the default-mode header is XOR-masked, so a
/// raw byte patch would not land on the intended value) and forge the trailer
/// so it declares a 1 TiB envelope at the same offset.
fn forge_envelope(path: &Path, ube_offset: u64, meta_len: u32) {
    let mut data = fs::read(path).unwrap();
    let start = ube_offset as usize;

    let mut header =
        EnvelopeHeader::unpack_with_password(&data[start..start + HEADER_SIZE], None).unwrap();
    header.meta_len = meta_len;
    let packed = header
        .pack_with_profile(None, &StructureProfile::default())
        .unwrap();
    data[start..start + HEADER_SIZE].copy_from_slice(&packed);

    // CRC-32 over the two forged fields, exactly as `EnvelopeTrailer::unpack`
    // recomputes it, so the trailer parses and the locator accepts it.
    let forged = EnvelopeTrailer::create(ube_offset, 1u64 << 40, STANDARD_TRAILER_MAGIC);
    let n = data.len();
    data[n - TRAILER_SIZE..].copy_from_slice(&forged.pack());
    fs::write(path, data).unwrap();
}

fn write_carrier_with(dir: &Path, name: &str, carrier: Vec<u8>, strategy: &str) -> PathBuf {
    let carrier_path = dir.join(format!("{name}-carrier"));
    let out = dir.join(format!("{name}-stego"));
    fs::write(&carrier_path, carrier).unwrap();
    write_carrier(
        &carrier_path,
        PayloadSource::Text("forged"),
        &WriteOptions::default()
            .with_output(&out)
            .with_strategy(strategy)
            .with_backup(false),
    )
    .unwrap();
    out
}

/// The read/inspect/verify entry points must all treat the forged envelope as
/// "nothing here" instead of acting on the declared size.
fn assert_forged_envelope_is_inert(path: &Path, label: &str) {
    let err = read_carrier(
        path,
        &ReadOptions::default().with_output(&path.with_extension("out")),
    )
    .expect_err("a forged envelope must not be readable");
    let err = err.to_string().to_lowercase();
    assert!(
        err.contains("no hidden") || err.contains("no valid"),
        "{label}: unexpected error: {err}"
    );

    let inspected = inspect_carrier(path, None).unwrap();
    assert!(
        !inspected.has_hidden_data,
        "{label}: inspect reported hidden data for a forged envelope"
    );

    let verified = verify_carrier(path, None).unwrap();
    assert!(
        !verified.level2_envelope.ok,
        "{label}: verify accepted a forged envelope ({})",
        verified.level2_envelope.detail
    );
}

#[test]
fn forged_eof_envelope_size_is_rejected_without_allocating() {
    let dir = scratch("forge_eof");
    let stego = write_carrier_with(&dir, "eof", make_png(), "eof");
    let ube_offset = envelope_offset(&stego);
    // 4 GiB metadata on a ~1 KiB file: the pre-fix code allocated this before
    // it could discover the stream was short.
    forge_envelope(&stego, ube_offset, 0xFFFF_FFF0);
    assert_forged_envelope_is_inert(&stego, "eof");
}

/// A legitimate envelope can still declare a high-ratio compressed payload.
/// Before the fix `raw_size` was only checked against the 1 GiB absolute cap
/// *after* decrypting, so a tiny carrier could force the reader to decrypt and
/// then start decompressing up to 1 GiB. The limit must now be derived from the
/// physical carrier size and checked before decryption.
#[test]
fn oversized_declared_payload_is_rejected_before_decrypt() {
    let dir = scratch("forge_declared_size");
    let carrier = dir.join("carrier.png");
    fs::write(&carrier, make_png()).unwrap();
    // 10 MB compresses to well under 1 MiB and is still inside the 64 MiB
    // floor of the writer's limit, so the envelope is legitimately writable.
    // Its `raw_size` has the same number of JSON digits as the forged value
    // below, which lets us swap it without changing the metadata length.
    let payload = vec![0u8; 10_000_000];
    let stego = dir.join("stego.png");
    write_carrier(
        &carrier,
        PayloadSource::Bytes(&payload),
        &WriteOptions::default()
            .with_output(&stego)
            .with_strategy("eof")
            .with_backup(false),
    )
    .unwrap();
    assert!(
        fs::metadata(&stego).unwrap().len() < 1024 * 1024,
        "test payload should compress into a small envelope"
    );

    // Forge `raw_size` to 65 MiB (> the 64 MiB floor for this physical size)
    // and re-seal the metadata with the public default key, so only the
    // limit check stands between the reader and a 65 MiB decompression.
    let offset = envelope_offset(&stego);
    let mut data = fs::read(&stego).unwrap();
    let start = offset as usize;
    let header =
        EnvelopeHeader::unpack_with_password(&data[start..start + HEADER_SIZE], None).unwrap();
    let hint_len = header.hint_len as usize;
    let meta_off = start + HEADER_SIZE + hint_len;
    let meta_end = meta_off + header.meta_len as usize;
    let hint = &data[start + HEADER_SIZE..meta_off];
    let meta_key = derive_keys(StructureProfile::default().secret(), &header.salt)
        .expect("derive default keys")
        .1;
    let aad = header.auth_aad(hint);
    let plain = decrypt_metadata(
        &data[meta_off..meta_end],
        &meta_key,
        &header.base_nonce,
        &aad,
    )
    .expect("decrypt metadata with the public default key");
    let mut meta = CarrierMetadata::decode_compact(&plain).expect("decode compact metadata");
    meta.raw_size = 65 * 1024 * 1024;
    let forged_plain = meta.encode_compact().expect("encode compact metadata");
    // The varint for both sizes is four bytes, so the seal keeps `meta_len`.
    assert_eq!(forged_plain.len(), plain.len());
    let sealed = encrypt_metadata(forged_plain.as_slice(), &meta_key, &header.base_nonce, &aad)
        .expect("re-seal forged metadata");
    assert_eq!(sealed.len(), header.meta_len as usize);
    data[meta_off..meta_end].copy_from_slice(&sealed);
    fs::write(&stego, data).unwrap();

    let out = dir.join("out.bin");
    let err = read_carrier(&stego, &ReadOptions::default().with_output(&out))
        .expect_err("a 65 MiB declared payload must not be decrypted from a tiny carrier");
    let err = err.to_string().to_lowercase();
    assert!(
        err.contains("decompression limit"),
        "unexpected error: {err}"
    );
}

#[test]
fn forged_ebml_void_envelope_size_is_rejected_without_allocating() {
    let dir = scratch("forge_mkv");
    let stego = write_carrier_with(&dir, "mkv", make_mkv(), "ebml_void");
    let ube_offset = envelope_offset(&stego);
    forge_envelope(&stego, ube_offset, 0xFFFF_FFF0);
    assert_forged_envelope_is_inert(&stego, "ebml_void");
}

#[test]
fn forged_pe_overlay_envelope_size_is_rejected_without_allocating() {
    let dir = scratch("forge_pe");
    let stego = write_carrier_with(&dir, "pe", make_pe(4096), "pe_overlay");
    let ube_offset = envelope_offset(&stego);
    forge_envelope(&stego, ube_offset, 0xFFFF_FFF0);
    assert_forged_envelope_is_inert(&stego, "pe_overlay");
}

#[test]
fn meta_len_above_the_cap_is_rejected_even_with_a_consistent_trailer() {
    // Keep the trailer honest (the envelope really is where it says) and only
    // inflate `meta_len`: the field-range cap is the layer that catches this,
    // independently of the physical containment check.
    let dir = scratch("forge_meta_cap");
    let stego = write_carrier_with(&dir, "cap", make_png(), "eof");
    let ube_offset = envelope_offset(&stego);

    let mut data = fs::read(&stego).unwrap();
    let start = ube_offset as usize;
    let mut header =
        EnvelopeHeader::unpack_with_password(&data[start..start + HEADER_SIZE], None).unwrap();
    header.meta_len = MAX_META_LEN + 1;
    let packed = header
        .pack_with_profile(None, &StructureProfile::default())
        .unwrap();
    data[start..start + HEADER_SIZE].copy_from_slice(&packed);
    fs::write(&stego, data).unwrap();

    let verified = verify_carrier(&stego, None).unwrap();
    assert!(!verified.level2_envelope.ok);
    assert!(
        verified
            .level2_envelope
            .detail
            .contains("Metadata block length"),
        "unexpected detail: {}",
        verified.level2_envelope.detail
    );
}

#[test]
fn a_forged_trailer_with_an_oversized_envelope_is_ignored() {
    // Same idea as the allocation tests but without touching the header: a
    // trailer whose declared envelope is larger than the whole file cannot be
    // tail-aligned, so locate must not build a reader over bytes that do not
    // exist. A forged *offset* alone is harmless: the real start is derived
    // from the tail so a later carrier rewrite can slide an appended envelope.
    let dir = scratch("forge_past_eof");
    let stego = write_carrier_with(&dir, "past", make_png(), "eof");
    let mut data = fs::read(&stego).unwrap();
    let n = data.len();
    let trailer = EnvelopeTrailer::unpack(&data[n - TRAILER_SIZE..], None).unwrap();
    let forged = EnvelopeTrailer::create(trailer.ube_offset, n as u64 + 1, STANDARD_TRAILER_MAGIC);
    data[n - TRAILER_SIZE..].copy_from_slice(&forged.pack());
    fs::write(&stego, data).unwrap();

    assert!(!inspect_carrier(&stego, None).unwrap().has_hidden_data);
    assert!(!verify_carrier(&stego, None).unwrap().level2_envelope.ok);
}
