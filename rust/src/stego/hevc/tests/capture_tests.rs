use super::*;
use crate::stego::format::DEFAULT_HEVC_FORMAT;

fn record(bands: Vec<std::ops::Range<usize>>, band_bits: [Vec<u8>; 2]) -> CarrierRecord {
    let total = bands.iter().map(|r| r.len()).sum();
    CarrierRecord {
        slice_contexts: Vec::new(),
        all_slots: Vec::new(),
        band_bits,
        bands,
        pictures: 1,
        band_pictures: [1, 0],
        digest_inputs: DigestInputs::ParameterSets {
            parameter_sets: Vec::new(),
        },
        recorded_slices: 1,
        raw_bits: Vec::new(),
        slice_slot_ranges: vec![(total, 0)],
        capacity_band_counts: None,
    }
}

fn pack(bits: &[u8]) -> Vec<u8> {
    let mut packer = BitPacker::default();
    for &bit in bits {
        packer.push(bit);
    }
    packer.bytes
}

/// `Capture::Bits` must answer exactly what `all_slots[p].original_bit`
/// answered, including across byte boundaries and across the drift-ladder
/// partition.
#[test]
fn slot_bit_matches_the_pool_order() {
    // band 0: 10 slots (not a byte multiple), band 1: 3 slots.
    let band0 = [1u8, 0, 1, 1, 0, 0, 0, 1, 1, 0];
    let band1 = [0u8, 1, 1];
    let rec = record(vec![0..10, 10..13], [pack(&band0), pack(&band1)]);
    assert_eq!(rec.total_slots(), 13);
    let expected: Vec<u8> = band0.iter().chain(band1.iter()).copied().collect();
    for (index, &want) in expected.iter().enumerate() {
        assert_eq!(rec.slot_bit(index), want, "pool position {index}");
    }
}

/// An empty band 0 shifts band 1 to pool position 0; the mapping must not
/// fall back to band 0's (empty) buffer.
#[test]
fn slot_bit_handles_an_empty_leading_band() {
    let rec = record(vec![0..0, 0..4], [Vec::new(), pack(&[1, 0, 0, 1])]);
    assert_eq!(rec.total_slots(), 4);
    assert_eq!(
        (0..4).map(|i| rec.slot_bit(i)).collect::<Vec<_>>(),
        vec![1, 0, 0, 1]
    );
}

/// LSB-first packing, including the last partial byte.
#[test]
fn bit_packer_packs_lsb_first() {
    assert_eq!(pack(&[1]), vec![0b0000_0001]);
    assert_eq!(pack(&[0, 0, 0, 0, 0, 0, 0, 1]), vec![0b1000_0000]);
    assert_eq!(pack(&[1; 9]), vec![0xFF, 0b0000_0001]);
    assert_eq!(pack(&[]), Vec::<u8>::new());
}

#[test]
fn superblock_v4_encode_decode_roundtrip() {
    let sb = HevcSuperblockV4 {
        magic: [0x53, 0x54, 0x52, 0x48],
        version: CONTENT_ENVELOPE_VERSION,
        flags: FLAG_EXT_PRESENT,
        stc_u: 2,
        window_slices: 12,
        ext_len: 8,
        suite_id: 1,
        body_len: 1040,
        nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    };
    let encoded = sb.encode();
    assert_eq!(encoded.len(), HEVC_SUPERBLOCK_BYTES);
    let decoded = HevcSuperblockV4::decode(&encoded, sb.magic).expect("decode superblock");
    assert_eq!(decoded, sb);
}

#[test]
fn superblock_v4_rejects_truncated_or_tampered_headers() {
    let sb = HevcSuperblockV4 {
        magic: [0x53, 0x54, 0x52, 0x48],
        version: CONTENT_ENVELOPE_VERSION,
        flags: 0,
        stc_u: 2,
        window_slices: 1,
        ext_len: 0,
        suite_id: 1,
        body_len: 64,
        nonce: [0u8; 12],
    };
    let encoded = sb.encode();
    // Wrong magic is "someone else's carrier", never a version error.
    assert!(HevcSuperblockV4::decode(&encoded, [0, 0, 0, 0]).is_err());
    // CRC mismatch is rejected before any field drives an allocation.
    let mut flipped = encoded;
    flipped[0] ^= 0x80;
    assert!(HevcSuperblockV4::decode(&flipped, sb.magic).is_err());
    // body_len bounds: 0, below BODY_OVERHEAD, and above HEADER_LEN_MAX.
    let mut zero = encoded;
    zero[12..16].copy_from_slice(&0u32.to_be_bytes());
    let zero_crc = crc32_span(&zero);
    zero[28..32].copy_from_slice(&zero_crc.to_be_bytes());
    assert!(HevcSuperblockV4::decode(&zero, sb.magic).is_err());
    let mut below = encoded;
    below[12..16].copy_from_slice(&(BODY_OVERHEAD as u32 - 1).to_be_bytes());
    let below_crc = crc32_span(&below);
    below[28..32].copy_from_slice(&below_crc.to_be_bytes());
    assert!(HevcSuperblockV4::decode(&below, sb.magic).is_err());
    // A forged huge body_len inside the byte range must be rejected by the
    // slot budget in extract; decode itself cannot know the carrier size.
    let mut huge = encoded;
    huge[12..16].copy_from_slice(&0x00FF_FFFFu32.to_be_bytes());
    let huge_crc = crc32_span(&huge);
    huge[28..32].copy_from_slice(&huge_crc.to_be_bytes());
    assert!(HevcSuperblockV4::decode(&huge, sb.magic).is_ok());
    // Above HEADER_LEN_MAX the length field itself is invalid.
    let mut over = encoded;
    over[12..16].copy_from_slice(&0x0400_0000u32.to_be_bytes());
    let over_crc = crc32_span(&over);
    over[28..32].copy_from_slice(&over_crc.to_be_bytes());
    assert!(HevcSuperblockV4::decode(&over, sb.magic).is_err());
    // Unknown suite is "no data", not an oracle.
    let mut suite = encoded;
    suite[10..12].copy_from_slice(&999u16.to_be_bytes());
    let suite_crc = crc32_span(&suite);
    suite[28..32].copy_from_slice(&suite_crc.to_be_bytes());
    assert!(HevcSuperblockV4::decode(&suite, sb.magic).is_err());
    // Truncation: `decode` takes a fixed 32-byte array, so a short buffer
    // cannot reach it; the extractor's `sb_raw.len()` guard is the
    // equivalent check and is covered by the caller contract.
    assert!(encoded.len() == HEVC_SUPERBLOCK_BYTES);
}

fn crc32_span(bytes: &[u8; HEVC_SUPERBLOCK_BYTES]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&bytes[..HEVC_V4_CRC_SPAN]);
    hasher.finalize()
}

/// Probe and embed must agree byte for byte: the payload the probe
/// advertises is exactly the largest body the writer can place, including
/// the extension area's slot cost.
#[test]
fn capacity_formula_is_the_written_body_budget() {
    let fmt = &DEFAULT_HEVC_FORMAT;
    for total_slots in [2048usize, 4096, 10000] {
        for ext_len in [0usize, 8, 16] {
            let cap = hevc_max_raw_payload(total_slots, ext_len, fmt).expect("capacity formula");
            let fits = cap + BODY_OVERHEAD;
            let slots = StcTrellis::slots_for_params(fits * 8, fmt.stc_h, fmt.stc_u);
            assert!(hevc_header_slots(ext_len) + slots <= total_slots);
            if cap > 0 {
                let over = cap + 1 + BODY_OVERHEAD;
                let over_slots = StcTrellis::slots_for_params(over * 8, fmt.stc_h, fmt.stc_u);
                assert!(hevc_header_slots(ext_len) + over_slots > total_slots);
            }
        }
    }
    // An extension area strictly reduces the payload budget.
    let plain = hevc_max_raw_payload(4096, 0, fmt).expect("plain");
    let ext = hevc_max_raw_payload(4096, 8, fmt).expect("ext");
    assert!(ext < plain);
}

/// The extension area is part of the AAD; a carrier whose extension bytes
/// changed must fail authentication.
#[test]
fn extension_area_is_bound_into_the_aad() {
    let header = [0x5Au8; HEVC_SUPERBLOCK_BYTES];
    let without = build_v4_aad_with(
        crate::stego::format::OFFICIAL_AAD_PREFIX,
        HEVC_FORMAT_ID,
        &header,
        &[],
    );
    let with = build_v4_aad_with(
        crate::stego::format::OFFICIAL_AAD_PREFIX,
        HEVC_FORMAT_ID,
        &header,
        &[0x01, 0x02, 0xAA, 0xBB],
    );
    assert_ne!(without, with);
    let changed = build_v4_aad_with(
        crate::stego::format::OFFICIAL_AAD_PREFIX,
        HEVC_FORMAT_ID,
        &header,
        &[0x01, 0x02, 0xAA, 0xBC],
    );
    assert_ne!(with, changed);
}

#[test]
fn unknown_tlv_criticality_is_classified() {
    assert!(!tags_have_critical(&[0x01, 0x02]));
    assert!(tags_have_critical(&[0x81]));
    assert!(tags_have_critical(&[0x01, 0x83]));
}

/// A forged header field with a *recomputed* CRC passes `decode` (the CRC
/// only protects against accidental damage), so authentication has to
/// reject it: the AAD is built over the exact 32 header bytes.
#[test]
fn header_tamper_with_recomputed_crc_is_rejected_by_aead() {
    let sb = HevcSuperblockV4 {
        magic: [0x53, 0x54, 0x52, 0x48],
        version: CONTENT_ENVELOPE_VERSION,
        flags: 0,
        stc_u: 2,
        window_slices: 1,
        ext_len: 0,
        suite_id: 1,
        body_len: 32,
        nonce: [9; 12],
    };
    let key = [0x11u8; 32];
    let original = sb.encode();
    let plaintext = build_plaintext(&Payload::bytes(b"hevc aead header")).expect("plaintext");
    let ciphertext = encrypt_v4_with_aad(
        CipherSuiteId::Aes256Gcm,
        &key,
        &sb.nonce,
        &build_v4_aad_with(
            crate::stego::format::OFFICIAL_AAD_PREFIX,
            HEVC_FORMAT_ID,
            &original,
            &[],
        ),
        &plaintext,
    )
    .expect("encrypt");

    let ok = unpack_v4_envelope_parts(
        CipherSuiteId::Aes256Gcm,
        &key,
        &sb.nonce,
        &build_v4_aad_with(
            crate::stego::format::OFFICIAL_AAD_PREFIX,
            HEVC_FORMAT_ID,
            &original,
            &[],
        ),
        &ciphertext,
        &ExtractParams::default(),
    )
    .expect("authentic header decrypts");
    assert_eq!(ok.as_bytes(), b"hevc aead header");

    let mut forged = sb;
    forged.window_slices = 999;
    let forged_bytes = forged.encode();
    // The CRC is recomputed, so the structural parser accepts it.
    assert!(HevcSuperblockV4::decode(&forged_bytes, sb.magic).is_ok());
    let res = unpack_v4_envelope_parts(
        CipherSuiteId::Aes256Gcm,
        &key,
        &sb.nonce,
        &build_v4_aad_with(
            crate::stego::format::OFFICIAL_AAD_PREFIX,
            HEVC_FORMAT_ID,
            &forged_bytes,
            &[],
        ),
        &ciphertext,
        &ExtractParams::default(),
    );
    assert!(matches!(res, Err(StrHideError::NoHiddenData(_))));
}

#[test]
fn superblock_positions_are_distinct_and_prefix_stable() {
    let seed = [7u8; 32];
    let base = superblock_positions(2048, &seed, 0);
    assert_eq!(base.len(), HEVC_SUPERBLOCK_MIN_SLOTS);
    let set: HashSet<usize> = base.iter().copied().collect();
    assert_eq!(set.len(), HEVC_SUPERBLOCK_MIN_SLOTS);
    for &p in &base {
        assert!(p < 2048);
    }

    let with_ext = superblock_positions(2048, &seed, 8);
    assert_eq!(
        with_ext.len(),
        HEVC_SUPERBLOCK_MIN_SLOTS + hevc_extension_slots(8)
    );
    assert_eq!(with_ext[..base.len()], base[..]);

    // Different credentials must not reproduce the header permutation.
    let other = superblock_positions(2048, &[9u8; 32], 0);
    assert_ne!(other, base);
}

#[test]
fn bitpacker_extend_and_truncate_correctness() {
    for len1 in 0..35 {
        for len2 in 0..35 {
            let bits1: Vec<u8> = (0..len1).map(|i| ((i * 7 + 3) % 2) as u8).collect();
            let bits2: Vec<u8> = (0..len2).map(|i| ((i * 11 + 5) % 2) as u8).collect();

            let mut p1 = BitPacker::default();
            for &b in &bits1 {
                p1.push(b);
            }

            let mut p2 = BitPacker::default();
            for &b in &bits2 {
                p2.push(b);
            }

            p1.extend(&p2);

            assert_eq!(p1.len, len1 + len2);
            let combined: Vec<u8> = bits1.iter().chain(bits2.iter()).copied().collect();
            for (i, &expected) in combined.iter().enumerate() {
                assert_eq!(
                    bit_at(&p1.bytes, i),
                    expected,
                    "Mismatch at index {i} for len1={len1}, len2={len2}"
                );
            }

            // Test truncate
            for trunc_len in [0, len1 / 2, len1, len1 + len2 / 2, len1 + len2] {
                let mut p_trunc = BitPacker::default();
                for &b in &combined {
                    p_trunc.push(b);
                }
                p_trunc.truncate(trunc_len);
                assert_eq!(p_trunc.len, trunc_len);
                for (i, &expected) in combined.iter().enumerate().take(trunc_len) {
                    assert_eq!(
                        bit_at(&p_trunc.bytes, i),
                        expected,
                        "Truncate mismatch at {i} for trunc_len={trunc_len}"
                    );
                }
            }
        }
    }
}
