use super::*;

// Frozen golden test vectors (see docs/api/WIRE_SPEC_CONTENT.md).
const GOLDEN: &str = concat!(
    "1234567840010200010400010000012c",
    "202122232425262728292a2b65db3bcb",
);
const MAGIC: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

fn hex<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), N * 2, "hex length");
    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    out
}

#[test]
fn golden_superblock_round_trips_byte_for_byte() {
    let raw = hex::<32>(GOLDEN);
    let header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
    assert_eq!(
        header.version,
        crate::stego::header::CONTENT_ENVELOPE_VERSION
    );
    assert_eq!(header.stc_u, 2);
    assert_eq!(header.window_slices, 1);
    assert_eq!(header.ext_len, 4);
    assert_eq!(header.suite_id, 1);
    assert_eq!(header.body_len, 300);
    assert!(header.ext_present());
    assert!(!header.ext_critical());
    assert_eq!(header.encode(), raw);
}

#[test]
fn magic_and_field_ranges_are_enforced() {
    let raw = hex::<32>(GOLDEN);
    let err = HevcSuperblockV4::decode(&raw, [0x12, 0x34, 0x56, 0x79]).expect_err("wrong magic");
    assert!(matches!(err, StrHideError::CorruptedData(_)));

    let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
    header.version = 0x30;
    let err = HevcSuperblockV4::decode(&header.encode(), MAGIC).expect_err("v3 must fail");
    assert!(matches!(err, StrHideError::UnsupportedVersion(_)));

    let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
    header.flags = 0x04;
    assert!(HevcSuperblockV4::decode(&header.encode(), MAGIC).is_err());

    let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
    header.ext_len = 0;
    assert!(HevcSuperblockV4::decode(&header.encode(), MAGIC).is_err());

    let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
    header.ext_len = 65;
    assert!(HevcSuperblockV4::decode(&header.encode(), MAGIC).is_err());

    let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
    header.stc_u = 0;
    assert!(HevcSuperblockV4::decode(&header.encode(), MAGIC).is_err());

    let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
    header.stc_u = 65;
    assert!(HevcSuperblockV4::decode(&header.encode(), MAGIC).is_err());

    let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
    header.window_slices = 0;
    assert!(HevcSuperblockV4::decode(&header.encode(), MAGIC).is_err());

    let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
    header.suite_id = 3;
    let err = HevcSuperblockV4::decode(&header.encode(), MAGIC).expect_err("unknown suite");
    assert!(matches!(err, StrHideError::UnsupportedVersion(_)));

    let mut raw = hex::<32>(GOLDEN);
    raw[16] ^= 0x01;
    let err = HevcSuperblockV4::decode(&raw, MAGIC).expect_err("flip must fail CRC");
    assert!(matches!(err, StrHideError::CorruptedData(_)));
}

#[test]
fn extension_slots_match_the_plan() {
    assert_eq!(hevc_extension_slots(0), 0);
    assert_eq!(hevc_extension_slots(1), 28);
    assert_eq!(hevc_extension_slots(64), 1036);
    assert_eq!(524 + hevc_extension_slots(64), 1560);
    assert!(524 + hevc_extension_slots(HEVC_MAX_EXT_BYTES) <= HEVC_HEADER_SLOTS_MAX);
}

/// Patch validation is the release-build guard for a mismatched internal
/// patch list: it rejects the three shapes that used to panic inside
/// `apply_hevc_patches` (reversed span, end past the carrier, replacement
/// length differing from the span). Runs in every profile, unlike the
/// debug assertion in the apply loop.
#[test]
fn patch_validation_rejects_malformed_spans() {
    let carrier_len = 16;
    assert!(validate_hevc_patches(carrier_len, &[(2..6, vec![9; 4])]).is_ok());
    assert!(validate_hevc_patches(carrier_len, &[]).is_ok());

    for (span, re_nal) in [
        (0..8, vec![9; 4]),   // replacement too short
        (0..4, vec![9; 5]),   // replacement too long
        (8..20, vec![9; 12]), // end beyond the carrier
        // Built as a struct literal: `6..2` is rejected by clippy's
        // `reversed_empty_ranges` before the test can observe it.
        (std::ops::Range { start: 6, end: 2 }, vec![9; 4]),
    ] {
        let err = validate_hevc_patches(carrier_len, &[(span, re_nal)])
            .expect_err("malformed patch must be rejected");
        assert!(
            matches!(err, StrHideError::General(ref msg) if msg.contains("does not fit")),
            "unexpected error: {err}"
        );
    }
}

/// The debug assertion fires before the copy, so a direct caller gets a
/// message naming the span instead of `range end index out of range`.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "does not fit")]
fn patch_apply_asserts_before_copying_in_debug() {
    let mut carrier = vec![0u8; 8];
    apply_hevc_patches(&mut carrier, &[(0..4, vec![1; 3])]);
}
