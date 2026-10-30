// Regression tests for the second-round review (docs/CODE-REVIEW-R2-20261030.md).
//
// Every case here started life as a *silent* failure: a slice panic on a
// crafted ISO-BMFF box, a decoy end-of-central-directory record adopted as the
// real one, or a patch span that quietly grew the carrier instead of failing.

use crate::common::*;
use std::fs;
use std::io::Cursor;

use strhide::errors::StrHideError;

/// `ftyp` + one box whose 64-bit `largesize` is `u64::MAX`.
///
/// `pos + bsize` used to wrap below `pos`, passing the "fits in the buffer"
/// check and then panicking on the slice that follows. With `panic = "abort"`
/// in release that aborted the whole process (review R2 P0-1).
fn heif_with_oversized_top_level_box() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&24u32.to_be_bytes());
    out.extend_from_slice(b"ftypheic");
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(b"mif1heic");

    out.extend_from_slice(&1u32.to_be_bytes()); // size32 == 1 → largesize follows
    out.extend_from_slice(b"meta");
    out.extend_from_slice(&u64::MAX.to_be_bytes());
    out.extend_from_slice(&[0u8; 16]);
    out
}

/// Same trick one level down: a well-formed `meta` whose first child declares
/// a 64-bit size of `u64::MAX`.
fn heif_with_oversized_meta_subbox() -> Vec<u8> {
    let mut meta_body = Vec::new();
    meta_body.extend_from_slice(&0u32.to_be_bytes()); // version + flags
    meta_body.extend_from_slice(&1u32.to_be_bytes()); // size32 == 1
    meta_body.extend_from_slice(b"iinf");
    meta_body.extend_from_slice(&u64::MAX.to_be_bytes());
    meta_body.extend_from_slice(&[0u8; 16]);

    let meta_size = 8 + meta_body.len() as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&24u32.to_be_bytes());
    out.extend_from_slice(b"ftypheic");
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(b"mif1heic");
    out.extend_from_slice(&meta_size.to_be_bytes());
    out.extend_from_slice(b"meta");
    out.extend_from_slice(&meta_body);
    out
}

#[test]
fn heif_oversized_64bit_box_is_an_error_not_a_panic() {
    use strhide::stego::{EmbedOptions, extract_carrier};

    for carrier in [
        heif_with_oversized_top_level_box(),
        heif_with_oversized_meta_subbox(),
    ] {
        let opts = EmbedOptions::default();
        let extract = extract_carrier(&carrier, &opts.extract_options());
        assert!(
            extract.is_err(),
            "extract on a crafted oversized box must fail cleanly, got {extract:?}"
        );

        let embed = strhide::stego::embed_carrier(
            &carrier,
            &strhide::core::payload::Payload::bytes(b"x"),
            &opts,
        );
        assert!(
            embed.is_err(),
            "embed on a crafted oversized box must fail cleanly"
        );
    }
}

#[test]
fn isobmff_capability_probe_rejects_oversized_box() {
    use strhide::structure::adapters::isobmff::isobmff_can_item_hidden;

    for carrier in [
        heif_with_oversized_top_level_box(),
        heif_with_oversized_meta_subbox(),
    ] {
        // Only requirement: no panic and no "yes, item_hidden works" claim.
        assert!(
            !isobmff_can_item_hidden(&mut Cursor::new(carrier)),
            "a crafted oversized box must not be reported as injectable"
        );
    }
}

/// A ZIP whose EOCD comment carries a second, decoy EOCD record that also ends
/// at EOF but points its `cd_offset` at the local file header.
fn zip_with_decoy_eocd() -> Vec<u8> {
    make_zip_with_fake_eocd_comment()
}

#[test]
fn zip_decoy_eocd_does_not_win_over_the_real_one() {
    use strhide::structure::adapters::zip::find_eocd_offset;

    let zip = zip_with_decoy_eocd();
    let (eocd_pos, cd_offset, cd_size) = find_eocd_offset(&mut Cursor::new(&zip)).unwrap();

    // The adopted record must address the real central directory.
    assert_eq!(
        &zip[cd_offset as usize..cd_offset as usize + 4],
        b"PK\x01\x02",
        "cd_offset must point at a central-directory record, not a decoy"
    );
    // And the real EOCD comes before the decoy inside the comment.
    let real_eocd = zip
        .windows(4)
        .position(|w| w == b"PK\x05\x06")
        .expect("real EOCD present");
    assert_eq!(
        eocd_pos as usize, real_eocd,
        "the first (genuine) EOCD record must be the one adopted"
    );
    assert!(cd_offset + cd_size <= eocd_pos);
}

#[test]
fn jar_signature_guard_is_not_bypassed_by_a_decoy_eocd() {
    use strhide::structure::rejection::check_jar_signature;

    let signed = make_zip_with_entries(&[
        ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        ("META-INF/SIGNER.SF", b"Signature-Version: 1.0\n"),
        ("payload.txt", b"data"),
    ]);
    // Append a decoy EOCD inside a comment: `cd_offset` points at the local
    // header, so a naive walk finds no signature and reports "unsigned".
    let mut crafted = signed.clone();
    let fake =
        b"PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\x20\x00\x00\x00\x10\x00\x00\x00\x00\x00";
    let total_comment = fake.len() as u16;
    let eocd_pos = crafted
        .windows(4)
        .rposition(|w| w == b"PK\x05\x06")
        .expect("EOCD present");
    crafted[eocd_pos + 20..eocd_pos + 22].copy_from_slice(&total_comment.to_le_bytes());
    crafted.extend_from_slice(fake);

    for (label, bytes) in [("plain", signed), ("crafted", crafted)] {
        let found = check_jar_signature(&mut Cursor::new(&bytes), None).unwrap();
        assert!(
            found.is_some(),
            "{label}: a signed JAR must be reported as signed"
        );
    }
}

#[test]
fn commit_carrier_patches_refuses_a_span_past_eof() {
    use strhide::commit::commit_carrier_patches;

    let dir = scratch("patch_span");
    let carrier = dir.join("carrier.bin");
    let original = b"0123456789".to_vec();
    fs::write(&carrier, &original).unwrap();

    let patches = vec![(900usize..904usize, vec![0xAAu8; 4])];
    let res = commit_carrier_patches(&carrier, &carrier, &patches, false, false);
    assert!(
        matches!(res, Err(StrHideError::CorruptedData(_))),
        "an out-of-range patch span must be rejected, got {res:?}"
    );
    assert_eq!(
        fs::read(&carrier).unwrap(),
        original,
        "the carrier must be left untouched"
    );

    // In-range patches still commit.
    let patches = vec![(2usize..4usize, vec![b'X', b'Y'])];
    commit_carrier_patches(&carrier, &carrier, &patches, false, false).unwrap();
    assert_eq!(fs::read(&carrier).unwrap(), b"01XY456789".to_vec());
}
