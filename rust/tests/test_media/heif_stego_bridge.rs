// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

use strhide::core::payload::Payload;
use strhide::errors::StrHideError;
use strhide::stego::{EmbedOptions, embed_carrier, extract_carrier};

#[test]
fn test_heif_bridge_unsupported_carrier_fails_gracefully() {
    // Synthetic minimal HEIF container without any bridgeable item (ftyp + free)
    let mut stub = Vec::new();
    stub.extend_from_slice(&24u32.to_be_bytes());
    stub.extend_from_slice(b"ftypheic");
    stub.extend_from_slice(&0u32.to_be_bytes());
    stub.extend_from_slice(b"mif1heic");
    stub.extend_from_slice(&8u32.to_be_bytes());
    stub.extend_from_slice(b"free");

    let payload = b"test payload";
    let opts = EmbedOptions::default();
    let res = embed_carrier(&stub, &Payload::bytes(payload), &opts);
    assert!(
        matches!(res, Err(StrHideError::UnsupportedFormat(_))),
        "HEIF with no bridgeable thumbnail must return UnsupportedFormat, got {:?}",
        res
    );

    let ext_res = extract_carrier(&stub, &opts.extract_options());
    assert!(
        matches!(ext_res, Err(StrHideError::NoHiddenData(_))),
        "Extracting from HEIF with no bridgeable thumbnail must return NoHiddenData, got {:?}",
        ext_res
    );
}

const JPEG: &[u8] = include_bytes!("../assets/minimal.jpg");

fn bmff_box(fourcc: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&((8 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(fourcc);
    out.extend_from_slice(body);
    out
}

fn push_u16(out: &mut Vec<u8>, le: bool, v: u16) {
    if le {
        out.extend_from_slice(&v.to_le_bytes());
    } else {
        out.extend_from_slice(&v.to_be_bytes());
    }
}

fn push_u32(out: &mut Vec<u8>, le: bool, v: u32) {
    if le {
        out.extend_from_slice(&v.to_le_bytes());
    } else {
        out.extend_from_slice(&v.to_be_bytes());
    }
}

/// Write one IFD1 entry whose value width follows `typ` (3 = SHORT, 4 = LONG).
fn push_ifd1_entry(out: &mut Vec<u8>, le: bool, tag: u16, typ: u16, value: u32) {
    push_u16(out, le, tag);
    push_u16(out, le, typ);
    push_u32(out, le, 1);
    if typ == 3 {
        push_u16(out, le, value as u16);
        push_u16(out, le, 0);
    } else {
        push_u32(out, le, value);
    }
}

/// Build an Exif/TIFF block with IFD0 → IFD1 → (thumbnail), covering the four
/// encodings that used to disagree: little/big endian, SHORT/LONG tag type,
/// and IFD1 placed before or after the embedded JPEG.
fn build_exif_tiff(le: bool, long_type: bool, ifd1_after: bool) -> Vec<u8> {
    const IFD0_SIZE: usize = 2 + 12 + 4; // one entry + next-IFD pointer
    const IFD1_SIZE: usize = 2 + 2 * 12 + 4; // two entries + next pointer

    let jpeg_rel = if ifd1_after {
        8 + IFD0_SIZE
    } else {
        8 + IFD0_SIZE + IFD1_SIZE
    };
    let ifd1_off = if ifd1_after {
        jpeg_rel + JPEG.len()
    } else {
        8 + IFD0_SIZE
    };
    let typ: u16 = if long_type { 4 } else { 3 };

    let mut tiff = Vec::new();
    tiff.extend_from_slice(if le { b"II" } else { b"MM" });
    push_u16(&mut tiff, le, 42);
    push_u32(&mut tiff, le, 8);

    // IFD0: a single Orientation entry plus the pointer to IFD1.
    push_u16(&mut tiff, le, 1);
    push_u16(&mut tiff, le, 0x0112);
    push_u16(&mut tiff, le, 3);
    push_u32(&mut tiff, le, 1);
    push_u16(&mut tiff, le, 1);
    push_u16(&mut tiff, le, 0);
    push_u32(&mut tiff, le, ifd1_off as u32);

    let write_ifd1 = |out: &mut Vec<u8>| {
        push_u16(out, le, 2);
        push_ifd1_entry(out, le, 0x0201, typ, jpeg_rel as u32);
        push_ifd1_entry(out, le, 0x0202, typ, JPEG.len() as u32);
        push_u32(out, le, 0);
    };

    if !ifd1_after {
        write_ifd1(&mut tiff);
    }
    assert_eq!(
        tiff.len(),
        jpeg_rel,
        "thumbnail must start at its tag offset"
    );
    tiff.extend_from_slice(JPEG);
    if ifd1_after {
        write_ifd1(&mut tiff);
    }
    tiff
}

/// Wrap an Exif payload in the smallest HEIF that `find_bridge_target` reads:
/// `ftyp` + `meta(iinf + iloc)` + `mdat`.
fn build_exif_heif(exif_payload: &[u8]) -> Vec<u8> {
    let mut infe_body = vec![2, 0, 0, 0];
    infe_body.extend_from_slice(&1u16.to_be_bytes()); // item_ID
    infe_body.extend_from_slice(&0u16.to_be_bytes()); // protection
    infe_body.extend_from_slice(b"Exif");
    infe_body.push(0); // empty name
    let infe = bmff_box(b"infe", &infe_body);

    let mut iinf_body = vec![0, 0, 0, 0];
    iinf_body.extend_from_slice(&1u16.to_be_bytes());
    iinf_body.extend_from_slice(&infe);
    let iinf = bmff_box(b"iinf", &iinf_body);

    // iloc v1, 4-byte offset/length/base fields, a single file extent.
    let mut iloc_body = vec![1, 0, 0, 0];
    iloc_body.push(0x44);
    iloc_body.push(0x40);
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // item count
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // item_ID
    iloc_body.extend_from_slice(&0u16.to_be_bytes()); // construction_method
    iloc_body.extend_from_slice(&0u16.to_be_bytes()); // data_reference_index
    const BASE_OFFSET_AT: usize = 4 + 1 + 1 + 2 + 2 + 2 + 2;
    iloc_body.extend_from_slice(&0u32.to_be_bytes()); // base_offset (patched)
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // extent_count
    iloc_body.extend_from_slice(&0u32.to_be_bytes()); // extent_offset
    iloc_body.extend_from_slice(&(exif_payload.len() as u32).to_be_bytes());

    let ftyp = {
        let mut body = Vec::new();
        body.extend_from_slice(b"heic");
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(b"mif1heic");
        bmff_box(b"ftyp", &body)
    };
    let meta_len = 12 + iinf.len() + 8 + iloc_body.len();
    let mdat_data_pos = (ftyp.len() + meta_len + 8) as u32;
    iloc_body[BASE_OFFSET_AT..BASE_OFFSET_AT + 4].copy_from_slice(&mdat_data_pos.to_be_bytes());
    let iloc = bmff_box(b"iloc", &iloc_body);

    let mut meta_body = vec![0, 0, 0, 0];
    meta_body.extend_from_slice(&iinf);
    meta_body.extend_from_slice(&iloc);
    let meta = bmff_box(b"meta", &meta_body);

    let mut file = ftyp;
    file.extend_from_slice(&meta);
    file.extend_from_slice(&bmff_box(b"mdat", exif_payload));
    file
}

/// Verifies every legal Exif thumbnail encoding survives embedding and is readable,
/// across little/big-endian TIFF and SHORT/LONG tag lengths.
#[test]
fn heif_exif_thumbnail_roundtrips_for_every_tiff_encoding() {
    let payload = b"exif bridge payload";
    for &le in &[true, false] {
        for &long_type in &[true, false] {
            for &ifd1_after in &[true, false] {
                let tiff = build_exif_tiff(le, long_type, ifd1_after);
                let mut exif = vec![0u8, 0, 0, 0]; // HEIF Exif item TIFF offset
                exif.extend_from_slice(&tiff);
                let carrier = build_exif_heif(&exif);

                let opts = EmbedOptions::default();
                let stego = embed_carrier(&carrier, &Payload::bytes(payload), &opts)
                    .unwrap_or_else(|e| {
                        panic!(
                            "embed failed (le={le}, long={long_type}, ifd1_after={ifd1_after}): {e}"
                        )
                    });
                let got = extract_carrier(&stego, &opts.extract_options()).unwrap_or_else(|e| {
                    panic!(
                        "extract failed (le={le}, long={long_type}, ifd1_after={ifd1_after}): {e}"
                    )
                });
                assert_eq!(
                    got.as_slice(),
                    payload,
                    "payload mismatch (le={le}, long={long_type}, ifd1_after={ifd1_after})"
                );
            }
        }
    }
}
