//! Integration tests for JPEG APP15 multi-segment chain hiding.

use crate::common::*;
use rand::RngExt;
use std::fs;
use strhide::structure::adapters::jpeg::{JPEG_COM, JPEG_EOI, JPEG_SOI, find_jpeg_sos_offset};
use strhide::structure::{
    PayloadSource, ReadOptions, RestoreOptions, WriteOptions, read_carrier, remove_carrier,
    verify_carrier, write_carrier,
};

fn make_sample_jpeg_with_comment(comment_text: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    // SOI
    d.extend_from_slice(&JPEG_SOI);
    // DQT
    d.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
    d.extend_from_slice(&[16u8; 64]);
    // SOF0 (baseline 8x8)
    d.extend_from_slice(&[
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x08, 0x00, 0x08, 0x01, 0x01, 0x11, 0x00,
    ]);
    // Existing original comment
    let com_len = (2 + comment_text.len()) as u16;
    d.extend_from_slice(&JPEG_COM);
    d.extend_from_slice(&com_len.to_be_bytes());
    d.extend_from_slice(comment_text);
    // SOS
    d.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
    // Scan entropy data
    d.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    // EOI
    d.extend_from_slice(&JPEG_EOI);
    d
}

#[test]
fn test_jpeg_multisegment_chain_boundary_and_lossless_restore() {
    let dir = scratch("multi_boundary");
    let carrier = dir.join("carrier.jpg");
    let orig_comment = b"Original Photographer Copyright 2024";
    fs::write(&carrier, make_sample_jpeg_with_comment(orig_comment)).unwrap();

    // Generate ~150KB payload (spans across 3 segments)
    let payload_size = 150_000usize;
    let mut payload = vec![0u8; payload_size];
    rand::rng().fill(&mut payload);
    let payload_file = dir.join("payload.bin");
    fs::write(&payload_file, &payload).unwrap();

    let stego = dir.join("stego.jpg");
    let res = write_carrier(
        &carrier,
        PayloadSource::File(&payload_file),
        &WriteOptions {
            output_path: Some(&stego),
            password: Some("secret123"),
            strategy: "auto",
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();

    // 1. Verify strategy selected is app_segment
    assert_eq!(res.strategy.name(), "app_segment");

    // 2. Scan markers in stego file:
    // Ensure multiple APP15 segments exist before SOS, and NO trailing data after EOI
    let stego_bytes = fs::read(&stego).unwrap();
    assert!(
        stego_bytes.ends_with(&JPEG_EOI),
        "Stego must end exactly at EOI with 0 trailing bytes"
    );

    let mut app15_count = 0;
    let mut found_orig_com = false;
    let mut pos = 2;
    while pos < stego_bytes.len() {
        if stego_bytes[pos] != 0xFF {
            pos += 1;
            continue;
        }
        let code = stego_bytes[pos + 1];
        if code == 0xDA {
            // SOS reached
            break;
        }
        if code == 0xD8 || code == 0xD9 || code == 0x01 || (0xD0..=0xD7).contains(&code) {
            pos += 2;
            continue;
        }
        let seg_len = u16::from_be_bytes([stego_bytes[pos + 2], stego_bytes[pos + 3]]) as usize;
        if code == 0xEF {
            app15_count += 1;
        } else if code == 0xFE {
            let seg_data = &stego_bytes[pos + 4..pos + 2 + seg_len];
            if seg_data == orig_comment {
                found_orig_com = true;
            }
        }
        pos += 2 + seg_len;
    }

    assert!(
        app15_count >= 2,
        "Expected multiple APP15 segments for 150KB, found {app15_count}"
    );
    assert!(
        found_orig_com,
        "Original comment must remain intact before SOS"
    );

    // 3. Verify carrier integrity (Level 1, Level 2, Level 3)
    let v = verify_carrier(&stego, Some("secret123")).unwrap();
    assert!(
        v.level1_host.ok,
        "L1 host check failed: {}",
        v.level1_host.detail
    );
    assert!(
        v.level2_envelope.ok,
        "L2 envelope check failed: {}",
        v.level2_envelope.detail
    );
    assert!(
        v.level3_crypto.ok,
        "L3 crypto check failed: {}",
        v.level3_crypto.detail
    );

    // 4. Read back payload
    let read_res = read_carrier(
        &stego,
        &ReadOptions {
            output_path: None,
            password: Some("secret123"),
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(read_res.data, payload);

    // 5. Lossless remove and bitwise SHA-256 comparison
    let restored = dir.join("restored.jpg");
    let rem_res = remove_carrier(
        &stego,
        &RestoreOptions {
            output_path: Some(&restored),
            password: Some("secret123"),
            backup: false,
            overwrite: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(rem_res.verified_identical);
    assert_eq!(fs::read(&restored).unwrap(), fs::read(&carrier).unwrap());
}

#[test]
fn test_jpeg_com_segments_are_not_envelope_channels() {
    let dir = scratch("legacy_com");
    let carrier = dir.join("carrier.jpg");
    fs::write(&carrier, make_sample_jpeg_with_comment(b"none")).unwrap();

    // Write a small payload directly into a COM segment manually to verify backward compat
    let sos_off = find_jpeg_sos_offset(&mut fs::File::open(&carrier).unwrap()).unwrap();
    let carrier_bytes = fs::read(&carrier).unwrap();

    // Prepare a mock UBE
    let ube_data = b"MOCK_UBE_DATA_REPRESENTING_OLD_COM_ENVELOPE";
    // Construct single COM segment
    let mut stego_bytes = Vec::new();
    stego_bytes.extend_from_slice(&carrier_bytes[..sos_off as usize]);
    let seg_len = (2 + ube_data.len()) as u16;
    stego_bytes.extend_from_slice(&JPEG_COM);
    stego_bytes.extend_from_slice(&seg_len.to_be_bytes());
    stego_bytes.extend_from_slice(ube_data);
    stego_bytes.extend_from_slice(&carrier_bytes[sos_off as usize..]);

    let stego = dir.join("legacy_stego.jpg");
    fs::write(&stego, &stego_bytes).unwrap();

    // COM segments are ordinary JPEG comments: the pre-v2 "COM chain" channel
    // is gone, so `locate` only looks at APP15 (and the EOF trailer) and must
    // report "no envelope" for a payload parked in a comment.
    let mut f = fs::File::open(&stego).unwrap();
    let adapter = strhide::structure::adapters::jpeg::JpegAdapter;
    use strhide::structure::adapters::HostAdapter;
    let loc = adapter.locate(&mut f, None).unwrap();
    assert!(loc.is_none());
}
