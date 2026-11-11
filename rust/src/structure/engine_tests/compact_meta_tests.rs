use super::*;

fn meta(name: &str, size: u64, ts: u64) -> CarrierMetadata {
    CarrierMetadata {
        filename: name.to_string(),
        raw_size: size,
        raw_sha256: "ab".repeat(32),
        created_at: ts,
    }
}

fn assert_same(actual: &CarrierMetadata, expected: &CarrierMetadata) {
    assert_eq!(actual.filename, expected.filename);
    assert_eq!(actual.raw_size, expected.raw_size);
    assert_eq!(actual.raw_sha256, expected.raw_sha256);
    assert_eq!(actual.created_at, expected.created_at);
}

#[test]
fn compact_roundtrip_covers_width_and_text_edges() {
    let cases = [
        ("a", 0u64, 0u64),
        ("x.txt", 1, 1_700_000_000),
        ("目录/长文件名-测试.bin", u32::MAX as u64, u64::MAX / 2),
        ("n", u64::MAX, 127),
    ];
    for (name, size, ts) in cases {
        let original = meta(name, size, ts);
        let encoded = original.encode_compact().expect("encodable");
        let decoded = CarrierMetadata::decode_compact(&encoded).expect("decodable");
        assert_same(&decoded, &original);
    }
    // 300-byte name still fits the u16 length field
    let long = meta(&"n".repeat(300), 7, 7);
    let encoded = long.encode_compact().expect("encodable");
    assert_same(&CarrierMetadata::decode_compact(&encoded).unwrap(), &long);
}

#[test]
fn compact_block_is_much_smaller_than_json() {
    let m = meta("s.txt", 1, 1_700_000_000);
    let compact = m.encode_compact().unwrap();
    let json = serde_json::to_vec(&m).unwrap();
    assert!(
        compact.len() + 80 < json.len(),
        "compact {} json {}",
        compact.len(),
        json.len()
    );
    // 1 version + 2 name_len + 5 name + 1 size + 32 digest + 5 timestamp
    assert_eq!(compact.len(), 46);
}

#[test]
fn varint_rejects_values_that_overflow_u64() {
    // 9 continuation bytes followed by 0x02: bits past 63 must trigger an error.
    let mut overflowing = vec![0x80u8; 9];
    overflowing.push(0x02);
    let mut pos = 0;
    assert!(matches!(
        take_varint(&overflowing, &mut pos),
        Err(StrHideError::CorruptedData(_))
    ));

    // The canonical 10-byte encoding of u64::MAX still parses.
    let mut max = vec![0xffu8; 9];
    max.push(0x01);
    let mut pos = 0;
    assert_eq!(take_varint(&max, &mut pos).unwrap(), u64::MAX);

    // A 10th byte with the continuation bit set is "too long": it must not
    // be silently accepted either.
    let too_long = vec![0xffu8; 10];
    let mut pos = 0;
    assert!(take_varint(&too_long, &mut pos).is_err());
}

#[test]
fn compact_rejects_corrupt_input() {
    assert!(CarrierMetadata::decode_compact(&[]).is_err());
    assert!(CarrierMetadata::decode_compact(&[0x01]).is_err());
    // unsupported version
    assert!(CarrierMetadata::decode_compact(&[0x02, 0x00, 0x00]).is_err());
    // truncated filename
    assert!(CarrierMetadata::decode_compact(&[0x01, 0x05, 0x00, b'a']).is_err());
    // truncated digest
    let mut v = vec![0x01, 0x01, 0x00, b'a'];
    put_varint(&mut v, 1);
    v.extend_from_slice(&[0u8; 10]);
    assert!(CarrierMetadata::decode_compact(&v).is_err());
    // invalid UTF-8 filename
    assert!(CarrierMetadata::decode_compact(&[0x01, 0x01, 0x00, 0xff]).is_err());
}

#[test]
fn pre_v2_json_metadata_is_rejected() {
    let m = meta("legacy.bin", 42, 1_600_000_000);
    let json = serde_json::to_vec(&m).unwrap();
    // A pre-v2 carrier stores JSON with FLAG_COMPACT_META clear. That
    // combination is now a hard error rather than a second decode path.
    assert!(decode_metadata(&json, false).is_err());
    // The compact path must not accept JSON either.
    assert!(decode_metadata(&json, true).is_err());
    // And the compact layout still round-trips.
    let compact = m.encode_compact().unwrap();
    assert_same(&decode_metadata(&compact, true).unwrap(), &m);
}

#[test]
fn unencodable_metadata_is_a_writer_error() {
    let long_name = meta(&"n".repeat(COMPACT_META_MAX_NAME + 1), 1, 1);
    assert!(long_name.encode_compact().is_none());
    assert!(encode_metadata(&long_name).is_err());

    let mut bad_digest = meta("x", 1, 1);
    bad_digest.raw_sha256 = "zz".repeat(32);
    assert!(bad_digest.encode_compact().is_none());
    assert!(encode_metadata(&bad_digest).is_err());
}

#[test]
fn test_warning_render_bilingual() {
    use crate::core::i18n::{Lang, RenderCtx};

    let w1 = Warning::SizeInflation {
        ube_size: 1000,
        host_size: 1500,
        ratio_pct: 66.7,
    };
    assert_eq!(w1.render(RenderCtx::new(Lang::En)), w1.message());
    assert!(w1.render(RenderCtx::new(Lang::Zh)).contains("隐藏数据信封"));

    let w2 = Warning::SuspiciousStructures {
        hints: vec!["prIv chunk".into()],
    };
    assert_eq!(w2.render(RenderCtx::new(Lang::En)), w2.message());
    assert!(
        w2.render(RenderCtx::new(Lang::Zh))
            .contains("载体呈现与隐藏信封一致的结构")
    );
}

#[test]
fn test_read_summary_and_metadata_inspection() {
    let read = ReadResult {
        carrier: PathBuf::from("test.png"),
        data: b"hello world".to_vec(),
        is_file: false,
        is_encrypted: false,
        filename: String::new(),
        raw_size: 11,
        written_file: None,
    };
    let summary = read.summary();
    assert_eq!(summary.raw_size, 11);
    assert_eq!(summary.text_preview, Some("hello world".into()));

    let meta = CarrierMetadata {
        filename: "secret.txt".into(),
        raw_size: 100,
        raw_sha256: "0".repeat(64),
        created_at: 12345678,
    };
    let inspection = MetadataInspection::Decrypted(meta.clone());
    let json = serde_json::to_string(&inspection).expect("serialize");
    assert!(json.contains("secret.txt"));

    let fail = MetadataInspection::DecryptFailed {
        error: "Invalid password".into(),
    };
    let json_fail = serde_json::to_string(&fail).expect("serialize");
    assert!(json_fail.contains("Invalid password"));
}
