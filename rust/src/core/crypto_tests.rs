use super::*;

/// `zero_bytes` backs the `Drop` impls that wipe the derived keys; if it
/// silently skipped bytes, those impls would be decorative.
#[test]
fn zero_bytes_clears_every_byte_without_touching_neighbours() {
    let mut buf = [0u8; 40];
    buf[..32].fill(0xAA);
    zero_bytes(&mut buf[..32]);
    assert_eq!(buf[..32], [0u8; 32], "the whole slice must be cleared");
    assert_eq!(
        buf[32..],
        [0u8; 8],
        "bytes outside the slice stay untouched"
    );

    let mut empty: [u8; 0] = [];
    zero_bytes(&mut empty);
}

/// A cloned secret must be independently owned: dropping one copy may not
/// leave the other's bytes cleared (that is what `Copy` used to hide).
#[test]
fn cloned_password_secrets_survive_dropping_the_original() {
    let original = PasswordSecrets {
        payload_key: [1u8; 32],
        meta_key: [2u8; 32],
        header_mask: [3u8; 76],
    };
    let copy = original.clone();
    drop(original);
    assert_eq!(copy.payload_key, [1u8; 32]);
    assert_eq!(copy.meta_key, [2u8; 32]);
    assert_eq!(&copy.header_mask[..], &[3u8; 76][..]);
}

#[test]
fn compression_probe_rejects_short_input_in_release_too() {
    // The old `debug_assert!` disappeared in release builds, where a short
    // payload would underflow `span` and slice out of bounds.
    assert!(probe_compressibility(&[0u8; 32 * 1024], 6).is_err());
    assert!(probe_compressibility(&[], 6).is_err());
    assert!(probe_compressibility(&vec![0u8; COMPRESSION_PROBE_MIN_BYTES + 1], 6).is_ok());
}

/// Both of these are `pub fn`s reachable from an embedding host, and both
/// used to assume a validated `chunk_size`. `chunk_count` divided by zero
/// (a panic, and `panic = "abort"` makes that a process kill) and
/// `encrypt_stream_to_chunks` only had a `debug_assert!`, so a release build
/// silently wrote a single empty chunk instead of failing.
#[test]
fn zero_chunk_size_is_rejected_or_degraded_not_a_panic() {
    assert_eq!(chunk_count(100, 0), 100);
    assert_eq!(chunk_count(0, 0), 1);

    let key = [7u8; 32];
    let nonce = [9u8; 12];
    let aad = [0u8; AAD_SIZE];
    let mut input: &[u8] = b"payload";
    let mut out = Vec::new();
    let err = encrypt_stream_to_chunks(&mut input, &mut out, &key, &nonce, &aad, 0)
        .expect_err("a zero chunk size must be an error, not an empty chunk");
    assert!(
        err.to_string().contains("chunk_size"),
        "error must name the knob: {err}"
    );
    assert!(out.is_empty(), "nothing may be written before the check");
}

#[test]
fn test_python_crypto_vector_compatibility() {
    let salt = b"1234567890123456";
    let (pk, mk) = derive_keys("test_password", salt).unwrap();
    let (hm, tm) = derive_stealth_magics("test_password", b"strhide-stealth-v1").unwrap();

    // Check against Python computed hex strings
    let expected_pk = "2834274fef93d55fc5a3cb070c09c08eedecd8910b9a601fd67b703c8e078674";
    let expected_mk = "5406a23d873a956bcf01781771ea5f96857b61bda4f15ef53d40d87f07477c68";
    let expected_hm = "3858efa8820a029b";
    let expected_tm = "3a97756c";

    assert_eq!(
        pk.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        expected_pk
    );
    assert_eq!(
        mk.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        expected_mk
    );
    assert_eq!(
        hm.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        expected_hm
    );
    assert_eq!(
        tm.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        expected_tm
    );
}

#[test]
fn framed_len_matches_the_framer() {
    // The engine sizes the envelope with `framed_len` before anything is
    // written, so it must agree with `encrypt_stream_to_chunks` byte for
    // byte — including the empty payload, which still emits one chunk.
    for (plain_len, chunk_size) in [
        (0u64, CHUNK_SIZE),
        (1, CHUNK_SIZE),
        (CHUNK_SIZE as u64, CHUNK_SIZE),
        (CHUNK_SIZE as u64 + 1, CHUNK_SIZE),
        (5 * CHUNK_SIZE as u64 + 7, CHUNK_SIZE),
        (1234, 64),
    ] {
        let plain = vec![0u8; plain_len as usize];
        let mut cipher = Vec::new();
        let written = encrypt_stream_to_chunks(
            &mut &plain[..],
            &mut cipher,
            &[0x11u8; 32],
            &[0x22u8; 12],
            &[0x33u8; AAD_SIZE],
            chunk_size,
        )
        .unwrap();
        assert_eq!(
            written,
            framed_len(plain_len, chunk_size),
            "framing overhead drift for {plain_len} bytes at chunk_size {chunk_size}"
        );
        assert_eq!(cipher.len() as u64, written);
    }
}

#[test]
fn test_deflate_compatibility() {
    let data = b"Hello World! This is a test of raw deflate compression.";
    let mut comp = Vec::new();
    let (raw_len, comp_len) = compress_stream(&mut &data[..], &mut comp, 6).unwrap();
    assert_eq!(raw_len, data.len() as u64);
    assert_eq!(comp_len, comp.len() as u64);

    let mut decomp = Vec::new();
    let decomp_len = decompress_stream(&mut &comp[..], &mut decomp, data.len() as u64).unwrap();
    assert_eq!(decomp_len, data.len() as u64);
    assert_eq!(decomp, data);
}

#[test]
fn test_metadata_encryption_roundtrip_and_tamper() {
    let salt = b"1234567890123456";
    let base_nonce = [7u8; 12];
    let (_, meta_key) = derive_keys("SafePassword", salt).unwrap();
    let aad = [0x55u8; AAD_SIZE];
    let plain = b"{\"filename\":\"test.txt\",\"raw_size\":42}";

    // Encrypt
    let cipher = encrypt_metadata(plain, &meta_key, &base_nonce, &aad).unwrap();
    assert_ne!(cipher, plain);
    assert_eq!(cipher.len(), plain.len() + 16); // 16-byte Poly/GCM tag

    // Decrypt successfully
    let decrypted = decrypt_metadata(&cipher, &meta_key, &base_nonce, &aad).unwrap();
    assert_eq!(decrypted, plain);

    // Wrong password / key
    let (_, wrong_meta_key) = derive_keys("WrongPassword", salt).unwrap();
    assert!(matches!(
        decrypt_metadata(&cipher, &wrong_meta_key, &base_nonce, &aad),
        Err(StrHideError::CorruptedData(_))
    ));

    // Tampered AAD
    let mut tampered_aad = aad;
    tampered_aad[0] ^= 0xFF;
    assert!(matches!(
        decrypt_metadata(&cipher, &meta_key, &base_nonce, &tampered_aad),
        Err(StrHideError::CorruptedData(_))
    ));
}

#[test]
fn test_chunked_stream_roundtrip_multi_megabytes() {
    let salt = b"salt_for_stream!";
    let base_nonce = [3u8; 12];
    let (payload_key, _) = derive_keys("StreamPassword", salt).unwrap();
    let aad = [0xAAu8; AAD_SIZE];

    // 5MB data across multiple 2MB chunks
    let orig_size = 5 * 1024 * 1024 + 12345;
    let mut original_data = Vec::with_capacity(orig_size);
    for i in 0..orig_size {
        original_data.push(((i * 61 + 17) & 0xFF) as u8);
    }

    let mut in_stream = std::io::Cursor::new(&original_data);
    let mut cipher_stream = std::io::Cursor::new(Vec::new());

    let total_cipher_len = encrypt_stream_to_chunks(
        &mut in_stream,
        &mut cipher_stream,
        &payload_key,
        &base_nonce,
        &aad,
        crate::crypto::CHUNK_SIZE,
    )
    .unwrap();

    assert!(total_cipher_len > orig_size as u64);

    // Decrypt
    cipher_stream.set_position(0);
    let mut plain_stream = std::io::Cursor::new(Vec::new());
    let total_plain_len = decrypt_stream_from_chunks(
        &mut cipher_stream,
        &mut plain_stream,
        &payload_key,
        &base_nonce,
        &aad,
        total_cipher_len,
    )
    .unwrap();

    assert_eq!(total_plain_len, orig_size as u64);
    assert_eq!(plain_stream.into_inner(), original_data);
}

#[test]
fn test_chunk_size_max_boundary() {
    let salt = b"salt_for_stream!";
    let base_nonce = [4u8; 12];
    let (payload_key, _) = derive_keys("MaxChunkPassword", salt).unwrap();
    let aad = [0x55u8; AAD_SIZE];

    let orig_size = MAX_CHUNK_SIZE;
    let original_data = vec![0x7Au8; orig_size];

    let mut in_stream = std::io::Cursor::new(&original_data);
    let mut cipher_stream = std::io::Cursor::new(Vec::new());

    let total_cipher_len = encrypt_stream_to_chunks(
        &mut in_stream,
        &mut cipher_stream,
        &payload_key,
        &base_nonce,
        &aad,
        MAX_CHUNK_SIZE,
    )
    .unwrap();

    assert_eq!(total_cipher_len, (4 + MAX_CHUNK_SIZE + AEAD_TAG_LEN) as u64);

    // Decrypt must succeed without hitting the previous "Chunk length exceeds maximum" bug
    cipher_stream.set_position(0);
    let mut plain_stream = std::io::Cursor::new(Vec::new());
    let total_plain_len = decrypt_stream_from_chunks(
        &mut cipher_stream,
        &mut plain_stream,
        &payload_key,
        &base_nonce,
        &aad,
        total_cipher_len,
    )
    .unwrap();

    assert_eq!(total_plain_len, orig_size as u64);
    assert_eq!(plain_stream.into_inner(), original_data);
}
