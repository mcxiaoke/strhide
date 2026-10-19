use std::fs;
use std::path::PathBuf;
use strhide::engine::{
    PayloadSource, WriteOptions, read_carrier, remove_carrier, verify_carrier, write_carrier,
};

fn scratch(sub: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strhide_stealth_test_{sub}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn sample_png() -> Vec<u8> {
    // Minimal valid PNG (1x1 red pixel)
    vec![
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // PNG signature
        0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77,
        0x53, 0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41, // IDAT chunk
        0x54, 0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xdd,
        0x8d, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, // IEND chunk
        0x44, 0xae, 0x42, 0x60, 0x82,
    ]
}

fn compute_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[test]
fn test_stealth_carrier_leaks_no_host_sha256() {
    let dir = scratch("no_host_sha256");
    let carrier_path = dir.join("carrier.png");
    let out_path = dir.join("out.png");

    let raw_png = sample_png();
    fs::write(&carrier_path, &raw_png).unwrap();
    let host_sha = compute_sha256(&raw_png);

    let password = "StealthDeFingerprintPassword@2026";
    let secret = "Top secret message hidden in stealth mode";

    write_carrier(
        &carrier_path,
        PayloadSource::Text(secret),
        &WriteOptions {
            output_path: Some(&out_path),
            password: Some(password),
            stealth: true,
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();

    let stego_bytes = fs::read(&out_path).unwrap();

    // 1. Verify that the 32-byte host SHA-256 does NOT appear anywhere in the stego file
    let found_hash = stego_bytes.windows(32).any(|w| w == host_sha);
    assert!(
        !found_hash,
        "Stealth carrier MUST NOT leak original host SHA-256 in plaintext!"
    );

    // 2. Read with password succeeds and verifies payload
    let read_res = read_carrier(&out_path, None, Some(password)).unwrap();
    assert_eq!(read_res.data, secret.as_bytes());

    // 3. Verify succeeds
    let verify_res = verify_carrier(&out_path, Some(password)).unwrap();
    assert!(verify_res.level1_host.ok);
    assert!(verify_res.level2_envelope.ok);
    assert!(verify_res.level3_crypto.ok);

    // 4. Remove restores exact byte-for-byte carrier
    let rem_res = remove_carrier(&out_path, None, Some(password), false).unwrap();
    assert!(rem_res.verified_identical);
    let restored_bytes = fs::read(&out_path).unwrap();
    assert_eq!(restored_bytes, raw_png);
}

#[test]
fn test_stealth_trailer_breaks_public_crc32_scan() {
    let dir = scratch("break_crc32_scan");
    let carrier_path = dir.join("carrier.png");
    let out_path = dir.join("out.png");

    let raw_png = sample_png();
    fs::write(&carrier_path, &raw_png).unwrap();

    let password = "StealthDeFingerprintPassword@2026";
    let secret = "Deniable payload";

    write_carrier(
        &carrier_path,
        PayloadSource::Text(secret),
        &WriteOptions {
            output_path: Some(&out_path),
            password: Some(password),
            stealth: true,
            backup: false,
            ..Default::default()
        },
    )
    .unwrap();

    let stego_bytes = fs::read(&out_path).unwrap();

    // A generic forensic scanner looking for strhide trailer scans every 24-byte
    // window testing: crc32fast::hash(&window[0..16]) == u32::from_le_bytes(window[16..20]).
    // In stealth mode, the trailer CRC is masked, so this standard scan should NOT match.
    let mut matching_windows = Vec::new();
    for (i, window) in stego_bytes.windows(24).enumerate() {
        let prefix = &window[0..16];
        let claimed_crc = u32::from_le_bytes(window[16..20].try_into().unwrap());
        if crc32fast::hash(prefix) == claimed_crc {
            matching_windows.push(i);
        }
    }

    assert!(
        matching_windows.is_empty(),
        "Stealth trailer must not match standard IEEE 802.3 CRC32 scan (found at offsets: {:?})",
        matching_windows
    );
}

#[test]
fn test_stealth_legacy_unmasked_backward_compatibility() {
    use rand::RngExt;
    use strhide::crypto::{
        derive_keys, derive_stealth_magics, encrypt_metadata, encrypt_stream_to_chunks,
    };
    use strhide::engine::CarrierMetadata;
    use strhide::envelope::{
        EnvelopeHeader, EnvelopeTrailer, FLAG_ENCRYPTED, FLAG_STEALTH, HEADER_SIZE,
    };

    let dir = scratch("legacy_stealth_compat");
    let carrier_path = dir.join("carrier.png");
    let raw_png = sample_png();
    let host_sha = compute_sha256(&raw_png);
    let host_size = raw_png.len() as u64;

    let password = "LegacyPassword123";
    let (header_magic, trailer_magic) =
        derive_stealth_magics(password, b"strhide-stealth-v1").unwrap();

    let mut salt = [0u8; 16];
    let mut base_nonce = [0u8; 12];
    rand::rng().fill(&mut salt);
    rand::rng().fill(&mut base_nonce);

    let (payload_key, meta_key) = derive_keys(password, &salt).unwrap();

    let flags = FLAG_ENCRYPTED | FLAG_STEALTH;
    let meta_obj = CarrierMetadata {
        filename: String::new(),
        raw_size: 14,
        raw_sha256: "57c686be41c66320bb8f451068c4176d51c708594aa82f9ec3e324194fae11e6".into(),
        created_at: 1773719840,
    };
    let meta_raw = serde_json::to_vec(&meta_obj).unwrap();

    let mut header = EnvelopeHeader {
        magic_header: header_magic,
        flags,
        strategy_id: 2, // chunk
        salt,
        base_nonce,
        orig_host_size: host_size,
        orig_host_sha256: host_sha,
        ..Default::default()
    };
    let aad = header.get_aad();

    let meta_cipher = encrypt_metadata(&meta_raw, &meta_key, &base_nonce, &aad).unwrap();
    header.meta_len = meta_cipher.len() as u32;

    let secret_payload = b"legacy payload";
    let mut payload_cipher = Vec::new();
    encrypt_stream_to_chunks(
        &mut std::io::Cursor::new(secret_payload),
        &mut payload_cipher,
        &payload_key,
        &base_nonce,
        &aad,
    )
    .unwrap();

    let ube_total_size =
        HEADER_SIZE as u64 + header.meta_len as u64 + payload_cipher.len() as u64 + 24;
    header.inject_offset = 57;
    header.inject_size = ube_total_size + 12;

    // Notice: legacy UBE used raw unmasked pack() and unmasked trailer create()!
    let raw_header_bytes = header.pack();
    let legacy_trailer = EnvelopeTrailer::create(57 + 8, ube_total_size, trailer_magic);

    let mut ube = Vec::new();
    ube.extend_from_slice(&raw_header_bytes);
    ube.extend_from_slice(&meta_cipher);
    ube.extend_from_slice(&payload_cipher);
    ube.extend_from_slice(&legacy_trailer.pack());

    // Inject into PNG before IEND (offset 57)
    let mut stego_png = Vec::new();
    stego_png.extend_from_slice(&raw_png[..57]); // before IEND

    // prIv chunk: length (BE), 'prIv', ube, CRC
    stego_png.extend_from_slice(&(ube.len() as u32).to_be_bytes());
    stego_png.extend_from_slice(b"prIv");
    stego_png.extend_from_slice(&ube);
    let mut chunk_crc = crc32fast::Hasher::new();
    chunk_crc.update(b"prIv");
    chunk_crc.update(&ube);
    stego_png.extend_from_slice(&chunk_crc.finalize().to_be_bytes());

    stego_png.extend_from_slice(&raw_png[57..]); // IEND chunk
    fs::write(&carrier_path, &stego_png).unwrap();

    // Verify that new strhide can read this legacy stealth envelope!
    let read_res = read_carrier(&carrier_path, None, Some(password)).unwrap();
    assert_eq!(read_res.data, secret_payload);

    // Verify that remove restores byte-for-byte exact host
    let rem_res = remove_carrier(&carrier_path, None, Some(password), false).unwrap();
    assert!(rem_res.verified_identical);
    assert_eq!(fs::read(&carrier_path).unwrap(), raw_png);
}
