use super::*;
use crate::stego::params::{ExtractParams, JpegParams, SafetyPolicy};

const CARRIER: &[u8] = include_bytes!("../../../tests/assets/small.jpg");

#[test]
fn trace_call_sites_do_not_format_eagerly() {
    // Verifies trace call sites pass `format_args!` rather than allocating eagerly with `format!`.
    let source = include_str!("engine.rs");
    // Split so this test's own source does not contain the needle.
    let eager_pattern = concat!("trace", "(&format!(");
    assert!(
        !source.contains(eager_pattern),
        "trace must receive format_args!, not an eagerly formatted String"
    );
}

fn decode_debug(stego: &[u8]) -> (JpegCoefficients, Vec<u32>, JpegSuperblockV4, Vec<u8>) {
    let fmt = &crate::stego::format::DEFAULT_JPEG_FORMAT;
    let coeffs = dct_io::read_coefficients(stego).expect("coefficients");
    let cover = CoverFrame::read(fmt, &coeffs);
    let pre_salt = jpeg_pre_salt(fmt, &cover);
    let master = derive_locator_master(
        Credential::Password("aad-test"),
        None,
        fmt.cipher,
        &pre_salt,
    )
    .expect("master");
    let locator =
        derive_l2_locator_keys(&master, fmt.cipher, b"strhide-v4-hdr-magic", None).expect("l2");
    let mut slots = v3_layout::grid_indices(cover.block_count, fmt.grid_rule);
    let sb_n = fmt.superblock_slots();
    let hdr_min = fmt.header_slots(0);
    let mut rng = ChaCha12Stream::from_seed(&locator.locate_seed);
    fisher_yates_prefix_from(&mut slots, 0, hdr_min, &mut rng);
    let sb = read_superblock(&coeffs, &slots[..sb_n], fmt, &locator).expect("header");
    let hdr_n = fmt.header_slots(sb.ext_len as usize);
    fisher_yates_prefix_from(&mut slots, hdr_min, hdr_n, &mut rng);
    let ext = read_bits(
        &coeffs,
        &slots[sb_n..hdr_n],
        fmt.grid_rule,
        locator.ext_stc_seed,
        fmt.ext_h,
        fmt.ext_u,
        8 * sb.ext_len as usize,
    )
    .expect("extension");
    (coeffs, slots, sb, ext)
}

#[test]
fn extension_area_is_authenticated_by_aad() {
    let fmt = &crate::stego::format::DEFAULT_JPEG_FORMAT;
    let tlv = vec![Tlv {
        type_id: 0x01,
        value: b"ext-a".to_vec(),
    }];
    let (stego, _, _) = embed_jpeg_with_stats(
        CARRIER,
        Payload::bytes(b"aad-extension-regression"),
        Credential::Password("aad-test"),
        None,
        1,
        &tlv,
        fmt,
        &JpegParams::default(),
        SafetyPolicy::default(),
        &crate::stego::jpeg::cost::UerdCostModel,
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed");

    let (coeffs, mut slots, sb, ext) = decode_debug(&stego);
    let cover = CoverFrame::read(fmt, &coeffs);
    let master = derive_locator_master(
        Credential::Password("aad-test"),
        None,
        fmt.cipher,
        &jpeg_pre_salt(fmt, &cover),
    )
    .expect("master");
    let suite = CipherSuiteId::from_u16(sb.suite_id).expect("suite");
    let session = derive_l3_session_keys(fmt.cipher, suite, &master, &sb.salt, None).expect("l3");
    let bits = sb.body_len as usize * 8;
    let window = bits + sb.stc_h as usize - 1;
    let body_n = window * sb.stc_u as usize;
    let hdr_n = fmt.header_slots(sb.ext_len as usize);
    let hdr_slots = slots[..hdr_n].to_vec();
    v3_layout::fill_body_grid(&mut slots, &hdr_slots, cover.block_count, fmt.grid_rule);
    permute_prefix(&mut slots, body_n, &session.perm_seed);
    slots.truncate(body_n);
    let ciphertext = read_bits(
        &coeffs,
        &slots,
        fmt.grid_rule,
        session.stc_seed,
        sb.stc_h,
        sb.stc_u,
        bits,
    )
    .expect("body");

    let aad = build_v4_aad_with(
        crate::stego::format::OFFICIAL_AAD_PREFIX,
        JPEG_FORMAT_ID,
        &sb.encode(),
        &ext,
    );
    assert!(
        unpack_v4_envelope_parts(
            suite,
            &session.enc_key,
            &sb.nonce,
            &aad,
            &ciphertext,
            &ExtractParams::default(),
        )
        .is_ok()
    );

    // Change the extension value and re-encode it: the CRC is valid again,
    // so only the AEAD binding can reject the carrier.
    let mut forged_tlvs = tlv.clone();
    forged_tlvs[0].value = b"ext-b".to_vec();
    let forged_ext = crate::stego::header::encode_extension(&forged_tlvs).expect("re-encode");
    assert!(
        parse_extension(&forged_ext).is_ok(),
        "re-encoded extension must carry a valid CRC"
    );
    let forged_aad = build_v4_aad_with(
        crate::stego::format::OFFICIAL_AAD_PREFIX,
        JPEG_FORMAT_ID,
        &sb.encode(),
        &forged_ext,
    );
    assert!(
        unpack_v4_envelope_parts(
            suite,
            &session.enc_key,
            &sb.nonce,
            &forged_aad,
            &ciphertext,
            &ExtractParams::default(),
        )
        .is_err(),
        "recomputed extension CRC must still fail AEAD"
    );
}

#[test]
fn forged_header_fields_cannot_drive_allocation() {
    let fmt = &crate::stego::format::DEFAULT_JPEG_FORMAT;
    let (stego, _, _) = embed_jpeg_with_stats(
        CARRIER,
        Payload::bytes(b"header-bounds"),
        Credential::Password("aad-test"),
        None,
        1,
        &[],
        fmt,
        &JpegParams::default(),
        SafetyPolicy::default(),
        &crate::stego::jpeg::cost::UerdCostModel,
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed");
    let coeffs = dct_io::read_coefficients(&stego).expect("coefficients");
    let cover = CoverFrame::read(fmt, &coeffs);
    let limits = ExtractParams::default();
    for body_len in [0u32, 1, 21] {
        assert!(
            limits
                .validate_header(1, body_len, fmt.header_slots(0), cover.n_total())
                .is_err(),
            "body_len {body_len} must be rejected before any slot work"
        );
    }
    // A forged upper-bound body_len may pass the byte-range gate, but its
    // slot footprint must exceed the carrier before any allocation.
    let huge_bits = 0x00FF_FFFFusize * 8;
    let huge_slots = (huge_bits + fmt.sb_h as usize - 1) * fmt.sb_u as usize;
    assert!(huge_slots > cover.n_total());
}

#[test]
fn truncated_header_slots_are_not_decodable() {
    let fmt = &crate::stego::format::DEFAULT_JPEG_FORMAT;
    let (stego, _, _) = embed_jpeg_with_stats(
        CARRIER,
        Payload::bytes(b"truncated-header"),
        Credential::Password("aad-test"),
        None,
        1,
        &[],
        fmt,
        &JpegParams::default(),
        SafetyPolicy::default(),
        &crate::stego::jpeg::cost::UerdCostModel,
        Freshness::Random,
        &Control::none(),
    )
    .expect("embed");
    let coeffs = dct_io::read_coefficients(&stego).expect("coefficients");
    let cover = CoverFrame::read(fmt, &coeffs);
    let pre_salt = jpeg_pre_salt(fmt, &cover);
    let master = derive_locator_master(
        Credential::Password("aad-test"),
        None,
        fmt.cipher,
        &pre_salt,
    )
    .expect("master");
    let locator =
        derive_l2_locator_keys(&master, fmt.cipher, b"strhide-v4-hdr-magic", None).expect("l2");
    let mut slots = v3_layout::grid_indices(cover.block_count, fmt.grid_rule);
    let sb_n = fmt.superblock_slots();
    fisher_yates_prefix_from(
        &mut slots,
        0,
        fmt.header_slots(0),
        &mut ChaCha12Stream::from_seed(&locator.locate_seed),
    );
    assert!(
        read_superblock(&coeffs, &slots[..sb_n - 1], fmt, &locator).is_none(),
        "a truncated header slot slice must not decode"
    );
}
