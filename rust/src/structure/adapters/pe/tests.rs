use super::*;

/// Synthetic 64-bit code: a repeating mix of `mov eax, ebx` (89 D8),
/// `mov ebx, eax` (8B C3-equivalent is 89 D9? no: 8B D9 = mov ebx, ecx),
/// TEST forms and a memory-operand instruction that must be filtered out.
fn synthetic_text() -> Vec<u8> {
    let mut v = Vec::new();
    // mov eax, ebx        ; 89 D8  (pair, bit 0)
    v.extend_from_slice(&[0x89, 0xD8]);
    // mov ecx, edx        ; 89 CA  (pair, bit 0)
    v.extend_from_slice(&[0x89, 0xCA]);
    // mov edx, ecx        ; 8B D1  (pair, bit 1)
    v.extend_from_slice(&[0x8B, 0xD1]);
    // mov [eax], ebx      ; 89 18  (memory operand -> filtered by F2)
    v.extend_from_slice(&[0x89, 0x18]);
    // test eax, ebx       ; 85 C3  (commutative, r0<r1 -> bit 0)
    v.extend_from_slice(&[0x85, 0xC3]);
    // test ebx, eax       ; 85 D8  (commutative, r0>r1 -> bit 1)
    v.extend_from_slice(&[0x85, 0xD8]);
    // test eax, eax       ; 85 C0  (equal regs -> filtered by F3)
    v.extend_from_slice(&[0x85, 0xC0]);
    // add eax, ebx        ; 01 D8  (pair, bit 0)
    v.extend_from_slice(&[0x01, 0xD8]);
    // cmp ebx, eax        ; 3B C3  (pair, bit 1)
    v.extend_from_slice(&[0x3B, 0xC3]);
    // embedded data (must be skipped as INVALID or unsupported)
    v.extend_from_slice(&[0x90, 0x90, 0x48, 0x89, 0x00]);
    v
}

#[test]
fn profile_filters_and_bits() {
    let text = synthetic_text();
    let prof = profile(&text, 64);
    // 89D8, 89CA, 8BD1, 85C3, 85D8, 01D8, 3BC3 = 7 positions.
    // 8918 (memory) and 85C0 (equal regs) are filtered out.
    assert_eq!(prof.len(), 7, "positions: {prof:?}");
    assert_eq!(prof[0].offset, 0);
    assert!(!prof[0].bit, "89 D8 is the store form (bit 0)");
    assert_eq!(prof[1].offset, 2);
    assert!(prof[2].bit, "8B D1 is the load form (bit 1)");
    assert_eq!(prof[3].offset, 8, "85 C3 after the memory-operand insn");
    assert!(!prof[3].bit);
    assert!(prof[4].bit, "85 D8 has r0 > r1 (bit 1)");
    assert!(!prof[5].bit, "01 D8 add store form");
    assert!(prof[6].bit, "3B C3 cmp load form");
    for p in &prof {
        assert!(p.len == 2);
    }
}

#[test]
fn profile_upto_returns_exactly_a_prefix() {
    let mut full = Vec::new();
    while full.len() < 8192 {
        full.extend_from_slice(&synthetic_text());
    }
    full.truncate(8192);
    let all = profile(&full, 64);
    assert!(all.len() >= CHANNEL_HEADER_BITS, "fixture has capacity");
    let limited = profile_upto(&full, 64, Some(CHANNEL_HEADER_BITS));
    assert_eq!(limited.len(), CHANNEL_HEADER_BITS.min(all.len()));
    assert_eq!(
        limited
            .iter()
            .map(|p| (p.offset, p.bit))
            .collect::<Vec<_>>(),
        all[..limited.len()]
            .iter()
            .map(|p| (p.offset, p.bit))
            .collect::<Vec<_>>(),
        "the bounded scan must be a prefix of the full one"
    );
    assert_eq!(profile_upto(&full, 64, None), all);
}

#[test]
fn profile_is_stable_after_embed() {
    // Repeat the synthetic pattern until there is enough capacity.
    let mut full = Vec::new();
    while full.len() < 8192 {
        full.extend_from_slice(&synthetic_text());
    }
    full.truncate(8192);
    let ube = vec![0xA5u8; 200];
    let (need_bits, need_slack) = channel_requirement(ube.len());
    let before = profile(&full, 64);
    assert!(before.len() >= need_bits);

    let diff = embed(&mut full, 64, &ube, 0x1000).expect("embed");
    assert_eq!(diff.len(), need_slack);

    let after = profile(&full, 64);
    assert_eq!(
        after.iter().map(|p| p.offset).collect::<Vec<_>>(),
        before.iter().map(|p| p.offset).collect::<Vec<_>>(),
        "position list must be identical after embed"
    );
}

#[test]
fn embed_extract_roundtrip() {
    let mut full = Vec::new();
    while full.len() < 8192 {
        full.extend_from_slice(&synthetic_text());
    }
    full.truncate(8192);
    // The UBE blob ends with its trailer magic; the channel reuses it.
    let mut ube: Vec<u8> = (0..200u32).map(|i| (i * 31 + 7) as u8).collect();
    let n = ube.len();
    ube[n - 4..].copy_from_slice(&CHANNEL_MAGIC);
    let original = full.clone();

    let diff = embed(&mut full, 64, &ube, 0x2222).expect("embed");

    let (header, got) = extract_ube(&full, 64).expect("extract");
    assert_eq!(header.magic, CHANNEL_MAGIC);
    assert_eq!(header.version, CHANNEL_VERSION);
    assert_eq!(header.ube_len, ube.len() as u32);
    assert_eq!(header.slack_off, 0x2222);
    assert_eq!(got, ube, "extracted UBE must round-trip byte-exactly");

    // Stealth magic: a channel written with a derived magic is invisible to
    // the standard expectation and readable with the right one.
    assert!(matches!(
        read_channel_header(&full, 64, Some(*b"XXXX")),
        Err(CodebitsError::ChannelNotFound)
    ));
    read_channel_header(&full, 64, Some(CHANNEL_MAGIC)).expect("standard magic");

    // Restore: apply the diff, then the text must equal the original.
    apply_diff(&mut full, 64, &diff).expect("apply_diff");
    assert_eq!(full, original, "strip must restore .text byte-exactly");
}

#[test]
fn channel_header_masking_roundtrip_only() {
    let magic = CHANNEL_MAGIC;
    let envelope_magic = crate::structure::envelope::STANDARD_HEADER_MAGIC;
    let header = ChannelHeader {
        magic,
        version: CHANNEL_VERSION,
        flags: 0,
        ube_len: 256,
        slack_off: 0x1000,
    };

    // 1. Masked packing: bytes 0..4 stay visible, the rest is keyed by the
    //    8-byte envelope header magic.
    let masked_bytes = header.pack_masked(&envelope_magic);
    assert_eq!(&masked_bytes[0..4], &magic);
    let mask = crate::crypto::derive_channel_header_mask(&envelope_magic);
    assert_eq!(masked_bytes[4], CHANNEL_VERSION ^ mask[0]);
    assert_ne!(masked_bytes[4], CHANNEL_VERSION);

    // Unpack masked bytes
    let unpacked =
        ChannelHeader::unpack_masked(&masked_bytes, &envelope_magic).expect("unpack masked");
    assert_eq!(unpacked, header);

    // 2. An unmasked (pre-v1) header no longer parses: the version byte is
    //    read straight out of the ciphertext stream instead of being
    //    accepted verbatim.
    let unmasked_bytes = header.pack_unmasked();
    assert_eq!(unmasked_bytes[4], CHANNEL_VERSION);
    let bogus =
        ChannelHeader::unpack_masked(&unmasked_bytes, &envelope_magic).expect("still 14 bytes");
    assert_ne!(bogus.version, CHANNEL_VERSION);
}

/// Regression test: validates that channel mask derivation relies on envelope header
/// magic rather than visible channel magic, preventing unauthenticated header unpacking.
#[test]
fn channel_header_mask_is_not_derivable_from_the_visible_magic() {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let visible_magic = CHANNEL_MAGIC;
    let envelope_magic = crate::structure::envelope::STANDARD_HEADER_MAGIC;
    let header = ChannelHeader {
        magic: visible_magic,
        version: CHANNEL_VERSION,
        flags: 0,
        ube_len: 256,
        slack_off: 0x1000,
    };

    // Legacy derivation for negative regression: HKDF over the 4 visible magic bytes.
    let old_mask = {
        let hk = Hkdf::<Sha256>::new(None, &visible_magic);
        let mut mask = [0u8; 10];
        hk.expand(b"strhide-pe-channel-mask-v1", &mut mask)
            .expect("HKDF-Expand for 10-byte channel mask never fails");
        mask
    };
    let mut old_bytes = header.pack_unmasked();
    for (i, m) in old_mask.iter().enumerate() {
        old_bytes[4 + i] ^= *m;
    }
    // Verify legacy mask behavior against raw bytes.
    assert_eq!(old_bytes[4] ^ old_mask[0], CHANNEL_VERSION);

    // The new reader keys the mask from the envelope header magic, so an
    // old-format header does not unmask into a usable channel header.
    let wrong = ChannelHeader::unpack_masked(&old_bytes, &envelope_magic).expect("still 14 bytes");
    assert_ne!(
        wrong.version, CHANNEL_VERSION,
        "old v1 masking must no longer parse"
    );
    assert!(matches!(
        validate_header_prefix(&wrong),
        Err(CodebitsError::Corrupted(_))
    ));

    // The visible 4-byte magic cannot reproduce the real mask: same first
    // four bytes, different remaining four, different keystream.
    let real_mask = crate::crypto::derive_channel_header_mask(&envelope_magic);
    assert_ne!(old_mask, real_mask);
    let mut other_ikm = envelope_magic;
    other_ikm[4..8].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    assert_ne!(
        crate::crypto::derive_channel_header_mask(&other_ikm),
        real_mask
    );

    // The visible bytes are not a prefix of the real IKM in standard mode,
    // which is what stops a `derive_channel_header_mask(visible)` caller.
    assert_ne!(&envelope_magic[0..4], &visible_magic);
}

#[test]
fn oversized_ube_len_is_rejected() {
    let header = ChannelHeader {
        magic: CHANNEL_MAGIC,
        version: CHANNEL_VERSION,
        flags: 0,
        ube_len: MAX_CODEBITS_UBE_LEN + 1,
        slack_off: 0,
    };
    assert!(matches!(
        validate_header_prefix(&header),
        Err(CodebitsError::Corrupted(_))
    ));
    // The length helpers must never wrap, even for an absurd header.
    assert_eq!(
        header.diff_len(),
        MAX_CODEBITS_UBE_LEN as usize + 1 + CHANNEL_HEADER_LEN
    );
}

#[test]
fn read_channel_header_rejects_foreign_magic() {
    let mut full = Vec::new();
    while full.len() < 8192 {
        full.extend_from_slice(&synthetic_text());
    }
    full.truncate(8192);

    // Craft a channel bitstream with a foreign magic and a valid masked header
    let foreign_header = ChannelHeader {
        magic: *b"STHC",
        version: CHANNEL_VERSION,
        flags: 0,
        ube_len: 200,
        slack_off: 0x1000,
    };
    let mut channel = Vec::new();
    // The mask IKM is the first 8 bytes of the fake UBE payload below
    // (channel positions 112..176); a foreign magic only fails the magic
    // check, so the header still has to unmask cleanly.
    channel.extend_from_slice(&foreign_header.pack_masked(&[0x42u8; 8]));
    channel.extend_from_slice(&[0x42u8; 200]);

    let bits = bytes_to_bits(&channel);
    let prof = profile(&full, 64);
    let mut encoder = iced_x86::Encoder::new(64);
    for (&want, pos) in bits.iter().zip(prof.iter()) {
        if pos.bit == want {
            continue;
        }
        let other = if pos.commutative {
            iced_x86::Instruction::with2(pos.code, pos.r1, pos.r0)
        } else {
            let dual = dual_and_bit(pos.code).unwrap().0;
            iced_x86::Instruction::with2(dual, pos.r0, pos.r1)
        }
        .unwrap();
        encoder.encode(&other, pos.offset as u64).unwrap();
        let enc = encoder.take_buffer();
        full[pos.offset..pos.offset + pos.len].copy_from_slice(&enc);
    }

    // The pre-v1 `STHC` placeholder magic is gone: only CHANNEL_MAGIC locates.
    assert!(matches!(
        read_channel_header(&full, 64, None),
        Err(CodebitsError::ChannelNotFound)
    ));
}

#[test]
fn embed_capacity_error() {
    let text = synthetic_text();
    let mut text = text;
    let ube = vec![0u8; 1000];
    let err = embed(&mut text, 64, &ube, 0).unwrap_err();
    assert!(
        matches!(err, CodebitsError::Capacity { .. }),
        "expected capacity error, got {err:?}"
    );
}

#[test]
fn bit_helpers_msb_first() {
    assert_eq!(
        bytes_to_bits(&[0b1000_0000, 0b0000_0001]),
        vec![
            true, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, true
        ]
    );
    assert_eq!(bits_to_bytes(&[true, false, true]), vec![0b1010_0000]);
    let mut buf = vec![0u8; 2];
    set_bit(&mut buf, 0);
    set_bit(&mut buf, 9);
    assert!(get_bit(&buf, 0));
    assert!(get_bit(&buf, 9));
    assert!(!get_bit(&buf, 1));
}

#[test]
fn pe_layout_and_slack_on_synthetic_image() {
    let img = synthetic_pe();
    let layout = pe_code_layout(&img).expect("layout");
    assert_eq!(layout.bitness, 64);
    assert_eq!(layout.text_offset, 0x400);
    assert!(layout.text_scan_len > 0);
    // Header padding [sec_table_end, 0x400) plus .text tail padding must
    // both be present and all-zero.
    assert!(layout.slack_ranges.len() >= 2);
    for (a, b) in &layout.slack_ranges {
        assert!(img[*a as usize..*b as usize].iter().all(|&x| x == 0));
    }
    let run = find_slack_run(&img, &layout.slack_ranges, 300).expect("slack run");
    assert!(
        img[run as usize..run as usize + 300]
            .iter()
            .all(|&x| x == 0)
    );
    // Streaming variant must agree with the in-memory variant.
    let mut cursor = std::io::Cursor::new(img.clone());
    let slayout = parse_pe_code_layout_streaming(&mut cursor).expect("stream layout");
    assert_eq!(slayout.text_offset, layout.text_offset);
    assert_eq!(slayout.text_scan_len, layout.text_scan_len);
    let srun = find_slack_run_streaming(&mut cursor, &slayout.slack_ranges, 300)
        .expect("stream slack")
        .expect("run");
    assert_eq!(srun, run);
}

/// Builds a minimal but structurally valid PE32+ image with a `.text`
/// section full of instrumentable instructions and zero padding.
pub fn synthetic_pe() -> Vec<u8> {
    let mut img = vec![0u8; 0x400];
    // DOS header
    img[0..2].copy_from_slice(b"MZ");
    img[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    // PE signature at 0x80
    img[0x80..0x84].copy_from_slice(b"PE\0\0");
    // COFF: machine=amd64, 1 section, opt header size 240, characteristics
    img[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    img[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    // TimeDateStamp / PointerToSymbolTable / NumberOfSymbols stay zero.
    img[0x94..0x96].copy_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader
    img[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes()); // executable
    // Optional header PE32+ (magic 0x20B), 240 bytes; security dir at +144 stays zero
    let opt = 0x98;
    img[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
    // Section table at 0x94 + 240 = 0x184
    let sec = opt + 240;
    let name = b".text\0\0\0";
    img[sec..sec + 8].copy_from_slice(name);
    let vsize: u32 = 0x300;
    let rawsize: u32 = 0x400;
    let rawptr: u32 = 0x400;
    img[sec + 8..sec + 12].copy_from_slice(&vsize.to_le_bytes());
    img[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    img[sec + 16..sec + 20].copy_from_slice(&rawsize.to_le_bytes());
    img[sec + 20..sec + 24].copy_from_slice(&rawptr.to_le_bytes());
    img[sec + 36..sec + 40].copy_from_slice(&0x60000020u32.to_le_bytes()); // code|exec|read

    // .text body: repeat a mixed pattern of instrumentable instructions.
    let body = synthetic_text();
    let mut text = Vec::new();
    while text.len() < vsize as usize {
        text.extend_from_slice(&body);
    }
    text.truncate(vsize as usize);
    img.extend_from_slice(&text);
    // Tail padding up to rawsize (0x100 bytes of zeros) then EOF.
    img.resize(rawptr as usize + rawsize as usize, 0);
    img
}

#[test]
fn truncated_section_table_returns_not_pe() {
    let mut img = synthetic_pe();
    // Section table starts at 0x98 + 240 = 0x188.
    // Truncate img so the section header is cut in half (< 40 bytes).
    img.truncate(0x188 + 20);
    let res = pe_geometry(&img);
    assert!(matches!(res, Err(CodebitsError::NotPe)));
}
