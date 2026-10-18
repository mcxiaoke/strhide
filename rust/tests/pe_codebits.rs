//! Integration tests for the `pe_codebits` strategy (design doc v1.0, §14).
//!
//! Carriers are synthetic PE images built in-memory: a `.text` section filled
//! with a repeating pattern of instrumentable instructions (semantic pairs +
//! commutative TEST), plus header/section-tail zero padding for the restore
//! diff. This keeps the suite hermetic (no dependency on host binaries) while
//! exercising the real engine flow: write -> read -> inspect -> verify ->
//! remove, with byte-exact restore assertions.

use std::fs;
use std::path::{Path, PathBuf};

use strhide::engine::{
    PayloadSource, WriteOptions, inspect_carrier, read_carrier, remove_carrier, verify_carrier,
    write_carrier,
};

// --------------------------------------------------------------------------- helpers

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strhide_pcb_{}_{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// 23-byte pattern yielding 7 instrumentable positions (verified against the
/// module unit tests): mov/mov/mov-store-load pair, a memory-operand mov and
/// an equal-register TEST that the profile filters out, TEST both orders,
/// add and cmp.
const TEXT_PATTERN: &[u8] = &[
    0x89, 0xD8, // mov eax, ebx      (pair, bit 0)
    0x89, 0xCA, // mov ecx, edx      (pair, bit 0)
    0x8B, 0xD1, // mov edx, ecx      (pair, bit 1)
    0x89, 0x18, // mov [eax], ebx    (memory -> filtered)
    0x85, 0xC3, // test eax, ebx     (commutative, bit 0)
    0x85, 0xD8, // test ebx, eax     (commutative, bit 1)
    0x85, 0xC0, // test eax, eax     (equal regs -> filtered)
    0x01, 0xD8, // add eax, ebx      (pair, bit 0)
    0x3B, 0xC3, // cmp ebx, eax      (pair, bit 1)
    0x90, 0x90, 0x48, 0x89, 0x00, // padding + memory mov (filtered)
];

/// Builds a minimal PE image. `machine`/`opt_magic` select 32/64-bit,
/// `text_len` sizes the `.text` virtual size, and `tight` removes all slack
/// (section starts right after the section table, raw size == virtual size).
fn make_pe(machine: u16, opt_magic: u16, text_len: usize, tight: bool) -> Vec<u8> {
    let is_pe32p = opt_magic == 0x20B;
    let opt_size: u16 = if is_pe32p { 240 } else { 224 };
    let e_lfanew: u32 = 0x80;
    let sec_table = e_lfanew as usize + 24 + opt_size as usize; // 0x98+240=0x188 / 0x98+224=0x178
    let sec_table_end = sec_table + 40;
    let raw_ptr: u32 = if tight { sec_table_end as u32 } else { 0x400 };
    let raw_size = (text_len as u32).div_ceil(0x200) * 0x200;

    let mut img = vec![0u8; raw_ptr as usize];
    img[0..2].copy_from_slice(b"MZ");
    img[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    img[0x80..0x84].copy_from_slice(b"PE\0\0");
    img[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
    img[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    img[0x94..0x96].copy_from_slice(&opt_size.to_le_bytes()); // SizeOfOptionalHeader
    img[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes()); // executable
    let opt = 0x98;
    img[opt..opt + 2].copy_from_slice(&opt_magic.to_le_bytes());

    let sec = sec_table;
    img[sec..sec + 8].copy_from_slice(b".text\0\0\0");
    img[sec + 8..sec + 12].copy_from_slice(&(text_len as u32).to_le_bytes()); // VirtualSize
    img[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    img[sec + 16..sec + 20].copy_from_slice(&raw_size.to_le_bytes()); // SizeOfRawData
    img[sec + 20..sec + 24].copy_from_slice(&raw_ptr.to_le_bytes()); // PointerToRawData
    img[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // code|exec|read

    // .text body: repeat the instrumentable pattern.
    let mut text = Vec::with_capacity(text_len);
    while text.len() < text_len {
        text.extend_from_slice(TEXT_PATTERN);
    }
    text.truncate(text_len);
    img.extend_from_slice(&text);
    img.resize(raw_ptr as usize + raw_size as usize, 0); // tail padding
    img
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::new()
        .chain_update(data)
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn write_opts<'a>(out: &'a Path, strategy: &'a str) -> WriteOptions<'a> {
    WriteOptions {
        output_path: Some(out),
        strategy,
        backup: false,
        ..Default::default()
    }
}

// --------------------------------------------------------------------------- tests

/// T4: auto selects pe_codebits, the full flow round-trips, the carrier size
/// is unchanged, and remove restores the carrier byte-for-byte.
#[test]
fn codebits_auto_roundtrip_and_byte_exact_restore() {
    let dir = scratch("auto");
    let carrier = dir.join("app.exe");
    let original = make_pe(0x8664, 0x20B, 0x3000, false); // ~2.4k positions
    fs::write(&carrier, &original).unwrap();
    let orig_sha = sha256_hex(&original);

    let out = dir.join("app.steg.exe");
    let result = write_carrier(
        &carrier,
        PayloadSource::Text("meet at the old bridge, 9pm"),
        &write_opts(&out, "auto"),
    )
    .expect("write");
    assert_eq!(
        result.strategy, "pe_codebits",
        "auto must pick pe_codebits: {:?}",
        result.strategy_note
    );
    assert_eq!(
        fs::metadata(&out).unwrap().len(),
        original.len() as u64,
        "pe_codebits must not change the file size"
    );

    // read back
    let read = read_carrier(&out, None, None).expect("read");
    assert_eq!(read.data, b"meet at the old bridge, 9pm");

    // inspect + verify
    let ins = inspect_carrier(&out, None).expect("inspect");
    assert_eq!(ins.strategy.as_deref(), Some("pe_codebits"));
    assert!(ins.has_hidden_data);
    let v = verify_carrier(&out, None).expect("verify");
    assert!(v.level1_host.ok, "L1: {}", v.level1_host.detail);
    assert!(v.level2_envelope.ok, "L2: {}", v.level2_envelope.detail);
    assert!(v.level3_crypto.ok, "L3: {}", v.level3_crypto.detail);

    // remove -> byte-exact restore
    let restored = dir.join("app.restored.exe");
    let rem = remove_carrier(&out, Some(&restored), None, false).expect("remove");
    assert!(rem.verified_identical);
    let restored_bytes = fs::read(&restored).unwrap();
    assert_eq!(restored_bytes.len(), original.len());
    assert_eq!(
        sha256_hex(&restored_bytes),
        orig_sha,
        "restore must be bit-exact"
    );

    // idempotency: a second write on the restored file works again
    let out2 = dir.join("app2.steg.exe");
    let r2 = write_carrier(
        &restored,
        PayloadSource::Text("again"),
        &write_opts(&out2, "auto"),
    )
    .expect("re-write after remove");
    assert_eq!(r2.strategy, "pe_codebits");
}

/// T6: encrypted payload round-trips through the bit channel.
#[test]
fn codebits_encrypted_roundtrip() {
    let dir = scratch("enc");
    let carrier = dir.join("enc.exe");
    fs::write(&carrier, make_pe(0x8664, 0x20B, 0x3000, false)).unwrap();

    let out = dir.join("enc.steg.exe");
    let opts = WriteOptions {
        output_path: Some(&out),
        strategy: "pe_codebits",
        password: Some("correct horse battery staple"),
        backup: false,
        ..Default::default()
    };
    write_carrier(&carrier, PayloadSource::Text("encrypted secret"), &opts).expect("write");

    // Wrong password must fail cleanly.
    assert!(read_carrier(&out, None, Some("wrong pw")).is_err());
    // Right password round-trips.
    let read = read_carrier(&out, None, Some("correct horse battery staple")).expect("read");
    assert_eq!(read.data, b"encrypted secret");

    let restored = dir.join("enc.restored.exe");
    let rem = remove_carrier(
        &out,
        Some(&restored),
        Some("correct horse battery staple"),
        false,
    )
    .expect("remove");
    assert!(rem.verified_identical);
}

/// T6: stealth mode — the channel is invisible without the password and fully
/// functional with it.
#[test]
fn codebits_stealth_denies_without_password() {
    let dir = scratch("stealth");
    let carrier = dir.join("s.exe");
    let original = make_pe(0x8664, 0x20B, 0x3000, false);
    fs::write(&carrier, &original).unwrap();

    let out = dir.join("s.steg.exe");
    let opts = WriteOptions {
        output_path: Some(&out),
        strategy: "pe_codebits",
        password: Some("stealth pw"),
        stealth: true,
        backup: false,
        ..Default::default()
    };
    write_carrier(&carrier, PayloadSource::Text("invisible"), &opts).expect("write");

    // No password: nothing to find (plausible deniability).
    let err = read_carrier(&out, None, None).unwrap_err();
    assert!(
        matches!(err, strhide::errors::StrHideError::NoHiddenData(_)),
        "expected NoHiddenData, got {err:?}"
    );
    // Wrong password: same.
    assert!(read_carrier(&out, None, Some("nope")).is_err());

    // Right password: full round-trip and byte-exact restore.
    let read = read_carrier(&out, None, Some("stealth pw")).expect("read");
    assert_eq!(read.data, b"invisible");
    let restored = dir.join("s.restored.exe");
    let rem = remove_carrier(&out, Some(&restored), Some("stealth pw"), false).expect("remove");
    assert!(rem.verified_identical);
    assert_eq!(
        sha256_hex(&fs::read(&restored).unwrap()),
        sha256_hex(&original)
    );
}

/// T8: a `.text` too small for the channel makes auto fall back to
/// pe_overlay, which still round-trips normally.
#[test]
fn auto_falls_back_to_overlay_on_tiny_text() {
    let dir = scratch("fallback");
    let carrier = dir.join("tiny.exe");
    let original = make_pe(0x8664, 0x20B, 0x40, false); // ~19 positions
    fs::write(&carrier, &original).unwrap();
    let orig_sha = sha256_hex(&original);

    let out = dir.join("tiny.steg.exe");
    let result = write_carrier(
        &carrier,
        PayloadSource::Text("hi"),
        &write_opts(&out, "auto"),
    )
    .expect("write");
    assert_eq!(
        result.strategy, "pe_overlay",
        "tiny .text must fall back to overlay"
    );

    let read = read_carrier(&out, None, None).expect("read");
    assert_eq!(read.data, b"hi");
    let restored = dir.join("tiny.restored.exe");
    let rem = remove_carrier(&out, Some(&restored), None, false).expect("remove");
    assert!(rem.verified_identical);
    assert_eq!(sha256_hex(&fs::read(&restored).unwrap()), orig_sha);
}

/// T8: explicitly requesting pe_codebits on an incapable carrier is a hard
/// error (no silent downgrade).
#[test]
fn explicit_codebits_rejects_incapable_carriers() {
    let dir = scratch("reject");

    // Too little capacity.
    let tiny = dir.join("tiny2.exe");
    fs::write(&tiny, make_pe(0x8664, 0x20B, 0x40, false)).unwrap();
    let out = dir.join("tiny2.steg.exe");
    let err = write_carrier(
        &tiny,
        PayloadSource::Text("hi"),
        &write_opts(&out, "pe_codebits"),
    )
    .unwrap_err();
    assert!(
        matches!(err, strhide::errors::StrHideError::UnsupportedFormat(_)),
        "expected UnsupportedFormat, got {err:?}"
    );

    // Enough capacity but no zero-value slack run (tight layout).
    let tight = dir.join("tight.exe");
    fs::write(&tight, make_pe(0x8664, 0x20B, 0x3000, true)).unwrap();
    let out2 = dir.join("tight.steg.exe");
    let err2 = write_carrier(
        &tight,
        PayloadSource::Text("hi"),
        &write_opts(&out2, "pe_codebits"),
    )
    .unwrap_err();
    assert!(
        matches!(err2, strhide::errors::StrHideError::UnsupportedFormat(_)),
        "expected UnsupportedFormat, got {err2:?}"
    );
}

/// T8: a second injection on a channel carrier is refused.
#[test]
fn double_write_refused() {
    let dir = scratch("double");
    let carrier = dir.join("d.exe");
    fs::write(&carrier, make_pe(0x8664, 0x20B, 0x3000, false)).unwrap();

    let out = dir.join("d.steg.exe");
    write_carrier(
        &carrier,
        PayloadSource::Text("first"),
        &write_opts(&out, "pe_codebits"),
    )
    .expect("first write");

    let out2 = dir.join("d.steg2.exe");
    assert!(
        write_carrier(
            &out,
            PayloadSource::Text("second"),
            &write_opts(&out2, "auto")
        )
        .is_err(),
        "writing over an existing envelope must be refused"
    );
}

/// T9: corrupting a byte inside the channel region must fail cleanly (never
/// silently produce garbage or a wrong restore).
#[test]
fn corrupted_text_fails_cleanly() {
    let dir = scratch("corrupt");
    let carrier = dir.join("c.exe");
    fs::write(&carrier, make_pe(0x8664, 0x20B, 0x3000, false)).unwrap();

    let out = dir.join("c.steg.exe");
    write_carrier(
        &carrier,
        PayloadSource::Text("do not tamper"),
        &write_opts(&out, "pe_codebits"),
    )
    .expect("write");

    // Flip a byte well inside the .text channel region (offset 0x400 + 0x100).
    let mut bytes = fs::read(&out).unwrap();
    bytes[0x400 + 0x100] ^= 0xFF;
    let tampered = dir.join("c.tampered.exe");
    fs::write(&tampered, &bytes).unwrap();

    assert!(
        read_carrier(&tampered, None, None).is_err(),
        "read must fail on a tampered channel"
    );
    let restored = dir.join("c.tampered.restored.exe");
    assert!(
        remove_carrier(&tampered, Some(&restored), None, false).is_err(),
        "remove must fail (or refuse) on a tampered channel"
    );
}

/// T4: the 32-bit (PE32) path round-trips as well.
#[test]
fn codebits_32bit_pe_roundtrip() {
    let dir = scratch("pe32");
    let carrier = dir.join("x32.exe");
    let original = make_pe(0x14C, 0x10B, 0x3000, false);
    fs::write(&carrier, &original).unwrap();
    let orig_sha = sha256_hex(&original);

    let out = dir.join("x32.steg.exe");
    let result = write_carrier(
        &carrier,
        PayloadSource::Text("thirty-two bits"),
        &write_opts(&out, "auto"),
    )
    .expect("write");
    assert_eq!(result.strategy, "pe_codebits");
    assert_eq!(fs::metadata(&out).unwrap().len(), original.len() as u64);

    let read = read_carrier(&out, None, None).expect("read");
    assert_eq!(read.data, b"thirty-two bits");
    let restored = dir.join("x32.restored.exe");
    let rem = remove_carrier(&out, Some(&restored), None, false).expect("remove");
    assert!(rem.verified_identical);
    assert_eq!(sha256_hex(&fs::read(&restored).unwrap()), orig_sha);
}

/// Guard: the strategy registry knows pe_codebits (id 8) in both directions.
#[test]
fn strategy_registry_roundtrip() {
    use strhide::router::{id_to_strategy, strategy_to_id};
    assert_eq!(strategy_to_id("pe_codebits"), 8);
    assert_eq!(id_to_strategy(8), "pe_codebits");
}

/// Guard: a plain (non-PE) file is unaffected by the PE adapter changes.
#[test]
fn non_pe_carrier_unaffected() {
    let dir = scratch("nonpe");
    let carrier = dir.join("plain.bin");
    let original = b"just some generic host bytes, not a PE at all".to_vec();
    fs::write(&carrier, &original).unwrap();

    let out = dir.join("plain.steg.bin");
    let result = write_carrier(
        &carrier,
        PayloadSource::Text("eof"),
        &write_opts(&out, "auto"),
    )
    .expect("write");
    assert_eq!(result.format, "GENERIC");
    let read = read_carrier(&out, None, None).expect("read");
    assert_eq!(read.data, b"eof");
    let restored = dir.join("plain.restored.bin");
    let rem = remove_carrier(&out, Some(&restored), None, false).expect("remove");
    assert!(rem.verified_identical);
    assert_eq!(fs::read(&restored).unwrap(), original);
}

/// Sanity: helpers agree on the carrier shape the tests rely on.
#[test]
fn synthetic_carrier_shape() {
    let img = make_pe(0x8664, 0x20B, 0x3000, false);
    assert!(img.len() > 0x1F00);
    // Header padding [sec_table_end, 0x400) must exist and be zero.
    assert!(img[0x188 + 40..0x400].iter().all(|&b| b == 0));
    // .text starts at 0x400 with the instrumentable pattern.
    assert_eq!(&img[0x400..0x400 + 4], &[0x89, 0xD8, 0x89, 0xCA]);
}
