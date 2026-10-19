//! Integration tests for the `pe_slack` strategy: the envelope lives in the
//! PE's section alignment padding, so the carrier's size never changes, nothing
//! is appended, and the restore is bit-exact because only all-zero padding is
//! overwritten.
//!
//! Carriers are synthetic PE images built in memory (hermetic: no dependency on
//! host binaries) with configurable padding, section count and machine type.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use strhide::adapters::pe_codebits;
use strhide::engine::{
    PayloadSource, WriteOptions, inspect_carrier, read_carrier, remove_carrier, verify_carrier,
    write_carrier,
};
use strhide::envelope::EnvelopeHeader;
use strhide::errors::StrHideError;

// --------------------------------------------------------------------------- helpers

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strhide_pes_{}_{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn align_up(n: usize, a: usize) -> usize {
    n.div_ceil(a) * a
}

/// x86/x64 instruction pattern (same generator as the pe_codebits suite) so a
/// carrier can be made capable of the instruction channel too.
const TEXT_PATTERN: &[u8] = &[
    0x89, 0xD8, 0x89, 0xCA, 0x8B, 0xD1, 0x89, 0x18, 0x85, 0xC3, 0x85, 0xD8, 0x85, 0xC0, 0x01, 0xD8,
    0x3B, 0xC3, 0x90, 0x90, 0x48, 0x89, 0x00,
];

fn text_body(len: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(len + TEXT_PATTERN.len());
    while body.len() < len {
        body.extend_from_slice(TEXT_PATTERN);
    }
    body.truncate(len);
    body
}

/// One section: name, raw body, requested zero padding after `VirtualSize`.
struct Sec {
    name: &'static str,
    body: Vec<u8>,
    slack: usize,
}

fn sec(name: &'static str, body: Vec<u8>, slack: usize) -> Sec {
    Sec { name, body, slack }
}

/// Builds a PE image. `header_gap` is the zero gap between the section table
/// and the first section's raw data (`None` → tight, no gap).
fn build_pe(machine: u16, opt_magic: u16, secs: &[Sec], header_gap: Option<usize>) -> Vec<u8> {
    assert!(!secs.is_empty());
    let is_pe32p = opt_magic == 0x20B;
    let opt_size: u16 = if is_pe32p { 240 } else { 224 };
    let e_lfanew: u32 = 0x80;
    let sec_table = e_lfanew as usize + 24 + opt_size as usize;
    let sec_table_end = sec_table + 40 * secs.len();
    let raw_ptr0 = match header_gap {
        Some(gap) => align_up(sec_table_end + gap, 0x200),
        None => sec_table_end,
    };

    let mut img = vec![0u8; raw_ptr0];
    img[0..2].copy_from_slice(b"MZ");
    img[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    img[0x80..0x84].copy_from_slice(b"PE\0\0");
    img[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
    img[0x86..0x88].copy_from_slice(&(secs.len() as u16).to_le_bytes());
    img[0x94..0x96].copy_from_slice(&opt_size.to_le_bytes());
    img[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes()); // executable
    let opt = 0x98;
    img[opt..opt + 2].copy_from_slice(&opt_magic.to_le_bytes());

    let mut raw_ptr = raw_ptr0;
    let mut vaddr = 0x1000usize;
    for (i, s) in secs.iter().enumerate() {
        let sec_hdr = sec_table + i * 40;
        let mut name = [0u8; 8];
        name[..s.name.len()].copy_from_slice(s.name.as_bytes());
        img[sec_hdr..sec_hdr + 8].copy_from_slice(&name);
        let vsize = s.body.len();
        let raw_size = align_up(vsize + s.slack, 0x200);
        img[sec_hdr + 8..sec_hdr + 12].copy_from_slice(&(vsize as u32).to_le_bytes());
        img[sec_hdr + 12..sec_hdr + 16].copy_from_slice(&(vaddr as u32).to_le_bytes());
        img[sec_hdr + 16..sec_hdr + 20].copy_from_slice(&(raw_size as u32).to_le_bytes());
        img[sec_hdr + 20..sec_hdr + 24].copy_from_slice(&(raw_ptr as u32).to_le_bytes());
        let characteristics: u32 = if s.name == ".text" {
            0x6000_0020 // code | execute | read
        } else {
            0x4000_0040 // initialized data | read
        };
        img[sec_hdr + 36..sec_hdr + 40].copy_from_slice(&characteristics.to_le_bytes());

        img.resize(raw_ptr + raw_size, 0);
        img[raw_ptr..raw_ptr + vsize].copy_from_slice(&s.body);
        raw_ptr += raw_size;
        vaddr += align_up(vsize.max(1), 0x1000);
    }
    img
}

/// A carrier with a small `.text` (too few instructions for the code-bit
/// channel) but generous header padding, so `auto` must pick pe_slack.
fn slack_carrier() -> Vec<u8> {
    build_pe(
        0x8664,
        0x20B,
        &[sec(".text", text_body(0x40), 0x400)],
        Some(0x200),
    )
}

/// Builds a PE image with explicit section geometry, including overlapping and
/// zero-`VirtualSize` sections that the sequential builder above cannot express.
/// `secs` is `(name, virtual_size, size_of_raw_data, pointer_to_raw_data, body)`.
fn build_pe_raw(machine: u16, opt_magic: u16, secs: &[(&str, u32, u32, u32, Vec<u8>)]) -> Vec<u8> {
    let opt_size: u16 = if opt_magic == 0x20B { 240 } else { 224 };
    let e_lfanew: u32 = 0x80;
    let sec_table = e_lfanew as usize + 24 + opt_size as usize;
    let mut file_len = sec_table + 40 * secs.len();
    for (_, _, rawsize, rawptr, _) in secs {
        file_len = file_len.max(*rawptr as usize + *rawsize as usize);
    }

    let mut img = vec![0u8; file_len];
    img[0..2].copy_from_slice(b"MZ");
    img[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    img[0x80..0x84].copy_from_slice(b"PE\0\0");
    img[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
    img[0x86..0x88].copy_from_slice(&(secs.len() as u16).to_le_bytes());
    img[0x94..0x96].copy_from_slice(&opt_size.to_le_bytes());
    img[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes());
    img[0x98..0x9A].copy_from_slice(&opt_magic.to_le_bytes());

    for (i, (name, vsize, rawsize, rawptr, body)) in secs.iter().enumerate() {
        let hdr = sec_table + i * 40;
        let mut nm = [0u8; 8];
        nm[..name.len()].copy_from_slice(name.as_bytes());
        img[hdr..hdr + 8].copy_from_slice(&nm);
        img[hdr + 8..hdr + 12].copy_from_slice(&vsize.to_le_bytes());
        img[hdr + 12..hdr + 16].copy_from_slice(&(0x1000u32 * (i as u32 + 1)).to_le_bytes());
        img[hdr + 16..hdr + 20].copy_from_slice(&rawsize.to_le_bytes());
        img[hdr + 20..hdr + 24].copy_from_slice(&rawptr.to_le_bytes());
        img[hdr + 36..hdr + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        let at = *rawptr as usize;
        img[at..at + body.len()].copy_from_slice(body);
    }
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

fn slack_ranges(data: &[u8]) -> Vec<(u64, u64)> {
    let mut cur = Cursor::new(data);
    pe_codebits::parse_slack_layout_streaming(&mut cur)
        .expect("pe slack layout")
        .slack_ranges
}

// --------------------------------------------------------------------------- tests

/// T1: `auto` prefers pe_slack when the instruction channel cannot fit, the
/// file size is unchanged, and remove restores the carrier byte-for-byte.
#[test]
fn auto_prefers_slack_and_restores_bit_exact() {
    let dir = scratch("auto");
    let original = slack_carrier();
    let carrier = dir.join("app.exe");
    fs::write(&carrier, &original).unwrap();
    let orig_sha = sha256_hex(&original);

    let out = dir.join("app.steg.exe");
    let res = write_carrier(
        &carrier,
        PayloadSource::Text("meet at the old bridge, 9pm"),
        &write_opts(&out, "auto"),
    )
    .expect("write");
    assert_eq!(
        res.strategy, "pe_slack",
        "auto must pick pe_slack here: {:?}",
        res.strategy_note
    );
    assert_eq!(
        fs::metadata(&out).unwrap().len(),
        original.len() as u64,
        "pe_slack must not change the file size"
    );

    let read = read_carrier(&out, None, None).expect("read");
    assert_eq!(read.data, b"meet at the old bridge, 9pm");

    let ins = inspect_carrier(&out, None).expect("inspect");
    assert!(ins.has_hidden_data);
    assert_eq!(ins.strategy.as_deref(), Some("pe_slack"));

    let v = verify_carrier(&out, None).expect("verify");
    assert!(v.level1_host.ok, "L1: {}", v.level1_host.detail);
    assert!(v.level2_envelope.ok, "L2: {}", v.level2_envelope.detail);
    assert!(v.level3_crypto.ok, "L3: {}", v.level3_crypto.detail);

    let restored = dir.join("app.restored.exe");
    let rem = remove_carrier(&out, Some(&restored), None, false).expect("remove");
    assert!(rem.verified_identical);
    assert_eq!(
        restored_sha(&restored),
        orig_sha,
        "restore must be bit-exact"
    );

    // Re-writing the restored carrier works again (idempotent lifecycle).
    let out2 = dir.join("app2.steg.exe");
    let again = write_carrier(
        &restored,
        PayloadSource::Text("again"),
        &write_opts(&out2, "auto"),
    )
    .expect("re-write after remove");
    assert_eq!(again.strategy, "pe_slack");
}

fn restored_sha(path: &Path) -> String {
    sha256_hex(&fs::read(path).unwrap())
}

/// T2: `auto` keeps pe_codebits ahead of pe_slack when both are usable.
#[test]
fn auto_prefers_codebits_over_slack() {
    let dir = scratch("priority");
    let carrier = dir.join("big.exe");
    fs::write(
        &carrier,
        build_pe(
            0x8664,
            0x20B,
            &[sec(".text", text_body(0x3000), 0x400)],
            Some(0x200),
        ),
    )
    .unwrap();

    let out = dir.join("big.steg.exe");
    let res = write_carrier(
        &carrier,
        PayloadSource::Text("priority check"),
        &write_opts(&out, "auto"),
    )
    .expect("write");
    assert_eq!(
        res.strategy, "pe_codebits",
        "auto order is codebits -> slack -> overlay"
    );
}

/// T3: nothing but padding bytes may change, and they must all be inside the
/// advertised padding ranges.
#[test]
fn slack_only_rewrites_padding_bytes() {
    let dir = scratch("footprint");
    let original = slack_carrier();
    let carrier = dir.join("fp.exe");
    fs::write(&carrier, &original).unwrap();
    let ranges = slack_ranges(&original);
    assert!(!ranges.is_empty());

    let out = dir.join("fp.steg.exe");
    let res = write_carrier(
        &carrier,
        PayloadSource::Text("footprint"),
        &write_opts(&out, "pe_slack"),
    )
    .expect("write");

    let stego = fs::read(&out).unwrap();
    assert_eq!(stego.len(), original.len(), "size must not change");
    let mut diffs = 0usize;
    for (i, (a, b)) in stego.iter().zip(original.iter()).enumerate() {
        if a != b {
            diffs += 1;
            let off = i as u64;
            assert!(
                ranges.iter().any(|&(s, e)| off >= s && off < e),
                "byte at offset {off:#x} changed outside the padding ({ranges:?})"
            );
        }
    }
    assert!(diffs > 0, "the envelope must change something");
    assert!(
        diffs as u64 <= res.ube_size,
        "at most the envelope size may change ({diffs} > {})",
        res.ube_size
    );
}

/// T4: an explicit pe_slack request on a padding-free PE fails loudly instead
/// of silently falling back.
#[test]
fn explicit_slack_rejects_padding_free_carriers() {
    let dir = scratch("reject");
    let carrier = dir.join("tight.exe");
    // `.text` exactly fills its raw size and starts right after the table.
    fs::write(
        &carrier,
        build_pe(0x8664, 0x20B, &[sec(".text", text_body(0x200), 0)], None),
    )
    .unwrap();

    let out = dir.join("tight.steg.exe");
    let err = write_carrier(
        &carrier,
        PayloadSource::Text("hi"),
        &write_opts(&out, "pe_slack"),
    )
    .unwrap_err();
    assert!(
        matches!(err, StrHideError::UnsupportedFormat(_)),
        "expected UnsupportedFormat, got {err:?}"
    );
    assert!(
        err.to_string().contains("pe_slack"),
        "error must name the strategy: {err}"
    );
    assert!(!out.exists(), "no output must be produced");
}

/// T5: the padding envelope works for a non-x86 PE (ARM64), which the
/// instruction channel cannot serve at all.
#[test]
fn arm64_pe_uses_padding() {
    let dir = scratch("arm64");
    let original = build_pe(
        0xAA64, // ARM64
        0x20B,
        &[
            sec(".text", vec![0x1F, 0x20, 0x03, 0xD5], 0x600),
            sec(".rdata", vec![0xAA; 0x180], 0x200),
        ],
        Some(0x200),
    );
    let carrier = dir.join("arm64.exe");
    fs::write(&carrier, &original).unwrap();

    let out = dir.join("arm64.steg.exe");
    let res = write_carrier(
        &carrier,
        PayloadSource::Text("arm64 secret"),
        &write_opts(&out, "auto"),
    )
    .expect("write");
    assert_eq!(res.strategy, "pe_slack", "codebits cannot serve ARM64");
    assert_eq!(fs::metadata(&out).unwrap().len(), original.len() as u64);

    let read = read_carrier(&out, None, None).expect("read");
    assert_eq!(read.data, b"arm64 secret");

    let restored = dir.join("arm64.restored.exe");
    let rem = remove_carrier(&out, Some(&restored), None, false).expect("remove");
    assert!(rem.verified_identical);
    assert_eq!(fs::read(&restored).unwrap(), original);
}

/// T6: encryption + wrong password, and a byte-exact restore with the right one.
#[test]
fn slack_encrypted_roundtrip() {
    let dir = scratch("enc");
    let original = slack_carrier();
    let carrier = dir.join("enc.exe");
    fs::write(&carrier, &original).unwrap();

    let out = dir.join("enc.steg.exe");
    let opts = WriteOptions {
        output_path: Some(&out),
        strategy: "pe_slack",
        password: Some("correct horse battery staple"),
        backup: false,
        ..Default::default()
    };
    write_carrier(&carrier, PayloadSource::Text("encrypted secret"), &opts).expect("write");

    assert!(read_carrier(&out, None, None).is_err(), "password required");
    assert!(read_carrier(&out, None, Some("wrong pw")).is_err());

    let read = read_carrier(&out, None, Some("correct horse battery staple")).expect("read");
    assert_eq!(read.data, b"encrypted secret");

    let restored = dir.join("enc.restored.exe");
    remove_carrier(
        &out,
        Some(&restored),
        Some("correct horse battery staple"),
        false,
    )
    .expect("remove");
    assert_eq!(fs::read(&restored).unwrap(), original);
}

/// T7: stealth — invisible without the password (plausible deniability), and
/// the structural scanner still hints that the padding is occupied.
#[test]
fn slack_stealth_denies_without_password() {
    let dir = scratch("stealth");
    let original = slack_carrier();
    let carrier = dir.join("s.exe");
    fs::write(&carrier, &original).unwrap();

    let out = dir.join("s.steg.exe");
    let opts = WriteOptions {
        output_path: Some(&out),
        strategy: "pe_slack",
        password: Some("stealth pw"),
        stealth: true,
        backup: false,
        ..Default::default()
    };
    write_carrier(&carrier, PayloadSource::Text("invisible"), &opts).expect("write");

    let err = read_carrier(&out, None, None).unwrap_err();
    assert!(
        matches!(err, StrHideError::NoHiddenData(_)),
        "expected NoHiddenData, got {err:?}"
    );
    assert!(
        err.to_string()
            .contains("non-zero bytes in PE section padding"),
        "the padding trace should be reported: {err}"
    );
    assert!(read_carrier(&out, None, Some("nope")).is_err());

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

/// T8: a second injection on a padding carrier is refused.
#[test]
fn double_write_refused() {
    let dir = scratch("double");
    let carrier = dir.join("d.exe");
    fs::write(&carrier, slack_carrier()).unwrap();

    let out = dir.join("d.steg.exe");
    write_carrier(
        &carrier,
        PayloadSource::Text("first"),
        &write_opts(&out, "pe_slack"),
    )
    .expect("first write");

    let out2 = dir.join("d.steg2.exe");
    let err = write_carrier(
        &out,
        PayloadSource::Text("second"),
        &write_opts(&out2, "auto"),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("already contains hidden data"),
        "{err}"
    );
}

/// T9: tampering with the ciphertext must fail cleanly on read, while the
/// restore stays bit-exact: `pe_slack` restores by zero-filling the padding the
/// header points at, so a damaged payload cannot corrupt the recovered carrier.
#[test]
fn tampered_envelope_fails_cleanly() {
    let dir = scratch("corrupt");
    let original = slack_carrier();
    let carrier = dir.join("c.exe");
    fs::write(&carrier, &original).unwrap();

    let out = dir.join("c.steg.exe");
    let res = write_carrier(
        &carrier,
        PayloadSource::Text("do not tamper"),
        &write_opts(&out, "pe_slack"),
    )
    .expect("write");

    // Flip a byte in the middle of the ciphertext (well past header and meta).
    let ins = inspect_carrier(&out, None).expect("inspect");
    let envelope_off = ins.ube_offset.expect("envelope offset") as usize;
    let mut bytes = fs::read(&out).unwrap();
    bytes[envelope_off + res.ube_size as usize / 2] ^= 0xFF;
    let tampered = dir.join("c.tampered.exe");
    fs::write(&tampered, &bytes).unwrap();

    assert!(
        read_carrier(&tampered, None, None).is_err(),
        "read must fail on tampered ciphertext"
    );
    let restored = dir.join("c.tampered.restored.exe");
    let rem = remove_carrier(&tampered, Some(&restored), None, false)
        .expect("restore must still succeed");
    assert!(rem.verified_identical);
    assert_eq!(
        fs::read(&restored).unwrap(),
        original,
        "the padding restore is independent of the damaged payload"
    );
}

/// T10: a header whose `inject_offset` points at section data must be refused,
/// so a corrupted envelope can never zero executable bytes.
#[test]
fn strip_refuses_ranges_outside_padding() {
    use strhide::adapters::HostAdapter;
    use strhide::adapters::pe::PeAdapter;

    let original = slack_carrier();
    let ranges = slack_ranges(&original);
    // The header gap ends exactly where `.text` raw data begins, so this offset
    // is section data — not padding.
    let text_start = ranges[0].1;
    assert!(
        !ranges
            .iter()
            .any(|&(a, b)| text_start >= a && text_start + 0x100 <= b),
        "the probe window must sit outside every padding range"
    );

    let header = EnvelopeHeader {
        strategy_id: 9, // pe_slack
        inject_offset: text_start,
        inject_size: 0x100,
        ..Default::default()
    };

    let mut stego = Cursor::new(original);
    let mut out = Cursor::new(Vec::new());
    let err = PeAdapter
        .strip(&mut stego, &mut out, &header)
        .expect_err("strip must refuse to zero non-padding bytes");
    assert!(
        matches!(err, StrHideError::CorruptedData(_)),
        "expected CorruptedData, got {err:?}"
    );
    assert!(out.into_inner().is_empty(), "nothing must be written");
}

/// T11: `inspect` reports the measured padding capacity and keeps the
/// documented priority order.
#[test]
fn inspect_reports_padding_capacity() {
    let dir = scratch("capacity");
    let carrier = dir.join("cap.exe");
    fs::write(&carrier, slack_carrier()).unwrap();

    let res = inspect_carrier(&carrier, None).expect("inspect");
    let names: Vec<&str> = res.strategies.iter().map(|c| c.strategy.as_str()).collect();
    assert_eq!(
        names,
        vec!["pe_codebits", "pe_slack", "pe_overlay", "eof"],
        "priority order"
    );

    let pad = res
        .strategies
        .iter()
        .find(|c| c.strategy == "pe_slack")
        .expect("pe_slack capacity");
    let cap = pad.capacity_bytes.expect("measured");
    assert!(cap >= 178, "carrier must hold at least a bare envelope");
    assert!(pad.limit.contains("file size unchanged"));

    // The reported bound must admit a real write.
    let out = dir.join("cap.steg.exe");
    let written = write_carrier(
        &carrier,
        PayloadSource::Text("fits"),
        &write_opts(&out, "auto"),
    )
    .expect("write");
    assert!(
        written.ube_size <= cap,
        "envelope {} B exceeded reported capacity {cap} B",
        written.ube_size
    );
}

/// T14: padding candidates must never overlap another section's file-backed
/// bytes. Malformed/packed images do contain overlapping section tables; a
/// writer that trusted `raw_ptr + raw_size` blindly would corrupt them.
#[test]
fn overlapping_sections_are_never_offered_as_padding() {
    // `.data` declares raw [0x400, 0xC00) but only maps 0x100 bytes; `.text`
    // starts at 0x600, inside `.data`'s declared raw range.
    let img = build_pe_raw(
        0x8664,
        0x20B,
        &[
            (".data", 0x100, 0x800, 0x400, vec![0xCC; 0x100]),
            (".text", 0x400, 0x400, 0x600, vec![0x90; 0x400]),
        ],
    );
    let ranges = slack_ranges(&img);
    let text_span = (0x600u64, 0xA00u64);
    for &(a, b) in &ranges {
        assert!(
            b <= text_span.0 || a >= text_span.1,
            "padding range [{a:#x}, {b:#x}) overlaps .text data {text_span:?} (all: {ranges:?})"
        );
    }
    assert!(
        ranges.iter().any(|&(a, b)| a == 0x500 && b == 0x600),
        "the safe sub-range before .text must be offered: {ranges:?}"
    );
    assert!(
        ranges.iter().any(|&(a, b)| a == 0xA00 && b == 0xC00),
        "the safe sub-range after .text must be offered: {ranges:?}"
    );
}

/// T15: a section with `VirtualSize == 0` is ambiguous across loaders and must
/// never be used as padding.
#[test]
fn zero_virtual_size_section_is_not_padding() {
    let img = build_pe_raw(
        0x8664,
        0x20B,
        &[(".data", 0, 0x400, 0x400, vec![0xEE; 0x400])],
    );
    let ranges = slack_ranges(&img);
    assert!(
        ranges.iter().all(|&(a, b)| b <= 0x400 || a >= 0x800),
        "a zero-VirtualSize section's raw data must not be padding: {ranges:?}"
    );
}

/// T12: the strategy registry knows pe_slack (id 9) in both directions.
#[test]
fn strategy_registry_roundtrip() {
    use strhide::router::{id_to_strategy, strategy_to_id};
    assert_eq!(strategy_to_id("pe_slack"), 9);
    assert_eq!(id_to_strategy(9), "pe_slack");
}

/// T13: an envelope placed in the *last* section's padding ends exactly at EOF.
/// `locate` must still report `pe_slack` (not the generic EOF fallback), or
/// `inspect` would mislabel the carrier and remove would take the wrong path.
#[test]
fn envelope_ending_at_eof_is_still_reported_as_slack() {
    let dir = scratch("tail");

    // Step 1: measure the envelope size for the payload we are going to use.
    let probe = dir.join("probe.exe");
    fs::write(&probe, slack_carrier()).unwrap();
    let probe_out = dir.join("probe.steg.exe");
    let probed = write_carrier(
        &probe,
        PayloadSource::Text("tail placement"),
        &write_opts(&probe_out, "pe_slack"),
    )
    .expect("probe write");
    let ube_size = probed.ube_size as usize;

    // Step 2: build a carrier whose only zero run is exactly `ube_size` long
    // and ends at EOF (tight layout, `.text` sized so raw_size == vsize + N).
    let body_len = (0x200 - (ube_size % 0x200)) % 0x200;
    let body_len = if body_len == 0 { 0x200 } else { body_len };
    let original = build_pe(
        0x8664,
        0x20B,
        &[sec(".text", text_body(body_len), ube_size)],
        None,
    );
    let ranges = slack_ranges(&original);
    assert_eq!(ranges.len(), 1, "one tail range only: {ranges:?}");
    assert_eq!((ranges[0].1 - ranges[0].0) as usize, ube_size);

    let carrier = dir.join("tail.exe");
    fs::write(&carrier, &original).unwrap();
    let out = dir.join("tail.steg.exe");
    let res = write_carrier(
        &carrier,
        PayloadSource::Text("tail placement"),
        &write_opts(&out, "pe_slack"),
    )
    .expect("write");
    assert_eq!(res.ube_size as usize, ube_size);

    let stego_len = fs::metadata(&out).unwrap().len();
    let ins = inspect_carrier(&out, None).expect("inspect");
    assert_eq!(
        ins.strategy.as_deref(),
        Some("pe_slack"),
        "a padding envelope at EOF must not be reported as eof"
    );
    assert_eq!(
        ins.ube_offset.expect("offset") + res.ube_size,
        stego_len,
        "the envelope must end exactly at EOF"
    );

    let read = read_carrier(&out, None, None).expect("read");
    assert_eq!(read.data, b"tail placement");

    let restored = dir.join("tail.restored.exe");
    let rem = remove_carrier(&out, Some(&restored), None, false).expect("remove");
    assert!(rem.verified_identical);
    assert_eq!(fs::read(&restored).unwrap(), original);
}
