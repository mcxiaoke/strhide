use super::boxes::{patch_sized_uint, write_sized_uint};
use super::*;
use crate::structure::adapters::{HeifAdapter, HostAdapter};
use crate::structure::envelope::{EnvelopeHeader, STANDARD_TRAILER_MAGIC, TRAILER_SIZE};
use std::io::Cursor;

/// The 32-bit form tops out at `0xFFFFFFFF`; the value that exactly reaches
/// that bound must already use the 64-bit header, so no truncated size is
/// ever written.
#[test]
fn prefix_len_switches_to_the_large_header_at_the_u32_bound() {
    assert_eq!(calc_prefix_len(0), 24);
    assert_eq!(calc_prefix_len(1), 24);
    assert_eq!(calc_prefix_len(0xFFFF_FFE6), 24, "24 + it == 0xFFFFFFFE");
    assert_eq!(calc_prefix_len(0xFFFF_FFE7), 32, "24 + it == 0xFFFFFFFF");
    assert_eq!(calc_prefix_len(0xFFFF_FFE8), 32);
    assert_eq!(calc_prefix_len(u32::MAX as u64), 32);
    assert_eq!(calc_prefix_len(5 * 1024 * 1024 * 1024), 32);
}

/// `inject` and `envelope_offset_delta` must agree on the header length:
/// the writer places the envelope after `calc_prefix_len` bytes, and this
/// test pins the two together for both header forms.
#[test]
fn inject_writes_exactly_calc_prefix_len_header_bytes() {
    for ube_size in [0usize, 100, 4096] {
        let host = b"....ftypisom....mdat".to_vec();
        let ube = vec![0x5Au8; ube_size];
        let mut out = Vec::new();
        let (offset, size, _, _) = isobmff_inject(
            "MP4",
            &mut Cursor::new(host.clone()),
            &mut Cursor::new(ube.clone()),
            &mut out,
            "box_uuid",
        )
        .unwrap();

        let prefix = calc_prefix_len(ube_size as u64) as usize;
        assert_eq!(offset, host.len() as u64);
        assert_eq!(size, prefix as u64 + ube_size as u64);
        assert_eq!(out.len(), host.len() + prefix + ube_size);
        assert_eq!(
            &out[host.len() + prefix..],
            &ube[..],
            "envelope must start exactly after the header"
        );
        // 32-bit form: size field, 'uuid', usertype.
        assert_eq!(
            u32::from_be_bytes(out[host.len()..host.len() + 4].try_into().unwrap()) as usize,
            prefix + ube_size
        );
        assert_eq!(&out[host.len() + 4..host.len() + 8], b"uuid");
        assert_eq!(&out[host.len() + 8..host.len() + 24], &MP4_UUID_NEUTRAL);
    }
}

/// Build `host + 64-bit uuid box + envelope` by hand. The 64-bit form is
/// unreachable through `inject` without a 4 GiB payload, so the reader path
/// is exercised with a synthesised container whose declared `largesize`
/// matches the (small) envelope it actually carries.
///
/// `ube_data` is the envelope body without its 24-byte trailer; the trailer
/// emitted here records the same total size the large header declares.
fn synthesise_large_box_stego(host: &[u8], ube_data: &[u8]) -> Vec<u8> {
    let ube_offset = host.len() as u64 + 32;
    let ube_total = ube_data.len() as u64 + TRAILER_SIZE as u64;
    let mut out = host.to_vec();
    out.extend_from_slice(&1u32.to_be_bytes()); // size == 1
    out.extend_from_slice(b"uuid");
    out.extend_from_slice(&(32 + ube_total).to_be_bytes());
    out.extend_from_slice(&MP4_UUID_NEUTRAL);
    out.extend_from_slice(ube_data);
    out.extend_from_slice(
        &EnvelopeTrailer::create(ube_offset, ube_total, STANDARD_TRAILER_MAGIC).pack(),
    );
    out
}

#[test]
fn verify_rejects_a_forged_24_byte_trailer_tail() {
    // Any >= 24-byte file whose last 16 bytes say "offset 0, total = file
    // length" used to make L1 report a hidden envelope. The trailer magic
    // and CRC must also match before the tail is accepted.
    let mut forged = vec![0u8; TRAILER_SIZE];
    forged[8..16].copy_from_slice(&(TRAILER_SIZE as u64).to_le_bytes());
    forged[20..24].copy_from_slice(b"FAKE");
    let mut cursor = Cursor::new(forged);
    let (ok, detail) = isobmff_verify_structure("MP4", &mut cursor, None).unwrap();
    assert!(
        !ok,
        "a forged 24-byte tail must not verify as an envelope: {detail}"
    );
}

#[test]
fn locate_and_verify_accept_a_64_bit_box() {
    let host = b"\x00\x00\x00\x18ftypisom\x00\x00\x00\x00isomiso2".to_vec();
    let ube = vec![0xA5u8; 128];
    let stego = synthesise_large_box_stego(&host, &ube);

    let mut cursor = Cursor::new(stego.clone());
    let found = isobmff_locate(&mut cursor, None).unwrap();
    let (offset, size, strategy) = found.expect("64-bit box must be located");
    assert_eq!(strategy, "box_uuid");
    assert_eq!(offset, host.len() as u64 + 32);
    assert_eq!(size, ube.len() as u64 + 24);

    let mut cursor = Cursor::new(stego.clone());
    let (ok, detail) = isobmff_verify_structure("MP4", &mut cursor, None).unwrap();
    assert!(ok, "64-bit box container must verify: {detail}");

    let mut cursor = Cursor::new(stego);
    let warnings = isobmff_suspicious_structures(&mut cursor);
    assert!(
        warnings.iter().any(|w| w.contains("64-bit uuid box")),
        "structural scan must report the 64-bit box, got {warnings:?}"
    );
}

/// A 32-bit box in the same position must NOT be reported as 64-bit, and
/// vice versa: the two header shapes overlap in their first 24 bytes.
#[test]
fn suspicious_structures_distinguishes_the_two_header_forms() {
    let host = b"\x00\x00\x00\x18ftypisom\x00\x00\x00\x00isomiso2".to_vec();
    // At least HEADER_SIZE + TRAILER_SIZE: `isobmff_locate` refuses an
    // envelope shorter than that, which a real one never is.
    let ube = vec![0x11u8; 128];

    // 32-bit form
    let ube_offset = host.len() as u64 + 24;
    let ube_total = ube.len() as u64 + TRAILER_SIZE as u64;
    let mut stego = host.clone();
    stego.extend_from_slice(&((24 + ube_total) as u32).to_be_bytes());
    stego.extend_from_slice(b"uuid");
    stego.extend_from_slice(&MP4_UUID_NEUTRAL);
    stego.extend_from_slice(&ube);
    stego.extend_from_slice(
        &EnvelopeTrailer::create(ube_offset, ube_total, STANDARD_TRAILER_MAGIC).pack(),
    );

    let mut cursor = Cursor::new(stego.clone());
    let warnings = isobmff_suspicious_structures(&mut cursor);
    assert_eq!(warnings.len(), 1, "got {warnings:?}");
    assert!(warnings[0].contains("trailing uuid box"));
    assert!(!warnings[0].contains("64-bit"));

    let mut cursor = Cursor::new(stego);
    let (offset, _, strategy) = isobmff_locate(&mut cursor, None).unwrap().unwrap();
    assert_eq!(strategy, "box_uuid");
    assert_eq!(offset, ube_offset);
}

/// Verifies that truncated iloc boxes across all versions return Ok(false) without aborting.
#[test]
fn short_iloc_boxes_of_every_version_do_not_panic() {
    for len in 0..24usize {
        let mut box_bytes = vec![0u8; len];
        if len >= 9 {
            box_bytes[8] = 2; // version 2 wherever the byte exists
        }
        let _ = check_iloc_has_target(&box_bytes, 0, 0);
        if len >= 9 {
            box_bytes[8] = 0; // and version 0
        }
        let _ = check_iloc_has_target(&box_bytes, 0, 0);
    }
}

// ------------------------------------------------------------------
// Synthetic meta-HEIF hosts for the item_hidden iinf/iloc core.
//
// These are the only in-CI carriers that reach the iinf/iloc patch and
// restore code of the item_hidden strategy; the real-corpus lifecycle
// tests for that path are all `--ignored`.

/// `iinf` box (v0 with an infe v2 entry, or v1 with an infe v3 entry).
fn make_iinf(item_id: u32, infe_version: u8) -> Vec<u8> {
    let mut infe = Vec::new();
    if infe_version == 2 {
        infe.extend_from_slice(&21u32.to_be_bytes());
        infe.extend_from_slice(b"infe");
        infe.extend_from_slice(&[2, 0, 0, 0]);
        infe.extend_from_slice(&(item_id as u16).to_be_bytes());
        infe.extend_from_slice(&0u16.to_be_bytes()); // protection_index
        infe.extend_from_slice(b"hvc1");
        infe.push(0); // null-terminated item name
    } else {
        infe.extend_from_slice(&23u32.to_be_bytes());
        infe.extend_from_slice(b"infe");
        infe.extend_from_slice(&[3, 0, 0, 0]);
        infe.extend_from_slice(&item_id.to_be_bytes());
        infe.extend_from_slice(&0u16.to_be_bytes());
        infe.extend_from_slice(b"hvc1");
        infe.push(0);
    }
    let iinf_ver = if infe_version == 2 { 0u8 } else { 1u8 };
    let mut iinf = Vec::new();
    let count_sz = if iinf_ver == 0 { 2usize } else { 4 };
    iinf.extend_from_slice(&((12 + count_sz + infe.len()) as u32).to_be_bytes());
    iinf.extend_from_slice(b"iinf");
    iinf.extend_from_slice(&[iinf_ver, 0, 0, 0]);
    if iinf_ver == 0 {
        iinf.extend_from_slice(&1u16.to_be_bytes());
    } else {
        iinf.extend_from_slice(&1u32.to_be_bytes());
    }
    iinf.extend_from_slice(&infe);
    iinf
}

/// `iloc` v1 box (36 bytes): offset/length size 4, base size 4, one item
/// with one extent located through `base_offset`. `count_override` can
/// declare more items than the box actually holds.
fn make_iloc_box(count_override: Option<u16>) -> Vec<u8> {
    let mut iloc = Vec::new();
    iloc.extend_from_slice(&36u32.to_be_bytes());
    iloc.extend_from_slice(b"iloc");
    iloc.extend_from_slice(&[1, 0, 0, 0]); // version 1
    iloc.push(0x44); // offset_size=4, length_size=4
    iloc.push(0x40); // base_size=4, index_size=0
    iloc.extend_from_slice(&count_override.unwrap_or(1).to_be_bytes());
    iloc.extend_from_slice(&1u16.to_be_bytes()); // item_id
    iloc.extend_from_slice(&0u16.to_be_bytes()); // construction_method
    iloc.extend_from_slice(&0u16.to_be_bytes()); // data_reference_index
    iloc.extend_from_slice(&0u32.to_be_bytes()); // base_offset — patched below
    iloc.extend_from_slice(&1u16.to_be_bytes()); // extent_count
    iloc.extend_from_slice(&0u32.to_be_bytes()); // extent_offset
    iloc.extend_from_slice(&64u32.to_be_bytes()); // extent_length
    iloc
}

/// ftyp(24) + meta(fullbox: iinf + iloc) + mdat(64 bytes). The iloc item's
/// base_offset is patched to the absolute mdat payload position.
fn assemble_meta_heif(iinf: &[u8], iloc: &[u8]) -> Vec<u8> {
    let meta_len = 12 + iinf.len() + iloc.len();
    let mut out = Vec::new();
    out.extend_from_slice(&24u32.to_be_bytes());
    out.extend_from_slice(b"ftyp");
    out.extend_from_slice(b"mif1");
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(b"mif1heic");
    let mdat_pos = (24 + meta_len + 8) as u32;
    out.extend_from_slice(&(meta_len as u32).to_be_bytes());
    out.extend_from_slice(b"meta");
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(iinf);
    out.extend_from_slice(iloc);
    out.extend_from_slice(&(72u32.to_be_bytes()));
    out.extend_from_slice(b"mdat");
    out.resize(out.len() + 64, 0xC3);
    // base_offset field: meta starts at 24, iloc follows the 12-byte meta
    // header plus iinf, and sits 22 bytes into the iloc box.
    let base_pos = 24 + 12 + iinf.len() + 22;
    out[base_pos..base_pos + 4].copy_from_slice(&mdat_pos.to_be_bytes());
    out
}

/// ftyp(24) + mdat(72) + meta(fullbox: iinf + iloc). The media bytes come
/// *before* the metadata, which is legal ISOBMFF but was mishandled: every
/// iloc offset used to be shifted by `delta_meta` even though the item
/// itself never moved.
fn assemble_meta_heif_mdat_first(iinf: &[u8], iloc: &[u8]) -> Vec<u8> {
    let mdat_len = 72usize;
    let meta_off = 24 + mdat_len;
    let meta_len = 12 + iinf.len() + iloc.len();
    let mut out = Vec::new();
    out.extend_from_slice(&24u32.to_be_bytes());
    out.extend_from_slice(b"ftyp");
    out.extend_from_slice(b"mif1");
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(b"mif1heic");
    out.extend_from_slice(&(mdat_len as u32).to_be_bytes());
    out.extend_from_slice(b"mdat");
    out.resize(out.len() + mdat_len - 8, 0xC3);
    out.extend_from_slice(&(meta_len as u32).to_be_bytes());
    out.extend_from_slice(b"meta");
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(iinf);
    out.extend_from_slice(iloc);
    let mdat_payload: u32 = 24 + 8;
    let base_pos = meta_off + 12 + iinf.len() + 22;
    out[base_pos..base_pos + 4].copy_from_slice(&mdat_payload.to_be_bytes());
    out
}

fn synthetic_meta_heif(item_id: u32, infe_version: u8) -> Vec<u8> {
    let iinf = make_iinf(item_id, infe_version);
    let iloc = make_iloc_box(None);
    assemble_meta_heif(&iinf, &iloc)
}

/// Rewrite a normal box into the 16-byte `largesize` header form.
fn as_64_bit_box(box_bytes: &[u8]) -> Vec<u8> {
    let body = &box_bytes[8..];
    let mut out = Vec::new();
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&box_bytes[4..8]);
    out.extend_from_slice(&((16 + body.len()) as u64).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// `item_hidden` patches `iloc`/`iinf` at their 8-byte-header offsets; a
/// 64-bit header must be refused instead of silently mangled.
#[test]
fn item_hidden_inject_rejects_64_bit_iloc_and_iinf_headers() {
    let normal_iloc = make_iloc_box(None);
    let normal_iinf = make_iinf(1, 2);
    for (iloc, iinf) in [
        (as_64_bit_box(&normal_iloc), normal_iinf.clone()),
        (normal_iloc.clone(), as_64_bit_box(&normal_iinf)),
    ] {
        let host = assemble_meta_heif(&iinf, &iloc);
        let mut ube = vec![0x77u8; 200];
        ube.extend_from_slice(&EnvelopeTrailer::create(0, 224, STANDARD_TRAILER_MAGIC).pack());
        let err = isobmff_inject(
            "HEIF",
            &mut Cursor::new(host),
            &mut Cursor::new(ube),
            &mut Vec::new(),
            "item_hidden",
        )
        .unwrap_err();
        assert!(
            matches!(err, StrHideError::UnsupportedFormat(_)),
            "expected UnsupportedFormat, got: {err}"
        );
    }
}

#[test]
fn item_hidden_leaves_pre_meta_mdat_offsets_alone() {
    let iinf = make_iinf(1, 2);
    let iloc = make_iloc_box(None);
    let host = assemble_meta_heif_mdat_first(&iinf, &iloc);

    let delta_meta = 41u64;
    let inject_offset = host.len() as u64 + delta_meta;
    let ube_data_len = 200u64;
    let ube_total = ube_data_len + TRAILER_SIZE as u64;
    let mut ube = vec![0x77u8; ube_data_len as usize];
    ube.extend_from_slice(
        &EnvelopeTrailer::create(inject_offset + 8, ube_total, STANDARD_TRAILER_MAGIC).pack(),
    );

    let mut out = Vec::new();
    isobmff_inject(
        "HEIF",
        &mut Cursor::new(host.clone()),
        &mut Cursor::new(ube),
        &mut out,
        "item_hidden",
    )
    .unwrap();

    // meta starts after mdat and does not move, but the injected 21-byte
    // infe grows iinf and therefore shifts the iloc entries by one infe.
    let meta_off = 24 + 72;
    let base_pos = meta_off + 12 + iinf.len() + 21 + 22;
    let base = u32::from_be_bytes(out[base_pos..base_pos + 4].try_into().unwrap());
    assert_eq!(
        base, 32,
        "an item inside the pre-meta mdat must keep its absolute offset"
    );

    // ... and removal still restores the host byte-exactly.
    let header = EnvelopeHeader {
        strategy_id: 12,
        inject_offset,
        inject_size: 8 + ube_total,
        ..Default::default()
    };
    let mut restored = Cursor::new(Vec::new());
    isobmff_strip(&mut Cursor::new(out), &mut restored, &header).unwrap();
    assert_eq!(restored.into_inner(), host);
}

/// A legal but unusual encoding: `base_offset` lies *inside* `meta`
/// (12, the meta header) while the extent offset places the item data in
/// the following `mdat`. The base is not rewritten (it is inside the
/// untouched prefix), so the extent must be shifted or the item ends up
/// 41 bytes short after the meta grows.
#[test]
fn item_hidden_shifts_extents_when_the_base_offset_sits_inside_meta() {
    let iinf = make_iinf(1, 2);
    let iloc = make_iloc_box(None);
    let mut host = assemble_meta_heif(&iinf, &iloc);

    let meta_len = 12 + iinf.len() + iloc.len();
    let mdat_payload = (24 + meta_len + 8) as u32;
    let base: u32 = 12;
    let extent = mdat_payload - base;
    let base_pos = 24 + 12 + iinf.len() + 22;
    host[base_pos..base_pos + 4].copy_from_slice(&base.to_be_bytes());
    host[base_pos + 6..base_pos + 10].copy_from_slice(&extent.to_be_bytes());

    let delta_meta = 41u64;
    let inject_offset = host.len() as u64 + delta_meta;
    let ube_data_len = 200u64;
    let ube_total = ube_data_len + TRAILER_SIZE as u64;
    let mut ube = vec![0x77u8; ube_data_len as usize];
    ube.extend_from_slice(
        &EnvelopeTrailer::create(inject_offset + 8, ube_total, STANDARD_TRAILER_MAGIC).pack(),
    );

    let mut out = Vec::new();
    isobmff_inject(
        "HEIF",
        &mut Cursor::new(host.clone()),
        &mut Cursor::new(ube),
        &mut out,
        "item_hidden",
    )
    .unwrap();

    // iinf grew by a 21-byte infe, so the iloc base field (and the extent
    // fields after it) moved by that much inside the box.
    let base_pos = 24 + 12 + iinf.len() + 21 + 22;
    let new_base = u32::from_be_bytes(out[base_pos..base_pos + 4].try_into().unwrap());
    let new_extent = u32::from_be_bytes(out[base_pos + 6..base_pos + 10].try_into().unwrap());
    assert_eq!(new_base, base, "a base inside meta must stay put");
    assert_eq!(
        new_extent as u64,
        extent as u64 + delta_meta,
        "the extent must absorb the meta growth"
    );

    let header = EnvelopeHeader {
        strategy_id: 12,
        inject_offset,
        inject_size: 8 + ube_total,
        ..Default::default()
    };
    let mut restored = Cursor::new(Vec::new());
    isobmff_strip(&mut Cursor::new(out), &mut restored, &header).unwrap();
    assert_eq!(restored.into_inner(), host);
}

/// `inspect`, `auto` and the writer must agree: a 64-bit `meta` header is
/// refused by the writer, so the probe must not advertise `item_hidden`
/// for it.
#[test]
fn item_hidden_probe_rejects_a_64_bit_meta_header() {
    let host = synthetic_meta_heif(1, 2);
    let meta_len = u32::from_be_bytes(host[24..28].try_into().unwrap()) as usize;
    let mut wide = host[..24].to_vec();
    wide.extend_from_slice(&1u32.to_be_bytes());
    wide.extend_from_slice(b"meta");
    wide.extend_from_slice(&((meta_len + 8) as u64).to_be_bytes());
    wide.extend_from_slice(&host[32..24 + meta_len]);
    wide.extend_from_slice(&host[24 + meta_len..]);

    assert!(
        !isobmff_can_item_hidden(&mut Cursor::new(wide.clone())),
        "a 64-bit meta header cannot be rewritten in place"
    );
    assert_eq!(
        HeifAdapter.choose_auto_strategy(&mut Cursor::new(wide), 1024),
        "box_uuid"
    );
}

#[test]
fn item_hidden_roundtrips_on_a_synthetic_meta_heif() {
    let host = synthetic_meta_heif(1, 2);
    // Deterministic for this fixture: one 21-byte infe + one 20-byte iloc
    // entry appended to iinf/iloc.
    let delta_meta = 41u64;
    let inject_offset = host.len() as u64 + delta_meta;
    let ube_data_len = 200u64;
    let ube_total = ube_data_len + TRAILER_SIZE as u64;

    let mut ube = vec![0x77u8; ube_data_len as usize];
    ube.extend_from_slice(
        &EnvelopeTrailer::create(inject_offset + 8, ube_total, STANDARD_TRAILER_MAGIC).pack(),
    );

    let mut out = Vec::new();
    let (offset, size, patch_off, orig) = isobmff_inject(
        "HEIF",
        &mut Cursor::new(host.clone()),
        &mut Cursor::new(ube.clone()),
        &mut out,
        "item_hidden",
    )
    .unwrap();
    assert_eq!(offset, inject_offset);
    assert_eq!(size, 8 + ube_total);
    assert_eq!((patch_off, orig), (0, 0));

    let mut cur = Cursor::new(out.clone());
    let (lo, ls, strat) = isobmff_locate(&mut cur, None).unwrap().unwrap();
    assert_eq!(strat, "item_hidden");
    assert_eq!(
        lo,
        inject_offset + 8,
        "trailer records the mdat payload start"
    );
    assert_eq!(ls, ube_total);

    let mut cur = Cursor::new(out.clone());
    let (ok, detail) = isobmff_verify_structure("HEIF", &mut cur, None).unwrap();
    assert!(ok, "synthetic item_hidden stego must verify: {detail}");

    let header = EnvelopeHeader {
        strategy_id: 12,
        inject_offset: offset,
        inject_size: size,
        ..Default::default()
    };
    let mut restored = Cursor::new(Vec::new());
    isobmff_strip(&mut Cursor::new(out), &mut restored, &header).unwrap();
    assert_eq!(
        restored.into_inner(),
        host,
        "strip must restore the host byte-exactly"
    );
}

/// Verifies that ultra-short iloc boxes fail gracefully as CorruptedData rather than panicking.
#[test]
fn item_hidden_inject_rejects_an_ultra_short_iloc() {
    let iinf = make_iinf(1, 2);
    for (len, ver) in [
        (8usize, 1u8),
        (12, 1),
        (13, 1),
        (14, 0),
        (15, 1),
        (16, 2),
        (17, 2),
    ] {
        let mut iloc = vec![0u8; len];
        iloc[0..4].copy_from_slice(&(len as u32).to_be_bytes());
        iloc[4..8].copy_from_slice(b"iloc");
        if len > 8 {
            iloc[8] = ver;
        }
        let host = assemble_meta_heif(&iinf, &iloc);
        let err = isobmff_inject(
            "HEIF",
            &mut Cursor::new(host),
            &mut Cursor::new(vec![0u8; 224]),
            &mut Vec::new(),
            "item_hidden",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("Truncated iloc"),
            "iloc len {len} v{ver}: {err}"
        );
    }
}

/// Verifies that iloc item counts exceeding box boundaries are rejected by inject and strip walks.
#[test]
fn item_hidden_walks_reject_iloc_count_beyond_data() {
    let iinf = make_iinf(1, 2);
    let iloc = make_iloc_box(Some(2)); // declares 2 items, box holds 1

    let err = isobmff_inject(
        "HEIF",
        &mut Cursor::new(assemble_meta_heif(&iinf, &iloc)),
        &mut Cursor::new(vec![0u8; 224]),
        &mut Vec::new(),
        "item_hidden",
    )
    .unwrap_err();
    assert!(err.to_string().contains("Truncated iloc entry"), "{err}");

    // Strip side: take a valid stego and inflate the item count.
    let host = synthetic_meta_heif(1, 2);
    let mut stego = Vec::new();
    let (offset, size, _, _) = isobmff_inject(
        "HEIF",
        &mut Cursor::new(host),
        &mut Cursor::new(vec![0u8; 200]),
        &mut stego,
        "item_hidden",
    )
    .unwrap();
    // In the stego the iloc box sits after the grown iinf (one 21-byte
    // infe added); its 16-bit item count is 14 bytes into the box.
    let count_pos = 24 + 12 + 35 + 21 + 14;
    stego[count_pos..count_pos + 2].copy_from_slice(&5u16.to_be_bytes());
    let header = EnvelopeHeader {
        strategy_id: 12,
        inject_offset: offset,
        inject_size: size,
        ..Default::default()
    };
    let err = isobmff_strip(
        &mut Cursor::new(stego),
        &mut Cursor::new(Vec::new()),
        &header,
    )
    .unwrap_err();
    assert!(err.to_string().contains("Truncated iloc entry"), "{err}");
}

/// The declared item/extent counts are attacker-controlled. With all field
/// widths zero an extent iteration consumes no bytes, so 8,000 items x
/// 65,535 extents used to drive ~524 million iterations on a 64 KiB box.
/// The per-byte budget keeps the walk linear in the box size.
#[test]
fn iloc_with_absurd_counts_is_scanned_within_a_byte_budget() {
    const ITEMS: usize = 8_000;
    let mut iloc = vec![0u8; 16 + ITEMS * 8];
    let box_len = iloc.len() as u32;
    iloc[0..4].copy_from_slice(&box_len.to_be_bytes());
    iloc[4..8].copy_from_slice(b"iloc");
    iloc[8] = 1; // version 1
    iloc[12] = 0; // offset/length width 0
    iloc[13] = 0; // base/index width 0
    iloc[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    for i in 0..ITEMS {
        let at = 16 + i * 8;
        iloc[at..at + 2].copy_from_slice(&(i as u16).to_be_bytes());
        iloc[at + 6..at + 8].copy_from_slice(&u16::MAX.to_be_bytes());
    }

    let start = std::time::Instant::now();
    let found = check_iloc_has_target(&iloc, 1, 1).unwrap();
    let elapsed = start.elapsed();

    assert!(!found);
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "the iloc walk must be bounded by the box size, took {elapsed:?}"
    );
}

/// ISO/IEC 14496-12 allows a zero field width, which encodes the value 0
/// in no bytes. Writing or patching a non-zero value into such a field
/// would silently drop it, so both helpers must refuse.
#[test]
fn zero_width_iloc_fields_accept_only_the_implicit_zero() {
    let mut buf = Vec::new();
    write_sized_uint(&mut buf, 0, 0).unwrap();
    assert!(buf.is_empty());
    assert!(write_sized_uint(&mut buf, 1, 0).is_err());

    let mut buf = vec![0xAAu8; 8];
    patch_sized_uint(&mut buf, 0, 0, 0).unwrap();
    assert_eq!(buf, vec![0xAAu8; 8]);
    assert!(patch_sized_uint(&mut buf, 0, 0, 1).is_err());

    // Widths other than 0/4/8 stay unsupported.
    assert!(write_sized_uint(&mut buf, 0, 2).is_err());
    assert!(write_sized_uint(&mut buf, 0, 16).is_err());
}

/// Verifies that an infe entry declaring `item_id = u32::MAX` is safely rejected.
#[test]
fn item_hidden_inject_rejects_item_id_u32_max() {
    let host = synthetic_meta_heif(u32::MAX, 3);
    let err = isobmff_inject(
        "HEIF",
        &mut Cursor::new(host),
        &mut Cursor::new(vec![0u8; 224]),
        &mut Vec::new(),
        "item_hidden",
    )
    .unwrap_err();
    assert!(err.to_string().contains("item_id space exhausted"), "{err}");
}

/// Verifies that strip validates declared coordinates against physical layout before slicing.
#[test]
fn item_hidden_strip_rejects_forged_coordinates() {
    let host = synthetic_meta_heif(1, 2);
    let ube_total = 224u64;
    let mut stego = Vec::new();
    isobmff_inject(
        "HEIF",
        &mut Cursor::new(host),
        &mut Cursor::new(vec![0u8; 200]),
        &mut stego,
        "item_hidden",
    )
    .unwrap();

    // (a) inject_offset inside the meta box would slice start > end.
    let mut header = EnvelopeHeader {
        strategy_id: 12,
        inject_offset: 40, // meta spans 24..(24+meta_len)
        inject_size: stego.len() as u64 - 40,
        ..Default::default()
    };
    let err = isobmff_strip(
        &mut Cursor::new(stego.clone()),
        &mut Cursor::new(Vec::new()),
        &header,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("precedes the end of the meta box"),
        "{err}"
    );

    // (b) a size that does not run to the end of the file is equally forged.
    header.inject_offset = stego.len() as u64 - 8 - ube_total;
    header.inject_size = 8 + ube_total - 1;
    let err = isobmff_strip(
        &mut Cursor::new(stego),
        &mut Cursor::new(Vec::new()),
        &header,
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("does not match the stego file length"),
        "{err}"
    );
}

/// Records every byte handed to `read`, so a test can assert that the
/// `meta` probes skip a large box body instead of buffering the file.
struct ByteCounter {
    inner: Cursor<Vec<u8>>,
    read_bytes: usize,
}

impl std::io::Read for ByteCounter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.read_bytes += read;
        Ok(read)
    }
}

impl std::io::Seek for ByteCounter {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

fn box_bytes(tag: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&((8 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(tag);
    out.extend_from_slice(body);
    out
}

/// Verifies that meta box probes seek over preceding mdat boxes without whole-file buffering.
#[test]
fn meta_probes_seek_over_the_mdat_body() {
    let meta = {
        let mut body = vec![0u8; 4]; // version + flags
        // Empty but structurally valid iinf/iloc: version 0, zero entries,
        // and 4-byte offset/length/base field widths.
        body.extend_from_slice(&box_bytes(b"iinf", &[0, 0, 0, 0, 0, 0]));
        body.extend_from_slice(&box_bytes(b"iloc", &[0, 0, 0, 0, 0x44, 0x40, 0, 0]));
        box_bytes(b"meta", &body)
    };
    let mut file = box_bytes(b"ftyp", &[0u8; 16]);
    file.extend_from_slice(&box_bytes(b"mdat", &vec![0u8; 8 * 1024 * 1024]));
    file.extend_from_slice(&meta);
    let meta_len = meta.len();

    let mut counter = ByteCounter {
        inner: Cursor::new(file.clone()),
        read_bytes: 0,
    };
    assert!(isobmff_can_item_hidden(&mut counter));
    assert!(
        counter.read_bytes < meta_len + 64,
        "read {} bytes; a whole-prefix scan would read the 8 MiB mdat",
        counter.read_bytes
    );

    let mut counter = ByteCounter {
        inner: Cursor::new(file),
        read_bytes: 0,
    };
    assert!(!isobmff_has_iloc_item(&mut counter, 0, 0).unwrap());
    assert!(
        counter.read_bytes < meta_len + 64,
        "iloc probe read {} bytes",
        counter.read_bytes
    );
}
