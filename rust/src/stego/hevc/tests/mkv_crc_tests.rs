use super::*;
use crate::stego::format::DEFAULT_HEVC_FORMAT;
use crate::stego::hevc::mkv_boxes::parse_mkv_targets;

/// Count checksums `parse_mkv_targets` accepts as consistent. A patched
/// cluster whose CRC was left stale is no longer recognised, so the count
/// drops when a caller skips the refresh.
fn valid_crc_count(bytes: &[u8]) -> usize {
    parse_mkv_targets(bytes)
        .expect("parse Matroska")
        .crcs
        .iter()
        .filter(|crc| crc.endian.is_some())
        .count()
}

/// A caller that writes MKV through the library entry point, not
/// `MkvEngine`, must still get a file whose Matroska CRC-32 elements match.
/// The refresh lives in `embed_hevc_with_info_v4` so both paths share it.
#[test]
fn library_embed_refreshes_mkv_crcs() {
    let path = "../temp/videosamples/TEST2__hevc_mkv_1080.mkv";
    if !std::path::Path::new(path).exists() {
        return;
    }
    let carrier = std::fs::read(path).expect("read MKV sample");
    assert!(
        !parse_mkv_targets(&carrier)
            .expect("parse Matroska")
            .crcs
            .is_empty(),
        "sample must carry CRC-32 elements"
    );
    let before = valid_crc_count(&carrier);
    assert!(
        before > 0,
        "sample must have a consistent CRC-32 to compare"
    );

    let (out, _, _) = embed_hevc_with_info(
        &carrier,
        &Payload::bytes(b"mkv-crc"),
        Some("mkv-crc-pw"),
        None,
        &DEFAULT_HEVC_FORMAT,
        Freshness::Random,
        SafetyPolicy::new(),
        &Control::none(),
    )
    .expect("library embed");

    assert_eq!(out.len(), carrier.len(), "patch embed keeps the length");
    assert_eq!(valid_crc_count(&out), before, "CRC-32 refreshed");
}
