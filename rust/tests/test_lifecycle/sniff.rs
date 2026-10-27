//! Format-layer consistency: one classification, three consumers.
//!
//! [`strhide::formats::sniff`] is the single source of truth for "what file is
//! this?" and [`strhide::formats::capability`] for "what can be done with it?".
//! The structure domain still classifies through each adapter's own `detect`,
//! and `list` still renders its own tables, so those two must agree with the
//! format layer. These tests are the guard: they build one fixture per format
//! and assert the three views tell the same story.

use std::io::Cursor;

use strhide::formats::{FileFormat, capability_of, sniff_bytes, sniff_stream};
use strhide::router::{ADAPTERS, find_adapter};

use crate::common::*;

/// One synthetic carrier per container format, in `list` order.
fn cases() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("PNG", make_png()),
        ("JPEG", make_jpeg()),
        ("WEBP", make_webp()),
        ("HEIF", make_heif()),
        ("MP4", make_mp4()),
        ("WAV", make_wav()),
        ("ZIP", make_zip()),
        ("PDF", make_pdf()),
        ("PE", make_pe(256)),
        ("MKV", make_mkv()),
    ]
}

#[test]
fn sniff_bytes_agrees_with_the_router_for_every_format() {
    for (name, bytes) in cases() {
        let format = sniff_bytes(&bytes).unwrap_or_else(|| panic!("{name} not recognised"));
        assert_eq!(format.as_str(), name, "format layer name");

        // The stream entry point must agree and must leave the cursor alone.
        let mut cur = Cursor::new(bytes.clone());
        cur.set_position(7);
        assert_eq!(
            sniff_stream(&mut cur).expect("sniff_stream"),
            Some(format),
            "{name} via stream"
        );
        assert_eq!(
            cur.position(),
            7,
            "{name}: sniff_stream must restore the cursor"
        );

        // The structure domain's router must pick the same format.
        let adapter = find_adapter(&mut Cursor::new(bytes))
            .unwrap_or_else(|| panic!("{name} has no adapter"));
        assert_eq!(adapter.format_name(), name, "{name} router name");
        assert_eq!(
            FileFormat::from_adapter_name(adapter.format_name()),
            Some(format),
            "{name}: adapter name must round-trip through FileFormat"
        );
    }
}

#[test]
fn capability_table_matches_the_adapters() {
    for adapter in ADAPTERS {
        let name = adapter.format_name();
        if name == "GENERIC" {
            continue;
        }
        let format = FileFormat::from_adapter_name(name)
            .unwrap_or_else(|| panic!("{name} is missing from FileFormat"));
        let mut declared = capability_of(format).structure.to_vec();
        let mut implemented = adapter.supported_strategies();
        declared.sort_unstable();
        implemented.sort_unstable();
        assert_eq!(
            declared, implemented,
            "{name}: CAPABILITIES.structure must equal HostAdapter::supported_strategies"
        );
    }
}

#[test]
fn every_structure_capable_format_has_an_adapter() {
    for format in FileFormat::ALL {
        if !format.supports_structure() {
            continue;
        }
        let found = ADAPTERS
            .iter()
            .any(|a| a.format_name() == format.as_str() && a.format_name() != "GENERIC");
        assert!(
            found,
            "{format:?} claims structure support but has no adapter"
        );
    }
}

#[test]
fn raw_annexb_is_content_only() {
    // A VPS NAL after a 4-byte start code.
    let annexb = [0x00u8, 0x00, 0x00, 0x01, 32 << 1, 0x01, 0x00];
    assert_eq!(sniff_bytes(&annexb), Some(FileFormat::HevcAnnexB));
    assert!(!FileFormat::HevcAnnexB.supports_structure());
    assert!(FileFormat::HevcAnnexB.supports_stego());
    assert!(
        find_adapter(&mut Cursor::new(annexb.to_vec())).is_none(),
        "the router must keep rejecting raw bitstreams"
    );
}

#[test]
fn container_only_formats_are_rejected_by_the_content_domain() {
    for (name, bytes) in cases() {
        let format = sniff_bytes(&bytes).expect("recognised");
        if matches!(
            format,
            FileFormat::Zip
                | FileFormat::Pdf
                | FileFormat::Pe
                | FileFormat::Wav
                | FileFormat::Webp
                | FileFormat::Mkv
        ) {
            assert!(
                !format.supports_stego(),
                "{name} must not advertise content-domain support"
            );
        }
    }
}
