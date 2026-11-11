use super::*;

/// `inject_size` lives in the header but outside the AEAD's AAD, so a zero
/// in that field must not be read as "this is a scattered strategy". Before
/// the fix, any contiguous strategy (`eof`, `chunk`, `box_uuid`) with the
/// field flipped to 0 skipped Level 2 entirely and `verify` passed a carrier
/// whose coordinates disagreed with its body.
#[test]
fn zero_inject_size_only_exempts_pe_codebits() {
    let ube_total = 256u64;
    let file_len = 4096u64;

    let header = EnvelopeHeader {
        strategy_id: crate::structure::registry::strategy_to_id("eof").expect("eof id"),
        inject_offset: 0,
        offset_delta: 0,
        inject_size: 0,
        ..Default::default()
    };

    assert!(
        envelope_coordinates_agree(&header, "eof", 0, ube_total, file_len).is_err(),
        "a zeroed inject_size on a contiguous strategy must be rejected"
    );

    // `pe_codebits` is the one strategy that records 0/0 by construction.
    let header = EnvelopeHeader {
        strategy_id: crate::structure::registry::strategy_to_id("pe_codebits")
            .expect("codebits id"),
        ..header
    };
    assert!(
        envelope_coordinates_agree(&header, "pe_codebits", 0, ube_total, file_len).is_ok(),
        "the scattered strategy must still be exempt"
    );
}

/// An MKV `ebml_void` envelope moves when a remux resizes the Segment in
/// front of the appended Void block. `MkvAdapter::locate` resolves that
/// block from the tail precisely to survive the shift, so the coordinate
/// check must accept it — otherwise `read` succeeds while `verify`/`restore`
/// call the same carrier corrupt.
#[test]
fn ebml_void_tolerates_a_relocated_envelope() {
    let ube_total = 256u64;
    let file_len = 8192u64;
    let offset_delta = 3u8; // EBML Void ID + 2-byte VINT
    let header = EnvelopeHeader {
        strategy_id: crate::structure::registry::strategy_to_id("ebml_void").expect("id"),
        inject_offset: 4096,
        offset_delta,
        inject_size: ube_total + offset_delta as u64,
        ..Default::default()
    };

    let at_write_time = header.inject_offset + offset_delta as u64;
    assert!(
        envelope_coordinates_agree(&header, "ebml_void", at_write_time, ube_total, file_len)
            .is_ok(),
        "an unmoved envelope must pass unchanged"
    );

    let shifted = at_write_time + 100;
    assert!(
        envelope_coordinates_agree(&header, "ebml_void", shifted, ube_total, file_len).is_ok(),
        "a shifted ebml_void envelope must be accepted, not called corrupt"
    );
    let relocated = strip_coordinates_for_location(&header, shifted, "ebml_void")
        .expect("strip must follow the located position");
    assert_eq!(
        relocated.inject_offset,
        header.inject_offset + 100,
        "strip must be told where the envelope really is"
    );

    // A strategy anchored at write time keeps refusing the same shift.
    let anchored = EnvelopeHeader {
        strategy_id: crate::structure::registry::strategy_to_id("box_uuid").expect("id"),
        ..header.clone()
    };
    assert!(
        envelope_coordinates_agree(&anchored, "box_uuid", shifted, ube_total, file_len).is_err(),
        "box_uuid is pinned to its write-time offset"
    );
}
