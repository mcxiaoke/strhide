use super::*;

#[test]
fn writer_window_never_drops_below_the_reader_pool() {
    let hdr = hevc_header_slots(0);
    // Even with no body at all the window must cover the reader's pool.
    assert_eq!(hevc_window_target_slots(hdr, 0), HEVC_SUPERBLOCK_POOL_SLOTS);
    // A body larger than the pool keeps its own demand.
    assert_eq!(hevc_window_target_slots(hdr, 4096), hdr + 4096 + 128);
}

/// A multi-picture carrier where one picture is smaller than the reader
/// pool: without the floor, `TargetSlots(652)` stops after the first
/// picture (~650 slots) and places the header over a 650-slot permutation,
/// while extraction scans 2048 slots and reads nothing.
#[test]
fn write_and_read_record_the_same_pool_for_a_multipicture_carrier() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/assets/tiny40.hevc");
    let frame = std::fs::read(&path).expect("read tiny40.hevc");
    let mut carrier = Vec::new();
    for _ in 0..64 {
        carrier.extend_from_slice(&frame);
    }
    let kind = sniff_hevc_carrier(&carrier).expect("annex-b carrier");
    let target = hevc_window_target_slots(hevc_header_slots(0), 0);
    let write = record_carrier_state(
        &carrier,
        kind,
        Capture::Full,
        StopCondition::TargetSlots(target),
        &Control::none(),
    )
    .expect("write record");
    let read = record_carrier_state(
        &carrier,
        kind,
        Capture::Bits,
        StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
        &Control::none(),
    )
    .expect("read record");
    assert_eq!(
        write.total_slots().min(HEVC_SUPERBLOCK_POOL_SLOTS),
        read.total_slots().min(HEVC_SUPERBLOCK_POOL_SLOTS),
        "writer and reader must derive the header permutation from the same pool"
    );
}

/// The header read stops scanning at the first slice that crosses the pool
/// threshold. `slot_budget` lets a GOP stop decoding there instead of
/// decoding every slice of its wave; the resulting pool must be byte-for-byte
/// the same one a `TargetSlots` window records.
#[test]
fn header_read_and_target_window_record_the_same_pool() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/assets/tiny40.hevc");
    let frame = std::fs::read(&path).expect("read tiny40.hevc");
    let mut carrier = Vec::new();
    for _ in 0..64 {
        carrier.extend_from_slice(&frame);
    }
    let kind = sniff_hevc_carrier(&carrier).expect("annex-b carrier");
    let read = record_carrier_state(
        &carrier,
        kind,
        Capture::Bits,
        StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
        &Control::none(),
    )
    .expect("header record");
    let window = record_carrier_state(
        &carrier,
        kind,
        Capture::Bits,
        StopCondition::TargetSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
        &Control::none(),
    )
    .expect("window record");
    assert_eq!(read.total_slots(), window.total_slots());
    assert_eq!(read.slice_slot_ranges, window.slice_slot_ranges);
    assert_eq!(read.raw_bits, window.raw_bits);
    assert!(
        read.total_slots() >= HEVC_SUPERBLOCK_POOL_SLOTS,
        "fixture must cross the header pool so the stop path is exercised"
    );
    let last = read
        .slice_slot_ranges
        .last()
        .expect("non-empty recording")
        .0;
    let before_last = read.total_slots() - last;
    assert!(
        before_last < HEVC_SUPERBLOCK_POOL_SLOTS,
        "the read must stop at the crossing slice: {before_last} slots before the last one"
    );
}
