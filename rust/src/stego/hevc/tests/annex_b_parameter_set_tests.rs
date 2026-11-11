use super::{active_parameter_sets, sample_prefix_has_inter};

#[test]
fn a_gop_only_sees_parameter_sets_that_precede_it() {
    let sets = vec![vec![0x40, 0x01], vec![0x42, 0x01], vec![0x44, 0x01]];
    // Container carriers apply every set up front.
    let all = active_parameter_sets(&sets, None, 0);
    assert_eq!(all.len(), 3);

    // Annex-B: the set ending at byte 10 is not visible to a GOP at byte 5,
    // while both earlier sets are.
    let ends = [10usize, 20, 90];
    assert_eq!(active_parameter_sets(&sets, Some(&ends), 5).len(), 0);
    assert_eq!(active_parameter_sets(&sets, Some(&ends), 10).len(), 1);
    assert_eq!(active_parameter_sets(&sets, Some(&ends), 90).len(), 3);
    // A mid-stream redefinition does not leak backwards.
    assert_eq!(active_parameter_sets(&sets, Some(&ends), 45).len(), 2);
}

#[test]
fn sample_prefix_classifies_slice_nal_types() {
    let mut sample = Vec::new();
    // length_size = 2, IRAP slice (type 19) then a trailing P slice (type 1).
    sample.extend_from_slice(&4u16.to_be_bytes());
    sample.extend_from_slice(&[19 << 1, 1, 0, 0]);
    sample.extend_from_slice(&4u16.to_be_bytes());
    sample.extend_from_slice(&[1 << 1, 1, 0, 0]);
    assert!(sample_prefix_has_inter(&sample, 2));

    // Only an IRAP slice is not an inter frame.
    let mut irap_only = Vec::new();
    irap_only.extend_from_slice(&4u16.to_be_bytes());
    irap_only.extend_from_slice(&[19 << 1, 1, 0, 0]);
    assert!(!sample_prefix_has_inter(&irap_only, 2));

    // A truncated final NAL simply ends the walk.
    let mut truncated = Vec::new();
    truncated.extend_from_slice(&4u16.to_be_bytes());
    truncated.extend_from_slice(&[19 << 1, 1]);
    assert!(!sample_prefix_has_inter(&truncated, 2));

    // Empty/garbage prefixes never panic.
    assert!(!sample_prefix_has_inter(&[], 4));
    assert!(!sample_prefix_has_inter(&[0u8; 4], 0));
    let mut huge = 0xFFFF_FFFFu32.to_be_bytes().to_vec();
    huge.push(0);
    assert!(!sample_prefix_has_inter(&huge, 4));
}
