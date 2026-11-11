//! Carrier recording: one decode pass that fills the slot pool.
//!
//! Wraps [`super::scan`]' decoder so callers ask for "record this carrier" and
//! get every artefact the pipelines need, with the capture level deciding cost.

use rayon::prelude::*;

use crate::core::control::{Control, Event, Stage};
use crate::errors::StrHideError;
use crate::stego::hevc::slot::RecordMode;
use crate::stego::hevc::sniff::{HevcCarrierKind, sniff_hevc_carrier};

use super::layout::{CarrierLayout, EMBED_WINDOW_GOPS, parse_carrier_layout};
use super::scan::{
    Capture, CarrierRecord, GopSliceRecord, SlotSink, active_parameter_sets, count_pictures,
    decode_gop_slice_range, estimate_gops_for_slices, find_gop_ranges, is_irap, merge_gop_record,
};
use super::support::StopCondition;

pub(super) fn record_carrier_state(
    carrier: &[u8],
    kind: HevcCarrierKind,
    capture: Capture,
    stop: StopCondition,
    control: &Control<'_>,
) -> Result<CarrierRecord, StrHideError> {
    record_carrier_state_inner(carrier, kind, capture, stop, control, false)
}

/// Like [`record_carrier_state`], but when a `TargetSlots` window stops early
/// the remaining GOPs are decoded once more in slot-only mode and counted, so
/// the whole-carrier capacity needs no second pass. The capacity is exact:
/// slot counts do not depend on the capture level.
pub(super) fn record_carrier_state_with_capacity(
    carrier: &[u8],
    kind: HevcCarrierKind,
    capture: Capture,
    stop: StopCondition,
    control: &Control<'_>,
) -> Result<CarrierRecord, StrHideError> {
    record_carrier_state_inner(carrier, kind, capture, stop, control, true)
}

fn record_carrier_state_inner(
    carrier: &[u8],
    kind: HevcCarrierKind,
    capture: Capture,
    stop: StopCondition,
    control: &Control<'_>,
    count_after_stop: bool,
) -> Result<CarrierRecord, StrHideError> {
    let count_remaining = count_after_stop && matches!(stop, StopCondition::TargetSlots(_));
    let mode = if capture == Capture::Full {
        RecordMode::Embed
    } else {
        RecordMode::Slots
    };

    let CarrierLayout {
        candidates,
        parameter_sets,
        ps_end_offsets,
        digest_inputs,
    } = parse_carrier_layout(carrier, kind)?;

    let has_inter = candidates.iter().any(|c| !is_irap(c.nal_type));

    let (pictures, band_pictures) = if capture == Capture::Bits {
        (1, [1, 0])
    } else {
        count_pictures(carrier, kind, &candidates, has_inter)
    };

    let gop_ranges = find_gop_ranges(carrier, &candidates);
    let total_slices = candidates.len();
    control.stage_sized(Stage::Decode, total_slices as u64);

    let mut global_sink = SlotSink::new(capture);
    let mut global_slice_contexts = Vec::new();
    let mut global_recorded_slices = 0usize;
    let mut decode_error: Option<String> = None;
    // Whole-carrier counts, filled from every GOP the window pass completes and
    // then from the slot-only continuation after the window stops.
    let mut capacity_counts = count_remaining.then_some([0usize; 2]);
    let mut counting_remaining = false;
    let mut reported_gops = 0usize;

    let mut gop_idx = 0;
    // A payload that fits in one GOP must not pay for sixteen: start at one and
    // double until the window batch is reached. `capacity --exact` (All) keeps
    // its fixed 32 and never ramps.
    let mut batch_cap = 1usize;
    while gop_idx < gop_ranges.len() {
        control.check()?;
        if counting_remaining {
            // The write window is complete; decode the rest slot-only. The
            // first GOP here is the one the window truncated (or completed on
            // its last slice), so decoding it again keeps the count exact.
            let end_idx = (gop_idx + 32).min(gop_ranges.len());
            let batch_ranges = &gop_ranges[gop_idx..end_idx];
            let batch_results: Vec<Result<GopSliceRecord, String>> = batch_ranges
                .par_iter()
                .map(|range| {
                    let gop_start_byte = candidates
                        .get(range.start)
                        .map_or(0, |cand| cand.span.start);
                    let active_sets = active_parameter_sets(
                        &parameter_sets,
                        ps_end_offsets.as_deref(),
                        gop_start_byte,
                    );
                    decode_gop_slice_range(
                        carrier,
                        &candidates[range.clone()],
                        &active_sets,
                        has_inter,
                        RecordMode::Slots,
                        Capture::Count,
                        None,
                    )
                })
                .collect();
            for gop_res in batch_results {
                if let Ok(gop) = gop_res
                    && let Some(counts) = capacity_counts.as_mut()
                {
                    counts[0] += gop.sink.counts[0];
                    counts[1] += gop.sink.counts[1];
                }
            }
            if end_idx > reported_gops {
                reported_gops = end_idx;
                control.report(Event::progress(
                    Stage::Decode,
                    gop_ranges[..end_idx].iter().map(|r| r.len()).sum::<usize>() as u64,
                    Some(total_slices as u64),
                ));
            }
            gop_idx = end_idx;
            continue;
        }
        let batch_size = match stop {
            StopCondition::All => 32,
            StopCondition::MinSlots(min) => {
                if min <= 2048 {
                    1
                } else {
                    16
                }
            }
            StopCondition::TargetSlices(target_slices) => {
                let needed = target_slices.saturating_sub(global_recorded_slices);
                let est_gops = estimate_gops_for_slices(
                    &gop_ranges[gop_idx..],
                    &candidates,
                    has_inter,
                    needed,
                );
                est_gops.clamp(1, 48)
            }
            StopCondition::TargetSlots(_) => batch_cap,
        };

        let end_idx = (gop_idx + batch_size).min(gop_ranges.len());
        let batch_ranges = &gop_ranges[gop_idx..end_idx];

        // Slots still missing before the window can stop. Every GOP in the
        // batch may record up to this; a GOP that reaches it stops decoding,
        // and the merge truncates to the exact slice either way.
        let slot_budget = match stop {
            StopCondition::TargetSlots(target) => Some(
                target
                    .saturating_sub(global_sink.counts[0] + global_sink.counts[1])
                    .max(1),
            ),
            // The header read (`MinSlots`) needs only the pool prefix; without a
            // budget every GOP in the wave decodes all of its slices, even though
            // the first slice already crosses the threshold. The budget makes the
            // GOP stop at exactly the slice where the outer merge would truncate,
            // so the recorded pool is unchanged.
            StopCondition::MinSlots(min) => Some(
                min.saturating_sub(global_sink.counts[0] + global_sink.counts[1])
                    .max(1),
            ),
            _ => None,
        };

        let batch_results: Vec<Result<GopSliceRecord, String>> = batch_ranges
            .par_iter()
            .map(|range| {
                let gop_start_byte = candidates
                    .get(range.start)
                    .map_or(0, |cand| cand.span.start);
                let active_sets = active_parameter_sets(
                    &parameter_sets,
                    ps_end_offsets.as_deref(),
                    gop_start_byte,
                );
                decode_gop_slice_range(
                    carrier,
                    &candidates[range.clone()],
                    &active_sets,
                    has_inter,
                    mode,
                    capture,
                    slot_budget,
                )
            })
            .collect();

        let mut finished = false;
        let mut resume_counting_at = None;
        for (batch_i, gop_res) in batch_results.into_iter().enumerate() {
            let mut gop = match gop_res {
                Ok(g) => g,
                Err(e) => {
                    decode_error.get_or_insert(e);
                    continue;
                }
            };
            if let Some(err) = gop.decode_error.take() {
                decode_error.get_or_insert(err);
            }
            let gop_counts = gop.sink.counts;

            let mut current_slots = global_sink.counts[0] + global_sink.counts[1];
            let mut current_slices = global_recorded_slices;
            let mut slices_to_take = gop.recorded_slices;
            let mut stop_now = false;

            for (idx, &(slot_cnt, _band)) in gop.sink.slice_slot_ranges.iter().enumerate() {
                current_slots += slot_cnt;
                current_slices += 1;
                let should_stop = match stop {
                    StopCondition::All => false,
                    StopCondition::MinSlots(min) => current_slots >= min,
                    StopCondition::TargetSlices(target_slices) => current_slices >= target_slices,
                    StopCondition::TargetSlots(target) => current_slots >= target,
                };
                if should_stop {
                    slices_to_take = idx + 1;
                    stop_now = true;
                    break;
                }
            }

            if slices_to_take < gop.recorded_slices {
                gop.truncate_to_slices(slices_to_take);
            }

            // A GOP that does not stop the window was decoded completely (the
            // slot budget only truncates the GOP that crosses the target), so
            // its counts belong to the whole-carrier capacity. The stopping GOP
            // is re-decoded in the counting phase instead of being counted
            // twice.
            if !stop_now && let Some(counts) = capacity_counts.as_mut() {
                counts[0] += gop_counts[0];
                counts[1] += gop_counts[1];
            }

            merge_gop_record(
                &mut global_sink,
                &mut global_slice_contexts,
                &mut global_recorded_slices,
                gop,
            );

            if stop_now {
                if capacity_counts.is_some() {
                    resume_counting_at = Some(gop_idx + batch_i);
                }
                finished = true;
                break;
            }
        }

        if end_idx > reported_gops {
            reported_gops = end_idx;
            control.report(Event::progress(
                Stage::Decode,
                gop_ranges[..end_idx].iter().map(|r| r.len()).sum::<usize>() as u64,
                Some(total_slices as u64),
            ));
        }

        if finished {
            if let Some(start) = resume_counting_at {
                counting_remaining = true;
                gop_idx = start;
                continue;
            }
            break;
        }
        if matches!(stop, StopCondition::TargetSlots(_)) {
            batch_cap = (batch_cap * 2).min(EMBED_WINDOW_GOPS);
        }
        gop_idx = end_idx;
    }

    if global_recorded_slices == 0
        && let Some(reason) = decode_error
    {
        return Err(StrHideError::UnsupportedFormat(format!(
            "HEVC carrier could not be decoded: {reason}"
        )));
    }

    let SlotSink {
        counts,
        band_bits,
        raw_bits,
        raw_slots,
        slice_slot_ranges,
        ..
    } = global_sink;
    let band0_len = counts[0];
    let total_slots = counts[0] + counts[1];

    let [band0_bits, band1_bits] = band_bits;
    let bands = vec![0..band0_len, band0_len..total_slots];

    Ok(CarrierRecord {
        slice_contexts: global_slice_contexts,
        all_slots: raw_slots,
        band_bits: [band0_bits.bytes, band1_bits.bytes],
        bands,
        pictures,
        band_pictures,
        digest_inputs,
        recorded_slices: global_recorded_slices,
        raw_bits: raw_bits.bytes,
        slice_slot_ranges,
        capacity_band_counts: capacity_counts,
    })
}
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct ScanStats {
    pub slices_scanned: usize,
    pub total_slots: usize,
    pub band0_slots: usize,
    pub band1_slots: usize,
    pub elapsed_micros: u64,
}

#[doc(hidden)]
pub fn bench_scan_slices(
    carrier: &[u8],
    slice_count: usize,
    full_capture: bool,
) -> Result<ScanStats, StrHideError> {
    let kind = sniff_hevc_carrier(carrier)
        .ok_or_else(|| StrHideError::UnsupportedFormat("Not HEVC carrier".into()))?;
    let capture = if full_capture {
        Capture::Full
    } else {
        Capture::Bits
    };
    let t0 = std::time::Instant::now();
    let record = record_carrier_state(
        carrier,
        kind,
        capture,
        StopCondition::TargetSlices(slice_count),
        &Control::none(),
    )?;
    let elapsed = t0.elapsed().as_micros() as u64;
    let band0 = record.bands.first().map_or(0, |r| r.len());
    let band1 = record.bands.get(1).map_or(0, |r| r.len());
    Ok(ScanStats {
        slices_scanned: record.slice_slot_ranges.len(),
        total_slots: band0 + band1,
        band0_slots: band0,
        band1_slots: band1,
        elapsed_micros: elapsed,
    })
}
