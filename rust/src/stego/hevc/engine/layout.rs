//! Carrier layout: container spans, GOP boundaries and embed window sizing.
//!
//! Parsing lives here rather than next to the recorder because the peak-memory
//! estimator must see exactly the same spans the recorder will decode.

use crate::errors::StrHideError;
use crate::stego::SafetyPolicy;
use crate::stego::coding::StcTrellis;
use crate::stego::format::HevcFormatProfile;
use crate::stego::hevc::bitstream::parse_annex_b_spans;
use crate::stego::hevc::heif_boxes::parse_heif_targets;
use crate::stego::hevc::mkv_boxes::parse_mkv_targets;
use crate::stego::hevc::mp4_boxes::parse_mp4_targets;
use crate::stego::hevc::sniff::{HevcCarrierKind, sniff_hevc_carrier};

use super::scan::{
    CandidateSlice, DigestInputs, candidate_slice, find_gop_ranges, owned_parameter_sets,
};

/// Carrier bytes an embed keeps recorded at once, in groups of pictures.
///
/// `record_carrier_state` decodes a batch of this many GOPs and only then
/// merges it, checks the stopping condition and truncates the window. Every
/// slot, CABAC bin and RBSP in that batch is live at the same time, so this
/// constant — not the carrier size — sets the embed's memory peak.
pub(crate) const EMBED_WINDOW_GOPS: usize = 16;

/// Container facts `record_carrier_state` needs before it can decode.
///
/// Parsed once so the peak estimator and the recorder see exactly the same
/// slice spans and GOP boundaries; a second, cheaper parser would be free to
/// disagree with the one that decides where memory goes.
pub(super) struct CarrierLayout {
    pub(super) candidates: Vec<CandidateSlice>,
    pub(super) parameter_sets: Vec<Vec<u8>>,
    pub(super) ps_end_offsets: Option<Vec<usize>>,
    pub(super) digest_inputs: DigestInputs,
}

pub(super) fn parse_carrier_layout(
    carrier: &[u8],
    kind: HevcCarrierKind,
) -> Result<CarrierLayout, StrHideError> {
    let (candidates, parameter_sets, ps_end_offsets, digest_inputs) = match kind {
        HevcCarrierKind::HeifContainer => {
            let target = parse_heif_targets(carrier)
                .map_err(|e| StrHideError::UnsupportedFormat(format!("HEIF parse error: {e}")))?;
            let parameter_sets = owned_parameter_sets(&target.parameter_sets);
            let mut candidates = Vec::with_capacity(target.slice_spans.len());
            for span in &target.slice_spans {
                if let Some(cand) = candidate_slice(carrier, span.start..span.end()) {
                    candidates.push(cand);
                }
            }
            (
                candidates,
                parameter_sets.clone(),
                None,
                DigestInputs::ParameterSets { parameter_sets },
            )
        }
        HevcCarrierKind::Mp4Container => {
            let target = parse_mp4_targets(carrier).map_err(|e| {
                StrHideError::UnsupportedFormat(format!("MP4/MOV parse error: {e}"))
            })?;
            let parameter_sets = owned_parameter_sets(&target.parameter_sets);
            let mut candidates = Vec::with_capacity(target.slice_spans.len());
            for span in &target.slice_spans {
                if let Some(cand) = candidate_slice(carrier, span.start..span.end()) {
                    candidates.push(cand);
                }
            }
            (
                candidates,
                parameter_sets.clone(),
                None,
                DigestInputs::ParameterSets { parameter_sets },
            )
        }
        HevcCarrierKind::MkvContainer => {
            let target = parse_mkv_targets(carrier)
                .map_err(|e| StrHideError::UnsupportedFormat(format!("MKV parse error: {e}")))?;
            let parameter_sets = owned_parameter_sets(&target.parameter_sets);
            let mut candidates = Vec::with_capacity(target.slice_spans.len());
            for span in &target.slice_spans {
                if let Some(cand) = candidate_slice(carrier, span.start..span.end()) {
                    candidates.push(cand);
                }
            }
            (
                candidates,
                parameter_sets.clone(),
                None,
                DigestInputs::ParameterSets { parameter_sets },
            )
        }
        HevcCarrierKind::AnnexBStream => {
            let spans = parse_annex_b_spans(carrier);
            let mut parameter_sets = Vec::new();
            let mut ps_end_offsets = Vec::new();
            for span in &spans {
                if span.is_param_set() {
                    let end = span.end_offset().min(carrier.len());
                    parameter_sets.push(carrier[span.header_offset..end].to_vec());
                    ps_end_offsets.push(end);
                }
            }
            let mut candidates = Vec::new();
            for span in &spans {
                if !span.is_vcl() {
                    continue;
                }
                let range = span.header_offset..span.end_offset().min(carrier.len());
                if let Some(cand) = candidate_slice(carrier, range) {
                    candidates.push(cand);
                }
            }
            (
                candidates,
                parameter_sets,
                Some(ps_end_offsets),
                DigestInputs::AnnexB { spans },
            )
        }
    };
    Ok(CarrierLayout {
        candidates,
        parameter_sets,
        ps_end_offsets,
        digest_inputs,
    })
}

/// One batch's ceiling: the carrier bytes and group count of the first
/// [`EMBED_WINDOW_GOPS`] GOPs, or of the whole carrier when it has fewer.
///
/// `None` when the carrier is not HEVC or has no decodable slice.
fn embed_window(carrier: &[u8]) -> Option<(u64, usize)> {
    let kind = sniff_hevc_carrier(carrier)?;
    let layout = parse_carrier_layout(carrier, kind).ok()?;
    if layout.candidates.is_empty() {
        return None;
    }
    let gops = find_gop_ranges(carrier, &layout.candidates);
    let taken = gops.len().min(EMBED_WINDOW_GOPS);
    let first = gops.first()?;
    let last = gops.get(taken.checked_sub(1)?)?;
    let start = layout.candidates.get(first.start)?.span.start;
    let end = layout.candidates.get(last.end.checked_sub(1)?)?.span.end;
    Some((end.saturating_sub(start).min(carrier.len()) as u64, taken))
}

/// Carrier bytes the first batch of an embed records, measured over VCL spans.
#[allow(dead_code)]
pub(crate) fn embed_window_bytes(carrier: &[u8]) -> Option<u64> {
    embed_window(carrier).map(|(bytes, _)| bytes)
}

/// Predicted peak of an in-place embed, split into the part that scales with
/// the recorded window and the part that does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmbedPeakEstimate {
    /// Carrier bytes the recorder holds at once (the recorded window).
    pub window_bytes: u64,
    /// Groups of pictures that window covers.
    pub window_gops: usize,
    /// Predicted peak private bytes.
    pub peak_bytes: u64,
}

/// Measured private-byte peak per carrier byte of the recorded window.
///
/// Fitted at 66 on Windows (24-minute 1080p film, 40 s 720p 21 Mbps clip);
/// rounded up because the window is measured over VCL spans, which are
/// slightly smaller than the file the fit was taken against.
const EMBED_WINDOW_BYTES_PER_CARRIER_BYTE: u64 = 70;

/// Fixed decoder/pool overhead of an in-place embed.
const EMBED_FIXED_BYTES: u64 = 64 * 1024 * 1024;

/// Peak private bytes for a recorded window of `window` carrier bytes.
#[inline]
fn embed_peak_for_window(window: u64, carrier_len: u64) -> u64 {
    window
        .saturating_mul(EMBED_WINDOW_BYTES_PER_CARRIER_BYTE)
        .saturating_add(carrier_len)
        .saturating_add(EMBED_FIXED_BYTES)
}

/// Peak estimate for embedding `payload_len` bytes into `carrier`.
///
/// The embed stops at the slice that meets the payload's slot target and keeps
/// only that window; the batch it was decoded in doubles from one GOP up to
/// [`EMBED_WINDOW_GOPS`], so at most one more window's worth is live beside it.
/// A `file_size × constant` estimate over-rejects long videos by ~12×, and a
/// whole-batch estimate over-rejects small payloads by 50×: a 4 KiB payload on
/// a 104 MB clip peaks at 129 MiB, not 6,759 MiB.
///
/// Returns `None` for carriers this engine does not decode.
pub(crate) fn estimate_embed_peak_bytes(
    carrier: &[u8],
    payload_len: usize,
    safety: SafetyPolicy,
    fmt: &HevcFormatProfile,
) -> Option<EmbedPeakEstimate> {
    let (batch_bytes, window_gops) = embed_window(carrier)?;
    // Header + payload + AEAD tag, with the flag/name area rounded up.
    let body_msg_len = payload_len.saturating_add(256);
    let body_slots = StcTrellis::slots_for_params(body_msg_len * 8, fmt.stc_h, fmt.stc_u);
    let factor = (1.0 / safety.level.video_budget().non_ref_fraction).max(1.0);
    let target_bytes = ((body_slots as f64 * factor).ceil() as u64).min(carrier.len() as u64);
    // One batch's worth on top of the window: the ramp decodes at most as much
    // again as it had already recorded before it can stop.
    let overshoot = target_bytes.min(batch_bytes);
    let window = target_bytes.saturating_add(overshoot);
    // Matroska and HEIF are committed as a whole rewritten file, so they hold a
    // second copy of the carrier beside the original. MP4 and Annex-B stream
    // their patches and never do. Once the window stopped dominating, this copy
    // became the peak: a 429.5 MB MKV peaks at 831 MiB, its 405.6 MB MP4 twin
    // at 443 MiB.
    let rewrite_copy = match sniff_hevc_carrier(carrier) {
        Some(HevcCarrierKind::MkvContainer | HevcCarrierKind::HeifContainer) => {
            carrier.len() as u64
        }
        _ => 0,
    };
    Some(EmbedPeakEstimate {
        window_bytes: window,
        window_gops,
        peak_bytes: embed_peak_for_window(window, carrier.len() as u64)
            .saturating_add(rewrite_copy),
    })
}
