//! Spatial carrier slot layout and budget planning (PNG).

use crate::errors::StrHideError;
use crate::stego::header::PNG_AUDIO_BASE_SLOTS;
use crate::stego::prng::permute_prefix;

use super::codec::RawImage;
use super::{SPATIAL_ELIGIBLE_MAX, SPATIAL_ELIGIBLE_MIN};

/// Whole-pipeline working-set ceiling for a spatial carrier, deliberately the
/// same value the JPEG engine uses.
///
/// The 64 MP pixel cap alone does not bound memory: HILL keeps six full-image
/// `f64` planes (~3 GiB at that size), and the trellis keeps one bitmap word per
/// state per element, which on a 64 MP RGB carrier with the three-channel pool
/// reaches tens of GiB. Without a budget, a large payload aborted the process
/// (`panic = "abort"`) instead of returning an error.
const MAX_PIPELINE_BYTES: u64 = 8 << 30;
/// Bytes that exist for every spatial embed regardless of payload: the decoded
/// image (up to 4 B/px), the six cost planes (48 B/px), the candidate list and
/// the per-pixel header mask (9 B/px).
const PIPELINE_BYTES_PER_PIXEL: u64 = 4 + 48 + 9;
/// Per body slot: slot values, the move table, the two direction-cost rows and
/// the body index. The trellis bitmap is charged separately.
const PIPELINE_BYTES_PER_SLOT: u64 = 24;
const PIPELINE_FIXED_BYTES: u64 = 64 << 20;

fn pipeline_base_bytes(total_pixels: usize) -> u64 {
    PIPELINE_FIXED_BYTES.saturating_add(total_pixels as u64 * PIPELINE_BYTES_PER_PIXEL)
}

/// Bytes of per-slot state, including the trellis bitmap when the STC codec runs.
fn pipeline_bytes_per_slot(trellis_h: Option<u8>) -> u64 {
    let bitmap = trellis_h.map_or(0, crate::stego::coding::backtrack_bytes_per_slot);
    PIPELINE_BYTES_PER_SLOT.saturating_add(bitmap)
}

pub(crate) fn check_pipeline_budget(
    total_pixels: usize,
    body_n: usize,
    trellis_h: Option<u8>,
) -> Result<(), StrHideError> {
    let total = pipeline_base_bytes(total_pixels)
        .saturating_add(body_n as u64 * pipeline_bytes_per_slot(trellis_h));
    if total > MAX_PIPELINE_BYTES {
        return Err(StrHideError::PayloadTooLarge(format!(
            "PNG carrier is too large for this payload: it needs about {} MiB of working memory and the {} MiB budget would be exceeded (use the Hamming codec, a smaller --stc-h, or a smaller payload)",
            total >> 20,
            MAX_PIPELINE_BYTES >> 20
        )));
    }
    Ok(())
}

/// Body slots whose working set still fits the pipeline budget.
///
/// Used by the capacity probe (via [`body_payload_fits`]) so the advertised
/// `max_raw_payload_bytes` never exceeds what the embedder's
/// [`check_pipeline_budget`] will accept.
pub(crate) fn max_body_slots_within_pipeline(total_pixels: usize, trellis_h: Option<u8>) -> usize {
    let remaining = MAX_PIPELINE_BYTES.saturating_sub(pipeline_base_bytes(total_pixels));
    usize::try_from(remaining / pipeline_bytes_per_slot(trellis_h)).unwrap_or(usize::MAX)
}

/// Payload ceiling the safety tier recommends for a spatial carrier.
///
/// Shared by the embed-time enforcement and the capacity probe, so the number
/// the probe advertises is exactly the number the writer accepts. `ratio_slots`
/// is deliberately the single-channel (green) pool: the tier is expressed in
/// bits per *pixel*, and a three-channel pool would loosen the ratio bound
/// without any calibration for the extra channels.
pub(crate) fn recommended_bytes_for(
    total_pixels: usize,
    ratio_slots: usize,
    level: crate::params::SafetyLevel,
) -> usize {
    let bpp_bits = (total_pixels as f64 * level.bpp_limit()).floor() as usize;
    let ratio_bits = (ratio_slots as f64 / level.target_ratio()).floor() as usize;
    (bpp_bits.min(ratio_bits) / 8).saturating_sub(crate::stego::envelope::BODY_OVERHEAD)
}

// ---------------------------------------------------------------------------
// Slot plan: the single source of truth for "which pixels carry what"
// ---------------------------------------------------------------------------

/// Channel the base header and the feature word are written into: green for
/// colour images (least visible), channel 0 for grayscale / gray+alpha.
///
/// The body may use more channels ([`ChannelMode`]); the header never does, so
/// its slot set does not depend on the body's mode. That is required: the
/// feature word carries the mode, and it cannot be read before the header.
pub(crate) fn embed_channel(image: &RawImage) -> usize {
    if image.channels >= 3 { 1 } else { 0 }
}

/// Which pixel channels the payload body may be written into.
///
/// The embedder chooses the mode from capacity need and records it in the
/// feature word, so the extractor never guesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelMode {
    /// Green (or the carrier's only channel): the single-channel layout.
    Green = 0,
    /// Red, green and blue. Alpha is never touched.
    Rgb = 1,
}

impl ChannelMode {
    /// Wire value -> mode. Unknown values are rejected: a carrier claiming a
    /// mode this build cannot reproduce must read as "no payload here".
    pub(crate) fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(ChannelMode::Green),
            1 => Some(ChannelMode::Rgb),
            _ => None,
        }
    }

    /// The channels this mode writes, for a carrier with `channels` components.
    pub(crate) fn channels(self, channels: usize) -> &'static [usize] {
        const GREEN: [usize; 1] = [1];
        const GRAY: [usize; 1] = [0];
        const RGB: [usize; 3] = [0, 1, 2];
        match self {
            ChannelMode::Green if channels >= 3 => &GREEN,
            ChannelMode::Green => &GRAY,
            ChannelMode::Rgb => &RGB,
        }
    }

    /// False when the mode needs channels the carrier does not have.
    pub(crate) fn available(self, channels: usize) -> bool {
        match self {
            ChannelMode::Green => true,
            ChannelMode::Rgb => channels >= 3,
        }
    }

    /// Human-readable name for diagnostics.
    pub(crate) fn name(self) -> &'static str {
        match self {
            ChannelMode::Green => "green",
            ChannelMode::Rgb => "rgb",
        }
    }
}

/// The carrier's slot layout: candidates, header assignment, body pool.
///
/// Embed, extract and capacity-probe all need exactly this decision, and three
/// hand-copied versions of it had already drifted: the probe derived its header
/// permutation from `(None, None)` while the embedder used the caller's
/// password and domain. Since the 512 header/feature slots are removed from the
/// body pool, a probe with different credentials excludes *different* pixels and
/// reports a capacity the writer cannot reach.
pub(crate) struct SlotPlan {
    /// Body candidates: cost-ranked, after the smooth-pixel exclusion, in
    /// ranking order. Never used to place the header.
    pub(crate) candidates: Vec<usize>,
    /// Header layout: the eligible pixels in keyed order. The first
    /// `header_slots` entries carry the 64-byte base header and the optional
    /// extension area.
    ///
    /// This vector is a pure function of the carrier's pixels and the locator
    /// seed -- **not** of any cost map. That is what lets the extractor read
    /// the header (and therefore the algorithm id inside it) before it knows
    /// which cost model wrote the carrier.
    pub(crate) permuted: Vec<usize>,
    /// Number of leading `permuted` entries reserved for header + extension.
    pub(crate) header_slots: usize,
    /// `used_by_header[px]`: the pixel is one of those header slots.
    pub(crate) used_by_header: Vec<bool>,
}

/// Wire form of the smooth-area exclusion: permille in `0..=900`.
///
/// The base header stores `exclusion_permille`, and both ends must cut the
/// candidate list with the same integer, so the percentile never enters the
/// arithmetic. `(k / 1000.0) * 1000.0` round-trips exactly for every
/// `k in 0..=900`, so re-quantising the header value is lossless.
pub(crate) fn exclusion_permille(percentile: f64) -> u16 {
    (percentile.clamp(0.0, 0.9) * 1000.0) as u16
}

/// Pixels eligible to carry the header channel, in ascending pixel order.
///
/// Eligibility is the class-interior test on the header channel: `val` in
/// `[8, 247]` so at least one of `val ± 1` stays inside the same eight-value
/// class. Deliberately **cost-free** -- see [`SlotPlan::permuted`].
pub(crate) fn header_pool(image: &RawImage) -> Vec<usize> {
    let total_pixels = image.width as usize * image.height as usize;
    let channel_offset = embed_channel(image);
    (0..total_pixels)
        .filter(|&idx| {
            let val = image.pixels[idx * image.channels + channel_offset];
            (SPATIAL_ELIGIBLE_MIN..=SPATIAL_ELIGIBLE_MAX).contains(&val)
        })
        .collect()
}

/// Carrier identity mixed into the L1 PBKDF2 salt.
///
/// Both ends compute this from the decoded image only: dimensions, colour
/// layout and the **critical**-chunk stream. `IDAT` is excluded (it is what the
/// embedder rewrites) and so is every ancillary chunk.
///
/// Only critical chunks may take part (first letter uppercase per the PNG
/// spec: `IHDR`, `PLTE`, `IEND`). They are exactly what defines the pixels; the
/// ancillary ones (`tEXt`, `zTXt`, `iTXt`, `tIME`, `eXIf`, `iCCP`, `gAMA`,
/// `sRGB`, `pHYs`, our own `prIv`, ...) are metadata that other tools rewrite
/// at will. Hashing those used to mean that adding one `tEXt` chunk after an
/// embed -- exiftool, an optimiser, an editor's "save as" -- re-derived the
/// locator keys and turned the payload into unrecoverable garbage
/// (`No valid payload found`). A carrier is identified by its pixels, not by
/// its tags.
///
/// A standard `IHDR`/`IDAT`/`IEND` file hashes identically under the old and
/// new rule, so payloads written before this change stay readable as long as
/// their metadata was not touched.
pub fn png_pre_salt(
    image: &RawImage,
    spatial: &crate::stego::format::PngFormatProfile,
) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};

    let mut meta = Sha256::new();
    for chunk in &image.chunks {
        // IDAT is rewritten by the embedder; `prIv` carries the envelope itself.
        if chunk.ty == *b"IDAT" || chunk.ty == *b"prIv" {
            continue;
        }
        // Ancillary chunk: metadata, not image identity (see the doc comment).
        if chunk.ty[0].is_ascii_lowercase() {
            continue;
        }
        meta.update(chunk.ty);
        meta.update((chunk.data.len() as u32).to_be_bytes());
        meta.update(&chunk.data);
    }
    let meta: [u8; 32] = meta.finalize().into();

    let mut out = Sha256::new();
    out.update(spatial.hpos_salt);
    out.update(b"png-v4");
    out.update((image.width as u64).to_be_bytes());
    out.update((image.height as u64).to_be_bytes());
    out.update([image.bit_depth, image.color_type, image.channels as u8]);
    out.update(meta);
    out.finalize().into()
}

/// The keyed header layout, computed without a cost model.
///
/// `locate_seed` comes from L2; `ext_len` extends the permuted prefix by eight
/// slots per extension byte. `permute_prefix` is prefix-stable, so the first
/// 512 slots are identical whether or not the extension area is known — that
/// is what lets the reader decode the base header before it learns `ext_len`.
pub(crate) fn header_layout(
    image: &RawImage,
    locate_seed: &[u8; 32],
    ext_len: usize,
) -> Vec<usize> {
    let mut slots = header_pool(image);
    let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * ext_len;
    permute_prefix(&mut slots, header_slots, locate_seed);
    slots
}

/// Read `byte_count` bytes (MSB first) from the given pixel slots.
///
/// Callers guarantee `slots.len() == 8 * byte_count`; the base header path
/// always has 512 slots and the extension path is sized from `ext_len`.
pub(crate) fn read_slot_bytes(image: &RawImage, slots: &[usize], byte_count: usize) -> Vec<u8> {
    let channel_offset = embed_channel(image);
    let mut bytes = Vec::with_capacity(byte_count);
    for byte_i in 0..byte_count {
        let mut b = 0u8;
        for bit_i in 0..8 {
            let slot = slots[byte_i * 8 + bit_i];
            let val = image.pixels[slot * image.channels + channel_offset];
            b = (b << 1) | (val & 1);
        }
        bytes.push(b);
    }
    bytes
}

impl SlotPlan {
    /// Rank the body candidates and apply the keyed header layout.
    ///
    /// `locate_seed` keys the header permutation and `ext_len` reserves the
    /// extension slots, so the plan must be built from exactly the inputs the
    /// writer will use — they change which pixels the header occupies and
    /// therefore the body capacity.
    pub(crate) fn build(
        image: &RawImage,
        costs: &[f64],
        locate_seed: &[u8; 32],
        ext_len: usize,
        exclusion_permille: u16,
    ) -> Result<Self, StrHideError> {
        let total_pixels = image.width as usize * image.height as usize;
        if costs.len() != total_pixels {
            return Err(StrHideError::General("Cost map dimension mismatch".into()));
        }
        let channel_offset = embed_channel(image);

        // Eligible pixels: the class must be interior, i.e. `val` must sit in
        // [8, 247] so that at least one of `val ± 1` stays inside the same
        // eight-value class. That keeps three invariants the extractor relies on:
        // 1. `val & 0xF8` never changes, so the HILL cost map is bit-identical;
        // 2. modified values stay in [7, 248], never reaching 0/255 (no clipping);
        // 3. eligibility itself is class-based, so both ends derive the same set.
        //
        // Ranking order is a *total* order: (cost bits, pixel index). HILL costs
        // are non-negative finite values, so their bit patterns sort exactly
        // like the values, and the index reproduces the tie-breaking the
        // previous stable `sort_by` produced -- which matters because flat areas
        // give thousands of exactly equal costs (`1 / epsilon`). A total order
        // is what allows `select_nth_unstable` below to stay bit-identical to a
        // full sort.
        let mut ranked: Vec<(u64, usize)> = (0..total_pixels)
            .filter(|&idx| {
                let val = image.pixels[idx * image.channels + channel_offset];
                (SPATIAL_ELIGIBLE_MIN..=SPATIAL_ELIGIBLE_MAX).contains(&val)
            })
            .map(|idx| (costs[idx].to_bits(), idx))
            .collect();

        // Exclude the smoothest fraction (e.g. 30%). Only the kept prefix is
        // needed, so partition first (O(n)) and sort just that prefix; the
        // candidate list grows ~3x when the body spans three channels.
        //
        // The cut is integer arithmetic on the *wire* permille, not on the
        // float percentile: `(len * (1000 - k)) / 1000` is exactly reproducible
        // by any reader, whereas `len * (1.0 - k / 1000.0)` rounds in the last
        // bit and can land one element short (k = 900, len = 1000 gives 99
        // instead of 100). Extraction must rebuild the same candidate list, so
        // this formula is part of the wire format, not an implementation detail.
        let allowed_count = ranked.len() * (1000 - exclusion_permille as usize) / 1000;
        if allowed_count < ranked.len() {
            ranked.select_nth_unstable(allowed_count);
            ranked.truncate(allowed_count);
        }
        ranked.sort_unstable();
        let candidates: Vec<usize> = ranked.into_iter().map(|(_, px)| px).collect();

        // The header is placed from the cost-free layout, so a reader can find
        // it without knowing the algorithm.
        let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * ext_len;
        let permuted = header_layout(image, locate_seed, ext_len);

        let mut used_by_header = vec![false; total_pixels];
        for &s in permuted.iter().take(header_slots) {
            used_by_header[s] = true;
        }

        Ok(Self {
            candidates,
            permuted,
            header_slots,
            used_by_header,
        })
    }

    /// True when there are enough candidates for the base header *and* the
    /// extension area reserved by the plan.
    pub(crate) fn header_fits(&self) -> bool {
        self.permuted.len() >= self.header_slots
    }

    /// The [`PNG_AUDIO_BASE_SLOTS`] slots carrying the 64-byte base header.
    ///
    /// Callers must have checked [`Self::header_fits`].
    pub(crate) fn base_header_slots(&self) -> &[usize] {
        &self.permuted[..PNG_AUDIO_BASE_SLOTS]
    }

    /// Slots `PNG_AUDIO_BASE_SLOTS .. header_slots` carrying the extension TLV
    /// bytes, eight bit-slots per byte.
    pub(crate) fn extension_slots(&self) -> &[usize] {
        &self.permuted[PNG_AUDIO_BASE_SLOTS..self.header_slots]
    }

    /// Visit every body slot in ranking order.
    ///
    /// A slot is a **byte offset** into `image.pixels` (`pixel * channels +
    /// channel`). Expressing slots as offsets is what makes multi-channel
    /// embedding possible without a second index space, and it reduces to the
    /// historical `pixel` index when only one channel is in play. Slots come
    /// out pixel by pixel in cost order and, inside a pixel, in ascending
    /// channel order -- exactly the `(cost, channel, pixel)` total order,
    /// without materialising a second sort.
    ///
    /// Restrictions, shared by embed / extract / probe:
    /// - the pixel already passed header-channel eligibility and the
    ///   smooth-area exclusion, so one ranking serves both header and body;
    /// - the header's 512 pixels keep their header channel reserved for the
    ///   header (the body may still use their other channels: a class-internal
    ///   `±1` leaves `val & 0xF8` untouched, so the cost map the header is
    ///   ranked on is bit-identical before and after embedding);
    /// - the considered channel's own value must be class-interior and, under
    ///   the safe `class_rule == 1`, sit in `val % 8 ∈ [1, 6]`, which removes
    ///   the r=0/7 boundary deficit (P0-B).
    pub(crate) fn for_each_body_slot(
        &self,
        image: &RawImage,
        class_rule: u8,
        mode: ChannelMode,
        mut visit: impl FnMut(usize) -> bool,
    ) {
        let channels = image.channels;
        let header_channel = embed_channel(image);
        let used = mode.channels(channels);
        for &px in &self.candidates {
            let reserved = self.used_by_header[px];
            for &c in used {
                if reserved && c == header_channel {
                    continue;
                }
                let slot = px * channels + c;
                let val = image.pixels[slot];
                if !(SPATIAL_ELIGIBLE_MIN..=SPATIAL_ELIGIBLE_MAX).contains(&val) {
                    continue;
                }
                if class_rule == 1 && !(1..=6).contains(&(val % 8)) {
                    continue;
                }
                if !visit(slot) {
                    return;
                }
            }
        }
    }

    /// Number of body slots available under `mode` / `class_rule`.
    pub(crate) fn count_body_slots(
        &self,
        image: &RawImage,
        class_rule: u8,
        mode: ChannelMode,
    ) -> usize {
        let mut n = 0usize;
        self.for_each_body_slot(image, class_rule, mode, |_| {
            n += 1;
            true
        });
        n
    }

    /// The first `limit` body slots under `mode` / `class_rule`, in ranking order.
    pub(crate) fn body_slots_upto(
        &self,
        image: &RawImage,
        class_rule: u8,
        mode: ChannelMode,
        limit: usize,
    ) -> Vec<usize> {
        let max_possible = self
            .candidates
            .len()
            .saturating_mul(mode.channels(image.channels).len());
        let mut out = Vec::with_capacity(limit.min(max_possible));
        if limit == 0 {
            return out;
        }
        self.for_each_body_slot(image, class_rule, mode, |slot| {
            out.push(slot);
            out.len() < limit
        });
        out
    }
}
