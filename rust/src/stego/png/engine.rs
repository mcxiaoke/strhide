//! Spatial domain steganographic embedding and extraction engine (PNG).
//!
//! Uses content-adaptive distortion costs (e.g. HILL) to isolate complex texture
//! and noisy regions, completely avoiding smooth areas.
//!
//! # Embedding operation
//!
//! Bits are written by **ternary `±1` matching**: a slot whose LSB must change
//! moves to `val + 1` or `val - 1`, whichever is cheaper and legal, instead of
//! having its LSB replaced. Both directions flip the LSB, so the payload bit is
//! still the slot's parity and extraction is unchanged.
//!
//! The move is constrained to the pixel's **eight-value class** (`val & 0xF8`):
//! the engine ranks candidates under the safe rule
//! ([`crate::stego::coding::spatial_move_safe`]), where class positions `r = 0`
//! and `r = 7` are not candidates at all, `r = 1` may only move up and `r = 6`
//! only down, so no modified pixel ever lands on a boundary residue. The
//! constraint exists because the extractor rebuilds the slot ranking from a
//! cost map computed on the *stego* image, so the ranking must be reproducible:
//! HILL masks its input with `0xF8`, and a class-internal `±1` leaves that
//! masked value untouched. Unrestricted matching would change it and
//! desynchronise the ranking.
//!
//! Why this is not just LSB replacement with extra steps: replacement always
//! moves a slot in the direction of the target bit, so every value pair
//! `(2k, 2k+1)` is equalised — the exact signature chi-square and SPA look for.
//! Here the four interior class positions (`r = 2..=5`, half of every class)
//! can move either way, so probability mass crosses pair boundaries and the
//! pairs are no longer individually flat. Direction choice is further biased
//! towards the local mean by
//! [`crate::stego::traits::PngCostModel::direction_costs`].

use crate::core::control::{Control, Stage};
use crate::core::media::MediaInfo;
use crate::core::payload::Payload;

use crate::crypto::{CipherSuiteId, Credential};
use crate::errors::StrHideError;
use crate::stego::coding::{
    Move, StcTrellis, hamming_embed_ternary, hamming_extract_bytes, spatial_move_safe,
    write_bit_ternary,
};
use crate::stego::envelope::{
    Freshness, build_plaintext, build_v4_aad_with, encrypt_v4_with_aad, unpack_v4_envelope_parts,
};
use crate::stego::format::{derive_l2_locator_keys, derive_l3_session_keys, derive_locator_master};
use crate::stego::header::{
    CONTENT_ENVELOPE_VERSION, FLAG_EXT_CRITICAL, FLAG_EXT_PRESENT, HEADER_LEN_MAX, MAX_EXT_BYTES,
    PNG_AUDIO_BASE_HEADER_BYTES, PNG_AUDIO_BASE_SLOTS, SpatialHeaderV4, TLV_CRITICAL, Tlv,
    encode_extension_for_write, parse_extension, quantize_epsilon_k,
};
use crate::stego::options::{StegoHeaderInfo, StegoVerifyResult, VerifyLevel};
use crate::stego::params::{ExtractParams, SafetyPolicy};
use crate::stego::prng::{permute_indices, permute_prefix};
use crate::stego::traits::PngCostModel;
use crate::stego::{PngParams, StegoCapacityInfo, StegoCodec};

/// Inclusive range of pixel values the spatial engine may embed into.
///
/// The bounds are the class-interior rule: from a value in `[8, 247]` at least
/// one of `val ± 1` stays inside the same eight-value class, and no move can
/// reach 0 or 255. Both the writer and the extractor must use this range
/// verbatim; it is exported so tests can assert against the same constant
/// instead of re-typing the bounds.
pub const SPATIAL_ELIGIBLE_MIN: u8 = 8;
pub const SPATIAL_ELIGIBLE_MAX: u8 = 247;

/// `format_id` written into the V4 content envelope for PNG carriers.
const PNG_FORMAT_ID: u8 = 1;

// ---------------------------------------------------------------------------
// Envelope header layout (32 bytes = 256 slots)
// ---------------------------------------------------------------------------
//
// [0..16) salt, [16..28) nonce, [28..32) the flags+length word. The layout and
// its bit allocation live in [`crate::stego::header`], shared with the JPEG
// engine so both carriers describe their codec identically.

#[path = "codec.rs"]
mod codec;

pub use codec::{IdatInfo, PngChunk, RawImage, decode_png, encode_png};

use codec::trace;

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

fn check_pipeline_budget(
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
fn max_body_slots_within_pipeline(total_pixels: usize, trellis_h: Option<u8>) -> usize {
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
fn recommended_bytes_for(
    total_pixels: usize,
    ratio_slots: usize,
    level: crate::params::SafetyLevel,
) -> usize {
    let bpp_bits = (total_pixels as f64 * level.bpp_limit()).floor() as usize;
    let ratio_bits = (ratio_slots as f64 / level.target_ratio()).floor() as usize;
    (bpp_bits.min(ratio_bits) / 8).saturating_sub(crate::stego::envelope::BODY_OVERHEAD)
}

#[cfg(test)]
use codec::{choose_deflate_level, deflate_len, filter_row, write_chunk};
// ---------------------------------------------------------------------------
// Slot plan: the single source of truth for "which pixels carry what"
// ---------------------------------------------------------------------------

/// Channel the base header and the feature word are written into: green for
/// colour images (least visible), channel 0 for grayscale / gray+alpha.
///
/// The body may use more channels ([`ChannelMode`]); the header never does, so
/// its slot set does not depend on the body's mode. That is required: the
/// feature word carries the mode, and it cannot be read before the header.
fn embed_channel(image: &RawImage) -> usize {
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
    fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(ChannelMode::Green),
            1 => Some(ChannelMode::Rgb),
            _ => None,
        }
    }

    /// The channels this mode writes, for a carrier with `channels` components.
    fn channels(self, channels: usize) -> &'static [usize] {
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
    fn available(self, channels: usize) -> bool {
        match self {
            ChannelMode::Green => true,
            ChannelMode::Rgb => channels >= 3,
        }
    }

    /// Human-readable name for diagnostics.
    fn name(self) -> &'static str {
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
struct SlotPlan {
    /// Body candidates: cost-ranked, after the smooth-pixel exclusion, in
    /// ranking order. Never used to place the header.
    candidates: Vec<usize>,
    /// Header layout: the eligible pixels in keyed order. The first
    /// `header_slots` entries carry the 64-byte base header and the optional
    /// extension area.
    ///
    /// This vector is a pure function of the carrier's pixels and the locator
    /// seed -- **not** of any cost map. That is what lets the extractor read
    /// the header (and therefore the algorithm id inside it) before it knows
    /// which cost model wrote the carrier.
    permuted: Vec<usize>,
    /// Number of leading `permuted` entries reserved for header + extension.
    header_slots: usize,
    /// `used_by_header[px]`: the pixel is one of those header slots.
    used_by_header: Vec<bool>,
}

/// Wire form of the smooth-area exclusion: permille in `0..=900`.
///
/// The base header stores `exclusion_permille`, and both ends must cut the
/// candidate list with the same integer, so the percentile never enters the
/// arithmetic. `(k / 1000.0) * 1000.0` round-trips exactly for every
/// `k in 0..=900`, so re-quantising the header value is lossless.
fn exclusion_permille(percentile: f64) -> u16 {
    (percentile.clamp(0.0, 0.9) * 1000.0) as u16
}

/// Pixels eligible to carry the header channel, in ascending pixel order.
///
/// Eligibility is the class-interior test on the header channel: `val` in
/// `[8, 247]` so at least one of `val ± 1` stays inside the same eight-value
/// class. Deliberately **cost-free** -- see [`SlotPlan::permuted`].
fn header_pool(image: &RawImage) -> Vec<usize> {
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
fn header_layout(image: &RawImage, locate_seed: &[u8; 32], ext_len: usize) -> Vec<usize> {
    let mut slots = header_pool(image);
    let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * ext_len;
    permute_prefix(&mut slots, header_slots, locate_seed);
    slots
}

/// Read `byte_count` bytes (MSB first) from the given pixel slots.
///
/// Callers guarantee `slots.len() == 8 * byte_count`; the base header path
/// always has 512 slots and the extension path is sized from `ext_len`.
fn read_slot_bytes(image: &RawImage, slots: &[usize], byte_count: usize) -> Vec<u8> {
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
    fn build(
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
    fn header_fits(&self) -> bool {
        self.permuted.len() >= self.header_slots
    }

    /// The [`PNG_AUDIO_BASE_SLOTS`] slots carrying the 64-byte base header.
    ///
    /// Callers must have checked [`Self::header_fits`].
    fn base_header_slots(&self) -> &[usize] {
        &self.permuted[..PNG_AUDIO_BASE_SLOTS]
    }

    /// Slots `PNG_AUDIO_BASE_SLOTS .. header_slots` carrying the extension TLV
    /// bytes, eight bit-slots per byte.
    fn extension_slots(&self) -> &[usize] {
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
    fn for_each_body_slot(
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
    fn count_body_slots(&self, image: &RawImage, class_rule: u8, mode: ChannelMode) -> usize {
        let mut n = 0usize;
        self.for_each_body_slot(image, class_rule, mode, |_| {
            n += 1;
            true
        });
        n
    }

    /// The first `limit` body slots under `mode` / `class_rule`, in ranking order.
    fn body_slots_upto(
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

// ---------------------------------------------------------------------------
// Embedding & Extraction
// ---------------------------------------------------------------------------

/// Embed a payload into a PNG carrier with content-adaptive spatial steganography.
///
/// The complete expert entry: format identity, cost model, tuning parameters
/// and salt/nonce source are all explicit. `secret` is the resolved credential
/// (explicit password, else the profile's private stego secret, else `None` for
/// the official public constant); `domain` isolates the HKDF derivation.
/// `Freshness::Seeded` makes the output byte-identical for the same carrier,
/// payload, secret and seed. `safety` is the capacity policy the embed is
/// checked against.
#[allow(clippy::too_many_arguments)]
pub fn embed_png<'a>(
    carrier_bytes: &[u8],
    payload: impl Into<Payload<'a>>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    safety: SafetyPolicy,
    freshness: Freshness,
    control: &Control<'_>,
) -> Result<Vec<u8>, StrHideError> {
    embed_png_with_stats(
        carrier_bytes,
        payload,
        cred,
        domain,
        suite_id,
        extensions,
        spatial,
        cost_model,
        params,
        safety,
        freshness,
        control,
    )
    .map(|(bytes, _, _)| bytes)
}

/// Embed a payload into a PNG carrier and return modified bytes, embed statistics, and capacity info.
#[allow(clippy::too_many_arguments)]
pub(crate) fn embed_png_with_stats<'a>(
    carrier_bytes: &[u8],
    payload: impl Into<Payload<'a>>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    safety: SafetyPolicy,
    freshness: Freshness,
    control: &Control<'_>,
) -> Result<(Vec<u8>, crate::stego::EmbedStats, StegoCapacityInfo), StrHideError> {
    let payload = payload.into();
    params.validate()?;
    let suite = CipherSuiteId::from_u16(suite_id).ok_or_else(|| {
        StrHideError::UnsupportedVersion(format!("Unknown content cipher suite id {suite_id}"))
    })?;
    let extension = encode_extension_for_write(extensions)?;
    if extension.len() > MAX_EXT_BYTES {
        return Err(StrHideError::General(format!(
            "Extension area is {} bytes, the maximum is {MAX_EXT_BYTES}",
            extension.len()
        )));
    }
    control.stage(Stage::Decode);
    let mut image = decode_png(carrier_bytes)?;
    // Checkpoint after the decode: on a 50 MP carrier this alone is seconds.
    control.check()?;
    control.stage(Stage::CostMap);
    let w = image.width as usize;
    let h = image.height as usize;
    let total_pixels = w * h;

    log::info!(
        target: "stego::png",
        "embed_png: image {}x{} ({} px), payload {} B",
        w, h, total_pixels, payload.as_bytes().len()
    );

    // Frame the payload and derive the per-carrier keys. The ciphertext itself
    // is produced further down: the finished base header plus extension area is
    // its associated data, so it cannot exist until codec/h/u are settled.
    let plaintext = build_plaintext(&payload)?;
    let cipher = spatial.cipher;
    let pre_salt = png_pre_salt(&image, spatial);
    let master = derive_locator_master(cred, domain, cipher, &pre_salt)?;
    let locator = derive_l2_locator_keys(&master, cipher, b"strhide-v4-hdr-magic", domain)?;
    // Seeded runs bind salt/nonce to the cover, payload, format, version and
    // extension area, so a replay on different inputs can never reuse a
    // (key, nonce) pair.
    let fresh_binding =
        Freshness::seeded_binding(carrier_bytes, payload.as_bytes(), PNG_FORMAT_ID, &extension);
    let salt = freshness.salt(0, &fresh_binding);
    let nonce = freshness.nonce(0, &fresh_binding);
    let session = derive_l3_session_keys(cipher, suite, &master, &salt, domain)?;
    let ext_len = extension.len();
    let ciphertext_len = plaintext.len() + suite.tag_len();

    // Quantise the hyperparameters to their wire-exact forms *before* any
    // use, and run the whole embed on them: the feature word can only carry
    // `epsilon` as a power of two and `sigma` at `f32` precision, so the
    // extractor can only ever reproduce these forms. The prober quantises
    // the same way, so advertised capacity and embedding pool agree.
    let params = params.wire_quantized();
    let eps_k = quantize_epsilon_k(params.epsilon);

    // Compute distortion cost map
    let costs = cost_model.compute_cost(&image.pixels, w, h, image.channels, &params);
    // Checkpoint after the cost map: the second big fixed cost of an embed.
    control.check()?;
    control.stage(Stage::Solve);

    let channel_offset = embed_channel(&image);

    let plan = SlotPlan::build(
        &image,
        &costs,
        &locator.locate_seed,
        ext_len,
        exclusion_permille(params.exclusion_percentile),
    )?;
    let (capacity_info, pool_green, pool_rgb) =
        build_png_capacity_with_pools(&image, &plan, &params, cost_model.id(), safety.level)?;
    if !plan.header_fits() {
        return Err(StrHideError::General(format!(
            "Carrier capacity insufficient: available {} slots, minimum header requires {} slots",
            plan.permuted.len(),
            plan.header_slots
        )));
    }
    let header_slots = plan.base_header_slots();
    let extension_slots = plan.extension_slots();

    let ciphertext_bits = ciphertext_len * 8;

    // Single-channel body pool first. Small payloads therefore keep the exact
    // layout (and byte-for-byte output) they had before multi-channel existed.
    // Safety enforcement policy check
    if safety.is_enforced() {
        let recommended_max_bytes = recommended_bytes_for(total_pixels, pool_green, safety.level);

        if payload.len() > recommended_max_bytes {
            return Err(StrHideError::SafetyThreshold {
                tier: safety.level,
                required_bytes: payload.len(),
                available_bytes: recommended_max_bytes,
            });
        }
    }

    // Resolve matrix-coding strategy and channel mode together.
    //
    // `Auto` (and STC with `stc_u = 0`) picks the group size from a slot pool,
    // but the pool that actually carries the body depends on that group size:
    // once the payload no longer fits one channel, the body moves to `Rgb`.
    // Resolving `u` against `pool_green` and then switching to `Rgb` kept the
    // degraded `u = 1` chosen for a pool that is never used, which is plain
    // parity coding with no cost-model optimisation. Re-resolve against the
    // pool the body will live in.
    let (resolved_codec, resolved_u, mode, pool_max) = 'resolve: {
        if matches!(params.codec, StegoCodec::Auto)
            || (params.codec == StegoCodec::Stc && params.stc_u == 0)
        {
            let (codec, u) = crate::stego::coding::auto_select_codec(pool_green, ciphertext_bits);
            let needed =
                crate::stego::coding::slots_for_codec(ciphertext_bits, codec, params.stc_h, u)?;
            if needed <= pool_green {
                break 'resolve (codec, u, ChannelMode::Green, pool_green);
            }
            let Some(pool_rgb) = pool_rgb else {
                return Err(StrHideError::PayloadTooLarge(format!(
                    "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: spatial-{})",
                    needed,
                    codec.describe(params.stc_h, u),
                    pool_green,
                    cost_model.id(),
                )));
            };
            let (codec, u) = crate::stego::coding::auto_select_codec(pool_rgb, ciphertext_bits);
            let rgb_needed =
                crate::stego::coding::slots_for_codec(ciphertext_bits, codec, params.stc_h, u)?;
            if rgb_needed <= pool_rgb {
                break 'resolve (codec, u, ChannelMode::Rgb, pool_rgb);
            }
            return Err(StrHideError::PayloadTooLarge(format!(
                "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: spatial-{} {})",
                rgb_needed,
                codec.describe(params.stc_h, u),
                pool_rgb,
                cost_model.id(),
                ChannelMode::Rgb.name(),
            )));
        }

        let (codec, u) = match params.codec {
            StegoCodec::Stc => (StegoCodec::Stc, params.stc_u),
            StegoCodec::Hamming => (StegoCodec::Hamming, 0),
            StegoCodec::Auto => unreachable!("handled above"),
        };
        let needed =
            crate::stego::coding::slots_for_codec(ciphertext_bits, codec, params.stc_h, u)?;
        if needed <= pool_green {
            break 'resolve (codec, u, ChannelMode::Green, pool_green);
        }
        if let Some(pool_rgb) = pool_rgb {
            if needed <= pool_rgb {
                break 'resolve (codec, u, ChannelMode::Rgb, pool_rgb);
            }
            return Err(StrHideError::PayloadTooLarge(format!(
                "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: spatial-{} {})",
                needed,
                codec.describe(params.stc_h, u),
                pool_rgb,
                cost_model.id(),
                ChannelMode::Rgb.name(),
            )));
        }
        return Err(StrHideError::PayloadTooLarge(format!(
            "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: spatial-{})",
            needed,
            codec.describe(params.stc_h, u),
            pool_green,
            cost_model.id(),
        )));
    };

    trace(format_args!(
        "plan pool_green={pool_green} pool_max={pool_max} mode={mode:?} codec={resolved_codec:?} u={resolved_u}"
    ));

    // Recompute the slot count from the resolved codec for the solve phase.
    let needed_body_slots = crate::stego::coding::slots_for_codec(
        ciphertext_bits,
        resolved_codec,
        params.stc_h,
        resolved_u,
    )?;

    // Refuse before the solve allocates anything: the trellis keeps one word per
    // state per element, so a large payload on a large carrier is a multi-GiB
    // allocation, and with `panic = "abort"` an OOM is a process kill rather
    // than an error the user can act on.
    check_pipeline_budget(
        total_pixels,
        needed_body_slots,
        match resolved_codec {
            StegoCodec::Hamming => None,
            _ => Some(params.stc_h),
        },
    )?;

    // V4 base header: `body_len` is the AEAD ciphertext length including the
    // tag, with no per-format padding adjustment.
    if ciphertext_len > HEADER_LEN_MAX as usize {
        return Err(StrHideError::General(format!(
            "Envelope of {ciphertext_len} bytes exceeds the {HEADER_LEN_MAX}-byte header length field"
        )));
    }
    let algorithm_id = crate::stego::png::registry::spatial_wire_id(cost_model.id()).ok_or_else(
        || {
            StrHideError::General(format!(
                "PNG cost model '{}' has no wire id; a carrier written with it could not be extracted",
                cost_model.id()
            ))
        },
    )?;
    let sigma = if cost_model.id() == "mipod" {
        params
            .algorithm_options
            .get("alpha")
            .copied()
            .unwrap_or(0.20)
            .clamp(0.01, 0.90) as f32
    } else {
        params
            .algorithm_options
            .get("sigma")
            .copied()
            .unwrap_or(1.0) as f32
    };
    let flags = {
        let mut flags = 0u8;
        if !extension.is_empty() {
            flags |= FLAG_EXT_PRESENT;
        }
        if extensions.iter().any(Tlv::is_critical) {
            flags |= FLAG_EXT_CRITICAL;
        }
        flags
    };
    let (codec_id, wire_h, wire_u) = match resolved_codec {
        StegoCodec::Hamming => (0u8, 0u8, 0u8),
        StegoCodec::Stc | StegoCodec::Auto => (1u8, params.stc_h, resolved_u),
    };
    let header = SpatialHeaderV4 {
        salt,
        nonce,
        body_len: ciphertext_len as u32,
        version: CONTENT_ENVELOPE_VERSION,
        flags,
        format_id: PNG_FORMAT_ID,
        algorithm_id,
        suite_id: suite.as_u16(),
        codec_id,
        stc_h: wire_h,
        stc_u: wire_u,
        // Self-describing: the extractor rebuilds the body pool from this and
        // nothing else, so a write here would desynchronise the two ends.
        channel_mode: mode as u8,
        class_rule: 1, // Safe [1, 6] non-boundary
        p1_window: params.p1_window as u16,
        p2_window: params.p2_window as u16,
        neg_log2_epsilon: eps_k,
        exclusion_permille: exclusion_permille(params.exclusion_percentile),
        sigma,
        kernel_id: 0, // the built-in KB kernel; custom kernels need matching configs
        ext_len: ext_len as u16,
    };
    let header_bytes = header.encode();
    let aad = build_v4_aad_with(cipher.aad_prefix, PNG_FORMAT_ID, &header_bytes, &extension);

    // Encrypt last: the whole base header plus extension area is the AEAD's
    // associated data, so a tampered field fails the tag instead of steering
    // the decoder somewhere else.
    let ciphertext_body = encrypt_v4_with_aad(suite, &session.enc_key, &nonce, &aad, &plaintext)?;

    // Phase 2: Keyed permutation of body slots.
    let perm_seed = session.perm_seed;
    let stc_seed = session.stc_seed;

    let mut body_slots = plan.body_slots_upto(&image, 1, mode, needed_body_slots);
    debug_assert_eq!(body_slots.len(), needed_body_slots, "pool counted above");
    permute_indices(&mut body_slots, &perm_seed);

    // Asymmetric per-direction costs. Embed-side only: ranking never sees them,
    // so the extractor does not have to reproduce them.
    //
    // The model prices only the requested slots, so the working set stays
    // payload-sized instead of materializing full-plane maps per channel.
    // Header slots are already pixel indices on the header channel; body
    // slots are byte offsets and become pixel indices per channel.
    let mut header_rp = vec![0.0f64; plan.header_slots];
    let mut header_rm = vec![0.0f64; plan.header_slots];
    let mut body_rp = vec![0.0f64; needed_body_slots];
    let mut body_rm = vec![0.0f64; needed_body_slots];
    let header_px: Vec<usize> = header_slots
        .iter()
        .chain(extension_slots.iter())
        .copied()
        .collect();
    for &channel in mode.channels(image.channels) {
        // Body pixel indices for this channel, in body-slot order (the
        // per-channel subset stays at its body-slot position).
        let body_px: Vec<usize> = body_slots
            .iter()
            .filter(|&&slot| slot % image.channels == channel)
            .map(|&slot| slot / image.channels)
            .collect();
        let (header_plus, header_minus) = if channel == channel_offset {
            cost_model.direction_costs(
                &costs,
                &image.pixels,
                w,
                h,
                image.channels,
                channel,
                &header_px,
            )
        } else {
            (Vec::new(), Vec::new())
        };
        let (body_plus, body_minus) = cost_model.direction_costs(
            &costs,
            &image.pixels,
            w,
            h,
            image.channels,
            channel,
            &body_px,
        );
        if channel == channel_offset {
            if header_plus.len() != header_px.len() || header_minus.len() != header_px.len() {
                return Err(StrHideError::General(
                    "Direction cost vector dimension mismatch".into(),
                ));
            }
            for (i, (&rp, &rm)) in header_plus.iter().zip(header_minus.iter()).enumerate() {
                header_rp[i] = rp;
                header_rm[i] = rm;
            }
        }
        if body_plus.len() != body_px.len() || body_minus.len() != body_px.len() {
            return Err(StrHideError::General(
                "Direction cost vector dimension mismatch".into(),
            ));
        }
        let mut k = 0usize;
        for (i, &slot) in body_slots.iter().enumerate() {
            if slot % image.channels == channel {
                body_rp[i] = body_plus[k];
                body_rm[i] = body_minus[k];
                k += 1;
            }
        }
    }

    let mut modified_slots = 0;

    // Embed Phase 1: 64-byte base header (512 slots), then the optional
    // extension area (8 slots per byte) from the same keyed permutation.
    for (byte_i, &b) in header_bytes.iter().enumerate() {
        for bit_i in 0..8 {
            let target_bit = (b >> (7 - bit_i)) & 1;
            let bit_index = byte_i * 8 + bit_i;
            let byte_idx = header_slots[bit_index] * image.channels + channel_offset;
            let prev = image.pixels[byte_idx];
            write_bit_ternary(
                &mut image.pixels[byte_idx],
                target_bit,
                header_rp[bit_index],
                header_rm[bit_index],
            );
            if image.pixels[byte_idx] != prev {
                modified_slots += 1;
            }
        }
    }
    for (byte_i, &b) in extension.iter().enumerate() {
        for bit_i in 0..8 {
            let target_bit = (b >> (7 - bit_i)) & 1;
            let bit_index = PNG_AUDIO_BASE_SLOTS + byte_i * 8 + bit_i;
            let byte_idx = extension_slots[byte_i * 8 + bit_i] * image.channels + channel_offset;
            let prev = image.pixels[byte_idx];
            write_bit_ternary(
                &mut image.pixels[byte_idx],
                target_bit,
                header_rp[bit_index],
                header_rm[bit_index],
            );
            if image.pixels[byte_idx] != prev {
                modified_slots += 1;
            }
        }
    }

    // Embed Phase 2: Ciphertext body. Slots are byte offsets, so the write is
    // a direct `pixels[slot]` -- no channel arithmetic left to get wrong.
    let mut slot_vals: Vec<u8> = body_slots.iter().map(|&slot| image.pixels[slot]).collect();
    let moves: Vec<Move> = slot_vals.iter().map(|&v| spatial_move_safe(v)).collect();
    match resolved_codec {
        StegoCodec::Hamming => {
            hamming_embed_ternary(
                &mut slot_vals,
                &moves,
                &body_rp,
                &body_rm,
                &ciphertext_body,
                crate::stego::coding::DEFAULT_HAMMING_K,
            )?;
        }
        StegoCodec::Stc | StegoCodec::Auto => {
            let trellis = StcTrellis::from_seed_grouped(stc_seed, params.stc_h, resolved_u)?;
            trellis.embed(&mut slot_vals, &moves, &body_rp, &body_rm, &ciphertext_body)?;
        }
    }

    for (i, &slot) in body_slots.iter().enumerate() {
        if image.pixels[slot] != slot_vals[i] {
            modified_slots += 1;
        }
        image.pixels[slot] = slot_vals[i];
    }

    control.stage(Stage::Encode);
    let encoded = encode_png(&image)?;
    let stats = crate::stego::EmbedStats {
        modified_slots,
        total_candidate_slots: total_pixels,
    };
    Ok((encoded, stats, capacity_info))
}

/// Extract a payload from a PNG carrier with content-adaptive spatial steganography.
///
/// The complete expert entry. The carrier declares its cost model in the
/// feature word, so `cost_model` is only a hint; `params` must repeat the
/// embed-time filter windows because the body slot ranking is recomputed from
/// the cost map.
#[allow(clippy::too_many_arguments)]
pub fn extract_png(
    carrier_bytes: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    params.validate()?;
    control.stage(Stage::Decode);
    let image = decode_png(carrier_bytes)?;
    control.check()?;
    extract_png_image(
        &image, cred, domain, spatial, cost_model, params, limits, control,
    )
}

/// L1/L2 outputs shared by extract, inspect and verify.
///
/// `verify` needs the locator keys for its header level *and* for its payload
/// level; deriving them twice paid the 200k-iteration L1 twice for one user
/// request. This value is derived once and passed down.
struct PngKeys {
    master: [u8; 32],
    locator: crate::stego::format::HeaderLocatorKeys,
}

/// Derive the per-carrier L1 master and L2 locator keys.
fn png_keys(
    image: &RawImage,
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
) -> Result<PngKeys, StrHideError> {
    let cipher = spatial.cipher;
    let pre_salt = png_pre_salt(image, spatial);
    let master = derive_locator_master(cred, domain, cipher, &pre_salt)?;
    let locator = derive_l2_locator_keys(&master, cipher, b"strhide-v4-hdr-magic", domain)?;
    Ok(PngKeys { master, locator })
}

/// Whether a policy is willing to pay the fixed V4 L1 cost.
fn l1_allowed(cred: &Credential<'_>, limits: &ExtractParams) -> bool {
    !matches!(cred, Credential::Password(_))
        || limits.max_pbkdf2_iterations >= crate::crypto::CONTENT_L1_PBKDF2_ITERATIONS
}

/// Base header and extension area every PNG reader must decode first.
struct OpenedPngHeader {
    header: SpatialHeaderV4,
    base_bytes: [u8; PNG_AUDIO_BASE_HEADER_BYTES],
    extension: Vec<u8>,
    /// The cost-free header permutation prefix. `extract` reuses it for a
    /// debug assertion that the body plan agrees with the header layout.
    base_layout: Vec<usize>,
}

/// Why the shared header bootstrap stopped.
enum OpenedPngHeaderError {
    /// The pool is large enough but the keyed slot read came back short: an
    /// anomaly worth a diagnostic note in `inspect`, not the ordinary
    /// "nothing hidden here" answer.
    HeaderSlotsShort { carrier_slots: usize, needed: usize },
    /// Everything else: no readable header, a malformed extension, or a
    /// digit that violates the caller's policy. Readers fold this into their
    /// own "no payload" / empty-info semantics.
    Rejected,
}

/// Read and validate the base header + extension area.
///
/// `extract_png_with_keys` and `inspect_png_with_keys` used to carry two
/// copies of this bootstrap (base header, extension decode, critical-TLV
/// rejection, policy limits). Keeping one implementation is what makes
/// "inspect says readable" and "extract says no payload" unable to disagree.
fn open_png_header(
    image: &RawImage,
    locator: &crate::stego::format::HeaderLocatorKeys,
    limits: &ExtractParams,
) -> Result<OpenedPngHeader, OpenedPngHeaderError> {
    let carrier_slots = header_pool(image).len();
    if carrier_slots < PNG_AUDIO_BASE_SLOTS {
        return Err(OpenedPngHeaderError::Rejected);
    }

    let base_layout = header_layout(image, &locator.locate_seed, 0);
    let base_bytes: [u8; PNG_AUDIO_BASE_HEADER_BYTES] =
        read_slot_bytes(image, &base_layout[..PNG_AUDIO_BASE_SLOTS], 64)
            .try_into()
            .map_err(|_| OpenedPngHeaderError::HeaderSlotsShort {
                carrier_slots,
                needed: PNG_AUDIO_BASE_SLOTS,
            })?;
    let header = SpatialHeaderV4::decode(&base_bytes, PNG_FORMAT_ID)
        .map_err(|_| OpenedPngHeaderError::Rejected)?;

    let ext_len = header.ext_len as usize;
    let header_slot_count = PNG_AUDIO_BASE_SLOTS + 8 * ext_len;
    if header_slot_count > carrier_slots {
        return Err(OpenedPngHeaderError::Rejected);
    }
    let full_layout = header_layout(image, &locator.locate_seed, ext_len);
    let extension = read_slot_bytes(
        image,
        &full_layout[PNG_AUDIO_BASE_SLOTS..header_slot_count],
        ext_len,
    );

    // The extension area is authenticated by the AAD, but its structure must
    // be sane first: an unknown critical TLV is fatal, non-critical ones are
    // ignored. `validate_ext_critical` also cross-checks the flags.
    header
        .validate_ext_critical(&extension)
        .map_err(|_| OpenedPngHeaderError::Rejected)?;
    let records = parse_extension(&extension).map_err(|_| OpenedPngHeaderError::Rejected)?;
    if records
        .iter()
        .any(|(type_id, _)| type_id & TLV_CRITICAL != 0)
    {
        return Err(OpenedPngHeaderError::Rejected);
    }

    // Policy checks run after the base header and extension are decoded but
    // before any body slot is computed or allocated.
    limits
        .validate_header(
            header.suite_id,
            header.body_len,
            header_slot_count,
            carrier_slots,
        )
        .map_err(|_| OpenedPngHeaderError::Rejected)?;

    Ok(OpenedPngHeader {
        header,
        base_bytes,
        extension,
        base_layout,
    })
}

/// Body of [`extract_png`] for an already-decoded image.
///
/// `verify_png` decodes once and reuses the pixels across all three levels
/// instead of running the full PNG decode three times.
#[allow(clippy::too_many_arguments)]
fn extract_png_image(
    image: &RawImage,
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    params.validate()?;
    // Refuse a policy that cannot pay the one fixed L1 cost before running it.
    if !l1_allowed(&cred, limits) {
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }
    let keys = png_keys(image, cred, domain, spatial)?;
    extract_png_with_keys(
        image, &keys, domain, spatial, cost_model, params, limits, control,
    )
}

/// Extraction over a pre-derived L1/L2 key set.
#[allow(clippy::too_many_arguments)]
fn extract_png_with_keys(
    image: &RawImage,
    keys: &PngKeys,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    params.validate()?;
    let no_hidden = || StrHideError::NoHiddenData("No valid payload found".into());
    // `HeaderLocatorKeys` is not `Copy` (it wipes itself on drop), so borrow it
    // instead of moving it out of the shared reference. `master` is a plain
    // array and stays a value copy.
    let master = keys.master;
    let locator = &keys.locator;

    let w = image.width as usize;
    let h = image.height as usize;
    let cipher = spatial.cipher;

    let OpenedPngHeader {
        header,
        base_bytes,
        extension,
        base_layout,
    } = open_png_header(image, locator, limits).map_err(|_| no_hidden())?;
    let ext_len = header.ext_len as usize;

    // The carrier names its cost model. An id this build does not know means a
    // carrier written by a newer tool -- reported exactly like "no payload",
    // because guessing a model would silently decode noise.
    let resolved = crate::stego::png::registry::spatial_model_from_wire_id(header.algorithm_id)
        .ok_or_else(no_hidden)?;
    if resolved.id() != cost_model.id() {
        // The carrier is authoritative; the caller's choice is only a hint.
        trace(format_args!(
            "carrier declares '{}', caller asked for '{}': using the carrier's",
            resolved.id(),
            cost_model.id()
        ));
    }

    // The carrier is self-describing about every hyperparameter that shapes
    // the cost map: exclusion percentile, HILL's windows and epsilon, and the
    // sigma model option. Whatever the caller configured is a hint only --
    // the wire values are what the embedder actually computed with.
    let mut effective_params = params.clone();
    effective_params.exclusion_percentile = (header.exclusion_permille as f64) / 1000.0;
    effective_params.p1_window = header.p1_window as usize;
    effective_params.p2_window = header.p2_window as usize;
    effective_params.epsilon = 2f64.powi(-(header.neg_log2_epsilon as i32));
    if resolved.id() == "suniward" {
        effective_params
            .algorithm_options
            .insert("sigma".to_string(), header.sigma as f64);
    } else if resolved.id() == "mipod" {
        effective_params
            .algorithm_options
            .insert("alpha".to_string(), (header.sigma as f64).clamp(0.01, 0.90));
    }
    effective_params.validate()?;

    // Distortion cost map of the declared model. Identical to what the embedder
    // computed, because header/feature pixels never leave their eight-value
    // class, so the map is bit-identical on the stego.
    let costs = resolved.compute_cost(&image.pixels, w, h, image.channels, &effective_params);
    control.check()?;
    // Body ranking needs costs; the header layout inside this plan is the same
    // cost-free one read above, so the two cannot disagree.
    let plan = SlotPlan::build(
        image,
        &costs,
        &locator.locate_seed,
        ext_len,
        header.exclusion_permille,
    )?;
    debug_assert_eq!(
        plan.permuted.get(..PNG_AUDIO_BASE_SLOTS),
        Some(&base_layout[..PNG_AUDIO_BASE_SLOTS]),
        "the header layout must not depend on the cost map"
    );

    // The body's channel mode arrives in the header. An unknown value, or one
    // the carrier cannot support, means the header landed on the wrong slots --
    // folded into the same generic failure as an AEAD reject.
    let mode = ChannelMode::from_wire(header.channel_mode).ok_or_else(no_hidden)?;
    if !mode.available(image.channels) {
        return Err(no_hidden());
    }
    let codec = match header.codec_id {
        0 => StegoCodec::Hamming,
        1 => StegoCodec::Stc,
        _ => return Err(no_hidden()),
    };
    let suite = CipherSuiteId::from_u16(header.suite_id).ok_or_else(no_hidden)?;
    if !limits.allows_suite(header.suite_id) {
        return Err(no_hidden());
    }

    // `body_len` is the AEAD ciphertext length including the 16-byte tag.
    let ciphertext_len = header.body_len as usize;
    let ciphertext_bits = ciphertext_len * 8;
    let needed_body_slots =
        crate::stego::coding::slots_for_codec(ciphertext_bits, codec, header.stc_h, header.stc_u)
            .map_err(|_| no_hidden())?;

    // Same budget the writer applies: a header claiming a payload this large
    // would otherwise have the reader allocate its way into an OOM abort before
    // it ever gets to reject the carrier.
    check_pipeline_budget(
        image.width as usize * image.height as usize,
        needed_body_slots,
        match codec {
            StegoCodec::Hamming => None,
            _ => Some(header.stc_h),
        },
    )
    .map_err(|_| no_hidden())?;

    // `body_slots_upto` stops as soon as `needed_body_slots` are collected and
    // its length check below rejects short pools, so a separate full-image
    // `count_body_slots` pass only doubled the scan without changing the
    // verdict.
    let mut body_slots = plan.body_slots_upto(image, header.class_rule, mode, needed_body_slots);
    trace(format_args!(
        "extract mode={:?} class_rule={} body_len={ciphertext_len} needed={needed_body_slots} pool={}",
        mode,
        header.class_rule,
        body_slots.len()
    ));
    // Short pool == the carrier is smaller than the header claims: no payload.
    if body_slots.len() < needed_body_slots {
        return Err(no_hidden());
    }
    let session = derive_l3_session_keys(cipher, suite, &master, &header.salt, domain)
        .map_err(|_| no_hidden())?;
    permute_indices(&mut body_slots, &session.perm_seed);

    let slot_vals: Vec<u8> = body_slots.iter().map(|&slot| image.pixels[slot]).collect();

    let ciphertext = match codec {
        StegoCodec::Hamming => hamming_extract_bytes(
            &slot_vals,
            ciphertext_len,
            crate::stego::coding::DEFAULT_HAMMING_K,
        )
        .map_err(|_| no_hidden())?,
        StegoCodec::Stc | StegoCodec::Auto => {
            let trellis =
                StcTrellis::from_seed_grouped(session.stc_seed, header.stc_h, header.stc_u)
                    .map_err(|_| no_hidden())?;
            trellis.extract(&slot_vals, ciphertext_bits)
        }
    };

    let aad = build_v4_aad_with(cipher.aad_prefix, PNG_FORMAT_ID, &base_bytes, &extension);
    // AEAD failure (and every structural failure before it) already collapsed
    // to `NoHiddenData` inside the envelope code. Once the tag verifies the
    // carrier is provably ours, so a broken frame / oversized payload must
    // surface as `CorruptedData` / capacity instead of "no payload here".
    unpack_v4_envelope_parts(
        suite,
        &session.enc_key,
        &header.nonce,
        &aad,
        &ciphertext,
        limits,
    )
}

/// Inspect PNG for stego header and self-describing metadata without decoding body.
pub(crate) fn inspect_png(
    carrier_bytes: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    control.check()?;
    let image = match decode_png(carrier_bytes) {
        Ok(img) => img,
        Err(e) => {
            return Ok(StegoHeaderInfo {
                format: "PNG".into(),
                has_hidden_data: false,
                algorithm: None,
                codec: None,
                envelope_len: None,
                payload_len: None,
                media_info: None,
                note: Some(format!("Decode failed: {e}")),
            });
        }
    };
    control.check()?;
    inspect_png_image(&image, cred, domain, spatial, limits, control)
}

/// Header inspection for an already-decoded image.
///
/// `verify_png` and `inspect_png` share this so the PNG decode runs once.
fn inspect_png_image(
    image: &RawImage,
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    if !l1_allowed(&cred, limits) {
        let mut empty = StegoHeaderInfo::empty("PNG");
        empty.media_info = Some(MediaInfo::new(image.width, image.height));
        return Ok(empty);
    }
    let keys = png_keys(image, cred, domain, spatial)?;
    inspect_png_with_keys(image, &keys, limits, control)
}

/// Header inspection over a pre-derived L1/L2 key set.
fn inspect_png_with_keys(
    image: &RawImage,
    keys: &PngKeys,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    control.check()?;
    let media_info = Some(MediaInfo::new(image.width, image.height));
    let mut empty_info = StegoHeaderInfo::empty("PNG");
    empty_info.media_info = media_info;

    let opened = match open_png_header(image, &keys.locator, limits) {
        Ok(opened) => opened,
        Err(OpenedPngHeaderError::HeaderSlotsShort {
            carrier_slots,
            needed,
        }) => {
            // The pool length was checked inside the bootstrap, so a short read
            // means the slot mapping disagrees with the image — an anomaly, not
            // the "no header here" answer every clean PNG gives below.
            log::debug!(
                target: "stego::inspect",
                "png header slots could not be read (pool {} slots, need {})",
                carrier_slots,
                needed
            );
            empty_info.note = Some(format!(
                "Header slots could not be read: pool has {carrier_slots} slots, the header needs {needed}"
            ));
            return Ok(empty_info);
        }
        Err(OpenedPngHeaderError::Rejected) => return Ok(empty_info),
    };
    let header = opened.header;

    let algo_name = crate::stego::png::registry::spatial_model_from_wire_id(header.algorithm_id)
        .map(|m| m.id().to_string())
        .unwrap_or_else(|| format!("Unknown(0x{:02x})", header.algorithm_id));
    let codec = match header.codec_id {
        0 => "Hamming".to_string(),
        1 => format!("Stc (h={}, u={})", header.stc_h, header.stc_u),
        other => format!("Unknown({other})"),
    };

    Ok(StegoHeaderInfo {
        format: "PNG".into(),
        has_hidden_data: true,
        algorithm: Some(algo_name),
        codec: Some(codec),
        envelope_len: Some(header.body_len as usize),
        payload_len: None,
        media_info,
        note: None,
    })
}

/// Three-level diagnostic verification for PNG carriers.
pub(crate) fn verify_png(
    carrier_bytes: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    control.check()?;
    let mut levels = Vec::new();

    // Level 1: Container & Decode
    let image = match decode_png(carrier_bytes) {
        Ok(img) => {
            levels.push(VerifyLevel::pass(
                1,
                format!(
                    "PNG structure valid ({}x{}, {} channels)",
                    img.width, img.height, img.channels
                ),
            ));
            img
        }
        Err(e) => {
            levels.push(VerifyLevel::fail(1, "PNG structure decode", e.to_string()));
            levels.push(VerifyLevel::fail(
                2,
                "Stego header",
                "Skipped due to level 1 failure",
            ));
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                "Skipped due to level 1 failure",
            ));
            return Ok(StegoVerifyResult::new("PNG", levels));
        }
    };
    control.check()?;

    // The L1 cost is fixed by V4; a policy that cannot pay it must fail before
    // the header read so the report says "policy", not "wrong password".
    if matches!(cred, Credential::Password(_))
        && limits.max_pbkdf2_iterations < crate::crypto::CONTENT_L1_PBKDF2_ITERATIONS
    {
        levels.push(VerifyLevel::fail(
            2,
            "Stego header",
            format!(
                "PBKDF2 iteration limit {} is below the V4 L1 cost {}",
                limits.max_pbkdf2_iterations,
                crate::crypto::CONTENT_L1_PBKDF2_ITERATIONS
            ),
        ));
        levels.push(VerifyLevel::fail(
            3,
            "Payload decryption",
            "Skipped due to level 2 policy failure",
        ));
        return Ok(StegoVerifyResult::new("PNG", levels));
    }

    // Level 2 and 3 share one L1/L2 derivation: `verify` is one user request,
    // so it must not pay the 200k-iteration L1 twice (plan M-14).
    let keys = png_keys(&image, cred, domain, spatial)?;
    let header_info = inspect_png_with_keys(&image, &keys, limits, control)?;
    if !header_info.has_hidden_data {
        levels.push(VerifyLevel::fail(
            2,
            "Stego header",
            "No valid V4 stego header found (or wrong password)",
        ));
        levels.push(VerifyLevel::fail(
            3,
            "Payload decryption",
            "No stego header to extract payload from",
        ));
        return Ok(StegoVerifyResult::new("PNG", levels));
    }
    levels.push(VerifyLevel::pass(
        2,
        format!(
            "Stego header valid (algorithm: {}, codec: {}, envelope: {} B)",
            header_info.algorithm.as_deref().unwrap_or("unknown"),
            header_info.codec.as_deref().unwrap_or("unknown"),
            header_info.envelope_len.unwrap_or(0),
        ),
    ));
    control.check()?;

    // Level 3: Payload Decryption & AEAD Authenticity
    let model = crate::stego::options::SpatialAlgorithm::default().model();
    let params = crate::stego::params::PngParams::default();
    match extract_png_with_keys(
        &image, &keys, domain, spatial, &*model, &params, limits, control,
    ) {
        Ok(payload) => {
            let desc = match payload.name() {
                Some(name) => format!(
                    "Payload decrypted & verified ({} bytes, filename: '{}')",
                    payload.len(),
                    name
                ),
                None => format!(
                    "Payload decrypted & verified ({} bytes, raw/text)",
                    payload.len()
                ),
            };
            levels.push(VerifyLevel::pass(3, desc));
        }
        Err(e) => {
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                format!("Decryption or authentication failed: {e}"),
            ));
        }
    }

    Ok(StegoVerifyResult::new("PNG", levels))
}

/// Would the embedder accept `raw_bytes` on the green or RGB body pool?
///
/// This mirrors the codec/`u` resolution in [`embed_png_with_stats`] exactly:
/// `Auto` (and `Stc` with `stc_u = 0`) re-resolve the group size against each
/// candidate pool, while fixed codecs use the configured group size. Capacity
/// probing and embedding therefore share one accounting rule instead of the
/// probe assuming `u = 1` and the writer using whatever the pool resolves to.
///
/// `total_pixels` feeds the same pipeline-memory budget the embedder enforces
/// in [`check_pipeline_budget`]: a payload whose slots fit the pool but whose
/// working set would exceed [`MAX_PIPELINE_BYTES`] is reported as not fitting,
/// so the probe never advertises a size the writer must refuse.
fn body_payload_fits(
    params: &PngParams,
    pool_green: usize,
    pool_rgb: Option<usize>,
    raw_bytes: usize,
    total_pixels: usize,
) -> Result<bool, StrHideError> {
    let ciphertext_bytes = raw_bytes.saturating_add(crate::stego::envelope::BODY_OVERHEAD);
    let Some(bits) = ciphertext_bytes.checked_mul(8) else {
        return Ok(false);
    };
    for pool in std::iter::once(pool_green).chain(pool_rgb) {
        if pool == 0 {
            continue;
        }
        let (codec, u) = if matches!(params.codec, StegoCodec::Auto)
            || (params.codec == StegoCodec::Stc && params.stc_u == 0)
        {
            crate::stego::coding::auto_select_codec(pool, bits)
        } else {
            match params.codec {
                StegoCodec::Stc => (StegoCodec::Stc, params.stc_u),
                StegoCodec::Hamming => (StegoCodec::Hamming, 0),
                StegoCodec::Auto => unreachable!("handled above"),
            }
        };
        let slots = crate::stego::coding::slots_for_codec(bits, codec, params.stc_h, u)?;
        if slots > pool {
            continue;
        }
        // Same budget rule as the embedder: the trellis bitmap is only
        // charged when the STC codec runs (Hamming has no trellis).
        let trellis_h = match codec {
            StegoCodec::Hamming => None,
            _ => Some(params.stc_h),
        };
        if slots <= max_body_slots_within_pipeline(total_pixels, trellis_h) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Largest raw payload the writer accepts on the given body pools.
///
/// Binary search over `body_payload_fits`, so it uses the *same* slot
/// accounting as the embedder. The previous closed-form inverse assumed
/// `u = 1` and overshot by a few bytes whenever the pool resolved a larger
/// group size or a codec whose warm-up rows do not invert exactly.
fn max_raw_payload_for_pools(
    params: &PngParams,
    pool_green: usize,
    pool_rgb: Option<usize>,
    total_pixels: usize,
) -> Result<usize, StrHideError> {
    let largest_pool = pool_green.max(pool_rgb.unwrap_or(0));
    if largest_pool == 0 {
        return Ok(0);
    }
    // Even the densest codec (Hamming) needs more than one slot per byte of
    // ciphertext, so `8 * slots` is a safe, generous upper bound.
    let mut lo = 0usize;
    let mut hi = largest_pool.saturating_mul(8);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if body_payload_fits(params, pool_green, pool_rgb, mid, total_pixels)? {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Ok(lo)
}

/// Construct the capacity metadata directly from an already computed [`SlotPlan`].
///
/// Shared between embedding and probing so that embedding never has to decode
/// the carrier or recompute the distortion cost map a second time to report capacity.
fn build_png_capacity_with_pools(
    image: &RawImage,
    plan: &SlotPlan,
    params: &PngParams,
    cost_model_id: &str,
    safety_level: crate::stego::SafetyLevel,
) -> Result<(StegoCapacityInfo, usize, Option<usize>), StrHideError> {
    let w = image.width as usize;
    let h = image.height as usize;
    let total_pixels = w * h;

    let header_fits = plan.header_fits();
    let pool_green = if header_fits {
        plan.count_body_slots(image, 1, ChannelMode::Green)
    } else {
        0
    };
    let pool_rgb = (header_fits && image.channels >= 3)
        .then(|| plan.count_body_slots(image, 1, ChannelMode::Rgb));
    let available_body_slots = match pool_rgb {
        Some(rgb) => rgb,
        None => pool_green,
    };
    let ratio_slots = pool_green;

    let max_raw_payload_bytes =
        max_raw_payload_for_pools(params, pool_green, pool_rgb, total_pixels)?;

    let recommended_max_bytes = recommended_bytes_for(total_pixels, ratio_slots, safety_level);
    let hamming_k = crate::stego::coding::DEFAULT_HAMMING_K;
    let tier_limits = crate::params::SafetyLevel::ALL
        .map(|level| recommended_bytes_for(total_pixels, ratio_slots, level));

    let info = StegoCapacityInfo {
        format: "PNG".into(),
        algorithm: cost_model_id.into(),
        total_elements: total_pixels,
        available_slots: available_body_slots,
        max_raw_payload_bytes,
        max_raw_is_grouped: false,
        recommended_max_bytes,
        tier_limits,
        estimated_change_rate: match params.codec {
            StegoCodec::Hamming => crate::stego::coding::expected_change_rate(hamming_k),
            StegoCodec::Stc if params.stc_u > 0 => {
                crate::stego::coding::expected_stc_change_rate(params.stc_u)
            }
            StegoCodec::Stc | StegoCodec::Auto => crate::stego::coding::expected_stc_change_rate(3),
        },
        safety_level: safety_level.as_str().into(),
        safety_bpp_limit: safety_level.bpp_limit(),
        is_estimated: false,
        media_info: Some(MediaInfo::new(image.width, image.height)),
    };
    Ok((info, pool_green, pool_rgb))
}

fn build_png_capacity_info(
    image: &RawImage,
    plan: &SlotPlan,
    params: &PngParams,
    cost_model_id: &str,
    safety_level: crate::stego::SafetyLevel,
) -> Result<StegoCapacityInfo, StrHideError> {
    build_png_capacity_with_pools(image, plan, params, cost_model_id, safety_level)
        .map(|(info, _, _)| info)
}

/// Probe the embedding capacity of a PNG carrier.
///
/// The complete expert entry: `safety_level` picks the tier `recommended_max_bytes`
/// is derived from; `secret`/`domain` key the header-slot permutation, which
/// decides which pixels are available to the payload.
#[allow(clippy::too_many_arguments)]
pub fn probe_png_capacity(
    carrier_bytes: &[u8],
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    safety_level: crate::stego::SafetyLevel,
    cred: Credential<'_>,
    domain: Option<&str>,
    extensions: &[Tlv],
    spatial: &crate::stego::format::PngFormatProfile,
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    params.validate()?;
    // Probe with the same wire-quantised hyperparameters the embedder will
    // use, so the advertised capacity matches the pool embedding sees.
    let params = params.wire_quantized();
    let extension = encode_extension_for_write(extensions)?;
    if extension.len() > MAX_EXT_BYTES {
        return Err(StrHideError::General(format!(
            "Extension area is {} bytes, the maximum is {MAX_EXT_BYTES}",
            extension.len()
        )));
    }
    control.stage(Stage::Decode);
    let image = decode_png(carrier_bytes)?;

    control.stage(Stage::CostMap);
    let costs = cost_model.compute_cost(
        &image.pixels,
        image.width as usize,
        image.height as usize,
        image.channels,
        &params,
    );
    control.check()?;

    // Same credential, carrier identity and extension area as the writer: the
    // header permutation (and therefore the body pool) must match exactly.
    let cipher = spatial.cipher;
    let pre_salt = png_pre_salt(&image, spatial);
    let master = derive_locator_master(cred, domain, cipher, &pre_salt)?;
    let locator = derive_l2_locator_keys(&master, cipher, b"strhide-v4-hdr-magic", domain)?;
    let plan = SlotPlan::build(
        &image,
        &costs,
        &locator.locate_seed,
        extension.len(),
        exclusion_permille(params.exclusion_percentile),
    )?;
    build_png_capacity_info(&image, &plan, &params, cost_model.id(), safety_level)
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
