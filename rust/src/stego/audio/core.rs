//! Shared V4 envelope pipeline for every audio carrier (WAV PCM, FLAC residuals).
//!
//! Each carrier is reduced to an ordered array of **slots**, each of which holds
//! a signed integer whose parity is the embedded bit and which can be moved by
//! `±1` without changing anything else. The V4 envelope stack is then shared
//! with the image engines.
//!
//! # Layout
//!
//! ```text
//! plan slot    0 .. 512        64-byte base header (salt | nonce | body_len | params)
//! plan slot  512 .. 512+8*ext  extension TLV area, one bit per slot
//! plan slot  ...               AEAD ciphertext body, matrix-coded
//! ```
//!
//! `plan slot i` is a keyed pseudo-random permutation of the carrier's slot
//! indices, so the payload is spread over the whole file and its position is
//! unguessable without the password.
//!
//! # Why the header is readable before the extension is known
//!
//! The permutation is derived from the password and the carrier-derived
//! `pre_salt`, never from the payload. [`crate::stego::prng::permute_prefix`]
//! keeps the first 512 positions of the permutation identical whether or not
//! extension slots are reserved, so a reader can decode the base header and only
//! then learn `ext_len` from it.
//!
//! # Slot count is content-independent
//!
//! The body length is `slots_for(ciphertext bits)` and the permutation is over
//! the carrier, so a reader that recovers `body_len` from the header addresses
//! the same slots the writer used.

use crate::SafetyPolicy;
use crate::core::control::{Control, Stage};
use crate::core::payload::Payload;
use crate::crypto::{CipherSuiteId, Credential};
use crate::errors::StrHideError;
use crate::params::SafetyLevel;
use crate::stego::audio::cost::CostParams;
use crate::stego::audio::perm::KeyedPermutation;
use crate::stego::coding::{
    DEFAULT_HAMMING_K, DEFAULT_STC_H, Move, StcTrellis, auto_select_codec,
    expected_stc_change_rate, required_slots, slots_for_codec,
};
use crate::stego::envelope::{
    BODY_OVERHEAD, Freshness, NONCE_LEN, SALT_LEN, build_plaintext, build_v4_aad,
    encrypt_v4_with_aad, unpack_v4_envelope_parts,
};
use crate::stego::format::{
    HeaderLocatorKeys, WireCipherProfile, derive_l2_locator_keys, derive_l3_session_keys,
    derive_locator_master,
};
use crate::stego::header::{
    CONTENT_ENVELOPE_VERSION, FLAG_EXT_CRITICAL, FLAG_EXT_PRESENT, HEADER_LEN_MAX, MAX_EXT_BYTES,
    PNG_AUDIO_BASE_SLOTS, SpatialHeaderV4, TLV_CRITICAL, Tlv, encode_extension_for_write,
    parse_extension,
};
use crate::stego::options::{StegoHeaderInfo, StegoVerifyResult, VerifyLevel};
use crate::stego::{EmbedStats, StegoCapacityInfo, StegoCodec};

/// Upper bound on the working set one embed may allocate.
///
/// The trellis keeps a backtrack bitmap of `words_per_col * 8` bytes per slot
/// (`h = 8` needs 32 bytes/slot), so the payload -- not the carrier -- decides
/// the peak. 768 MiB admits roughly a 1 MiB payload at `h = 8`, far beyond what
/// the safety tiers allow on any realistic audio carrier, and keeps a runaway
/// request from aborting the process on an allocation failure.
const MAX_WORKING_SET_BYTES: u64 = 768 * 1024 * 1024;

/// Slot-change budget per safety tier, **in percent of all slots**.
///
/// Audio slots are samples, not pixels, and a 1-LSB move on 1 % of them is
/// roughly 110 dB below full scale -- inaudible by a wide margin. The tiers are
/// ordered like the image ones (`Paranoid` < `High` < `Balanced`) and are
/// deliberately conservative: classical LSB replacement rewrites *half* the
/// samples.
pub(crate) const CHANGE_PERCENT_PARANOID: f64 = 0.5;
pub(crate) const CHANGE_PERCENT_HIGH: f64 = 1.5;
pub(crate) const CHANGE_PERCENT_BALANCED: f64 = 3.0;

/// Percent of slots the given tier may modify.
pub(crate) fn change_percent(level: SafetyLevel) -> f64 {
    match level {
        SafetyLevel::Paranoid => CHANGE_PERCENT_PARANOID,
        SafetyLevel::High => CHANGE_PERCENT_HIGH,
        SafetyLevel::Balanced => CHANGE_PERCENT_BALANCED,
    }
}

/// One audio carrier, viewed as an array of parity-carrying slots.
///
/// Implementations own the bytes they mutate: `apply` writes straight into the
/// carrier, `finalize` recomputes whatever the format requires (nothing for
/// WAV, frame CRCs and the STREAMINFO MD5 for FLAC).
pub(crate) trait SlotCarrier {
    /// Number of addressable slots.
    fn slot_count(&self) -> usize;

    /// Current signed value of a slot; its parity is the embedded bit.
    fn slot_value(&self, index: usize) -> i32;

    /// Which `±1` moves are legal at this slot.
    fn move_legality(&self, index: usize) -> Move;

    /// Perceptual cost of moving this slot by one unit (embed-side only).
    fn cost(&self, index: usize, params: &CostParams) -> f64;

    /// Move a slot by `delta` (must be `-1`, `0` or `1`).
    fn apply(&mut self, index: usize, delta: i8) -> Result<(), StrHideError>;

    /// Recompute the carrier's own integrity fields after all moves.
    fn finalize(&mut self) -> Result<(), StrHideError>;

    /// Slots actually moved so far.
    fn modified_slots(&self) -> usize;

    /// Display label used in capacity reports.
    fn format_label(&self) -> &'static str;

    /// Slots the *carrier* could offer, which is not always `slot_count()`.
    ///
    /// WAV materialises every sample, so the two agree. FLAC materialises only
    /// the slots a given payload needs, but its capacity report must describe
    /// the whole file, so it overrides this with the count of residuals that can
    /// currently move plus the fixed header slots. Reporting only: the slot
    /// *plan* thins over FLAC's structural pool instead, which is the count both
    /// ends derive (see `flac::FlacAnalysis`).
    fn capacity_slots(&self) -> usize {
        self.slot_count()
    }

    /// Slots the header area can occupy. WAV uses the whole permuted pool;
    /// FLAC can only put header bits in subframe tails, which are disjoint from
    /// the body residuals, so it overrides this with the tail count.
    fn header_capacity(&self) -> usize {
        self.slot_count()
    }

    /// Smallest STC group size `u` this carrier can encode with.
    ///
    /// `u = 1` pins every plan slot to a target parity, so a single slot that
    /// cannot move breaks the whole code. Carriers whose slots are not all
    /// equal -- FLAC's compensation chains make some residuals immovable --
    /// return 3, and the capacity report is then priced at that group size
    /// instead of promising the geometric maximum.
    fn min_group(&self) -> u8 {
        1
    }

    /// One-line human description of the carrier (depth, channels, duration),
    /// surfaced in `inspect` output. `None` when the format has nothing useful
    /// to add.
    fn describe(&self) -> Option<String> {
        None
    }
}

/// How plan positions map onto carrier slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mapping {
    /// Keyed pseudo-random permutation of the whole slot pool (WAV). Spreads the
    /// payload over the file and hides its position without the password.
    Permuted,
    /// Header slots stay put, body positions are permuted within the body
    /// region (FLAC).
    ///
    /// FLAC needs both halves of this: the header slots must be the subframe
    /// tails, because a header bit cannot be rerouted if its slot cannot move,
    /// while the body wants the payload scattered so that the residuals a given
    /// key skips are spread over the whole file instead of clustering in one
    /// quiet passage.
    BodyPermuted,
}

/// Everything derived once per call from the credential and the carrier.
///
/// Extraction, inspection and verification all need L1 and L2; deriving them
/// twice would pay PBKDF2 twice for one user request. `verify` in particular
/// reuses this for both of its levels.
pub(crate) struct PreparedCarrier {
    /// L1 output: the locator master.
    pub master: [u8; 32],
    /// L2 output: the header-location seed.
    pub locator: HeaderLocatorKeys,
}

/// Derive the L1 master and L2 locator keys from `cred` and the carrier hash.
pub(crate) fn prepare(
    cred: Credential<'_>,
    domain: Option<&str>,
    cipher: &WireCipherProfile,
    pre_salt: &[u8; 32],
) -> Result<PreparedCarrier, StrHideError> {
    let master = derive_locator_master(cred, domain, cipher, pre_salt)?;
    let locator = derive_l2_locator_keys(&master, cipher, b"strhide-v4-hdr-magic", domain)?;
    Ok(PreparedCarrier { master, locator })
}

/// The slot plan shared by writer and reader.
enum SlotPlan {
    Permuted {
        perm: KeyedPermutation,
        header_slots: usize,
    },
    BodyPermuted {
        perm: KeyedPermutation,
        header_slots: usize,
    },
}

impl SlotPlan {
    fn new(
        mapping: Mapping,
        slot_count: usize,
        header_slots: usize,
        header_seed: &[u8; 32],
    ) -> Self {
        match mapping {
            Mapping::Permuted => SlotPlan::Permuted {
                perm: KeyedPermutation::new(header_seed, slot_count),
                header_slots,
            },
            Mapping::BodyPermuted => {
                let body = slot_count.saturating_sub(header_slots);
                SlotPlan::BodyPermuted {
                    perm: KeyedPermutation::new(header_seed, body),
                    header_slots,
                }
            }
        }
    }

    #[inline]
    fn header_slot(&self, i: usize) -> usize {
        match self {
            // WAV permutes the whole pool; FLAC's header picks are already in
            // place at the front of the slot array.
            SlotPlan::Permuted { perm, .. } => perm.at(i),
            SlotPlan::BodyPermuted { .. } => i,
        }
    }

    #[inline]
    fn extension_slot(&self, i: usize) -> usize {
        self.header_slot(PNG_AUDIO_BASE_SLOTS + i)
    }

    #[inline]
    fn body_slot(&self, i: usize) -> usize {
        match self {
            SlotPlan::Permuted { perm, header_slots } => perm.at(header_slots + i),
            SlotPlan::BodyPermuted { perm, header_slots } => header_slots + perm.at(i),
        }
    }
}

/// Byte of the base header / extension assembled from slot parities.
fn read_bytes<C: SlotCarrier + ?Sized>(
    carrier: &C,
    slots: impl Iterator<Item = usize>,
    len: usize,
) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for (bit, slot) in slots.take(len * 8).enumerate() {
        if (carrier.slot_value(slot) & 1) != 0 {
            out[bit / 8] |= 1 << (7 - (bit % 8));
        }
    }
    out
}

/// Deterministic direction for a parity flip.
///
/// Costs are symmetric for audio (a `+1` and a `-1` LSB move are equally
/// audible), so the direction is chosen by a keyed coin flip instead of a cost
/// comparison. Always moving `+1` would shift the sample mean upwards on every
/// carrier; alternating by key keeps the first-order histogram symmetric.
#[inline]
fn direction_flip(index: usize, salt: u64) -> bool {
    let mut z = salt ^ (index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z ^= z >> 33;
    z = z.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    z ^= z >> 33;
    z & 1 == 1
}

/// Write one bit into `slot` by flipping its parity.
fn write_bit<C: SlotCarrier + ?Sized>(
    carrier: &mut C,
    slot: usize,
    bit: u8,
    salt: u64,
) -> Result<(), StrHideError> {
    let value = carrier.slot_value(slot);
    if ((value & 1) as u8) == bit {
        return Ok(());
    }
    let delta = match carrier.move_legality(slot) {
        Move::PlusOnly => 1,
        Move::MinusOnly => -1,
        Move::Both => {
            if direction_flip(slot, salt) {
                1
            } else {
                -1
            }
        }
        // The header and extension slots are written outside the trellis, so an
        // immovable one cannot be routed around. Refuse rather than silently
        // leaving a header bit unset -- a corrupt header would make the whole
        // envelope unreadable instead of failing loudly.
        Move::None => {
            return Err(StrHideError::General(format!(
                "slot {slot} cannot carry the required bit: no legal move preserves its class"
            )));
        }
    };
    carrier.apply(slot, delta)
}

/// Write whole bytes into consecutive plan slots.
fn write_bytes<C: SlotCarrier + ?Sized>(
    carrier: &mut C,
    slots: Vec<usize>,
    bytes: &[u8],
    salt: u64,
) -> Result<(), StrHideError> {
    for (bit, slot) in slots.into_iter().take(bytes.len() * 8).enumerate() {
        let value = (bytes[bit / 8] >> (7 - (bit % 8))) & 1;
        write_bit(carrier, slot, value, salt)?;
    }
    Ok(())
}

/// Peer estimate used by both the prober and the embedder.
fn working_set_bytes(n: usize, h: u8, u: u8) -> u64 {
    let state_bits = (h as u64 - 1) + u64::from(u > 1);
    let words_per_col = (1u64 << state_bits).div_ceil(64);
    // Backtrack bitmap + parities + deltas + move flags + cost scratch.
    n as u64 * (words_per_col * 8 + 1 + 1 + 1 + 8)
}

/// Slots required for `bits` ciphertext bits under `codec`.
fn body_slots(bits: usize, codec: StegoCodec, h: u8, u: u8) -> Result<usize, StrHideError> {
    slots_for_codec(bits, codec, h, u)
}

/// Capacity in payload bytes for a given body slot budget.
fn payload_bytes_from_slots(slots: usize, codec: StegoCodec, h: u8, u: u8) -> usize {
    if slots == 0 {
        return 0;
    }
    let ciphertext_bits = match codec {
        StegoCodec::Hamming => {
            let k = DEFAULT_HAMMING_K;
            let n = (1usize << k) - 1;
            let blocks = slots / n;
            blocks * k + (slots % n).min(k - 1)
        }
        StegoCodec::Stc | StegoCodec::Auto => {
            let u = u.max(1) as usize;
            let rows = slots / u;
            rows.saturating_sub(h as usize - 1)
        }
    };
    (ciphertext_bits / 8).saturating_sub(BODY_OVERHEAD)
}

/// Largest body length that stays inside [`MAX_WORKING_SET_BYTES`].
fn max_body_slots(h: u8, u: u8) -> usize {
    let per_slot = working_set_bytes(1, h, u).max(1);
    (MAX_WORKING_SET_BYTES / per_slot) as usize
}

/// Quantise `epsilon` to the power of two the header can express.
fn quantize_epsilon(epsilon: f64) -> u16 {
    if !epsilon.is_finite() || epsilon <= 0.0 {
        return 23;
    }
    (-epsilon.log2()).round().clamp(1.0, 127.0) as u16
}

/// Build the capacity report shared by `probe` and `embed`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn capacity_info(
    total: usize,
    header_slots: usize,
    label: &str,
    level: SafetyLevel,
    h: u8,
    u: u8,
    codec: StegoCodec,
    min_u: u8,
) -> StegoCapacityInfo {
    let available = total.saturating_sub(header_slots);
    let u = u.max(min_u);

    let ceiling = max_body_slots(h, u).min(available);
    let max_raw_payload_bytes = payload_bytes_from_slots(ceiling, codec, h, u);

    // Per-tier capacity has to use the codec the embedder would actually pick
    // for that payload size -- `u` falls as the payload grows, and the change
    // rate falls with it. Solve the fixed point instead of guessing: three
    // iterations always converge (the ratio only moves in one direction).
    let mut tier_limits = [0usize; 3];
    let mut tier_u = [u; 3];
    for (idx, lvl) in [
        SafetyLevel::Paranoid,
        SafetyLevel::High,
        SafetyLevel::Balanced,
    ]
    .into_iter()
    .enumerate()
    {
        let budget = (total as f64 * change_percent(lvl) / 100.0) as usize;
        let mut candidate_u = u.max(min_u);
        for _ in 0..3 {
            let rate_u = expected_stc_change_rate(candidate_u).max(1e-6);
            let bits = (budget as f64 / rate_u) as usize;
            let (_, next_u) = auto_select_codec(available, bits.max(1));
            let next_u = next_u.max(min_u);
            if next_u == candidate_u {
                break;
            }
            candidate_u = next_u;
        }
        let rate_u = expected_stc_change_rate(candidate_u).max(1e-6);
        let bits = (budget as f64 / rate_u) as usize;
        let slots_needed = match codec {
            StegoCodec::Hamming => required_slots(bits, DEFAULT_HAMMING_K),
            _ => StcTrellis::slots_for_params(bits, h, candidate_u),
        };
        let usable = slots_needed.min(ceiling);
        tier_limits[idx] = payload_bytes_from_slots(usable, codec, h, candidate_u);
        tier_u[idx] = candidate_u;
    }

    let recommended = tier_limits[level.tier_index()].min(max_raw_payload_bytes);
    let pct = change_percent(level);
    let recommended_u = tier_u[level.tier_index()];

    StegoCapacityInfo {
        format: label.to_string(),
        // `max_raw` is priced at the widest coding; the recommended tier is what
        // a caller should plan for.
        algorithm: format!("audio-stc-h{h}-u{recommended_u}"),
        total_elements: total,
        available_slots: available,
        max_raw_payload_bytes,
        max_raw_is_grouped: false,
        recommended_max_bytes: recommended,
        tier_limits,
        estimated_change_rate: expected_stc_change_rate(recommended_u),
        safety_level: level.as_str().to_string(),
        // Audio is bounded by a *percentage of slots*, not bits per pixel; the
        // field keeps its historic name and carries the fraction (0.015 = 1.5 %).
        safety_bpp_limit: pct / 100.0,
        is_estimated: false,
        media_info: None,
    }
}

/// Base header read result, before the extension area is known.
pub(crate) struct HeaderView {
    pub header: SpatialHeaderV4,
    pub base_bytes: [u8; PNG_AUDIO_BASE_BYTES],
}

const PNG_AUDIO_BASE_BYTES: usize = crate::stego::header::PNG_AUDIO_BASE_HEADER_BYTES;

/// Read and decode the 64-byte base header.
///
/// Only the fixed first 512 permutation positions are addressed, which is why
/// this works before `ext_len` is known.
pub(crate) fn read_base<C: SlotCarrier + ?Sized>(
    carrier: &C,
    mapping: Mapping,
    prepared: &PreparedCarrier,
    format_id: u8,
) -> Result<HeaderView, StrHideError> {
    let total = carrier.slot_count();
    if total < PNG_AUDIO_BASE_SLOTS {
        return Err(no_hidden());
    }
    let plan = SlotPlan::new(
        mapping,
        total,
        PNG_AUDIO_BASE_SLOTS,
        &prepared.locator.locate_seed,
    );
    let bytes = read_bytes(
        carrier,
        (0..PNG_AUDIO_BASE_SLOTS).map(|i| plan.header_slot(i)),
        PNG_AUDIO_BASE_BYTES,
    );
    let base_bytes: [u8; PNG_AUDIO_BASE_BYTES] = bytes.try_into().map_err(|_| no_hidden())?;
    let header = SpatialHeaderV4::decode(&base_bytes, format_id).map_err(|_| no_hidden())?;
    Ok(HeaderView { header, base_bytes })
}

/// Test-only: rewrite the 64-byte base header through the same keyed layout the
/// reader uses, so negative tests can forge authenticated fields.
#[cfg(test)]
pub(crate) fn rewrite_base_header<C: SlotCarrier + ?Sized>(
    carrier: &mut C,
    mapping: Mapping,
    prepared: &PreparedCarrier,
    bytes: &[u8; PNG_AUDIO_BASE_BYTES],
) -> Result<(), StrHideError> {
    let plan = SlotPlan::new(
        mapping,
        carrier.slot_count(),
        PNG_AUDIO_BASE_SLOTS,
        &prepared.locator.locate_seed,
    );
    let salt = u64::from_be_bytes(prepared.locator.locate_seed[..8].try_into().unwrap());
    for i in 0..PNG_AUDIO_BASE_SLOTS {
        let bit = (bytes[i / 8] >> (7 - (i % 8))) & 1;
        write_bit(carrier, plan.header_slot(i), bit, salt)?;
    }
    Ok(())
}

/// Test-only: rewrite the extension area through the same keyed layout the
/// reader uses.
///
/// The writer refuses critical TLVs, so the reader's fail-closed path can only
/// be exercised by forging the area a hostile writer would have produced.
#[cfg(test)]
pub(crate) fn rewrite_extension<C: SlotCarrier + ?Sized>(
    carrier: &mut C,
    mapping: Mapping,
    prepared: &PreparedCarrier,
    header_slots: usize,
    extension: &[u8],
) -> Result<(), StrHideError> {
    let plan = SlotPlan::new(
        mapping,
        carrier.slot_count(),
        header_slots,
        &prepared.locator.locate_seed,
    );
    let salt = u64::from_be_bytes(prepared.locator.locate_seed[..8].try_into().unwrap());
    write_bytes(
        carrier,
        (0..extension.len() * 8)
            .map(|i| plan.extension_slot(i))
            .collect(),
        extension,
        salt,
    )
}

/// Read and validate the extension area described by `header`.
fn read_extension<C: SlotCarrier + ?Sized>(
    carrier: &C,
    mapping: Mapping,
    prepared: &PreparedCarrier,
    header: &SpatialHeaderV4,
) -> Result<Vec<u8>, StrHideError> {
    let ext_len = header.ext_len as usize;
    if ext_len > MAX_EXT_BYTES {
        return Err(no_hidden());
    }
    let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * ext_len;
    if header_slots > carrier.slot_count() {
        return Err(no_hidden());
    }
    let plan = SlotPlan::new(
        mapping,
        carrier.slot_count(),
        header_slots,
        &prepared.locator.locate_seed,
    );
    let extension = read_bytes(
        carrier,
        (0..ext_len * 8).map(|i| plan.extension_slot(i)),
        ext_len,
    );
    header
        .validate_ext_critical(&extension)
        .map_err(|_| no_hidden())?;
    let records = parse_extension(&extension).map_err(|_| no_hidden())?;
    if records
        .iter()
        .any(|(type_id, _)| type_id & TLV_CRITICAL != 0)
    {
        return Err(no_hidden());
    }
    Ok(extension)
}

/// Codec choice and slot budget for one ciphertext against one carrier.
pub(crate) struct PlanShape {
    pub codec: StegoCodec,
    pub u: u8,
    pub h: u8,
    /// Body slots the matrix code will occupy.
    pub body_slots: usize,
}

/// Compute the codec, group size and slot budget for `ciphertext_len` bytes
/// against `available` body slots.
pub(crate) fn plan_body(
    ciphertext_len: usize,
    available: usize,
    h: u8,
    min_u: u8,
) -> Result<PlanShape, StrHideError> {
    let bits = ciphertext_len.saturating_mul(8);
    let (codec, u) = auto_select_codec(available, bits.max(1));
    let u = u.max(min_u);
    let body_slots = body_slots(bits, codec, h, u)?;
    Ok(PlanShape {
        codec,
        u,
        h,
        body_slots,
    })
}

/// Codec stored in the header's `codec_id` byte.
fn codec_of(header: &SpatialHeaderV4) -> StegoCodec {
    match header.codec_id {
        0 => StegoCodec::Hamming,
        _ => StegoCodec::Stc,
    }
}

/// Body slots the envelope in `header` needs, without reading any of them.
pub(crate) fn body_slots_for(header: &SpatialHeaderV4) -> Result<usize, StrHideError> {
    if CipherSuiteId::from_u16(header.suite_id).is_none() {
        return Err(no_hidden());
    }
    let codec = codec_of(header);
    if codec == StegoCodec::Hamming {
        return Err(no_hidden());
    }
    body_slots(
        header.body_len as usize * 8,
        codec,
        header.stc_h,
        header.stc_u,
    )
    .map_err(|_| no_hidden())
}

/// Binding context for the per-attempt session salt/nonce.
///
/// The FLAC carrier has to derive its body thinning phase *before* the envelope
/// is written, and that phase is folded with exactly the salt/nonce the header
/// will carry. Keeping the derivation here means the carrier builder and the
/// envelope writer cannot disagree about the pair used for one attempt.
pub(crate) fn fresh_binding_for(
    binding_input: &[u8],
    payload: &Payload<'_>,
    format_id: u8,
    extensions: &[Tlv],
) -> Result<Vec<u8>, StrHideError> {
    let extension = encode_extension_for_write(extensions)?;
    Ok(Freshness::seeded_binding(
        binding_input,
        payload.as_bytes(),
        format_id,
        &extension,
    ))
}

/// Embed `payload` into `carrier`, returning capacity metadata and change stats.
#[allow(clippy::too_many_arguments)]
pub(crate) fn embed<C: SlotCarrier + ?Sized>(
    carrier: &mut C,
    mapping: Mapping,
    payload: &Payload<'_>,
    prepared: &PreparedCarrier,
    domain: Option<&str>,
    suite: CipherSuiteId,
    extensions: &[Tlv],
    cipher: &WireCipherProfile,
    format_id: u8,
    safety: SafetyPolicy,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    control: &Control<'_>,
) -> Result<(StegoCapacityInfo, EmbedStats), StrHideError> {
    control.stage(Stage::Decode);
    control.check()?;

    let extension = encode_extension_for_write(extensions)?;
    let ext_len = extension.len();
    if ext_len > MAX_EXT_BYTES {
        return Err(StrHideError::General(format!(
            "Extension area of {ext_len} bytes exceeds the {MAX_EXT_BYTES}-byte header limit"
        )));
    }
    let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * ext_len;

    // `slot_count()` is what can be *written* (FLAC materialises only the slots
    // a payload needs); `capacity_slots()` is what the carrier could offer and
    // is what the capacity report and the codec choice must use.
    let total = carrier.slot_count();
    let capacity_total = carrier.capacity_slots();
    if total < header_slots {
        return Err(StrHideError::General(format!(
            "Audio carrier too small: {total} slots, the header alone needs {header_slots}"
        )));
    }

    let plaintext = build_plaintext(payload)?;
    let session = derive_l3_session_keys(cipher, suite, &prepared.master, &salt, domain)?;

    let ciphertext_len = plaintext.len() + suite.tag_len();
    if ciphertext_len > HEADER_LEN_MAX as usize {
        return Err(StrHideError::General(format!(
            "Envelope of {ciphertext_len} bytes exceeds the {HEADER_LEN_MAX}-byte header length field"
        )));
    }
    // The header and extension are carved out of the same permuted pool for
    // WAV. FLAC's header lives in subframe tails, a pool disjoint from the body
    // residuals, so extension slots do not shrink the body budget.
    let body_header_slots = match mapping {
        Mapping::Permuted => header_slots,
        Mapping::BodyPermuted => PNG_AUDIO_BASE_SLOTS,
    };
    let available = capacity_total.saturating_sub(body_header_slots);
    let shape = plan_body(
        ciphertext_len,
        available,
        DEFAULT_STC_H,
        carrier.min_group(),
    )?;
    if shape.codec == StegoCodec::Hamming {
        return Err(StrHideError::General(
            "Hamming coding is not supported for audio carriers".into(),
        ));
    }
    let needed_slots = shape.body_slots;
    if header_slots + needed_slots > total {
        return Err(StrHideError::General(format!(
            "Audio carrier capacity is too small: it exposes {total} slots but the payload needs {}",
            header_slots + needed_slots
        )));
    }
    if needed_slots > available {
        return Err(StrHideError::General(format!(
            "Audio carrier capacity insufficient: payload needs {needed_slots} body slots, {available} available"
        )));
    }
    if needed_slots > max_body_slots(shape.h, shape.u) {
        return Err(StrHideError::General(format!(
            "Payload needs {needed_slots} body slots, above the {} slot working-set ceiling; \
             reduce the payload size",
            max_body_slots(shape.h, shape.u)
        )));
    }

    // Safety tier: refuse (or warn by returning the info) before touching bytes.
    let info = capacity_info(
        capacity_total,
        body_header_slots,
        carrier.format_label(),
        safety.level,
        shape.h,
        shape.u,
        shape.codec,
        carrier.min_group(),
    );
    if safety.is_enforced() && payload.as_bytes().len() > info.recommended_max_bytes {
        return Err(StrHideError::SafetyThreshold {
            tier: safety.level,
            required_bytes: payload.as_bytes().len(),
            available_bytes: info.recommended_max_bytes,
        });
    }

    let params = CostParams::default();
    let any_critical = extensions.iter().any(Tlv::is_critical);
    let header = SpatialHeaderV4 {
        salt,
        nonce,
        body_len: ciphertext_len as u32,
        version: CONTENT_ENVELOPE_VERSION,
        flags: (if ext_len > 0 { FLAG_EXT_PRESENT } else { 0 })
            | (if any_critical { FLAG_EXT_CRITICAL } else { 0 }),
        format_id,
        algorithm_id: 0,
        suite_id: suite.as_u16(),
        codec_id: if shape.codec == StegoCodec::Hamming {
            0
        } else {
            1
        },
        stc_h: shape.h,
        stc_u: shape.u,
        channel_mode: 0,
        class_rule: 0,
        // The wire field is an odd window size: store `2 * half_width + 1`.
        // `CostParams::window` is a half-width, so this round-trips exactly and
        // stays inside the 1..=63 range the header validates.
        p1_window: (params.window as u16) * 2 + 1,
        p2_window: 1,
        neg_log2_epsilon: quantize_epsilon(params.epsilon),
        exclusion_permille: 0,
        sigma: 1.0,
        kernel_id: 0,
        ext_len: ext_len as u16,
    };
    let header_bytes = header.encode();
    let aad = build_v4_aad(format_id, &header_bytes, &extension);
    let ciphertext = encrypt_v4_with_aad(suite, &session.enc_key, &header.nonce, &aad, &plaintext)?;
    debug_assert_eq!(ciphertext.len(), ciphertext_len);

    control.stage(Stage::Solve);
    control.check()?;

    let plan = SlotPlan::new(mapping, total, header_slots, &prepared.locator.locate_seed);

    // Header, extension: one bit per slot, no error correction. The AEAD tag
    // authenticates the whole envelope, so a flipped header bit surfaces as
    // "no hidden data" rather than a wrong payload.
    let dir_salt = u64::from_be_bytes(session.perm_seed[..8].try_into().unwrap());
    write_bytes(
        carrier,
        (0..PNG_AUDIO_BASE_SLOTS)
            .map(|i| plan.header_slot(i))
            .collect(),
        &header_bytes,
        dir_salt,
    )?;
    if ext_len > 0 {
        write_bytes(
            carrier,
            (0..ext_len * 8).map(|i| plan.extension_slot(i)).collect(),
            &extension,
            dir_salt ^ 0x5DEE_CE66,
        )?;
    }

    // Body: matrix coding over the remaining plan slots.
    let slots: Vec<usize> = (0..needed_slots).map(|i| plan.body_slot(i)).collect();
    let vals: Vec<u8> = slots
        .iter()
        .map(|&s| (carrier.slot_value(s) & 1) as u8)
        .collect();
    let moves: Vec<Move> = slots.iter().map(|&s| carrier.move_legality(s)).collect();

    let trellis = StcTrellis::from_seed_grouped(session.stc_seed, shape.h, shape.u)?;
    let mut deltas = vec![0i8; needed_slots];
    let _flips = trellis.embed_with_cost_fn(
        &vals,
        &moves,
        |j| {
            // Symmetric perceptual cost, polarised direction: the two LSB moves
            // are equally audible, so a plain tie would send *every* change to
            // `+1` and leave a one-sided delta histogram -- a textbook
            // first-order steganalysis signature. Discounting the keyed
            // preferred direction by half keeps the per-slot position cost `c`
            // (so the trellis still ranks slots identically) while making the
            // `+1`/`-1` split balanced across the carrier.
            let c = carrier.cost(slots[j], &params);
            if direction_flip(slots[j], dir_salt ^ 0xA5A5_5A5A) {
                (c * 0.5, c)
            } else {
                (c, c * 0.5)
            }
        },
        &ciphertext,
        &mut deltas,
    )?;
    for (j, &delta) in deltas.iter().enumerate() {
        if delta != 0 {
            carrier.apply(slots[j], delta)?;
        }
    }

    carrier.finalize()?;

    let stats = EmbedStats {
        modified_slots: carrier.modified_slots(),
        total_candidate_slots: total,
    };
    Ok((info, stats))
}

/// Extract the payload, reusing a base header that was already read.
#[allow(clippy::too_many_arguments)]
pub(crate) fn extract_with_header<C: SlotCarrier + ?Sized>(
    carrier: &C,
    mapping: Mapping,
    prepared: &PreparedCarrier,
    domain: Option<&str>,
    cipher: &WireCipherProfile,
    format_id: u8,
    view: &HeaderView,
    limits: &crate::stego::params::ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    control.check()?;
    let header = &view.header;
    let extension = read_extension(carrier, mapping, prepared, header)?;
    let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * header.ext_len as usize;
    limits
        .validate_header(
            header.suite_id,
            header.body_len,
            header_slots,
            carrier.capacity_slots(),
        )
        .map_err(|_| no_hidden())?;

    let suite = CipherSuiteId::from_u16(header.suite_id).ok_or_else(no_hidden)?;
    let codec = codec_of(header);
    if codec == StegoCodec::Hamming {
        return Err(no_hidden());
    }
    let ciphertext_len = header.body_len as usize;
    let needed_slots = body_slots(ciphertext_len * 8, codec, header.stc_h, header.stc_u)
        .map_err(|_| no_hidden())?;
    if header_slots + needed_slots > carrier.slot_count() {
        return Err(no_hidden());
    }

    let session = derive_l3_session_keys(cipher, suite, &prepared.master, &header.salt, domain)
        .map_err(|_| no_hidden())?;
    let plan = SlotPlan::new(
        mapping,
        carrier.slot_count(),
        header_slots,
        &prepared.locator.locate_seed,
    );
    let vals: Vec<u8> = (0..needed_slots)
        .map(|i| (carrier.slot_value(plan.body_slot(i)) & 1) as u8)
        .collect();

    let trellis = StcTrellis::from_seed_grouped(session.stc_seed, header.stc_h, header.stc_u)
        .map_err(|_| no_hidden())?;
    let ciphertext = trellis.extract(&vals, ciphertext_len * 8);

    let aad = build_v4_aad(format_id, &view.base_bytes, &extension);
    unpack_v4_envelope_parts(
        suite,
        &session.enc_key,
        &header.nonce,
        &aad,
        &ciphertext,
        limits,
    )
}

/// Extract the payload from `carrier` in one pass (WAV).
#[allow(clippy::too_many_arguments)]
pub(crate) fn extract<C: SlotCarrier + ?Sized>(
    carrier: &C,
    mapping: Mapping,
    prepared: &PreparedCarrier,
    domain: Option<&str>,
    cipher: &WireCipherProfile,
    format_id: u8,
    limits: &crate::stego::params::ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    let view = read_base(carrier, mapping, prepared, format_id)?;
    extract_with_header(
        carrier, mapping, prepared, domain, cipher, format_id, &view, limits, control,
    )
}

/// Report the carrier's embedding capacity.
///
/// `extensions` is the same list the embedder would receive: reserving an
/// extension area reduces the body budget for WAV and raises the subframe-tail
/// requirement for FLAC, so the report and the embed agree.
pub(crate) fn probe<C: SlotCarrier + ?Sized>(
    carrier: &C,
    mapping: Mapping,
    level: SafetyLevel,
    prepared: &PreparedCarrier,
    extensions: &[Tlv],
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    // The capacity arithmetic does not depend on the locator seed, but taking
    // the same `prepared` value as `embed` keeps the probe and the writer on
    // one credential / `pre_salt` / extension path by construction.
    let _ = prepared;
    control.check()?;
    let extension = encode_extension_for_write(extensions)?;
    if extension.len() > MAX_EXT_BYTES {
        return Err(StrHideError::General(format!(
            "Extension area of {} bytes exceeds the {MAX_EXT_BYTES}-byte header limit",
            extension.len()
        )));
    }
    let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * extension.len();
    if header_slots > carrier.header_capacity() {
        return Err(StrHideError::General(format!(
            "Audio carrier too small: {} header slots available, the header needs {header_slots}",
            carrier.header_capacity()
        )));
    }
    let total = carrier.capacity_slots();
    // Mirror `embed`: the report must price the same header slots the writer
    // carves out, otherwise FLAC with an extension under-reports its body.
    let body_header_slots = match mapping {
        Mapping::Permuted => header_slots,
        Mapping::BodyPermuted => PNG_AUDIO_BASE_SLOTS,
    };
    let available = total.saturating_sub(body_header_slots);
    if available < 8 {
        return Err(StrHideError::General(format!(
            "Audio carrier too small: {available} body slots available"
        )));
    }
    // Advertise the codec the embedder would pick for a payload that fills the
    // tier: `u` falls as the payload grows, and so does the change rate.
    let (codec, u) = auto_select_codec(available, available.max(1));
    let u = u.max(carrier.min_group());
    let h = DEFAULT_STC_H;
    Ok(capacity_info(
        total,
        body_header_slots,
        carrier.format_label(),
        level,
        h,
        u,
        codec,
        carrier.min_group(),
    ))
}

/// Inspect the carrier header without extracting the payload.
#[allow(clippy::too_many_arguments)]
pub(crate) fn inspect_with_header<C: SlotCarrier + ?Sized>(
    carrier: &C,
    mapping: Mapping,
    prepared: &PreparedCarrier,
    view: &HeaderView,
    limits: &crate::stego::params::ExtractParams,
) -> StegoHeaderInfo {
    let mut info = StegoHeaderInfo::empty(carrier.format_label());
    let header = &view.header;
    if read_extension(carrier, mapping, prepared, header).is_err() {
        return info;
    }
    let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * header.ext_len as usize;
    if limits
        .validate_header(
            header.suite_id,
            header.body_len,
            header_slots,
            carrier.capacity_slots(),
        )
        .is_err()
    {
        return info;
    }
    let needed = match body_slots_for(header) {
        Ok(needed) => needed,
        Err(_) => return info,
    };
    if header_slots + needed > carrier.slot_count() {
        return info;
    }

    info.has_hidden_data = true;
    info.note = carrier.describe();
    info.algorithm = Some("audio-stc".into());
    info.codec = Some(format!("stc-h{}-u{}", header.stc_h, header.stc_u));
    info.envelope_len = Some(header.body_len as usize);
    info.payload_len = Some((header.body_len as usize).saturating_sub(BODY_OVERHEAD));
    info
}

/// Inspect the carrier header in one pass (WAV).
pub(crate) fn inspect<C: SlotCarrier + ?Sized>(
    carrier: &C,
    mapping: Mapping,
    prepared: &PreparedCarrier,
    format_id: u8,
    limits: &crate::stego::params::ExtractParams,
) -> StegoHeaderInfo {
    let view = match read_base(carrier, mapping, prepared, format_id) {
        Ok(view) => view,
        Err(_) => return StegoHeaderInfo::empty(carrier.format_label()),
    };
    inspect_with_header(carrier, mapping, prepared, &view, limits)
}

/// Does the caller's PBKDF2 policy forbid the fixed V4 L1 cost?
pub(crate) fn pbkdf2_policy_blocks(
    cred: Credential<'_>,
    limits: &crate::stego::params::ExtractParams,
) -> bool {
    matches!(cred, Credential::Password(_))
        && limits.max_pbkdf2_iterations < crate::crypto::CONTENT_L1_PBKDF2_ITERATIONS
}

/// Verification report for the "policy cannot pay L1" case.
pub(crate) fn policy_failure_result(label: &str) -> StegoVerifyResult {
    let mut levels = Vec::with_capacity(3);
    levels.push(VerifyLevel {
        level: 1,
        name: "carrier".into(),
        ok: true,
        message: Some(format!("{label} carrier parsed")),
    });
    levels.push(VerifyLevel {
        level: 2,
        name: "header".into(),
        ok: false,
        message: Some(format!(
            "PBKDF2 iteration limit is below the V4 L1 cost {}",
            crate::crypto::CONTENT_L1_PBKDF2_ITERATIONS
        )),
    });
    levels.push(VerifyLevel {
        level: 3,
        name: "payload".into(),
        ok: false,
        message: Some("Skipped due to level 2 policy failure".into()),
    });
    StegoVerifyResult::new(label, levels)
}

/// Three-level verification: container sanity, header readability, payload integrity.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify<C: SlotCarrier + ?Sized>(
    carrier: &C,
    mapping: Mapping,
    prepared: &PreparedCarrier,
    domain: Option<&str>,
    cipher: &WireCipherProfile,
    format_id: u8,
    limits: &crate::stego::params::ExtractParams,
    control: &Control<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    control.check()?;
    let mut levels = Vec::with_capacity(3);

    levels.push(VerifyLevel {
        level: 1,
        name: "carrier".into(),
        ok: true,
        message: Some(format!(
            "{} carrier parsed: {} slots",
            carrier.format_label(),
            carrier.slot_count()
        )),
    });

    let inspected = inspect(carrier, mapping, prepared, format_id, limits);
    levels.push(VerifyLevel {
        level: 2,
        name: "header".into(),
        ok: inspected.has_hidden_data,
        message: Some(if inspected.has_hidden_data {
            format!(
                "Envelope of {:?} bytes ({:?} payload)",
                inspected.envelope_len, inspected.payload_len
            )
        } else {
            "No readable header (wrong password or no payload)".into()
        }),
    });

    let (ok, message) = match extract(
        carrier, mapping, prepared, domain, cipher, format_id, limits, control,
    ) {
        Ok(payload) => (
            true,
            format!("Payload authenticated: {} bytes", payload.as_bytes().len()),
        ),
        Err(StrHideError::NoHiddenData(_)) => (false, "No authenticated payload".into()),
        Err(e) => (false, format!("Extraction failed: {e}")),
    };
    levels.push(VerifyLevel {
        level: 3,
        name: "payload".into(),
        ok,
        message: Some(message),
    });

    Ok(StegoVerifyResult::new(carrier.format_label(), levels))
}

#[inline]
fn no_hidden() -> StrHideError {
    StrHideError::NoHiddenData("No valid payload found".into())
}

/// The same error as `no_hidden`, for callers outside this module.
pub(crate) fn no_hidden_data() -> StrHideError {
    no_hidden()
}
