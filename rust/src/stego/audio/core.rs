//! Shared embedding driver for the audio content engines.
//!
//! Every audio carrier (WAV PCM today, FLAC residuals next) is reduced to one
//! abstraction: an ordered array of **slots**, each of which holds a signed
//! integer whose parity is the embedded bit and which can be moved by `±1`
//! without changing anything else. That is exactly what the matrix-coding layer
//! already expects, so the whole envelope / header / STC stack is reused
//! unchanged from the image engines.
//!
//! # Layout (identical to the spatial codec)
//!
//! ```text
//! plan slot    0 .. 256   32-byte base header: salt(16) | nonce(12) | word(4)
//! plan slot  256 .. 512   32-byte feature word (codec, h, u, cost parameters)
//! plan slot  512 .. 512+n ciphertext body, STC-coded
//! ```
//!
//! `plan slot i` is `perm.at(i)`, a keyed pseudo-random permutation of the
//! carrier's slot indices, so the payload is spread over the whole file and its
//! position is unguessable without the password.
//!
//! # Why the header can be read before anything is known
//!
//! The header occupies the *first* 512 permutation positions, and the
//! permutation is derived from the password alone -- no carrier content, no
//! salt. A reader therefore finds the header before it knows the codec, exactly
//! like the spatial codec. Everything the body needs (codec, `h`, `u`, cost
//! parameters) travels in the feature word.
//!
//! # Slot count is content-independent
//!
//! The body length is `slots_for(ciphertext bits)` and the permutation is over
//! the *whole* carrier, so a reader that recovers `total_len` from the header
//! addresses the same slots the writer used. Nothing in this module depends on
//! the payload's statistical profile.

use crate::SafetyPolicy;
use crate::core::control::{Control, Stage};
use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::params::SafetyLevel;
use crate::stego::audio::cost::CostParams;
use crate::stego::audio::perm::KeyedPermutation;
use crate::stego::coding::{
    DEFAULT_HAMMING_K, DEFAULT_STC_H, Move, StcTrellis, auto_select_codec,
    expected_stc_change_rate, hamming_extract_bytes, required_slots, slots_for_codec,
};
use crate::stego::envelope::{
    BODY_OVERHEAD, Freshness, HEADER_OVERHEAD, build_plaintext, encrypt_with_aad,
    unpack_envelope_parts,
};
use crate::stego::format::{AudioFormatProfile, body_keys, derive_master};
use crate::stego::header::{
    FEATURE_WORD_BYTES, FEATURE_WORD_SLOTS, FeatureWord, HEADER_LEN_MAX, HEADER_V2_ESCAPE_H,
    V2_TOTAL_HEADER_SLOTS, decode_header_word, encode_header_word,
};
use crate::stego::options::{StegoHeaderInfo, StegoVerifyResult, VerifyLevel};
use crate::stego::{EmbedStats, StegoCapacityInfo, StegoCodec};

/// Bytes of the base header: salt(16) + nonce(12) + length word(4).
const BASE_HEADER_BYTES: usize = 32;
/// Slots carrying the base header, one bit each.
const BASE_HEADER_SLOTS: usize = BASE_HEADER_BYTES * 8;

const _: () = assert!(BASE_HEADER_SLOTS + FEATURE_WORD_SLOTS == V2_TOTAL_HEADER_SLOTS);

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

    /// One-line human description of the carrier (depth, channels, duration),
    /// surfaced in `inspect` output. `None` when the format has nothing useful
    /// to add.
    fn describe(&self) -> Option<String> {
        None
    }
}

/// The keyed slot plan shared by writer and reader.
struct SlotPlan {
    perm: KeyedPermutation,
}

impl SlotPlan {
    fn new(slot_count: usize, header_seed: &[u8; 32]) -> Self {
        Self {
            perm: KeyedPermutation::new(header_seed, slot_count),
        }
    }

    #[inline]
    fn header_slot(&self, i: usize) -> usize {
        self.perm.at(i)
    }

    #[inline]
    fn feature_slot(&self, i: usize) -> usize {
        self.perm.at(BASE_HEADER_SLOTS + i)
    }

    #[inline]
    fn body_slot(&self, i: usize) -> usize {
        self.perm.at(V2_TOTAL_HEADER_SLOTS + i)
    }
}

/// Byte of the base header / feature word assembled from slot parities.
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

/// Build the capacity report shared by `probe` and `embed`.
fn capacity_info<C: SlotCarrier + ?Sized>(
    carrier: &C,
    level: SafetyLevel,
    h: u8,
    u: u8,
    codec: StegoCodec,
) -> StegoCapacityInfo {
    let total = carrier.slot_count();
    let available = total.saturating_sub(V2_TOTAL_HEADER_SLOTS);

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
        let mut candidate_u = u;
        for _ in 0..3 {
            let rate_u = expected_stc_change_rate(candidate_u).max(1e-6);
            let bits = (budget as f64 / rate_u) as usize;
            let (_, next_u) = auto_select_codec(available, bits.max(1));
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
        format: carrier.format_label().to_string(),
        // `max_raw` is priced at `u = 1` (the widest but least efficient
        // coding); the recommended tier is what a caller should plan for.
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

/// What a successful header read produced.
struct ReadHeader {
    salt: [u8; crate::stego::envelope::SALT_LEN],
    nonce: [u8; crate::stego::envelope::NONCE_LEN],
    total_len: u32,
    codec: StegoCodec,
    h: u8,
    u: u8,
    header_bytes: [u8; BASE_HEADER_BYTES],
    feature_bytes: [u8; FEATURE_WORD_BYTES],
}

fn read_header<C: SlotCarrier + ?Sized>(
    carrier: &C,
    plan: &SlotPlan,
) -> Result<ReadHeader, StrHideError> {
    let bytes = read_bytes(
        carrier,
        (0..BASE_HEADER_SLOTS).map(|i| plan.header_slot(i)),
        BASE_HEADER_BYTES,
    );
    let word = u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
    let (total_len, _codec_id, _h_escape) = decode_header_word(word);
    if total_len as usize <= HEADER_OVERHEAD {
        return Err(StrHideError::NoHiddenData(
            "No valid payload found or incorrect password".into(),
        ));
    }

    let feature = read_bytes(
        carrier,
        (0..FEATURE_WORD_SLOTS).map(|i| plan.feature_slot(i)),
        FEATURE_WORD_BYTES,
    );
    let feature_array: [u8; FEATURE_WORD_BYTES] = feature
        .try_into()
        .map_err(|_| StrHideError::CorruptedData("feature word size mismatch".into()))?;
    let fw = FeatureWord::decode(&feature_array).map_err(|_| {
        StrHideError::NoHiddenData("No valid payload found or incorrect password".into())
    })?;

    let mut salt = [0u8; crate::stego::envelope::SALT_LEN];
    salt.copy_from_slice(&bytes[..crate::stego::envelope::SALT_LEN]);
    let mut nonce = [0u8; crate::stego::envelope::NONCE_LEN];
    nonce.copy_from_slice(
        &bytes[crate::stego::envelope::SALT_LEN
            ..crate::stego::envelope::SALT_LEN + crate::stego::envelope::NONCE_LEN],
    );

    let header_array: [u8; BASE_HEADER_BYTES] = bytes
        .try_into()
        .map_err(|_| StrHideError::CorruptedData("header size mismatch".into()))?;

    Ok(ReadHeader {
        salt,
        nonce,
        total_len,
        codec: fw.codec,
        h: fw.h,
        u: fw.u,
        header_bytes: header_array,
        feature_bytes: feature_array,
    })
}

/// Embed `payload` into `carrier`, returning capacity metadata and change stats.
#[allow(clippy::too_many_arguments)]
pub(crate) fn embed<C: SlotCarrier + ?Sized>(
    carrier: &mut C,
    payload: &Payload<'_>,
    secret: Option<&str>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    safety: SafetyPolicy,
    freshness: Freshness,
    binding: &[u8],
    control: &Control<'_>,
) -> Result<(StegoCapacityInfo, EmbedStats), StrHideError> {
    control.stage(Stage::Decode);
    control.check()?;

    let total = carrier.slot_count();
    if total < V2_TOTAL_HEADER_SLOTS + 64 {
        return Err(StrHideError::General(format!(
            "Audio carrier too small: {total} slots, the header alone needs {V2_TOTAL_HEADER_SLOTS}"
        )));
    }

    let suite = profile.body.default_suite();
    let plaintext = build_plaintext(payload)?;
    let salt = freshness.salt(0, binding);
    let nonce = freshness.nonce(0, binding);
    let master = derive_master(suite, secret.unwrap_or(profile.fallback_secret), &salt)?;
    let (enc_key, perm_seed) = body_keys(profile.body, &master, &salt, domain);

    let ciphertext_len = plaintext.len() + suite.tag_len();
    let total_len = HEADER_OVERHEAD + ciphertext_len;
    if total_len > HEADER_LEN_MAX as usize {
        return Err(StrHideError::General(format!(
            "Envelope of {total_len} bytes exceeds the {HEADER_LEN_MAX}-byte header length field"
        )));
    }

    let available = total - V2_TOTAL_HEADER_SLOTS;
    let bits = ciphertext_len * 8;
    let (codec, u) = auto_select_codec(available, bits);
    let h = DEFAULT_STC_H;

    let needed_slots = body_slots(bits, codec, h, u)?;
    if needed_slots > available {
        return Err(StrHideError::General(format!(
            "Audio carrier capacity insufficient: payload needs {needed_slots} body slots, {available} available"
        )));
    }
    if needed_slots > max_body_slots(h, u) {
        return Err(StrHideError::General(format!(
            "Payload needs {needed_slots} body slots, above the {} slot working-set ceiling; \
             reduce the payload size",
            max_body_slots(h, u)
        )));
    }

    // Safety tier: refuse (or warn by returning the info) before touching bytes.
    let info = capacity_info(carrier, safety.level, h, u, codec);
    if safety.is_enforced() && payload.as_bytes().len() > info.recommended_max_bytes {
        return Err(StrHideError::SafetyThreshold {
            tier: safety.level,
            required_bytes: payload.as_bytes().len(),
            available_bytes: info.recommended_max_bytes,
        });
    }

    let header_word = encode_header_word(total_len as u32, codec, HEADER_V2_ESCAPE_H, u);
    let mut header_bytes = [0u8; BASE_HEADER_BYTES];
    header_bytes[..crate::stego::envelope::SALT_LEN].copy_from_slice(&salt);
    header_bytes[crate::stego::envelope::SALT_LEN
        ..crate::stego::envelope::SALT_LEN + crate::stego::envelope::NONCE_LEN]
        .copy_from_slice(&nonce);
    header_bytes[28..32].copy_from_slice(&header_word.to_be_bytes());

    let params = CostParams::default();
    let feature = FeatureWord {
        version: 3,
        codec,
        u,
        h,
        channel_mode: 0,
        class_rule: 0,
        // The wire field is an odd window size: store `2 * half_width + 1`.
        // `CostParams::window` is a half-width, so this round-trips exactly and
        // stays inside the 1..=63 range the feature word validates.
        p1_window: (params.window as u16) * 2 + 1,
        p2_window: 1,
        neg_log2_epsilon: FeatureWord::quantize_epsilon(params.epsilon),
        exclusion_permille: 0,
        // 0 = the built-in perceptual cost model. Audio has exactly one model
        // today; the field keeps the header self-describing for a future one.
        algorithm_id: 0,
        sigma: 1.0,
        kernel_id: 0,
    };
    let feature_bytes = feature.encode();

    let mut aad = Vec::with_capacity(BASE_HEADER_BYTES + FEATURE_WORD_BYTES);
    aad.extend_from_slice(&header_bytes);
    aad.extend_from_slice(&feature_bytes);
    let ciphertext = encrypt_with_aad(suite, &enc_key, &nonce, &aad, &plaintext)?;
    debug_assert_eq!(ciphertext.len(), ciphertext_len);

    control.stage(Stage::Solve);
    control.check()?;

    let header_seed =
        crate::stego::envelope::derive_header_perm_seed_audio(secret, domain, profile);
    let plan = SlotPlan::new(total, &header_seed);

    // Header and feature word: one bit per slot, no error correction (the AEAD
    // tag authenticates the whole envelope, so a flipped header bit surfaces as
    // "no hidden data" rather than a wrong payload).
    let dir_salt = u64::from_be_bytes(perm_seed[..8].try_into().unwrap());
    write_bytes(
        carrier,
        (0..BASE_HEADER_SLOTS)
            .map(|i| plan.header_slot(i))
            .collect(),
        &header_bytes,
        dir_salt,
    )?;
    write_bytes(
        carrier,
        (0..FEATURE_WORD_SLOTS)
            .map(|i| plan.feature_slot(i))
            .collect(),
        &feature_bytes,
        dir_salt ^ 0x5DEE_CE66,
    )?;

    // Body: matrix coding over the remaining plan slots.
    let stc_seed =
        crate::stego::envelope::derive_stc_seed_with_label(&perm_seed, &salt, profile.stc_label);
    let body_slots: Vec<usize> = (0..needed_slots).map(|i| plan.body_slot(i)).collect();
    let vals: Vec<u8> = body_slots
        .iter()
        .map(|&s| (carrier.slot_value(s) & 1) as u8)
        .collect();
    let moves: Vec<Move> = body_slots
        .iter()
        .map(|&s| carrier.move_legality(s))
        .collect();

    let flips = match codec {
        StegoCodec::Hamming => {
            // Hamming needs mutable slot values, which the abstract carrier
            // does not expose. Audio only ever selects STC; keep the arm
            // explicit so a future codec knob cannot silently mis-encode.
            return Err(StrHideError::General(
                "Hamming coding is not supported for audio carriers".into(),
            ));
        }
        StegoCodec::Stc | StegoCodec::Auto => {
            let trellis = StcTrellis::from_seed_grouped(stc_seed, h, u)?;
            let mut deltas = vec![0i8; needed_slots];
            let flips = trellis.embed_with_cost_fn(
                &vals,
                &moves,
                |j| {
                    // Symmetric perceptual cost, polarised direction: the two
                    // LSB moves are equally audible, so a plain tie would send
                    // *every* change to `+1` and leave a one-sided delta
                    // histogram -- a textbook first-order steganalysis
                    // signature. Discounting the keyed preferred direction by
                    // half keeps the per-slot position cost `c` (so the trellis
                    // still ranks slots identically) while making the `+1`/`-1`
                    // split balanced across the carrier.
                    let c = carrier.cost(body_slots[j], &params);
                    if direction_flip(body_slots[j], dir_salt ^ 0xA5A5_5A5A) {
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
                    carrier.apply(body_slots[j], delta)?;
                }
            }
            flips
        }
    };

    carrier.finalize()?;

    let stats = EmbedStats {
        modified_slots: carrier.modified_slots(),
        total_candidate_slots: total,
    };
    let _ = flips;
    Ok((info, stats))
}

/// Extract the payload from `carrier`.
pub(crate) fn extract<C: SlotCarrier + ?Sized>(
    carrier: &C,
    secret: Option<&str>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    control.check()?;
    let total = carrier.slot_count();
    if total < V2_TOTAL_HEADER_SLOTS {
        return Err(StrHideError::NoHiddenData(
            "No valid payload found or incorrect password".into(),
        ));
    }
    let header_seed =
        crate::stego::envelope::derive_header_perm_seed_audio(secret, domain, profile);
    let plan = SlotPlan::new(total, &header_seed);
    let header = read_header(carrier, &plan)?;

    let ciphertext_len = (header.total_len as usize).saturating_sub(HEADER_OVERHEAD);
    if ciphertext_len == 0 {
        return Err(StrHideError::NoHiddenData(
            "No valid payload found or incorrect password".into(),
        ));
    }
    let bits = ciphertext_len * 8;
    let needed_slots = body_slots(bits, header.codec, header.h, header.u)?;
    if V2_TOTAL_HEADER_SLOTS + needed_slots > total {
        return Err(StrHideError::NoHiddenData(
            "No valid payload found or incorrect password".into(),
        ));
    }

    let suite = profile.body.default_suite();
    let master = derive_master(
        suite,
        secret.unwrap_or(profile.fallback_secret),
        &header.salt,
    )?;
    let (enc_key, _perm_seed) = body_keys(profile.body, &master, &header.salt, domain);

    let vals: Vec<u8> = (0..needed_slots)
        .map(|i| (carrier.slot_value(plan.body_slot(i)) & 1) as u8)
        .collect();

    let ciphertext = match header.codec {
        StegoCodec::Hamming => hamming_extract_bytes(&vals, ciphertext_len, DEFAULT_HAMMING_K)?,
        StegoCodec::Stc | StegoCodec::Auto => {
            let stc_seed = crate::stego::envelope::derive_stc_seed_with_label(
                &_perm_seed,
                &header.salt,
                profile.stc_label,
            );
            let trellis = StcTrellis::from_seed_grouped(stc_seed, header.h, header.u)?;
            trellis.extract(&vals, bits)
        }
    };

    let mut aad = Vec::with_capacity(BASE_HEADER_BYTES + FEATURE_WORD_BYTES);
    aad.extend_from_slice(&header.header_bytes);
    aad.extend_from_slice(&header.feature_bytes);
    unpack_envelope_parts(suite, &enc_key, &header.nonce, &aad, &ciphertext)
}

/// Report the carrier's embedding capacity.
pub(crate) fn probe<C: SlotCarrier + ?Sized>(
    carrier: &C,
    level: SafetyLevel,
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    control.check()?;
    let total = carrier.slot_count();
    if total < V2_TOTAL_HEADER_SLOTS + 8 {
        return Err(StrHideError::General(format!(
            "Audio carrier too small: {total} slots, the header alone needs {V2_TOTAL_HEADER_SLOTS}"
        )));
    }
    let available = total - V2_TOTAL_HEADER_SLOTS;
    // Advertise the codec the embedder would pick for a payload that fills the
    // tier: `u` falls as the payload grows, and so does the change rate.
    let (codec, u) = auto_select_codec(available, available.max(1));
    let h = DEFAULT_STC_H;
    Ok(capacity_info(carrier, level, h, u, codec))
}

/// Inspect the carrier header without extracting the payload.
pub(crate) fn inspect<C: SlotCarrier + ?Sized>(
    carrier: &C,
    secret: Option<&str>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    control.check()?;
    let total = carrier.slot_count();
    let mut info = StegoHeaderInfo::empty(carrier.format_label());
    if total < V2_TOTAL_HEADER_SLOTS {
        return Ok(info);
    }
    let header_seed =
        crate::stego::envelope::derive_header_perm_seed_audio(secret, domain, profile);
    let plan = SlotPlan::new(total, &header_seed);
    let header = match read_header(carrier, &plan) {
        Ok(h) => h,
        // A wrong password simply relocates the header; report "nothing here"
        // exactly like the image engines rather than leaking a distinction.
        Err(_) => return Ok(info),
    };

    let ciphertext_len = (header.total_len as usize).saturating_sub(HEADER_OVERHEAD);
    let bits = ciphertext_len * 8;
    let needed = body_slots(bits, header.codec, header.h, header.u).unwrap_or(usize::MAX);
    if V2_TOTAL_HEADER_SLOTS + needed > total {
        return Ok(info);
    }

    info.has_hidden_data = true;
    info.note = carrier.describe();
    info.algorithm = Some("audio-stc".into());
    info.codec = Some(header.codec.describe(header.h, header.u));
    info.envelope_len = Some(header.total_len as usize);
    info.payload_len = Some(
        (header.total_len as usize)
            .saturating_sub(HEADER_OVERHEAD)
            .saturating_sub(BODY_OVERHEAD),
    );
    Ok(info)
}

/// Three-level verification: container sanity, header readability, payload integrity.
pub(crate) fn verify<C: SlotCarrier + ?Sized>(
    carrier: &C,
    secret: Option<&str>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
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

    let inspected = inspect(carrier, secret, domain, profile, control)?;
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

    let (ok, message) = match extract(carrier, secret, domain, profile, control) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_and_feature_slots_never_overlap_body_slots() {
        // The plan positions are a permutation, so as long as the three ranges
        // are disjoint the writer cannot clobber its own header.
        assert_eq!(BASE_HEADER_SLOTS, 256);
        assert_eq!(
            BASE_HEADER_SLOTS + FEATURE_WORD_SLOTS,
            V2_TOTAL_HEADER_SLOTS
        );
        assert_eq!(V2_TOTAL_HEADER_SLOTS, 512);
    }

    #[test]
    fn working_set_grows_with_the_constraint_height() {
        let small = working_set_bytes(1_000_000, 4, 3);
        let large = working_set_bytes(1_000_000, 8, 3);
        assert!(large > small);
        assert!(max_body_slots(8, 3) > 1_000_000);
    }

    #[test]
    fn capacity_shrinks_as_the_tier_tightens() {
        assert!(change_percent(SafetyLevel::Paranoid) < change_percent(SafetyLevel::High));
        assert!(change_percent(SafetyLevel::High) < change_percent(SafetyLevel::Balanced));
    }

    #[test]
    fn payload_bytes_never_exceed_the_slot_budget() {
        for slots in [1_000usize, 100_000, 1_000_000] {
            for u in 1..=3u8 {
                let bytes = payload_bytes_from_slots(slots, StegoCodec::Stc, 8, u);
                if bytes == 0 {
                    continue;
                }
                let needed = StcTrellis::slots_for_params(bytes * 8 + BODY_OVERHEAD * 8, 8, u);
                assert!(
                    needed <= slots,
                    "u={u} slots={slots}: {bytes} bytes need {needed} slots"
                );
            }
        }
    }
}
