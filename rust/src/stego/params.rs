//! Steganography configuration parameters and fine-tuning interfaces.
//!
//! Designed to allow runtime parameter adjustment, custom confusion/anti-detection
//! weights, and future configuration file deserialization.

use serde::{Deserialize, Serialize};

use crate::errors::StrHideError;
use crate::params::Profile;
use crate::stego::envelope::Freshness;

/// Matrix-coding layer used to place payload bits into candidate slots.
///
/// Both variants write "a slot's LSB equals a payload bit"; they differ only in
/// *which* slots get changed, and therefore in distortion:
///
/// - [`Hamming`](Self::Hamming): fixed blocks of seven slots carry three bits,
///   at most one slot per block is touched (0.2917 changes/bit). Block-local,
///   so a block may have to flip an expensive slot even though a cheap one is
///   available elsewhere.
/// - [`Stc`](Self::Stc): one global trellis (Viterbi) over the whole slot
///   sequence, minimising the *cost-weighted* distortion subject to
///   `H x = message`. Change count is higher (~0.5/bit) but every change lands
///   on the cheapest slots.
///
/// The choice is **not** self-describing: it is recorded in two spare bits of
/// the envelope header (see `png::engine`), so extraction never needs to be
/// told which one was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StegoCodec {
    /// Automatic adaptive selection (default): dynamically chooses optimal STC group
    /// size (u=3, u=2, or u=1) based on carrier slot availability and payload size.
    #[default]
    Auto,
    /// `(7,3)` Hamming matrix embedding.
    Hamming,
    /// Syndrome-trellis codes (explicit).
    Stc,
}

impl StegoCodec {
    /// Stable identifier written into the envelope header.
    pub fn id(self) -> u32 {
        match self {
            StegoCodec::Hamming => 0,
            StegoCodec::Stc | StegoCodec::Auto => 1,
        }
    }

    /// Decode a header identifier; unknown values are an error rather than a
    /// silent fallback, because a wrong guess can only ever fail downstream.
    pub fn from_id(id: u32) -> Result<Self, StrHideError> {
        match id {
            0 => Ok(StegoCodec::Hamming),
            1 => Ok(StegoCodec::Stc),
            other => Err(StrHideError::CorruptedData(format!(
                "Unknown matrix-coding identifier {other} in envelope header"
            ))),
        }
    }

    /// Human-readable form for diagnostics ("Auto (STC-adaptive)", "Hamming k=3", "STC h=8 u=2").
    pub fn describe(self, stc_h: u8, stc_u: u8) -> String {
        match self {
            StegoCodec::Auto => "Auto (STC-adaptive)".into(),
            StegoCodec::Hamming => {
                format!("Hamming k={}", crate::stego::coding::DEFAULT_HAMMING_K)
            }
            StegoCodec::Stc if stc_u == 0 => format!("STC h={stc_h} (auto u)"),
            StegoCodec::Stc if stc_u == 1 => format!("STC h={stc_h}"),
            StegoCodec::Stc => format!("STC h={stc_h} u={stc_u}"),
        }
    }
}

/// Capacity safety tier controlling the maximum recommended bits per pixel (bpp).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SafetyLevel {
    /// Paranoid security tier: bpp <= 0.06 bits/pixel (approx r >= 11.5), ultra-low detection risk.
    Paranoid,
    /// High security tier (recommended default): bpp <= 0.10 bits/pixel (approx r >= 6.9).
    #[default]
    High,
    /// Balanced tier: bpp <= 0.15 bits/pixel (approx r >= 4.6). Legacy boundary, not claimed undetectable.
    Balanced,
}

impl std::str::FromStr for SafetyLevel {
    type Err = StrHideError;

    /// Parse a safety tier: case-insensitive `paranoid` / `high` / `balanced`,
    /// or the numeric aliases `0` (paranoid), `1` (high), `2` (balanced).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "0" | "paranoid" | "Paranoid" | "PARANOID" => Ok(SafetyLevel::Paranoid),
            "1" | "high" | "High" | "HIGH" => Ok(SafetyLevel::High),
            "2" | "balanced" | "Balanced" | "BALANCED" => Ok(SafetyLevel::Balanced),
            other => Err(StrHideError::General(format!(
                "Invalid safety level '{other}'. Supported: 'paranoid' (0), 'high' (1, default), 'balanced' (2)"
            ))),
        }
    }
}

impl SafetyLevel {
    /// Maximum bits per pixel (bpp) allowed under this safety level.
    pub fn bpp_limit(self) -> f64 {
        match self {
            SafetyLevel::Paranoid => 0.06,
            SafetyLevel::High => 0.10,
            SafetyLevel::Balanced => 0.15,
        }
    }

    /// Target candidate-to-message ratio `r = slots / bits`.
    /// Calibrated against the DIV2K natural image dataset in Phase 0 (c_density ≈ 0.69).
    pub fn target_ratio(self) -> f64 {
        match self {
            SafetyLevel::Paranoid => 11.5,
            SafetyLevel::High => 6.9,
            SafetyLevel::Balanced => 4.6,
        }
    }

    /// Parse from case-insensitive string ("high", "balanced", "paranoid").
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "paranoid" => Some(SafetyLevel::Paranoid),
            "high" => Some(SafetyLevel::High),
            "balanced" => Some(SafetyLevel::Balanced),
            _ => None,
        }
    }

    /// Display string for diagnostics and CLI output.
    pub fn as_str(self) -> &'static str {
        match self {
            SafetyLevel::Paranoid => "paranoid",
            SafetyLevel::High => "high",
            SafetyLevel::Balanced => "balanced",
        }
    }
}

/// Safety policy enforcement mode for embedding operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SafetyEnforcement {
    /// Advisory (default): warn when exceeding safety threshold, but do not block embedding.
    #[default]
    Advisory,
    /// Enforced: strictly reject embedding if payload exceeds safety threshold.
    Enforced,
}

/// The capacity safety policy: which tier to target and how hard to enforce it.
///
/// This is the single source of truth for safety settings. It lives on
/// [`StegoOptions::safety`] only -- the per-domain parameter structs used to
/// carry their own copies, which the unified entry silently overwrote, so a
/// caller that set `PngParams::safety_enforcement` alone could believe it had
/// enabled enforcement while the default advisory policy was in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SafetyPolicy {
    /// Target capacity tier (default [`SafetyLevel::High`]).
    pub level: SafetyLevel,
    /// How to treat a payload above the tier's recommendation (default
    /// [`SafetyEnforcement::Advisory`]).
    pub enforcement: SafetyEnforcement,
}

impl SafetyPolicy {
    /// Official default policy: `High` tier, `Advisory` enforcement.
    pub const fn new() -> Self {
        Self {
            level: SafetyLevel::High,
            enforcement: SafetyEnforcement::Advisory,
        }
    }

    /// Whether this policy blocks an over-tier payload instead of warning.
    pub fn is_enforced(self) -> bool {
        matches!(self.enforcement, SafetyEnforcement::Enforced)
    }
}

/// Fine-tuning parameters for spatial-domain steganography (e.g. HILL, WOW).
///
/// Every field here either travels in the carrier's feature word
/// (`p1_window`, `p2_window`, `epsilon`, `exclusion_percentile`, `codec`,
/// `stc_h`, `stc_u`) or only shapes the embed-side offer, so extraction never
/// depends on the caller repeating an embed-time value. The high-pass kernel
/// is deliberately **not** a field: the built-in normalized KB kernel is the
/// only one with a wire identity (`kernel_id = 0`), and a custom kernel would
/// silently produce carriers the default extractor cannot read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PngParams {
    /// First-stage low-pass filter window size (odd, default 3).
    pub p1_window: usize,
    /// Second-stage low-pass filter window size (odd, default 15).
    pub p2_window: usize,
    /// Small numerical epsilon to avoid division by zero and control content sensitivity.
    pub epsilon: f64,
    /// Fraction of smoothest pixels to completely exclude from embedding (0.0 .. 0.9, default 0.30).
    pub exclusion_percentile: f64,
    /// Matrix-coding layer (default Hamming; STC is opt-in).
    #[serde(default)]
    pub codec: StegoCodec,
    /// STC constraint height, used only when `codec == Stc` (default 8).
    #[serde(default = "default_stc_h")]
    pub stc_h: u8,
    /// STC group size: how many elements share one syndrome row (default 1).
    ///
    /// `1` is the classic one-row-per-element code (one slot per bit). `2` and
    /// `3` carry one bit per 2 or 3 slots instead, which spreads the same
    /// message over more elements: the change *count* drops, and because every
    /// change still lands on the cheapest available slot the weighted
    /// distortion drops further. The trade is capacity -- a group of `u` buys
    /// roughly `1/u` bit per slot. Extraction reads `u` from the envelope
    /// header, so it never needs to be repeated.
    #[serde(default = "default_stc_u")]
    pub stc_u: u8,
    /// Scalar knobs belonging to a cost model that is **not** the built-in HILL.
    ///
    /// The typed fields above (`p1_window`, `p2_window`, `epsilon`) are HILL's
    /// own and stay typed because one of them is not a scalar. Every *other*
    /// model reads its settings from here, keyed by its own vocabulary:
    ///
    /// ```toml
    /// [png_params.algorithm_options]
    /// sigma = 1.0
    /// ```
    ///
    /// The point is that adding a model must not require editing this file. A
    /// model reads the keys it knows and falls back to its own defaults for
    /// absent ones; unknown keys are ignored so one config can serve several
    /// models. `validate` only checks that keys are non-empty and values are
    /// finite -- it cannot know what a key means, and pretending otherwise would
    /// put model knowledge back in the wrong place.
    #[serde(default)]
    pub algorithm_options: std::collections::BTreeMap<String, f64>,
}

fn default_stc_h() -> u8 {
    crate::stego::coding::DEFAULT_STC_H
}

fn default_stc_u() -> u8 {
    0
}

impl PngParams {
    /// Quantise the hyperparameters to the exact forms the PNG feature word
    /// can carry: `epsilon` as a power of two and the `sigma` model option
    /// at `f32` precision. The embedder, prober and extractor all run on
    /// these quantised values, so a carrier's wire description always
    /// reproduces the cost map it was built with. Values already in wire
    /// form (the defaults) round-trip unchanged.
    #[must_use]
    pub fn wire_quantized(&self) -> Self {
        let mut p = self.clone();
        let k = crate::stego::header::FeatureWord::quantize_epsilon(p.epsilon);
        p.epsilon = (0.5f64).powi(k as i32);
        if let Some(s) = p.algorithm_options.get_mut("sigma") {
            *s = *s as f32 as f64;
        }
        p
    }
}

impl Default for PngParams {
    fn default() -> Self {
        Self {
            p1_window: 3,
            p2_window: 15,
            epsilon: f32::EPSILON as f64,
            exclusion_percentile: 0.30,
            codec: StegoCodec::Auto,
            stc_h: default_stc_h(),
            stc_u: default_stc_u(),
            algorithm_options: std::collections::BTreeMap::new(),
        }
    }
}

impl PngParams {
    /// Reject parameter combinations that the HILL pipeline cannot serve.
    ///
    /// Both low-pass windows must be **positive odd** numbers: the symmetric
    /// padding is derived as `1 + (p1 - 1) / 2 + (p2 - 1) / 2`, which is only
    /// exact for odd windows, and the separable stage-3 convolution indexes
    /// whole samples.
    ///
    /// This is what turns the previous hard failure into a readable error.
    /// Before the padding was derived, `pad` was a constant 9 and any
    /// `p1 + p2 > 18` combination panicked with a slice range overflow inside
    /// the stage-3 pass (`range end index ... out of range`), reachable from
    /// the CLI via `--p1-window 5` or `--p2-window 31`.
    pub fn validate(&self) -> Result<(), StrHideError> {
        for (name, window) in [("p1_window", self.p1_window), ("p2_window", self.p2_window)] {
            if window == 0 || window % 2 == 0 {
                return Err(StrHideError::General(format!(
                    "HILL parameter '{name}' must be a positive odd number, got {window}"
                )));
            }
            // Upper bound keeps the padding (and the intermediate buffers)
            // bounded; anything larger is a configuration mistake, not a
            // tuning choice.
            if window > 63 {
                return Err(StrHideError::General(format!(
                    "HILL parameter '{name}' must be <= 63, got {window}"
                )));
            }
        }
        if !self.epsilon.is_finite() || self.epsilon <= 0.0 {
            return Err(StrHideError::General(format!(
                "HILL parameter 'epsilon' must be a finite positive number, got {}",
                self.epsilon
            )));
        }
        if self.codec == StegoCodec::Stc || self.codec == StegoCodec::Auto {
            crate::stego::coding::validate_stc_h(self.stc_h)?;
            if self.stc_u != 0 {
                crate::stego::coding::validate_stc_u(self.stc_u)?;
                if self.stc_u > self.stc_h {
                    return Err(StrHideError::General(format!(
                        "STC parameter 'stc_u' must be <= 'stc_h' (got u={}, h={})",
                        self.stc_u, self.stc_h
                    )));
                }
            }
        }
        validate_algorithm_options(&self.algorithm_options, "spatial")?;
        Ok(())
    }

    /// Value of a model-private knob, or `default` when the key is absent.
    ///
    /// The accessor exists so a cost model can declare its defaults next to the
    /// code that uses them instead of shipping a matching struct field here.
    pub fn model_option(&self, key: &str, default: f64) -> f64 {
        self.algorithm_options.get(key).copied().unwrap_or(default)
    }
}

/// Fine-tuning parameters for JPEG-domain DCT steganography (e.g. UERD).
///
/// Everything here changes either the offer (which slots are cheap) or the
/// embed-side search. None of it changes what the extractor must know: the
/// superblock carries `h` and `u`, and the slot set is derived from the key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JpegParams {
    /// Weight applied to the 8-neighborhood block energies (default 0.25).
    pub neighbor_weight: f64,
    /// Cost assigned to coefficients the model cannot rank (default 1e13).
    pub wet_cost: f64,
    /// STC constraint height written into the superblock (default 8).
    #[serde(default = "default_stc_h")]
    pub stc_h: u8,
    /// Trellis-size budget: `u` is chosen so `u * (bits + h - 1) <= slot_budget`.
    ///
    /// Embed-side performance knob only (roughly `slot_budget * 2^h / 2` state
    /// transitions, and `slot_budget * 2^h / 32` bytes of backtracking bitmap).
    /// It is **not** part of the wire format: the extractor trusts the `u` in
    /// the superblock, so carriers written with a different budget still decode.
    ///
    /// `None` means "not configured", which is **not** the same as configuring
    /// [`DEFAULT_SLOT_BUDGET`]: the default scales with the carrier, an explicit
    /// value is used as given. Comparing by value made `--slot-budget 1200000`
    /// (exactly the default number) behave as "unset" and silently rescale,
    /// contradicting the documented meaning of the flag.
    ///
    /// One exception: on a carrier whose Huffman table is over-optimised the
    /// value is still raised when needed to keep the body group size at
    /// `u >= 3` (see [`grouped_body_budget`]). That is a correctness
    /// constraint, like the grid bound -- `u = 1` cannot route around dead
    /// slots, and `u = 2` is still a coin flip at these loads -- not a
    /// tuning override.
    #[serde(default)]
    pub slot_budget: Option<usize>,
    /// Cipher suite written into the superblock (default: the profile's default).
    #[serde(default = "default_cipher_suite")]
    pub cipher_suite: u16,
    /// Cost polarization weight, i.e. the discount applied to the *preferred*
    /// direction of each coefficient.
    ///
    /// A JPEG coefficient is a quantized sample of a smooth signal, so the value
    /// it "should" have had can be estimated (dequantize -> Wiener denoise ->
    /// re-quantize). Moving a coefficient towards that estimate is less visible
    /// than moving it away, because it is the direction the signal lies in. The
    /// cost model reports that preference per coefficient
    /// ([`JpegCostModel::direction_bias`]) and the engine prices the preferred
    /// move at `base * polarize_weight`, leaving the opposite move at `base`.
    ///
    /// `1.0` (default) disables the mechanism: no bias is computed at all and the
    /// cost map stays symmetric. `0.65` is what `hstego` (MIT) uses. Valid range
    /// is `(0, 1]` -- a weight above `1` would *penalize* the less visible
    /// direction, which is the opposite of the intent, so it is rejected rather
    /// than silently inverted.
    ///
    /// Embed-side only: extraction never computes costs, so nothing about this
    /// setting is written into the carrier or needed to read it back.
    ///
    /// [`JpegCostModel::direction_bias`]: crate::stego::traits::JpegCostModel::direction_bias
    #[serde(default = "default_polarize_weight")]
    pub polarize_weight: f64,
    /// Extension records written into the TLV area (default: none).
    #[serde(default)]
    pub extensions: Vec<crate::stego::jpeg::header_v3::Tlv>,
    /// Scalar knobs belonging to a JPEG cost model that is **not** the built-in
    /// UERD.
    ///
    /// `neighbor_weight` above is UERD's own; anything a different model needs
    /// (e.g. J-UNIWARD's wavelet smoothing) is read from here by its own key.
    /// See [`PngParams::algorithm_options`] for the rationale -- the same
    /// rules apply, so that adding a model is a model-side change only.
    #[serde(default)]
    pub algorithm_options: std::collections::BTreeMap<String, f64>,
    /// Force the portable scalar kernels instead of the AVX2/FMA dispatch.
    ///
    /// Set automatically when [`StegoOptions::freshness`] is
    /// [`Freshness::Seeded`]. The AVX2 path fuses multiply-add and rounds once
    /// where the scalar path rounds twice, so the two can disagree in the last
    /// bit of a cost value -- enough to flip a near-tied trellis decision and
    /// produce a different stego file. A seeded run that lands on different
    /// slots would defeat the purpose.
    ///
    /// Not serialised: it describes the run, not the carrier.
    #[serde(skip)]
    #[doc(hidden)]
    pub deterministic: bool,
}

/// Validate a model-owned options bag.
///
/// Deliberately shallow: the library cannot know what a key means, so it checks
/// only what is universally wrong -- an empty key (unaddressable) or a
/// non-finite value (poisons any cost arithmetic downstream).
fn validate_algorithm_options(
    bag: &std::collections::BTreeMap<String, f64>,
    family: &str,
) -> Result<(), StrHideError> {
    for (key, value) in bag {
        if key.trim().is_empty() {
            return Err(StrHideError::General(format!(
                "{family} parameter 'algorithm_options' contains an empty key"
            )));
        }
        if !value.is_finite() {
            return Err(StrHideError::General(format!(
                "{family} parameter 'algorithm_options.{key}' must be finite, got {value}"
            )));
        }
    }
    Ok(())
}

/// Default trellis budget: 1.2M slots.
///
/// Chosen by the Phase 3 grid (`h` x budget, 8 photos, 4/16/64 KiB): 1.2M has the
/// lowest distortion and file growth of every configuration that stays under the
/// 3 s embed gate, at ~38 MB of backtracking bitmap (one bit per column and
/// state: `n * 2^h / 8`, `h = 8`). 800k is 40% faster and 13 MB lighter for ~6%
/// more changes. It is now only the *floor* of the automatic budget -- see
/// [`JpegParams::effective_slot_budget`]. See
/// `docs/stc_v3_phase3_eval_20261021.md`.
pub const DEFAULT_SLOT_BUDGET: usize = 1_200_000;

/// Ceiling on the STC backtracking bitmap, i.e. on an automatically scaled
/// trellis size.
///
/// This replaces the flat 2.4M-slot ceiling the code used to apply. That ceiling
/// pinned a 24 MP carrier holding 200 KB to `u = 1`, which is the one group size
/// with *no* freedom at all -- a `(1,1)` parity code whose solution is unique, so
/// the UERD cost map cannot move a single flip, and the weighted distortion is
/// ~29x that of `u = 3`. Sizing by the bitmap instead keeps the trellis
/// proportional to the carrier and bounds what actually matters:
///
/// * memory -- one slot costs `2^h / 64` words of traceback state (32 B at
///   `h = 8`, 128 B at `h = 10`), so 256 MiB allows 8.4M slots at `h = 8`;
/// * time -- bytes per slot and states per slot are the same power of two, so
///   they cancel and the worst case is ~1 s of kernel time for *any* `h`.
pub const MAX_AUTO_BACKTRACK_BYTES: usize = 4 << 30; // 4 GiB

/// Ceiling on the STC backtracking bitmap for the *correctness-driven* group
/// size on carriers whose Huffman table is over-optimised.
///
/// Set to 4 GiB: modern hardware easily accommodates multi-hundred megabyte
/// to multi-gigabyte trellis buffers, and huge carriers (50 MP .. 100+ MP)
/// carrying large payloads (512 KiB .. 4+ MiB) need room for `u >= 3` without
/// arbitrary artificial ceilings. At `h = 8` (32 B/slot) 4 GiB accommodates
/// 134M slots, fully unlocking the geometric capacity of massive carriers.
pub const MAX_GROUPED_BACKTRACK_BYTES: usize = 4 << 30; // 4 GiB

/// Slot ceiling implied by [`MAX_GROUPED_BACKTRACK_BYTES`] at height `h`.
///
/// One slot costs `2^h / 64` words of traceback state (32 B at `h = 8`,
/// 128 B at `h = 10`).
pub fn max_grouped_backtrack_slots(h: u8) -> usize {
    let states = 1usize << h;
    let bytes_per_slot = states.div_ceil(64) * 8;
    MAX_GROUPED_BACKTRACK_BYTES / bytes_per_slot
}

/// Budget that keeps the body trellis grouped on an over-optimised carrier.
///
/// Returns the budget the layout should use -- the automatic one when it
/// already buys `u >= 3`, otherwise raised to `3 * window` -- and `None` when
/// `u = 3` does not fit, in which case the caller must refuse the payload
/// instead of running an embed whose outcome is a lottery.
///
/// `u = 2` is deliberately *not* offered as a fallback: measured on 24 MP
/// carriers it still fails often enough to be a coin flip at the loads where
/// `u = 1` gets rejected (512 KiB: 4/10; 900 KiB: 0/6, three salt retries
/// each), because two slots per bit leave too little room to route around
/// cross-zero chains. `u = 3` measured 10/10 at the same load. The caller's
/// `u < 3` gate lifts any smaller group to `u = 3` or refuses the embed when
/// not even `u = 3` fits.
///
/// `window` is `bits + h - 1`: the number of elements one STC pass covers.
pub fn grouped_body_budget(
    body_grid_len: usize,
    bits: usize,
    h: u8,
    auto_budget: usize,
) -> Option<usize> {
    if bits == 0 {
        return Some(auto_budget);
    }
    let window = bits + h as usize - 1;
    let room = body_grid_len.min(max_grouped_backtrack_slots(h));
    if room / window < 3 {
        return None;
    }
    Some(auto_budget.max(3 * window))
}

fn default_cipher_suite() -> u16 {
    crate::stego::format::DEFAULT_SUITE_ID
}

fn default_polarize_weight() -> f64 {
    1.0
}

impl Default for JpegParams {
    fn default() -> Self {
        Self {
            neighbor_weight: 0.25,
            wet_cost: 1e13,
            stc_h: default_stc_h(),
            slot_budget: None,
            cipher_suite: default_cipher_suite(),
            polarize_weight: default_polarize_weight(),
            extensions: Vec::new(),
            algorithm_options: std::collections::BTreeMap::new(),
            deterministic: false,
        }
    }
}

impl JpegParams {
    /// Reject parameter values that would produce a NaN/Inf cost map, an empty
    /// search or a header field the decoder rejects.
    pub fn validate(&self) -> Result<(), StrHideError> {
        if !self.neighbor_weight.is_finite() || self.neighbor_weight < 0.0 {
            return Err(StrHideError::General(format!(
                "UERD parameter 'neighbor_weight' must be a finite non-negative number, got {}",
                self.neighbor_weight
            )));
        }
        if !self.wet_cost.is_finite() || self.wet_cost <= 0.0 {
            return Err(StrHideError::General(format!(
                "UERD parameter 'wet_cost' must be a finite positive number, got {}",
                self.wet_cost
            )));
        }
        crate::stego::coding::validate_stc_h(self.stc_h)?;
        if let Some(budget) = self.slot_budget
            && budget < 8
        {
            return Err(StrHideError::General(format!(
                "JPEG parameter 'slot_budget' must be >= 8, got {budget}"
            )));
        }
        if !self.polarize_weight.is_finite() || self.polarize_weight <= 0.0 {
            return Err(StrHideError::General(format!(
                "JPEG parameter 'polarize_weight' must be a finite positive number, got {}",
                self.polarize_weight
            )));
        }
        // Above 1 the weight would penalize the *preferred* direction instead of
        // discounting it, which inverts the meaning of the setting. Reject it
        // rather than silently doing the opposite of what the name says.
        if self.polarize_weight > 1.0 {
            return Err(StrHideError::General(format!(
                "JPEG parameter 'polarize_weight' must be <= 1.0 (1.0 disables polarization), got {}",
                self.polarize_weight
            )));
        }
        if self.cipher_suite == 0 {
            return Err(StrHideError::General(
                "Cipher suite id 0 is reserved for 'unset'".into(),
            ));
        }
        validate_algorithm_options(&self.algorithm_options, "JPEG")?;
        Ok(())
    }

    /// Value of a model-private knob, or `default` when the key is absent.
    pub fn model_option(&self, key: &str, default: f64) -> f64 {
        self.algorithm_options.get(key).copied().unwrap_or(default)
    }

    /// Compute the effective slot budget for layout optimization.
    ///
    /// Unset (`None`) is proportional to the carrier: a quarter of its body
    /// grid, so a body grid holding `r` slots per payload bit yields `u = r / 4`
    /// -- the group size follows how much room the carrier actually has instead
    /// of being pinned by a flat slot count. Two clamps keep it sane:
    /// [`DEFAULT_SLOT_BUDGET`] as a floor (small carriers stay generous) and
    /// [`MAX_AUTO_BACKTRACK_BYTES`] as a memory ceiling (huge carriers stop
    /// growing the traceback bitmap). An explicit value is respected exactly,
    /// even when it happens to equal [`DEFAULT_SLOT_BUDGET`].
    ///
    /// Worked example: a 24 MP carrier (23.6M-slot grid) with a 200 KB payload
    /// has `r = 14.7`, so the budget is `23.6M / 4 = 5.9M` and `u = 3`; the old
    /// flat ceiling gave `u = 1` here, i.e. no adaptivity at all.
    pub fn effective_slot_budget(&self, body_slots: usize) -> usize {
        match self.slot_budget {
            Some(budget) => budget,
            None => {
                // `stc_h` is validated to 4..=10 at the API boundary; clamp
                // anyway so a hand-built params struct cannot shift-overflow.
                let h = self.stc_h.min(crate::stego::coding::MAX_STC_H);
                let states = 1usize << h;
                let bytes_per_slot = states.div_ceil(64) * 8;
                let memory_cap =
                    (MAX_AUTO_BACKTRACK_BYTES / bytes_per_slot).max(DEFAULT_SLOT_BUDGET);
                DEFAULT_SLOT_BUDGET.max((body_slots / 4).min(memory_cap))
            }
        }
    }
}

/// Extraction policy.
///
/// Unlike [`JpegParams`] this is **not** part of the offer: it only says how
/// much work this call is willing to spend and which suites it trusts. Two
/// extractors with different policies still read the same carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractParams {
    /// Suites to try, ascending. `None` means "every suite in the profile".
    ///
    /// A private build may narrow this to keep a slow suite from being probed;
    /// dropping a suite only makes carriers written with it unreadable.
    pub allowed_suites: Option<Vec<u16>>,
    /// Ceiling on PBKDF2 iterations the decoder will execute for one attempt.
    ///
    /// A forged `suite_id` must not be able to turn the extractor into a space
    /// heater, so the cost is checked before the KDF runs.
    pub max_pbkdf2_iterations: u32,
}

impl Default for ExtractParams {
    fn default() -> Self {
        Self {
            allowed_suites: None,
            max_pbkdf2_iterations: crate::stego::format::MAX_PBKDF2_ITERATIONS,
        }
    }
}

impl ExtractParams {
    /// Whether `suite_id` may be tried under this policy.
    pub fn allows_suite(&self, suite_id: u16) -> bool {
        match &self.allowed_suites {
            Some(ids) => ids.contains(&suite_id),
            None => true,
        }
    }
}

/// Unified configuration options passed to embed and extract pipelines.
///
/// Everything here is either a per-call choice ([`algorithm`](Self::algorithm))
/// or a user-supplied credential ([`password`](Self::password)), plus **L-class**
/// tuning knobs that only the writer's cost map depends on. The **P-class**
/// part -- the private no-password secret -- deliberately lives in
/// [`StegoProfile`](crate::params::StegoProfile), next to the structure-domain
/// dialect fields, so there is exactly one object to store and pass around.
#[derive(Debug, Clone, Default)]
pub struct StegoOptions {
    /// Requested algorithm name (e.g. "hill", "uerd", "auto").
    pub algorithm: Option<String>,
    /// Password for cryptographic key derivation and PRNG scattering.
    pub password: Option<String>,
    /// Custom domain tag for isolating the HKDF key derivation domain.
    ///
    /// Runtime half of the dialect: the explicit value wins, the profile's
    /// [`StegoProfile::domain`](crate::params::StegoProfile) is the fallback,
    /// `None` means the official default derivation.
    pub domain: Option<String>,
    /// Capacity safety policy: target tier and enforcement (default
    /// `High` / `Advisory`). The single source of truth -- the per-domain
    /// parameter structs carry no safety settings of their own.
    pub safety: SafetyPolicy,
    /// Fine-tuning parameters for spatial domain algorithms.
    pub png_params: PngParams,
    /// Fine-tuning parameters for JPEG DCT domain algorithms.
    pub jpeg_params: JpegParams,
    /// Extraction policy: which suites to try and how much KDF work to allow.
    pub extract_params: ExtractParams,
    /// Source of the per-embedding salt and nonce.
    ///
    /// [`Freshness::Random`] (the default) draws fresh bytes and is what every
    /// production path uses. [`Freshness::Seeded`] derives them from a seed so
    /// the same inputs produce the same stego file -- for regression tests, the
    /// `repro_*` examples, and bug reports that need to be replayed.
    pub freshness: Freshness,
}

impl StegoOptions {
    /// Chainable builder: set the password.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Chainable builder: set the requested algorithm name
    /// (`hill` / `suniward` / `uerd` / `juniward` / `hevc` / `cabac` / `auto`).
    pub fn with_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.algorithm = Some(algorithm.into());
        self
    }

    /// Chainable builder: set the HKDF domain-isolation tag.
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Chainable builder: set the capacity safety tier and its enforcement.
    pub fn with_safety(mut self, level: SafetyLevel, enforcement: SafetyEnforcement) -> Self {
        self.safety = SafetyPolicy { level, enforcement };
        self
    }

    /// Chainable builder: set the salt/nonce source.
    pub fn with_freshness(mut self, freshness: Freshness) -> Self {
        self.freshness = freshness;
        self
    }

    /// Chainable builder: replace the PNG tuning parameters.
    pub fn with_png_params(mut self, params: PngParams) -> Self {
        self.png_params = params;
        self
    }

    /// Chainable builder: replace the JPEG tuning parameters.
    pub fn with_jpeg_params(mut self, params: JpegParams) -> Self {
        self.jpeg_params = params;
        self
    }

    /// Secret actually used for key derivation: the explicit password wins, the
    /// profile's private stego secret is the fallback, `None` means "official
    /// public constant" (resolved inside the envelope layer).
    ///
    /// Resolving here keeps the two engine families byte-identical: a private
    /// default secret is not special-cased anywhere downstream, it simply
    /// travels the same path as a user password.
    ///
    /// An empty password is treated as "not supplied" and does **not** mask the
    /// profile secret. The previous implementation joined the two options with
    /// `or` and filtered afterwards, so `password = Some("")` silently dropped
    /// the private secret and fell back to the public constant -- a quiet
    /// downgrade of exactly the knob that exists to prevent it.
    pub fn secret<'a>(&'a self, profile: &'a Profile) -> Option<&'a str> {
        self.password
            .as_deref()
            .filter(|s| !s.is_empty())
            .or_else(|| profile.stego_secret())
    }

    /// Custom domain tag used for isolating the HKDF key derivation domain:
    /// the explicit [`domain`](Self::domain) wins, the profile's stego domain is
    /// the fallback, `None` means the official default derivation.
    pub fn domain<'a>(&'a self, profile: &'a Profile) -> Option<&'a str> {
        self.domain
            .as_deref()
            .filter(|s| !s.is_empty())
            .or_else(|| profile.stego_domain())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The options bag is the extension point that keeps a new cost model out
    /// of this file, so its accessor and validation have to behave predictably.
    #[test]
    fn algorithm_options_default_to_the_models_own_values() {
        let params = PngParams::default();
        assert!(
            params.algorithm_options.is_empty(),
            "default carries no bag"
        );
        assert_eq!(params.model_option("sigma", 1.0), 1.0);

        let mut tuned = PngParams::default();
        tuned.algorithm_options.insert("sigma".into(), 0.5);
        assert_eq!(tuned.model_option("sigma", 1.0), 0.5);
        assert_eq!(
            tuned.model_option("unrelated", 7.0),
            7.0,
            "an absent key must fall back, not fail"
        );
        tuned.validate().expect("a tuned bag is valid");
    }

    #[test]
    fn algorithm_options_reject_empty_keys_and_non_finite_values() {
        let mut empty_key = PngParams::default();
        empty_key.algorithm_options.insert("  ".into(), 1.0);
        let err = empty_key
            .validate()
            .expect_err("empty key must be rejected");
        assert!(err.to_string().contains("empty key"), "got: {err}");

        let mut not_finite = JpegParams::default();
        not_finite.algorithm_options.insert("gain".into(), f64::NAN);
        let err = not_finite
            .validate()
            .expect_err("NaN must be rejected before it reaches a cost map");
        assert!(err.to_string().contains("gain"), "got: {err}");
    }

    #[test]
    fn explicit_password_wins_over_profile_secret() {
        let opts = StegoOptions {
            password: Some("user-password".into()),
            ..Default::default()
        };
        let profile = Profile::default().with_stego_secret("private-dialect");
        assert_eq!(opts.secret(&profile), Some("user-password"));
    }

    #[test]
    fn profile_secret_fills_in_without_a_password() {
        let profile = Profile::default().with_stego_secret("private-dialect");
        assert_eq!(
            StegoOptions::default().secret(&profile),
            Some("private-dialect")
        );
        // Official profile -> public constant, resolved downstream.
        assert_eq!(StegoOptions::default().secret(&Profile::default()), None);
    }

    #[test]
    fn empty_password_does_not_mask_the_profile_secret() {
        let opts = StegoOptions {
            password: Some(String::new()),
            ..Default::default()
        };
        let profile = Profile::default().with_stego_secret("private-dialect");
        assert_eq!(opts.secret(&profile), Some("private-dialect"));
    }

    #[test]
    fn explicit_slot_budget_is_honoured_even_when_it_equals_the_default() {
        // "Explicitly configured" and "unset" must be distinguishable: an
        // unset budget scales with the carrier, an explicit one does not.
        // Comparing the value to `DEFAULT_SLOT_BUDGET` conflated the two, so
        // `--slot-budget 1200000` silently rescaled like the default.
        let body_slots = 8_000_000; // body/4 = 2M, above the default
        let explicit = JpegParams {
            slot_budget: Some(DEFAULT_SLOT_BUDGET),
            ..JpegParams::default()
        };
        assert_eq!(
            explicit.effective_slot_budget(body_slots),
            DEFAULT_SLOT_BUDGET
        );
        assert_eq!(
            JpegParams::default().effective_slot_budget(body_slots),
            body_slots / 4
        );
        // A small carrier never gets a budget below the default.
        assert_eq!(
            JpegParams::default().effective_slot_budget(100),
            DEFAULT_SLOT_BUDGET
        );
    }

    /// The default policy must never pin a high-resolution carrier holding a
    /// large payload to `u = 1`. A flat 2.4M-slot ceiling used to do exactly
    /// that (24 MP + 200 KB -> `u = 1`), and `u = 1` is a `(1,1)` parity code:
    /// the solution is unique, so the UERD cost map cannot move a single flip
    /// and the weighted distortion is ~29x that of `u = 3`.
    #[test]
    fn large_carrier_with_large_payload_keeps_a_grouped_trellis() {
        // 4:2:0 24 MP -> 375k blocks -> 23.6M grid slots, minus the header.
        let n_total = 375_000 * 63;
        let hdr_n = 718;
        let params = JpegParams::default();
        let body_slots = n_total - hdr_n;
        let budget = params.effective_slot_budget(body_slots);
        // A quarter of the grid, so `u` tracks the ratio instead of a constant.
        assert_eq!(budget, body_slots / 4);

        let bits = 8 * (200_000 + 21); // 200 KB payload plus the envelope header
        let layout =
            crate::stego::jpeg::v3_layout::compute(n_total, hdr_n, bits, params.stc_h, budget)
                .unwrap();
        assert!(
            layout.u >= 3,
            "24 MP + 200 KB must not fall back to u = {}",
            layout.u
        );
        assert_eq!(
            layout.u,
            3,
            "r = {:.1} implies u = 3",
            body_slots as f64 / (bits + 7) as f64
        );

        // The same carrier with a payload that nearly fills it still degrades
        // gracefully -- it just cannot afford a grouped code.
        let dense = 8 * (700_000 + 21);
        let dense_layout =
            crate::stego::jpeg::v3_layout::compute(n_total, hdr_n, dense, params.stc_h, budget)
                .unwrap();
        assert!(dense_layout.u >= 1 && dense_layout.u <= layout.u);
    }

    #[test]
    fn safety_level_parse_and_bpp_limits() {
        assert_eq!(SafetyLevel::parse("paranoid"), Some(SafetyLevel::Paranoid));
        assert_eq!(SafetyLevel::parse("High"), Some(SafetyLevel::High));
        assert_eq!(SafetyLevel::parse("BALANCED"), Some(SafetyLevel::Balanced));
        assert_eq!(SafetyLevel::parse("unknown"), None);

        assert_eq!(SafetyLevel::Paranoid.bpp_limit(), 0.06);
        assert_eq!(SafetyLevel::High.bpp_limit(), 0.10);
        assert_eq!(SafetyLevel::Balanced.bpp_limit(), 0.15);

        assert_eq!(SafetyLevel::default(), SafetyLevel::High);
        assert_eq!(SafetyEnforcement::default(), SafetyEnforcement::Advisory);
    }

    /// 24 MP carrier geometry with no extensions: 375k blocks, 23.6M grid
    /// slots, header 718 + 28.
    fn carrier_24mp() -> (usize, usize) {
        (
            375_000 * 63,
            crate::stego::format::DEFAULT_JPEG_FORMAT.header_slots(0),
        )
    }

    #[test]
    fn grouped_backtrack_slot_ceiling_scales_with_height() {
        // 4 GiB / 32 B per slot at h = 8.
        assert_eq!(max_grouped_backtrack_slots(8), (4usize << 30) >> 5);
        // h = 10 doubles the states per slot, hence halves the slot ceiling.
        assert_eq!(max_grouped_backtrack_slots(10), (4usize << 30) / 128);
    }

    /// The automatic budget pins a 24 MP carrier holding 512 KiB to `u = 1`,
    /// which an over-optimised Huffman table cannot host; the grouped budget
    /// must lift it to `u = 3`, the measured reliable operating point.
    #[test]
    fn grouped_body_budget_lifts_u_one_to_u_three() {
        let (n_total, hdr_n) = carrier_24mp();
        let body_slots = n_total - hdr_n;
        let params = JpegParams::default();
        let auto = params.effective_slot_budget(body_slots);
        let bits = 8 * (524_288 + 21);

        let layout =
            crate::stego::jpeg::v3_layout::compute(n_total, hdr_n, bits, params.stc_h, auto)
                .unwrap();
        assert_eq!(layout.u, 1, "the automatic budget lands on u = 1");

        let budget =
            grouped_body_budget(body_slots, bits, params.stc_h, auto).expect("u = 3 must fit");
        let grouped =
            crate::stego::jpeg::v3_layout::compute(n_total, hdr_n, bits, params.stc_h, budget)
                .unwrap();
        assert_eq!(grouped.u, 3);
        // The correctness path stays inside its own memory ceiling.
        assert!(grouped.body_n * 32 <= MAX_GROUPED_BACKTRACK_BYTES);
    }

    /// `u = 2` is not offered as a fallback: at the loads where `u = 1` gets
    /// rejected it is still a coin flip (512 KiB: 4/10, 900 KiB: 0/6 on a
    /// 24 MP carrier, three salt retries each), because two slots per bit
    /// leave too little room to route around cross-zero chains. `u = 3`
    /// measured 10/10 at the same load.
    #[test]
    fn grouped_body_budget_refuses_when_u_three_does_not_fit() {
        let (n_total, hdr_n) = carrier_24mp();
        let body_slots = n_total - hdr_n;
        let params = JpegParams::default();
        let auto = params.effective_slot_budget(body_slots);
        // 700 KiB on 24 MP: 3 * window = 16.80M slots fits inside the 23.6M grid
        // and 4 GiB memory ceiling.
        let bits_700k = 8 * (700_000 + 21);
        assert!(grouped_body_budget(body_slots, bits_700k, params.stc_h, auto).is_some());

        // 1 MiB on 24 MP requires 3 * 8.388M = 25.16M slots, which exceeds
        // the 23.6M physical grid of 24 MP, so it is refused.
        let bits_1m = 8 * (1_048_576 + 21);
        assert!(grouped_body_budget(body_slots, bits_1m, params.stc_h, auto).is_none());

        // A massive payload (2 MiB) on 24 MP is well beyond physical grid capacity.
        let bits_2m = 8 * (2 * 1_048_576 + 21);
        assert!(grouped_body_budget(body_slots, bits_2m, params.stc_h, auto).is_none());
    }

    /// An already-grouped automatic budget is returned untouched.
    #[test]
    fn grouped_body_budget_keeps_an_already_grouped_auto_budget() {
        let (n_total, hdr_n) = carrier_24mp();
        let body_slots = n_total - hdr_n;
        let params = JpegParams::default();
        let auto = params.effective_slot_budget(body_slots);
        let bits = 8 * (200_000 + 21); // auto budget already buys u = 3

        let layout =
            crate::stego::jpeg::v3_layout::compute(n_total, hdr_n, bits, params.stc_h, auto)
                .unwrap();
        assert_eq!(layout.u, 3);
        assert_eq!(
            grouped_body_budget(body_slots, bits, params.stc_h, auto),
            Some(auto)
        );
    }

    /// A small carrier with an explicit tiny budget: the grouped floor lifts
    /// `u = 1` to `u = 3` without exceeding the grid.
    #[test]
    fn grouped_body_budget_lifts_a_small_carrier() {
        // 256x256 fixture: 1024 blocks, 63,766 body slots.
        let body_slots = 1024 * 63 - 746;
        let bits = 8 * (8 + 21);
        let budget = grouped_body_budget(body_slots, bits, 8, 300).expect("u = 3 fits");
        let layout =
            crate::stego::jpeg::v3_layout::compute(1024 * 63, 746, bits, 8, budget).unwrap();
        assert_eq!(layout.u, 3);
        assert!(layout.body_n <= body_slots);
    }
}
