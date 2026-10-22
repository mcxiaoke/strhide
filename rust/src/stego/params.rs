//! Steganography configuration parameters and fine-tuning interfaces.
//!
//! Designed to allow runtime parameter adjustment, custom confusion/anti-detection
//! weights, and future configuration file deserialization.

use serde::{Deserialize, Serialize};

use crate::errors::StrHideError;
use crate::params::Profile;

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
/// the envelope header (see `spatial::engine`), so extraction never needs to be
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

/// Fine-tuning parameters for spatial-domain steganography (e.g. HILL, WOW).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpatialParams {
    /// 3x3 high-pass filter kernel (row-major). Default is normalized KB kernel.
    pub high_pass_kernel: [f64; 9],
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
    /// Capacity safety tier (default High).
    #[serde(default)]
    pub safety_level: SafetyLevel,
    /// Safety policy enforcement mode (default Advisory).
    #[serde(default)]
    pub safety_enforcement: SafetyEnforcement,
}

fn default_stc_h() -> u8 {
    crate::stego::coding::DEFAULT_STC_H
}

fn default_stc_u() -> u8 {
    0
}

impl Default for SpatialParams {
    fn default() -> Self {
        Self {
            // Normalized KB 3x3 kernel: [-1, 2, -1; 2, -4, 2; -1, 2, -1] / 4.0
            high_pass_kernel: [-0.25, 0.50, -0.25, 0.50, -1.00, 0.50, -0.25, 0.50, -0.25],
            p1_window: 3,
            p2_window: 15,
            epsilon: f32::EPSILON as f64,
            exclusion_percentile: 0.30,
            codec: StegoCodec::Auto,
            stc_h: default_stc_h(),
            stc_u: default_stc_u(),
            safety_level: SafetyLevel::default(),
            safety_enforcement: SafetyEnforcement::default(),
        }
    }
}

impl SpatialParams {
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
        if self.high_pass_kernel.iter().any(|v| !v.is_finite()) {
            return Err(StrHideError::General(
                "HILL parameter 'high_pass_kernel' must contain only finite values".into(),
            ));
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
        Ok(())
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
    #[serde(default)]
    pub slot_budget: Option<usize>,
    /// Cipher suite written into the superblock (default: the profile's default).
    #[serde(default = "default_cipher_suite")]
    pub cipher_suite: u16,
    /// Directional cost weight: `rho_minus *= polarize_weight`.
    ///
    /// `1.0` (default) means "disabled", i.e. a symmetric cost map, which is the
    /// only setting with a measured track record. Values below 1 make shrinking
    /// `|c|` cheaper; the plan treats that as a Phase 3 experiment that has to
    /// win an A/B before it becomes a default.
    #[serde(default = "default_polarize_weight")]
    pub polarize_weight: f64,
    /// Extension records written into the TLV area (default: none).
    #[serde(default)]
    pub extensions: Vec<crate::stego::jpeg::header_v3::Tlv>,
    /// Capacity safety tier (default High).
    #[serde(default)]
    pub safety_level: SafetyLevel,
    /// Safety policy enforcement mode (default Advisory).
    #[serde(default)]
    pub safety_enforcement: SafetyEnforcement,
}

/// Default trellis budget: 1.2M slots.
///
/// Chosen by the Phase 3 grid (`h` x budget, 8 photos, 4/16/64 KiB): 1.2M has the
/// lowest distortion and file growth of every configuration that stays under the
/// 3 s embed gate, at ~77 MB of backtracking bitmap (`n * 2^h / 4`, `h = 8`).
/// 800k is 40% faster and 26 MB lighter for ~6% more changes; 2M+ only adds
/// memory. See `docs/stc_v3_phase3_eval_20261021.md`.
pub const DEFAULT_SLOT_BUDGET: usize = 1_200_000;

/// Upper limit for automatic dynamic scaling of slot budget on massive carriers.
pub const MAX_DEFAULT_SLOT_BUDGET: usize = 2_400_000;

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
            safety_level: SafetyLevel::default(),
            safety_enforcement: SafetyEnforcement::default(),
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
        if self.cipher_suite == 0 {
            return Err(StrHideError::General(
                "Cipher suite id 0 is reserved for 'unset'".into(),
            ));
        }
        Ok(())
    }

    /// Compute the effective slot budget for layout optimization.
    ///
    /// Unset (`None`) scales dynamically with carrier capacity (`body_slots / 4`)
    /// so large carriers (e.g. 24 MP+) keep optimal low-distortion group sizes
    /// (`u >= 2`) without an excessive memory footprint. An explicit value is
    /// respected exactly, even when it happens to equal [`DEFAULT_SLOT_BUDGET`].
    pub fn effective_slot_budget(&self, body_slots: usize) -> usize {
        match self.slot_budget {
            Some(budget) => budget,
            None => DEFAULT_SLOT_BUDGET.max((body_slots / 4).min(MAX_DEFAULT_SLOT_BUDGET)),
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
    pub stego_domain: Option<String>,
    /// Capacity safety tier (default High: bpp <= 0.10).
    pub safety_level: SafetyLevel,
    /// Safety policy enforcement mode (default Advisory).
    pub safety_enforcement: SafetyEnforcement,
    /// Fine-tuning parameters for spatial domain algorithms.
    pub spatial_params: SpatialParams,
    /// Fine-tuning parameters for JPEG DCT domain algorithms.
    pub jpeg_params: JpegParams,
    /// Extraction policy: which suites to try and how much KDF work to allow.
    pub extract_params: ExtractParams,
}

impl StegoOptions {
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
    /// the explicit `stego_domain` wins, the profile's `stego_domain` is the fallback,
    /// `None` means official default derivation.
    pub fn domain<'a>(&'a self, profile: &'a Profile) -> Option<&'a str> {
        self.stego_domain
            .as_deref()
            .filter(|s| !s.is_empty())
            .or_else(|| profile.stego_domain())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
