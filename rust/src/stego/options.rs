//! Typed per-call options for the content domain.
//!
//! One `StegoOptions` bag served embed, extract and capacity probing before
//! this module existed. Three problems came with that:
//!
//! 1. **The extractor was handed the writer's knobs.** `extract_carrier` began
//!    with `options.png_params.validate()?`, so a PNG filter window that was
//!    only ever meant for a write could reject a perfectly readable JPEG.
//! 2. **Nothing said which call a field belonged to.** `freshness` (a write-side
//!    salt source) and `extract_params` (a read-side policy) sat next to each
//!    other, and every new field made the bag bigger for everyone.
//! 3. **The algorithm was a `String`.** A typo could only be discovered deep
//!    inside the engine, and a custom cost model could not be injected at all
//!    (`CostModelRegistry` resolves names only).
//!
//! Now each call gets exactly its own fields, the cost model is a value
//! ([`SpatialAlgorithm`] / [`JpegAlgorithm`]) instead of a name, and the
//! progress/cancellation pair rides along in every one of them (see
//! [`crate::core::control`]).
//!
//! # What extraction does *not* need
//!
//! No tuning. A carrier is self-describing: the PNG feature word carries the
//! codec, `u`, `h`, both filter windows, epsilon, the exclusion percentile, the
//! cost-model wire id and S-UNIWARD's `sigma`; the JPEG superblock carries its
//! own `u`/`h`/salt/nonce/ciphertext length. Repeating an embed-time value at
//! extract time is therefore not just unnecessary, it is a second source of
//! truth that can silently disagree with the carrier.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::core::control::Control;
use crate::errors::StrHideError;
use crate::formats::FileFormat;
use crate::stego::StegoCapacityInfo;
use crate::stego::envelope::Freshness;
#[cfg(feature = "content-jpeg")]
use crate::stego::jpeg::registry as jpeg_registry;
#[cfg(feature = "content-jpeg")]
use crate::stego::params::JpegParams;
#[cfg(feature = "content-png")]
use crate::stego::params::PngParams;
use crate::stego::params::StegoProfile;
use crate::stego::params::{ExtractParams, SafetyPolicy};
#[cfg(feature = "content-png")]
use crate::stego::png::registry as png_registry;
#[cfg(feature = "content-jpeg")]
use crate::stego::traits::JpegCostModel;
#[cfg(feature = "content-png")]
use crate::stego::traits::PngCostModel;

/// Spatial-domain cost model selection.
///
/// Replaces the `"hill"` / `"suniward"` strings the old options carried. A typo
/// is now a compile error or a [`from_name`](Self::from_name) `None`, not a
/// runtime "unknown algorithm" from inside the engine -- and
/// [`Custom`](Self::Custom) closes the "a private build cannot inject its own
/// cost model" gap the registry-only lookup had.
#[cfg(feature = "content-png")]
#[derive(Clone, Default)]
pub enum SpatialAlgorithm {
    /// HILL (Li et al., ICIP 2014) -- the default.
    #[default]
    Hill,
    /// S-UNIWARD (Holub et al., EURASIP JIS 2014).
    Suniward,
    /// A caller-supplied model. The engine treats it exactly like a built-in
    /// one, but a carrier written with it can only be read back by a build that
    /// registers the same model under a wire id.
    Custom(Arc<dyn PngCostModel>),
}

#[cfg(feature = "content-png")]
impl SpatialAlgorithm {
    /// Resolve a CLI/config name. `None` for an unknown name; `"auto"` maps to
    /// [`Hill`](Self::Hill), matching the registry's "auto stays on HILL"
    /// decision.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim() {
            "auto" | "hill" => Some(SpatialAlgorithm::Hill),
            "suniward" => Some(SpatialAlgorithm::Suniward),
            _ => None,
        }
    }

    /// The model instance to run.
    pub fn model(&self) -> Arc<dyn PngCostModel> {
        match self {
            SpatialAlgorithm::Hill => png_registry::get_spatial_model(Some("hill"))
                .expect("the built-in HILL model always resolves"),
            SpatialAlgorithm::Suniward => png_registry::get_spatial_model(Some("suniward"))
                .expect("the built-in S-UNIWARD model always resolves"),
            SpatialAlgorithm::Custom(model) => Arc::clone(model),
        }
    }

    /// Stable name, for messages and listings.
    pub fn id(&self) -> &'static str {
        match self {
            SpatialAlgorithm::Hill => "hill",
            SpatialAlgorithm::Suniward => "suniward",
            SpatialAlgorithm::Custom(model) => model.id(),
        }
    }
}

#[cfg(feature = "content-png")]
impl std::fmt::Debug for SpatialAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

#[cfg(feature = "content-png")]
impl PartialEq for SpatialAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Hill, Self::Hill) => true,
            (Self::Suniward, Self::Suniward) => true,
            (Self::Custom(a), Self::Custom(b)) => Arc::ptr_eq(a, b) || a.id() == b.id(),
            _ => false,
        }
    }
}

#[cfg(feature = "content-png")]
impl Eq for SpatialAlgorithm {}

/// JPEG DCT-domain cost model selection.
#[cfg(feature = "content-jpeg")]
#[derive(Clone, Default)]
pub enum JpegAlgorithm {
    /// UERD (Guo et al., IEEE TIFS 2015) -- the default.
    #[default]
    Uerd,
    /// J-UNIWARD (Holub et al., EURASIP JIS 2014).
    Juniward,
    /// A caller-supplied model.
    Custom(Arc<dyn JpegCostModel>),
}

#[cfg(feature = "content-jpeg")]
impl JpegAlgorithm {
    /// Resolve a CLI/config name. `None` for an unknown name; `"auto"` maps to
    /// [`Uerd`](Self::Uerd).
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim() {
            "auto" | "uerd" => Some(JpegAlgorithm::Uerd),
            "juniward" => Some(JpegAlgorithm::Juniward),
            _ => None,
        }
    }

    /// The model instance to run.
    pub fn model(&self) -> Arc<dyn JpegCostModel> {
        match self {
            JpegAlgorithm::Uerd => jpeg_registry::get_jpeg_model(Some("uerd"))
                .expect("the built-in UERD model always resolves"),
            JpegAlgorithm::Juniward => jpeg_registry::get_jpeg_model(Some("juniward"))
                .expect("the built-in J-UNIWARD model always resolves"),
            JpegAlgorithm::Custom(model) => Arc::clone(model),
        }
    }

    /// Stable name, for messages and listings.
    pub fn id(&self) -> &'static str {
        match self {
            JpegAlgorithm::Uerd => "uerd",
            JpegAlgorithm::Juniward => "juniward",
            JpegAlgorithm::Custom(model) => model.id(),
        }
    }
}

#[cfg(feature = "content-jpeg")]
impl std::fmt::Debug for JpegAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

#[cfg(feature = "content-jpeg")]
impl PartialEq for JpegAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Uerd, Self::Uerd) => true,
            (Self::Juniward, Self::Juniward) => true,
            (Self::Custom(a), Self::Custom(b)) => Arc::ptr_eq(a, b) || a.id() == b.id(),
            _ => false,
        }
    }
}

#[cfg(feature = "content-jpeg")]
impl Eq for JpegAlgorithm {}

/// Which HEVC scheme the caller wants for a HEIF carrier.
#[cfg(feature = "content-hevc")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HevcMode {
    /// Scheme C (CABAC in-place) when the carrier allows it, the thumbnail
    /// bridge when it does not. This is the only mode that ever falls back.
    #[default]
    Auto,
    /// Scheme C only: refuse instead of falling back, so a caller that must not
    /// have a second payload layered into a JPEG thumbnail gets a hard error.
    Cabac,
}

#[cfg(feature = "content-hevc")]
impl HevcMode {
    /// Resolve `"hevc"` / `"cabac"` / `"auto"`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim() {
            "auto" => Some(HevcMode::Auto),
            "hevc" | "cabac" => Some(HevcMode::Cabac),
            _ => None,
        }
    }
}

/// Per-call HEVC tuning.
///
/// The Scheme C engine has no cost model to choose and no filter windows to
/// tune: what it needs travels in the carrier (slice NALs, its own header) or
/// is a capacity policy ([`SafetyPolicy`], [`ProbeOptions::exact`]). The type
/// exists so the [`StegoTuning`] arm and the plumbing around it are written
/// once -- a future knob (a drift-ladder limit, a WPP switch) becomes a field
/// here instead of a new enum shape that breaks every caller.
#[cfg(feature = "content-hevc")]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HevcParams {}

/// Which engine configuration a write or a probe wants.
///
/// `Auto` is the default and means "the defaults of whichever format the
/// carrier turns out to be", which is what every existing caller does. Naming a
/// format pins that half explicitly -- and makes a mismatch (a PNG cost model on
/// a JPEG carrier) an error instead of a silently ignored field.
#[derive(Clone, Default, PartialEq)]
pub enum StegoTuning {
    /// Per-format defaults.
    #[default]
    Auto,
    /// Explicit spatial tuning; only valid for PNG carriers.
    #[cfg(feature = "content-png")]
    Png {
        /// Cost model to run.
        model: SpatialAlgorithm,
        /// Filter windows, codec and exclusion percentile.
        params: PngParams,
    },
    /// Explicit DCT tuning; only valid for JPEG carriers.
    #[cfg(feature = "content-jpeg")]
    Jpeg {
        /// Cost model to run.
        model: JpegAlgorithm,
        /// Neighbour weights, slot budget and cipher suite.
        params: JpegParams,
    },
    /// Explicit HEVC scheme selection.
    #[cfg(feature = "content-hevc")]
    Hevc {
        /// Whether the thumbnail bridge may be used as a fallback.
        mode: HevcMode,
        /// Reserved per-call knobs.
        params: HevcParams,
    },
}

impl std::fmt::Debug for StegoTuning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StegoTuning::Auto => f.write_str("Auto"),
            #[cfg(feature = "content-png")]
            StegoTuning::Png { model, params } => f
                .debug_struct("Png")
                .field("model", model)
                .field("codec", &params.codec)
                .field("stc_h", &params.stc_h)
                .finish(),
            #[cfg(feature = "content-jpeg")]
            StegoTuning::Jpeg { model, params } => f
                .debug_struct("Jpeg")
                .field("model", model)
                .field("cipher_suite", &params.cipher_suite)
                .field("stc_h", &params.stc_h)
                .finish(),
            #[cfg(feature = "content-hevc")]
            StegoTuning::Hevc { mode, .. } => f.debug_struct("Hevc").field("mode", mode).finish(),
        }
    }
}

impl StegoTuning {
    /// Explicit spatial tuning with the given parameters and the default model.
    #[cfg(feature = "content-png")]
    pub fn png(params: PngParams) -> Self {
        StegoTuning::Png {
            model: SpatialAlgorithm::default(),
            params,
        }
    }

    /// Explicit DCT tuning with the given parameters and the default model.
    #[cfg(feature = "content-jpeg")]
    pub fn jpeg(params: JpegParams) -> Self {
        StegoTuning::Jpeg {
            model: JpegAlgorithm::default(),
            params,
        }
    }

    /// Explicit HEVC scheme selection with the default (empty) params.
    #[cfg(feature = "content-hevc")]
    pub fn hevc(mode: HevcMode) -> Self {
        StegoTuning::Hevc {
            mode,
            params: HevcParams::default(),
        }
    }

    /// Reject a tuning that cannot apply to `format`.
    ///
    /// Naming one format's tuning while writing another is a caller mistake --
    /// today it is caught only inside the engine as "unknown or incompatible
    /// algorithm", after the carrier has already been decoded. The HEVC engine
    /// accepts any tuning on purpose: a HEIF carrier may legitimately be filled
    /// through its JPEG or PNG item, and that bridge picks whichever half the
    /// tuning names.
    pub(crate) fn applicable_to(&self, format: FileFormat) -> Result<(), StrHideError> {
        match (self, format) {
            (StegoTuning::Auto, _) => Ok(()),
            #[cfg(feature = "content-png")]
            (StegoTuning::Png { model, .. }, FileFormat::Png) => {
                let _ = model;
                Ok(())
            }
            #[cfg(feature = "content-jpeg")]
            (StegoTuning::Jpeg { .. }, FileFormat::Jpeg) => Ok(()),
            #[cfg(feature = "content-hevc")]
            (StegoTuning::Hevc { .. }, FileFormat::Heif | FileFormat::Mp4) => Ok(()),
            #[cfg(feature = "content-hevc")]
            (StegoTuning::Hevc { .. }, FileFormat::HevcAnnexB) => Ok(()),
            #[cfg(feature = "content-png")]
            (StegoTuning::Png { model, .. }, other) => Err(StrHideError::General(format!(
                "stego algorithm '{}' is a spatial (PNG) model and cannot be used on a {} carrier",
                model.id(),
                other.as_str()
            ))),
            #[cfg(feature = "content-jpeg")]
            (StegoTuning::Jpeg { model, .. }, other) => Err(StrHideError::General(format!(
                "stego algorithm '{}' is a JPEG DCT model and cannot be used on a {} carrier",
                model.id(),
                other.as_str()
            ))),
            #[cfg(feature = "content-hevc")]
            (StegoTuning::Hevc { .. }, other) => Err(StrHideError::General(format!(
                "the HEVC engine cannot be used on a {} carrier",
                other.as_str()
            ))),
            #[allow(unreachable_patterns)]
            _ => Ok(()),
        }
    }

    /// Fully resolved knobs, defaults filled in for formats the tuning does not
    /// name. Used by the HEIF bridge, which may end up in either half.
    pub(crate) fn resolve(&self) -> ResolvedTuning {
        #[allow(unused_mut)]
        let mut resolved = ResolvedTuning::default();
        match self {
            StegoTuning::Auto => {}
            #[cfg(feature = "content-png")]
            StegoTuning::Png { model, params } => {
                resolved.png_model = model.model();
                resolved.png_params = params.clone();
            }
            #[cfg(feature = "content-jpeg")]
            StegoTuning::Jpeg { model, params } => {
                resolved.jpeg_model = model.model();
                resolved.jpeg_params = params.clone();
            }
            #[cfg(feature = "content-hevc")]
            StegoTuning::Hevc { mode, .. } => resolved.hevc_mode = *mode,
        }
        resolved
    }
}

/// Every knob an engine needs, with the tuning half it does not name filled in
/// from the defaults.
#[derive(Clone)]
pub(crate) struct ResolvedTuning {
    #[cfg(feature = "content-png")]
    pub(crate) png_model: Arc<dyn PngCostModel>,
    #[cfg(feature = "content-png")]
    pub(crate) png_params: PngParams,
    #[cfg(feature = "content-jpeg")]
    pub(crate) jpeg_model: Arc<dyn JpegCostModel>,
    #[cfg(feature = "content-jpeg")]
    pub(crate) jpeg_params: JpegParams,
    #[cfg(feature = "content-hevc")]
    pub(crate) hevc_mode: HevcMode,
}

impl Default for ResolvedTuning {
    fn default() -> Self {
        Self {
            #[cfg(feature = "content-png")]
            png_model: SpatialAlgorithm::default().model(),
            #[cfg(feature = "content-png")]
            png_params: PngParams::default(),
            #[cfg(feature = "content-jpeg")]
            jpeg_model: JpegAlgorithm::default().model(),
            #[cfg(feature = "content-jpeg")]
            jpeg_params: JpegParams::default(),
            #[cfg(feature = "content-hevc")]
            hevc_mode: HevcMode::Auto,
        }
    }
}

/// Options for writing a payload into a carrier.
///
/// Everything here is either a per-call choice ([`tuning`](Self::tuning)), a
/// credential, or a policy. The private no-password secret is **not** here: it
/// is dialect state ([`StegoProfile`]) and travels as its own argument, so there
/// is exactly one object to store and pass around.
#[derive(Clone, Default)]
pub struct EmbedOptions<'a> {
    /// User password. Winning over the dialect's private secret when non-empty;
    /// an empty string counts as "not supplied".
    pub password: Option<&'a str>,
    /// HKDF domain-isolation tag; the dialect's tag is the fallback.
    pub domain: Option<&'a str>,
    /// Capacity safety tier and whether a breach is fatal.
    pub safety: SafetyPolicy,
    /// Cost model and per-format tuning.
    pub tuning: StegoTuning,
    /// Salt/nonce source: fresh randomness, or a seed for reproducible output.
    pub freshness: Freshness,
    /// Force a full capacity scan instead of the sampling estimate.
    pub exact: bool,
    /// Progress sink and cancellation token.
    pub control: Control<'a>,
    /// Rayon pool to run the engine on. `None` uses the global pool.
    pub pool: Option<Arc<rayon::ThreadPool>>,
    /// Omit original filename from micro-header even when payload came from a file.
    pub no_filename: bool,
}

impl PartialEq for EmbedOptions<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.password == other.password
            && self.domain == other.domain
            && self.safety == other.safety
            && self.tuning == other.tuning
            && self.freshness == other.freshness
            && self.exact == other.exact
            && self.control == other.control
            && self.no_filename == other.no_filename
            && match (&self.pool, &other.pool) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }
}

impl std::fmt::Debug for EmbedOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbedOptions")
            .field("password", &self.password.map(|_| "<redacted>"))
            .field("domain", &self.domain)
            .field("safety", &self.safety)
            .field("tuning", &self.tuning)
            .field("freshness", &self.freshness)
            .field("exact", &self.exact)
            .field("control", &self.control)
            .field("pool", &self.pool.as_ref().map(|_| "<ThreadPool>"))
            .field("no_filename", &self.no_filename)
            .finish()
    }
}

impl<'a> EmbedOptions<'a> {
    /// Omit original filename from micro-header.
    pub fn with_no_filename(mut self, no_filename: bool) -> Self {
        self.no_filename = no_filename;
        self
    }
    /// Set the password.
    pub fn with_password(mut self, password: &'a str) -> Self {
        self.password = Some(password);
        self
    }

    /// Set the HKDF domain-isolation tag.
    pub fn with_domain(mut self, domain: &'a str) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Set the capacity safety tier and its enforcement.
    pub fn with_safety(
        mut self,
        level: crate::stego::params::SafetyLevel,
        enforcement: crate::stego::params::SafetyEnforcement,
    ) -> Self {
        self.safety = SafetyPolicy { level, enforcement };
        self
    }

    /// Replace the tuning.
    pub fn with_tuning(mut self, tuning: StegoTuning) -> Self {
        self.tuning = tuning;
        self
    }

    /// Replace the PNG tuning, keeping the default model.
    #[cfg(feature = "content-png")]
    pub fn with_png_tuning(mut self, params: PngParams) -> Self {
        self.tuning = StegoTuning::png(params);
        self
    }

    /// Replace the JPEG tuning, keeping the default model.
    #[cfg(feature = "content-jpeg")]
    pub fn with_jpeg_tuning(mut self, params: JpegParams) -> Self {
        self.tuning = StegoTuning::jpeg(params);
        self
    }

    /// Set the salt/nonce source.
    pub fn with_freshness(mut self, freshness: Freshness) -> Self {
        self.freshness = freshness;
        self
    }

    /// Force (or stop forcing) an exact capacity scan.
    pub fn with_exact(mut self, exact: bool) -> Self {
        self.exact = exact;
        self
    }

    /// Attach a progress sink and cancellation token.
    pub fn with_control(mut self, control: Control<'a>) -> Self {
        self.control = control;
        self
    }

    /// Run the engine on `pool` instead of the global rayon pool.
    pub fn with_pool(mut self, pool: Arc<rayon::ThreadPool>) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Mutable PNG parameters, switching the tuning to the PNG arm first.
    ///
    /// For a caller that sets one knob without naming a model:
    /// `opts.png_params_mut().stc_h = 6`.
    #[cfg(feature = "content-png")]
    pub fn png_params_mut(&mut self) -> &mut PngParams {
        if !matches!(self.tuning, StegoTuning::Png { .. }) {
            let params = match std::mem::take(&mut self.tuning) {
                StegoTuning::Png { params, .. } => params,
                _ => PngParams::default(),
            };
            self.tuning = StegoTuning::png(params);
        }
        match &mut self.tuning {
            StegoTuning::Png { params, .. } => params,
            _ => unreachable!("the arm was just installed"),
        }
    }

    /// Mutable JPEG parameters, switching the tuning to the JPEG arm first.
    #[cfg(feature = "content-jpeg")]
    pub fn jpeg_params_mut(&mut self) -> &mut JpegParams {
        if !matches!(self.tuning, StegoTuning::Jpeg { .. }) {
            let params = match std::mem::take(&mut self.tuning) {
                StegoTuning::Jpeg { params, .. } => params,
                _ => JpegParams::default(),
            };
            self.tuning = StegoTuning::jpeg(params);
        }
        match &mut self.tuning {
            StegoTuning::Jpeg { params, .. } => params,
            _ => unreachable!("the arm was just installed"),
        }
    }

    /// Credential actually used: the explicit password wins, the dialect's
    /// private secret is the fallback, `None` means the public constant.
    ///
    /// An empty password is treated as "not supplied" and does **not** mask the
    /// dialect secret -- joining the two with `or` and filtering afterwards made
    /// `password = Some("")` silently drop the private secret.
    pub fn secret<'s>(&'s self, dialect: &'s StegoProfile) -> Option<&'s str>
    where
        'a: 's,
    {
        self.password
            .filter(|s| !s.is_empty())
            .or_else(|| dialect.secret())
    }

    /// Custom stego domain tag: the explicit one wins, the dialect's is the
    /// fallback.
    pub fn domain<'s>(&'s self, dialect: &'s StegoProfile) -> Option<&'s str>
    where
        'a: 's,
    {
        self.domain
            .filter(|s| !s.is_empty())
            .or_else(|| dialect.stego_domain())
    }

    /// A read-side option set that reuses this write's credentials.
    ///
    /// Embedding and then reading back with the same password is the common
    /// case (round-trip checks, the CLI's `--capacity` warning path); spelling
    /// it out by hand is how a caller ends up extracting with the wrong
    /// credential. The read-side policy (`limits`) and the tuning stay at their
    /// defaults: a carrier is self-describing.
    pub fn extract_options(&self) -> ExtractOptions<'_> {
        ExtractOptions {
            password: self.password,
            domain: self.domain,
            limits: ExtractParams::default(),
            control: self.control,
            pool: self.pool.clone(),
        }
    }

    /// A probe option set that reuses this write's credentials and tuning.
    ///
    /// A probe that advertises the capacity of a different configuration than
    /// the writer is worse than useless, so this shares `tuning`, `safety` and
    /// `exact` rather than defaulting them.
    pub fn probe_options(&self) -> ProbeOptions<'_> {
        ProbeOptions {
            password: self.password,
            domain: self.domain,
            safety: self.safety,
            tuning: self.tuning.clone(),
            exact: self.exact,
            control: self.control,
            pool: self.pool.clone(),
        }
    }
}

/// Options for a capacity probe.
///
/// Separate from [`EmbedOptions`] because a probe does not write: no salt
/// source, no write-side progress, but it does read the safety tier (the
/// recommendation is derived from it) and the tuning (a probe that advertises
/// the capacity of a different configuration than the writer is worse than
/// useless).
#[derive(Clone, Default)]
pub struct ProbeOptions<'a> {
    /// User password; keys the spatial header permutation.
    pub password: Option<&'a str>,
    /// HKDF domain-isolation tag.
    pub domain: Option<&'a str>,
    /// Capacity safety tier the recommendation is derived from.
    pub safety: SafetyPolicy,
    /// Cost model and per-format tuning.
    pub tuning: StegoTuning,
    /// Force a full scan instead of the sampling estimate.
    pub exact: bool,
    /// Progress sink and cancellation token.
    pub control: Control<'a>,
    /// Rayon pool to run on.
    pub pool: Option<Arc<rayon::ThreadPool>>,
}

impl PartialEq for ProbeOptions<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.password == other.password
            && self.domain == other.domain
            && self.safety == other.safety
            && self.tuning == other.tuning
            && self.exact == other.exact
            && self.control == other.control
            && match (&self.pool, &other.pool) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }
}

impl std::fmt::Debug for ProbeOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeOptions")
            .field("password", &self.password.map(|_| "<redacted>"))
            .field("domain", &self.domain)
            .field("safety", &self.safety)
            .field("tuning", &self.tuning)
            .field("exact", &self.exact)
            .field("control", &self.control)
            .field("pool", &self.pool.as_ref().map(|_| "<ThreadPool>"))
            .finish()
    }
}

impl<'a> ProbeOptions<'a> {
    /// Set the password.
    pub fn with_password(mut self, password: &'a str) -> Self {
        self.password = Some(password);
        self
    }

    /// Set the HKDF domain-isolation tag.
    pub fn with_domain(mut self, domain: &'a str) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Set the capacity safety tier and its enforcement.
    pub fn with_safety(
        mut self,
        level: crate::stego::params::SafetyLevel,
        enforcement: crate::stego::params::SafetyEnforcement,
    ) -> Self {
        self.safety = SafetyPolicy { level, enforcement };
        self
    }

    /// Replace the tuning.
    pub fn with_tuning(mut self, tuning: StegoTuning) -> Self {
        self.tuning = tuning;
        self
    }

    /// Replace the PNG tuning, keeping the default model.
    #[cfg(feature = "content-png")]
    pub fn with_png_tuning(mut self, params: PngParams) -> Self {
        self.tuning = StegoTuning::png(params);
        self
    }

    /// Replace the JPEG tuning, keeping the default model.
    #[cfg(feature = "content-jpeg")]
    pub fn with_jpeg_tuning(mut self, params: JpegParams) -> Self {
        self.tuning = StegoTuning::jpeg(params);
        self
    }

    /// Force (or stop forcing) an exact capacity scan.
    pub fn with_exact(mut self, exact: bool) -> Self {
        self.exact = exact;
        self
    }

    /// Attach a progress sink and cancellation token.
    pub fn with_control(mut self, control: Control<'a>) -> Self {
        self.control = control;
        self
    }

    /// Credential actually used (see [`EmbedOptions::secret`]).
    pub fn secret<'s>(&'s self, dialect: &'s StegoProfile) -> Option<&'s str>
    where
        'a: 's,
    {
        self.password
            .filter(|s| !s.is_empty())
            .or_else(|| dialect.secret())
    }

    /// Custom stego domain tag (see [`EmbedOptions::domain`]).
    pub fn domain<'s>(&'s self, dialect: &'s StegoProfile) -> Option<&'s str>
    where
        'a: 's,
    {
        self.domain
            .filter(|s| !s.is_empty())
            .or_else(|| dialect.stego_domain())
    }
}

/// Options for reading a payload back out.
///
/// No tuning (see the module docs: the carrier is self-describing), no salt
/// source, no safety policy -- a reader that refuses a carrier because it
/// exceeds a write-side tier would be inventing a failure.
#[derive(Clone, Default)]
pub struct ExtractOptions<'a> {
    /// User password.
    pub password: Option<&'a str>,
    /// HKDF domain-isolation tag.
    pub domain: Option<&'a str>,
    /// Cipher suites to try and the KDF work ceiling.
    pub limits: ExtractParams,
    /// Progress sink and cancellation token.
    pub control: Control<'a>,
    /// Rayon pool to run on.
    pub pool: Option<Arc<rayon::ThreadPool>>,
}

impl PartialEq for ExtractOptions<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.password == other.password
            && self.domain == other.domain
            && self.limits == other.limits
            && self.control == other.control
            && match (&self.pool, &other.pool) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }
}

impl std::fmt::Debug for ExtractOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtractOptions")
            .field("password", &self.password.map(|_| "<redacted>"))
            .field("domain", &self.domain)
            .field("limits", &self.limits)
            .field("control", &self.control)
            .field("pool", &self.pool.as_ref().map(|_| "<ThreadPool>"))
            .finish()
    }
}

impl<'a> ExtractOptions<'a> {
    /// Set the password.
    pub fn with_password(mut self, password: &'a str) -> Self {
        self.password = Some(password);
        self
    }

    /// Set the HKDF domain-isolation tag.
    pub fn with_domain(mut self, domain: &'a str) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Restrict the cipher suites this call will try.
    pub fn with_allowed_suites(mut self, suites: Vec<u16>) -> Self {
        self.limits.allowed_suites = Some(suites);
        self
    }

    /// Cap the PBKDF2 iterations one attempt may spend.
    pub fn with_max_pbkdf2_iterations(mut self, iterations: u32) -> Self {
        self.limits.max_pbkdf2_iterations = iterations;
        self
    }

    /// Attach a progress sink and cancellation token.
    pub fn with_control(mut self, control: Control<'a>) -> Self {
        self.control = control;
        self
    }

    /// Credential actually used (see [`EmbedOptions::secret`]).
    pub fn secret<'s>(&'s self, dialect: &'s StegoProfile) -> Option<&'s str>
    where
        'a: 's,
    {
        self.password
            .filter(|s| !s.is_empty())
            .or_else(|| dialect.secret())
    }

    /// Custom stego domain tag (see [`EmbedOptions::domain`]).
    pub fn domain<'s>(&'s self, dialect: &'s StegoProfile) -> Option<&'s str>
    where
        'a: 's,
    {
        self.domain
            .filter(|s| !s.is_empty())
            .or_else(|| dialect.stego_domain())
    }
}

/// Options for the HEIF thumbnail bridge.
///
/// The bridge is the one content-domain path that may end up in *either* half
/// (a JPEG thumbnail or a PNG `unci` item), so it takes a whole
/// [`StegoTuning`] and resolves it: naming a PNG cost model still lets a
/// JPEG-thumbnail carrier work, with UERD, because
/// `StegoTuning::resolve` fills the unnamed half from the defaults.
///
/// It is public because "embed only in the HEIF thumbnail, leave the primary
/// image alone" is a legitimate request the router does not expose: the router
/// always tries Scheme C first.
#[cfg(feature = "content-heif-bridge")]
#[derive(Debug, Clone)]
pub struct BridgeOptions<'a> {
    /// Private-dialect wire-format identities and no-password secret.
    pub dialect: &'a StegoProfile,
    /// User password. Wins over the dialect's private secret when non-empty.
    pub password: Option<&'a str>,
    /// HKDF domain-isolation tag.
    pub domain: Option<&'a str>,
    /// Cost model selection; see the type docs for how a mismatched half is
    /// resolved.
    pub tuning: StegoTuning,
    /// Capacity safety policy.
    pub safety: SafetyPolicy,
    /// Salt/nonce source. Unused on the read path, where it stays at its
    /// default.
    pub freshness: Freshness,
    /// Omit original filename from micro-header.
    pub no_filename: bool,
}

#[cfg(feature = "content-heif-bridge")]
impl Default for BridgeOptions<'_> {
    /// The official dialect: `BridgeOptions::default()` behaves exactly like
    /// the router with default options, which is what a test wants.
    fn default() -> Self {
        Self::new(&OFFICIAL_DIALECT)
    }
}

/// The official dialect, as a value a `Default` impl can borrow.
#[cfg(feature = "content-heif-bridge")]
static OFFICIAL_DIALECT: StegoProfile = StegoProfile::new();

#[cfg(feature = "content-heif-bridge")]
impl<'a> BridgeOptions<'a> {
    /// Official-dialect options with every knob at its default.
    pub const fn new(dialect: &'a StegoProfile) -> Self {
        Self {
            dialect,
            password: None,
            domain: None,
            tuning: StegoTuning::Auto,
            safety: SafetyPolicy::new(),
            freshness: Freshness::Random,
            no_filename: false,
        }
    }

    /// Set the password.
    pub fn with_password(mut self, password: &'a str) -> Self {
        self.password = Some(password);
        self
    }

    /// Set the HKDF domain-isolation tag.
    pub fn with_domain(mut self, domain: &'a str) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Replace the tuning.
    pub fn with_tuning(mut self, tuning: StegoTuning) -> Self {
        self.tuning = tuning;
        self
    }

    /// Credential actually used (see [`EmbedOptions::secret`]).
    pub fn resolved_secret<'s>(&'s self, dialect: &'s StegoProfile) -> Option<&'s str>
    where
        'a: 's,
    {
        self.password
            .filter(|s| !s.is_empty())
            .or_else(|| dialect.secret())
    }

    /// Custom stego domain tag (see [`EmbedOptions::domain`]).
    pub fn resolved_domain<'s>(&'s self, dialect: &'s StegoProfile) -> Option<&'s str>
    where
        'a: 's,
    {
        self.domain
            .filter(|s| !s.is_empty())
            .or_else(|| dialect.stego_domain())
    }
}

/// Exact carrier modification statistics reported by the embedder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbedStats {
    /// Number of elements (pixels, DCT coefficients, or CABAC bins) modified.
    pub modified_slots: usize,
    /// Total number of candidate elements in the carrier pool.
    pub total_candidate_slots: usize,
}

/// What an embed produced.
#[derive(Debug, Clone)]
pub struct EmbedOutput {
    /// The modified carrier.
    pub bytes: Vec<u8>,
    /// Capacity metadata, when the engine computed it while embedding.
    ///
    /// `None` for PNG and JPEG on purpose: their embedders do not run the
    /// capacity model, and inventing numbers here (as an earlier sketch did)
    /// would report a budget nobody actually checked. Call
    /// [`probe`](crate::stego::probe_carrier_capacity) when the number matters.
    pub capacity: Option<StegoCapacityInfo>,
    /// Exact modification statistics from the embedder, when available.
    pub stats: Option<EmbedStats>,
}

impl EmbedOutput {
    /// An output with no capacity metadata or embed stats.
    pub fn bytes_only(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            capacity: None,
            stats: None,
        }
    }

    /// An output with both bytes and embed statistics.
    pub fn with_stats(bytes: Vec<u8>, stats: EmbedStats) -> Self {
        Self {
            bytes,
            capacity: None,
            stats: Some(stats),
        }
    }
}

/// Advisory warnings produced during steganographic embedding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StegoWarning {
    SafetyThresholdExceeded {
        payload_bytes: usize,
        recommended_max_bytes: usize,
        safety_level: String,
        actual_bpp: f64,
        limit_bpp: f64,
    },
}

/// Structured outcome of embedding into a carrier file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StegoEmbedResult {
    pub carrier: PathBuf,
    pub written_to: PathBuf,
    pub format: crate::formats::FileFormat,
    pub payload_bytes: usize,
    pub carrier_before_bytes: u64,
    pub carrier_after_bytes: u64,
    pub backup_file: Option<PathBuf>,
    pub capacity: Option<StegoCapacityInfo>,
    pub stats: Option<EmbedStats>,
    pub warnings: Vec<StegoWarning>,
}

/// Read-only steganographic header diagnostics obtained without full payload decoding.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StegoHeaderInfo {
    pub format: String,
    pub has_hidden_data: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_len: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_len: Option<usize>,
    /// Resolution (and, for video carriers, frame rate/duration/bitrate) of
    /// the carrier, when it could be parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_info: Option<crate::core::media::MediaInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl StegoHeaderInfo {
    pub fn empty(format: impl Into<String>) -> Self {
        Self {
            format: format.into(),
            has_hidden_data: false,
            algorithm: None,
            codec: None,
            envelope_len: None,
            payload_len: None,
            media_info: None,
            note: None,
        }
    }
}

/// Options for inspecting a content carrier for steganographic headers.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct InspectOptions<'a> {
    pub password: Option<&'a str>,
    pub domain: Option<&'a str>,
    pub limits: ExtractParams,
    pub control: Control<'a>,
}

impl std::fmt::Debug for InspectOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InspectOptions")
            .field("password", &self.password.map(|_| "<redacted>"))
            .field("domain", &self.domain)
            .field("limits", &self.limits)
            .field("control", &self.control)
            .finish()
    }
}

impl<'a> InspectOptions<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_password(mut self, password: &'a str) -> Self {
        self.password = Some(password);
        self
    }

    pub fn with_domain(mut self, domain: &'a str) -> Self {
        self.domain = Some(domain);
        self
    }

    pub fn with_limits(mut self, limits: ExtractParams) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_control(mut self, control: Control<'a>) -> Self {
        self.control = control;
        self
    }

    pub fn secret<'s>(&'s self, dialect: &'s StegoProfile) -> Option<&'s str>
    where
        'a: 's,
    {
        self.password
            .filter(|s| !s.is_empty())
            .or_else(|| dialect.secret())
    }

    pub fn domain<'s>(&'s self, dialect: &'s StegoProfile) -> Option<&'s str>
    where
        'a: 's,
    {
        self.domain
            .filter(|s| !s.is_empty())
            .or_else(|| dialect.stego_domain())
    }
}

/// Status of one verification tier.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VerifyLevel {
    pub level: u8,
    pub name: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl VerifyLevel {
    pub fn render_message(&self, _ctx: crate::core::i18n::RenderCtx) -> Option<&str> {
        self.message.as_deref()
    }

    pub fn pass(level: u8, name: impl Into<String>) -> Self {
        Self {
            level,
            name: name.into(),
            ok: true,
            message: None,
        }
    }

    pub fn fail(level: u8, name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            level,
            name: name.into(),
            ok: false,
            message: Some(message.into()),
        }
    }
}

/// Three-tier diagnostic verification result for content carriers.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StegoVerifyResult {
    pub format: String,
    pub levels: Vec<VerifyLevel>,
}

impl StegoVerifyResult {
    pub fn new(format: impl Into<String>, levels: Vec<VerifyLevel>) -> Self {
        Self {
            format: format.into(),
            levels,
        }
    }

    pub fn is_all_ok(&self) -> bool {
        self.levels.iter().all(|l| l.ok)
    }
}

/// Options for verifying a content carrier through diagnostic levels.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct VerifyOptions<'a> {
    pub password: Option<&'a str>,
    pub domain: Option<&'a str>,
    pub limits: ExtractParams,
    pub control: Control<'a>,
}

impl std::fmt::Debug for VerifyOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyOptions")
            .field("password", &self.password.map(|_| "<redacted>"))
            .field("domain", &self.domain)
            .field("limits", &self.limits)
            .field("control", &self.control)
            .finish()
    }
}

impl<'a> VerifyOptions<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_password(mut self, password: &'a str) -> Self {
        self.password = Some(password);
        self
    }

    pub fn with_domain(mut self, domain: &'a str) -> Self {
        self.domain = Some(domain);
        self
    }

    pub fn with_limits(mut self, limits: ExtractParams) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_control(mut self, control: Control<'a>) -> Self {
        self.control = control;
        self
    }

    pub fn secret<'s>(&'s self, dialect: &'s StegoProfile) -> Option<&'s str>
    where
        'a: 's,
    {
        self.password
            .filter(|s| !s.is_empty())
            .or_else(|| dialect.secret())
    }

    pub fn domain<'s>(&'s self, dialect: &'s StegoProfile) -> Option<&'s str>
    where
        'a: 's,
    {
        self.domain
            .filter(|s| !s.is_empty())
            .or_else(|| dialect.stego_domain())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_tuning_accepts_every_format() {
        let tuning = StegoTuning::Auto;
        for format in [
            FileFormat::Png,
            FileFormat::Jpeg,
            FileFormat::Heif,
            FileFormat::Mp4,
            FileFormat::HevcAnnexB,
        ] {
            assert!(
                tuning.applicable_to(format).is_ok(),
                "Auto must be usable on {format:?}"
            );
        }
    }

    #[test]
    fn format_specific_tuning_rejects_the_wrong_carrier() {
        let png = StegoTuning::Png {
            model: SpatialAlgorithm::Suniward,
            params: PngParams::default(),
        };
        assert!(png.applicable_to(FileFormat::Png).is_ok());
        let err = png.applicable_to(FileFormat::Jpeg).expect_err("mismatch");
        assert!(
            err.to_string().contains("suniward") && err.to_string().contains("JPEG"),
            "the message must name both sides: {err}"
        );

        let jpeg = StegoTuning::jpeg(JpegParams::default());
        assert!(jpeg.applicable_to(FileFormat::Jpeg).is_ok());
        assert!(jpeg.applicable_to(FileFormat::Png).is_err());

        let hevc = StegoTuning::hevc(HevcMode::Cabac);
        for format in [FileFormat::Heif, FileFormat::Mp4, FileFormat::HevcAnnexB] {
            assert!(hevc.applicable_to(format).is_ok());
        }
        assert!(hevc.applicable_to(FileFormat::Png).is_err());
    }

    #[test]
    fn resolve_fills_the_halves_the_tuning_does_not_name() {
        let tuning = StegoTuning::Png {
            model: SpatialAlgorithm::Suniward,
            params: PngParams {
                stc_h: 6,
                ..PngParams::default()
            },
        };
        let resolved = tuning.resolve();
        assert_eq!(resolved.png_model.id(), "suniward");
        assert_eq!(resolved.png_params.stc_h, 6);
        // The JPEG half stays at its defaults so the HEIF bridge still works.
        assert_eq!(resolved.jpeg_model.id(), "uerd");
        assert_eq!(resolved.jpeg_params, JpegParams::default());
        assert_eq!(resolved.hevc_mode, HevcMode::Auto);
    }

    #[test]
    fn params_mut_helpers_install_the_right_arm() {
        let mut opts = EmbedOptions::default();
        opts.png_params_mut().stc_h = 5;
        match &opts.tuning {
            StegoTuning::Png { params, .. } => assert_eq!(params.stc_h, 5),
            other => panic!("expected the PNG arm, got {other:?}"),
        }
        // Switching to the other half keeps the value already set.
        opts.jpeg_params_mut().stc_h = 7;
        match &opts.tuning {
            StegoTuning::Jpeg { params, .. } => assert_eq!(params.stc_h, 7),
            other => panic!("expected the JPEG arm, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_password_does_not_mask_the_dialect_secret() {
        let dialect = StegoProfile::new().with_default_secret("org-key");
        let opts = EmbedOptions::default().with_password("");
        assert_eq!(opts.secret(&dialect), Some("org-key"));

        let opts = EmbedOptions::default().with_password("user-pw");
        assert_eq!(opts.secret(&dialect), Some("user-pw"));

        let official = StegoProfile::new();
        assert_eq!(EmbedOptions::default().secret(&official), None);
    }

    #[test]
    fn domain_falls_back_to_the_dialect() {
        let dialect = StegoProfile::new().with_stego_domain("org/domain");
        assert_eq!(ProbeOptions::default().domain(&dialect), Some("org/domain"));
        assert_eq!(
            ProbeOptions::default().with_domain("call").domain(&dialect),
            Some("call")
        );
    }

    #[test]
    fn algorithm_names_round_trip_through_the_public_parsers() {
        for name in ["hill", "suniward"] {
            let model = SpatialAlgorithm::from_name(name).expect(name);
            assert_eq!(model.id(), name);
            assert_eq!(model.model().id(), name);
        }
        for name in ["uerd", "juniward"] {
            let model = JpegAlgorithm::from_name(name).expect(name);
            assert_eq!(model.id(), name);
            assert_eq!(model.model().id(), name);
        }
        assert_eq!(SpatialAlgorithm::from_name("auto").unwrap().id(), "hill");
        assert_eq!(JpegAlgorithm::from_name("auto").unwrap().id(), "uerd");
        assert!(SpatialAlgorithm::from_name("juniward").is_none());
        assert!(JpegAlgorithm::from_name("hill").is_none());
        assert!(HevcMode::from_name("cabac").is_some());
        assert!(HevcMode::from_name("nope").is_none());
    }

    #[test]
    fn password_is_redacted_in_debug() {
        let opts = EmbedOptions::default().with_password("super-secret-password");
        let debug = format!("{opts:?}");
        assert!(!debug.contains("super-secret-password"));
        assert!(debug.contains("<redacted>"));

        let probe = ProbeOptions::default().with_password("super-secret-password");
        let debug_probe = format!("{probe:?}");
        assert!(!debug_probe.contains("super-secret-password"));
        assert!(debug_probe.contains("<redacted>"));

        let extract = ExtractOptions::default().with_password("super-secret-password");
        let debug_extract = format!("{extract:?}");
        assert!(!debug_extract.contains("super-secret-password"));
        assert!(debug_extract.contains("<redacted>"));

        let inspect = InspectOptions::default().with_password("super-secret-password");
        let debug_inspect = format!("{inspect:?}");
        assert!(!debug_inspect.contains("super-secret-password"));
        assert!(debug_inspect.contains("<redacted>"));

        let verify = VerifyOptions::default().with_password("super-secret-password");
        let debug_verify = format!("{verify:?}");
        assert!(!debug_verify.contains("super-secret-password"));
        assert!(debug_verify.contains("<redacted>"));
    }
}
