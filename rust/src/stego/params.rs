//! Steganography configuration parameters and fine-tuning interfaces.
//!
//! Designed to allow runtime parameter adjustment, custom confusion/anti-detection
//! weights, and future configuration file deserialization.

use serde::{Deserialize, Serialize};

use crate::errors::StrHideError;
use crate::params::Profile;

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
    /// Cost assigned to unembeddable or excluded pixels.
    pub wet_cost: f64,
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
            wet_cost: 1e13,
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
        if !self.wet_cost.is_finite() || self.wet_cost <= 0.0 {
            return Err(StrHideError::General(format!(
                "HILL parameter 'wet_cost' must be a finite positive number, got {}",
                self.wet_cost
            )));
        }
        Ok(())
    }
}

/// Fine-tuning parameters for JPEG-domain DCT steganography (e.g. UERD).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JpegParams {
    /// Weight applied to the 8-neighborhood block energies (default 0.25).
    pub neighbor_weight: f64,
    /// Weight applied to DC mode quantization step (default 0.5).
    pub mode_dc_weight: f64,
    /// Minimum absolute coefficient value eligible for embedding (default 1 to skip zero AC).
    pub min_abs_coeff: i16,
    /// Fraction of lowest-energy DCT blocks to completely exclude from embedding (default 0.20).
    pub block_exclusion_percentile: f64,
    /// Cost assigned to unembeddable or excluded coefficients.
    pub wet_cost: f64,
}

impl Default for JpegParams {
    fn default() -> Self {
        Self {
            neighbor_weight: 0.25,
            mode_dc_weight: 0.5,
            min_abs_coeff: 1,
            block_exclusion_percentile: 0.20,
            wet_cost: 1e13,
        }
    }
}

impl JpegParams {
    /// Reject parameter values that would produce a NaN/Inf cost map or an
    /// empty candidate set (both surface later as an opaque "no capacity" or
    /// "no hidden data" error instead of a configuration error).
    pub fn validate(&self) -> Result<(), StrHideError> {
        for (name, value) in [
            ("neighbor_weight", self.neighbor_weight),
            ("mode_dc_weight", self.mode_dc_weight),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(StrHideError::General(format!(
                    "UERD parameter '{name}' must be a finite non-negative number, got {value}"
                )));
            }
        }
        if self.min_abs_coeff < 0 {
            return Err(StrHideError::General(format!(
                "UERD parameter 'min_abs_coeff' must be >= 0, got {}",
                self.min_abs_coeff
            )));
        }
        if !(0.0..1.0).contains(&self.block_exclusion_percentile) {
            return Err(StrHideError::General(format!(
                "UERD parameter 'block_exclusion_percentile' must be in [0, 1), got {}",
                self.block_exclusion_percentile
            )));
        }
        if !self.wet_cost.is_finite() || self.wet_cost <= 0.0 {
            return Err(StrHideError::General(format!(
                "UERD parameter 'wet_cost' must be a finite positive number, got {}",
                self.wet_cost
            )));
        }
        Ok(())
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
    /// Fine-tuning parameters for spatial domain algorithms.
    pub spatial_params: SpatialParams,
    /// Fine-tuning parameters for JPEG DCT domain algorithms.
    pub jpeg_params: JpegParams,
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
}
