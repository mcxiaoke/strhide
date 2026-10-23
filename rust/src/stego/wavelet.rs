//! Daubechies-8 wavelet filter bank, shared by the UNIWARD family.
//!
//! S-UNIWARD (spatial) and J-UNIWARD (DCT) both measure distortion in the same
//! three directional wavelet sub-bands, so the filters live here instead of
//! being duplicated in each cost model.
//!
//! The 2D filters are separable by construction: `F = a ⊗ b` for 1D pairs
//! `(a, b) ∈ {(lpdf, hpdf), (hpdf, lpdf), (hpdf, hpdf)}`. That is not a
//! convenience -- it is what makes both implementations affordable, because the
//! residual pass and the suitability pass each collapse to two 16-tap 1D runs
//! instead of a 16x16 2D convolution.

/// First 1D filter of the bank, 16 taps (Daubechies-8).
///
/// # Naming
///
/// The UNIWARD reference implementations call this array `hpdf`, but in this
/// convention it is the **detail** filter: its taps sum to zero, so a constant
/// plane produces no response. The smoothing filter is the derived [`lpdf`],
/// whose taps sum to `sqrt(2)`. The names are kept to match the papers and the
/// reference code; only the pair matters, and [`bands`] uses them in the order
/// the papers list the three sub-bands.
pub const HPDF: [f64; 16] = [
    -0.0544158422,
    0.3128715909,
    -0.6756307363,
    0.5853546837,
    0.0158291053,
    -0.2840155430,
    -0.0004724846,
    0.1287474266,
    0.0173693010,
    -0.0440882539,
    -0.0139810279,
    0.0087460940,
    0.0048703530,
    -0.0003917404,
    -0.0006754494,
    -0.0001174768,
];

/// Smoothing filter derived from [`HPDF`]: `lpdf[i] = (-1)^i * hpdf[15 - i]`.
///
/// Sum of taps is `sqrt(2)`, i.e. it passes a constant plane; orthogonal to
/// [`HPDF`] with unit energy, so the bank is orthonormal.
pub fn lpdf() -> [f64; 16] {
    let mut out = [0.0f64; 16];
    for (i, v) in out.iter_mut().enumerate() {
        let sign = if i % 2 == 0 { 1.0 } else { -1.0 };
        *v = sign * HPDF[15 - i];
    }
    out
}

/// Tap count of one 1D filter.
pub const TAPS: usize = 16;

/// Half the filter support, i.e. the centring offset used by the residual pass.
pub const HALF: usize = TAPS / 2;

/// The three directional sub-bands, as separable 1D pairs.
///
/// Order matches the UNIWARD papers: horizontal, vertical, diagonal.
pub fn bands() -> [([f64; 16], [f64; 16]); 3] {
    let l = lpdf();
    let h = HPDF;
    [(l, h), (h, l), (h, h)]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both filters must have unit energy: the bank is orthonormal.
    #[test]
    fn both_filters_are_normalised() {
        let energy: f64 = HPDF.iter().map(|v| v * v).sum();
        assert!(
            (energy - 1.0).abs() < 1e-6,
            "Daubechies-8 must have unit energy, got {energy}"
        );
    }

    /// Reversing and sign-flipping must keep the same energy, and the two
    /// filters must be orthogonal to each other (perfect reconstruction bank).
    #[test]
    fn highpass_is_orthogonal_to_lowpass() {
        let l = lpdf();
        let l_energy: f64 = l.iter().map(|v| v * v).sum();
        assert!((l_energy - 1.0).abs() < 1e-6, "lpdf energy {l_energy}");

        let dot: f64 = HPDF.iter().zip(l.iter()).map(|(a, b)| a * b).sum();
        assert!(
            dot.abs() < 1e-6,
            "the two filters must be orthogonal, got {dot}"
        );
    }

    /// A constant plane must survive the smoothing filter and vanish in the
    /// detail filter. That asymmetry is the whole reason the distortion measure
    /// is high in smooth areas and low in texture.
    #[test]
    fn detail_filter_rejects_dc() {
        let detail: f64 = HPDF.iter().sum();
        let smooth: f64 = lpdf().iter().sum();
        assert!(
            detail.abs() < 1e-6,
            "the detail filter must reject DC, got {detail}"
        );
        assert!(
            (smooth - std::f64::consts::SQRT_2).abs() < 1e-6,
            "the smoothing filter must pass DC with gain sqrt(2), got {smooth}"
        );
    }
}
