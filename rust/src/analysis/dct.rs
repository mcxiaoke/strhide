//! Frequency-domain statistics for JPEG carriers.

use super::calibration;
use super::{DetectorMetric, Finding, Severity};

/// Calibrated DCT estimate at which a JPEG is reported as suspicious.
///
/// Recalibrated for the ternary (V3) embedding model on the 80-carrier corpus
/// (2026-10-21): the statistic now also looks at the `(0, 1)` pair, which is
/// where `0 <-> ±1` moves land. Measured on that corpus:
///
/// | population | median | max |
/// | :--- | ---: | ---: |
/// | clean | 0.000 | 0.011 |
/// | recommended load (bpp <= 0.10) | 0.000 | 0.007 |
/// | full capacity | 0.141 | 0.741 |
///
/// `0.05` is 4.5x above the highest clean value and detects 85% of
/// full-capacity carriers; the recommended load stays undetected by design.
/// This is a heuristic with a measured false-negative rate, not a proof procedure.
const CALIBRATION_FLAG_RATE: f64 = 0.05;
/// Estimate above which the finding is raised to `Likely`.
const CALIBRATION_STRONG_RATE: f64 = 0.15;

pub(super) fn track_jpeg_dct_domain(
    data: &[u8],
    findings: &mut Vec<Finding>,
    detectors: &mut Vec<DetectorMetric>,
    calibrated_signal: &mut bool,
) {
    // 1. Calibrated DCT Analysis (Fridrich 2002)
    let coefficients = dct_io::read_coefficients(data).ok();
    if let Some(est) = coefficients
        .as_ref()
        .and_then(|c| calibration::estimate_with_coefficients(data, c))
    {
        if est.rate >= CALIBRATION_FLAG_RATE {
            *calibrated_signal = true;
            findings.push(Finding {
                detector: "dct:calibration".into(),
                severity: if est.rate >= CALIBRATION_STRONG_RATE {
                    Severity::Likely
                } else {
                    Severity::Suspicious
                },
                detail: format!(
                    "Calibrated DCT estimate: ~{:.0}% of coefficients look LSB-replaced (rate {:.3}, imbalance ratio {:.2} vs calibrated reference, {} blocks)",
                    est.rate * 100.0,
                    est.rate,
                    est.imbalance_ratio,
                    est.blocks
                ),
            });
            detectors.push(DetectorMetric {
                name: "dct:calibration".into(),
                domain: "dct".into(),
                status: "ALERT".into(),
                metric: format!("rate: {:.3}", est.rate),
                threshold: Some(format!("{CALIBRATION_FLAG_RATE:.3}")),
                detail: format!(
                    "imbalance: {:.3}, {} blocks",
                    est.imbalance_ratio, est.blocks
                ),
            });
        } else {
            detectors.push(DetectorMetric {
                name: "dct:calibration".into(),
                domain: "dct".into(),
                status: "PASS".into(),
                metric: format!("rate: {:.3}", est.rate),
                threshold: Some(format!("{CALIBRATION_FLAG_RATE:.3}")),
                detail: format!(
                    "imbalance: {:.3}, {} blocks",
                    est.imbalance_ratio, est.blocks
                ),
            });
        }
    } else {
        detectors.push(DetectorMetric {
            name: "dct:calibration".into(),
            domain: "dct".into(),
            status: "SKIPPED".into(),
            metric: "n/a".into(),
            threshold: Some(format!("{CALIBRATION_FLAG_RATE:.3}")),
            // The check is `mean step < 2` (which fine quantization tables trip),
            // or other unreadable states (unreadable DQT, CMYK/16-bit, geometry mismatch).
            detail: "quantisation too fine for calibration (mean step < 2), \
                     or the DQT/pixel data could not be read"
                .into(),
        });
    }

    // 2. DCT AC Pairs Chi-Square Analysis (Westfeld 2001)
    if let Some(suspicion) = coefficients
        .as_ref()
        .and_then(calibration::dct_chi2_suspicion_with_coefficients)
    {
        if suspicion > 0.50 {
            findings.push(Finding {
                detector: "dct:chi2".into(),
                severity: Severity::Suspicious,
                detail: format!("DCT AC pairs heavily equalized (suspicion {suspicion:.2})"),
            });
            detectors.push(DetectorMetric {
                name: "dct:chi2".into(),
                domain: "dct".into(),
                status: "ALERT".into(),
                metric: format!("suspicion: {suspicion:.3}"),
                threshold: Some("0.500".into()),
                detail: "AC coefficient pair equalization detected".into(),
            });
        } else {
            detectors.push(DetectorMetric {
                name: "dct:chi2".into(),
                domain: "dct".into(),
                status: "PASS".into(),
                metric: format!("suspicion: {suspicion:.3}"),
                threshold: Some("0.500".into()),
                detail: "natural Laplacian AC coefficient decay".into(),
            });
        }
    } else {
        // Explicitly report skipped detector status and reason to distinguish
        // from a passing detector.
        let detail = if coefficients.is_none() {
            "no readable DCT coefficient stream"
        } else {
            "too few AC coefficient pairs with enough samples for chi-square"
        };
        detectors.push(DetectorMetric {
            name: "dct:chi2".into(),
            domain: "dct".into(),
            status: "SKIPPED".into(),
            metric: "n/a".into(),
            threshold: Some("0.500".into()),
            detail: detail.into(),
        });
    }
}
