//! Perceptual distortion cost for one PCM slot.
//!
//! The model prices a `±1` LSB move at a slot by how much the ear is likely to
//! notice it. Two local statistics carry almost all of the signal:
//!
//! * **Short-time energy** (`rms` over `±window` slots). Loud passages mask a
//!   1-LSB error; digital silence does the opposite. This is the audio analogue
//!   of HILL's texture term for images.
//! * **First difference** (`|s[i] - s[i-1]|`). A steep slope means the waveform
//!   is already moving, so a one-unit nudge is buried in the motion; a flat
//!   stretch (pure tone or silence) makes it stand out.
//!
//! `rho = 1 / (eps + rms + 0.5 * d1)` -- low cost in busy, loud passages where
//! STC will prefer to spend its changes.
//!
//! # Silence
//!
//! Digital silence (all-zero samples) is the one place a `±1` change is *more*
//! audible than anywhere else: it turns a mathematically exact zero into a DC
//! offset and produces a click at the edit point. `rms == 0 && d1 == 0` therefore
//! returns [`SILENCE_COST`], a finite but enormous value. It must stay finite:
//! STC solves over `f64` costs and an `inf` poisons the trellis comparisons.
//!
//! # Extract-side independence
//!
//! Extraction never runs this model. Slot *positions* come from the keyed
//! permutation and the carrier geometry alone, so the cost function is free to
//! use anything the embedder can see (including the cover's own statistics)
//! without the reader having to reproduce it.

/// Half-width of the RMS window, in slots.
///
/// 16 slots at 44.1 kHz stereo is ~0.4 ms -- shorter than the ear's temporal
/// integration window, so it tracks transients rather than averaging across
/// them, and it keeps the per-slot work at ~33 reads.
///
/// The value is carried in the feature word as `2 * window + 1`, which the
/// wire format constrains to odd values <= 63, i.e. `window <= 31`.
pub(crate) const DEFAULT_WINDOW: usize = 16;

/// Additive floor of the cost denominator, in normalised amplitude units.
///
/// Without it a unit-amplitude passage would drive the cost to zero and let the
/// trellis ignore the model entirely.
pub(crate) const DEFAULT_EPSILON: f64 = 1e-3;

/// Cost assigned to a slot sitting in digital silence.
pub(crate) const SILENCE_COST: f64 = 1e6;

/// Below this normalised energy a window counts as silence.
const SILENCE_FLOOR: f64 = 1e-7;

/// Amplitude normalisation for one sample layout.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PcmScale {
    /// Value that maps to `0.0` (128 for unsigned 8-bit, else 0).
    pub center: f64,
    /// Divisor that maps full scale to `±1.0`.
    pub full: f64,
}

impl PcmScale {
    /// Scale for a layout with `bits` significant bits and a `center` bias.
    pub(crate) fn new(bits: u32, center: i32) -> Self {
        Self {
            center: center as f64,
            full: (1u64 << (bits - 1)) as f64,
        }
    }

    #[inline]
    fn normalise(self, value: i32) -> f64 {
        (value as f64 - self.center) / self.full
    }
}

/// Cost model parameters, recorded in the feature word so the prober and the
/// embedder agree on the *advertised* capacity (the extractor ignores both).
#[derive(Debug, Clone, Copy)]
pub(crate) struct CostParams {
    pub window: usize,
    pub epsilon: f64,
}

impl Default for CostParams {
    fn default() -> Self {
        Self {
            window: DEFAULT_WINDOW,
            epsilon: DEFAULT_EPSILON,
        }
    }
}

impl CostParams {
    /// Cost of moving the slot at `index` by one unit, using `read` to sample
    /// the carrier (`slot_count` bounds the window).
    pub(crate) fn cost_at<F>(
        &self,
        slot_count: usize,
        index: usize,
        scale: PcmScale,
        read: F,
    ) -> f64
    where
        F: Fn(usize) -> i32,
    {
        let window = self.window.max(1);
        let lo = index.saturating_sub(window);
        let hi = (index + window + 1).min(slot_count);
        let mut energy = 0.0f64;
        for j in lo..hi {
            let s = scale.normalise(read(j));
            energy += s * s;
        }
        let count = (hi - lo).max(1) as f64;
        let rms = (energy / count).sqrt();

        let d1 = if index == 0 {
            0.0
        } else {
            (scale.normalise(read(index)) - scale.normalise(read(index - 1))).abs()
        };

        if rms < SILENCE_FLOOR && d1 < SILENCE_FLOOR {
            return SILENCE_COST;
        }
        1.0 / (self.epsilon + rms + 0.5 * d1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scale16() -> PcmScale {
        PcmScale::new(16, 0)
    }

    #[test]
    fn silence_is_the_most_expensive_place_to_write() {
        let params = CostParams::default();
        let silent = |_: usize| 0i32;
        let loud = |i: usize| if i.is_multiple_of(2) { 20_000 } else { -20_000 };

        let quiet_cost = params.cost_at(4096, 2048, scale16(), silent);
        let loud_cost = params.cost_at(4096, 2048, scale16(), loud);
        assert_eq!(quiet_cost, SILENCE_COST);
        assert!(
            loud_cost < quiet_cost / 1000.0,
            "loud passage {loud_cost} must be far cheaper than silence"
        );
    }

    #[test]
    fn a_steep_slope_is_cheaper_than_a_flat_one_at_equal_energy() {
        let params = CostParams::default();
        // Both windows have the same |amplitude|; only the local motion differs.
        let flat = |i: usize| {
            if i < 2048 { 8_000 } else { -8_000 }
        };
        let steep = |i: usize| {
            if i < 2048 {
                8_000
            } else if i.is_multiple_of(2) {
                -8_000
            } else {
                8_000
            }
        };
        let flat_cost = params.cost_at(4096, 2048, scale16(), flat);
        let steep_cost = params.cost_at(4096, 2048, scale16(), steep);
        assert!(
            steep_cost <= flat_cost,
            "motion should not raise the cost: flat {flat_cost}, steep {steep_cost}"
        );
    }

    #[test]
    fn cost_is_always_finite_and_positive() {
        let params = CostParams::default();
        for value in [i32::MIN, -1, 0, 1, i32::MAX] {
            let read = move |_: usize| value;
            let cost = params.cost_at(64, 32, PcmScale::new(32, 0), read);
            assert!(cost.is_finite() && cost > 0.0, "value {value} -> {cost}");
        }
    }

    #[test]
    fn window_is_clamped_at_the_carrier_edges() {
        let params = CostParams::default();
        let read = |_: usize| 1_000i32;
        for index in [0usize, 1, 63] {
            let cost = params.cost_at(64, index, scale16(), read);
            assert!(cost.is_finite() && cost > 0.0);
        }
    }
}
