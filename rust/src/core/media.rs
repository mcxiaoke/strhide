//! Container media metadata: one typed shape for "how big is this carrier?".
//!
//! Before stage 4 every carrier reported this as a pre-rendered English string
//! (`"4032x3024"`, `"1920x1080, 24.00 fps, 11.9s (15.2 Mbps)"`), so a front end
//! that wanted to sort by resolution, filter by bitrate, or show the numbers in
//! another locale had to parse them back out of prose (plan §5.3).

use serde::{Deserialize, Serialize};

/// Pixel (and, for video carriers, temporal) dimensions of a carrier.
///
/// Every field beyond `width`/`height` is optional because not every format
/// carries it: a PNG has no frame rate, an Annex-B H.265 stream has no declared
/// duration.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct MediaInfo {
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// Frames per second, when the container declares a constant rate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fps: Option<f32>,
    /// Duration in milliseconds, when the container declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Overall bitrate in bits per second (file size / duration).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitrate_bps: Option<u64>,
}

impl MediaInfo {
    /// Dimensions only.
    pub const fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            fps: None,
            duration_ms: None,
            bitrate_bps: None,
        }
    }

    /// Add frame rate, duration, and bitrate (video carriers).
    pub const fn with_video(mut self, fps: f32, duration_ms: u64, bitrate_bps: u64) -> Self {
        self.fps = Some(fps);
        self.duration_ms = Some(duration_ms);
        self.bitrate_bps = Some(bitrate_bps);
        self
    }

    /// Pixel count (`width * height`), saturating.
    pub const fn pixels(&self) -> u64 {
        self.width as u64 * self.height as u64
    }

    /// True when both dimensions are known and non-zero.
    pub const fn has_dimensions(&self) -> bool {
        self.width > 0 && self.height > 0
    }
}

impl std::fmt::Display for MediaInfo {
    /// The historical one-line summary, kept verbatim so the CLI's text output
    /// does not change when the field became typed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}x{}", self.width, self.height)?;
        if let (Some(fps), Some(ms), Some(bps)) = (self.fps, self.duration_ms, self.bitrate_bps) {
            write!(
                f,
                ", {fps:.2} fps, {:.1}s ({:.1} Mbps)",
                ms as f64 / 1000.0,
                bps as f64 / 1_000_000.0
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_image_renders_dimensions_only() {
        let m = MediaInfo::new(4032, 3024);
        assert_eq!(m.to_string(), "4032x3024");
        assert!(m.has_dimensions());
        assert_eq!(m.pixels(), 4032 * 3024);
        assert_eq!(m.fps, None);
    }

    #[test]
    fn video_renders_the_historical_format() {
        let m = MediaInfo::new(1920, 1080).with_video(24.0, 11_900, 15_200_000);
        assert_eq!(m.to_string(), "1920x1080, 24.00 fps, 11.9s (15.2 Mbps)");
    }

    #[test]
    fn empty_media_has_no_dimensions() {
        let m = MediaInfo::default();
        assert!(!m.has_dimensions());
        assert_eq!(m.to_string(), "0x0");
    }
}
