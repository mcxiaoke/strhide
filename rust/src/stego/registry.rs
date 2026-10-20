//! Extensible algorithm registry for content-adaptive steganography.
//!
//! Provides factory lookup for spatial and JPEG distortion models by name.
//! Only algorithms that actually exist are accepted: the earlier "wow" ->
//! HILL and "nsf5" -> UERD silent aliases were removed (2026-10-20) because
//! they let callers believe they had selected a different cost model than
//! the one that ran.

use std::sync::Arc;

use crate::stego::jpeg::cost::UerdCostModel;
use crate::stego::spatial::cost::HillCostModel;
use crate::stego::traits::{JpegCostModel, SpatialCostModel};

/// Registry providing lookup of distortion cost models.
pub struct CostModelRegistry;

impl CostModelRegistry {
    /// Look up a spatial cost model by algorithm identifier.
    /// Default model is "hill" if None or "auto" is requested.
    pub fn get_spatial_model(name: Option<&str>) -> Option<Arc<dyn SpatialCostModel>> {
        match name {
            None | Some("auto") | Some("hill") => Some(Arc::new(HillCostModel)),
            _ => None,
        }
    }

    /// Look up a JPEG DCT cost model by algorithm identifier.
    /// Default model is "uerd" if None or "auto" is requested.
    pub fn get_jpeg_model(name: Option<&str>) -> Option<Arc<dyn JpegCostModel>> {
        match name {
            None | Some("auto") | Some("uerd") => Some(Arc::new(UerdCostModel)),
            _ => None,
        }
    }

    /// Return list of available algorithm names and descriptions for CLI listing.
    pub fn list_algorithms() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            (
                "hill",
                "Spatial (PNG)",
                "High-Low-Low content-adaptive filter (Li et al., ICIP 2014)",
            ),
            (
                "uerd",
                "JPEG (JPG)",
                "Uniform Embedding Revisited Distortion model (Guo et al., IEEE TIFS 2015)",
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_algorithm_names_are_rejected_not_silently_aliased() {
        // The removed "wow"/"nsf5" aliases made callers believe a different
        // cost model had been selected. They must now fail loudly.
        assert!(CostModelRegistry::get_spatial_model(Some("wow")).is_none());
        assert!(CostModelRegistry::get_jpeg_model(Some("nsf5")).is_none());
        assert!(CostModelRegistry::get_spatial_model(Some("uniward")).is_none());
        assert!(CostModelRegistry::get_jpeg_model(Some("juniward")).is_none());
    }

    #[test]
    fn real_algorithms_still_resolve() {
        assert!(CostModelRegistry::get_spatial_model(None).is_some());
        assert!(CostModelRegistry::get_spatial_model(Some("auto")).is_some());
        assert!(CostModelRegistry::get_spatial_model(Some("hill")).is_some());
        assert!(CostModelRegistry::get_jpeg_model(None).is_some());
        assert!(CostModelRegistry::get_jpeg_model(Some("uerd")).is_some());
    }
}
