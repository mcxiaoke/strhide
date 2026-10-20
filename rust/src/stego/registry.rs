//! Extensible algorithm registry for content-adaptive steganography.
//!
//! Provides factory lookup for spatial and JPEG distortion models by name, allowing
//! new algorithms (e.g. S-UNIWARD, WOW, J-UNIWARD, nsF5) to be plugged in seamlessly.

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
            Some("wow") => {
                // Future WOW implementation or alias
                Some(Arc::new(HillCostModel))
            }
            _ => None,
        }
    }

    /// Look up a JPEG DCT cost model by algorithm identifier.
    /// Default model is "uerd" if None or "auto" is requested.
    pub fn get_jpeg_model(name: Option<&str>) -> Option<Arc<dyn JpegCostModel>> {
        match name {
            None | Some("auto") | Some("uerd") => Some(Arc::new(UerdCostModel)),
            Some("nsf5") => {
                // Future nsF5 implementation or alias
                Some(Arc::new(UerdCostModel))
            }
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
