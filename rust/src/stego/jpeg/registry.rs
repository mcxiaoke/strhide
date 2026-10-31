//! JPEG DCT-domain cost-model registry: name lookup.
//!
//! Split out of the former monolithic `stego::registry` so the HEVC engine can
//! be compiled without linking any DCT model. Unlike the spatial side there is
//! no wire id here: the JPEG V3 slot set is geometric and keyed, so extraction
//! never needs to know which model wrote the carrier.

use std::sync::Arc;

use crate::stego::jpeg::cost::{JmipodCostModel, JuniwardCostModel, UerdCostModel};
use crate::stego::traits::JpegCostModel;

/// Look up a JPEG DCT cost model by algorithm identifier.
/// Default model is "uerd" if None or "auto" is requested.
///
/// "auto" deliberately resolves to UERD, not to the strongest model:
/// J-UNIWARD costs roughly two orders of magnitude more per embed for a
/// distortion difference that the literature does not show to be a win, so
/// it is opt-in only.
pub fn get_jpeg_model(name: Option<&str>) -> Option<Arc<dyn JpegCostModel>> {
    match name {
        None | Some("auto") | Some("uerd") => Some(Arc::new(UerdCostModel)),
        Some("juniward") => Some(Arc::new(JuniwardCostModel)),
        Some("jmipod") => Some(Arc::new(JmipodCostModel)),
        _ => None,
    }
}

/// The listing entries this registry contributes to `CostModelRegistry::list_algorithms`.
pub fn list() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "uerd",
            "JPEG (JPG)",
            "Uniform Embedding Revisited Distortion model (Guo et al., IEEE TIFS 2015)",
        ),
        (
            "juniward",
            "JPEG (JPG)",
            "J-UNIWARD wavelet-relative distortion (Holub et al., EURASIP JIS 2014)",
        ),
        (
            "jmipod",
            "JPEG (JPG)",
            "J-MiPOD statistical DCT detectability model (Cogranne et al., ACM IH&MMSec 2020)",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_algorithm_names_are_rejected_not_silently_aliased() {
        // The removed "wow"/"nsf5" aliases made callers believe a different
        // cost model had been selected. They must now fail loudly.
        assert!(get_jpeg_model(Some("nsf5")).is_none());
        assert!(get_jpeg_model(Some("wow")).is_none());
    }

    #[test]
    fn real_algorithms_still_resolve() {
        assert!(get_jpeg_model(None).is_some());
        assert!(get_jpeg_model(Some("auto")).is_some());
        assert!(get_jpeg_model(Some("uerd")).is_some());
        assert!(get_jpeg_model(Some("juniward")).is_some());
    }

    #[test]
    fn listed_algorithms_are_consistent_across_all_lookup_tables() {
        for (name, domain, description) in list() {
            assert_eq!(domain, "JPEG (JPG)");
            assert!(!description.is_empty(), "{name}: empty description");
            let model = get_jpeg_model(Some(name))
                .unwrap_or_else(|| panic!("{name}: listed but not resolvable"));
            assert_eq!(model.id(), name, "{name}: list name != model id");
            crate::stego::params::JpegParams::default()
                .validate()
                .unwrap_or_else(|e| panic!("{name}: default params are invalid: {e}"));
        }
    }
}
