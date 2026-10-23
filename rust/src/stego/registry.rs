//! Extensible algorithm registry for content-adaptive steganography.
//!
//! Provides factory lookup for spatial and JPEG distortion models by name.
//! Only algorithms that actually exist are accepted: the earlier "wow" ->
//! HILL and "nsf5" -> UERD silent aliases were removed (2026-10-20) because
//! they let callers believe they had selected a different cost model than
//! the one that ran.
//!
//! # Wire ids
//!
//! Spatial carriers store the cost model in the feature word
//! ([`crate::stego::header::FeatureWord::algorithm_id`]) so extraction does not
//! need the algorithm out of band. That id is a **permanent** contract: once a
//! number has been written into a carrier it can never mean a different
//! algorithm. Adding a model means adding a name and an unused id here, and
//! [`CostModelRegistry::spatial_wire_ids_are_a_bijection`] keeps the two
//! directions in step.

use std::sync::Arc;

use crate::stego::jpeg::cost::{JuniwardCostModel, UerdCostModel};
use crate::stego::spatial::cost::{HillCostModel, SuniwardCostModel};
use crate::stego::traits::{JpegCostModel, SpatialCostModel};

/// Wire id of [`HillCostModel`]. Reserved permanently.
pub const SPATIAL_ALGORITHM_HILL: u8 = 1;
/// Wire id of [`SuniwardCostModel`]. Reserved permanently.
pub const SPATIAL_ALGORITHM_SUNIWARD: u8 = 2;

/// Registry providing lookup of distortion cost models.
pub struct CostModelRegistry;

impl CostModelRegistry {
    /// Look up a spatial cost model by algorithm identifier.
    /// Default model is "hill" if None or "auto" is requested.
    ///
    /// "auto" stays on HILL. S-UNIWARD is available but the 2025-2026 CNN
    /// evaluations put HILL's detection rate *below* the UNIWARD family, so
    /// promoting it to the default would be a change with no evidence behind it.
    pub fn get_spatial_model(name: Option<&str>) -> Option<Arc<dyn SpatialCostModel>> {
        match name {
            None | Some("auto") | Some("hill") => Some(Arc::new(HillCostModel)),
            Some("suniward") => Some(Arc::new(SuniwardCostModel)),
            _ => None,
        }
    }

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
            _ => None,
        }
    }

    /// Wire id written into a spatial carrier's feature word for `name`.
    ///
    /// `None` for an unknown name, so a caller that failed to resolve a model
    /// cannot silently stamp another algorithm's id onto the carrier.
    pub fn spatial_wire_id(name: &str) -> Option<u8> {
        match name {
            "hill" => Some(SPATIAL_ALGORITHM_HILL),
            "suniward" => Some(SPATIAL_ALGORITHM_SUNIWARD),
            _ => None,
        }
    }

    /// Inverse of [`Self::spatial_wire_id`]: the algorithm a carrier claims.
    pub fn spatial_name_from_wire_id(id: u8) -> Option<&'static str> {
        match id {
            SPATIAL_ALGORITHM_HILL => Some("hill"),
            SPATIAL_ALGORITHM_SUNIWARD => Some("suniward"),
            _ => None,
        }
    }

    /// Resolve the spatial cost model a carrier declares.
    ///
    /// `None` when the id is not one this build knows -- an unknown id is
    /// treated exactly like "no payload here", never as a fallback to the
    /// default model (a silent fallback would extract garbage instead of
    /// reporting that the carrier was written by a newer tool).
    pub fn spatial_model_from_wire_id(id: u8) -> Option<Arc<dyn SpatialCostModel>> {
        Self::spatial_name_from_wire_id(id).and_then(|name| Self::get_spatial_model(Some(name)))
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
                "suniward",
                "Spatial (PNG)",
                "S-UNIWARD wavelet-relative distortion (Holub et al., EURASIP JIS 2014)",
            ),
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
        assert!(CostModelRegistry::get_spatial_model(Some("juniward")).is_none());
    }

    #[test]
    fn real_algorithms_still_resolve() {
        assert!(CostModelRegistry::get_spatial_model(None).is_some());
        assert!(CostModelRegistry::get_spatial_model(Some("auto")).is_some());
        assert!(CostModelRegistry::get_spatial_model(Some("hill")).is_some());
        assert!(CostModelRegistry::get_jpeg_model(None).is_some());
        assert!(CostModelRegistry::get_jpeg_model(Some("uerd")).is_some());
    }

    /// The three name lists in this file (`get_*_model`, `list_algorithms`, and
    /// the wire-id tables) are maintained by hand, and only the first two were
    /// covered by tests. Adding a model to one and forgetting another used to be
    /// undetectable until a user hit it.
    ///
    /// This walks the public listing and requires every entry to be consistent
    /// across all of them.
    #[test]
    fn every_listed_algorithm_is_consistent_across_all_lookup_tables() {
        let listed = CostModelRegistry::list_algorithms();
        assert!(!listed.is_empty(), "the CLI listing must not be empty");

        let mut spatial_seen = 0usize;
        let mut jpeg_seen = 0usize;
        for (name, domain, description) in listed {
            assert!(!description.is_empty(), "{name}: empty description");
            match domain {
                "Spatial (PNG)" => {
                    spatial_seen += 1;
                    let model = CostModelRegistry::get_spatial_model(Some(name))
                        .unwrap_or_else(|| panic!("{name}: listed but not resolvable"));
                    assert_eq!(model.id(), name, "{name}: list name != model id");
                    let id = CostModelRegistry::spatial_wire_id(name).unwrap_or_else(|| {
                        panic!("{name}: no wire id, carriers could not name it")
                    });
                    assert_eq!(
                        CostModelRegistry::spatial_name_from_wire_id(id),
                        Some(name),
                        "{name}: wire id {id} does not map back"
                    );
                    assert!(
                        CostModelRegistry::spatial_model_from_wire_id(id).is_some(),
                        "{name}: wire id {id} resolves to no model"
                    );
                    crate::stego::params::SpatialParams::default()
                        .validate()
                        .unwrap_or_else(|e| panic!("{name}: default params are invalid: {e}"));
                }
                "JPEG (JPG)" => {
                    jpeg_seen += 1;
                    let model = CostModelRegistry::get_jpeg_model(Some(name))
                        .unwrap_or_else(|| panic!("{name}: listed but not resolvable"));
                    assert_eq!(model.id(), name, "{name}: list name != model id");
                    crate::stego::params::JpegParams::default()
                        .validate()
                        .unwrap_or_else(|e| panic!("{name}: default params are invalid: {e}"));
                }
                other => panic!("{name}: unknown domain label {other:?}"),
            }
        }

        assert!(spatial_seen > 0, "no spatial algorithm listed");
        assert!(jpeg_seen > 0, "no JPEG algorithm listed");
    }

    /// A wire id is written into carriers permanently, so two algorithms must
    /// never share one.
    #[test]
    fn spatial_wire_ids_are_a_bijection() {
        let names: Vec<&str> = CostModelRegistry::list_algorithms()
            .into_iter()
            .filter(|(_, domain, _)| *domain == "Spatial (PNG)")
            .map(|(name, _, _)| name)
            .collect();

        let mut ids: Vec<u8> = names
            .iter()
            .map(|n| CostModelRegistry::spatial_wire_id(n).expect("listed model needs a wire id"))
            .collect();
        let unique = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), unique, "two spatial models share a wire id");

        for name in names {
            let id = CostModelRegistry::spatial_wire_id(name).unwrap();
            assert_ne!(
                id, 0,
                "id 0 is reserved for 'unset', {name} must not use it"
            );
            assert_eq!(
                CostModelRegistry::spatial_name_from_wire_id(id),
                Some(name),
                "{name}: id {id} does not round-trip"
            );
        }
    }

    /// An unknown id must not fall back to the default model: that would decode
    /// noise instead of reporting "no payload here".
    #[test]
    fn unknown_wire_ids_do_not_fall_back() {
        for id in [0u8, 2, 99, 255] {
            if CostModelRegistry::spatial_name_from_wire_id(id).is_some() {
                continue; // a future model legitimately owns this id
            }
            assert!(
                CostModelRegistry::spatial_model_from_wire_id(id).is_none(),
                "id {id} must not resolve to a model"
            );
        }
    }

    /// The feature word is the only place the algorithm is recorded, so its
    /// round trip has to carry the id.
    #[test]
    fn feature_word_carries_the_algorithm_id() {
        let id = SPATIAL_ALGORITHM_HILL;
        let fw = crate::stego::header::FeatureWord {
            algorithm_id: id,
            ..Default::default()
        };
        let decoded = crate::stego::header::FeatureWord::decode(&fw.encode()).expect("decode");
        assert_eq!(decoded.algorithm_id, id);
        assert_eq!(decoded, fw);
    }
}
