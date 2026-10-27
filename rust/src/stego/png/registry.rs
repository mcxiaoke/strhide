//! Spatial-domain (PNG) cost-model registry: name lookup and wire ids.
//!
//! Split out of the former monolithic `stego::registry` so the HEVC engine can
//! be compiled without linking any spatial model: everything in this file is
//! PNG-only by construction.

use std::sync::Arc;

use crate::stego::png::cost::{HillCostModel, SuniwardCostModel};
use crate::stego::traits::PngCostModel;

/// Wire id of [`HillCostModel`]. Reserved permanently.
pub const SPATIAL_ALGORITHM_HILL: u8 = 1;
/// Wire id of [`SuniwardCostModel`]. Reserved permanently.
pub const SPATIAL_ALGORITHM_SUNIWARD: u8 = 2;

/// Look up a spatial cost model by algorithm identifier.
/// Default model is "hill" if None or "auto" is requested.
///
/// "auto" stays on HILL. S-UNIWARD is available but the 2025-2026 CNN
/// evaluations put HILL's detection rate *below* the UNIWARD family, so
/// promoting it to the default would be a change with no evidence behind it.
pub fn get_spatial_model(name: Option<&str>) -> Option<Arc<dyn PngCostModel>> {
    match name {
        None | Some("auto") | Some("hill") => Some(Arc::new(HillCostModel)),
        Some("suniward") => Some(Arc::new(SuniwardCostModel)),
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

/// Inverse of [`spatial_wire_id`]: the algorithm a carrier claims.
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
pub fn spatial_model_from_wire_id(id: u8) -> Option<Arc<dyn PngCostModel>> {
    spatial_name_from_wire_id(id).and_then(|name| get_spatial_model(Some(name)))
}

/// The listing entries this registry contributes to `CostModelRegistry::list_algorithms`.
pub fn list() -> Vec<(&'static str, &'static str, &'static str)> {
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
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_algorithm_names_are_rejected_not_silently_aliased() {
        // The removed "wow"/"nsf5" aliases made callers believe a different
        // cost model had been selected. They must now fail loudly.
        assert!(get_spatial_model(Some("wow")).is_none());
        assert!(get_spatial_model(Some("uniward")).is_none());
        assert!(get_spatial_model(Some("juniward")).is_none());
    }

    #[test]
    fn real_algorithms_still_resolve() {
        assert!(get_spatial_model(None).is_some());
        assert!(get_spatial_model(Some("auto")).is_some());
        assert!(get_spatial_model(Some("hill")).is_some());
    }

    #[test]
    fn listed_algorithms_are_consistent_across_all_lookup_tables() {
        for (name, domain, description) in list() {
            assert_eq!(domain, "Spatial (PNG)");
            assert!(!description.is_empty(), "{name}: empty description");
            let model = get_spatial_model(Some(name))
                .unwrap_or_else(|| panic!("{name}: listed but not resolvable"));
            assert_eq!(model.id(), name, "{name}: list name != model id");
            let id = spatial_wire_id(name)
                .unwrap_or_else(|| panic!("{name}: no wire id, carriers could not name it"));
            assert_eq!(
                spatial_name_from_wire_id(id),
                Some(name),
                "{name}: wire id {id} does not map back"
            );
            assert!(
                spatial_model_from_wire_id(id).is_some(),
                "{name}: wire id {id} resolves to no model"
            );
            crate::stego::params::PngParams::default()
                .validate()
                .unwrap_or_else(|e| panic!("{name}: default params are invalid: {e}"));
        }
    }

    /// A wire id is written into carriers permanently, so two algorithms must
    /// never share one.
    #[test]
    fn spatial_wire_ids_are_a_bijection() {
        let names: Vec<&str> = list().into_iter().map(|(name, _, _)| name).collect();

        let mut ids: Vec<u8> = names
            .iter()
            .map(|n| spatial_wire_id(n).expect("listed model needs a wire id"))
            .collect();
        let unique = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), unique, "two spatial models share a wire id");

        for name in names {
            let id = spatial_wire_id(name).unwrap();
            assert_ne!(
                id, 0,
                "id 0 is reserved for 'unset', {name} must not use it"
            );
            assert_eq!(
                spatial_name_from_wire_id(id),
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
            if spatial_name_from_wire_id(id).is_some() {
                continue; // a future model legitimately owns this id
            }
            assert!(
                spatial_model_from_wire_id(id).is_none(),
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
