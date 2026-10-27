//! Algorithm registry facade for content-adaptive steganography.
//!
//! The per-domain registries live next to their engines
//! ([`crate::stego::png::registry`] for spatial models, with the wire ids the
//! PNG feature word carries, and [`crate::stego::jpeg::registry`] for DCT
//! models). This module is the aggregate the CLI lists: it forwards the
//! lookups and owns the one HEVC listing row.
//!
//! Only algorithms that actually exist are accepted: the earlier "wow" ->
//! HILL and "nsf5" -> UERD silent aliases were removed (2026-10-20) because
//! they let callers believe they had selected a different cost model than
//! the one that ran.

/// Return list of available algorithm names and descriptions for CLI listing.
pub fn list_algorithms() -> Vec<(&'static str, &'static str, &'static str)> {
    let mut out = crate::stego::png::registry::list();
    out.extend(crate::stego::jpeg::registry::list());
    out.push((
        "hevc",
        "HEIF/HEVC",
        "H.265 CABAC bypass sign bit in-place steganography (Scheme C, zero expansion)",
    ));
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_listed_algorithm_is_consistent_across_all_lookup_tables() {
        let listed = super::list_algorithms();
        assert!(!listed.is_empty(), "the CLI listing must not be empty");

        let mut spatial_seen = 0usize;
        let mut jpeg_seen = 0usize;
        let mut hevc_seen = 0usize;
        for (name, domain, description) in listed {
            assert!(!description.is_empty(), "{name}: empty description");
            match domain {
                "Spatial (PNG)" => {
                    spatial_seen += 1;
                    let model = crate::stego::png::registry::get_spatial_model(Some(name))
                        .unwrap_or_else(|| panic!("{name}: listed but not resolvable"));
                    assert_eq!(model.id(), name, "{name}: list name != model id");
                    let id = crate::stego::png::registry::spatial_wire_id(name)
                        .unwrap_or_else(|| panic!("{name}: no wire id"));
                    assert_eq!(
                        crate::stego::png::registry::spatial_name_from_wire_id(id),
                        Some(name),
                        "{name}: wire id {id} does not map back"
                    );
                }
                "JPEG (JPG)" => {
                    jpeg_seen += 1;
                    let model = crate::stego::jpeg::registry::get_jpeg_model(Some(name))
                        .unwrap_or_else(|| panic!("{name}: listed but not resolvable"));
                    assert_eq!(model.id(), name, "{name}: list name != model id");
                }
                // The HEVC Scheme C engine carries no cost-model selection, so
                // this entry only needs to exist for the CLI listing.
                "HEIF/HEVC" => hevc_seen += 1,
                other => panic!("{name}: unknown domain label {other:?}"),
            }
        }

        assert!(spatial_seen > 0, "no spatial algorithm listed");
        assert!(jpeg_seen > 0, "no JPEG algorithm listed");
        assert!(hevc_seen > 0, "no HEVC algorithm listed");
    }
}
