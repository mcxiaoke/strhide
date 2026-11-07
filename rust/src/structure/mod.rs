//! Structure domain: format-preserving envelope injection with bit-exact restore.
//!
//! `structure` and `stego` are peer domains: neither depends on the other.
//! Entry points (`write_carrier`, `verify_carrier`, `read_carrier`) are exported
//! here so callers do not need to know internal module paths.
//!
//! Dependency direction: this domain depends on [`crate::core`] and [`crate::formats`] and
//! **must not** reference [`crate::stego`]. There are no cross-domain exceptions:
//! content capacity reporting is strictly aggregated at the facade and CLI layers.

#[doc(hidden)]
pub mod adapters;
pub mod engine;
#[doc(hidden)]
pub mod envelope;
pub mod options;
pub mod params;
#[doc(hidden)]
pub mod registry;
#[doc(hidden)]
pub mod rejection;

pub use adapters::StrategyCapacity;
pub use engine::{
    CarrierMetadata, InspectResult, LevelStatus, MetadataInspection, PayloadSource, ReadResult,
    ReadSummary, RemoveResult, STEALTH_DOMAIN, VerifyResult, Warning, WriteResult,
    commit_carrier_bytes, inspect_carrier, inspect_carrier_bytes, inspect_carrier_with,
    read_carrier, read_carrier_bytes, read_carrier_with_dialect, remove_carrier,
    remove_carrier_bytes, remove_carrier_with_dialect, same_file, sanitize_filename,
    verify_carrier, verify_carrier_bytes, verify_carrier_with, verify_passed, write_carrier,
    write_carrier_bytes, write_carrier_with,
};
pub use options::{ReadOptions, RestoreOptions, StrategyChoice, WriteOptions};
pub use params::StructureProfile;
pub use registry::StrategyId;
