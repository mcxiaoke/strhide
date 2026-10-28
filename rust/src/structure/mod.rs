//! Structure domain: format-preserving envelope injection with bit-exact restore.
//!
//! Everything reachable as `crate::structure::X` used to live at the crate root
//! as `crate::structure::X` / `crate::structure::adapters::X` / `crate::structure::registry::X`, which made
//! the container-domain engine look like the primary one and the content-domain
//! engine (then and now `crate::stego`) a plugin. The module layout now names
//! the two domains as peers; the free functions keep their names, so
//! `structure::write_carrier` is the same entry point `engine::write_carrier`
//! was.
//!
//! Dependency direction (see `docs/strhide_architecture_and_refactoring_plan.md`
//! §2.1): this domain depends on [`crate::core`] and [`crate::formats`] and
//! **must not** reference [`crate::stego`]. One exception remains: `inspect`
//! measures content capacity inline behind `#[cfg(feature = "content")]`. It
//! now at least asks [`crate::formats::capability`] whether the format has a
//! content engine instead of carrying a per-adapter flag; stage 3 moves the
//! whole aggregation up to the CLI, which is where cross-domain reporting
//! belongs.

pub mod adapters;
pub mod engine;
pub mod envelope;
pub mod options;
pub mod params;
pub mod registry;
pub mod rejection;

pub use engine::*;
pub use options::{ReadOptions, RestoreOptions, StrategyChoice, WriteOptions};
pub use params::StructureProfile;
pub use registry::{
    ADAPTERS, STRATEGY_REGISTRY, StrategyId, find_adapter, find_adapter_or_reject,
    supports_content_stego,
};
