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
pub use engine::*;
pub use options::{ReadOptions, RestoreOptions, StrategyChoice, WriteOptions};
pub use params::StructureProfile;
pub use registry::StrategyId;
