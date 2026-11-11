//! High-level engine: write, read, inspect, verify, and remove operations.
//!
//! This is the module library callers should use. The flow for each operation
//! is:
//!
//! 1. Run rejection checks ([`crate::structure::rejection`]).
//! 2. Snapshot the carrier's metadata (size, SHA-256, permissions, mtime/atime).
//! 3. Detect the carrier format via [`crate::structure::registry`] and locate any existing
//!    envelope.
//! 4. Build the UBE (header + optional hint + encrypted metadata + chunked
//!    encrypted payload + trailer) in a staging buffer.
//! 5. Inject it into a `<target>.strhide.tmp` file, patch the header/trailer
//!    back with the real offsets, and self-verify the written envelope.
//! 6. On success: optional in-place `.bak` backup, atomic rename, restore
//!    permissions/timestamps.
//!
//! [`remove_carrier`] performs the inverse: it locates the envelope, strips
//! the injected bytes, restores any patched fields, and then **verifies the
//! result against the SHA-256 recorded in the header** before committing. Any
//! mismatch leaves the original carrier untouched.
//!
//! The five operations live in sibling submodules (`write`, `read`, `inspect`,
//! `verify`, `remove`); `locate`, `metadata`, `capacity` and `report` hold the
//! helpers they share. Public entry points are re-exported here so
//! `structure::engine::*` and `structure::*` keep their historical paths.

pub use crate::commit::commit_carrier_bytes;
pub use crate::commit::same_file;

mod capacity;
mod inspect;
mod locate;
mod metadata;
mod read;
mod remove;
mod report;
mod verify;
mod write;

pub use inspect::{inspect_carrier, inspect_carrier_bytes, inspect_carrier_with};
pub use metadata::{CarrierMetadata, MetadataInspection};
pub use read::{read_carrier, read_carrier_bytes, read_carrier_with_dialect};
pub use remove::{remove_carrier, remove_carrier_bytes, remove_carrier_with_dialect};
pub use report::{
    InspectResult, LevelStatus, PayloadSource, ReadResult, ReadSummary, RemoveResult, VerifyResult,
    Warning, WriteResult, verify_passed,
};
pub use verify::{verify_carrier, verify_carrier_bytes, verify_carrier_with};
pub use write::{write_carrier, write_carrier_bytes, write_carrier_with};

/// Stealth mode password derivation domain separation string.
///
/// Re-exported from [`crate::params`] for the public API: the constant lives
/// next to [`StructureProfile::stealth_domain`], which is what actually drives
/// derivation.
pub use crate::params::STEALTH_DOMAIN;

/// Sanitize an untrusted metadata filename down to a safe bare file name.
///
/// Re-exported from [`crate::core::fs`] so the structure-domain path keeps its
/// historical name and both domains share one implementation.
pub use crate::core::fs::sanitize_filename;

#[cfg(test)]
use capacity::apply_engine_payload_limit;
#[cfg(test)]
use metadata::{COMPACT_META_MAX_NAME, decode_metadata, encode_metadata, put_varint, take_varint};
#[cfg(test)]
use remove::strip_coordinates_for_location;
#[cfg(test)]
use verify::envelope_coordinates_agree;

#[cfg(test)]
use crate::errors::StrHideError;
#[cfg(test)]
use crate::params::LocalParams;
#[cfg(test)]
use crate::structure::envelope::EnvelopeHeader;
#[cfg(test)]
use crate::structure::options::WriteOptions;
#[cfg(test)]
use crate::structure::params::StructureProfile;
#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
#[path = "engine_tests/compact_meta_tests.rs"]
mod compact_meta_tests;

#[cfg(test)]
#[path = "engine_tests/envelope_coordinate_tests.rs"]
mod envelope_coordinate_tests;

#[cfg(test)]
#[path = "engine_tests/pbkdf2_budget_tests.rs"]
mod pbkdf2_budget_tests;
