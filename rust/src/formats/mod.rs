//! Shared carrier-format layer (layer 2 of the target architecture).
//!
//! Format identification and the capability matrix live here, with no knowledge
//! of either domain's engines: `structure` and `stego` both depend on this
//! module and never on each other (see
//! `docs/strhide_architecture_and_refactoring_plan.md` §2.1).
//!
//! - [`sniff`] answers "what file is this?" — [`FileFormat`],
//!   [`sniff_bytes`](sniff::sniff_bytes), [`sniff_stream`](sniff::sniff_stream).
//! - [`annexb`] is the raw-bitstream framing probe that
//!   [`sniff`](sniff::sniff_bytes) consults last.
//! - [`capability`] answers "what can be done with it?" — one row per format.

pub mod annexb;
pub mod capability;
pub mod sniff;

pub use capability::{CAPABILITIES, Capability, StegoKind, capability_of};
pub use sniff::{FileFormat, sniff_bytes, sniff_stream};
