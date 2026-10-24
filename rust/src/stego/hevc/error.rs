//! HEVC bitstream decoding and steganography error types.

use thiserror::Error as ThisError;

/// Failures encountered during HEVC syntax parsing and steganography.
#[derive(Debug, Clone, PartialEq, Eq, ThisError)]
pub enum HevcError {
    /// Bitstream ended prematurely.
    #[error("HEVC bitstream truncated")]
    Truncated,

    /// Bitstream syntax violated ITU-T H.265 specification.
    #[error("invalid HEVC bitstream syntax: {0}")]
    InvalidData(&'static str),

    /// Valid HEVC syntax, but using an unsupported feature.
    #[error("unsupported HEVC feature: {0}")]
    Unsupported(&'static str),

    /// Missing VPS/SPS/PPS parameter set.
    #[error("missing HEVC parameter set: {0}")]
    MissingParameterSet(&'static str),

    /// Image dimensions or CTU count exceed memory limits.
    #[error("picture too large to decode or buffer")]
    TooLarge,

    /// No coded slice NAL units found in picture.
    #[error("no coded slice NAL units found")]
    NoSlices,

    /// Container structure (HEIF/MP4 box) malformed.
    #[error("malformed container box structure: {0}")]
    ContainerMalformed(&'static str),

    /// Internal structure malformed.
    #[error("malformed internal structure: {0}")]
    Malformed(&'static str),

    /// Missing required box.
    #[error("missing required box {0}")]
    MissingBox(&'static str),

    /// Box too large.
    #[error("box {boxtype:?} is too large ({size} bytes)")]
    BoxTooLarge { boxtype: [u8; 4], size: u64 },

    /// Missing item.
    #[error("missing item {0}")]
    MissingItem(u32),

    /// Cyclic item derivation.
    #[error("cyclic item derivation at item {0}")]
    CyclicDerivation(u32),
}

/// Type alias for compatibility with internal modules.
pub type Error = HevcError;

/// Convenience result type for HEVC operations.
pub type Result<T> = std::result::Result<T, HevcError>;
