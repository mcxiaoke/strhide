//! Library-facing tuning parameters (the **L class**).
//!
//! Exactly one type lives here: [`LocalParams`], which changes only what the
//! writer does. The reader never needs to know, so nothing here can make a
//! carrier unreadable and every value is safe to vary per call.
//!
//! Dialect (the **P class** — the private keying/magic/format identity both
//! sides must agree on) is *not* here any more. It is split by domain:
//!
//! - [`crate::structure::params::StructureProfile`] — UBE envelope dialect;
//! - [`crate::stego::params::StegoProfile`] — content-domain dialect;
//! - [`crate::facade::Dialect`] — the two halves composed, which is what a
//!   host stores and passes around.
//!
//! Splitting it this way keeps `core`-level primitives free of any format
//! dependency (plan §3.5) while preserving the "one object to store" property
//! at the facade.
//!
//! `LocalParams` never changes the UBE v2.2 wire format: chunk framing and
//! compression are self-describing in the envelope.

use crate::crypto::{CHUNK_SIZE, MAX_CHUNK_SIZE};

/// Standard high-entropy binary header magic (8 bytes): SHA-256("strhide-standard-header-v2")[..8]
pub const STANDARD_HEADER_MAGIC: [u8; 8] = [0xb7, 0x54, 0x2c, 0x82, 0x7e, 0x31, 0x1d, 0x6e];

/// Standard high-entropy binary trailer magic (4 bytes): SHA-256("strhide-standard-trailer-v2")[..4]
pub const STANDARD_TRAILER_MAGIC: [u8; 4] = [0x78, 0xe6, 0x66, 0xd2];

/// Domain separator mixed into stealth magic derivation.
///
/// **P class.** It does not travel in the envelope, so read and write must
/// agree. Changing it yields a different header/trailer magic pair for the same
/// password, which is exactly what a private dialect wants.
pub const STEALTH_DOMAIN: &[u8] = b"strhide-stealth-v1";

/// Default raw-deflate level used by [`CompressionStrategy::Auto`] and
/// [`CompressionStrategy::Always`] when no level is given.
pub const DEFAULT_COMPRESSION_LEVEL: u32 = 6;

/// Reject anything above this: raw deflate takes 0..=9.
pub const MAX_COMPRESSION_LEVEL: u32 = 9;

/// Historical compression trigger: keep the deflate stream only when it saves
/// at least 2% (`comp_len * 100 < raw_size * 98`).
pub const AUTO_COMPRESSION_SAVING_PERCENT: u128 = 2;

/// A header/trailer magic pair identifying a private dialect.
///
/// The header magic is stored verbatim in the envelope (bytes 0..8), so a
/// custom value is *self-describing*; the trailer magic is what the reader
/// searches for, so a custom value is what hides the envelope from the
/// official `locate` path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MagicPair {
    /// 8-byte header magic written at envelope offset 0.
    pub header: [u8; 8],
    /// 4-byte trailer magic written at the end of the envelope.
    pub trailer: [u8; 4],
}

impl MagicPair {
    /// The official pair.
    pub const STANDARD: Self = Self {
        header: STANDARD_HEADER_MAGIC,
        trailer: STANDARD_TRAILER_MAGIC,
    };
}

/// When to compress the payload before sealing it.
///
/// **L class.** Only the writer decides; the reader trusts `FLAG_COMPRESSED`
/// and always inflates raw deflate, independent of the level used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum CompressionStrategy {
    /// Compress when it saves at least 2% (the historical rule) at level 6.
    #[default]
    Auto,
    /// Never compress, even when it would help.
    Never,
    /// Always compress at `level` (0..=9).
    Always {
        /// Raw-deflate level; validated against [`MAX_COMPRESSION_LEVEL`].
        level: u32,
    },
}

impl CompressionStrategy {
    /// Deflate level to use once the decision to compress has been made.
    pub fn level(&self) -> u32 {
        match self {
            Self::Auto | Self::Never => DEFAULT_COMPRESSION_LEVEL,
            Self::Always { level } => *level,
        }
    }

    /// Keep the compressed stream for this payload?
    ///
    /// `raw_len` is the uncompressed size, `comp_len` the deflate output size.
    pub fn should_compress(&self, raw_len: u64, comp_len: u64) -> bool {
        match self {
            Self::Auto => {
                (comp_len as u128) * 100
                    < (raw_len as u128) * (100 - AUTO_COMPRESSION_SAVING_PERCENT)
            }
            Self::Never => false,
            Self::Always { .. } => true,
        }
    }
}

/// Pre-write safety check granularity.
///
/// **L class.** The checks protect the carrier from being written when it looks
/// signed or unwritable; they never affect what the reader can decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RejectionPolicy {
    /// Every check: container signatures (PE/PDF/JAR), filename policy (APK,
    /// `.sig`), read-only carrier, and target-directory writability.
    #[default]
    Strict,
    /// Structure checks only: signed PE Authenticode block, PDF `/ByteRange`
    /// signatures, JAR signature entries, APK. Skips filesystem checks, which
    /// is what an in-memory carrier needs.
    ContentOnly,
    /// No pre-write checks. The caller takes full responsibility.
    Skip,
}

/// Writer-side knobs that never influence decoding.
///
/// Passing a different `LocalParams` to the writer cannot make an existing
/// carrier unreadable: the reader derives everything it needs from the
/// envelope (chunk lengths are self-framing, compression is flagged, and
/// neither is negotiated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LocalParams {
    /// Plaintext bytes per AEAD chunk. Default 2 MiB, maximum 64 MiB.
    ///
    /// The reader does **not** need this value: chunks are framed by their own
    /// 4-byte length prefix and the final chunk is identified by the byte
    /// budget. Larger values reduce per-chunk overhead (20 B per chunk);
    /// smaller values cap peak allocation and bound the cost of a corrupt
    /// chunk.
    pub chunk_size: usize,
    /// Compression decision and level.
    pub compression: CompressionStrategy,
    /// Pre-write safety check granularity.
    pub rejection: RejectionPolicy,
}

impl Default for LocalParams {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalParams {
    /// Official defaults (2 MiB chunks, auto compression, strict rejection).
    ///
    /// `const` so a host can build an engine with tuned [`LocalParams`] at
    /// compile time.
    pub const fn new() -> Self {
        Self {
            chunk_size: CHUNK_SIZE,
            compression: CompressionStrategy::Auto,
            rejection: RejectionPolicy::Strict,
        }
    }

    /// Set [`chunk_size`](Self::chunk_size).
    ///
    /// Builder form because the struct is `#[non_exhaustive]`: downstream
    /// crates cannot use struct-literal or `..Default::default()` syntax, only
    /// field assignment or these helpers.
    pub const fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    /// Set [`compression`](Self::compression).
    pub const fn with_compression(mut self, compression: CompressionStrategy) -> Self {
        self.compression = compression;
        self
    }

    /// Set [`rejection`](Self::rejection).
    pub const fn with_rejection(mut self, rejection: RejectionPolicy) -> Self {
        self.rejection = rejection;
        self
    }

    /// Validate the knobs before any work happens, so a bad value fails with a
    /// clear message instead of a downstream panic (deflate rejects levels
    /// above 9, and a zero chunk size would divide by zero).
    pub fn validate(&self) -> Result<(), crate::errors::StrHideError> {
        if self.chunk_size == 0 {
            return Err(crate::errors::StrHideError::General(
                "chunk_size must be greater than zero".into(),
            ));
        }
        if self.chunk_size > MAX_CHUNK_SIZE {
            return Err(crate::errors::StrHideError::General(format!(
                "chunk_size {} exceeds the {} byte maximum",
                self.chunk_size, MAX_CHUNK_SIZE
            )));
        }
        if let CompressionStrategy::Always { level } = self.compression
            && level > MAX_COMPRESSION_LEVEL
        {
            return Err(crate::errors::StrHideError::General(format!(
                "compression level {level} exceeds the maximum {MAX_COMPRESSION_LEVEL}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn const_constructors_build_official_defaults() {
        // The const chain must be usable in a const context.
        const LOCAL: LocalParams = LocalParams::new().with_rejection(RejectionPolicy::ContentOnly);
        assert_eq!(LOCAL.rejection, RejectionPolicy::ContentOnly);
        assert_eq!(LOCAL.chunk_size, CHUNK_SIZE);
    }

    #[test]
    fn compression_decisions() {
        assert!(CompressionStrategy::Auto.should_compress(1_000_000, 10_000));
        assert!(!CompressionStrategy::Auto.should_compress(1_000_000, 990_000));
        assert!(!CompressionStrategy::Never.should_compress(1_000_000, 10));
        assert!(
            CompressionStrategy::Always { level: 9 }.should_compress(10, 11),
            "Always ignores the saving and compresses anyway"
        );
    }

    #[test]
    fn local_params_validation() {
        assert!(LocalParams::default().validate().is_ok());
        assert!(
            LocalParams {
                chunk_size: 0,
                ..LocalParams::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            LocalParams {
                chunk_size: MAX_CHUNK_SIZE + 1,
                ..LocalParams::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            LocalParams {
                compression: CompressionStrategy::Always { level: 10 },
                ..LocalParams::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn magic_pair_standard_is_the_official_pair() {
        assert_eq!(MagicPair::STANDARD.header, STANDARD_HEADER_MAGIC);
        assert_eq!(MagicPair::STANDARD.trailer, STANDARD_TRAILER_MAGIC);
    }
}
