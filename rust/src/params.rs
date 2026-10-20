//! Library-facing tuning parameters and private-dialect profiles.
//!
//! Two orthogonal types, split by **who has to know** rather than by read/write
//! direction (see `docs/library_api_practical_plan_20261020.md`):
//!
//! - [`LocalParams`] — **L class**: changes only what the writer does. The
//!   reader never needs to know, so nothing here can make a carrier
//!   unreadable. Safe to vary per call.
//! - [`Profile`] — **P class**: defines *which private dialect* an envelope is
//!   written in. The same profile must be supplied on both sides; a mismatch
//!   makes the carrier unreadable **by design** (and, in the stealth case,
//!   invisible). An all-default profile is the official dialect.
//!
//! Splitting this way (instead of the earlier `EngineConfig` / `ReadConfig`
//! pair) removes the "set on write, forgot on read" failure mode from the type
//! system's reach: there is only one `Profile` to pass.
//!
//! Neither type changes the UBE v2.2 wire format. Everything here is either
//! writer-only behaviour or an input to key/magic derivation whose result is
//! already stored in (or recoverable from) the envelope.

use std::borrow::Cow;

use crate::crypto::{BUILTIN_DEFAULT_KEY, CHUNK_SIZE, MAX_CHUNK_SIZE};
use crate::envelope::{STANDARD_HEADER_MAGIC, STANDARD_TRAILER_MAGIC};

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
#[derive(Debug, Clone)]
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
        Self {
            chunk_size: CHUNK_SIZE,
            compression: CompressionStrategy::Auto,
            rejection: RejectionPolicy::Strict,
        }
    }
}

impl LocalParams {
    /// Set [`chunk_size`](Self::chunk_size).
    ///
    /// Builder form because the struct is `#[non_exhaustive]`: downstream
    /// crates cannot use struct-literal or `..Default::default()` syntax, only
    /// field assignment or these helpers.
    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    /// Set [`compression`](Self::compression).
    pub fn with_compression(mut self, compression: CompressionStrategy) -> Self {
        self.compression = compression;
        self
    }

    /// Set [`rejection`](Self::rejection).
    pub fn with_rejection(mut self, rejection: RejectionPolicy) -> Self {
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

/// The private dialect an envelope is written in: everything read and write
/// must agree on, and that deliberately does not live in the wire format.
///
/// `Profile::default()` is the official dialect — byte-compatible with every
/// strhide release. Setting any field opts into a private dialect that the
/// official binary cannot read.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Profile {
    /// Secret keying every "no user password" envelope, replacing the public
    /// [`BUILTIN_DEFAULT_KEY`].
    ///
    /// **The highest-value knob for a library user.** With the public constant,
    /// every no-password envelope is readable by anyone holding any strhide
    /// binary. With a private secret, those envelopes are unreadable without
    /// it — and the wire format does not change by a single byte.
    ///
    /// An explicit password always wins over this value.
    pub default_secret: Option<Cow<'static, str>>,
    /// Domain separator for stealth magic derivation. `None` = [`STEALTH_DOMAIN`].
    pub stealth_domain: Option<Cow<'static, [u8]>>,
    /// Custom header/trailer magic pair. `None` = the standard magics.
    ///
    /// A custom *trailer* magic is what the reader searches for, so envelopes
    /// written under it are invisible to an official reader's `locate`.
    ///
    /// Ignored in stealth mode, where both magics are derived from the
    /// password instead (a fixed magic would defeat plausible deniability).
    pub magic: Option<MagicPair>,
}

impl Profile {
    /// Set [`default_secret`](Self::default_secret).
    ///
    /// Builder form because the struct is `#[non_exhaustive]`: downstream
    /// crates cannot use struct-literal or `..Default::default()` syntax.
    pub fn with_default_secret<S: Into<Cow<'static, str>>>(mut self, secret: S) -> Self {
        self.default_secret = Some(secret.into());
        self
    }

    /// Set [`stealth_domain`](Self::stealth_domain).
    pub fn with_stealth_domain<D: Into<Cow<'static, [u8]>>>(mut self, domain: D) -> Self {
        self.stealth_domain = Some(domain.into());
        self
    }

    /// Set [`magic`](Self::magic).
    pub fn with_magic(mut self, magic: MagicPair) -> Self {
        self.magic = Some(magic);
        self
    }

    /// Secret used when no user password is supplied.
    pub fn secret(&self) -> &str {
        self.default_secret
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(BUILTIN_DEFAULT_KEY)
    }

    /// Domain separator mixed into stealth magic derivation.
    pub fn domain(&self) -> &[u8] {
        self.stealth_domain.as_deref().unwrap_or(STEALTH_DOMAIN)
    }

    /// Header magic this dialect writes.
    pub fn header_magic(&self) -> [u8; 8] {
        self.magic.map_or(STANDARD_HEADER_MAGIC, |m| m.header)
    }

    /// Trailer magic this dialect writes and searches for.
    pub fn trailer_magic(&self) -> [u8; 4] {
        self.magic.map_or(STANDARD_TRAILER_MAGIC, |m| m.trailer)
    }

    /// Trailer magic to hand to `HostAdapter::locate`: `None` for the official
    /// dialect (which also accepts legacy magics), the custom magic otherwise.
    pub(crate) fn locator_magic(&self) -> Option<&[u8; 4]> {
        self.magic.as_ref().map(|m| &m.trailer)
    }

    /// True when every field is default, i.e. the official dialect.
    pub fn is_official(&self) -> bool {
        self.default_secret.as_deref().is_none_or(|s| s.is_empty())
            && self.stealth_domain.is_none()
            && self.magic.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_uses_official_constants() {
        let p = Profile::default();
        assert!(p.is_official());
        assert_eq!(p.secret(), BUILTIN_DEFAULT_KEY);
        assert_eq!(p.domain(), STEALTH_DOMAIN);
        assert_eq!(p.header_magic(), STANDARD_HEADER_MAGIC);
        assert_eq!(p.trailer_magic(), STANDARD_TRAILER_MAGIC);
        assert!(p.locator_magic().is_none());
    }

    #[test]
    fn custom_profile_is_not_official() {
        let p = Profile {
            default_secret: Some(Cow::Borrowed("private")),
            ..Profile::default()
        };
        assert!(!p.is_official());
        assert_eq!(p.secret(), "private");

        let p = Profile {
            magic: Some(MagicPair {
                header: *b"PRIVHDR!",
                trailer: *b"PRVT",
            }),
            ..Profile::default()
        };
        assert!(!p.is_official());
        assert_eq!(p.locator_magic(), Some(b"PRVT"));
    }

    #[test]
    fn empty_secret_falls_back_to_builtin() {
        let p = Profile {
            default_secret: Some(Cow::Borrowed("")),
            ..Profile::default()
        };
        assert_eq!(p.secret(), BUILTIN_DEFAULT_KEY);
        assert!(p.is_official());
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
}
