//! The structure-domain half of a dialect.
//!
//! Split out of the old all-in-one `Profile` (stage 4, see
//! `docs/strhide_architecture_and_refactoring_plan.md` §3.5): the structure
//! engine only ever needed these three fields, and the content-domain half
//! lives in [`crate::stego::params::StegoProfile`]. [`crate::facade::Dialect`]
//! composes the two so a host still stores and passes **one** object.
//!
//! Nothing here changes the UBE v2.2 wire format: every field is either
//! writer-only or an input to key/magic derivation whose result is already
//! stored in (or recoverable from) the envelope.

use crate::crypto::BUILTIN_DEFAULT_KEY;
use crate::params::{MagicPair, STANDARD_HEADER_MAGIC, STANDARD_TRAILER_MAGIC, STEALTH_DOMAIN};

/// The private structure-domain dialect an envelope is written in: everything
/// read and write must agree on, and that deliberately does not live in the
/// wire format.
///
/// `StructureProfile::default()` is the official dialect — byte-compatible
/// with every strhide release. Setting any field opts into a private dialect
/// that the official binary cannot read.
///
/// ```rust
/// use strhide::structure::params::StructureProfile;
///
/// const PRIVATE: StructureProfile = StructureProfile::new()
///     .with_default_secret("my-structure-secret");
/// assert!(!PRIVATE.is_official());
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StructureProfile {
    /// Secret keying every "no user password" envelope, replacing the public
    /// [`BUILTIN_DEFAULT_KEY`].
    ///
    /// **The highest-value knob for a library user.** With the public constant,
    /// every no-password envelope is readable by anyone holding any strhide
    /// binary. With a private secret, those envelopes are unreadable without
    /// it — and the wire format does not change by a single byte.
    ///
    /// An explicit password always wins over this value.
    pub default_secret: Option<&'static str>,
    /// Domain separator for stealth magic derivation. `None` = [`STEALTH_DOMAIN`].
    pub stealth_domain: Option<&'static [u8]>,
    /// Custom header/trailer magic pair. `None` = the standard magics.
    ///
    /// A custom *trailer* magic is what the reader searches for, so envelopes
    /// written under it are invisible to an official reader's `locate`.
    ///
    /// Ignored in stealth mode, where both magics are derived from the
    /// password instead (a fixed magic would defeat plausible deniability).
    pub magic: Option<MagicPair>,
}

impl StructureProfile {
    /// Official dialect: every field at its default.
    pub const fn new() -> Self {
        Self {
            default_secret: None,
            stealth_domain: None,
            magic: None,
        }
    }

    /// Set [`default_secret`](Self::default_secret).
    ///
    /// `const` builder form because the struct is `#[non_exhaustive]`:
    /// downstream crates cannot use struct-literal or `..Default::default()`
    /// syntax.
    pub const fn with_default_secret(mut self, secret: &'static str) -> Self {
        self.default_secret = Some(secret);
        self
    }

    /// Set [`stealth_domain`](Self::stealth_domain).
    pub const fn with_stealth_domain(mut self, domain: &'static [u8]) -> Self {
        self.stealth_domain = Some(domain);
        self
    }

    /// Set [`magic`](Self::magic).
    pub const fn with_magic(mut self, magic: MagicPair) -> Self {
        self.magic = Some(magic);
        self
    }

    /// Secret used when no user password is supplied.
    pub fn secret(&self) -> &str {
        self.default_secret
            .filter(|s| !s.is_empty())
            .unwrap_or(BUILTIN_DEFAULT_KEY)
    }

    /// Domain separator mixed into stealth magic derivation.
    pub fn domain(&self) -> &[u8] {
        self.stealth_domain.unwrap_or(STEALTH_DOMAIN)
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
        self.default_secret.is_none_or(|s| s.is_empty())
            && self.stealth_domain.is_none()
            && self.magic.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_official() {
        let p = StructureProfile::default();
        assert!(p.is_official());
        assert_eq!(p.secret(), BUILTIN_DEFAULT_KEY);
        assert_eq!(p.domain(), STEALTH_DOMAIN);
        assert_eq!(p.header_magic(), STANDARD_HEADER_MAGIC);
        assert_eq!(p.trailer_magic(), STANDARD_TRAILER_MAGIC);
        assert!(p.locator_magic().is_none());
    }

    #[test]
    fn custom_fields_are_not_official() {
        let p = StructureProfile::new().with_default_secret("private");
        assert!(!p.is_official());
        assert_eq!(p.secret(), "private");

        let p = StructureProfile::new().with_magic(MagicPair {
            header: *b"PRIVHDR!",
            trailer: *b"PRVT",
        });
        assert!(!p.is_official());
        assert_eq!(p.locator_magic(), Some(b"PRVT"));
    }

    #[test]
    fn empty_secret_falls_back_to_builtin() {
        let p = StructureProfile::new().with_default_secret("");
        assert_eq!(p.secret(), BUILTIN_DEFAULT_KEY);
        assert!(p.is_official());
    }
}
