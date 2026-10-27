//! The unified payload type both domains carry.
//!
//! Before this module the content domain took `payload: &[u8]` while the
//! structure domain took its own [`PayloadSource`](crate::structure::PayloadSource)
//! and returned an `Extracted` struct. Three shapes for one concept meant every
//! caller converted by hand, and a GUI that had a file on disk could not tell
//! either domain "this came from `report.pdf`" without smuggling the name
//! through a side channel.
//!
//! [`Payload`] is that single shape: borrowed or owned bytes plus the metadata
//! a caller already knows. **Metadata is not on the wire in this phase**
//! (`name` / `kind` travel no further than the engine call); the content
//! domain's micro-header that persists them arrives in stage 3. The signature
//! is written once now so it does not have to change twice.
//!
//! ```no_run
//! use strhide::core::payload::Payload;
//!
//! // A file on disk, with its name kept for the micro-header.
//! let bytes = std::fs::read("notes.txt").unwrap();
//! let payload = Payload::file("notes.txt", &bytes);
//! assert_eq!(payload.name(), Some("notes.txt"));
//! assert_eq!(payload.kind(), strhide::core::payload::PayloadKind::File);
//! ```

use std::borrow::Cow;

/// What the payload originally was.
///
/// Only used for display today; stage 3 writes it into the content-domain
/// micro-header so an extract can restore a file with the right name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum PayloadKind {
    /// Bytes that were text, or an in-memory buffer of unknown provenance.
    ///
    /// The default: a caller that only has bytes should not have to claim they
    /// came from a file.
    #[default]
    Bytes,
    /// Bytes read from a file; [`Payload::name`] usually carries its name.
    File,
    /// A string the caller handed over directly.
    Text,
}

/// A payload to embed, borrowed when possible.
///
/// `data` is a [`Cow`] so an in-memory caller pays no copy and a caller that
/// built the bytes locally can hand over ownership instead of leaking a
/// temporary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload<'a> {
    /// The bytes to hide.
    pub data: Cow<'a, [u8]>,
    /// What the bytes were; metadata only, never on the wire in this phase.
    pub kind: PayloadKind,
    /// Original file name, when known. Metadata only, see [`PayloadKind`].
    pub name: Option<String>,
}

impl<'a> Payload<'a> {
    /// A payload of raw bytes with no provenance.
    pub fn bytes(data: &'a [u8]) -> Self {
        Self {
            data: Cow::Borrowed(data),
            kind: PayloadKind::Bytes,
            name: None,
        }
    }

    /// A payload the caller built in memory; no copy on the way in.
    pub fn owned(data: Vec<u8>) -> Self {
        Self {
            data: Cow::Owned(data),
            kind: PayloadKind::Bytes,
            name: None,
        }
    }

    /// A text payload.
    pub fn text(text: &'a str) -> Self {
        Self {
            data: Cow::Borrowed(text.as_bytes()),
            kind: PayloadKind::Text,
            name: None,
        }
    }

    /// A payload that came from a file, with the name it had there.
    ///
    /// The name is stored as given: normalisation and any `..`/separator
    /// stripping belong to whoever writes it out, not to the carrier format.
    pub fn file(name: impl Into<String>, data: &'a [u8]) -> Self {
        Self {
            data: Cow::Borrowed(data),
            kind: PayloadKind::File,
            name: Some(name.into()),
        }
    }

    /// An owned file payload.
    pub fn owned_file(name: impl Into<String>, data: Vec<u8>) -> Payload<'static> {
        Payload {
            data: Cow::Owned(data),
            kind: PayloadKind::File,
            name: Some(name.into()),
        }
    }

    /// Convert this payload into an owned [`Payload<'static>`].
    pub fn into_owned(self) -> Payload<'static> {
        Payload {
            data: Cow::Owned(self.data.into_owned()),
            kind: self.kind,
            name: self.name,
        }
    }

    /// Set the original file name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the payload kind.
    pub fn with_kind(mut self, kind: PayloadKind) -> Self {
        self.kind = kind;
        self
    }

    /// The bytes, as a slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_ref()
    }

    /// The bytes, detached from this value.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data.into_owned()
    }

    /// How many bytes will be hidden.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether there is nothing to hide.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// What the bytes were.
    pub fn kind(&self) -> PayloadKind {
        self.kind
    }

    /// The original file name, when the caller supplied one.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

impl std::ops::Deref for Payload<'_> {
    type Target = [u8];

    /// Lets an engine that only wants bytes keep taking `&[u8]` at its inner
    /// layers: `payload` derefs, so `&payload[..]` and `&*payload` both work.
    fn deref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<'a> From<&'a [u8]> for Payload<'a> {
    fn from(data: &'a [u8]) -> Self {
        Self::bytes(data)
    }
}

impl<'a> From<&'a Vec<u8>> for Payload<'a> {
    fn from(data: &'a Vec<u8>) -> Self {
        Self::bytes(data.as_slice())
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for Payload<'a> {
    fn from(data: &'a [u8; N]) -> Self {
        Self::bytes(data.as_slice())
    }
}

impl<'a> From<&'a str> for Payload<'a> {
    fn from(text: &'a str) -> Self {
        Self::text(text)
    }
}

impl<'a> From<&'a Payload<'a>> for Payload<'a> {
    fn from(p: &'a Payload<'a>) -> Self {
        p.clone()
    }
}

impl<'a> From<Vec<u8>> for Payload<'a> {
    fn from(data: Vec<u8>) -> Self {
        Self::owned(data)
    }
}

impl PartialEq<[u8]> for Payload<'_> {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_bytes() == other
    }
}

impl PartialEq<Vec<u8>> for Payload<'_> {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_bytes() == other.as_slice()
    }
}

impl PartialEq<Payload<'_>> for Vec<u8> {
    fn eq(&self, other: &Payload<'_>) -> bool {
        self.as_slice() == other.as_bytes()
    }
}

impl PartialEq<&[u8]> for Payload<'_> {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_bytes() == *other
    }
}

impl PartialEq<Payload<'_>> for &[u8] {
    fn eq(&self, other: &Payload<'_>) -> bool {
        *self == other.as_bytes()
    }
}

impl<const N: usize> PartialEq<[u8; N]> for Payload<'_> {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.as_bytes() == other.as_slice()
    }
}

impl<const N: usize> PartialEq<Payload<'_>> for [u8; N] {
    fn eq(&self, other: &Payload<'_>) -> bool {
        self.as_slice() == other.as_bytes()
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for Payload<'_> {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.as_bytes() == other.as_slice()
    }
}

impl<const N: usize> PartialEq<Payload<'_>> for &[u8; N] {
    fn eq(&self, other: &Payload<'_>) -> bool {
        self.as_slice() == other.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_payloads_do_not_copy() {
        let bytes = b"hello".to_vec();
        let payload = Payload::bytes(&bytes);
        assert!(matches!(payload.data, Cow::Borrowed(_)));
        assert_eq!(payload.as_bytes(), b"hello");
        assert_eq!(payload.len(), 5);
        assert!(!payload.is_empty());
        assert_eq!(payload.kind(), PayloadKind::Bytes);
        assert_eq!(payload.name(), None);
    }

    #[test]
    fn file_payload_keeps_its_name() {
        let payload = Payload::file("photo.jpg", b"payload");
        assert_eq!(payload.name(), Some("photo.jpg"));
        assert_eq!(payload.kind(), PayloadKind::File);
        // Deref gives the engine the bytes without a conversion step.
        assert_eq!(&payload[..], b"payload");
    }

    #[test]
    fn text_payload_is_bytes_with_provenance() {
        let payload = Payload::text("héllo");
        assert_eq!(payload.as_bytes(), "héllo".as_bytes());
        assert_eq!(payload.kind(), PayloadKind::Text);
        assert_eq!(payload.into_bytes(), "héllo".as_bytes().to_vec());
    }

    #[test]
    fn conversions_round_trip() {
        let from_slice = Payload::from(&b"abc"[..]);
        assert_eq!(from_slice.kind(), PayloadKind::Bytes);
        let from_str = Payload::from("abc");
        assert_eq!(from_str.kind(), PayloadKind::Text);
        let from_vec = Payload::from(vec![1u8, 2, 3]);
        assert_eq!(from_vec.into_bytes(), vec![1, 2, 3]);
    }
}
