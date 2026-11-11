//! Envelope location: adapter dispatch plus the physical-size bound.
//!
//! Adapters only propose candidate locations; this module is the single place
//! that decides whether the carrier really contains the envelope an adapter
//! claims.

use std::io::SeekFrom;

use crate::crypto::derive_stealth_magics;
use crate::errors::StrHideError;
use crate::formats::FileFormat;
use crate::structure::adapters::{HostAdapter, LocatedEnvelope, SeekRead};
use crate::structure::envelope::{HEADER_SIZE, TRAILER_SIZE};
use crate::structure::params::StructureProfile;

/// Locate an envelope: password-derived stealth magic first, then the profile's
/// dialect magic.
///
/// The official profile passes `None` to `locate`, which lets adapters also
/// accept the legacy magics. A private dialect passes its own trailer magic and
/// deliberately does **not** fall back to the standard scan: an official
/// envelope must look like "no hidden data" to a private-profile reader (and
/// vice versa), otherwise the two dialects would silently cross-read.
pub(super) fn locate_envelope(
    carrier: &mut dyn SeekRead,
    adapter: &dyn HostAdapter,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<Option<LocatedEnvelope>, StrHideError> {
    Ok(locate_envelope_with_magic(carrier, adapter, password, profile)?.location)
}

/// Outcome of a locate scan: where the envelope is, plus the stealth magics the
/// scan derived on the way (if a password was supplied).
pub(super) struct Located {
    pub(super) location: Option<LocatedEnvelope>,
    /// Header magic derived from password + profile domain.
    pub(super) stealth_header_magic: Option<[u8; 8]>,
    /// Trailer magic derived from the same PBKDF2 run. Level 1 and Level 2
    /// both need it for stealth overlays; cached here to avoid redundant key derivations.
    pub(super) stealth_trailer_magic: Option<[u8; 4]>,
}

/// [`locate_envelope`], also returning the stealth magics it had to derive
/// on the way.
///
/// `unpack_with_secrets` needs exactly the header magic to decide whether the
/// header is a stealth one, and the trailer check needs its counterpart —
/// deriving them twice costs a full PBKDF2 (100k HMAC-SHA256 iterations) — so
/// the locator hands its result over instead of recomputing it.
pub(super) fn locate_envelope_with_magic(
    carrier: &mut dyn SeekRead,
    adapter: &dyn HostAdapter,
    password: Option<&str>,
    profile: &StructureProfile,
) -> Result<Located, StrHideError> {
    let mut stealth_header_magic = None;
    let mut stealth_trailer_magic = None;
    let found = if let Some(pwd) = password {
        let magics = derive_stealth_magics(pwd, profile.domain())?;
        // The derived magics are kept even when the stealth scan misses: the
        // header/trailer unpack need them to rule out the stealth branch, and
        // dropping them here would cost a second PBKDF2.
        stealth_header_magic = Some(magics.0);
        stealth_trailer_magic = Some(magics.1);
        match adapter.locate_with_hint(carrier, Some(&magics.1), Some(&magics.0))? {
            Some(location) => Some(location),
            None => adapter.locate_with_hint(
                carrier,
                profile.locator_magic(),
                Some(&profile.header_magic()),
            )?,
        }
    } else {
        adapter.locate_with_hint(
            carrier,
            profile.locator_magic(),
            Some(&profile.header_magic()),
        )?
    };

    Ok(Located {
        location: confine_location(carrier, found)?,
        stealth_header_magic,
        stealth_trailer_magic,
    })
}

/// Reject a located envelope that cannot physically fit inside the carrier.
///
/// Adapters only propose candidate locations based on the 24-byte trailer.
/// Because trailer fields are untrusted, this check bounds the envelope to
/// the physical carrier size before allocating buffers from declared header geometry,
/// preventing out-of-bounds reads and denial-of-service from forged container headers.
///
/// This is the single place that decides whether a carrier really contains the
/// envelope an adapter claims, and it runs before any buffer is sized from the
/// header. `<= file_len` (rather than `== file_len`) is what the strategies
/// need: only the EOF-appending ones end at the file end, while chunk, box and
/// padding strategies are followed by the rest of the container.
fn confine_location(
    carrier: &mut dyn SeekRead,
    location: Option<LocatedEnvelope>,
) -> Result<Option<LocatedEnvelope>, StrHideError> {
    let Some(location) = location else {
        return Ok(None);
    };
    let file_len = carrier.seek(SeekFrom::End(0))?;
    let min_envelope = (HEADER_SIZE + TRAILER_SIZE) as u64;
    let end = location.offset.checked_add(location.size);
    if location.size < min_envelope || end.is_none_or(|end| end > file_len) {
        // Not an error: a trailer-shaped tail that points outside the file is
        // exactly what a carrier without a (readable) envelope looks like.
        return Ok(None);
    }
    Ok(Some(location))
}

/// Typed format of an adapter, or an error when its name is unregistered.
///
/// `format_name()` stays a `&'static str` because adapters are the low-level
/// layer; the public result structs carry the enum, so the conversion happens
/// once, here, instead of at every construction site.
pub(super) fn adapter_format(adapter: &dyn HostAdapter) -> Result<FileFormat, StrHideError> {
    FileFormat::from_adapter_name(adapter.format_name()).ok_or_else(|| {
        StrHideError::General(format!(
            "Adapter reports unknown format name '{}'",
            adapter.format_name()
        ))
    })
}

/// Build the "no hidden data" error for a carrier that `locate` could not
/// resolve. A stealth envelope written with a password we were not given is
/// invisible to magic-based location by design; `suspicious_structures` gives
/// a password-independent structural opinion, which turns the bare "not found"
/// message into actionable guidance instead of a dead end.
pub(super) fn no_hidden_data_error(
    carrier: &mut dyn SeekRead,
    adapter: &'static dyn HostAdapter,
    label: &str,
    password_supplied: bool,
) -> StrHideError {
    let mut msg = format!("No hidden strhide data found in '{label}'");
    let hints = adapter.suspicious_structures(carrier);
    if !hints.is_empty() {
        if password_supplied {
            msg.push_str(&format!(
                ". Note: the carrier shows envelope-shaped structures ({}); a stealth envelope may exist under a different password.",
                hints.join("; ")
            ));
        } else {
            msg.push_str(&format!(
                ". Note: the carrier shows envelope-shaped structures ({}); it may contain a stealth envelope - provide the password used at write time with -p/--password to check.",
                hints.join("; ")
            ));
        }
    }
    StrHideError::NoHiddenData(msg)
}
