//! Audio content-domain steganography (WAV PCM, FLAC residuals).
//!
//! # What makes this "content domain"
//!
//! The structure domain already hides data in RIFF chunks and EOF trailers --
//! bytes a format analyser can strip without touching the sound. This module
//! does the opposite: it changes the **samples themselves** by the smallest
//! representable step, so the payload lives in the waveform and survives
//! metadata stripping, chunk re-ordering and any lossless repackaging.
//!
//! # Carrier contract
//!
//! A carrier exposes an ordered array of **slots**. A slot is one scalar whose
//! parity is the embedded bit and which can move by `±1` without disturbing
//! anything else:
//!
//! | Carrier | Slot is | Move is |
//! | :--- | :--- | :--- |
//! | WAV | one PCM sample component | `±1` LSB, in place |
//! | FLAC | one Rice-coded residual | `±1` residual, code-length preserving |
//!
//! Everything above the slot layer -- the AEAD envelope, the 512-slot header,
//! the keyed slot permutation, the STC trellis -- is shared, which is why the
//! two carriers differ only in their `SlotCarrier` implementation.
//!
//! # Zero expansion
//!
//! No byte is added, removed or moved: WAV stays byte-for-byte the same length
//! with identical chunk offsets, FLAC keeps every frame at its original byte
//! length (the modification is chosen so the Rice codeword keeps its width).
//! A carrier that cannot guarantee this is refused rather than degraded.

#[cfg(test)]
mod tests;

mod core;
mod cost;
mod perm;
mod sample;
mod wav;

#[allow(unused_imports)]
pub(crate) use core::{SlotCarrier, change_percent};

use crate::SafetyPolicy;
use crate::core::control::Control;
use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::stego::EmbedStats;
use crate::stego::StegoCapacityInfo;
use crate::stego::envelope::Freshness;
use crate::stego::format::AudioFormatProfile;

/// Embed a payload into a WAV carrier, returning the modified file.
///
/// The returned bytes have exactly the same length as the input; only bytes
/// inside the `data` chunk differ.
// Eight parameters is the engine's own call shape (carrier, payload, secret,
// domain, profile, safety, freshness, control); bundling them into a struct
// would only move the list one level up.
#[allow(clippy::too_many_arguments)]
pub(crate) fn embed_wav(
    carrier: &[u8],
    payload: &Payload<'_>,
    secret: Option<&str>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    safety: SafetyPolicy,
    freshness: Freshness,
    control: &Control<'_>,
) -> Result<(Vec<u8>, StegoCapacityInfo, EmbedStats), StrHideError> {
    let layout = wav::parse_wav(carrier)?;
    let mut bytes = carrier.to_vec();
    let binding = Freshness::seeded_binding(carrier, payload.as_bytes());
    let (info, stats) = {
        let mut pcm = wav::PcmCarrier::new(&mut bytes, layout);
        core::embed(
            &mut pcm, payload, secret, domain, profile, safety, freshness, &binding, control,
        )?
    };
    Ok((bytes, info, stats))
}

/// Extract a payload from a WAV carrier.
pub(crate) fn extract_wav(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    let layout = wav::parse_wav(carrier)?;
    // Extraction never mutates: present the file as an immutable slot array.
    let mut scratch = carrier.to_vec();
    let pcm = wav::PcmCarrier::new(&mut scratch, layout);
    core::extract(&pcm, secret, domain, profile, control)
}

/// Report a WAV carrier's embedding capacity.
pub(crate) fn probe_wav(
    carrier: &[u8],
    level: crate::params::SafetyLevel,
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    let layout = wav::parse_wav(carrier)?;
    let mut scratch = carrier.to_vec();
    let pcm = wav::PcmCarrier::new(&mut scratch, layout);
    core::probe(&pcm, level, control)
}

/// Inspect a WAV carrier's stego header.
pub(crate) fn inspect_wav(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    control: &Control<'_>,
) -> Result<crate::stego::StegoHeaderInfo, StrHideError> {
    let layout = wav::parse_wav(carrier)?;
    let mut scratch = carrier.to_vec();
    let pcm = wav::PcmCarrier::new(&mut scratch, layout);
    core::inspect(&pcm, secret, domain, profile, control)
}

/// Multi-tier verification of a WAV carrier.
pub(crate) fn verify_wav(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    control: &Control<'_>,
) -> Result<crate::stego::StegoVerifyResult, StrHideError> {
    let layout = wav::parse_wav(carrier)?;
    let mut scratch = carrier.to_vec();
    let pcm = wav::PcmCarrier::new(&mut scratch, layout);
    core::verify(&pcm, secret, domain, profile, control)
}
