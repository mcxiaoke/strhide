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

/// Number of trellis seeds tried before a FLAC carrier is declared unusable.
///
/// One seed is enough on almost every file; the retries exist for carriers whose
/// quiet stretches hold long runs of residuals that cannot be compensated.
const FLAC_EMBED_ATTEMPTS: usize = 4;

/// Embed a payload into a FLAC carrier, returning the modified file.
///
/// The output has exactly the same length as the input and every frame keeps
/// its byte size: only the last bits of selected Rice codewords, the affected
/// frame checksums and the `STREAMINFO` MD5 differ.
#[allow(clippy::too_many_arguments)]
pub(crate) fn embed_flac(
    carrier: &[u8],
    payload: &Payload<'_>,
    secret: Option<&str>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    safety: SafetyPolicy,
    freshness: Freshness,
    control: &Control<'_>,
) -> Result<(Vec<u8>, StegoCapacityInfo, EmbedStats), StrHideError> {
    let info = flac::parse_stream_info(carrier)?;
    if info.bits_per_sample > 24 {
        // 24-bit residuals fit comfortably in i32; wider ones could overflow
        // the slot array, so decline with a clear message instead of risking it.
        return Err(StrHideError::UnsupportedFormat(format!(
            "{}-bit FLAC is not supported for in-place residual coding (limit 24-bit)",
            info.bits_per_sample
        )));
    }
    let analysis = flac::analyse(carrier, &info)?;
    if info.md5 != [0u8; 16] && analysis.pcm_md5 != info.md5 {
        return Err(StrHideError::UnsupportedFormat(
            "FLAC carrier could not be fully validated (decoded PCM does not match the \
             STREAMINFO MD5)"
                .into(),
        ));
    }

    // Size the carrier's slot array from the envelope the payload will produce.
    let suite = profile.body.default_suite();
    let plaintext = crate::stego::envelope::build_plaintext(payload)?;
    // Plan against what can actually move: a residual whose compensation
    // chain does not fit any Rice bucket keeps its parity, so counting it would
    // promise capacity the trellis cannot reach.
    let available = analysis
        .usable
        .min(analysis.slots)
        .saturating_sub(crate::stego::header::V2_TOTAL_HEADER_SLOTS);
    let shape = core::plan_body(
        plaintext.len(),
        suite.tag_len(),
        available,
        crate::stego::coding::DEFAULT_STC_H,
    )?;

    let mut bytes = carrier.to_vec();
    let header_phase = 0x5EED_1234_ABCD_0001u64;
    let body_phase = 0x1234_5678_9ABC_DEF0u64;
    // A quiet passage leaves runs of residuals whose predictor reaction fits no
    // Rice bucket. Those slots keep their parity, so an unlucky salt can strand
    // a whole trellis group with nothing to flip even though the carrier as a
    // whole has room. A fresh salt reshuffles only the trellis seed, so retrying
    // is cheap in expectation and turns "sometimes fails" into "succeeds".
    let binding = Freshness::seeded_binding(carrier, payload.as_bytes());
    let mut embedding = None;
    let mut last_error = None;
    for attempt in 0..FLAC_EMBED_ATTEMPTS {
        let mut flac =
            flac::FlacCarrier::new(&mut bytes, info, shape.body_slots, header_phase, body_phase)?;
        match core::embed(
            &mut flac,
            core::Mapping::BodyPermuted,
            payload,
            secret,
            domain,
            profile,
            safety,
            freshness,
            &binding,
            attempt as u32,
            control,
        ) {
            Ok(result) => {
                embedding = Some(result);
                break;
            }
            Err(e @ StrHideError::TrellisInfeasible { .. }) => {
                last_error = Some(e);
                bytes = carrier.to_vec();
            }
            Err(other) => return Err(other),
        }
    }
    let (capacity, stats) = match embedding {
        Some(result) => result,
        None => {
            return Err(match last_error {
                // Name the cause instead of leaking the solver's vocabulary.
                Some(_) => StrHideError::UnsupportedFormat(
                    concat!(
                        "This FLAC's predictor reacts too strongly for in-place residual ",
                        "coding: in a quiet stretch a one-unit residual move would need ",
                        "neighbouring codewords to change width, which FLAC cannot ",
                        "represent. Try a louder or longer carrier."
                    )
                    .into(),
                ),
                None => StrHideError::General("FLAC embedding failed".into()),
            });
        }
    };

    let drift = flac::max_sample_drift(carrier, &bytes, &info)?;
    if drift > flac::DRIFT_BUDGET {
        return Err(StrHideError::General(format!(
            "FLAC embed would shift the decoded waveform by {drift} units, past the              compensation budget; refusing to emit a carrier whose predictor is unstable"
        )));
    }
    Ok((bytes, capacity, stats))
}

/// Extract a payload from a FLAC carrier.
pub(crate) fn extract_flac(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    let info = flac::parse_stream_info(carrier)?;
    let header_phase = 0x5EED_1234_ABCD_0001u64;
    let body_phase = 0x1234_5678_9ABC_DEF0u64;

    // First read the header with an empty body, then rebuild with the body the
    // header advertises. The slot arrays differ, which is why this is two
    // constructions rather than one.
    let mut scratch = carrier.to_vec();
    let header_view = flac::FlacCarrier::new(&mut scratch, info, 0, header_phase, body_phase)?;
    let body_slots = core::body_slots_from_header(
        &header_view,
        core::Mapping::BodyPermuted,
        secret,
        domain,
        profile,
        control,
    )?;

    let mut scratch = carrier.to_vec();
    let flac = flac::FlacCarrier::new(&mut scratch, info, body_slots, header_phase, body_phase)?;
    core::extract(
        &flac,
        core::Mapping::BodyPermuted,
        secret,
        domain,
        profile,
        control,
    )
}

/// Report a FLAC carrier's embedding capacity.
pub(crate) fn probe_flac(
    carrier: &[u8],
    level: crate::params::SafetyLevel,
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    let info = flac::parse_stream_info(carrier)?;
    let analysis = flac::analyse(carrier, &info)?;
    let mut scratch = carrier.to_vec();
    // An empty body still materialises the 512 header slots, which is the shape
    // `probe` measures.
    let flac = flac::FlacCarrier::new(
        &mut scratch,
        info,
        0,
        0x5EED_1234_ABCD_0001u64,
        0x1234_5678_9ABC_DEF0u64,
    )?;
    let _ = analysis;
    core::probe(&flac, level, control)
}

/// Inspect a FLAC carrier's stego header.
///
/// Two constructions, exactly like extraction: the carrier materialises only the
/// slots the envelope needs, and the size of that envelope is what the header
/// says. A single-pass view would expose 512 slots and `inspect` would conclude
/// the body does not fit.
pub(crate) fn inspect_flac(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    control: &Control<'_>,
) -> Result<crate::stego::StegoHeaderInfo, StrHideError> {
    let info = flac::parse_stream_info(carrier)?;
    let header_phase = 0x5EED_1234_ABCD_0001u64;
    let body_phase = 0x1234_5678_9ABC_DEF0u64;

    let mut scratch = carrier.to_vec();
    let header_view = flac::FlacCarrier::new(&mut scratch, info, 0, header_phase, body_phase)?;
    // A wrong password makes the header unreadable; fall back to the header-only
    // view, which reports "nothing here" instead of an error.
    let body_slots = core::body_slots_from_header(
        &header_view,
        core::Mapping::BodyPermuted,
        secret,
        domain,
        profile,
        control,
    )
    .unwrap_or(0);

    let mut scratch = carrier.to_vec();
    let flac = flac::FlacCarrier::new(&mut scratch, info, body_slots, header_phase, body_phase)?;
    core::inspect(
        &flac,
        core::Mapping::BodyPermuted,
        secret,
        domain,
        profile,
        control,
    )
}

/// Multi-tier verification of a FLAC carrier.
pub(crate) fn verify_flac(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    control: &Control<'_>,
) -> Result<crate::stego::StegoVerifyResult, StrHideError> {
    let info = flac::parse_stream_info(carrier)?;
    let header_phase = 0x5EED_1234_ABCD_0001u64;
    let body_phase = 0x1234_5678_9ABC_DEF0u64;

    // Same two-phase view as `inspect`/`extract`: verification reads the body,
    // which only exists once the carrier materialises the envelope's slots.
    let mut scratch = carrier.to_vec();
    let header_view = flac::FlacCarrier::new(&mut scratch, info, 0, header_phase, body_phase)?;
    let body_slots = core::body_slots_from_header(
        &header_view,
        core::Mapping::BodyPermuted,
        secret,
        domain,
        profile,
        control,
    )
    .unwrap_or(0);

    let mut scratch = carrier.to_vec();
    let flac = flac::FlacCarrier::new(&mut scratch, info, body_slots, header_phase, body_phase)?;
    core::verify(
        &flac,
        core::Mapping::BodyPermuted,
        secret,
        domain,
        profile,
        control,
    )
}

#[cfg(test)]
mod tests;

pub(crate) mod core;
mod cost;
pub(crate) mod flac;
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
            &mut pcm,
            core::Mapping::Permuted,
            payload,
            secret,
            domain,
            profile,
            safety,
            freshness,
            &binding,
            0,
            control,
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
    core::extract(
        &pcm,
        core::Mapping::Permuted,
        secret,
        domain,
        profile,
        control,
    )
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
    core::inspect(
        &pcm,
        core::Mapping::Permuted,
        secret,
        domain,
        profile,
        control,
    )
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
    core::verify(
        &pcm,
        core::Mapping::Permuted,
        secret,
        domain,
        profile,
        control,
    )
}
