//! Audio content-domain steganography (WAV PCM and FLAC residuals).
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
//! Everything above the slot layer -- the AEAD envelope, the 64-byte V4 header,
//! the extension TLV area, the keyed slot permutation, the STC trellis -- is
//! shared, which is why the two carriers differ only in their `SlotCarrier`
//! implementation and in their `pre_salt` source.
//!
//! # Zero expansion
//!
//! No byte is added, removed or moved: WAV stays byte-for-byte the same length
//! with identical chunk offsets, FLAC keeps every frame at its original byte
//! length (the modification is chosen so the Rice codeword keeps its width).
//! A carrier that cannot guarantee this is refused rather than degraded.

use sha2::{Digest, Sha256};

use crate::SafetyPolicy;
use crate::core::control::Control;
use crate::core::payload::Payload;
use crate::crypto::{CipherSuiteId, Credential};
use crate::errors::StrHideError;
use crate::params::SafetyLevel;
use crate::stego::envelope::Freshness;
use crate::stego::format::AudioFormatProfile;
use crate::stego::header::{PNG_AUDIO_BASE_SLOTS, Tlv, encode_extension};
use crate::stego::params::ExtractParams;
use crate::stego::{EmbedStats, StegoCapacityInfo, StegoHeaderInfo, StegoVerifyResult};

/// V4 format id for WAV carriers.
const WAV_FORMAT_ID: u8 = 2;
/// V4 format id for FLAC carriers.
const FLAC_FORMAT_ID: u8 = 3;

/// Carrier identity mixed into L1 for WAV.
///
/// The sample format and the PCM length define the carrier; chunk metadata and
/// the PCM bytes themselves are deliberately excluded, because both the writer
/// and the reader must derive the same salt before and after embedding.
fn wav_pre_salt(layout: &wav::WavLayout, hpos_salt: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(hpos_salt);
    h.update(b"wav-v4");
    h.update(layout.channels.to_be_bytes());
    h.update(layout.sample_rate.to_be_bytes());
    h.update(layout.block_align.to_be_bytes());
    h.update((layout.kind.bits() as u16).to_be_bytes());
    h.update((layout.data_len as u32).to_be_bytes());
    h.finalize().into()
}

/// Carrier identity mixed into L1 for FLAC.
///
/// STREAMINFO is the clear-text carrier identity: the decoder must parse it
/// before it can locate any slot. The MD5 is deliberately excluded because
/// embedding recomputes it, which would move the locator keys.
fn flac_pre_salt(info: &flac::StreamInfo, hpos_salt: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(hpos_salt);
    h.update(b"flac-v4");
    h.update(info.sample_rate.to_be_bytes());
    h.update([info.channels, info.bits_per_sample]);
    h.update(info.total_samples.to_be_bytes());
    h.finalize().into()
}

/// Derive the three keyed thinning phases the FLAC layout needs.
fn flac_phases(locate_seed: &[u8; 32]) -> (u64, u64, u64) {
    (
        u64::from_le_bytes(locate_seed[0..8].try_into().unwrap()),
        u64::from_le_bytes(locate_seed[8..16].try_into().unwrap()),
        u64::from_le_bytes(locate_seed[16..24].try_into().unwrap()),
    )
}

fn suite_from_id(suite_id: u16) -> Result<CipherSuiteId, StrHideError> {
    CipherSuiteId::from_u16(suite_id).ok_or_else(|| {
        StrHideError::UnsupportedVersion(format!("Unknown content cipher suite id {suite_id}"))
    })
}

/// Embed a payload into a FLAC carrier, returning the modified file.
///
/// The output has exactly the same length as the input and every frame keeps
/// its byte size: only the last bits of selected Rice codewords, the affected
/// frame checksums and the `STREAMINFO` MD5 differ.
#[allow(clippy::too_many_arguments)]
pub(crate) fn embed_flac(
    carrier: &[u8],
    payload: &Payload<'_>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
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

    let suite = suite_from_id(suite_id)?;
    let extension = encode_extension(extensions)?;
    let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * extension.len();
    if analysis.tails < header_slots {
        return Err(StrHideError::General(format!(
            "FLAC carrier has {} usable subframe tails; the V4 header needs {header_slots}",
            analysis.tails
        )));
    }
    if analysis.usable < 8 {
        return Err(StrHideError::General(format!(
            "FLAC carrier has {} usable residual slots; at least 8 are required",
            analysis.usable
        )));
    }

    let pre_salt = flac_pre_salt(&info, profile.hpos_salt);
    let prepared = core::prepare(cred, domain, profile.cipher, &pre_salt)?;

    // Size the carrier's slot array from the envelope the payload will produce.
    let plaintext = crate::stego::envelope::build_plaintext(payload)?;
    let shape = core::plan_body(
        plaintext.len() + suite.tag_len(),
        analysis.usable,
        crate::stego::coding::DEFAULT_STC_H,
        flac::FlacCarrier::MIN_GROUP,
    )?;

    let (header_phase, ext_phase, body_phase) = flac_phases(&prepared.locator.locate_seed);
    let mut bytes = carrier.to_vec();
    let mut carrier_view = flac::FlacCarrier::new(
        &mut bytes,
        info,
        &analysis,
        shape.body_slots,
        header_slots,
        header_phase,
        ext_phase,
        body_phase,
    )?;
    let (capacity, stats) = {
        core::embed(
            &mut carrier_view,
            core::Mapping::BodyPermuted,
            payload,
            &prepared,
            domain,
            suite,
            extensions,
            profile.cipher,
            FLAC_FORMAT_ID,
            safety,
            freshness,
            carrier,
            control,
        )?
    };

    let drift = if carrier_view.pcm_md5() == Some(analysis.pcm_md5) {
        0
    } else {
        flac::max_sample_drift(carrier, &bytes, &info)?
    };
    if drift > flac::DRIFT_BUDGET {
        return Err(StrHideError::General(format!(
            "FLAC embed would shift the decoded waveform by {drift} units, past the compensation budget; refusing to emit a carrier whose predictor is unstable"
        )));
    }
    Ok((bytes, capacity, stats))
}

/// Extract a payload from a FLAC carrier.
pub(crate) fn extract_flac(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    if core::pbkdf2_policy_blocks(cred, limits) {
        return Err(core::no_hidden_data());
    }
    let info = flac::parse_stream_info(carrier)?;
    let analysis = flac::analyse(carrier, &info)?;
    let pre_salt = flac_pre_salt(&info, profile.hpos_salt);
    let prepared = core::prepare(cred, domain, profile.cipher, &pre_salt)?;
    let (header_phase, ext_phase, body_phase) = flac_phases(&prepared.locator.locate_seed);

    // First read the base header with an empty body, then rebuild with the body
    // the header advertises. The slot arrays differ, which is why this is two
    // constructions rather than one.
    let mut scratch = carrier.to_vec();
    let header_view = flac::FlacCarrier::new(
        &mut scratch,
        info,
        &analysis,
        0,
        PNG_AUDIO_BASE_SLOTS,
        header_phase,
        ext_phase,
        body_phase,
    )?;
    let view = core::read_base(
        &header_view,
        core::Mapping::BodyPermuted,
        &prepared,
        FLAC_FORMAT_ID,
    )?;
    let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * view.header.ext_len as usize;
    if header_slots > analysis.tails {
        return Err(core::no_hidden_data());
    }
    let body_slots = core::body_slots_for(&view.header)?;
    if body_slots > analysis.usable {
        return Err(core::no_hidden_data());
    }

    let mut scratch = carrier.to_vec();
    let flac = flac::FlacCarrier::new(
        &mut scratch,
        info,
        &analysis,
        body_slots,
        header_slots,
        header_phase,
        ext_phase,
        body_phase,
    )?;
    core::extract_with_header(
        &flac,
        core::Mapping::BodyPermuted,
        &prepared,
        domain,
        profile.cipher,
        FLAC_FORMAT_ID,
        &view,
        limits,
        control,
    )
}

/// Report a FLAC carrier's embedding capacity.
#[allow(clippy::too_many_arguments)]
pub(crate) fn probe_flac(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    extensions: &[Tlv],
    level: SafetyLevel,
    profile: &AudioFormatProfile,
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    let info = flac::parse_stream_info(carrier)?;
    if info.bits_per_sample > 24 {
        return Err(StrHideError::UnsupportedFormat(format!(
            "{}-bit FLAC is not supported for in-place residual coding (limit 24-bit)",
            info.bits_per_sample
        )));
    }
    let analysis = flac::analyse(carrier, &info)?;
    let extension = encode_extension(extensions)?;
    let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * extension.len();
    if analysis.tails < header_slots {
        return Err(StrHideError::General(format!(
            "FLAC carrier has {} usable subframe tails; the V4 header needs {header_slots}",
            analysis.tails
        )));
    }
    if analysis.usable < 8 {
        return Err(StrHideError::General(format!(
            "FLAC carrier has {} usable residual slots; at least 8 are required",
            analysis.usable
        )));
    }
    let pre_salt = flac_pre_salt(&info, profile.hpos_salt);
    let prepared = core::prepare(cred, domain, profile.cipher, &pre_salt)?;
    let view = flac::FlacCapacityView {
        total_usable: analysis.usable,
        header_total: analysis.tails,
    };
    core::probe(
        &view,
        core::Mapping::BodyPermuted,
        level,
        &prepared,
        extensions,
        control,
    )
}

/// Inspect a FLAC carrier's stego header.
///
/// Two constructions, exactly like extraction: the carrier materialises only the
/// slots the envelope needs, and the size of that envelope is what the header
/// says. A single-pass view would expose 512 slots and `inspect` would conclude
/// the body does not fit.
pub(crate) fn inspect_flac(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    if core::pbkdf2_policy_blocks(cred, limits) {
        return Ok(StegoHeaderInfo::empty("FLAC"));
    }
    control.check()?;
    let info = flac::parse_stream_info(carrier)?;
    let analysis = flac::analyse(carrier, &info)?;
    let pre_salt = flac_pre_salt(&info, profile.hpos_salt);
    let prepared = core::prepare(cred, domain, profile.cipher, &pre_salt)?;
    let (header_phase, ext_phase, body_phase) = flac_phases(&prepared.locator.locate_seed);

    let mut scratch = carrier.to_vec();
    let header_view = flac::FlacCarrier::new(
        &mut scratch,
        info,
        &analysis,
        0,
        PNG_AUDIO_BASE_SLOTS,
        header_phase,
        ext_phase,
        body_phase,
    )?;
    // A wrong password makes the header unreadable; fall back to the header-only
    // view, which reports "nothing here" instead of an error.
    let view = core::read_base(
        &header_view,
        core::Mapping::BodyPermuted,
        &prepared,
        FLAC_FORMAT_ID,
    );
    let (header_slots, body_slots) = match &view {
        Ok(v) => {
            let hs = PNG_AUDIO_BASE_SLOTS + 8 * v.header.ext_len as usize;
            let bs = core::body_slots_for(&v.header).unwrap_or(0);
            (hs, bs)
        }
        Err(_) => (PNG_AUDIO_BASE_SLOTS, 0),
    };

    let mut scratch = carrier.to_vec();
    let flac = flac::FlacCarrier::new(
        &mut scratch,
        info,
        &analysis,
        body_slots,
        header_slots,
        header_phase,
        ext_phase,
        body_phase,
    )?;
    Ok(match view {
        Ok(view) => {
            core::inspect_with_header(&flac, core::Mapping::BodyPermuted, &prepared, &view, limits)
        }
        Err(_) => StegoHeaderInfo::empty("FLAC"),
    })
}

/// Multi-tier verification of a FLAC carrier.
pub(crate) fn verify_flac(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    if core::pbkdf2_policy_blocks(cred, limits) {
        return Ok(core::policy_failure_result("FLAC"));
    }
    let info = flac::parse_stream_info(carrier)?;
    let analysis = flac::analyse(carrier, &info)?;
    let pre_salt = flac_pre_salt(&info, profile.hpos_salt);
    let prepared = core::prepare(cred, domain, profile.cipher, &pre_salt)?;
    let (header_phase, ext_phase, body_phase) = flac_phases(&prepared.locator.locate_seed);

    let mut scratch = carrier.to_vec();
    let header_view = flac::FlacCarrier::new(
        &mut scratch,
        info,
        &analysis,
        0,
        PNG_AUDIO_BASE_SLOTS,
        header_phase,
        ext_phase,
        body_phase,
    )?;
    let view = core::read_base(
        &header_view,
        core::Mapping::BodyPermuted,
        &prepared,
        FLAC_FORMAT_ID,
    );
    let (header_slots, body_slots) = match &view {
        Ok(v) => {
            let hs = PNG_AUDIO_BASE_SLOTS + 8 * v.header.ext_len as usize;
            let bs = core::body_slots_for(&v.header)
                .unwrap_or(0)
                .min(analysis.usable);
            (hs, bs)
        }
        Err(_) => (PNG_AUDIO_BASE_SLOTS, 0),
    };

    let mut scratch = carrier.to_vec();
    let flac = flac::FlacCarrier::new(
        &mut scratch,
        info,
        &analysis,
        body_slots,
        header_slots,
        header_phase,
        ext_phase,
        body_phase,
    )?;
    match view {
        Ok(_) => core::verify(
            &flac,
            core::Mapping::BodyPermuted,
            &prepared,
            domain,
            profile.cipher,
            FLAC_FORMAT_ID,
            limits,
            control,
        ),
        Err(_) => Ok(StegoVerifyResult::new(
            "FLAC",
            vec![
                crate::stego::VerifyLevel {
                    level: 1,
                    name: "carrier".into(),
                    ok: true,
                    message: Some("FLAC carrier parsed".into()),
                },
                crate::stego::VerifyLevel {
                    level: 2,
                    name: "header".into(),
                    ok: false,
                    message: Some("No readable header (wrong password or no payload)".into()),
                },
                crate::stego::VerifyLevel {
                    level: 3,
                    name: "payload".into(),
                    ok: false,
                    message: Some("Skipped because the header could not be decoded".into()),
                },
            ],
        )),
    }
}

#[cfg(test)]
mod tests;

pub(crate) mod core;
mod cost;
pub(crate) mod flac;
mod perm;
mod sample;
mod wav;

/// Embed a payload into a WAV carrier, returning the modified file.
///
/// The returned bytes have exactly the same length as the input; only bytes
/// inside the `data` chunk differ.
#[allow(clippy::too_many_arguments)]
pub(crate) fn embed_wav(
    carrier: &[u8],
    payload: &Payload<'_>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    profile: &AudioFormatProfile,
    safety: SafetyPolicy,
    freshness: Freshness,
    control: &Control<'_>,
) -> Result<(Vec<u8>, StegoCapacityInfo, EmbedStats), StrHideError> {
    let layout = wav::parse_wav(carrier)?;
    let suite = suite_from_id(suite_id)?;
    let pre_salt = wav_pre_salt(&layout, profile.hpos_salt);
    let prepared = core::prepare(cred, domain, profile.cipher, &pre_salt)?;
    let mut bytes = carrier.to_vec();
    let (info, stats) = {
        let mut pcm = wav::PcmCarrier::new(&mut bytes, layout);
        core::embed(
            &mut pcm,
            core::Mapping::Permuted,
            payload,
            &prepared,
            domain,
            suite,
            extensions,
            profile.cipher,
            WAV_FORMAT_ID,
            safety,
            freshness,
            carrier,
            control,
        )?
    };
    Ok((bytes, info, stats))
}

/// Extract a payload from a WAV carrier.
pub(crate) fn extract_wav(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    if core::pbkdf2_policy_blocks(cred, limits) {
        return Err(core::no_hidden_data());
    }
    let layout = wav::parse_wav(carrier)?;
    let pre_salt = wav_pre_salt(&layout, profile.hpos_salt);
    let prepared = core::prepare(cred, domain, profile.cipher, &pre_salt)?;
    // Extraction never mutates: present the file as an immutable slot array.
    let mut scratch = carrier.to_vec();
    let pcm = wav::PcmCarrier::new(&mut scratch, layout);
    core::extract(
        &pcm,
        core::Mapping::Permuted,
        &prepared,
        domain,
        profile.cipher,
        WAV_FORMAT_ID,
        limits,
        control,
    )
}

/// Report a WAV carrier's embedding capacity.
#[allow(clippy::too_many_arguments)]
pub(crate) fn probe_wav(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    extensions: &[Tlv],
    level: SafetyLevel,
    profile: &AudioFormatProfile,
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    let layout = wav::parse_wav(carrier)?;
    let pre_salt = wav_pre_salt(&layout, profile.hpos_salt);
    let prepared = core::prepare(cred, domain, profile.cipher, &pre_salt)?;
    let mut scratch = carrier.to_vec();
    let pcm = wav::PcmCarrier::new(&mut scratch, layout);
    core::probe(
        &pcm,
        core::Mapping::Permuted,
        level,
        &prepared,
        extensions,
        control,
    )
}

/// Inspect a WAV carrier's stego header.
pub(crate) fn inspect_wav(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    if core::pbkdf2_policy_blocks(cred, limits) {
        return Ok(StegoHeaderInfo::empty("WAV"));
    }
    control.check()?;
    let layout = wav::parse_wav(carrier)?;
    let pre_salt = wav_pre_salt(&layout, profile.hpos_salt);
    let prepared = core::prepare(cred, domain, profile.cipher, &pre_salt)?;
    let mut scratch = carrier.to_vec();
    let pcm = wav::PcmCarrier::new(&mut scratch, layout);
    Ok(core::inspect(
        &pcm,
        core::Mapping::Permuted,
        &prepared,
        WAV_FORMAT_ID,
        limits,
    ))
}

/// Multi-tier verification of a WAV carrier.
pub(crate) fn verify_wav(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    profile: &AudioFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    if core::pbkdf2_policy_blocks(cred, limits) {
        return Ok(core::policy_failure_result("WAV"));
    }
    let layout = wav::parse_wav(carrier)?;
    let pre_salt = wav_pre_salt(&layout, profile.hpos_salt);
    let prepared = core::prepare(cred, domain, profile.cipher, &pre_salt)?;
    let mut scratch = carrier.to_vec();
    let pcm = wav::PcmCarrier::new(&mut scratch, layout);
    core::verify(
        &pcm,
        core::Mapping::Permuted,
        &prepared,
        domain,
        profile.cipher,
        WAV_FORMAT_ID,
        limits,
        control,
    )
}
