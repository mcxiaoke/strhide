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
use crate::errors::{StrHideError, TrellisCause};
use crate::params::SafetyLevel;
use crate::stego::envelope::Freshness;
use crate::stego::format::AudioFormatProfile;
use crate::stego::header::{PNG_AUDIO_BASE_SLOTS, Tlv, encode_extension_for_write};
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

/// How many body-phase/salt draws a FLAC embed may try before giving up.
/// Mirrors the JPEG engine's bounded retry budget.
const FLAC_EMBED_ATTEMPTS: u32 = 6;

/// Body thinning phase for one embed attempt.
///
/// Header and extension phases stay password-derived so a reader can decode the
/// base header before it knows anything about the payload. Only the body phase
/// is folded with the session salt/nonce -- both already live in the V4 header,
/// so the extractor can reproduce the exact slot subset without a new wire
/// field. Varying them per attempt is what lets a retry escape a `DeadGroup`
/// caused by an unlucky run of immovable residuals.
fn flac_body_phase(base: u64, salt: &[u8], nonce: &[u8]) -> u64 {
    let mut h = Sha256::new();
    h.update(b"strhide-v4-flac-body-phase");
    h.update(base.to_le_bytes());
    h.update(salt);
    h.update(nonce);
    let digest = h.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("SHA-256 yields 32 bytes"))
}

/// A trellis that ran out of reachable states is worth another phase draw;
/// every other failure is structural and must not be masked by a retry.
fn flac_retryable(err: &StrHideError) -> bool {
    matches!(
        err,
        StrHideError::TrellisInfeasible {
            cause: TrellisCause::DeadGroup | TrellisCause::DeadElement,
            ..
        }
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
///
/// A keyed thinning can pick a body subset whose early groups contain no
/// movable residual at all, leaving the trellis no way to steer its warm-up
/// rows. The body phase is folded with the session salt/nonce that the V4
/// header already carries, so a bounded retry draws a different subset and the
/// extractor can reproduce it without any new wire field.
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
    let extension = encode_extension_for_write(extensions)?;
    let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * extension.len();
    if analysis.tails < header_slots {
        return Err(StrHideError::General(format!(
            "FLAC carrier has {} usable subframe tails; the V4 header needs {header_slots}",
            analysis.tails
        )));
    }
    if analysis.slots < 8 {
        return Err(StrHideError::General(format!(
            "FLAC carrier has {} residual slots; at least 8 are required",
            analysis.slots
        )));
    }

    let pre_salt = flac_pre_salt(&info, profile.hpos_salt);
    let prepared = core::prepare(cred, domain, profile.cipher, &pre_salt)?;

    // Everything up to here is attempt-independent: parsing a 20 MB FLAC and
    // recomputing its PCM MD5 once per retry would dominate the retry cost.
    let plaintext = crate::stego::envelope::build_plaintext(payload)?;
    let shape = core::plan_body(
        plaintext.len() + suite.tag_len(),
        analysis.usable,
        crate::stego::coding::DEFAULT_STC_H,
        flac::FlacCarrier::MIN_GROUP,
    )?;
    let (header_phase, ext_phase, body_phase_base) = flac_phases(&prepared.locator.locate_seed);
    let binding = core::fresh_binding_for(carrier, payload, FLAC_FORMAT_ID, extensions)?;

    let mut last_error: Option<StrHideError> = None;
    for attempt in 0..FLAC_EMBED_ATTEMPTS {
        control.check()?;
        let salt = freshness.salt(attempt, &binding);
        let nonce = freshness.nonce(attempt, &binding);
        let body_phase = flac_body_phase(body_phase_base, &salt, &nonce);

        // Fresh clone per attempt: a failed solve leaves header writes behind
        // in `bytes`, and the next attempt must start from the pristine cover.
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
        // The finalize pass decodes the patched file to rebuild the MD5; let it
        // compare the waveform against the cover in the same walk instead of
        // decoding both files again afterwards.
        carrier_view.track_drift(carrier);
        let result = core::embed(
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
            salt,
            nonce,
            control,
        );
        match result {
            Ok((capacity, stats)) => {
                let drift = carrier_view.pcm_max_drift();
                if drift > flac::DRIFT_BUDGET {
                    return Err(StrHideError::General(format!(
                        "FLAC embed would shift the decoded waveform by {drift} units, past the compensation budget; refusing to emit a carrier whose predictor is unstable"
                    )));
                }
                return Ok((bytes, capacity, stats));
            }
            Err(err) if flac_retryable(&err) => last_error = Some(err),
            Err(err) => return Err(err),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        StrHideError::General("FLAC embedding exhausted its retry budget".into())
    }))
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
    let (analysis, tails) = flac::analyse_with_tails(carrier, &info)?;
    let pre_salt = flac_pre_salt(&info, profile.hpos_salt);
    let prepared = core::prepare(cred, domain, profile.cipher, &pre_salt)?;
    let (header_phase, ext_phase, body_phase_base) = flac_phases(&prepared.locator.locate_seed);

    // First read the base header with an empty body, then rebuild with the body
    // the header advertises. The slot arrays differ, which is why this is two
    // constructions rather than one. The base header carries the salt/nonce
    // that selected this attempt's body subset, so the second pass can derive
    // exactly the phase the writer used. The validating scan above already
    // retained the tail pool, so the header view costs no second decode.
    let mut scratch = carrier.to_vec();
    let header_view = flac::FlacCarrier::header_view(
        &mut scratch,
        info,
        &analysis,
        &tails,
        PNG_AUDIO_BASE_SLOTS,
        header_phase,
        ext_phase,
    )?;
    let view = core::read_base(
        &header_view,
        core::Mapping::BodyPermuted,
        &prepared,
        FLAC_FORMAT_ID,
    )?;
    drop(header_view);
    let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * view.header.ext_len as usize;
    if header_slots > analysis.tails {
        return Err(core::no_hidden_data());
    }
    let body_slots = core::body_slots_for(&view.header)?;
    // Structural pool, not `usable`: embedding rewrites residual values, so the
    // stego file's movable count is not the one the writer planned with.
    if body_slots > analysis.slots {
        return Err(core::no_hidden_data());
    }

    // Reuse `scratch`: the header view borrows it only until `read_base`
    // returns, and the body view needs the same bytes, so a second full-file
    // clone is pure waste (F-26). The third `analyse` CRC recheck elsewhere
    // stays as-is.
    let body_phase = flac_body_phase(body_phase_base, &view.header.salt, &view.header.nonce);
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
    let extension = encode_extension_for_write(extensions)?;
    let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * extension.len();
    if analysis.tails < header_slots {
        return Err(StrHideError::General(format!(
            "FLAC carrier has {} usable subframe tails; the V4 header needs {header_slots}",
            analysis.tails
        )));
    }
    if analysis.slots < 8 {
        return Err(StrHideError::General(format!(
            "FLAC carrier has {} residual slots; at least 8 are required",
            analysis.slots
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
    let (analysis, tails) = flac::analyse_with_tails(carrier, &info)?;
    let pre_salt = flac_pre_salt(&info, profile.hpos_salt);
    let prepared = core::prepare(cred, domain, profile.cipher, &pre_salt)?;
    let (header_phase, ext_phase, body_phase) = flac_phases(&prepared.locator.locate_seed);

    // One scratch for both passes: `read_base` releases its borrow when it
    // returns, and the body view needs the same bytes, so a second full-file
    // clone is pure waste (C-07). Mirrors `extract_flac`. The header view reuses
    // the tail pool retained by the validating scan.
    let mut scratch = carrier.to_vec();
    let view = {
        let header_view = flac::FlacCarrier::header_view(
            &mut scratch,
            info,
            &analysis,
            &tails,
            PNG_AUDIO_BASE_SLOTS,
            header_phase,
            ext_phase,
        )?;
        // A wrong password makes the header unreadable; fall back to the
        // header-only view, which reports "nothing here" instead of an error.
        core::read_base(
            &header_view,
            core::Mapping::BodyPermuted,
            &prepared,
            FLAC_FORMAT_ID,
        )
    };
    let (header_slots, body_slots) = match &view {
        Ok(v) => {
            let hs = PNG_AUDIO_BASE_SLOTS + 8 * v.header.ext_len as usize;
            let bs = core::body_slots_for(&v.header).unwrap_or(0);
            (hs, bs)
        }
        Err(e) => {
            // A clean FLAC has no readable header, so this is the normal
            // "nothing here" answer — keep `has_hidden_data = false`, but leave
            // a record so "cannot read" stays distinguishable in the logs.
            log::debug!(target: "stego::inspect", "flac header view unreadable: {e}");
            (PNG_AUDIO_BASE_SLOTS, 0)
        }
    };

    // `ext_len` is unauthenticated until AEAD runs, so a forged value can ask
    // for more header/body slots than the stream has. That is "no header",
    // not an error: rejecting it here keeps inspect's documented surface
    // (`has_hidden_data=false`) instead of leaking a structural failure.
    if header_slots > analysis.tails || body_slots > analysis.slots {
        return Ok(StegoHeaderInfo::empty("FLAC"));
    }

    // Reuse `scratch` for the body view; see `inspect_flac`.
    // A wrong/unreadable header leaves the body phase at its password-derived
    // base; the caller reports "no hidden data" and never reads the body.
    let body_phase = match &view {
        Ok(v) => flac_body_phase(body_phase, &v.header.salt, &v.header.nonce),
        Err(e) => {
            log::debug!(
                target: "stego::inspect",
                "flac body phase stays at its password-derived base: {e}"
            );
            body_phase
        }
    };
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
        Err(e) => {
            log::debug!(target: "stego::inspect", "flac yields no header: {e}");
            StegoHeaderInfo::empty("FLAC")
        }
    })
}

/// Level-2/3 verdict for a FLAC carrier whose header cannot be decoded.
fn flac_unreadable() -> StegoVerifyResult {
    StegoVerifyResult::new(
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
    )
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
    let (analysis, tails) = flac::analyse_with_tails(carrier, &info)?;
    let pre_salt = flac_pre_salt(&info, profile.hpos_salt);
    let prepared = core::prepare(cred, domain, profile.cipher, &pre_salt)?;
    let (header_phase, ext_phase, body_phase) = flac_phases(&prepared.locator.locate_seed);

    // One scratch for both passes (C-07); `read_base` does not keep a borrow.
    // The header view reuses the tail pool retained by the validating scan.
    let mut scratch = carrier.to_vec();
    let view = {
        let header_view = flac::FlacCarrier::header_view(
            &mut scratch,
            info,
            &analysis,
            &tails,
            PNG_AUDIO_BASE_SLOTS,
            header_phase,
            ext_phase,
        )?;
        core::read_base(
            &header_view,
            core::Mapping::BodyPermuted,
            &prepared,
            FLAC_FORMAT_ID,
        )
    };
    let (header_slots, body_slots) = match &view {
        Ok(v) => {
            let hs = PNG_AUDIO_BASE_SLOTS + 8 * v.header.ext_len as usize;
            let bs = core::body_slots_for(&v.header)
                .unwrap_or(0)
                .min(analysis.slots);
            (hs, bs)
        }
        Err(e) => {
            log::debug!(target: "stego::verify", "flac header view unreadable: {e}");
            (PNG_AUDIO_BASE_SLOTS, 0)
        }
    };

    // Same unauthenticated-`ext_len` bound as `inspect_flac`.
    if header_slots > analysis.tails || body_slots > analysis.slots {
        return Ok(flac_unreadable());
    }

    // Reuse `scratch` for the body view; see `inspect_flac`.
    // A wrong/unreadable header leaves the body phase at its password-derived
    // base; the caller reports "no hidden data" and never reads the body.
    let body_phase = match &view {
        Ok(v) => flac_body_phase(body_phase, &v.header.salt, &v.header.nonce),
        Err(e) => {
            log::debug!(
                target: "stego::verify",
                "flac body phase stays at its password-derived base: {e}"
            );
            body_phase
        }
    };
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
        Err(e) => {
            log::debug!(target: "stego::verify", "flac header unreadable: {e}");
            Ok(flac_unreadable())
        }
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
    let binding = core::fresh_binding_for(carrier, payload, WAV_FORMAT_ID, extensions)?;
    let salt = freshness.salt(0, &binding);
    let nonce = freshness.nonce(0, &binding);
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
            salt,
            nonce,
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
