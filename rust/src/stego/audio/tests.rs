//! End-to-end tests for the audio content engines.
//!
//! They build carriers in memory so the assertions can talk about *bytes*: the
//! length must not change, and the set of modified offsets must stay inside the
//! PCM payload. The real-file corpus lives in the ignored `local_` tests, which
//! need `temp/testaudio/`.

use crate::SafetyPolicy;
use crate::core::control::Control;
use crate::core::payload::Payload;
use crate::crypto::Credential;
use crate::errors::StrHideError;
use crate::params::SafetyLevel;
use crate::stego::audio::{embed_wav, extract_wav, inspect_wav, probe_wav, verify_wav};
use crate::stego::envelope::Freshness;
use crate::stego::format::{AudioFormatProfile, OFFICIAL_AUDIO_CIPHER};
use crate::stego::header::Tlv;
use crate::stego::params::ExtractParams;

use super::{core, wav};

/// 16-bit mono PCM WAV whose samples follow a smooth, non-degenerate curve so
/// the cost model has something to discriminate on.
fn wav_carrier(frames: usize) -> Vec<u8> {
    let data_len = frames * 2;
    let mut out = Vec::with_capacity(44 + data_len);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&((36 + data_len) as u32).to_le_bytes());
    out.extend_from_slice(b"WAVE");
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // PCM
    out.extend_from_slice(&1u16.to_le_bytes()); // mono
    out.extend_from_slice(&44_100u32.to_le_bytes());
    out.extend_from_slice(&88_200u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&(data_len as u32).to_le_bytes());
    for i in 0..frames {
        // A 220 Hz tone with a small ripple: comfortably above the silence
        // threshold the cost model treats as unusable.
        let phase = (i % 200) as f64 / 200.0 * std::f64::consts::TAU;
        let value = (phase.sin() * 9_000.0) as i32 + ((i % 7) as i32 - 3);
        out.extend_from_slice(&(value as i16).to_le_bytes());
    }
    out
}

fn ctl() -> Control<'static> {
    Control::default()
}

fn profile() -> &'static AudioFormatProfile {
    &crate::stego::format::OFFICIAL_WAV_FORMAT
}

fn suite() -> u16 {
    OFFICIAL_AUDIO_CIPHER.default_suite.as_u16()
}

fn cred(password: Option<&str>) -> Credential<'_> {
    match password {
        Some(password) => Credential::Password(password),
        None => Credential::Password(crate::stego::envelope::PUBLIC_DEFAULT_SECRET),
    }
}

fn limits() -> ExtractParams {
    ExtractParams::default()
}

#[test]
fn wav_round_trip_preserves_length_and_confines_changes_to_data() {
    let cover = wav_carrier(16_384);
    let payload = Payload::file("secret.txt", b"audio content steganography round trip");
    let control = ctl();

    let (stego, capacity, stats) = embed_wav(
        &cover,
        &payload,
        cred(Some("correct horse")),
        None,
        suite(),
        &[],
        profile(),
        SafetyPolicy::new(),
        Freshness::default(),
        &control,
    )
    .expect("embed");

    assert_eq!(stego.len(), cover.len(), "Δ must be zero");
    assert!(stats.modified_slots > 0, "nothing was modified");
    assert!(capacity.max_raw_payload_bytes >= payload.as_bytes().len());

    // Every changed byte lies inside the PCM payload (offset 44 onwards).
    let first_diff = cover
        .iter()
        .zip(stego.iter())
        .position(|(a, b)| a != b)
        .expect("something must change");
    assert!(first_diff >= 44, "header byte {first_diff} was modified");

    let extracted = extract_wav(
        &stego,
        cred(Some("correct horse")),
        None,
        profile(),
        &limits(),
        &control,
    )
    .expect("extract");
    assert_eq!(extracted.as_bytes(), payload.as_bytes());
    assert_eq!(extracted.name(), Some("secret.txt"));

    // Wrong password: identical "nothing here" verdict, no oracle.
    let err = extract_wav(
        &stego,
        cred(Some("wrong")),
        None,
        profile(),
        &limits(),
        &control,
    )
    .unwrap_err();
    assert!(matches!(err, StrHideError::NoHiddenData(_)), "{err:?}");

    let info = inspect_wav(
        &stego,
        cred(Some("correct horse")),
        None,
        profile(),
        &limits(),
        &control,
    )
    .expect("inspect");
    assert!(info.has_hidden_data);
    assert_eq!(info.format, "WAV");
    assert!(
        !inspect_wav(
            &stego,
            cred(Some("wrong")),
            None,
            profile(),
            &limits(),
            &control
        )
        .expect("inspect wrong")
        .has_hidden_data
    );

    let verified = verify_wav(
        &stego,
        cred(Some("correct horse")),
        None,
        profile(),
        &limits(),
        &control,
    )
    .expect("verify");
    assert!(verified.is_all_ok(), "{verified:?}");
}

#[test]
fn clean_wav_reports_no_hidden_data() {
    let cover = wav_carrier(4_096);
    let control = ctl();
    let err = extract_wav(&cover, cred(None), None, profile(), &limits(), &control).unwrap_err();
    assert!(matches!(err, StrHideError::NoHiddenData(_)));
    assert!(
        !inspect_wav(&cover, cred(None), None, profile(), &limits(), &control)
            .unwrap()
            .has_hidden_data
    );
}

#[test]
fn payload_beyond_capacity_is_refused_not_truncated() {
    let cover = wav_carrier(2_048);
    // Incompressible so the envelope cannot shrink below the slot budget: a
    // repetitive buffer would deflate and legitimately fit.
    let raw: Vec<u8> = (0..4_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let payload = Payload::bytes(&raw);
    let control = ctl();
    let err = embed_wav(
        &cover,
        &payload,
        cred(None),
        None,
        suite(),
        &[],
        profile(),
        SafetyPolicy::new(),
        Freshness::default(),
        &control,
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("capacity"), "{msg}");
}

#[test]
fn probe_reports_a_capacity_the_embedder_can_actually_fill() {
    let cover = wav_carrier(20_000);
    let control = ctl();
    let info = probe_wav(
        &cover,
        cred(None),
        None,
        &[],
        SafetyLevel::High,
        profile(),
        &control,
    )
    .expect("probe");
    assert_eq!(info.format, "WAV");
    assert_eq!(info.total_elements, 20_000);
    assert!(info.max_raw_payload_bytes > 0);
    assert!(info.recommended_max_bytes <= info.max_raw_payload_bytes);
    assert!(info.tier_limits[0] <= info.tier_limits[1]);
    assert!(info.tier_limits[1] <= info.tier_limits[2]);

    // A payload at the advertised raw capacity must actually fit, and the
    // result must read back. Capping this at a few kilobytes (the old
    // `min(2_000)`) left the top of the range -- where the planner switches STC
    // group size -- completely untested.
    let raw: Vec<u8> = (0..info.max_raw_payload_bytes)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let payload = Payload::bytes(&raw);
    let (stego, _, _) = embed_wav(
        &cover,
        &payload,
        cred(None),
        None,
        suite(),
        &[],
        profile(),
        SafetyPolicy::new(),
        Freshness::default(),
        &control,
    )
    .expect("advertised capacity must be embeddable");
    let extracted = extract_wav(
        &stego,
        cred(None),
        None,
        profile(),
        &ExtractParams::default(),
        &control,
    )
    .expect("the carrier written at full capacity must extract");
    assert_eq!(extracted, raw);
}

#[test]
fn embedding_twice_into_the_same_cover_is_deterministic_when_seeded() {
    // Reproducibility is a first-class contract: the same cover, payload and
    // seed must produce byte-identical output.
    let cover = wav_carrier(8_192);
    let payload = Payload::bytes(b"deterministic");
    let seed = [7u8; 32];
    let control = ctl();
    let a = embed_wav(
        &cover,
        &payload,
        cred(Some("pw")),
        None,
        suite(),
        &[],
        profile(),
        SafetyPolicy::new(),
        Freshness::Seeded(seed),
        &control,
    )
    .expect("embed a")
    .0;
    let b = embed_wav(
        &cover,
        &payload,
        cred(Some("pw")),
        None,
        suite(),
        &[],
        profile(),
        SafetyPolicy::new(),
        Freshness::Seeded(seed),
        &control,
    )
    .expect("embed b")
    .0;
    assert_eq!(a, b, "seeded embeds must be bit-identical");
}

fn embedded_wav(payload: &[u8], extensions: &[Tlv]) -> Vec<u8> {
    let cover = wav_carrier(20_000);
    let payload = Payload::bytes(payload);
    embed_wav(
        &cover,
        &payload,
        cred(None),
        None,
        suite(),
        extensions,
        profile(),
        SafetyPolicy::new(),
        Freshness::default(),
        &ctl(),
    )
    .expect("embed")
    .0
}

/// Read the base header of a written carrier through the same keyed plan the
/// extractor uses.
fn wav_view(stego: &[u8]) -> (wav::WavLayout, core::PreparedCarrier, core::HeaderView) {
    let layout = wav::parse_wav(stego).expect("layout");
    let pre_salt = super::wav_pre_salt(&layout, profile().hpos_salt);
    let prepared = core::prepare(cred(None), None, profile().cipher, &pre_salt).expect("prepare");
    let mut scratch = stego.to_vec();
    let pcm = wav::PcmCarrier::new(&mut scratch, layout);
    let view = core::read_base(
        &pcm,
        core::Mapping::Permuted,
        &prepared,
        super::WAV_FORMAT_ID,
    )
    .expect("base header");
    (layout, prepared, view)
}

/// Put forged header bytes back into the carrier, so the extractor sees them.
fn rewrite_base(stego: &[u8], bytes: &[u8; 64]) -> Vec<u8> {
    let (layout, prepared, _) = wav_view(stego);
    let mut out = stego.to_vec();
    {
        let mut pcm = wav::PcmCarrier::new(&mut out, layout);
        core::rewrite_base_header(&mut pcm, core::Mapping::Permuted, &prepared, bytes)
            .expect("rewrite");
    }
    out
}

fn assert_no_hidden(bytes: &[u8]) {
    let err = extract_wav(bytes, cred(None), None, profile(), &limits(), &ctl()).unwrap_err();
    assert!(matches!(err, StrHideError::NoHiddenData(_)), "{err:?}");
}

#[test]
fn wav_forged_headers_and_truncated_bodies_are_rejected() {
    let stego = embedded_wav(b"negative coverage", &[]);
    let (_, _, view) = wav_view(&stego);

    // A carrier too short for the 512-slot header pool must report nothing.
    assert_no_hidden(&wav_carrier(64));

    // body_len at the tag-only minimum, below it, and far past any real pool:
    // all are refused before a body allocation happens.
    for forged in [0u32, 21, 0x03ff_ffff] {
        let mut header = view.header;
        header.body_len = forged;
        let bytes = header.encode();
        assert_no_hidden(&rewrite_base(&stego, &bytes));
    }

    // A raw flip leaves the CRC stale, so the header dies at decode time.
    let mut raw = view.base_bytes;
    raw[0] ^= 0x01;
    assert_no_hidden(&rewrite_base(&stego, &raw));

    // A flip that *does* recompute the CRC passes structure and fails the AEAD.
    let mut header = view.header;
    header.salt[0] ^= 0x01;
    let bytes = header.encode();
    assert_no_hidden(&rewrite_base(&stego, &bytes));

    // Sanity: the untouched carrier still reads.
    assert_eq!(
        extract_wav(&stego, cred(None), None, profile(), &limits(), &ctl())
            .expect("intact carrier")
            .as_bytes(),
        b"negative coverage"
    );
}

#[test]
fn wav_unknown_suite_and_extension_criticality_fail_closed() {
    let cover = wav_carrier(20_000);
    let payload = Payload::bytes(b"suite");
    let err = embed_wav(
        &cover,
        &payload,
        cred(None),
        None,
        0x7fff,
        &[],
        profile(),
        SafetyPolicy::new(),
        Freshness::default(),
        &ctl(),
    )
    .unwrap_err();
    assert!(
        matches!(err, StrHideError::UnsupportedVersion(_)),
        "{err:?}"
    );

    // Non-critical unknowns are carried through without disturbing the payload.
    let ext = [Tlv {
        type_id: 0x02,
        value: vec![1, 2, 3],
    }];
    let stego = embedded_wav(b"tlv", &ext);
    assert_eq!(
        extract_wav(&stego, cred(None), None, profile(), &limits(), &ctl())
            .expect("non-critical extension")
            .as_bytes(),
        b"tlv"
    );

    // The writer refuses a critical TLV outright: V4 defines no critical
    // extension, so accepting one would emit a carrier this build cannot read.
    let critical = [Tlv {
        type_id: 0x81,
        value: vec![9, 9],
    }];
    let err = embed_wav(
        &cover,
        &Payload::bytes(b"critical"),
        cred(None),
        None,
        suite(),
        &critical,
        profile(),
        SafetyPolicy::new(),
        Freshness::default(),
        &ctl(),
    )
    .unwrap_err();
    assert!(matches!(err, StrHideError::General(_)), "{err:?}");

    // A hostile writer bypasses that check; the reader must still refuse the
    // carrier instead of skipping the unknown critical tag.
    let forged = forge_critical_extension(&stego, &[0x81, 0x02, 9, 9]);
    assert_no_hidden(&forged);
}

/// Rewrite a WAV carrier's header and extension area so it declares the given
/// (critical) TLV bytes, the way a writer that ignored the fail-closed
/// validation would have produced it.
fn forge_critical_extension(stego: &[u8], extension: &[u8]) -> Vec<u8> {
    use crate::stego::header::{FLAG_EXT_CRITICAL, FLAG_EXT_PRESENT};

    let layout = wav::parse_wav(stego).expect("layout");
    let pre_salt = super::wav_pre_salt(&layout, profile().hpos_salt);
    let prepared = core::prepare(cred(None), None, profile().cipher, &pre_salt).expect("prepare");
    let mut scratch = stego.to_vec();
    {
        let mut pcm = wav::PcmCarrier::new(&mut scratch, layout);
        let view = core::read_base(
            &pcm,
            core::Mapping::Permuted,
            &prepared,
            super::WAV_FORMAT_ID,
        )
        .expect("base header");

        let mut header = view.header;
        header.ext_len = extension.len() as u16;
        header.flags = FLAG_EXT_PRESENT | FLAG_EXT_CRITICAL;
        let bytes = header.encode();
        core::rewrite_base_header(&mut pcm, core::Mapping::Permuted, &prepared, &bytes)
            .expect("rewrite header");
        let header_slots = crate::stego::header::PNG_AUDIO_BASE_SLOTS + 8 * extension.len();
        core::rewrite_extension(
            &mut pcm,
            core::Mapping::Permuted,
            &prepared,
            header_slots,
            extension,
        )
        .expect("rewrite extension");
    }
    scratch
}

#[test]
fn written_directions_are_balanced_across_the_carrier() {
    // A trellis tie would send every change to `+1`; the keyed polarisation is
    // what keeps the delta histogram symmetric, which is the difference between
    // "invisible" and "a first-order steganalysis signature".
    let cover = wav_carrier(32_768);
    let payload = Payload::bytes(b"direction balance");
    let control = ctl();
    let (stego, _, stats) = embed_wav(
        &cover,
        &payload,
        cred(Some("pw")),
        None,
        suite(),
        &[],
        profile(),
        SafetyPolicy::new(),
        Freshness::default(),
        &control,
    )
    .expect("embed");

    let mut plus = 0usize;
    let mut minus = 0usize;
    for off in (44..cover.len()).step_by(2) {
        let before = i16::from_le_bytes([cover[off], cover[off + 1]]) as i32;
        let after = i16::from_le_bytes([stego[off], stego[off + 1]]) as i32;
        match after - before {
            0 => {}
            1 => plus += 1,
            -1 => minus += 1,
            other => panic!("slot moved by {other}, must stay within ±1"),
        }
    }
    assert_eq!(plus + minus, stats.modified_slots);
    assert!(plus > 0 && minus > 0, "one-sided: +{plus} / -{minus}");
    let skew = (plus as f64 - minus as f64).abs() / (plus + minus) as f64;
    assert!(
        skew < 0.15,
        "direction skew {skew:.3} too large: +{plus} / -{minus}"
    );
}

/// The body phase is the only thing a FLAC retry changes about slot selection,
/// and the extractor rebuilds it from the header's salt/nonce. It must be
/// deterministic for a given pair and must actually change when a retry draws
/// a new one -- otherwise the retry would keep hitting the same dead group.
#[test]
fn flac_body_phase_is_reproducible_and_attempt_sensitive() {
    use super::{flac_body_phase, flac_retryable};
    use crate::errors::{StrHideError, TrellisCause};

    let base = 0x1234_5678_9ABC_DEF0u64;
    let salt = [1u8; 16];
    let nonce = [2u8; 12];
    let first = flac_body_phase(base, &salt, &nonce);
    assert_eq!(first, flac_body_phase(base, &salt, &nonce));

    let mut salt2 = salt;
    salt2[0] ^= 1;
    assert_ne!(first, flac_body_phase(base, &salt2, &nonce));
    let mut nonce2 = nonce;
    nonce2[0] ^= 1;
    assert_ne!(first, flac_body_phase(base, &salt, &nonce2));

    // Two successive attempts with a seeded freshness must not collapse onto
    // the same phase (6 attempts, all distinct on this seed).
    let binding = b"deterministic binding context";
    let fresh = Freshness::Seeded([7u8; 32]);
    let mut seen = std::collections::HashSet::new();
    for attempt in 0..6u32 {
        let s = fresh.salt(attempt, binding);
        let n = fresh.nonce(attempt, binding);
        assert!(
            seen.insert(flac_body_phase(base, &s, &n)),
            "attempt {attempt} reused a phase"
        );
    }

    // Only a collapsed trellis is worth another attempt; structural failures
    // must surface immediately instead of being masked by six retries.
    assert!(flac_retryable(&StrHideError::TrellisInfeasible {
        cause: TrellisCause::DeadGroup,
        detail: "x".into(),
    }));
    assert!(flac_retryable(&StrHideError::TrellisInfeasible {
        cause: TrellisCause::DeadElement,
        detail: "x".into(),
    }));
    assert!(!flac_retryable(&StrHideError::General("x".into())));
}

/// Regression for the 40 % refusal on `07.朔漠南望.wav` (stereo 16-bit,
/// 24,205,608 samples, 24,205,096 body slots after the 512-slot V4 header).
///
/// At 40 % of the advertised 3,025,358-byte capacity the slot abundance picks
/// STC `u = 2`, but `u = 2` costs one extra state bit per column, so its
/// working-set ceiling (18,728,055 slots) is below the 24,205,096 slots the
/// carrier exposes. The planner accepted `u = 2`, produced 19,362,654 body
/// slots, and the embedder then refused a payload the capacity report had
/// promised. `plan_body` must fall back to `u = 1`, whose narrower per-slot
/// trellis fits the same payload.
///
/// The numbers are the ones the failing `audio_stress` run printed, so this
/// pins the exact `u = 2`/`u = 1` boundary instead of approximating it.
#[test]
fn wav_plan_falls_back_to_u1_when_u2_exceeds_the_working_set() {
    use crate::stego::coding::DEFAULT_STC_H;

    const AVAILABLE: usize = 24_205_608 - 512;
    // 3,025,358 bytes at 40 %, plus the 22-byte envelope expansion.
    let ciphertext = 1_210_143 + 22;
    let shape = core::plan_body(ciphertext, AVAILABLE, DEFAULT_STC_H, 1).expect("plan");
    assert_eq!(
        shape.u, 1,
        "a payload beyond the u = 2 ceiling must fall back to u = 1"
    );
    assert_eq!(shape.body_slots, ciphertext * 8 + 7);

    // Boundary probes: 1,170,480 bytes still fits the u = 2 ceiling
    // (18,728,046 <= 18,728,055 slots), one byte more does not.
    let fits = core::plan_body(1_170_480 + 22, AVAILABLE, DEFAULT_STC_H, 1).expect("plan");
    assert_eq!(
        fits.u, 2,
        "the fitting side of the boundary must keep u = 2"
    );
    let over = core::plan_body(1_170_481 + 22, AVAILABLE, DEFAULT_STC_H, 1).expect("plan");
    assert_eq!(over.u, 1, "the failing side of the boundary must fall back");
}
