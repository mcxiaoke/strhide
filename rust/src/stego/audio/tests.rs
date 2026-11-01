//! End-to-end tests for the audio content engines.
//!
//! They build carriers in memory so the assertions can talk about *bytes*: the
//! length must not change, and the set of modified offsets must stay inside the
//! PCM payload. The real-file corpus lives in the ignored `local_` tests, which
//! need `temp/testaudio/`.

use crate::SafetyPolicy;
use crate::core::control::Control;
use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::params::SafetyLevel;
use crate::stego::audio::{embed_wav, extract_wav, inspect_wav, probe_wav, verify_wav};
use crate::stego::envelope::Freshness;
use crate::stego::format::AudioFormatProfile;

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

#[test]
fn wav_round_trip_preserves_length_and_confines_changes_to_data() {
    let cover = wav_carrier(16_384);
    let payload = Payload::file("secret.txt", b"audio content steganography round trip");
    let control = ctl();

    let (stego, capacity, stats) = embed_wav(
        &cover,
        &payload,
        Some("correct horse"),
        None,
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

    let extracted =
        extract_wav(&stego, Some("correct horse"), None, profile(), &control).expect("extract");
    assert_eq!(extracted.as_bytes(), payload.as_bytes());
    assert_eq!(extracted.name(), Some("secret.txt"));

    // Wrong password: identical "nothing here" verdict, no oracle.
    let err = extract_wav(&stego, Some("wrong"), None, profile(), &control).unwrap_err();
    assert!(matches!(err, StrHideError::NoHiddenData(_)), "{err:?}");

    let info =
        inspect_wav(&stego, Some("correct horse"), None, profile(), &control).expect("inspect");
    assert!(info.has_hidden_data);
    assert_eq!(info.format, "WAV");
    assert!(
        !inspect_wav(&stego, Some("wrong"), None, profile(), &control)
            .expect("inspect wrong")
            .has_hidden_data
    );

    let verified =
        verify_wav(&stego, Some("correct horse"), None, profile(), &control).expect("verify");
    assert!(verified.is_all_ok(), "{verified:?}");
}

#[test]
fn clean_wav_reports_no_hidden_data() {
    let cover = wav_carrier(4_096);
    let control = ctl();
    let err = extract_wav(&cover, None, None, profile(), &control).unwrap_err();
    assert!(matches!(err, StrHideError::NoHiddenData(_)));
    assert!(
        !inspect_wav(&cover, None, None, profile(), &control)
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
        None,
        None,
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
    let info = probe_wav(&cover, SafetyLevel::High, &control).expect("probe");
    assert_eq!(info.format, "WAV");
    assert_eq!(info.total_elements, 20_000);
    assert!(info.max_raw_payload_bytes > 0);
    assert!(info.recommended_max_bytes <= info.max_raw_payload_bytes);
    assert!(info.tier_limits[0] <= info.tier_limits[1]);
    assert!(info.tier_limits[1] <= info.tier_limits[2]);

    // A payload at the advertised raw capacity must actually fit.
    let raw = vec![0x5Au8; info.max_raw_payload_bytes.min(2_000)];
    let payload = Payload::bytes(&raw);
    embed_wav(
        &cover,
        &payload,
        None,
        None,
        profile(),
        SafetyPolicy::new(),
        Freshness::default(),
        &control,
    )
    .expect("advertised capacity must be embeddable");
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
        Some("pw"),
        None,
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
        Some("pw"),
        None,
        profile(),
        SafetyPolicy::new(),
        Freshness::Seeded(seed),
        &control,
    )
    .expect("embed b")
    .0;
    assert_eq!(a, b, "seeded embeds must be bit-identical");
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
        Some("pw"),
        None,
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
