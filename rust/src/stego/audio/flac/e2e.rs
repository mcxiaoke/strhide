//! End-to-end tests for the FLAC residual engine.
//!
//! The carrier is built here rather than borrowed from `temp/`: a hand-written
//! encoder that emits FIXED-order-2 frames gives the tests a file whose every
//! predictor tap is known, so an assertion can say *why* a sample moved instead
//! of only that it did. Real-file coverage lives in the ignored
//! `flac_corpus_validates` harness.

use crate::core::control::Control;
use crate::core::payload::Payload;
use crate::crypto::Credential;
use crate::errors::StrHideError;
use crate::params::SafetyLevel;
use crate::stego::audio::{embed_flac, extract_flac, inspect_flac, probe_flac, verify_flac};
use crate::stego::envelope::{Freshness, PUBLIC_DEFAULT_SECRET};
use crate::stego::format::{AudioFormatProfile, OFFICIAL_AUDIO_CIPHER};
use crate::stego::header::Tlv;
use crate::stego::params::ExtractParams;
use crate::{SafetyEnforcement, SafetyPolicy};

/// Append `bits` of `value` MSB-first to a growable bit stream.
struct BitSink {
    out: Vec<u8>,
    bit: usize,
}

impl BitSink {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            bit: 0,
        }
    }

    fn put(&mut self, bits: u32, value: u64) {
        for i in (0..bits).rev() {
            if self.bit.is_multiple_of(8) {
                self.out.push(0);
            }
            let one = (value >> i) & 1 == 1;
            if one {
                let last = self.out.len() - 1;
                self.out[last] |= 1 << (7 - (self.bit % 8));
            }
            self.bit += 1;
        }
    }

    fn put_signed(&mut self, bits: u32, value: i64) {
        let mask = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        self.put(bits, (value as u64) & mask);
    }

    fn put_unary(&mut self, zeros: u32) {
        for _ in 0..zeros {
            self.put(1, 0);
        }
        self.put(1, 1);
    }

    fn align(&mut self) {
        while !self.bit.is_multiple_of(8) {
            self.put(1, 0);
        }
    }
}

fn crc8(data: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x8005
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Fold a signed residual into FLAC's Rice domain.
fn fold(value: i64) -> u64 {
    if value >= 0 {
        (value as u64) << 1
    } else {
        ((-value) as u64) * 2 - 1
    }
}

/// Build a mono 16-bit 44.1 kHz FLAC with configurable predictor order and Rice parameter k.
fn flac_carrier_custom(blocks: usize, block: usize, order: usize, k: u32) -> Vec<u8> {
    assert!(order <= 4, "FIXED orders 0..=4 supported");
    let block_code: u8 = match block {
        192 => 1,
        256 => 8,
        512 => 9,
        1024 => 10,
        2048 => 11,
        4096 => 12,
        8192 => 13,
        other => panic!("block size {other} has no header code"),
    };
    let total = (blocks * block) as u64;
    let mut pcm: Vec<i16> = Vec::with_capacity(total as usize);
    let mut state: u32 = 0x1234_5678;
    for i in 0..total as usize {
        // A tone plus deterministic noise: the tone keeps the waveform smooth,
        // the noise keeps the residuals spread over several Rice buckets.
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let noise = ((state >> 16) as i32 % 2_000) - 1_000;
        let phase = (i % 733) as f64 / 733.0 * std::f64::consts::TAU;
        let value = (phase.sin() * 6_000.0) as i32 + noise;
        pcm.push(value as i16);
    }

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"fLaC");
    let mut info = Vec::with_capacity(34);
    info.extend_from_slice(&(block as u16).to_be_bytes());
    info.extend_from_slice(&(block as u16).to_be_bytes());
    info.extend_from_slice(&0u32.to_be_bytes()[1..]); // min frame size
    info.extend_from_slice(&0u32.to_be_bytes()[1..]); // max frame size
    let packed: u64 = ((44_100u64) << 44) | (15u64) << 36 | total;
    info.extend_from_slice(&packed.to_be_bytes());
    info.extend_from_slice(&[0u8; 16]);
    out.push(0x80); // last metadata block, type 0 = STREAMINFO
    out.extend_from_slice(&(34u32).to_be_bytes()[1..]);
    out.extend_from_slice(&info);

    let mut number = 0u64;
    for _ in 0..blocks {
        let samples = &pcm[number as usize..(number as usize + block)];
        let mut frame = BitSink::new();
        frame.put(14, 0x3FFE);
        frame.put(1, 0); // reserved
        frame.put(1, 0); // not variable block size
        frame.put(4, block_code as u64);
        frame.put(4, 9);
        frame.put(4, 0); // mono
        frame.put(3, 4); // 16-bit
        frame.put(1, 0); // reserved
        frame.put(8, number);
        let header_crc = crc8(&frame.out);
        frame.put(8, header_crc as u64);

        for channel in 0..1 {
            let _ = channel;
            frame.put(1, 0); // zero padding bit
            frame.put(6, (8 + order) as u64); // subframe type: 8 + order = FIXED order
            frame.put(1, 0); // no wasted bits
            for &sample in &samples[..order] {
                frame.put_signed(16, sample as i64);
            }
            frame.put(2, 0);
            frame.put(4, 0);
            frame.put(4, k as u64);
            for i in order..block {
                let residual = match order {
                    0 => samples[i] as i64,
                    1 => samples[i] as i64 - samples[i - 1] as i64,
                    2 => samples[i] as i64 - 2 * samples[i - 1] as i64 + samples[i - 2] as i64,
                    3 => {
                        samples[i] as i64 - 3 * samples[i - 1] as i64 + 3 * samples[i - 2] as i64
                            - samples[i - 3] as i64
                    }
                    4 => {
                        samples[i] as i64 - 4 * samples[i - 1] as i64 + 6 * samples[i - 2] as i64
                            - 4 * samples[i - 3] as i64
                            + samples[i - 4] as i64
                    }
                    _ => unreachable!(),
                };
                let folded = fold(residual);
                frame.put_unary((folded >> k) as u32);
                frame.put(k, folded & ((1u64 << k) - 1));
            }
        }
        frame.align();
        let crc = crc16(&frame.out);
        frame.out.extend_from_slice(&crc.to_be_bytes());
        out.extend_from_slice(&frame.out);
        number += block as u64;
    }
    out
}

/// Synthesise a valid FLAC file containing `blocks` frames of `block` samples.
fn flac_carrier(blocks: usize, block: usize) -> Vec<u8> {
    flac_carrier_custom(blocks, block, 2, 8)
}

fn profile() -> &'static AudioFormatProfile {
    use std::sync::OnceLock;
    static PROFILE: OnceLock<crate::stego::params::StegoProfile> = OnceLock::new();
    PROFILE.get_or_init(Default::default).flac_format()
}

fn ctl() -> Control<'static> {
    Control::default()
}

fn suite() -> u16 {
    OFFICIAL_AUDIO_CIPHER.default_suite.as_u16()
}

fn cred(password: Option<&str>) -> Credential<'_> {
    match password {
        Some(password) => Credential::Password(password),
        None => Credential::Password(PUBLIC_DEFAULT_SECRET),
    }
}

fn limits() -> ExtractParams {
    ExtractParams::default()
}

#[test]
fn flac_roundtrip_preserves_length_and_payload() {
    let cover = flac_carrier(600, 256);
    let raw = vec![0xA7u8; 512];
    let payload = Payload::bytes(&raw);
    let control = ctl();
    let (stego, capacity, stats) = embed_flac(
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
    assert_eq!(stego.len(), cover.len(), "FLAC length must not change");
    assert!(stats.modified_slots > 0, "nothing was written");
    assert!(capacity.recommended_max_bytes > 0);

    let out = extract_flac(
        &stego,
        cred(Some("pw")),
        None,
        profile(),
        &limits(),
        &control,
    )
    .expect("extract");
    assert_eq!(out.as_bytes(), &raw[..]);

    let err = extract_flac(
        &stego,
        cred(Some("wrong")),
        None,
        profile(),
        &limits(),
        &control,
    )
    .unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("no valid")
            || err.to_string().to_lowercase().contains("password"),
        "{err}"
    );
}

#[test]
fn flac_waveform_moves_by_at_most_one_unit_per_changed_sample() {
    let cover = flac_carrier(600, 256);
    let raw = vec![0x5Au8; 256];
    let payload = Payload::bytes(&raw);
    let control = ctl();
    let (stego, _, _) = embed_flac(
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

    // Compare the *decoded* frames: the compensation chain exists precisely so
    // that a residual move does not leak into the following samples.
    let info = super::parse_stream_info(&cover).expect("info");
    let drift = super::max_sample_drift(&cover, &stego, &info).expect("drift");
    assert!(
        drift <= super::DRIFT_BUDGET,
        "waveform drifted by {drift} units (budget {})",
        super::DRIFT_BUDGET
    );
}

#[test]
fn flac_probe_and_inspect_agree_with_the_embedder() {
    let cover = flac_carrier(600, 256);
    let raw = vec![0x11u8; 128];
    let payload = Payload::bytes(&raw);
    let control = ctl();
    let (stego, capacity, _) = embed_flac(
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

    let probed = probe_flac(
        &cover,
        cred(None),
        None,
        &[],
        SafetyLevel::High,
        profile(),
        &control,
    )
    .expect("probe");
    assert!(probed.recommended_max_bytes > 0);
    assert!(probed.max_raw_payload_bytes >= capacity.recommended_max_bytes);

    let header = inspect_flac(
        &stego,
        cred(Some("pw")),
        None,
        profile(),
        &limits(),
        &control,
    )
    .expect("inspect");
    assert!(header.has_hidden_data, "inspect must see the envelope");
    assert!(header.envelope_len.is_some());
    // A wrong password must not turn a read into an error; it just means the
    // payload cannot be recovered (asserted in the round-trip test).
    inspect_flac(
        &stego,
        cred(Some("nope")),
        None,
        profile(),
        &limits(),
        &control,
    )
    .expect("inspect never errors");

    let report = verify_flac(
        &stego,
        cred(Some("pw")),
        None,
        profile(),
        &limits(),
        &control,
    )
    .expect("verify");
    assert!(report.is_all_ok(), "envelope must verify: {report:?}");
}

#[test]
fn flac_tampering_is_detected_not_silently_accepted() {
    let cover = flac_carrier(600, 256);
    let raw = vec![0x3Cu8; 256];
    let payload = Payload::bytes(&raw);
    let control = ctl();
    let (mut stego, _, _) = embed_flac(
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

    // Flip a bit deep inside the audio payload. The frame CRC no longer
    // matches, so the file must be rejected rather than decoded into garbage.
    let at = stego.len() / 2;
    stego[at] ^= 0x01;
    let result = extract_flac(
        &stego,
        cred(Some("pw")),
        None,
        profile(),
        &limits(),
        &control,
    );
    assert!(
        result.is_err(),
        "a corrupted frame must not extract cleanly"
    );
}

#[test]
fn flac_carrier_without_enough_tails_is_refused() {
    // Eight frames give eight tails, far short of the 512-slot header.
    let cover = flac_carrier(8, 256);
    let raw = vec![0u8; 32];
    let payload = Payload::bytes(&raw);
    let control = ctl();
    let err = embed_flac(
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
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("subframe tails"), "{msg}");
}

#[test]
fn flac_carrier_high_frozen_rate_embed_and_extract() {
    // FIXED order 3 with Rice k=4 creates a high frozen rate (>20%)
    // due to compensation deltas overflowing narrow Rice partitions.
    let cover = flac_carrier_custom(600, 256, 3, 4);
    let info = super::parse_stream_info(&cover).expect("info");
    let analysis = super::analyse(&cover, &info).expect("analyse");
    let stuck_rate = 1.0 - (analysis.usable as f64 / analysis.slots as f64);
    assert!(
        stuck_rate > 0.20,
        "test carrier should exhibit noticeable frozen rate, got {stuck_rate:.3}"
    );

    let raw = vec![0x42u8; 128];
    let payload = Payload::bytes(&raw);
    let control = ctl();
    let (stego, _, stats) = embed_flac(
        &cover,
        &payload,
        cred(Some("secret-pw")),
        None,
        suite(),
        &[],
        profile(),
        SafetyPolicy::new(),
        Freshness::default(),
        &control,
    )
    .expect("embed must succeed on carrier with high frozen rate");

    assert!(stats.modified_slots > 0);
    let extracted = extract_flac(
        &stego,
        cred(Some("secret-pw")),
        None,
        profile(),
        &limits(),
        &control,
    )
    .expect("extract must succeed");
    assert_eq!(extracted.as_bytes(), &raw[..]);
}

#[test]
fn flac_unknown_critical_extension_fails_closed() {
    let cover = flac_carrier(600, 256);
    let payload = Payload::bytes(b"critical");
    let control = ctl();
    let ext = [Tlv {
        type_id: 0x81,
        value: vec![1, 2],
    }];
    // The writer refuses a critical TLV: V4 defines none, and every reader
    // folds an unknown one into `NoHiddenData`. The reader-side fail-closed
    // path is covered by the WAV forging test, which shares `read_extension`.
    let err = embed_flac(
        &cover,
        &payload,
        cred(None),
        None,
        suite(),
        &ext,
        profile(),
        SafetyPolicy::new(),
        Freshness::default(),
        &control,
    )
    .unwrap_err();
    assert!(matches!(err, StrHideError::General(_)), "{err:?}");
}

#[test]
fn flac_probe_capacity_is_reachable_by_embed() {
    let cover = flac_carrier(600, 256);
    let control = ctl();
    let probed = probe_flac(
        &cover,
        cred(None),
        None,
        &[],
        SafetyLevel::High,
        profile(),
        &control,
    )
    .expect("probe");
    assert!(probed.max_raw_payload_bytes > 0);

    // Fill exactly the advertised capacity: a probe that overshoots would make
    // this embed fail, and an undershoot would leave usable slots dark.
    let raw = vec![0x5Au8; probed.max_raw_payload_bytes];
    let payload = Payload::bytes(&raw);
    embed_flac(
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
    .expect("advertised FLAC capacity must be embeddable");
}

#[test]
fn flac_extension_does_not_shrink_reported_body_capacity() {
    let cover = flac_carrier(600, 256);
    let control = ctl();
    let ext = [Tlv {
        type_id: 0x01,
        value: vec![0xAB],
    }];
    let plain = probe_flac(
        &cover,
        cred(None),
        None,
        &[],
        SafetyLevel::High,
        profile(),
        &control,
    )
    .expect("probe without extension");
    let with_ext = probe_flac(
        &cover,
        cred(None),
        None,
        &ext,
        SafetyLevel::High,
        profile(),
        &control,
    )
    .expect("probe with extension");

    // FLAC stores the header and extension in subframe tails, a pool disjoint
    // from the body, so an extension must not shrink the advertised body.
    assert_eq!(
        with_ext.max_raw_payload_bytes, plain.max_raw_payload_bytes,
        "extension slots must not reduce the FLAC body budget"
    );
    assert_eq!(
        with_ext.recommended_max_bytes, plain.recommended_max_bytes,
        "extension slots must not reduce the FLAC safety tier"
    );

    // Pass path: the reported tier is still embeddable and extractable.
    let enforced = SafetyPolicy {
        level: SafetyLevel::High,
        enforcement: SafetyEnforcement::Enforced,
    };
    let raw = vec![0x5Au8; with_ext.recommended_max_bytes];
    let (stego, _, _) = embed_flac(
        &cover,
        &Payload::bytes(&raw),
        cred(None),
        None,
        suite(),
        &ext,
        profile(),
        enforced,
        Freshness::default(),
        &control,
    )
    .expect("advertised capacity with an extension must be embeddable");
    let out =
        extract_flac(&stego, cred(None), None, profile(), &limits(), &control).expect("extract");
    assert_eq!(out.as_bytes(), &raw[..]);

    // Reject path: one byte beyond the enforced tier is refused.
    let too_big = vec![0x5Au8; with_ext.recommended_max_bytes + 1];
    let err = embed_flac(
        &cover,
        &Payload::bytes(&too_big),
        cred(None),
        None,
        suite(),
        &ext,
        profile(),
        enforced,
        Freshness::default(),
        &control,
    )
    .expect_err("one byte beyond the enforced FLAC tier must fail");
    assert!(
        matches!(err, StrHideError::SafetyThreshold { .. }),
        "{err:?}"
    );
}

#[test]
fn flac_invariants_preserved_across_embed() {
    // S1 invariant: the *structural* pools -- body candidates and subframe
    // tails -- must be invariant before and after embedding, because both ends
    // derive the plan from them.
    //
    // `usable` is deliberately NOT asserted: it counts slots that are legal for
    // the current residual values, and the embedding rewrites those values, so
    // it may legitimately move. Nothing in the write or read path may use it
    // (see `flac_body_plan_ignores_the_movable_slot_count`).
    let cover = flac_carrier_custom(600, 256, 3, 4);
    let info = super::parse_stream_info(&cover).expect("info");
    let before = super::analyse(&cover, &info).expect("analyse before");

    let raw = vec![0x99u8; 256];
    let payload = Payload::bytes(&raw);
    let control = ctl();
    let (stego, _, _) = embed_flac(
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

    let after = super::analyse(&stego, &info).expect("analyse after");
    assert_eq!(
        before.slots, after.slots,
        "candidate slot count must be invariant across embed"
    );
    assert_eq!(
        before.tails, after.tails,
        "tail slot count must be invariant across embed"
    );
}

#[test]
fn flac_carrier_with_trailing_non_audio_bytes_roundtrips() {
    let mut cover = flac_carrier(600, 256);
    let trailer = b"\xf0\x00\xff\x0fG@8@HF<6##&b?)_d%:]dCd\x0eU\xff\xf0";
    cover.extend_from_slice(trailer);

    let info = super::parse_stream_info(&cover).expect("info");
    let analysis = super::analyse(&cover, &info).expect("analyse with trailer");
    assert!(analysis.slots > 0);

    let raw = b"test secret payload";
    let payload = Payload::bytes(raw);
    let control = ctl();
    let (stego, _, _) = embed_flac(
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
    .expect("embed with trailer");

    // Stego must retain the trailer untouched.
    assert!(stego.ends_with(trailer));
    assert_eq!(stego.len(), cover.len());

    let extracted = extract_flac(
        &stego,
        cred(Some("pw")),
        None,
        profile(),
        &limits(),
        &control,
    )
    .expect("extract with trailer");
    assert_eq!(extracted.data.as_ref(), raw);
}

/// Body slot offsets one plan construction addresses.
fn body_plan_offsets(
    cover: &[u8],
    info: super::StreamInfo,
    analysis: &super::FlacAnalysis,
    body_slots: usize,
) -> Vec<u64> {
    let mut buf = cover.to_vec();
    let carrier = super::FlacCarrier::new(
        &mut buf,
        info,
        analysis,
        body_slots,
        crate::stego::header::PNG_AUDIO_BASE_SLOTS,
        0x1111_2222_3333_4444,
        0x5555_6666_7777_8888,
        0x9999_aaaa_bbbb_cccc,
    )
    .expect("plan construction");
    carrier.slots[crate::stego::header::PNG_AUDIO_BASE_SLOTS..]
        .iter()
        .map(|slot| slot.bit_offset)
        .collect()
}

#[test]
fn flac_body_plan_ignores_the_movable_slot_count() {
    // `analysis.usable` is value-dependent by construction: legality reads the
    // residual values, and embedding rewrites them. The writer analyses the
    // cover while the reader analyses the stego, so any dependence on `usable`
    // makes the two thin over different denominators, select different
    // codewords, and land on an AEAD failure with the right password.
    // Selection must therefore be a function of the structural pool alone.
    let cover = flac_carrier_custom(600, 256, 3, 4);
    let info = super::parse_stream_info(&cover).expect("info");
    let analysis = super::analyse(&cover, &info).expect("analyse");
    let body_slots = 200;
    assert!(
        analysis.slots > body_slots,
        "carrier must have a body pool, got {}",
        analysis.slots
    );

    let expected = body_plan_offsets(&cover, info, &analysis, body_slots);
    assert_eq!(expected.len(), body_slots);

    for usable in [0usize, 1, analysis.usable / 3, analysis.usable / 2] {
        let perturbed = super::FlacAnalysis { usable, ..analysis };
        assert_eq!(
            body_plan_offsets(&cover, info, &perturbed, body_slots),
            expected,
            "the body plan moved with usable={usable}; slot selection is not structural"
        );
    }
}
