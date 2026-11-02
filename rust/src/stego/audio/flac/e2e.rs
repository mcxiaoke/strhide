//! End-to-end tests for the FLAC residual engine.
//!
//! The carrier is built here rather than borrowed from `temp/`: a hand-written
//! encoder that emits FIXED-order-2 frames gives the tests a file whose every
//! predictor tap is known, so an assertion can say *why* a sample moved instead
//! of only that it did. Real-file coverage lives in the ignored
//! `flac_corpus_validates` harness.

use crate::SafetyPolicy;
use crate::core::control::Control;
use crate::core::payload::Payload;
use crate::params::SafetyLevel;
use crate::stego::audio::{embed_flac, extract_flac, inspect_flac, probe_flac, verify_flac};
use crate::stego::envelope::Freshness;
use crate::stego::format::AudioFormatProfile;

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

#[test]
fn flac_roundtrip_preserves_length_and_payload() {
    let cover = flac_carrier(600, 256);
    let raw = vec![0xA7u8; 512];
    let payload = Payload::bytes(&raw);
    let control = ctl();
    let (stego, capacity, stats) = embed_flac(
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
    assert_eq!(stego.len(), cover.len(), "FLAC length must not change");
    assert!(stats.modified_slots > 0, "nothing was written");
    assert!(capacity.recommended_max_bytes > 0);

    let out = extract_flac(&stego, Some("pw"), None, profile(), &control).expect("extract");
    assert_eq!(out.as_bytes(), &raw[..]);

    let err = extract_flac(&stego, Some("wrong"), None, profile(), &control).unwrap_err();
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
        Some("pw"),
        None,
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
        Some("pw"),
        None,
        profile(),
        SafetyPolicy::new(),
        Freshness::default(),
        &control,
    )
    .expect("embed");

    let probed = probe_flac(&cover, SafetyLevel::High, &control).expect("probe");
    assert!(probed.recommended_max_bytes > 0);
    assert!(probed.max_raw_payload_bytes >= capacity.recommended_max_bytes);

    let header = inspect_flac(&stego, Some("pw"), None, profile(), &control).expect("inspect");
    assert!(header.has_hidden_data, "inspect must see the envelope");
    assert!(header.envelope_len.is_some());
    // A wrong password must not turn a read into an error; it just means the
    // payload cannot be recovered (asserted in the round-trip test).
    inspect_flac(&stego, Some("nope"), None, profile(), &control).expect("inspect never errors");

    let report = verify_flac(&stego, Some("pw"), None, profile(), &control).expect("verify");
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
        Some("pw"),
        None,
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
    let result = extract_flac(&stego, Some("pw"), None, profile(), &control);
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
        Some("pw"),
        None,
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
        Some("secret-pw"),
        None,
        profile(),
        SafetyPolicy::new(),
        Freshness::default(),
        &control,
    )
    .expect("embed must succeed on carrier with high frozen rate");

    assert!(stats.modified_slots > 0);
    let extracted = extract_flac(&stego, Some("secret-pw"), None, profile(), &control)
        .expect("extract must succeed");
    assert_eq!(extracted.as_bytes(), &raw[..]);
}

#[test]
fn flac_invariants_preserved_across_embed() {
    // S1 invariant: slot count, usable count, and tail count must be
    // 100% invariant before and after embedding.
    let cover = flac_carrier_custom(600, 256, 3, 4);
    let info = super::parse_stream_info(&cover).expect("info");
    let before = super::analyse(&cover, &info).expect("analyse before");

    let raw = vec![0x99u8; 256];
    let payload = Payload::bytes(&raw);
    let control = ctl();
    let (stego, _, _) = embed_flac(
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

    let after = super::analyse(&stego, &info).expect("analyse after");
    assert_eq!(
        before.slots, after.slots,
        "candidate slot count must be invariant across embed"
    );
    assert_eq!(
        before.usable, after.usable,
        "usable movable slot count must be invariant across embed"
    );
    assert_eq!(
        before.tails, after.tails,
        "tail slot count must be invariant across embed"
    );
}
