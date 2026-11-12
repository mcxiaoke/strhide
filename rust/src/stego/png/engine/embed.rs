//! Spatial domain steganographic embedding pipeline (PNG).

use crate::core::control::{Control, Stage};
use crate::core::crypto::{CipherSuiteId, Credential};
use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::stego::coding::{
    Move, StcTrellis, hamming_embed_ternary, spatial_move_safe, write_bit_ternary,
};
use crate::stego::envelope::{Freshness, build_plaintext, build_v4_aad_with, encrypt_v4_with_aad};
use crate::stego::format::{derive_l2_locator_keys, derive_l3_session_keys, derive_locator_master};
use crate::stego::header::{
    CONTENT_ENVELOPE_VERSION, FLAG_EXT_CRITICAL, FLAG_EXT_PRESENT, HEADER_LEN_MAX, MAX_EXT_BYTES,
    PNG_AUDIO_BASE_SLOTS, SpatialHeaderV4, Tlv, encode_extension_for_write, quantize_epsilon_k,
};
use crate::stego::params::{PngParams, SafetyPolicy};
use crate::stego::prng::permute_indices;
use crate::stego::traits::PngCostModel;
use crate::stego::{StegoCapacityInfo, StegoCodec};

use super::PNG_FORMAT_ID;
use super::capacity::build_png_capacity_with_pools;
use super::codec::{decode_png, encode_png, trace};
use super::layout::{
    ChannelMode, SlotPlan, check_pipeline_budget, embed_channel, exclusion_permille, png_pre_salt,
    recommended_bytes_for,
};

/// Embed a payload into a PNG carrier with content-adaptive spatial steganography.
///
/// The complete expert entry: format identity, cost model, tuning parameters
/// and salt/nonce source are all explicit. `secret` is the resolved credential
/// (explicit password, else the profile's private stego secret, else `None` for
/// the official public constant); `domain` isolates the HKDF derivation.
/// `Freshness::Seeded` makes the output byte-identical for the same carrier,
/// payload, secret and seed. `safety` is the capacity policy the embed is
/// checked against.
#[allow(clippy::too_many_arguments)]
pub fn embed_png<'a>(
    carrier_bytes: &[u8],
    payload: impl Into<Payload<'a>>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    safety: SafetyPolicy,
    freshness: Freshness,
    control: &Control<'_>,
) -> Result<Vec<u8>, StrHideError> {
    embed_png_with_stats(
        carrier_bytes,
        payload,
        cred,
        domain,
        suite_id,
        extensions,
        spatial,
        cost_model,
        params,
        safety,
        freshness,
        control,
    )
    .map(|(bytes, _, _)| bytes)
}

/// Embed a payload into a PNG carrier and return modified bytes, embed statistics, and capacity info.
#[allow(clippy::too_many_arguments)]
pub(crate) fn embed_png_with_stats<'a>(
    carrier_bytes: &[u8],
    payload: impl Into<Payload<'a>>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    safety: SafetyPolicy,
    freshness: Freshness,
    control: &Control<'_>,
) -> Result<(Vec<u8>, crate::stego::EmbedStats, StegoCapacityInfo), StrHideError> {
    let payload = payload.into();
    params.validate()?;
    let suite = CipherSuiteId::from_u16(suite_id).ok_or_else(|| {
        StrHideError::UnsupportedVersion(format!("Unknown content cipher suite id {suite_id}"))
    })?;
    let extension = encode_extension_for_write(extensions)?;
    if extension.len() > MAX_EXT_BYTES {
        return Err(StrHideError::General(format!(
            "Extension area is {} bytes, the maximum is {MAX_EXT_BYTES}",
            extension.len()
        )));
    }
    control.stage(Stage::Decode);
    let mut image = decode_png(carrier_bytes)?;
    // Checkpoint after the decode: on a 50 MP carrier this alone is seconds.
    control.check()?;
    control.stage(Stage::CostMap);
    let w = image.width as usize;
    let h = image.height as usize;
    let total_pixels = w * h;

    log::info!(
        target: "stego::png",
        "embed_png: image {}x{} ({} px), payload {} B",
        w, h, total_pixels, payload.as_bytes().len()
    );

    // Frame the payload and derive the per-carrier keys. The ciphertext itself
    // is produced further down: the finished base header plus extension area is
    // its associated data, so it cannot exist until codec/h/u are settled.
    let plaintext = build_plaintext(&payload)?;
    let cipher = spatial.cipher;
    let pre_salt = png_pre_salt(&image, spatial);
    let master = derive_locator_master(cred, domain, cipher, &pre_salt)?;
    let locator = derive_l2_locator_keys(&master, cipher, b"strhide-v4-hdr-magic", domain)?;
    // Seeded runs bind salt/nonce to the cover, payload, format, version and
    // extension area, so a replay on different inputs can never reuse a
    // (key, nonce) pair.
    let fresh_binding =
        Freshness::seeded_binding(carrier_bytes, payload.as_bytes(), PNG_FORMAT_ID, &extension);
    let salt = freshness.salt(0, &fresh_binding);
    let nonce = freshness.nonce(0, &fresh_binding);
    let session = derive_l3_session_keys(cipher, suite, &master, &salt, domain)?;
    let ext_len = extension.len();
    let ciphertext_len = plaintext.len() + suite.tag_len();

    // Quantise the hyperparameters to their wire-exact forms *before* any
    // use, and run the whole embed on them: the feature word can only carry
    // `epsilon` as a power of two and `sigma` at `f32` precision, so the
    // extractor can only ever reproduce these forms. The prober quantises
    // the same way, so advertised capacity and embedding pool agree.
    let params = params.wire_quantized();
    let eps_k = quantize_epsilon_k(params.epsilon);

    // Compute distortion cost map
    let costs = cost_model.compute_cost(&image.pixels, w, h, image.channels, &params);
    // Checkpoint after the cost map: the second big fixed cost of an embed.
    control.check()?;
    control.stage(Stage::Solve);

    let channel_offset = embed_channel(&image);

    let plan = SlotPlan::build(
        &image,
        &costs,
        &locator.locate_seed,
        ext_len,
        exclusion_permille(params.exclusion_percentile),
    )?;
    let (capacity_info, pool_green, pool_rgb) =
        build_png_capacity_with_pools(&image, &plan, &params, cost_model.id(), safety.level)?;
    if !plan.header_fits() {
        return Err(StrHideError::General(format!(
            "Carrier capacity insufficient: available {} slots, minimum header requires {} slots",
            plan.permuted.len(),
            plan.header_slots
        )));
    }
    let header_slots = plan.base_header_slots();
    let extension_slots = plan.extension_slots();

    let ciphertext_bits = ciphertext_len * 8;

    // Single-channel body pool first. Small payloads therefore keep the exact
    // layout (and byte-for-byte output) they had before multi-channel existed.
    // Safety enforcement policy check
    if safety.is_enforced() {
        let recommended_max_bytes = recommended_bytes_for(total_pixels, pool_green, safety.level);

        if payload.len() > recommended_max_bytes {
            return Err(StrHideError::SafetyThreshold {
                tier: safety.level,
                required_bytes: payload.len(),
                available_bytes: recommended_max_bytes,
            });
        }
    }

    // Resolve matrix-coding strategy and channel mode together.
    //
    // `Auto` (and STC with `stc_u = 0`) picks the group size from a slot pool,
    // but the pool that actually carries the body depends on that group size:
    // once the payload no longer fits one channel, the body moves to `Rgb`.
    // Resolving `u` against `pool_green` and then switching to `Rgb` kept the
    // degraded `u = 1` chosen for a pool that is never used, which is plain
    // parity coding with no cost-model optimisation. Re-resolve against the
    // pool the body will live in.
    let (resolved_codec, resolved_u, mode, pool_max) = 'resolve: {
        if matches!(params.codec, StegoCodec::Auto)
            || (params.codec == StegoCodec::Stc && params.stc_u == 0)
        {
            let (codec, u) = crate::stego::coding::auto_select_codec(pool_green, ciphertext_bits);
            let needed =
                crate::stego::coding::slots_for_codec(ciphertext_bits, codec, params.stc_h, u)?;
            if needed <= pool_green {
                break 'resolve (codec, u, ChannelMode::Green, pool_green);
            }
            let Some(pool_rgb) = pool_rgb else {
                return Err(StrHideError::PayloadTooLarge(format!(
                    "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: spatial-{})",
                    needed,
                    codec.describe(params.stc_h, u),
                    pool_green,
                    cost_model.id(),
                )));
            };
            let (codec, u) = crate::stego::coding::auto_select_codec(pool_rgb, ciphertext_bits);
            let rgb_needed =
                crate::stego::coding::slots_for_codec(ciphertext_bits, codec, params.stc_h, u)?;
            if rgb_needed <= pool_rgb {
                break 'resolve (codec, u, ChannelMode::Rgb, pool_rgb);
            }
            return Err(StrHideError::PayloadTooLarge(format!(
                "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: spatial-{} {})",
                rgb_needed,
                codec.describe(params.stc_h, u),
                pool_rgb,
                cost_model.id(),
                ChannelMode::Rgb.name(),
            )));
        }

        let (codec, u) = match params.codec {
            StegoCodec::Stc => (StegoCodec::Stc, params.stc_u),
            StegoCodec::Hamming => (StegoCodec::Hamming, 0),
            StegoCodec::Auto => unreachable!("handled above"),
        };
        let needed =
            crate::stego::coding::slots_for_codec(ciphertext_bits, codec, params.stc_h, u)?;
        if needed <= pool_green {
            break 'resolve (codec, u, ChannelMode::Green, pool_green);
        }
        if let Some(pool_rgb) = pool_rgb {
            if needed <= pool_rgb {
                break 'resolve (codec, u, ChannelMode::Rgb, pool_rgb);
            }
            return Err(StrHideError::PayloadTooLarge(format!(
                "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: spatial-{} {})",
                needed,
                codec.describe(params.stc_h, u),
                pool_rgb,
                cost_model.id(),
                ChannelMode::Rgb.name(),
            )));
        }
        return Err(StrHideError::PayloadTooLarge(format!(
            "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: spatial-{})",
            needed,
            codec.describe(params.stc_h, u),
            pool_green,
            cost_model.id(),
        )));
    };

    trace(format_args!(
        "plan pool_green={pool_green} pool_max={pool_max} mode={mode:?} codec={resolved_codec:?} u={resolved_u}"
    ));

    // Recompute the slot count from the resolved codec for the solve phase.
    let needed_body_slots = crate::stego::coding::slots_for_codec(
        ciphertext_bits,
        resolved_codec,
        params.stc_h,
        resolved_u,
    )?;

    // Refuse before the solve allocates anything: the trellis keeps one word per
    // state per element, so a large payload on a large carrier is a multi-GiB
    // allocation, and with `panic = "abort"` an OOM is a process kill rather
    // than an error the user can act on.
    check_pipeline_budget(
        total_pixels,
        needed_body_slots,
        match resolved_codec {
            StegoCodec::Hamming => None,
            _ => Some(params.stc_h),
        },
    )?;

    // V4 base header: `body_len` is the AEAD ciphertext length including the
    // tag, with no per-format padding adjustment.
    if ciphertext_len > HEADER_LEN_MAX as usize {
        return Err(StrHideError::General(format!(
            "Envelope of {ciphertext_len} bytes exceeds the {HEADER_LEN_MAX}-byte header length field"
        )));
    }
    let algorithm_id = crate::stego::png::registry::spatial_wire_id(cost_model.id()).ok_or_else(
        || {
            StrHideError::General(format!(
                "PNG cost model '{}' has no wire id; a carrier written with it could not be extracted",
                cost_model.id()
            ))
        },
    )?;
    let sigma = if cost_model.id() == "mipod" {
        params
            .algorithm_options
            .get("alpha")
            .copied()
            .unwrap_or(0.20)
            .clamp(0.01, 0.90) as f32
    } else {
        params
            .algorithm_options
            .get("sigma")
            .copied()
            .unwrap_or(1.0) as f32
    };
    let flags = {
        let mut flags = 0u8;
        if !extension.is_empty() {
            flags |= FLAG_EXT_PRESENT;
        }
        if extensions.iter().any(Tlv::is_critical) {
            flags |= FLAG_EXT_CRITICAL;
        }
        flags
    };
    let (codec_id, wire_h, wire_u) = match resolved_codec {
        StegoCodec::Hamming => (0u8, 0u8, 0u8),
        StegoCodec::Stc | StegoCodec::Auto => (1u8, params.stc_h, resolved_u),
    };
    let header = SpatialHeaderV4 {
        salt,
        nonce,
        body_len: ciphertext_len as u32,
        version: CONTENT_ENVELOPE_VERSION,
        flags,
        format_id: PNG_FORMAT_ID,
        algorithm_id,
        suite_id: suite.as_u16(),
        codec_id,
        stc_h: wire_h,
        stc_u: wire_u,
        // Self-describing: the extractor rebuilds the body pool from this and
        // nothing else, so a write here would desynchronise the two ends.
        channel_mode: mode as u8,
        class_rule: 1, // Safe [1, 6] non-boundary
        p1_window: params.p1_window as u16,
        p2_window: params.p2_window as u16,
        neg_log2_epsilon: eps_k,
        exclusion_permille: exclusion_permille(params.exclusion_percentile),
        sigma,
        kernel_id: 0, // the built-in KB kernel; custom kernels need matching configs
        ext_len: ext_len as u16,
    };
    let header_bytes = header.encode();
    let aad = build_v4_aad_with(cipher.aad_prefix, PNG_FORMAT_ID, &header_bytes, &extension);

    // Encrypt last: the whole base header plus extension area is the AEAD's
    // associated data, so a tampered field fails the tag instead of steering
    // the decoder somewhere else.
    let ciphertext_body = encrypt_v4_with_aad(suite, &session.enc_key, &nonce, &aad, &plaintext)?;

    // Phase 2: Keyed permutation of body slots.
    let perm_seed = session.perm_seed;
    let stc_seed = session.stc_seed;

    let mut body_slots = plan.body_slots_upto(&image, 1, mode, needed_body_slots);
    debug_assert_eq!(body_slots.len(), needed_body_slots, "pool counted above");
    permute_indices(&mut body_slots, &perm_seed);

    // Asymmetric per-direction costs. Embed-side only: ranking never sees them,
    // so the extractor does not have to reproduce them.
    //
    // The model prices only the requested slots, so the working set stays
    // payload-sized instead of materializing full-plane maps per channel.
    // Header slots are already pixel indices on the header channel; body
    // slots are byte offsets and become pixel indices per channel.
    let mut header_rp = vec![0.0f64; plan.header_slots];
    let mut header_rm = vec![0.0f64; plan.header_slots];
    let mut body_rp = vec![0.0f64; needed_body_slots];
    let mut body_rm = vec![0.0f64; needed_body_slots];
    let header_px: Vec<usize> = header_slots
        .iter()
        .chain(extension_slots.iter())
        .copied()
        .collect();
    for &channel in mode.channels(image.channels) {
        // Body pixel indices for this channel, in body-slot order (the
        // per-channel subset stays at its body-slot position).
        let body_px: Vec<usize> = body_slots
            .iter()
            .filter(|&&slot| slot % image.channels == channel)
            .map(|&slot| slot / image.channels)
            .collect();
        let (header_plus, header_minus) = if channel == channel_offset {
            cost_model.direction_costs(
                &costs,
                &image.pixels,
                w,
                h,
                image.channels,
                channel,
                &header_px,
            )
        } else {
            (Vec::new(), Vec::new())
        };
        let (body_plus, body_minus) = cost_model.direction_costs(
            &costs,
            &image.pixels,
            w,
            h,
            image.channels,
            channel,
            &body_px,
        );
        if channel == channel_offset {
            if header_plus.len() != header_px.len() || header_minus.len() != header_px.len() {
                return Err(StrHideError::General(
                    "Direction cost vector dimension mismatch".into(),
                ));
            }
            for (i, (&rp, &rm)) in header_plus.iter().zip(header_minus.iter()).enumerate() {
                header_rp[i] = rp;
                header_rm[i] = rm;
            }
        }
        if body_plus.len() != body_px.len() || body_minus.len() != body_px.len() {
            return Err(StrHideError::General(
                "Direction cost vector dimension mismatch".into(),
            ));
        }
        let mut k = 0usize;
        for (i, &slot) in body_slots.iter().enumerate() {
            if slot % image.channels == channel {
                body_rp[i] = body_plus[k];
                body_rm[i] = body_minus[k];
                k += 1;
            }
        }
    }

    let mut modified_slots = 0;

    // Embed Phase 1: 64-byte base header (512 slots), then the optional
    // extension area (8 slots per byte) from the same keyed permutation.
    for (byte_i, &b) in header_bytes.iter().enumerate() {
        for bit_i in 0..8 {
            let target_bit = (b >> (7 - bit_i)) & 1;
            let bit_index = byte_i * 8 + bit_i;
            let byte_idx = header_slots[bit_index] * image.channels + channel_offset;
            let prev = image.pixels[byte_idx];
            write_bit_ternary(
                &mut image.pixels[byte_idx],
                target_bit,
                header_rp[bit_index],
                header_rm[bit_index],
            );
            if image.pixels[byte_idx] != prev {
                modified_slots += 1;
            }
        }
    }
    for (byte_i, &b) in extension.iter().enumerate() {
        for bit_i in 0..8 {
            let target_bit = (b >> (7 - bit_i)) & 1;
            let bit_index = PNG_AUDIO_BASE_SLOTS + byte_i * 8 + bit_i;
            let byte_idx = extension_slots[byte_i * 8 + bit_i] * image.channels + channel_offset;
            let prev = image.pixels[byte_idx];
            write_bit_ternary(
                &mut image.pixels[byte_idx],
                target_bit,
                header_rp[bit_index],
                header_rm[bit_index],
            );
            if image.pixels[byte_idx] != prev {
                modified_slots += 1;
            }
        }
    }

    // Embed Phase 2: Ciphertext body. Slots are byte offsets, so the write is
    // a direct `pixels[slot]` -- no channel arithmetic left to get wrong.
    let mut slot_vals: Vec<u8> = body_slots.iter().map(|&slot| image.pixels[slot]).collect();
    let moves: Vec<Move> = slot_vals.iter().map(|&v| spatial_move_safe(v)).collect();
    match resolved_codec {
        StegoCodec::Hamming => {
            hamming_embed_ternary(
                &mut slot_vals,
                &moves,
                &body_rp,
                &body_rm,
                &ciphertext_body,
                crate::stego::coding::DEFAULT_HAMMING_K,
            )?;
        }
        StegoCodec::Stc | StegoCodec::Auto => {
            let trellis = StcTrellis::from_seed_grouped(stc_seed, params.stc_h, resolved_u)?;
            trellis.embed(&mut slot_vals, &moves, &body_rp, &body_rm, &ciphertext_body)?;
        }
    }

    for (i, &slot) in body_slots.iter().enumerate() {
        if image.pixels[slot] != slot_vals[i] {
            modified_slots += 1;
        }
        image.pixels[slot] = slot_vals[i];
    }

    control.stage(Stage::Encode);
    let encoded = encode_png(&image)?;
    let stats = crate::stego::EmbedStats {
        modified_slots,
        total_candidate_slots: total_pixels,
    };
    Ok((encoded, stats, capacity_info))
}
