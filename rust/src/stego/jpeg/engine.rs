//! JPEG DCT domain steganographic embedding and extraction engine.
//!
//! Uses dct-io to read and write quantized DCT coefficients directly in the baseline
//! JPEG bitstream without decompressing to pixels, ensuring zero generation loss and
//! preserving EXIF, JFIF, and Huffman tables intact. Implements UERD cost-driven
//! coefficient selection and DCT matching with strict bounds to prevent run-length changes.
//!
//! # Matching, and why the matrix code is effectively binary here
//!
//! A coefficient may only move to the other side of its `(2k, 2k+1)` pair:
//! `[`dct_move`]` allows exactly one direction per coefficient, because UERD's
//! cost map is computed from `|c| & !1` on both ends and a wider move would
//! change that mask and desynchronise the slot ranking. That is the same
//! "ternary matching with one legal direction" situation as the spatial
//! engine's class floor/ceiling, so both codecs plug in unchanged: Hamming
//! forces one coefficient per block to cross its pair, STC picks the cheapest
//! coefficients globally.

use crate::errors::StrHideError;
use crate::stego::StegoCapacityInfo;
use crate::stego::coding::{Move, dct_move, hamming_embed_ternary, slots_for_codec};
use crate::stego::envelope::{pack_envelope, unpack_envelope};
use crate::stego::header::{
    HEADER_LEN_MAX, codec_from_header_id, decode_header_word, encode_header_word,
};
use crate::stego::params::{JpegParams, StegoCodec};
use crate::stego::prng::permute_indices;
use crate::stego::traits::JpegCostModel;

/// Map a dct_io error to StrHideError.
fn map_dct_error(e: dct_io::DctError) -> StrHideError {
    let err_str = e.to_string();
    if err_str.contains("SOF2") || err_str.to_lowercase().contains("progressive") {
        return StrHideError::UnsupportedFormat(
            "Progressive JPEG (SOF2) is not supported for content-adaptive DCT steganography; please convert to baseline JPEG or use 'strhide write' for structural hiding".into(),
        );
    }
    match e {
        dct_io::DctError::Unsupported(msg) => {
            if msg.contains("SOF2") || msg.to_lowercase().contains("progressive") {
                StrHideError::UnsupportedFormat(
                    "Progressive JPEG (SOF2) is not supported for content-adaptive DCT steganography; please convert to baseline JPEG or use 'strhide write' for structural hiding".into(),
                )
            } else {
                StrHideError::UnsupportedFormat(format!("Unsupported JPEG variant: {msg}"))
            }
        }
        _ => StrHideError::CorruptedData(format!("Corrupt JPEG coefficient stream: {e}")),
    }
}

/// Candidate layout shared by embed, extract and capacity probing.
///
/// Both ends rebuild it from the carrier alone, so it must be a pure function of
/// the coefficient values, the parameters and (for the header subset) the
/// password -- nothing that embedding changes.
struct SlotPlan {
    total_coeffs: usize,
    /// Header slots: a keyed random 256-slot subset of the candidates.
    header_slots: Vec<(usize, usize)>,
    /// Body candidates: the remaining slots, cheapest first. The body takes a
    /// prefix of this list so every change lands on the cheapest coefficients.
    body_candidates: Vec<(usize, usize)>,
}

/// Build the slot plan for a carrier.
fn plan_slots(
    carrier_bytes: &[u8],
    coeffs: &dct_io::JpegCoefficients,
    cost_model: &dyn JpegCostModel,
    params: &JpegParams,
    password: Option<&str>,
) -> Result<(SlotPlan, Vec<f64>), (StrHideError, bool)> {
    // The bool in the error tuple marks "no usable layout" (reported as
    // `NoHiddenData` on extract, as a hard error on embed).
    let geometry = crate::stego::jpeg::geometry::geometry_for_carrier(
        carrier_bytes,
        0,
        coeffs.components[0].blocks.len(),
    )
    .map_err(|e| (map_dct_error(e), false))?;
    let costs = cost_model.compute_cost(coeffs, &geometry, params);
    let total_coeffs = coeffs.components[0].blocks.len() * 64;
    if costs.len() != total_coeffs {
        return Err((
            StrHideError::General("JPEG cost dimension mismatch".into()),
            false,
        ));
    }

    let min_abs = params.min_abs_coeff.max(2);
    let comp = &coeffs.components[0];
    let mut eligible_slots: Vec<(usize, usize)> = Vec::new();
    for (bi, block) in comp.blocks.iter().enumerate() {
        for k in 1..64 {
            let val = block[k];
            if val.abs() >= min_abs && costs[bi * 64 + k] < params.wet_cost {
                eligible_slots.push((bi, k));
            }
        }
    }

    // Lowest cost (highest texture energy) first.
    eligible_slots.sort_by(|&(bi1, k1), &(bi2, k2)| {
        costs[bi1 * 64 + k1]
            .partial_cmp(&costs[bi2 * 64 + k2])
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Exclude the lowest-energy/highest-cost fraction.
    let allowed_count = ((eligible_slots.len() as f64)
        * (1.0 - params.block_exclusion_percentile.clamp(0.0, 0.8)))
        as usize;
    let candidate_slots = &eligible_slots[..allowed_count];

    if candidate_slots.len() < 256 {
        return Err((
            StrHideError::General(format!(
                "Carrier capacity insufficient: available {} slots, minimum header requires 256 slots",
                candidate_slots.len()
            )),
            true,
        ));
    }

    // Header slots: keyed permutation of the whole candidate set, so their
    // position is not a public "top-256 cheapest" fingerprint.
    let header_seed = crate::stego::envelope::derive_header_perm_seed(password);
    let mut permuted_candidates = candidate_slots.to_vec();
    permute_indices(&mut permuted_candidates, &header_seed);
    let header_slots = permuted_candidates[..256].to_vec();

    let is_header = {
        let mut v = vec![false; total_coeffs];
        for &(bi, k) in &header_slots {
            v[bi * 64 + k] = true;
        }
        v
    };
    let body_candidates: Vec<(usize, usize)> = candidate_slots
        .iter()
        .copied()
        .filter(|&(bi, k)| !is_header[bi * 64 + k])
        .collect();

    Ok((
        SlotPlan {
            total_coeffs,
            header_slots,
            body_candidates,
        },
        costs,
    ))
}

/// Embed secret payload into JPEG carrier using content-adaptive DCT steganography.
pub fn embed_jpeg(
    carrier_bytes: &[u8],
    payload: &[u8],
    password: Option<&str>,
    cost_model: &dyn JpegCostModel,
    params: &JpegParams,
) -> Result<Vec<u8>, StrHideError> {
    let mut coeffs = dct_io::read_coefficients(carrier_bytes).map_err(map_dct_error)?;
    if coeffs.components.is_empty() {
        return Err(StrHideError::UnsupportedFormat(
            "JPEG has no image components".into(),
        ));
    }

    let (plan, costs) =
        plan_slots(carrier_bytes, &coeffs, cost_model, params, password).map_err(|(e, _)| e)?;

    // Pack payload into micro-envelope.
    let envelope = pack_envelope(payload, password)?;
    let total_len = envelope.len() as u32;
    if total_len > HEADER_LEN_MAX {
        return Err(StrHideError::General(format!(
            "Envelope of {total_len} bytes exceeds the {HEADER_LEN_MAX}-byte header length field"
        )));
    }

    // Header: 32 bytes = 256 bits ([16B Salt][12B Nonce][4B flags+len]).
    let header_word = encode_header_word(total_len, params.codec, params.stc_h, params.stc_u);
    let mut header_bytes = [0u8; 32];
    header_bytes[..28].copy_from_slice(&envelope[..28]);
    header_bytes[28..].copy_from_slice(&header_word.to_be_bytes());

    let ciphertext_body = &envelope[28..];
    let ciphertext_bits = ciphertext_body.len() * 8;
    let needed_body_slots =
        slots_for_codec(ciphertext_bits, params.codec, params.stc_h, params.stc_u)?;
    if needed_body_slots > plan.body_candidates.len() {
        return Err(StrHideError::General(format!(
            "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: jpeg-{})",
            needed_body_slots,
            params.codec.describe(params.stc_h, params.stc_u),
            plan.body_candidates.len(),
            cost_model.id(),
        )));
    }

    // Body slot order: a keyed permutation of the cheapest `needed` slots.
    let salt = &envelope[..16];
    let (_, perm_seed) = crate::stego::envelope::derive_keys(
        password.unwrap_or(crate::stego::envelope::PUBLIC_DEFAULT_SECRET),
        salt,
    );
    let mut body_slots = plan.body_candidates[..needed_body_slots].to_vec();
    permute_indices(&mut body_slots, &perm_seed);

    // Phase 1: header, direct LSB matching (no coding across those 256 bits).
    for (byte_i, &b) in header_bytes.iter().enumerate() {
        for bit_i in 0..8 {
            let target_bit = (b >> (7 - bit_i)) & 1;
            let (bi, k) = plan.header_slots[byte_i * 8 + bit_i];
            embed_dct_lsb(&mut coeffs.components[0].blocks[bi][k], target_bit);
        }
    }

    // Phase 2: body through the matrix code.
    //
    // The trellis works on `u8` values, but a coefficient is an `i16` whose
    // magnitude can exceed 255. It does not need the magnitude: only the parity
    // decides which bit is written, and only "flip or keep" has to be
    // expressible. Both codecs are therefore handed a **parity carrier** in
    // `{2, 3}`: LSB 0 is 2, LSB 1 is 3, `+1` always flips the parity, and
    // neither value can overflow. The real move direction is chosen per
    // coefficient on write-back by [`dct_move`], which is the only thing the
    // UERD cost map depends on.
    let count = body_slots.len();
    let mut slot_vals: Vec<u8> = body_slots
        .iter()
        .map(|&(bi, k)| 2 | ((coeffs.components[0].blocks[bi][k] as i32) & 1) as u8)
        .collect();
    let moves = vec![Move::PlusOnly; count];
    let rp: Vec<f64> = body_slots
        .iter()
        .map(|&(bi, k)| costs[bi * 64 + k])
        .collect();
    let rm = vec![f64::INFINITY; count];

    match params.codec {
        StegoCodec::Hamming => {
            hamming_embed_ternary(
                &mut slot_vals,
                &moves,
                &rp,
                &rm,
                ciphertext_body,
                crate::stego::coding::DEFAULT_HAMMING_K,
            )?;
        }
        StegoCodec::Stc => {
            let stc_seed = crate::stego::envelope::derive_stc_seed(&perm_seed, salt);
            let trellis = crate::stego::coding::StcTrellis::from_seed_grouped(
                stc_seed,
                params.stc_h,
                params.stc_u,
            )?;
            trellis.embed(&mut slot_vals, &moves, &rp, &rm, ciphertext_body)?;
        }
    }

    // Write the codec's decisions back into the coefficients.
    for (i, &(bi, k)) in body_slots.iter().enumerate() {
        let coeff = &mut coeffs.components[0].blocks[bi][k];
        if ((*coeff as i32) & 1) as u8 != (slot_vals[i] & 1) {
            match dct_move(*coeff) {
                Move::PlusOnly => *coeff += 1,
                Move::MinusOnly => *coeff -= 1,
                // Unreachable: every eligible slot has |c| >= 2, so exactly one
                // direction keeps the bucket.
                Move::Both => {}
            }
        }
    }

    // Re-encode Huffman bitstream without generation loss.
    dct_io::write_coefficients(carrier_bytes, &coeffs).map_err(map_dct_error)
}

/// Write `target_bit` into an eligible AC coefficient's LSB by moving it to the
/// other side of its `(2k, 2k+1)` pair.
///
/// Strict protection: never allows |coeff| to drop below 2 (prevents run-length
/// changes). The move (not a raw bit replacement) keeps `|coeff| & !1`
/// invariant, which is what makes the UERD cost map reproducible at extraction
/// time. This is exactly what [`dct_move`] allows for the coefficient's sign and
/// parity, so the header and the coded body speak the same language.
fn embed_dct_lsb(coeff: &mut i16, target_bit: u8) {
    if (((*coeff as i32) & 1) as u8) == target_bit {
        return;
    }
    match dct_move(*coeff) {
        Move::PlusOnly => *coeff += 1,
        Move::MinusOnly => *coeff -= 1,
        Move::Both => {}
    }
}

/// Extract secret payload from JPEG carrier using content-adaptive DCT steganography.
pub fn extract_jpeg(
    carrier_bytes: &[u8],
    password: Option<&str>,
    cost_model: &dyn JpegCostModel,
    params: &JpegParams,
) -> Result<Vec<u8>, StrHideError> {
    let coeffs = dct_io::read_coefficients(carrier_bytes).map_err(map_dct_error)?;
    if coeffs.components.is_empty() {
        return Err(StrHideError::NoHiddenData("JPEG has no components".into()));
    }

    let no_hidden = || StrHideError::NoHiddenData("No valid payload found".into());

    let (plan, _costs) = plan_slots(carrier_bytes, &coeffs, cost_model, params, password).map_err(
        |(e, is_layout)| {
            if is_layout { no_hidden() } else { e }
        },
    )?;

    // Phase 1: 32-byte header.
    let mut header_bytes = [0u8; 32];
    for (byte_i, slot_byte) in header_bytes.iter_mut().enumerate() {
        let mut b = 0u8;
        for bit_i in 0..8 {
            let (bi, k) = plan.header_slots[byte_i * 8 + bit_i];
            let lsb = ((coeffs.components[0].blocks[bi][k] as i32) & 1) as u8;
            b = (b << 1) | lsb;
        }
        *slot_byte = b;
    }

    let salt = &header_bytes[..16];
    let (total_len, codec, stc_h, stc_u) = {
        let word = u32::from_be_bytes([
            header_bytes[28],
            header_bytes[29],
            header_bytes[30],
            header_bytes[31],
        ]);
        let (len, codec_id, stc_h) = decode_header_word(word);
        // Every decode failure below must look identical to "no envelope
        // here": a wrong secret lands the header on the wrong slots, and a
        // distinct message would tell an attacker that an envelope exists but
        // the layout is wrong -- an oracle the AEAD path deliberately denies.
        let (codec, stc_u) = codec_from_header_id(codec_id).map_err(|_| no_hidden())?;
        if codec == StegoCodec::Stc {
            crate::stego::coding::validate_stc_h(stc_h).map_err(|_| no_hidden())?;
            crate::stego::coding::validate_stc_u(stc_u).map_err(|_| no_hidden())?;
        }
        (len as usize, codec, stc_h, stc_u)
    };

    if !(49..=HEADER_LEN_MAX as usize).contains(&total_len) {
        return Err(no_hidden());
    }

    let ciphertext_len = total_len - 28;
    let ciphertext_bits = ciphertext_len * 8;
    let needed_body_slots = slots_for_codec(ciphertext_bits, codec, stc_h, stc_u)?;
    if needed_body_slots > plan.body_candidates.len() {
        return Err(no_hidden());
    }

    // Phase 2: keyed permutation of body slots using the salt-derived seed.
    let (_, perm_seed) = crate::stego::envelope::derive_keys(
        password.unwrap_or(crate::stego::envelope::PUBLIC_DEFAULT_SECRET),
        salt,
    );
    let mut body_slots = plan.body_candidates[..needed_body_slots].to_vec();
    permute_indices(&mut body_slots, &perm_seed);

    let slot_vals: Vec<u8> = body_slots
        .iter()
        .map(|&(bi, k)| ((coeffs.components[0].blocks[bi][k] as i32) & 1) as u8)
        .collect();

    let ciphertext_body = match codec {
        StegoCodec::Hamming => crate::stego::coding::hamming_extract_bytes(
            &slot_vals,
            ciphertext_len,
            crate::stego::coding::DEFAULT_HAMMING_K,
        )?,
        StegoCodec::Stc => {
            let stc_seed = crate::stego::envelope::derive_stc_seed(&perm_seed, salt);
            let trellis =
                crate::stego::coding::StcTrellis::from_seed_grouped(stc_seed, stc_h, stc_u)?;
            trellis.extract(&slot_vals, ciphertext_bits)
        }
    };

    let mut full_envelope = Vec::with_capacity(total_len);
    full_envelope.extend_from_slice(&header_bytes[..28]); // Salt + Nonce
    full_envelope.extend_from_slice(&ciphertext_body);

    unpack_envelope(&full_envelope, password)
}

/// Probe capacity of JPEG carrier for DCT content-adaptive steganography.
pub fn probe_jpeg_capacity(
    carrier_bytes: &[u8],
    cost_model: &dyn JpegCostModel,
    params: &JpegParams,
) -> Result<StegoCapacityInfo, StrHideError> {
    let coeffs = dct_io::read_coefficients(carrier_bytes).map_err(map_dct_error)?;
    if coeffs.components.is_empty() {
        return Err(StrHideError::UnsupportedFormat(
            "JPEG has no image components".into(),
        ));
    }

    // The header subset is keyed, but the *count* is not: capacity is the same
    // for every password. Pass `None` so the probe never needs one.
    let (plan, _costs) =
        plan_slots(carrier_bytes, &coeffs, cost_model, params, None).map_err(|(e, _)| e)?;

    let available_body_slots = plan.body_candidates.len();
    // The two codecs buy different payload per slot; the difference is real,
    // so the number follows `params.codec`.
    let max_ciphertext_bytes = match params.codec {
        StegoCodec::Hamming => crate::stego::coding::max_payload_bytes(
            available_body_slots,
            crate::stego::coding::DEFAULT_HAMMING_K,
        ),
        StegoCodec::Stc => {
            let trellis =
                crate::stego::coding::StcTrellis::from_seed_grouped(0, params.stc_h, params.stc_u)?;
            trellis.message_bits(available_body_slots) / 8
        }
    };
    // Only the body-borne overhead comes off here: salt/nonce already paid for
    // by the 256 header slots.
    let max_raw_payload_bytes =
        max_ciphertext_bytes.saturating_sub(crate::stego::envelope::BODY_OVERHEAD);
    let recommended_max_bytes = max_raw_payload_bytes / 2;

    Ok(StegoCapacityInfo {
        format: "JPEG".into(),
        algorithm: cost_model.id().into(),
        total_elements: plan.total_coeffs,
        available_slots: available_body_slots,
        max_raw_payload_bytes,
        recommended_max_bytes,
        estimated_change_rate: match params.codec {
            StegoCodec::Hamming => {
                crate::stego::coding::expected_change_rate(crate::stego::coding::DEFAULT_HAMMING_K)
            }
            StegoCodec::Stc => crate::stego::coding::expected_stc_change_rate(params.stc_u),
        },
    })
}
