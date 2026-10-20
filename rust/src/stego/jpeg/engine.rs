//! JPEG DCT domain steganographic embedding and extraction engine.
//!
//! Uses dct-io to read and write quantized DCT coefficients directly in the baseline
//! JPEG bitstream without decompressing to pixels, ensuring zero generation loss and
//! preserving EXIF, JFIF, and Huffman tables intact. Implements UERD cost-driven
//! coefficient selection and DCT matching with strict bounds to prevent run-length changes.

use crate::errors::StrHideError;
use crate::stego::StegoCapacityInfo;
use crate::stego::envelope::{pack_envelope, unpack_envelope};
use crate::stego::params::JpegParams;
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

    // Compute distortion cost map
    let costs = cost_model.compute_cost(&coeffs, params);
    let total_coeffs = coeffs.components[0].blocks.len() * 64;
    if costs.len() != total_coeffs {
        return Err(StrHideError::General("JPEG cost dimension mismatch".into()));
    }

    // Collect eligible (block_idx, ac_idx) slots:
    // Only AC coefficients (k in 1..64) with |value| >= min_abs_coeff (default 2)
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

    // Sort eligible slots by distortion cost: lowest cost (highest texture energy) first
    eligible_slots.sort_by(|&(bi1, k1), &(bi2, k2)| {
        costs[bi1 * 64 + k1]
            .partial_cmp(&costs[bi2 * 64 + k2])
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Exclude the lowest-energy/highest-cost fraction (e.g. 20%)
    let allowed_count = ((eligible_slots.len() as f64)
        * (1.0 - params.block_exclusion_percentile.clamp(0.0, 0.8)))
        as usize;
    let candidate_slots = &eligible_slots[..allowed_count];

    // Pack payload into micro-envelope
    let envelope = pack_envelope(payload, password)?;
    let total_len = envelope.len() as u32;

    // Header: 32 bytes = 256 bits ([16B Salt][12B Nonce][4B Total Len])
    let mut header_bytes = Vec::with_capacity(32);
    header_bytes.extend_from_slice(&envelope[..28]);
    header_bytes.extend_from_slice(&total_len.to_be_bytes());

    let ciphertext_body = &envelope[28..];
    let ciphertext_bits = ciphertext_body.len() * 8;
    let hamming_k = crate::stego::coding::DEFAULT_HAMMING_K;
    let needed_body_slots = crate::stego::coding::required_slots(ciphertext_bits, hamming_k);

    if candidate_slots.len() < 256 {
        return Err(StrHideError::General(format!(
            "Carrier capacity insufficient: available {} slots, minimum header requires 256 slots",
            candidate_slots.len()
        )));
    }

    // Phase 1: Keyed full candidate set permutation for header slots
    let header_seed = crate::stego::envelope::derive_header_perm_seed(password);
    let mut permuted_candidates = candidate_slots.to_vec();
    permute_indices(&mut permuted_candidates, &header_seed);

    let header_slots = &permuted_candidates[..256];

    // See `spatial::engine`: the header is a keyed random 256-slot subset, the
    // body keeps UERD's cost ordering so the cheapest slots are used first.
    let is_header = {
        let mut v = vec![false; total_coeffs];
        for &(bi, k) in header_slots {
            v[bi * 64 + k] = true;
        }
        v
    };
    let body_candidates: Vec<(usize, usize)> = candidate_slots
        .iter()
        .copied()
        .filter(|&(bi, k)| !is_header[bi * 64 + k])
        .collect();

    if needed_body_slots > body_candidates.len() {
        return Err(StrHideError::General(format!(
            "Carrier capacity exceeded: needed {} body slots (Hamming k={}), available {} slots (strategy: jpeg-{})",
            needed_body_slots,
            hamming_k,
            body_candidates.len(),
            cost_model.id(),
        )));
    }

    // Phase 2: Keyed permutation of body slots using PBKDF2 salt-derived seed
    let salt = &envelope[..16];
    let (_, perm_seed) = crate::stego::envelope::derive_keys(
        password.unwrap_or(crate::stego::envelope::PUBLIC_DEFAULT_SECRET),
        salt,
    );

    let mut body_slots = body_candidates[..needed_body_slots].to_vec();
    permute_indices(&mut body_slots, &perm_seed);

    // Embed Phase 1: Header (256 bits direct LSB replacement)
    for (byte_i, &b) in header_bytes.iter().enumerate() {
        for bit_i in 0..8 {
            let target_bit = (b >> (7 - bit_i)) & 1;
            let (bi, k) = header_slots[byte_i * 8 + bit_i];
            let coeff = &mut coeffs.components[0].blocks[bi][k];
            embed_dct_lsb(coeff, target_bit);
        }
    }

    // Embed Phase 2: Ciphertext body using (7, 3) Hamming matrix embedding
    let mut slot_vals: Vec<u8> = body_slots
        .iter()
        .map(|&(bi, k)| {
            let val = coeffs.components[0].blocks[bi][k];
            ((val as i32) & 1) as u8
        })
        .collect();
    let mut slot_refs: Vec<&mut u8> = slot_vals.iter_mut().collect();
    crate::stego::coding::hamming_embed_bytes(&mut slot_refs, ciphertext_body, hamming_k)?;

    for (i, &(bi, k)) in body_slots.iter().enumerate() {
        let target_bit = slot_vals[i];
        let coeff = &mut coeffs.components[0].blocks[bi][k];
        embed_dct_lsb(coeff, target_bit);
    }

    // Re-encode Huffman bitstream without generation loss
    dct_io::write_coefficients(carrier_bytes, &coeffs).map_err(map_dct_error)
}

/// Write `target_bit` into an eligible AC coefficient's LSB by replacement.
///
/// Strict protection: never allows |coeff| to drop below 2 (prevents run-length
/// changes). Replacement (not `±1` matching) keeps `|coeff| & !1` invariant,
/// which is what makes the UERD cost map reproducible at extraction time.
fn embed_dct_lsb(coeff: &mut i16, target_bit: u8) {
    let current_lsb = ((*coeff as i32) & 1) as u8;
    if current_lsb != target_bit {
        let v = *coeff;
        if v > 0 {
            // Flips between 2k and 2k+1 (e.g. 2 <-> 3), strictly >= 2 and preserves high bits
            *coeff = v ^ 1;
        } else if v < 0 {
            // Flips negative magnitude between 2k and 2k+1 (e.g. -2 <-> -3)
            let abs_v = (-v) ^ 1;
            *coeff = -abs_v;
        }
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

    let costs = cost_model.compute_cost(&coeffs, params);
    let total_coeffs = coeffs.components[0].blocks.len() * 64;
    if costs.len() != total_coeffs {
        return Err(StrHideError::NoHiddenData(
            "Invalid JPEG coefficient layout".into(),
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

    eligible_slots.sort_by(|&(bi1, k1), &(bi2, k2)| {
        costs[bi1 * 64 + k1]
            .partial_cmp(&costs[bi2 * 64 + k2])
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let allowed_count = ((eligible_slots.len() as f64)
        * (1.0 - params.block_exclusion_percentile.clamp(0.0, 0.8)))
        as usize;
    let candidate_slots = &eligible_slots[..allowed_count];

    if candidate_slots.len() < 256 {
        return Err(StrHideError::NoHiddenData(
            "Carrier has insufficient capacity for stego header".into(),
        ));
    }

    // Phase 1: Keyed full candidate set permutation for header slots
    let header_seed = crate::stego::envelope::derive_header_perm_seed(password);
    let mut permuted_candidates = candidate_slots.to_vec();
    permute_indices(&mut permuted_candidates, &header_seed);

    let header_slots = &permuted_candidates[..256];

    // See `spatial::engine`: the header is a keyed random 256-slot subset, the
    // body keeps UERD's cost ordering so the cheapest slots are used first.
    let is_header = {
        let mut v = vec![false; total_coeffs];
        for &(bi, k) in header_slots {
            v[bi * 64 + k] = true;
        }
        v
    };
    let body_candidates: Vec<(usize, usize)> = candidate_slots
        .iter()
        .copied()
        .filter(|&(bi, k)| !is_header[bi * 64 + k])
        .collect();

    // Read Phase 1: 32-byte Header
    let mut header_bytes = [0u8; 32];
    for byte_i in 0..32 {
        let mut b = 0u8;
        for bit_i in 0..8 {
            let (bi, k) = header_slots[byte_i * 8 + bit_i];
            let val = coeffs.components[0].blocks[bi][k];
            let lsb = ((val as i32) & 1) as u8;
            b = (b << 1) | lsb;
        }
        header_bytes[byte_i] = b;
    }

    let salt = &header_bytes[..16];
    let total_len = u32::from_be_bytes([
        header_bytes[28],
        header_bytes[29],
        header_bytes[30],
        header_bytes[31],
    ]) as usize;

    if !(49..=64 * 1024 * 1024).contains(&total_len) {
        // Deliberately generic: a wrong secret lands the header on the wrong
        // slots, and a distinct message ("invalid size") would tell an attacker
        // that *an envelope exists here but the layout is wrong*, which is an
        // oracle the AEAD path deliberately does not provide.
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }

    let ciphertext_len = total_len - 28;
    let ciphertext_bits = ciphertext_len * 8;
    let hamming_k = crate::stego::coding::DEFAULT_HAMMING_K;
    let needed_body_slots = crate::stego::coding::required_slots(ciphertext_bits, hamming_k);

    if needed_body_slots > body_candidates.len() {
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }

    // Phase 2: Keyed permutation of body slots using PBKDF2 salt-derived seed
    let (_, perm_seed) = crate::stego::envelope::derive_keys(
        password.unwrap_or(crate::stego::envelope::PUBLIC_DEFAULT_SECRET),
        salt,
    );

    let mut body_slots = body_candidates[..needed_body_slots].to_vec();
    permute_indices(&mut body_slots, &perm_seed);

    let slot_vals: Vec<u8> = body_slots
        .iter()
        .map(|&(bi, k)| {
            let val = coeffs.components[0].blocks[bi][k];
            ((val as i32) & 1) as u8
        })
        .collect();

    let ciphertext_body =
        crate::stego::coding::hamming_extract_bytes(&slot_vals, ciphertext_len, hamming_k)?;

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

    let costs = cost_model.compute_cost(&coeffs, params);
    let total_coeffs = coeffs.components[0].blocks.len() * 64;
    if costs.len() != total_coeffs {
        return Err(StrHideError::General("JPEG cost dimension mismatch".into()));
    }

    let min_abs = params.min_abs_coeff.max(2);
    let comp = &coeffs.components[0];
    let mut eligible_slots = 0usize;

    for (bi, block) in comp.blocks.iter().enumerate() {
        for k in 1..64 {
            let val = block[k];
            if val.abs() >= min_abs && costs[bi * 64 + k] < params.wet_cost {
                eligible_slots += 1;
            }
        }
    }

    let allowed_count = ((eligible_slots as f64)
        * (1.0 - params.block_exclusion_percentile.clamp(0.0, 0.8)))
        as usize;

    let header_slots = 256;
    let available_body_slots = allowed_count.saturating_sub(header_slots);
    let hamming_k = crate::stego::coding::DEFAULT_HAMMING_K;
    let max_ciphertext_bytes =
        crate::stego::coding::max_payload_bytes(available_body_slots, hamming_k);
    // Only the body-borne overhead comes off here: salt/nonce already paid for
    // by the 256 header slots. Subtracting MIN_ENVELOPE_LEN under-reported the
    // capacity by exactly 28 bytes (measured on real carriers).
    let max_raw_payload_bytes =
        max_ciphertext_bytes.saturating_sub(crate::stego::envelope::BODY_OVERHEAD);
    let recommended_max_bytes = max_raw_payload_bytes / 2;

    Ok(StegoCapacityInfo {
        format: "JPEG".into(),
        algorithm: cost_model.id().into(),
        total_elements: total_coeffs,
        available_slots: available_body_slots,
        max_raw_payload_bytes,
        recommended_max_bytes,
    })
}
