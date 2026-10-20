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
    let total_required_bits = 32 * 8 + ciphertext_bits;

    if total_required_bits > candidate_slots.len() {
        return Err(StrHideError::General(format!(
            "Carrier capacity exceeded: needed {} bits, available {} bits (strategy: jpeg-{})",
            total_required_bits,
            candidate_slots.len(),
            cost_model.id(),
        )));
    }

    // Phase 1: Header slots are top 256 lowest-cost candidate slots
    let header_slots = &candidate_slots[..256];

    // Phase 2: Ciphertext slots permuted using password-derived seed
    let salt = &envelope[..16];
    let (_, perm_seed) = match password {
        Some(p) => crate::stego::envelope::derive_keys(p, salt),
        None => crate::stego::envelope::derive_keys("strhide-default-content-stego-key-2026", salt),
    };

    let remaining_candidates = &candidate_slots[256..256 + ciphertext_bits];
    let mut body_slots = remaining_candidates.to_vec();
    permute_indices(&mut body_slots, &perm_seed);

    // Embed Phase 1: Header
    for (byte_i, &b) in header_bytes.iter().enumerate() {
        for bit_i in 0..8 {
            let target_bit = (b >> (7 - bit_i)) & 1;
            let (bi, k) = header_slots[byte_i * 8 + bit_i];
            let coeff = &mut coeffs.components[0].blocks[bi][k];
            apply_dct_matching(coeff, target_bit, perm_seed[bit_i], bi ^ k);
        }
    }

    // Embed Phase 2: Ciphertext body
    for (byte_i, &b) in ciphertext_body.iter().enumerate() {
        for bit_i in 0..8 {
            let target_bit = (b >> (7 - bit_i)) & 1;
            let (bi, k) = body_slots[byte_i * 8 + bit_i];
            let coeff = &mut coeffs.components[0].blocks[bi][k];
            apply_dct_matching(coeff, target_bit, perm_seed[bit_i], bi ^ k);
        }
    }

    // Re-encode Huffman bitstream without generation loss
    dct_io::write_coefficients(carrier_bytes, &coeffs).map_err(map_dct_error)
}

/// Modify an eligible AC coefficient's LSB using DCT matching (+-1).
/// Strict protection: never allows |coeff| to drop below 2 (prevents run-length changes).
fn apply_dct_matching(coeff: &mut i16, target_bit: u8, _seed_byte: u8, _slot: usize) {
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

    if candidate_slots.len() < 32 * 8 {
        return Err(StrHideError::NoHiddenData(
            "Carrier has insufficient capacity for stego header".into(),
        ));
    }

    // Read Phase 1: 32-byte Header
    let header_slots = &candidate_slots[..256];
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
        return Err(StrHideError::NoHiddenData(
            "Invalid stego envelope size".into(),
        ));
    }

    let ciphertext_len = total_len - 28;
    let ciphertext_bits = ciphertext_len * 8;
    if 256 + ciphertext_bits > candidate_slots.len() {
        return Err(StrHideError::NoHiddenData(
            "Truncated stego envelope".into(),
        ));
    }

    // Phase 2: Permute remaining candidate slots using derived perm_seed
    let (_, perm_seed) = match password {
        Some(p) => crate::stego::envelope::derive_keys(p, salt),
        None => crate::stego::envelope::derive_keys("strhide-default-content-stego-key-2026", salt),
    };

    let remaining_candidates = &candidate_slots[256..256 + ciphertext_bits];
    let mut body_slots = remaining_candidates.to_vec();
    permute_indices(&mut body_slots, &perm_seed);

    let mut full_envelope = Vec::with_capacity(total_len);
    full_envelope.extend_from_slice(&header_bytes[..28]); // Salt + Nonce

    for byte_i in 0..ciphertext_len {
        let mut b = 0u8;
        for bit_i in 0..8 {
            let (bi, k) = body_slots[byte_i * 8 + bit_i];
            let val = coeffs.components[0].blocks[bi][k];
            let lsb = ((val as i32) & 1) as u8;
            b = (b << 1) | lsb;
        }
        full_envelope.push(b);
    }

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

    let fixed_overhead_bits = 416; // 32B header (256 bits) + 20B envelope overhead (160 bits)
    let available_bits = allowed_count.saturating_sub(fixed_overhead_bits);
    let max_raw_payload_bytes = available_bits / 8;
    let recommended_max_bytes = max_raw_payload_bytes / 2;

    Ok(StegoCapacityInfo {
        format: "JPEG".into(),
        algorithm: cost_model.id().into(),
        total_elements: total_coeffs,
        available_slots: allowed_count,
        max_raw_payload_bytes,
        recommended_max_bytes,
    })
}
