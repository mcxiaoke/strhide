// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Hamming Matrix Embedding (F5 / Crandall syndrome coding).
//!
//! Provides minimal-distortion block embedding using (2^k - 1, k) Hamming codes.
//! In each block of n = 2^k - 1 cover slots, k message bits are embedded by flipping
//! at most ONE slot (or zero if the cover block already satisfies the syndrome).
//!
//! # Embedding Efficiency
//! - k = 1: (1, 1) direct LSB replacement (0.5 flips/bit)
//! - k = 3: (7, 3) 7 slots carry 3 bits; max 1 flip, average (7/8)/3 ≈ 0.2917 flips/bit (42% fewer changes)
//! - k = 4: (15, 4) 15 slots carry 4 bits; average (15/16)/4 ≈ 0.2344 flips/bit (53% fewer changes)
//! - k = 5: (31, 5) 31 slots carry 5 bits; average (31/32)/5 ≈ 0.1938 flips/bit (61% fewer changes)
//!
//! # Tail Handling
//! Any remaining message bits after full blocks (total_bits % k) are embedded directly
//! (1-to-1 LSB) using 1 slot per bit. This avoids padding ambiguities and preserves exact byte boundaries.
//!
//! # Memory
//! Bit access is computed on the fly from `payload`; the encoder never expands the
//! message into a `Vec<u8>` of one-byte-per-bit (that was an 8x blow-up on large
//! envelopes).

use crate::errors::StrHideError;

/// Default Hamming parameter k (7 slots carry 3 bits).
pub const DEFAULT_HAMMING_K: usize = 3;

/// Largest supported k. `2^7 - 1 = 127` slots per block keeps the per-block
/// scratch buffer small; larger k is not useful in practice because the block
/// would span more slots than a typical carrier has per region.
pub const MAX_HAMMING_K: usize = 7;

/// Reject `k` values the block math cannot serve.
///
/// `k = 0` used to divide by zero in `required_slots`, and `k >= 8` overflowed
/// the fixed 127-entry block buffer. Both are unreachable while `k` is the
/// compile-time `DEFAULT_HAMMING_K`, but the parameter is meant to become
/// user-configurable, so the guard belongs at the boundary.
pub fn validate_k(k: usize) -> Result<(), StrHideError> {
    if k == 0 {
        return Err(StrHideError::General(
            "Hamming parameter 'k' must be >= 1, got 0".into(),
        ));
    }
    if k > MAX_HAMMING_K {
        return Err(StrHideError::General(format!(
            "Hamming parameter 'k' must be <= {MAX_HAMMING_K}, got {k}"
        )));
    }
    Ok(())
}

/// Calculate required slots to embed `num_bits` with parameter `k`.
pub fn required_slots(num_bits: usize, k: usize) -> usize {
    if k <= 1 {
        return num_bits;
    }
    let n = (1usize << k) - 1;
    let full_blocks = num_bits / k;
    let tail_bits = num_bits % k;
    full_blocks * n + tail_bits
}

/// Calculate maximum payload capacity in bytes given `available_slots` and parameter `k`.
pub fn max_payload_bytes(available_slots: usize, k: usize) -> usize {
    if k <= 1 {
        return available_slots / 8;
    }
    let n = (1usize << k) - 1;
    let full_blocks = available_slots / n;
    let remaining_slots = available_slots % n;
    let total_bits = full_blocks * k + remaining_slots.min(k - 1);
    total_bits / 8
}

/// Read bit `idx` (MSB-first within each byte) of `payload`.
#[inline]
fn bit_at(payload: &[u8], idx: usize) -> u8 {
    (payload[idx / 8] >> (7 - (idx % 8))) & 1
}

/// Embed a single k-bit message value (0 <= msg < 2^k) into an n-slot block (n = 2^k - 1).
/// Modifies at most one element's LSB in `block`.
/// Returns 1 if a slot was flipped, or 0 if unchanged.
#[inline]
pub fn hamming_embed_block(block: &mut [u8], msg: u32, k: usize) -> usize {
    let n = (1usize << k) - 1;
    debug_assert!(block.len() >= n);
    debug_assert!(msg < (1u32 << k));

    // Syndrome s = XOR sum of (j * LSB_j) for 1 <= j <= n
    let mut syndrome = 0u32;
    for j in 1..=n {
        if (block[j - 1] & 1) != 0 {
            syndrome ^= j as u32;
        }
    }

    let diff = syndrome ^ msg;
    if diff != 0 {
        let flip_idx = (diff as usize) - 1;
        block[flip_idx] ^= 1;
        1
    } else {
        0
    }
}

/// Extract a k-bit message value from an n-slot block (n = 2^k - 1).
#[inline]
pub fn hamming_extract_block(block: &[u8], k: usize) -> u32 {
    let n = (1usize << k) - 1;
    debug_assert!(block.len() >= n);

    let mut syndrome = 0u32;
    for j in 1..=n {
        if (block[j - 1] & 1) != 0 {
            syndrome ^= j as u32;
        }
    }
    syndrome
}

/// Embed an arbitrary byte payload into candidate slot references.
///
/// Modifies the LSB of elements in `slots`.
/// Returns the total number of modified slots.
pub fn hamming_embed_bytes(
    slots: &mut [&mut u8],
    payload: &[u8],
    k: usize,
) -> Result<usize, StrHideError> {
    validate_k(k)?;

    let total_bits = payload.len() * 8;
    let needed = required_slots(total_bits, k);
    if slots.len() < needed {
        return Err(StrHideError::General(format!(
            "Insufficient slots for Hamming embedding: needed {}, available {}",
            needed,
            slots.len()
        )));
    }

    if k <= 1 {
        // Degenerate case: plain 1-to-1 LSB replacement.
        let mut flips = 0;
        for (i, target_bit) in (0..total_bits).map(|i| (i, bit_at(payload, i))) {
            if (*slots[i] & 1) != target_bit {
                *slots[i] ^= 1;
                flips += 1;
            }
        }
        return Ok(flips);
    }

    let n = (1usize << k) - 1;
    let mut slot_cursor = 0;
    let mut flips = 0;
    let mut block_bytes = [0u8; 127];

    let full_blocks = total_bits / k;
    for b in 0..full_blocks {
        let mut msg = 0u32;
        for i in 0..k {
            msg = (msg << 1) | (bit_at(payload, b * k + i) as u32);
        }

        // Gather block LSBs
        for (j, slot) in block_bytes.iter_mut().enumerate().take(n) {
            *slot = *slots[slot_cursor + j];
        }

        let flipped = hamming_embed_block(&mut block_bytes[..n], msg, k);
        flips += flipped;

        // Write back if modified
        if flipped > 0 {
            for (j, &v) in block_bytes.iter().enumerate().take(n) {
                *slots[slot_cursor + j] = v;
            }
        }
        slot_cursor += n;
    }

    // Embed tail bits (1-to-1)
    let tail_start = full_blocks * k;
    for bit_idx in tail_start..total_bits {
        let target_bit = bit_at(payload, bit_idx);
        let current_lsb = *slots[slot_cursor] & 1;
        if current_lsb != target_bit {
            *slots[slot_cursor] ^= 1;
            flips += 1;
        }
        slot_cursor += 1;
    }

    Ok(flips)
}

/// Extract an arbitrary byte payload of length `payload_len` from candidate slots.
pub fn hamming_extract_bytes(
    slots: &[u8],
    payload_len: usize,
    k: usize,
) -> Result<Vec<u8>, StrHideError> {
    validate_k(k)?;

    let total_bits = payload_len * 8;
    let needed = required_slots(total_bits, k);
    if slots.len() < needed {
        return Err(StrHideError::NoHiddenData(format!(
            "Insufficient slots for Hamming extraction: needed {}, available {}",
            needed,
            slots.len()
        )));
    }

    let mut result = vec![0u8; payload_len];

    if k <= 1 {
        for bit_idx in 0..total_bits {
            result[bit_idx / 8] |= (slots[bit_idx] & 1) << (7 - (bit_idx % 8));
        }
        return Ok(result);
    }

    let n = (1usize << k) - 1;
    let mut slot_cursor = 0;
    let mut bit_idx = 0usize;

    let full_blocks = total_bits / k;
    for _ in 0..full_blocks {
        let msg = hamming_extract_block(&slots[slot_cursor..slot_cursor + n], k);
        for shift in (0..k).rev() {
            result[bit_idx / 8] |= (((msg >> shift) & 1) as u8) << (7 - (bit_idx % 8));
            bit_idx += 1;
        }
        slot_cursor += n;
    }

    let tail_bits = total_bits % k;
    for _ in 0..tail_bits {
        result[bit_idx / 8] |= (slots[slot_cursor] & 1) << (7 - (bit_idx % 8));
        bit_idx += 1;
        slot_cursor += 1;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift32 stream: real pseudo-random LSB noise (the old
    /// version used `i % 2`, a periodic pattern that gave the syndrome test a
    /// degenerate cover).
    fn pseudo_random_bytes(len: usize, seed: u32) -> Vec<u8> {
        let mut s = seed | 1;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            out.push((s & 0xFF) as u8);
        }
        out
    }

    #[test]
    fn test_hamming_k_bounds() {
        assert!(
            validate_k(0).is_err(),
            "k=0 must be rejected, not divide by zero"
        );
        assert!(validate_k(1).is_ok());
        assert!(validate_k(DEFAULT_HAMMING_K).is_ok());
        assert!(validate_k(MAX_HAMMING_K).is_ok());
        assert!(
            validate_k(MAX_HAMMING_K + 1).is_err(),
            "k > 7 overflows the block buffer"
        );

        // The byte-level entry points must reject bad k instead of panicking.
        let mut buf = [0u8; 32];
        let mut refs: Vec<&mut u8> = buf.iter_mut().collect();
        assert!(hamming_embed_bytes(&mut refs, b"x", 0).is_err());
        assert!(hamming_embed_bytes(&mut refs, b"x", MAX_HAMMING_K + 1).is_err());
        assert!(hamming_extract_bytes(&buf, 1, 0).is_err());
    }

    #[test]
    fn test_hamming_block_roundtrip() {
        for k in 2..=5 {
            let n = (1 << k) - 1;
            let max_msg = 1u32 << k;
            for msg in 0..max_msg {
                // Test with various cover patterns
                for initial_pattern in 0..max_msg {
                    let mut block = vec![0u8; n];
                    for (i, val) in block.iter_mut().enumerate().take(n) {
                        *val = ((initial_pattern >> (i % k)) & 1) as u8;
                    }
                    let orig_block = block.clone();

                    let flips = hamming_embed_block(&mut block, msg, k);
                    assert!(flips <= 1, "k={k}: modified {flips} slots (must be <= 1)");

                    let extracted = hamming_extract_block(&block, k);
                    assert_eq!(
                        extracted, msg,
                        "k={k}, msg={msg}: extraction mismatch! got {extracted}"
                    );

                    // Check exact diff
                    let changed_count = block
                        .iter()
                        .zip(orig_block.iter())
                        .filter(|(a, b)| a != b)
                        .count();
                    assert_eq!(flips, changed_count);
                }
            }
        }
    }

    #[test]
    fn test_hamming_bytes_roundtrip() {
        for k in [1, 2, 3, 4, 5] {
            // Payload lengths whose bit count is not a multiple of k exercise
            // the 1-to-1 tail: 8n % k cycles through every residue.
            for payload_len in [1usize, 3, 5, 7, 8, 13] {
                let payload = pseudo_random_bytes(payload_len, 0x1234_5678 ^ payload_len as u32);
                let total_bits = payload.len() * 8;
                let needed = required_slots(total_bits, k);

                let mut carrier = pseudo_random_bytes(needed + 100, 0x9E37_79B9);

                let mut refs: Vec<&mut u8> = carrier.iter_mut().collect();
                let flips = hamming_embed_bytes(&mut refs, &payload, k).expect("Embed succeeded");

                let max_possible_flips = if k <= 1 {
                    total_bits
                } else {
                    (total_bits / k) + (total_bits % k)
                };
                assert!(
                    flips <= max_possible_flips,
                    "k={k}, len={payload_len}: flips ({flips}) exceeded upper bound ({max_possible_flips})"
                );

                let extracted =
                    hamming_extract_bytes(&carrier, payload.len(), k).expect("Extract succeeded");
                assert_eq!(
                    extracted, payload,
                    "k={k}, len={payload_len}: roundtrip mismatch"
                );
            }
        }
    }

    #[test]
    fn test_hamming_efficiency_statistical() {
        // Statistical verification of flip rate reduction for k=3
        let k = 3;
        let num_blocks = 10_000;
        let total_bits = num_blocks * k;
        let needed = required_slots(total_bits, k);

        let mut carrier = pseudo_random_bytes(needed, 0x5DEE_CE66);
        let payload = pseudo_random_bytes(total_bits / 8, 0x1234_ABCD);

        let mut refs: Vec<&mut u8> = carrier.iter_mut().collect();
        let flips = hamming_embed_bytes(&mut refs, &payload, k).unwrap();

        let flip_rate = flips as f64 / total_bits as f64;
        // Theoretical flip rate: (7/8) / 3 ≈ 0.291666...
        // Direct LSB replacement would be ~0.50
        assert!(
            (flip_rate - 0.2917).abs() < 0.015,
            "Expected flip rate near 0.2917, got {:.4}",
            flip_rate
        );
    }

    #[test]
    fn test_capacity_helpers_are_inverse() {
        // required_slots must never exceed the slot budget derived from
        // max_payload_bytes: the capacity probes are built on that inequality.
        for k in [1, 2, 3, 4, 5] {
            for slots in [0usize, 1, 7, 100, 255, 999, 4096] {
                let bytes = max_payload_bytes(slots, k);
                assert!(
                    required_slots(bytes * 8, k) <= slots,
                    "k={k}, slots={slots}: {bytes} bytes need {} slots",
                    required_slots(bytes * 8, k)
                );
            }
        }
    }
}
