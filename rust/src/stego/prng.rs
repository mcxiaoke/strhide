//! Cryptographically seeded pseudo-random permutation for embedding slot scattering.
//!
//! Scatters the embedding sequence across candidate slots (pixels or DCT coefficients)
//! using a 256-bit seed derived from the user password or profile secret. The general candidate
//! pool is ranked by the public cost model (HILL/UERD); the keyed permutation selects the 256
//! header slots from the candidate pool and scrambles the body slot embedding order, ensuring
//! that without the key, an attacker cannot determine header locations or the message stream order.
//!
//! # Architecture & Reproducibility Contract (§4.2)
//!
//! Content-adaptive steganography requires strict, lifetime-invariant reproducibility:
//! carrier pixels/coefficients are scattered according to a deterministic pseudorandom
//! permutation. If the PRNG or shuffle algorithm changes across library or dependency versions,
//! previously embedded carriers become permanently unextractable ("bricked").
//!
//! To prevent disaster caused by non-portable upstream PRNG changes (such as `rand::StdRng`
//! algorithm migrations), this module uses:
//! 1. A self-contained, hardcoded **ChaCha12** stream generator (RFC 8439 / Bernstein 2008).
//! 2. A self-contained, unbiased standard **Fisher-Yates** shuffle with deterministic rejection
//!    sampling.
//! 3. Value-stability contract tests locking "Fixed Seed -> Fixed Permutation Sequence" across
//!    all compiler versions and platforms.

/// Constant words for ChaCha: "expand 32-byte k" in little-endian.
const CHACHA_CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Quarter round operation for ChaCha cipher on a 16-word state array.
#[inline(always)]
fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(16);

    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(12);

    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(8);

    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(7);
}

/// Hardcoded, portable ChaCha12 stream generator.
///
/// Produces a cryptographically secure pseudo-random stream using 12 rounds of ChaCha.
/// Seeded with a 256-bit (32-byte) key, using a 64-bit counter and a 64-bit zero stream nonce.
#[derive(Clone, Debug)]
pub struct ChaCha12Stream {
    state: [u32; 16],
    buffer: [u32; 16],
    index: usize,
}

impl ChaCha12Stream {
    /// Initialize a ChaCha12 generator from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut key = [0u32; 8];
        let (chunks, _) = seed.as_chunks::<4>();
        for (k, chunk) in key.iter_mut().zip(chunks) {
            *k = u32::from_le_bytes(*chunk);
        }

        let state = [
            CHACHA_CONSTANTS[0],
            CHACHA_CONSTANTS[1],
            CHACHA_CONSTANTS[2],
            CHACHA_CONSTANTS[3],
            key[0],
            key[1],
            key[2],
            key[3],
            key[4],
            key[5],
            key[6],
            key[7],
            0,
            0, // 64-bit counter initialized to 0
            0,
            0, // 64-bit nonce/stream initialized to 0
        ];

        let mut stream = Self {
            state,
            buffer: [0u32; 16],
            index: 16, // forces immediate block generation on first read
        };
        stream.generate_block();
        stream
    }

    /// Compute the next 64-byte block (16 `u32` words) using 12 ChaCha rounds.
    #[inline]
    fn generate_block(&mut self) {
        let mut x = self.state;

        // 6 double-rounds = 12 rounds
        for _ in 0..6 {
            // Column round
            quarter_round(&mut x, 0, 4, 8, 12);
            quarter_round(&mut x, 1, 5, 9, 13);
            quarter_round(&mut x, 2, 6, 10, 14);
            quarter_round(&mut x, 3, 7, 11, 15);

            // Diagonal round
            quarter_round(&mut x, 0, 5, 10, 15);
            quarter_round(&mut x, 1, 6, 11, 12);
            quarter_round(&mut x, 2, 7, 8, 13);
            quarter_round(&mut x, 3, 4, 9, 14);
        }

        for (buf_slot, (&xi, &si)) in self.buffer.iter_mut().zip(x.iter().zip(&self.state)) {
            *buf_slot = xi.wrapping_add(si);
        }

        // Increment 64-bit block counter in state[12..14]
        let (next_low, carry) = self.state[12].overflowing_add(1);
        self.state[12] = next_low;
        if carry {
            self.state[13] = self.state[13].wrapping_add(1);
        }

        self.index = 0;
    }

    /// Generate the next pseudo-random `u32`.
    #[inline(always)]
    pub fn next_u32(&mut self) -> u32 {
        if self.index >= 16 {
            self.generate_block();
        }
        let val = self.buffer[self.index];
        self.index += 1;
        val
    }

    /// Generate the next pseudo-random `u64` (little-endian combination of two `u32` words).
    #[inline(always)]
    pub fn next_u64(&mut self) -> u64 {
        let lo = self.next_u32() as u64;
        let hi = self.next_u32() as u64;
        lo | (hi << 32)
    }

    /// Sample an unbiased uniform index in `0..bound` using rejection sampling.
    ///
    /// If `bound <= 1`, returns 0.
    #[inline]
    pub fn gen_range_usize(&mut self, bound: usize) -> usize {
        if bound <= 1 {
            return 0;
        }

        if bound <= (u32::MAX as usize) {
            let b = bound as u64;
            // 2^32 % b
            let rem = (1u64 << 32) % b;
            let limit = (1u64 << 32) - rem;
            loop {
                let r = self.next_u32() as u64;
                if r < limit {
                    return (r % b) as usize;
                }
            }
        } else {
            let b = bound as u128;
            // 2^64 % b
            let rem = (1u128 << 64) % b;
            let limit = (1u128 << 64) - rem;
            loop {
                let r = self.next_u64() as u128;
                if r < limit {
                    return (r % b) as usize;
                }
            }
        }
    }
}

/// Permute a slice of items in-place using standard Fisher-Yates (Durstenfeld) shuffle
/// driven by the hardcoded ChaCha12 PRNG.
pub fn permute_indices<T>(items: &mut [T], seed: &[u8; 32]) {
    if items.len() <= 1 {
        return;
    }
    let mut rng = ChaCha12Stream::from_seed(seed);
    fisher_yates_shuffle(items, &mut rng);
}

/// In-place unbiased Fisher-Yates shuffle using the provided PRNG stream.
pub fn fisher_yates_shuffle<T>(items: &mut [T], rng: &mut ChaCha12Stream) {
    if items.len() <= 1 {
        return;
    }
    for i in (1..items.len()).rev() {
        let j = rng.gen_range_usize(i + 1);
        items.swap(i, j);
    }
}

/// In-place unbiased *prefix* Fisher-Yates shuffle.
///
/// Uniformly selects and permutes the first `k` elements of `items` in O(k)
/// time. `k` is clamped to `n - 1`: a full forward Fisher-Yates permutation of
/// `n` elements needs exactly `n - 1` swap steps.
pub fn fisher_yates_prefix<T>(items: &mut [T], k: usize, rng: &mut ChaCha12Stream) {
    fisher_yates_prefix_from(items, 0, k, rng);
}

/// Continue a forward prefix shuffle over `start..end`.
///
/// A step at index `i` only swaps `i` with an index in `[i, n)`, so every
/// position below `i` is final. That is what lets the extractor shuffle the
/// minimum header prefix, read the superblock, and then continue the exact same
/// RNG stream up to the extension-area size the superblock declares.
pub fn fisher_yates_prefix_from<T>(
    items: &mut [T],
    start: usize,
    end: usize,
    rng: &mut ChaCha12Stream,
) {
    let n = items.len();
    if n <= 1 {
        return;
    }
    let end = end.min(n - 1);
    let start = start.min(end);
    for i in start..end {
        let j = i + rng.gen_range_usize(n - i);
        items.swap(i, j);
    }
}

/// Permute the first `k` elements of `items` in-place using the 32-byte seed.
///
/// This is the prefix counterpart of [`permute_indices`]. It starts a fresh
/// ChaCha12 stream, so embed and extract must both use it with the same seed
/// and the same `k` (or the same two-phase continuation).
pub fn permute_prefix<T>(items: &mut [T], k: usize, seed: &[u8; 32]) {
    if items.len() <= 1 || k == 0 {
        return;
    }
    let mut rng = ChaCha12Stream::from_seed(seed);
    fisher_yates_prefix(items, k, &mut rng);
}

/// Generate a permuted vector of indices 0..n using a 32-byte seed.
pub fn generate_permuted_indices(n: usize, seed: &[u8; 32]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..n).collect();
    permute_indices(&mut indices, seed);
    indices
}

/// Deterministic payload bytes of exactly `len` bytes.
///
/// Draws from the same ChaCha12 stream the slot scattering uses, so the output
/// is identical on every platform, every build and every run. That makes it a
/// fixture a hash can be pinned to without committing a binary file: tests and
/// the `repro_*` examples ask for `len` bytes with a seed and get the same bytes
/// back.
///
/// The bytes are raw keystream, i.e. incompressible, so
/// [`build_plaintext`](crate::stego::envelope::build_plaintext) stores them
/// uncompressed and the payload keeps its declared size.
pub fn deterministic_payload(len: usize, seed: u64) -> Vec<u8> {
    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&seed.to_le_bytes());
    // Domain tag so these bytes never collide with any other use of the stream.
    key[8..24].copy_from_slice(b"strhide-payload\0");
    let mut rng = ChaCha12Stream::from_seed(&key);

    let mut out = Vec::with_capacity(len.div_ceil(4) * 4);
    while out.len() < len {
        out.extend_from_slice(&rng.next_u32().to_le_bytes());
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Official Strombergson 2013 test vector 1 for ChaCha12 (256-bit key, IV=0, rounds=12).
    /// draft-strombergson-chacha-test-vectors-01 TC1
    #[test]
    fn test_chacha12_kat_strombergson_tc1() {
        let mut seed = [0u8; 32];
        seed[0] = 1;
        let mut stream = ChaCha12Stream::from_seed(&seed);

        let mut words = [0u32; 32];
        for w in &mut words {
            *w = stream.next_u32();
        }

        // Expected 8 u128 values from Strombergson TC1 in little-endian
        let expected_u128: [u128; 8] = [
            0x9a225cdf090f0eef6b0565d596e0512,
            0x10dd4d0bff1802930f5d5290278c2449,
            0xfefdfe067d7a109ee254a4d9392200a6,
            0xc029dc60c972179bf2f944a0eb0f21f0,
            0x2a37692ab05e660e2404c6cbc566730c,
            0xc8a72980b8c4c72a0978bb6fb279f97a,
            0xaf15ba8e302e43907dfcbb17c23b5154,
            0xa9177125baafe601560d10ef48eb5ac6,
        ];

        let mut actual_u128 = [0u128; 8];
        for i in 0..8 {
            let chunk = [
                words[i * 4],
                words[i * 4 + 1],
                words[i * 4 + 2],
                words[i * 4 + 3],
            ];
            let mut bytes = [0u8; 16];
            for (k, &cw) in chunk.iter().enumerate() {
                bytes[k * 4..k * 4 + 4].copy_from_slice(&cw.to_le_bytes());
            }
            actual_u128[i] = u128::from_le_bytes(bytes);
        }

        assert_eq!(actual_u128, expected_u128);
    }

    /// Contract Test (§4.2): Fixed Seed -> Fixed Permutation Sequence.
    ///
    /// This contract assertion guarantees that the permutation sequence for any given
    /// seed and candidate size NEVER changes across library versions, compiler updates,
    /// or host architectures. Changing these expected values would break extraction of
    /// previously generated stego carriers.
    #[test]
    fn test_fixed_seed_fixed_permutation_contract_256() {
        const CONTRACT_SEED: [u8; 32] = *b"strhide-prng-contract-seed-2026!";
        let permuted = generate_permuted_indices(256, &CONTRACT_SEED);

        assert_eq!(permuted.len(), 256);

        // Verification of set completeness (no duplicate, no loss)
        let mut sorted = permuted.clone();
        sorted.sort_unstable();
        let expected_sorted: Vec<usize> = (0..256).collect();
        assert_eq!(sorted, expected_sorted);

        // First 16 elements locked contract
        #[rustfmt::skip]
        let expected_first_16: [usize; 16] = [
            61, 121, 191, 236, 8, 58, 233, 146,
            64, 12, 35, 66, 70, 210, 254, 52,
        ];
        assert_eq!(&permuted[..16], &expected_first_16);

        // Last 16 elements locked contract
        #[rustfmt::skip]
        let expected_last_16: [usize; 16] = [
            93, 222, 27, 189, 132, 24, 10, 164,
            145, 37, 133, 170, 180, 127, 4, 135,
        ];
        assert_eq!(&permuted[240..], &expected_last_16);
    }

    /// Contract Test (§4.2): Fixed Seed -> Fixed Permutation Sequence for Large Candidate Pool (1024).
    #[test]
    fn test_fixed_seed_fixed_permutation_contract_1024() {
        const CONTRACT_SEED_1024: [u8; 32] = [0x5au8; 32];
        let permuted = generate_permuted_indices(1024, &CONTRACT_SEED_1024);

        assert_eq!(permuted.len(), 1024);

        let mut sorted = permuted.clone();
        sorted.sort_unstable();
        let expected_sorted: Vec<usize> = (0..1024).collect();
        assert_eq!(sorted, expected_sorted);

        // Contract checkpoints
        #[rustfmt::skip]
        let expected_head_8: [usize; 8] = [
            904, 214, 563, 165, 268, 138, 149, 367,
        ];
        assert_eq!(&permuted[..8], &expected_head_8);

        #[rustfmt::skip]
        let expected_tail_8: [usize; 8] = [
            792, 255, 914, 758, 195, 524, 765, 1000,
        ];
        assert_eq!(&permuted[1016..], &expected_tail_8);
    }

    /// Test rejection sampling and edge cases for gen_range_usize.
    #[test]
    fn test_gen_range_usize_bounds() {
        let seed = [0x42u8; 32];
        let mut rng = ChaCha12Stream::from_seed(&seed);

        assert_eq!(rng.gen_range_usize(0), 0);
        assert_eq!(rng.gen_range_usize(1), 0);

        for bound in [2, 3, 5, 7, 16, 100, 1000, 65536] {
            for _ in 0..200 {
                let v = rng.gen_range_usize(bound);
                assert!(v < bound);
            }
        }
    }

    /// Test seed avalanche property: 1-bit difference produces drastically different permutations.
    #[test]
    fn test_seed_avalanche_property() {
        let seed1 = [0x77u8; 32];
        let mut seed2 = seed1;
        seed2[0] ^= 0x01; // flip 1 bit

        let p1 = generate_permuted_indices(100, &seed1);
        let p2 = generate_permuted_indices(100, &seed2);

        let matching_positions = p1.iter().zip(p2.iter()).filter(|(a, b)| a == b).count();
        // Probability of index collision across 100 slots is roughly ~1%
        assert!(
            matching_positions <= 5,
            "1-bit flip produced too many matching positions: {matching_positions}"
        );
    }

    /// Test edge cases: empty slice and single-element slice do not panic.
    #[test]
    fn test_permute_edge_cases() {
        let seed = [0x11u8; 32];
        let mut empty: Vec<usize> = vec![];
        permute_indices(&mut empty, &seed);
        assert!(empty.is_empty());

        let mut single = vec![42];
        permute_indices(&mut single, &seed);
        assert_eq!(single, vec![42]);
    }

    /// The first `k` positions are a permutation of a k-element subset, and the
    /// untouched tail is still present exactly once.
    #[test]
    fn test_prefix_shuffle_keeps_a_set_without_duplicates() {
        let seed = [0x3Cu8; 32];
        for (n, k) in [
            (0usize, 0usize),
            (1, 0),
            (1, 1),
            (2, 0),
            (2, 1),
            (2, 2),
            (8, 3),
            (64, 32),
            (64, 63),
            (64, 64),
        ] {
            let mut items: Vec<usize> = (0..n).collect();
            permute_prefix(&mut items, k, &seed);
            assert_eq!(items.len(), n);
            let mut sorted = items.clone();
            sorted.sort_unstable();
            let expected: Vec<usize> = (0..n).collect();
            assert_eq!(sorted, expected, "n={n} k={k}");
        }
    }

    /// A single prefix call must equal a two-phase continuation split at any
    /// point. This is the contract the JPEG extractor relies on.
    #[test]
    fn test_prefix_continuation_matches_a_single_call() {
        let seed = [0xA7u8; 32];
        for n in [8usize, 37, 256] {
            for split in [0usize, 1, n / 3, n - 2, n - 1] {
                for k in [split, (split + n / 2).min(n)] {
                    let mut one_shot: Vec<usize> = (0..n).collect();
                    permute_prefix(&mut one_shot, k, &seed);

                    let mut two_phase: Vec<usize> = (0..n).collect();
                    let mut rng = ChaCha12Stream::from_seed(&seed);
                    fisher_yates_prefix_from(&mut two_phase, 0, split, &mut rng);
                    fisher_yates_prefix_from(&mut two_phase, split, k, &mut rng);

                    assert_eq!(
                        one_shot, two_phase,
                        "n={n} split={split} k={k}: continuation changed the permutation"
                    );
                }
            }
        }
    }

    /// Fixed seed -> fixed prefix sequence, so a future refactor cannot silently
    /// change the wire format.
    #[test]
    fn test_prefix_fixed_seed_contract() {
        const CONTRACT_SEED: [u8; 32] = *b"strhide-prng-contract-seed-2026!";
        let mut items: Vec<usize> = (0..256).collect();
        permute_prefix(&mut items, 16, &CONTRACT_SEED);
        #[rustfmt::skip]
        let expected_first_16: [usize; 16] = [
            135, 5, 129, 183, 174, 138, 43, 152, 172, 19, 34, 143, 201, 40, 236, 108,
        ];
        assert_eq!(&items[..16], &expected_first_16);
    }

    /// A one-element prefix over many seeds must hit every index roughly
    /// uniformly; a modulo-biased or reverse-order implementation would skew it.
    #[test]
    fn test_prefix_single_position_is_roughly_uniform() {
        let n = 16usize;
        let rounds = 4096usize;
        let mut counts = [0usize; 16];
        for round in 0..rounds {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(round as u64).to_le_bytes());
            let mut items: Vec<usize> = (0..n).collect();
            permute_prefix(&mut items, 1, &seed);
            counts[items[0]] += 1;
        }
        let expected = rounds as f64 / n as f64;
        for (idx, &count) in counts.iter().enumerate() {
            let deviation = (count as f64 - expected).abs() / expected;
            assert!(
                deviation < 0.25,
                "index {idx}: {count} hits, expected about {expected:.0}"
            );
        }
    }
}
