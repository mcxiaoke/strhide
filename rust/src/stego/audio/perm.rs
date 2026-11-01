//! Keyed pseudo-random permutation over `[0, n)`.
//!
//! The audio engines must spread a payload over the whole carrier instead of
//! filling the first seconds of sound. A materialised permutation vector would
//! cost 8 bytes per slot (a one-hour stereo WAV has 317 M slots -- 2.5 GB), so
//! the permutation is evaluated arithmetically: a balanced six-round Feistel
//! network over the smallest power-of-two domain that covers `n`, followed by
//! **cycle walking** to land inside `[0, n)`.
//!
//! # Why this is a permutation
//!
//! A Feistel network is a bijection on `[0, 2^(2h))` for any round function.
//! Cycle walking (`while y >= n { y = permute(y) }`) stays inside a bijection,
//! so restricted to `[0, n)` it is still one-to-one -- no slot is visited twice
//! and none is skipped. The expected number of walks is below two because
//! `2^(2h) < 4n` by construction.
//!
//! # What the key buys
//!
//! The seed is derived from the password (through the format profile's header
//! salt), so an observer without it sees the modified positions as uniform
//! noise over the file. Confidentiality itself comes from the AEAD envelope;
//! this only keeps the *positions* from announcing themselves.

use sha2::{Digest, Sha256};

/// Domain separator, so an audio permutation seed can never collide with any
/// other use of the same 32-byte seed.
const PERM_LABEL: &[u8] = b"strhide-audio-perm-v1";

/// Number of Feistel rounds. Six is the smallest count with a comfortable
/// margin against the structural bias four rounds show on short domains, and
/// the cost is irrelevant next to the sample access it guards.
const ROUNDS: u32 = 6;

/// SplitMix64 finaliser: cheap, well-distributed, and already the mixing
/// primitive the repository's PRNG uses.
#[inline]
fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A keyed bijection on `[0, n)`.
#[derive(Debug, Clone)]
pub(crate) struct KeyedPermutation {
    /// Size of the domain; `at()` always returns a value below it.
    n: u64,
    /// Bits per Feistel half. The walked domain is `2^(2 * half)`.
    half: u32,
    /// Round keys.
    keys: [u64; 2],
}

impl KeyedPermutation {
    /// Build the permutation for a domain of `n` slots.
    ///
    /// `seed` must be the caller's header-permutation seed (already domain
    /// separated by the format profile); `n == 0` yields a degenerate instance
    /// whose `at()` always returns 0 -- callers reject empty carriers before
    /// asking.
    pub(crate) fn new(seed: &[u8; 32], n: usize) -> Self {
        let n = n as u64;
        // Smallest `bits` with `2^bits >= n`, at least 1.
        let bits = if n <= 1 {
            1
        } else {
            u64::BITS - (n - 1).leading_zeros()
        };
        // Balanced halves; `bits <= 32` covers every realistic carrier
        // (4 Gi slots), so `2 * half <= 32` and no shift can overflow.
        let half = bits.div_ceil(2).clamp(1, 32);

        let mut hasher = Sha256::new();
        hasher.update(PERM_LABEL);
        hasher.update(seed);
        hasher.update(n.to_be_bytes());
        let digest = hasher.finalize();
        let mut k0 = [0u8; 8];
        let mut k1 = [0u8; 8];
        k0.copy_from_slice(&digest[..8]);
        k1.copy_from_slice(&digest[8..16]);

        Self {
            n,
            half,
            keys: [u64::from_be_bytes(k0), u64::from_be_bytes(k1)],
        }
    }

    /// Domain size this permutation was built for.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.n as usize
    }

    #[inline]
    fn round(&self, index: u64) -> u64 {
        mix(self.keys[(index & 1) as usize] ^ index.rotate_left(17))
    }

    /// One Feistel pass over the `2 * half`-bit domain (a bijection there).
    #[inline]
    fn permute_block(&self, x: u64) -> u64 {
        let half = self.half;
        let mask = (1u64 << half) - 1;
        let mut left = (x >> half) & mask;
        let mut right = x & mask;
        for round in 0..ROUNDS as u64 {
            let f = self.round(round ^ right) & mask;
            let next_right = left ^ f;
            left = right;
            right = next_right;
        }
        (left << half) | right
    }

    /// The slot at permutation position `i`.
    ///
    /// `i` must be below `len()`; larger indices are folded first so a caller
    /// that overshoots cannot produce an out-of-range slot.
    pub(crate) fn at(&self, i: usize) -> usize {
        if self.n <= 1 {
            return 0;
        }
        let mut x = (i as u64) % self.n;
        let mut y = self.permute_block(x);
        // Cycle walking: `permute_block` is a bijection on a superset of the
        // domain, so re-applying it until the value lands inside stays a
        // bijection on `[0, n)`.
        let mut guard = 0u32;
        while y >= self.n {
            x = y;
            y = self.permute_block(x);
            guard += 1;
            if guard > 64 {
                // Unreachable for a true bijection; returning the folded index
                // keeps a hypothetical defect from hanging an embed.
                return (i as u64 % self.n) as usize;
            }
        }
        y as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(tag: u8) -> [u8; 32] {
        [tag; 32]
    }

    #[test]
    fn produces_a_bijection_for_awkward_domain_sizes() {
        // Every size here forces cycle walking: none is a power of two.
        for n in [2usize, 3, 5, 7, 17, 63, 100, 1_001, 4_097] {
            let perm = KeyedPermutation::new(&seed(7), n);
            assert_eq!(perm.len(), n);
            let mut seen = vec![false; n];
            for i in 0..n {
                let s = perm.at(i);
                assert!(s < n, "n={n}: slot {s} out of range");
                assert!(!seen[s], "n={n}: slot {s} produced twice");
                seen[s] = true;
            }
            assert!(seen.iter().all(|&v| v), "n={n}: some slot never produced");
        }
    }

    #[test]
    fn is_stable_across_instances_and_depends_on_the_seed() {
        let a = KeyedPermutation::new(&seed(1), 5_000);
        let b = KeyedPermutation::new(&seed(1), 5_000);
        let c = KeyedPermutation::new(&seed(2), 5_000);
        let seq_a: Vec<usize> = (0..64).map(|i| a.at(i)).collect();
        let seq_b: Vec<usize> = (0..64).map(|i| b.at(i)).collect();
        let seq_c: Vec<usize> = (0..64).map(|i| c.at(i)).collect();
        assert_eq!(seq_a, seq_b, "same seed must reproduce the same order");
        assert_ne!(seq_a, seq_c, "a different seed must reorder the slots");
    }

    #[test]
    fn spreads_a_prefix_over_the_whole_domain() {
        // The point of the permutation: the first 512 positions (the header)
        // must not cluster in the opening of the file.
        let n = 200_000usize;
        let perm = KeyedPermutation::new(&seed(9), n);
        let head: Vec<usize> = (0..512).map(|i| perm.at(i)).collect();
        let min = *head.iter().min().unwrap();
        let max = *head.iter().max().unwrap();
        assert!(
            min < n / 8 && max > n - n / 8,
            "header spread too narrow: {min}..{max} of {n}"
        );
    }

    #[test]
    fn degenerate_domains_do_not_panic() {
        for n in [0usize, 1] {
            let perm = KeyedPermutation::new(&seed(3), n);
            assert_eq!(perm.at(0), 0);
            assert_eq!(perm.at(999), 0);
        }
    }
}
