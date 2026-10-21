//! Cryptographically seeded pseudo-random permutation for embedding slot scattering.
//!
//! Scatters the embedding sequence across candidate slots (pixels or DCT coefficients)
//! using a 256-bit seed derived from the user password or profile secret. The general candidate
//! pool is ranked by the public cost model (HILL/UERD); the keyed permutation selects the 256
//! header slots from the candidate pool and scrambles the body slot embedding order, ensuring
//! that without the key, an attacker cannot determine header locations or the message stream order.

use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;

/// Permute a slice of slot indices in-place using a 32-byte seed.
pub fn permute_indices<T>(items: &mut [T], seed: &[u8; 32]) {
    let mut rng = StdRng::from_seed(*seed);
    items.shuffle(&mut rng);
}

/// Generate a permuted vector of indices 0..n using a 32-byte seed.
pub fn generate_permuted_indices(n: usize, seed: &[u8; 32]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..n).collect();
    permute_indices(&mut indices, seed);
    indices
}
