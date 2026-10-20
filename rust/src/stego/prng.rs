//! Cryptographically seeded pseudo-random permutation for embedding slot scattering.
//!
//! Scatters the embedding sequence across candidate slots (pixels or DCT coefficients)
//! using a 256-bit seed derived from the user password, ensuring that without the key,
//! an attacker cannot determine which slots were modified or in what order.

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
