//! JPEG DCT-domain steganographic embedding and extraction (V4 content envelope).
//!
//! # The shape of the code
//!
//! The slot set is a *geometric* fact: every AC position of every block, ordered
//! by flat index, permuted with a key. Neither end ever filters by coefficient
//! value, so the extractor needs no cost map, no ranking and no threshold -- it
//! reads parities and rebuilds the same sequence from the key alone.
//!
//! ```text
//! Grid      = { (bi, k) | k in grid_rule }
//! HdrSlots  = permute(Grid, header_seed)[0 .. 718 + n_ext]
//! BodyGrid  = Grid \ HdrSlots
//! BodySlots = permute(BodyGrid, perm_seed)[0 .. u * (bits + h - 1)]
//! ```
//!
//! The header (44-byte superblock + optional TLV area) is located by a seed
//! derived from `SuiteKDF(password, cover_digest)`, so reading it costs a full
//! KDF: a wrong password cannot be rejected cheaply, and the structural checks
//! that follow are not a fast oracle.
//!
//! # Ternary matching and write-back
//!
//! The trellis works on parity carriers (`2`/`3`), but a coefficient is an
//! `i16`. [`StcTrellis::embed_with_deltas`] therefore returns one `-1/0/+1` per
//! slot and the engine applies exactly that to the coefficient, which lets a
//! single coefficient both keep its magnitude relationship with its neighbours
//! and land on the cheapest side.

use crate::errors::StrHideError;

mod capacity;
mod embed;
mod extract;
mod inspect;
mod layout;

#[cfg(test)]
pub(crate) use extract::{read_bits, read_superblock};
#[cfg(test)]
pub(crate) use layout::{CoverFrame, jpeg_pre_salt};

#[cfg(test)]
mod tests;

pub use capacity::{layout_for_payload, probe_jpeg_capacity};
pub use embed::embed_jpeg;
pub(crate) use embed::embed_jpeg_with_stats;
pub use extract::extract_jpeg;
pub(crate) use inspect::{inspect_jpeg, verify_jpeg};

/// `format_id` of JPEG in the V4 AAD domain separator.
pub(crate) const JPEG_FORMAT_ID: u8 = 4;

pub(crate) fn map_dct_error(e: dct_io::DctError) -> StrHideError {
    let err_str = e.to_string();
    if err_str.contains("SOF2") || err_str.to_lowercase().contains("progressive") {
        return StrHideError::UnsupportedFormat(
            "Progressive JPEG (SOF2) is not supported for content-adaptive DCT steganography; please convert to baseline JPEG or use 'strhide write' for structural hiding".into(),
        );
    }
    // The progressive check above already covers this arm's SOF2/progressive
    // test; repeating it here was a dead branch.
    match e {
        dct_io::DctError::Unsupported(msg) => {
            StrHideError::UnsupportedFormat(format!("Unsupported JPEG variant: {msg}"))
        }
        _ => StrHideError::CorruptedData(format!("Corrupt JPEG coefficient stream: {e}")),
    }
}

/// No-op tracer hook using `format_args!` to avoid eager heap allocation.
#[inline(always)]
pub(crate) fn trace(_args: std::fmt::Arguments<'_>) {}
